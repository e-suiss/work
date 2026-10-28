//! The outbox publisher (T-17, §18 OP-34): per ledger it reads pending pointers in one
//! transaction, builds each event from the committed record, publishes with `Nats-Msg-Id` and
//! awaits the JetStream ack outside any transaction (T-32 rule 4), then removes the acknowledged
//! pointers in a second transaction. Delivery is at least once and deduplicated by event id
//! (T-76 rule 3); a NATS outage leaves the pointers in place and is retried with backoff (T-21).
//! The [`Consumer`] pulls bounded batches from one durable consumer per owned partition and
//! hands each event to a [`Handler`]; when NATS is unreachable it reports
//! [`Health::Degraded`] and its fallback scan hands the same events, built from the pending
//! pointers and their committed rows, to the same handler. Repeats are dropped by event id and
//! order is never assumed (T-18, T-21).

use std::collections::VecDeque;
use std::future::Future;
use std::time::Duration;

use tokio::time::{sleep, timeout};
use work_store::{LedgerId, PendingEvent, PointerKey, StoreError};

use crate::domain::{
    Backoff, ConfigError, ConsumerConfig, EnvelopeError, Event, EventFacts, Health,
    PublisherConfig, Seen, cloud_event, parse_event, partition,
};
use crate::ports::{Bus, BusError, Committed, Handler, Outbound, Outbox, Pull, PullSpec, Settle};

/// Why one publishing pass stopped; the pointers not yet acknowledged stay pending.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// NATS failed or did not acknowledge (T-21).
    #[error("bus: {0}")]
    Bus(#[from] BusError),
    /// A store call did not finish within the call timeout.
    #[error("store call timed out")]
    StoreTimedOut,
    /// A committed row cannot be expressed as an event.
    #[error("event: {0}")]
    Envelope(#[from] EnvelopeError),
}

/// Counts of one [`Publisher::publish_ledger`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Published {
    /// Pointers whose publish JetStream acknowledged.
    pub acked: u64,
    /// Of those, acknowledged as duplicates of an earlier publish (T-76 rule 3).
    pub duplicates: u64,
    /// Pointers removed after their ack.
    pub removed: u64,
}

impl Published {
    fn add(&mut self, other: Self) {
        self.acked = self.acked.saturating_add(other.acked);
        self.duplicates = self.duplicates.saturating_add(other.duplicates);
        self.removed = self.removed.saturating_add(other.removed);
    }
}

/// Publishes outbox pointers to NATS JetStream.
#[derive(Debug)]
pub struct Publisher<O, B> {
    outbox: O,
    bus: B,
    config: PublisherConfig,
}

impl<O: Outbox, B: Bus> Publisher<O, B> {
    /// A publisher over `outbox` and `bus`.
    ///
    /// # Errors
    /// [`ConfigError`] if `config` does not validate.
    pub fn new(outbox: O, bus: B, config: PublisherConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            outbox,
            bus,
            config,
        })
    }

    /// The validated settings.
    #[must_use]
    pub const fn config(&self) -> &PublisherConfig {
        &self.config
    }

    /// Creates or updates the T-76 stream.
    ///
    /// # Errors
    /// [`DispatchError::Bus`].
    pub async fn ensure_stream(&self) -> Result<(), DispatchError> {
        timeout(
            self.config.call_timeout,
            self.bus.ensure_stream(&self.config.stream),
        )
        .await
        .map_err(|_| BusError::TimedOut)??;
        Ok(())
    }

    /// Publishes every pending pointer of `ledger`, batch by batch, until none is left or a
    /// call fails. Pointers acknowledged before a failure are still removed.
    ///
    /// # Errors
    /// The first [`DispatchError`]; pointers without an ack stay pending.
    pub async fn publish_ledger(&self, ledger: &LedgerId) -> Result<Published, DispatchError> {
        let mut total = Published::default();
        loop {
            let batch = self
                .store(self.outbox.pending(ledger, self.config.batch_size))
                .await?;
            let full = batch.len() >= usize::try_from(self.config.batch_size).unwrap_or(usize::MAX);
            if batch.is_empty() {
                return Ok(total);
            }
            let (acked, duplicates, failure) = self.send(ledger, &batch).await;
            let removed = if acked.is_empty() {
                0
            } else {
                self.store(self.outbox.remove(ledger, &acked)).await?
            };
            total.add(Published {
                acked: u64::try_from(acked.len()).unwrap_or(u64::MAX),
                duplicates,
                removed,
            });
            if let Some(e) = failure {
                return Err(e);
            }
            if !full {
                return Ok(total);
            }
        }
    }

    /// Publishes every ledger with pending pointers until `shutdown` resolves. Each poll
    /// discovers up to `ledgers_per_poll` ledgers through the store and publishes them in turn;
    /// after a full discovery without failure the next poll starts at once, otherwise it waits
    /// `poll_interval`, and after a failure the exponential backoff (T-21).
    pub async fn run(&self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut backoff = Backoff::new(self.config.backoff_min, self.config.backoff_max);
        let mut stream_ready = false;
        loop {
            let mut failed = false;
            let mut full = false;
            if !stream_ready {
                match self.ensure_stream().await {
                    Ok(()) => stream_ready = true,
                    Err(e) => {
                        tracing::warn!(error = %e, "event stream not ready");
                        failed = true;
                    }
                }
            }
            if stream_ready {
                match self.discover().await {
                    Ok(ledgers) => {
                        full = ledgers.len()
                            >= usize::try_from(self.config.ledgers_per_poll).unwrap_or(usize::MAX);
                        for ledger in &ledgers {
                            if let Err(e) = self.publish_ledger(ledger).await {
                                tracing::warn!(error = %e, "outbox publish pass stopped");
                                failed = true;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "outbox ledger discovery failed");
                        failed = true;
                    }
                }
            }
            let wait = if failed {
                backoff.fail()
            } else {
                backoff.reset();
                if full {
                    Duration::ZERO
                } else {
                    self.config.poll_interval
                }
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = sleep(wait) => {}
            }
        }
    }

    /// Up to `ledgers_per_poll` ledgers with pending pointers (§18 OP-34).
    ///
    /// # Errors
    /// [`DispatchError::Store`] or [`DispatchError::StoreTimedOut`].
    pub async fn discover(&self) -> Result<Vec<LedgerId>, DispatchError> {
        self.store(self.outbox.ledgers(self.config.ledgers_per_poll))
            .await
    }

    async fn store<T>(
        &self,
        call: impl Future<Output = Result<T, StoreError>>,
    ) -> Result<T, DispatchError> {
        timeout(self.config.call_timeout, call)
            .await
            .map_err(|_| DispatchError::StoreTimedOut)?
            .map_err(DispatchError::from)
    }

    fn outbound(&self, ledger: &LedgerId, event: &PendingEvent) -> Result<Outbound, EnvelopeError> {
        let facts = facts(ledger, event);
        Ok(Outbound {
            subject: self
                .config
                .stream
                .subject(ledger.as_bytes(), &event.event_type),
            msg_id: event.key.event_id.clone(),
            traceparent: event.traceparent.clone(),
            payload: cloud_event(&self.config.source, &facts)?,
        })
    }

    async fn send(
        &self,
        ledger: &LedgerId,
        batch: &[PendingEvent],
    ) -> (Vec<PointerKey>, u64, Option<DispatchError>) {
        let mut acked = Vec::with_capacity(batch.len());
        let mut duplicates = 0_u64;
        let mut failure: Option<DispatchError> = None;
        let mut in_flight: VecDeque<(PointerKey, B::Ack)> = VecDeque::new();
        for event in batch {
            if in_flight.len() >= self.config.max_in_flight
                && let Some((key, ack)) = in_flight.pop_front()
            {
                self.settle(key, ack, &mut acked, &mut duplicates, &mut failure)
                    .await;
            }
            if failure.is_some() {
                break;
            }
            let outbound = match self.outbound(ledger, event) {
                Ok(o) => o,
                Err(e) => {
                    failure = Some(e.into());
                    break;
                }
            };
            match timeout(self.config.call_timeout, self.bus.publish(outbound)).await {
                Ok(Ok(ack)) => in_flight.push_back((event.key.clone(), ack)),
                Ok(Err(e)) => {
                    failure = Some(e.into());
                    break;
                }
                Err(_) => {
                    failure = Some(BusError::TimedOut.into());
                    break;
                }
            }
        }
        while let Some((key, ack)) = in_flight.pop_front() {
            self.settle(key, ack, &mut acked, &mut duplicates, &mut failure)
                .await;
        }
        (acked, duplicates, failure)
    }

    async fn settle(
        &self,
        key: PointerKey,
        ack: B::Ack,
        acked: &mut Vec<PointerKey>,
        duplicates: &mut u64,
        failure: &mut Option<DispatchError>,
    ) {
        match timeout(self.config.call_timeout, ack).await {
            Ok(Ok(a)) => {
                if a.duplicate {
                    *duplicates = duplicates.saturating_add(1);
                }
                acked.push(key);
            }
            Ok(Err(e)) => {
                failure.get_or_insert(e.into());
            }
            Err(_) => {
                failure.get_or_insert(BusError::TimedOut.into());
            }
        }
    }
}

fn facts<'a>(ledger: &'a LedgerId, event: &'a PendingEvent) -> EventFacts<'a> {
    EventFacts {
        ledger: ledger.as_bytes(),
        pos: event.key.pos,
        event_id: &event.key.event_id,
        event_type: &event.event_type,
        traceparent: &event.traceparent,
        record_id: &event.record_id,
        recorded_at_ms: event.recorded_at_ms,
    }
}

/// Why a consumer call stopped.
#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    /// The partition is not one this consumer owns.
    #[error("partition {0} is not owned by this consumer")]
    NotOwned(u16),
    /// The store failed during the fallback scan.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A store call did not finish within the call timeout.
    #[error("store call timed out")]
    StoreTimedOut,
}

/// Counts of one [`Consumer::poll`] or [`Consumer::fallback`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Consumed {
    /// Whether the NATS path worked during the pass.
    pub health: Health,
    /// Events the handler took.
    pub handled: u64,
    /// Repeats of events already taken (T-76 rule 3).
    pub duplicates: u64,
    /// Events the handler did not take now.
    pub retried: u64,
    /// Payloads that are not Work events.
    pub rejected: u64,
}

impl Consumed {
    const fn new(health: Health) -> Self {
        Self {
            health,
            handled: 0,
            duplicates: 0,
            retried: 0,
            rejected: 0,
        }
    }
}

enum Outcome {
    Handled,
    Duplicate,
    Retried,
}

/// Consumes the T-76 stream through per-partition durable pull consumers (T-76 rule 6) and,
/// while NATS is unreachable, reads committed state instead (T-21).
#[derive(Debug)]
pub struct Consumer<P, H> {
    pull: P,
    handler: H,
    config: ConsumerConfig,
    seen: Seen,
    health: Health,
}

impl<P: Pull, H: Handler> Consumer<P, H> {
    /// A consumer over `pull` handing events to `handler`; it starts [`Health::Degraded`] until
    /// [`Consumer::prepare`] succeeds.
    ///
    /// # Errors
    /// [`ConfigError`] if `config` does not validate.
    pub fn new(pull: P, handler: H, config: ConsumerConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            pull,
            handler,
            seen: Seen::new(config.seen_capacity),
            config,
            health: Health::Degraded,
        })
    }

    /// The validated settings.
    #[must_use]
    pub const fn config(&self) -> &ConsumerConfig {
        &self.config
    }

    /// The health of the last NATS call.
    #[must_use]
    pub const fn health(&self) -> Health {
        self.health
    }

    /// The handler.
    #[must_use]
    pub const fn handler(&self) -> &H {
        &self.handler
    }

    /// The durable pull consumer of partition `p`.
    #[must_use]
    pub fn spec(&self, p: u16) -> PullSpec {
        PullSpec {
            stream: self.config.stream.name.clone(),
            durable: self.config.durable(p),
            filter: self.config.stream.partition_filter(p),
            max_in_flight: self.config.max_in_flight,
            ack_wait: self.config.ack_wait,
        }
    }

    /// Creates or updates the durable consumer of every owned partition.
    pub async fn prepare(&mut self) -> Health {
        let mut health = Health::Live;
        for &p in &self.config.partitions {
            let spec = self.spec(p);
            match timeout(self.config.call_timeout, self.pull.ensure_consumer(&spec)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, durable = %spec.durable, "event consumer not ready");
                    health = Health::Degraded;
                }
                Err(_) => {
                    tracing::warn!(durable = %spec.durable, "event consumer setup timed out");
                    health = Health::Degraded;
                }
            }
        }
        self.health = health;
        health
    }

    /// Pulls one bounded batch of partition `p`, hands each new event to the handler and
    /// settles every delivery. A NATS failure is no error: the pass reports
    /// [`Health::Degraded`].
    ///
    /// # Errors
    /// [`ConsumeError::NotOwned`].
    pub async fn poll(&mut self, p: u16) -> Result<Consumed, ConsumeError> {
        self.owned(p)?;
        let spec = self.spec(p);
        let fetched = timeout(
            self.config.call_timeout,
            self.pull
                .fetch(&spec, self.config.batch_size, self.config.fetch_wait),
        )
        .await
        .map_err(|_| BusError::TimedOut)
        .and_then(|r| r);
        let batch = match fetched {
            Ok(batch) => batch,
            Err(e) => {
                tracing::warn!(error = %e, durable = %spec.durable, "event fetch failed");
                self.health = Health::Degraded;
                return Ok(Consumed::new(Health::Degraded));
            }
        };
        let mut done = Consumed::new(Health::Live);
        for inbound in batch {
            let how = match parse_event(&inbound.payload) {
                Err(e) => {
                    tracing::warn!(error = %e, durable = %spec.durable, "not a work event");
                    done.rejected = done.rejected.saturating_add(1);
                    Settle::Reject
                }
                Ok(event) => match self.take(&event).await {
                    Outcome::Handled => {
                        done.handled = done.handled.saturating_add(1);
                        Settle::Ack
                    }
                    Outcome::Duplicate => {
                        done.duplicates = done.duplicates.saturating_add(1);
                        Settle::Ack
                    }
                    Outcome::Retried => {
                        done.retried = done.retried.saturating_add(1);
                        Settle::Retry
                    }
                },
            };
            let settled = timeout(
                self.config.call_timeout,
                self.pull.settle(inbound.token, how),
            )
            .await
            .map_err(|_| BusError::TimedOut)
            .and_then(|r| r);
            if let Err(e) = settled {
                tracing::warn!(error = %e, durable = %spec.durable, "event settle failed");
                done.health = Health::Degraded;
            }
        }
        self.health = done.health;
        Ok(done)
    }

    /// The fallback while NATS is unreachable (T-21, §18 OP-34 rule 2): for each ledger of
    /// partition `p` among the first `ledgers_per_scan` with pending pointers, reads the pointers
    /// page by page from the start and hands the event of each, built from its committed row, to
    /// the handler. The events equal the ones NATS carries, so repeats across both paths drop
    /// by event id.
    ///
    /// # Errors
    /// [`ConsumeError`]; events handled before the failure stay handled.
    pub async fn fallback<C: Committed>(
        &mut self,
        committed: &C,
        p: u16,
    ) -> Result<Consumed, ConsumeError> {
        self.owned(p)?;
        let mut done = Consumed::new(self.health);
        let ledgers = self
            .store(committed.ledgers(self.config.ledgers_per_scan))
            .await?;
        let page = u32::try_from(self.config.batch_size).unwrap_or(u32::MAX);
        let partitions = self.config.stream.partitions;
        for ledger in ledgers
            .iter()
            .filter(|l| partition(l.as_bytes(), partitions) == p)
        {
            let mut after: Option<PointerKey> = None;
            loop {
                let rows = self
                    .store(committed.pending_after(ledger, after.as_ref(), page))
                    .await?;
                for row in &rows {
                    match self.take(&Event::from_facts(&facts(ledger, row))).await {
                        Outcome::Handled => done.handled = done.handled.saturating_add(1),
                        Outcome::Duplicate => {
                            done.duplicates = done.duplicates.saturating_add(1);
                        }
                        Outcome::Retried => done.retried = done.retried.saturating_add(1),
                    }
                }
                let full = rows.len() >= self.config.batch_size;
                after = rows.last().map(|r| r.key.clone());
                if !full || after.is_none() {
                    break;
                }
            }
        }
        Ok(done)
    }

    /// Consumes every owned partition until `shutdown` resolves: while live it polls each
    /// partition in turn, each fetch waiting up to `fetch_wait`; while degraded it runs the fallback scan of each and waits
    /// `fallback_interval` before retrying NATS (T-21).
    pub async fn run<C: Committed>(&mut self, committed: &C, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut ready = false;
        loop {
            if !ready {
                ready = self.prepare().await == Health::Live;
            }
            let mut degraded = !ready;
            if ready {
                for p in self.config.partitions.clone() {
                    if let Ok(done) = self.poll(p).await {
                        degraded |= done.health == Health::Degraded;
                    }
                }
            }
            if degraded {
                ready = false;
                for p in self.config.partitions.clone() {
                    if let Err(e) = self.fallback(committed, p).await {
                        tracing::warn!(error = %e, partition = p, "fallback scan stopped");
                    }
                }
            }
            let wait = if degraded {
                self.config.fallback_interval
            } else {
                Duration::ZERO
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = sleep(wait) => {}
            }
        }
    }

    fn owned(&self, p: u16) -> Result<(), ConsumeError> {
        if self.config.partitions.contains(&p) {
            Ok(())
        } else {
            Err(ConsumeError::NotOwned(p))
        }
    }

    async fn take(&mut self, event: &Event) -> Outcome {
        if self.seen.contains(&event.ledger, &event.id) {
            return Outcome::Duplicate;
        }
        match timeout(self.config.call_timeout, self.handler.handle(event)).await {
            Ok(Ok(())) => {
                self.seen.insert(&event.ledger, &event.id);
                Outcome::Handled
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, event = %event.id, "event not handled");
                Outcome::Retried
            }
            Err(_) => {
                tracing::warn!(event = %event.id, "event handler timed out");
                Outcome::Retried
            }
        }
    }

    async fn store<T>(
        &self,
        call: impl Future<Output = Result<T, StoreError>>,
    ) -> Result<T, ConsumeError> {
        timeout(self.config.call_timeout, call)
            .await
            .map_err(|_| ConsumeError::StoreTimedOut)?
            .map_err(ConsumeError::from)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;
    use crate::domain::StreamSettings;
    use crate::ports::Acked;

    const L: [u8; 32] = [0xab; 32];
    const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn pending(pos: u64, id: &str) -> PendingEvent {
        PendingEvent {
            key: PointerKey {
                pos,
                event_id: id.to_owned(),
            },
            event_type: "work.opened".to_owned(),
            traceparent: TRACE.to_owned(),
            record_id: [0x01; 32],
            recorded_at_ms: 1_792_749_600_123,
        }
    }

    #[derive(Default)]
    struct MemOutbox {
        rows: Mutex<Vec<PendingEvent>>,
        more: Mutex<BTreeMap<LedgerId, Vec<PendingEvent>>>,
        removals: Mutex<Vec<Vec<PointerKey>>>,
        discoveries: Mutex<Vec<u32>>,
    }

    impl MemOutbox {
        fn with_rows<T>(
            &self,
            ledger: &LedgerId,
            f: impl FnOnce(&mut Vec<PendingEvent>) -> T,
        ) -> T {
            if *ledger == self::ledger() {
                f(&mut self.rows.lock().unwrap())
            } else {
                f(self.more.lock().unwrap().entry(*ledger).or_default())
            }
        }
    }

    impl Outbox for MemOutbox {
        fn ledgers(
            &self,
            limit: u32,
        ) -> impl Future<Output = Result<Vec<LedgerId>, StoreError>> + Send {
            self.discoveries.lock().unwrap().push(limit);
            let mut found: Vec<LedgerId> = self
                .more
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, rows)| !rows.is_empty())
                .map(|(l, _)| *l)
                .collect();
            if !self.rows.lock().unwrap().is_empty() {
                found.push(ledger());
            }
            found.sort();
            found.truncate(usize::try_from(limit).unwrap());
            std::future::ready(Ok(found))
        }

        fn pending(
            &self,
            ledger: &LedgerId,
            limit: u32,
        ) -> impl Future<Output = Result<Vec<PendingEvent>, StoreError>> + Send {
            let n = usize::try_from(limit).unwrap();
            let rows = self.with_rows(ledger, |rows| rows.iter().take(n).cloned().collect());
            std::future::ready(Ok(rows))
        }

        fn remove(
            &self,
            ledger: &LedgerId,
            keys: &[PointerKey],
        ) -> impl Future<Output = Result<u64, StoreError>> + Send {
            let gone = self.with_rows(ledger, |rows| {
                let before = rows.len();
                rows.retain(|r| !keys.contains(&r.key));
                before.checked_sub(rows.len()).unwrap()
            });
            self.removals.lock().unwrap().push(keys.to_vec());
            std::future::ready(Ok(u64::try_from(gone).unwrap()))
        }
    }

    struct MemBus {
        sent: Mutex<Vec<Outbound>>,
        seen: Mutex<Vec<String>>,
        ack_up_to: Option<usize>,
        refuse: bool,
    }

    impl MemBus {
        fn up() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                seen: Mutex::new(Vec::new()),
                ack_up_to: None,
                refuse: false,
            }
        }

        fn down() -> BusError {
            BusError::Unavailable("down".to_owned())
        }
    }

    impl Bus for MemBus {
        type Ack = std::future::Ready<Result<Acked, BusError>>;

        fn ensure_stream(
            &self,
            _settings: &StreamSettings,
        ) -> impl Future<Output = Result<(), BusError>> + Send {
            std::future::ready(if self.refuse {
                Err(Self::down())
            } else {
                Ok(())
            })
        }

        fn publish(
            &self,
            event: Outbound,
        ) -> impl Future<Output = Result<Self::Ack, BusError>> + Send {
            if self.refuse {
                return std::future::ready(Err(Self::down()));
            }
            let mut sent = self.sent.lock().unwrap();
            let n = sent.len();
            let mut seen = self.seen.lock().unwrap();
            let duplicate = seen.contains(&event.msg_id);
            seen.push(event.msg_id.clone());
            sent.push(event);
            let ack = if self.ack_up_to.is_some_and(|max| n >= max) {
                Err(BusError::TimedOut)
            } else {
                Ok(Acked { duplicate })
            };
            std::future::ready(Ok(std::future::ready(ack)))
        }
    }

    fn config() -> PublisherConfig {
        PublisherConfig {
            ledgers_per_poll: 2,
            batch_size: 2,
            max_in_flight: 1,
            call_timeout: Duration::from_secs(1),
            ..PublisherConfig::new("https://work.example")
        }
    }

    fn ledger() -> LedgerId {
        LedgerId::from_bytes(L)
    }

    #[tokio::test]
    async fn t_17_pointers_publish_in_order_with_the_event_id_as_msg_id() {
        let outbox = MemOutbox::default();
        *outbox.rows.lock().unwrap() = vec![pending(0, "a"), pending(0, "b"), pending(1, "c")];
        let p = Publisher::new(outbox, MemBus::up(), config()).unwrap();
        let done = p.publish_ledger(&ledger()).await.unwrap();
        assert_eq!(
            done,
            Published {
                acked: 3,
                duplicates: 0,
                removed: 3
            }
        );
        let sent = p.bus.sent.lock().unwrap();
        let ids: Vec<&str> = sent.iter().map(|o| o.msg_id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "c"]);
        assert!(sent.iter().all(|o| o.traceparent == TRACE));
        let subject = StreamSettings::default().subject(&L, "work.opened");
        assert!(sent.iter().all(|o| o.subject == subject));
        assert!(p.outbox.rows.lock().unwrap().is_empty());
        assert_eq!(p.outbox.removals.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn op_34_only_acknowledged_pointers_are_removed() {
        let outbox = MemOutbox::default();
        *outbox.rows.lock().unwrap() = vec![pending(0, "a"), pending(1, "b"), pending(2, "c")];
        let bus = MemBus {
            ack_up_to: Some(1),
            ..MemBus::up()
        };
        let p = Publisher::new(
            outbox,
            bus,
            PublisherConfig {
                batch_size: 10,
                ..config()
            },
        )
        .unwrap();
        let err = p.publish_ledger(&ledger()).await.unwrap_err();
        assert!(
            matches!(err, DispatchError::Bus(BusError::TimedOut)),
            "{err}"
        );
        let left: Vec<String> = p
            .outbox
            .rows
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.key.event_id.clone())
            .collect();
        assert_eq!(left, ["b", "c"]);
        assert_eq!(
            *p.outbox.removals.lock().unwrap(),
            [vec![PointerKey {
                pos: 0,
                event_id: "a".to_owned()
            }]]
        );
    }

    #[tokio::test]
    async fn t_21_bus_outage_keeps_every_pointer() {
        let outbox = MemOutbox::default();
        *outbox.rows.lock().unwrap() = vec![pending(0, "a")];
        let bus = MemBus {
            refuse: true,
            ..MemBus::up()
        };
        let p = Publisher::new(outbox, bus, config()).unwrap();
        assert!(p.ensure_stream().await.is_err());
        let err = p.publish_ledger(&ledger()).await.unwrap_err();
        assert!(matches!(err, DispatchError::Bus(BusError::Unavailable(_))));
        assert_eq!(p.outbox.rows.lock().unwrap().len(), 1);
        assert!(p.outbox.removals.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn t_76_a_duplicate_ack_still_removes_the_pointer() {
        let outbox = MemOutbox::default();
        *outbox.rows.lock().unwrap() = vec![pending(0, "a")];
        let bus = MemBus::up();
        bus.seen.lock().unwrap().push("a".to_owned());
        let p = Publisher::new(outbox, bus, config()).unwrap();
        let done = p.publish_ledger(&ledger()).await.unwrap();
        assert_eq!(done.duplicates, 1);
        assert_eq!(done.removed, 1);
    }

    #[tokio::test]
    async fn t_32_publisher_refuses_an_invalid_configuration() {
        let bad = PublisherConfig {
            batch_size: 0,
            ..config()
        };
        assert_eq!(
            Publisher::new(MemOutbox::default(), MemBus::up(), bad).err(),
            Some(ConfigError::Bounds)
        );
    }

    #[tokio::test]
    async fn t_21_run_polls_until_shutdown() {
        let outbox = MemOutbox::default();
        *outbox.rows.lock().unwrap() = vec![pending(0, "a")];
        let quick = PublisherConfig {
            poll_interval: Duration::from_millis(5),
            ..config()
        };
        let p = Publisher::new(outbox, MemBus::up(), quick).unwrap();
        p.run(sleep(Duration::from_millis(50))).await;
        assert!(p.outbox.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn t_80_run_discovers_every_ledger_with_pending_pointers() {
        let outbox = MemOutbox::default();
        *outbox.rows.lock().unwrap() = vec![pending(0, "a")];
        for b in [0x01_u8, 0x02, 0xcd] {
            outbox
                .more
                .lock()
                .unwrap()
                .insert(LedgerId::from_bytes([b; 32]), vec![pending(0, "x")]);
        }
        let quick = PublisherConfig {
            ledgers_per_poll: 2,
            poll_interval: Duration::from_secs(60),
            ..config()
        };
        let p = Publisher::new(outbox, MemBus::up(), quick).unwrap();
        p.run(sleep(Duration::from_millis(50))).await;
        assert!(p.outbox.rows.lock().unwrap().is_empty());
        assert!(p.outbox.more.lock().unwrap().values().all(Vec::is_empty));
        let discoveries = p.outbox.discoveries.lock().unwrap();
        assert_eq!(discoveries.first(), Some(&2));
        assert_eq!(discoveries.len(), 3);
        let sent = p.bus.sent.lock().unwrap();
        assert_eq!(sent.len(), 4);
        let first = StreamSettings::default().subject(&[0x01; 32], "work.opened");
        assert_eq!(
            sent.first().map(|o| o.subject.as_str()),
            Some(first.as_str())
        );
    }

    #[tokio::test]
    async fn t_21_run_waits_the_poll_interval_when_nothing_is_pending() {
        let quick = PublisherConfig {
            poll_interval: Duration::from_secs(60),
            ..config()
        };
        let p = Publisher::new(MemOutbox::default(), MemBus::up(), quick).unwrap();
        p.run(sleep(Duration::from_millis(30))).await;
        assert_eq!(*p.outbox.discoveries.lock().unwrap(), [2]);
    }

    mod consumer {
        use std::collections::{BTreeMap, BTreeSet, VecDeque};
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicBool, Ordering};

        use work_store::CommittedRecord;

        use super::*;
        use crate::ports::{HandlerError, Inbound};

        #[derive(Default)]
        struct MemPull {
            queues: Mutex<BTreeMap<String, VecDeque<Vec<u8>>>>,
            ensured: Mutex<Vec<PullSpec>>,
            settled: Mutex<Vec<(u64, Settle)>>,
            next: Mutex<u64>,
            down: AtomicBool,
        }

        impl MemPull {
            fn push(&self, durable: &str, payload: Vec<u8>) {
                self.queues
                    .lock()
                    .unwrap()
                    .entry(durable.to_owned())
                    .or_default()
                    .push_back(payload);
            }

            fn err(&self) -> Option<BusError> {
                self.down
                    .load(Ordering::SeqCst)
                    .then(|| BusError::Unavailable("down".to_owned()))
            }
        }

        impl Pull for MemPull {
            type Token = u64;

            fn ensure_consumer(
                &self,
                spec: &PullSpec,
            ) -> impl Future<Output = Result<(), BusError>> + Send {
                let r = if let Some(e) = self.err() {
                    Err(e)
                } else {
                    self.ensured.lock().unwrap().push(spec.clone());
                    Ok(())
                };
                std::future::ready(r)
            }

            fn fetch(
                &self,
                spec: &PullSpec,
                max: usize,
                _wait: Duration,
            ) -> impl Future<Output = Result<Vec<Inbound<u64>>, BusError>> + Send {
                if let Some(e) = self.err() {
                    return std::future::ready(Err(e));
                }
                let mut queues = self.queues.lock().unwrap();
                let queue = queues.entry(spec.durable.clone()).or_default();
                let mut next = self.next.lock().unwrap();
                let mut out = Vec::new();
                while out.len() < max {
                    let Some(payload) = queue.pop_front() else {
                        break;
                    };
                    out.push(Inbound {
                        payload,
                        token: *next,
                    });
                    *next = next.checked_add(1).unwrap();
                }
                std::future::ready(Ok(out))
            }

            fn settle(
                &self,
                token: u64,
                how: Settle,
            ) -> impl Future<Output = Result<(), BusError>> + Send {
                self.settled.lock().unwrap().push((token, how));
                std::future::ready(Ok(()))
            }
        }

        #[derive(Default)]
        struct MemHandler {
            taken: Mutex<Vec<(u64, String)>>,
            fail_once: Mutex<BTreeSet<String>>,
        }

        impl Handler for MemHandler {
            fn handle(
                &self,
                event: &Event,
            ) -> impl Future<Output = Result<(), HandlerError>> + Send {
                let r = if self.fail_once.lock().unwrap().remove(&event.id) {
                    Err(HandlerError("busy".to_owned()))
                } else {
                    self.taken
                        .lock()
                        .unwrap()
                        .push((event.pos, event.id.clone()));
                    Ok(())
                };
                std::future::ready(r)
            }
        }

        #[derive(Default)]
        struct MemCommitted {
            pending: BTreeMap<LedgerId, Vec<PendingEvent>>,
            pages: Mutex<Vec<Option<PointerKey>>>,
        }

        impl Committed for MemCommitted {
            fn ledgers(
                &self,
                limit: u32,
            ) -> impl Future<Output = Result<Vec<LedgerId>, StoreError>> + Send {
                let n = usize::try_from(limit).unwrap();
                std::future::ready(Ok(self.pending.keys().copied().take(n).collect()))
            }

            fn pending_after(
                &self,
                ledger: &LedgerId,
                after: Option<&PointerKey>,
                limit: u32,
            ) -> impl Future<Output = Result<Vec<PendingEvent>, StoreError>> + Send {
                self.pages.lock().unwrap().push(after.cloned());
                let n = usize::try_from(limit).unwrap();
                let rows = self
                    .pending
                    .get(ledger)
                    .into_iter()
                    .flatten()
                    .filter(|r| after.is_none_or(|a| r.key > *a))
                    .take(n)
                    .cloned()
                    .collect();
                std::future::ready(Ok(rows))
            }

            fn log_after(
                &self,
                _ledger: &LedgerId,
                _after: Option<u64>,
                _limit: u32,
            ) -> impl Future<Output = Result<Vec<CommittedRecord>, StoreError>> + Send {
                std::future::ready(Ok(Vec::new()))
            }
        }

        const M: [u8; 32] = [0xcd; 32];

        fn config() -> ConsumerConfig {
            ConsumerConfig {
                group: "derive".to_owned(),
                partitions: vec![partition(&L, 16), partition(&M, 16)],
                stream: StreamSettings::default(),
                batch_size: 2,
                max_in_flight: 4,
                fetch_wait: Duration::from_millis(10),
                ack_wait: Duration::from_secs(30),
                call_timeout: Duration::from_secs(1),
                fallback_interval: Duration::from_millis(5),
                ledgers_per_scan: 16,
                seen_capacity: 64,
            }
        }

        fn payload(ledger: &[u8; 32], pos: u64, id: &str) -> Vec<u8> {
            let row = pending(pos, id);
            let l = LedgerId::from_bytes(*ledger);
            cloud_event("https://work.example", &facts(&l, &row)).unwrap()
        }

        fn consumer() -> Consumer<MemPull, MemHandler> {
            Consumer::new(MemPull::default(), MemHandler::default(), config()).unwrap()
        }

        fn taken(c: &Consumer<MemPull, MemHandler>) -> Vec<String> {
            c.handler()
                .taken
                .lock()
                .unwrap()
                .iter()
                .map(|(_, id)| id.clone())
                .collect()
        }

        #[tokio::test]
        async fn op_25_one_durable_consumer_per_owned_partition() {
            let mut c = consumer();
            assert_eq!(c.health(), Health::Degraded);
            assert_eq!(c.prepare().await, Health::Live);
            let ensured = c.pull.ensured.lock().unwrap().clone();
            let names: Vec<&str> = ensured.iter().map(|s| s.durable.as_str()).collect();
            assert_eq!(names, ["derive-p11", "derive-p13"]);
            assert!(ensured.iter().all(|s| s.stream == "WORK_EVENTS"
                && s.max_in_flight == 4
                && s.ack_wait == Duration::from_secs(30)));
            assert_eq!(
                ensured.first().map(|s| s.filter.as_str()),
                Some("work.evt.11.*.>")
            );
        }

        #[tokio::test]
        async fn t_76_poll_takes_a_bounded_batch_and_acks_each_delivery() {
            let mut c = consumer();
            let p = partition(&L, 16);
            for (pos, id) in [(0, "a"), (1, "b"), (2, "c")] {
                c.pull.push("derive-p11", payload(&L, pos, id));
            }
            let done = c.poll(p).await.unwrap();
            assert_eq!(done.health, Health::Live);
            assert_eq!(done.handled, 2);
            assert_eq!(taken(&c), ["a", "b"]);
            assert_eq!(
                *c.pull.settled.lock().unwrap(),
                [(0, Settle::Ack), (1, Settle::Ack)]
            );
            assert_eq!(c.poll(p).await.unwrap().handled, 1);
            assert_eq!(taken(&c), ["a", "b", "c"]);
        }

        #[tokio::test]
        async fn t_18_repeats_drop_by_event_id_and_order_is_not_assumed() {
            let mut c = consumer();
            let p = partition(&L, 16);
            for (pos, id) in [(2, "c"), (0, "a"), (2, "c"), (1, "b")] {
                c.pull.push("derive-p11", payload(&L, pos, id));
            }
            let first = c.poll(p).await.unwrap();
            let second = c.poll(p).await.unwrap();
            assert_eq!(first.handled + second.handled, 3);
            assert_eq!(first.duplicates + second.duplicates, 1);
            assert_eq!(
                *c.handler().taken.lock().unwrap(),
                [
                    (2, "c".to_owned()),
                    (0, "a".to_owned()),
                    (1, "b".to_owned())
                ]
            );
            assert!(
                c.pull
                    .settled
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(_, how)| *how == Settle::Ack)
            );
        }

        #[tokio::test]
        async fn p_98_a_payload_that_is_not_a_work_event_is_rejected() {
            let mut c = consumer();
            c.pull
                .push("derive-p11", b"{\"specversion\":\"1.0\"}".to_vec());
            let done = c.poll(partition(&L, 16)).await.unwrap();
            assert_eq!(done.rejected, 1);
            assert_eq!(*c.pull.settled.lock().unwrap(), [(0, Settle::Reject)]);
            assert_eq!(taken(&c), Vec::<String>::new());
        }

        #[tokio::test]
        async fn t_18_a_handler_failure_is_redelivered_and_not_remembered() {
            let mut c = consumer();
            let p = partition(&L, 16);
            c.handler().fail_once.lock().unwrap().insert("a".to_owned());
            c.pull.push("derive-p11", payload(&L, 0, "a"));
            let done = c.poll(p).await.unwrap();
            assert_eq!(done.retried, 1);
            assert_eq!(*c.pull.settled.lock().unwrap(), [(0, Settle::Retry)]);
            c.pull.push("derive-p11", payload(&L, 0, "a"));
            assert_eq!(c.poll(p).await.unwrap().handled, 1);
            assert_eq!(taken(&c), ["a"]);
        }

        #[tokio::test]
        async fn t_21_unreachable_nats_reports_degraded() {
            let mut c = consumer();
            c.pull.down.store(true, Ordering::SeqCst);
            assert_eq!(c.prepare().await, Health::Degraded);
            let done = c.poll(partition(&L, 16)).await.unwrap();
            assert_eq!(done.health, Health::Degraded);
            assert_eq!(c.health(), Health::Degraded);
            c.pull.down.store(false, Ordering::SeqCst);
            assert_eq!(c.prepare().await, Health::Live);
        }

        #[tokio::test]
        async fn t_21_a_partition_not_owned_is_refused() {
            let mut c = consumer();
            let other = (0..16)
                .find(|p| !c.config().partitions.contains(p))
                .unwrap();
            assert!(matches!(
                c.poll(other).await,
                Err(ConsumeError::NotOwned(p)) if p == other
            ));
            assert!(matches!(
                c.fallback(&MemCommitted::default(), other).await,
                Err(ConsumeError::NotOwned(_))
            ));
        }

        fn committed() -> MemCommitted {
            let mut m = MemCommitted::default();
            m.pending.insert(
                LedgerId::from_bytes(L),
                vec![
                    pending(0, "a"),
                    pending(0, "b"),
                    pending(1, "c"),
                    pending(2, "d"),
                    pending(3, "e"),
                ],
            );
            m.pending
                .insert(LedgerId::from_bytes(M), vec![pending(0, "m")]);
            m.pending
                .insert(LedgerId::from_bytes([0x01; 32]), vec![pending(0, "x")]);
            m
        }

        #[tokio::test]
        async fn t_21_fallback_reads_committed_state_of_the_partition_from_a_cursor() {
            let mut c = consumer();
            let m = committed();
            let done = c.fallback(&m, partition(&L, 16)).await.unwrap();
            assert_eq!(done.health, Health::Degraded);
            assert_eq!(done.handled, 5);
            assert_eq!(taken(&c), ["a", "b", "c", "d", "e"]);
            let key = |pos, id: &str| {
                Some(PointerKey {
                    pos,
                    event_id: id.to_owned(),
                })
            };
            assert_eq!(*m.pages.lock().unwrap(), [None, key(0, "b"), key(2, "d")]);
            let again = c.fallback(&m, partition(&L, 16)).await.unwrap();
            assert_eq!((again.handled, again.duplicates), (0, 5));
            c.fallback(&m, partition(&M, 16)).await.unwrap();
            assert_eq!(taken(&c).last().map(String::as_str), Some("m"));
            assert!(!taken(&c).contains(&"x".to_owned()));
        }

        #[tokio::test]
        async fn t_21_events_from_both_paths_are_taken_once() {
            let mut c = consumer();
            let m = committed();
            let p = partition(&L, 16);
            c.fallback(&m, p).await.unwrap();
            c.pull.push("derive-p11", payload(&L, 1, "c"));
            c.pull.push("derive-p11", payload(&L, 4, "f"));
            let done = c.poll(p).await.unwrap();
            assert_eq!((done.handled, done.duplicates), (1, 1));
            assert_eq!(taken(&c), ["a", "b", "c", "d", "e", "f"]);
        }

        #[tokio::test]
        async fn t_18_the_fallback_event_equals_the_published_one() {
            let row = pending(9, "z");
            let l = LedgerId::from_bytes(L);
            let published =
                parse_event(&cloud_event("https://work.example", &facts(&l, &row)).unwrap())
                    .unwrap();
            assert_eq!(published, Event::from_facts(&facts(&l, &row)));
        }

        #[tokio::test]
        async fn t_21_run_falls_back_while_nats_is_down_and_returns_to_it() {
            let mut c = consumer();
            c.pull.down.store(true, Ordering::SeqCst);
            let m = committed();
            c.run(&m, sleep(Duration::from_millis(30))).await;
            assert_eq!(c.health(), Health::Degraded);
            assert_eq!(taken(&c), ["a", "b", "c", "d", "e", "m"]);
            c.pull.down.store(false, Ordering::SeqCst);
            c.pull.push("derive-p13", payload(&M, 1, "n"));
            c.pull.push("derive-p13", payload(&M, 0, "m"));
            c.run(&m, sleep(Duration::from_millis(30))).await;
            assert_eq!(c.health(), Health::Live);
            assert_eq!(taken(&c).last().map(String::as_str), Some("n"));
            assert_eq!(taken(&c).len(), 7);
        }
    }
}
