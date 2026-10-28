//! The outbox publisher (T-17, §18 OP-34): per ledger it reads pending pointers in one
//! transaction, builds each event from the committed record, publishes with `Nats-Msg-Id` and
//! awaits the JetStream ack outside any transaction (T-32 rule 4), then removes the acknowledged
//! pointers in a second transaction. Delivery is at least once and deduplicated by event id
//! (T-76 rule 3); a NATS outage leaves the pointers in place and is retried with backoff (T-21).

use std::collections::VecDeque;
use std::future::Future;

use tokio::time::{sleep, timeout};
use work_store::{LedgerId, PendingEvent, PointerKey, StoreError};

use crate::domain::{
    Backoff, ConfigError, EnvelopeError, EventFacts, PublisherConfig, cloud_event,
};
use crate::ports::{Bus, BusError, Outbound, Outbox};

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

    /// Publishes the ledgers of `ledgers` until `shutdown` resolves: polls every
    /// `poll_interval`, and after a failure waits with exponential backoff (T-21).
    pub async fn run(&self, ledgers: &[LedgerId], shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut backoff = Backoff::new(self.config.backoff_min, self.config.backoff_max);
        let mut stream_ready = false;
        loop {
            let mut failed = false;
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
                for ledger in ledgers {
                    if let Err(e) = self.publish_ledger(ledger).await {
                        tracing::warn!(error = %e, "outbox publish pass stopped");
                        failed = true;
                    }
                }
            }
            let wait = if failed {
                backoff.fail()
            } else {
                backoff.reset();
                self.config.poll_interval
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = sleep(wait) => {}
            }
        }
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
        let facts = EventFacts {
            ledger: ledger.as_bytes(),
            pos: event.key.pos,
            event_id: &event.key.event_id,
            event_type: &event.event_type,
            traceparent: &event.traceparent,
            record_id: &event.record_id,
            recorded_at_ms: event.recorded_at_ms,
        };
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

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
        removals: Mutex<Vec<Vec<PointerKey>>>,
    }

    impl Outbox for MemOutbox {
        fn pending(
            &self,
            _ledger: &LedgerId,
            limit: u32,
        ) -> impl Future<Output = Result<Vec<PendingEvent>, StoreError>> + Send {
            let rows = self.rows.lock().unwrap();
            let n = usize::try_from(limit).unwrap();
            std::future::ready(Ok(rows.iter().take(n).cloned().collect()))
        }

        fn remove(
            &self,
            _ledger: &LedgerId,
            keys: &[PointerKey],
        ) -> impl Future<Output = Result<u64, StoreError>> + Send {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|r| !keys.contains(&r.key));
            self.removals.lock().unwrap().push(keys.to_vec());
            let gone = before.checked_sub(rows.len()).unwrap();
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
        p.run(&[ledger()], sleep(Duration::from_millis(50))).await;
        assert!(p.outbox.rows.lock().unwrap().is_empty());
    }
}
