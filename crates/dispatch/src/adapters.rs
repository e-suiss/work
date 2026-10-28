//! Adapters of the publisher and consumer ports: [`PgOutbox`] over the canonical store,
//! connected as `work_publisher` (§18 OP-34, T-73 rule 2), also serving the consumer's cursor
//! scans (T-21); [`JetStreamBus`] over NATS JetStream with the T-76 stream, `Nats-Msg-Id`,
//! `traceparent` and the CloudEvents structured content type; and [`JetStreamPull`], the
//! per-partition durable pull consumers with explicit acks (T-76 rule 6).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::time::timeout;

use async_nats::jetstream::{
    self, AckKind,
    consumer::{self, AckPolicy, DeliverPolicy, PullConsumer},
    message::{Acker, PublishMessage},
    stream,
};
use futures_util::StreamExt;
use work_store::{CommittedRecord, LedgerId, PendingEvent, PointerKey, PublisherPool, StoreError};

use crate::domain::StreamSettings;
use crate::ports::{
    Acked, Bus, BusError, Committed, Inbound, Outbound, Outbox, Pull, PullSpec, Settle,
};

/// The canonical store's outbox over a pool logged in as `work_publisher`.
#[derive(Debug, Clone)]
pub struct PgOutbox {
    pool: PublisherPool,
}

impl PgOutbox {
    /// Over `pool`.
    #[must_use]
    pub const fn new(pool: PublisherPool) -> Self {
        Self { pool }
    }
}

impl Outbox for PgOutbox {
    async fn ledgers(&self, limit: u32) -> Result<Vec<LedgerId>, StoreError> {
        self.pool.outbox_ledgers(limit).await
    }

    async fn pending(
        &self,
        ledger: &LedgerId,
        limit: u32,
    ) -> Result<Vec<PendingEvent>, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let rows = tx.outbox_pending(limit).await?;
        tx.commit().await?;
        Ok(rows)
    }

    async fn remove(&self, ledger: &LedgerId, keys: &[PointerKey]) -> Result<u64, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let n = tx.outbox_remove(keys).await?;
        tx.commit().await?;
        Ok(n)
    }
}

impl Committed for PgOutbox {
    async fn ledgers(&self, limit: u32) -> Result<Vec<LedgerId>, StoreError> {
        self.pool.outbox_ledgers(limit).await
    }

    async fn pending_after(
        &self,
        ledger: &LedgerId,
        after: Option<&PointerKey>,
        limit: u32,
    ) -> Result<Vec<PendingEvent>, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let rows = tx.outbox_pending_after(after, limit).await?;
        tx.commit().await?;
        Ok(rows)
    }

    async fn log_after(
        &self,
        ledger: &LedgerId,
        after: Option<u64>,
        limit: u32,
    ) -> Result<Vec<CommittedRecord>, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let rows = tx.log_after(after, limit).await?;
        tx.commit().await?;
        Ok(rows)
    }
}

/// NATS JetStream.
#[derive(Debug, Clone)]
pub struct JetStreamBus {
    js: jetstream::Context,
    call_timeout: Duration,
}

impl JetStreamBus {
    /// Over `client`; a stream call, a send or an ack not done within `call_timeout` is
    /// [`BusError::TimedOut`] (§18 OP-34 rule 7, T-32 rule 7).
    #[must_use]
    pub fn new(client: async_nats::Client, call_timeout: Duration) -> Self {
        Self {
            js: jetstream::new(client),
            call_timeout,
        }
    }
}

/// The CloudEvents NATS binding's structured-mode content type.
pub const CLOUDEVENTS_JSON: &str = "application/cloudevents+json";

fn unavailable(e: &impl std::fmt::Display) -> BusError {
    BusError::Unavailable(e.to_string())
}

fn bounded<T, E: std::fmt::Display>(
    done: Result<Result<T, E>, tokio::time::error::Elapsed>,
) -> Result<T, BusError> {
    match done {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(unavailable(&e)),
        Err(_) => Err(BusError::TimedOut),
    }
}

impl Bus for JetStreamBus {
    type Ack = Pin<Box<dyn Future<Output = Result<Acked, BusError>> + Send>>;

    async fn ensure_stream(&self, settings: &StreamSettings) -> Result<(), BusError> {
        let config = stream::Config {
            name: settings.name.clone(),
            subjects: vec![settings.filter()],
            retention: stream::RetentionPolicy::Limits,
            storage: stream::StorageType::File,
            num_replicas: settings.replicas,
            max_age: settings.max_age,
            duplicate_window: settings.duplicate_window,
            ..Default::default()
        };
        bounded(timeout(self.call_timeout, self.js.create_or_update_stream(config)).await)?;
        Ok(())
    }

    async fn publish(&self, event: Outbound) -> Result<Self::Ack, BusError> {
        let message = PublishMessage::build()
            .payload(event.payload.into())
            .message_id(&event.msg_id)
            .header("traceparent", event.traceparent.as_str())
            .header("content-type", CLOUDEVENTS_JSON);
        let pending = bounded(
            timeout(
                self.call_timeout,
                self.js.send_publish(event.subject, message),
            )
            .await,
        )?;
        let wait = self.call_timeout;
        Ok(Box::pin(async move {
            bounded(timeout(wait, pending.into_future()).await).map(|ack| Acked {
                duplicate: ack.duplicate,
            })
        }))
    }
}

/// Per-partition durable JetStream pull consumers.
#[derive(Debug)]
pub struct JetStreamPull {
    js: jetstream::Context,
    call_timeout: Duration,
    consumers: Mutex<BTreeMap<String, PullConsumer>>,
}

impl JetStreamPull {
    /// Over `client`; a consumer call or an ack not done within `call_timeout` is
    /// [`BusError::TimedOut`] (T-32 rule 7). A fetch is bounded by its own wait plus
    /// `call_timeout`.
    #[must_use]
    pub fn new(client: async_nats::Client, call_timeout: Duration) -> Self {
        Self {
            js: jetstream::new(client),
            call_timeout,
            consumers: Mutex::new(BTreeMap::new()),
        }
    }

    fn cached(&self, durable: &str) -> Option<PullConsumer> {
        self.consumers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(durable)
            .cloned()
    }

    fn remember(&self, durable: &str, consumer: PullConsumer) {
        self.consumers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(durable.to_owned(), consumer);
    }

    async fn consumer(&self, spec: &PullSpec) -> Result<PullConsumer, BusError> {
        if let Some(c) = self.cached(&spec.durable) {
            return Ok(c);
        }
        let c: PullConsumer = bounded(
            timeout(
                self.call_timeout,
                self.js
                    .get_consumer_from_stream(&spec.durable, &spec.stream),
            )
            .await,
        )?;
        self.remember(&spec.durable, c.clone());
        Ok(c)
    }
}

/// The settle token of a [`JetStreamPull`] delivery.
pub struct PullToken(Acker);

impl std::fmt::Debug for PullToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PullToken").finish_non_exhaustive()
    }
}

impl Pull for JetStreamPull {
    type Token = PullToken;

    async fn ensure_consumer(&self, spec: &PullSpec) -> Result<(), BusError> {
        let max_ack_pending = i64::try_from(spec.max_in_flight)
            .map_err(|_| BusError::Unavailable("max_in_flight out of range".to_owned()))?;
        let stream = bounded(timeout(self.call_timeout, self.js.get_stream(&spec.stream)).await)?;
        let config = consumer::pull::Config {
            durable_name: Some(spec.durable.clone()),
            filter_subject: spec.filter.clone(),
            deliver_policy: DeliverPolicy::All,
            ack_policy: AckPolicy::Explicit,
            ack_wait: spec.ack_wait,
            max_ack_pending,
            ..Default::default()
        };
        let c: PullConsumer =
            bounded(timeout(self.call_timeout, stream.create_consumer(config)).await)?;
        self.remember(&spec.durable, c);
        Ok(())
    }

    async fn fetch(
        &self,
        spec: &PullSpec,
        max: usize,
        wait: Duration,
    ) -> Result<Vec<Inbound<PullToken>>, BusError> {
        let c = self.consumer(spec).await?;
        let pull = async move {
            let mut batch = c
                .batch()
                .max_messages(max)
                .expires(wait)
                .messages()
                .await
                .map_err(|e| unavailable(&e))?;
            let mut out = Vec::with_capacity(max);
            while let Some(next) = batch.next().await {
                let (message, acker) = next.map_err(|e| unavailable(&e))?.split();
                out.push(Inbound {
                    payload: message.payload.to_vec(),
                    token: PullToken(acker),
                });
            }
            Ok::<_, BusError>(out)
        };
        let limit = wait.saturating_add(self.call_timeout);
        timeout(limit, pull).await.map_err(|_| BusError::TimedOut)?
    }

    async fn settle(&self, token: PullToken, how: Settle) -> Result<(), BusError> {
        let kind = match how {
            Settle::Ack => AckKind::Ack,
            Settle::Retry => AckKind::Nak(None),
            Settle::Reject => AckKind::Term,
        };
        match timeout(self.call_timeout, token.0.ack_with(kind)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(BusError::Unavailable(e.to_string())),
            Err(_) => Err(BusError::TimedOut),
        }
    }
}
