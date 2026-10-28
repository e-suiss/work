//! Adapters of the publisher ports: [`PgOutbox`] over the canonical store, connected as
//! `work_publisher` (§18 OP-34, T-73 rule 2), and [`JetStreamBus`] over NATS JetStream with the
//! T-76 stream, `Nats-Msg-Id`, `traceparent` and the CloudEvents structured content type.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use async_nats::jetstream::{self, message::PublishMessage, stream};
use work_store::{LedgerId, LedgerTx, PendingEvent, PointerKey, Pool, StoreError};

use crate::domain::StreamSettings;
use crate::ports::{Acked, Bus, BusError, Outbound, Outbox};

/// The canonical store's outbox; the pool must log in as `work_publisher`.
#[derive(Debug, Clone)]
pub struct PgOutbox {
    pool: Pool,
}

impl PgOutbox {
    /// Over `pool`.
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

impl Outbox for PgOutbox {
    async fn pending(
        &self,
        ledger: &LedgerId,
        limit: u32,
    ) -> Result<Vec<PendingEvent>, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let rows = tx.outbox_pending(limit).await?;
        tx.commit().await?;
        Ok(rows)
    }

    async fn remove(&self, ledger: &LedgerId, keys: &[PointerKey]) -> Result<u64, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let n = tx.outbox_remove(keys).await?;
        tx.commit().await?;
        Ok(n)
    }
}

/// NATS JetStream.
#[derive(Debug, Clone)]
pub struct JetStreamBus {
    js: jetstream::Context,
    ack_timeout: Duration,
}

impl JetStreamBus {
    /// Over `client`; an ack not received within `ack_timeout` is [`BusError::TimedOut`].
    #[must_use]
    pub fn new(client: async_nats::Client, ack_timeout: Duration) -> Self {
        Self {
            js: jetstream::new(client),
            ack_timeout,
        }
    }
}

/// The CloudEvents NATS binding's structured-mode content type.
pub const CLOUDEVENTS_JSON: &str = "application/cloudevents+json";

fn unavailable(e: &impl std::fmt::Display) -> BusError {
    BusError::Unavailable(e.to_string())
}

impl Bus for JetStreamBus {
    type Ack = Pin<Box<dyn Future<Output = Result<Acked, BusError>> + Send>>;

    async fn ensure_stream(&self, settings: &StreamSettings) -> Result<(), BusError> {
        self.js
            .create_or_update_stream(stream::Config {
                name: settings.name.clone(),
                subjects: vec![settings.filter()],
                retention: stream::RetentionPolicy::Limits,
                storage: stream::StorageType::File,
                max_age: settings.max_age,
                duplicate_window: settings.duplicate_window,
                ..Default::default()
            })
            .await
            .map_err(|e| unavailable(&e))?;
        Ok(())
    }

    async fn publish(&self, event: Outbound) -> Result<Self::Ack, BusError> {
        let message = PublishMessage::build()
            .payload(event.payload.into())
            .message_id(&event.msg_id)
            .header("traceparent", event.traceparent.as_str())
            .header("content-type", CLOUDEVENTS_JSON);
        let pending = self
            .js
            .send_publish(event.subject, message)
            .await
            .map_err(|e| unavailable(&e))?;
        let wait = self.ack_timeout;
        Ok(Box::pin(async move {
            match tokio::time::timeout(wait, pending.into_future()).await {
                Ok(Ok(ack)) => Ok(Acked {
                    duplicate: ack.duplicate,
                }),
                Ok(Err(e)) => Err(unavailable(&e)),
                Err(_) => Err(BusError::TimedOut),
            }
        }))
    }
}
