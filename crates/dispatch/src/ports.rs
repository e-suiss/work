//! Ports of the publisher (T-32 rule 2): `Outbox`, the pending pointers of one ledger and their
//! removal after the ack (§18 OP-34), and `Bus`, the NATS JetStream signal (T-17, T-21, T-76).

use std::future::Future;

use work_store::{LedgerId, PendingEvent, PointerKey, StoreError};

use crate::domain::StreamSettings;

/// The outbox of the canonical store.
pub trait Outbox: Send + Sync {
    /// Up to `limit` pending pointers of `ledger` in `(pos, event_id)` order.
    fn pending(
        &self,
        ledger: &LedgerId,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<PendingEvent>, StoreError>> + Send;

    /// Removes the acknowledged pointers `keys` of `ledger`; returns how many were present.
    fn remove(
        &self,
        ledger: &LedgerId,
        keys: &[PointerKey],
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// One event to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// NATS subject (T-76 rule 1).
    pub subject: String,
    /// `Nats-Msg-Id`, the CloudEvents `id` (T-76 rule 3).
    pub msg_id: String,
    /// W3C `traceparent` header (§15 P-42).
    pub traceparent: String,
    /// Structured-mode CloudEvents JSON.
    pub payload: Vec<u8>,
}

/// The JetStream ack of one publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acked {
    /// The stream had already stored this `Nats-Msg-Id` inside the duplicate window.
    pub duplicate: bool,
}

/// Why the bus did not take or acknowledge a publish; never a correctness failure (T-21).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BusError {
    /// NATS did not answer in time.
    #[error("nats timed out")]
    TimedOut,
    /// NATS refused or could not take the call.
    #[error("nats: {0}")]
    Unavailable(String),
}

/// NATS JetStream.
pub trait Bus: Send + Sync {
    /// The pending ack of a sent publish.
    type Ack: Future<Output = Result<Acked, BusError>> + Send;

    /// Creates the stream or brings its configuration to `settings` (T-76).
    fn ensure_stream(
        &self,
        settings: &StreamSettings,
    ) -> impl Future<Output = Result<(), BusError>> + Send;

    /// Sends `event`; the returned future resolves with the JetStream ack.
    fn publish(&self, event: Outbound) -> impl Future<Output = Result<Self::Ack, BusError>> + Send;
}
