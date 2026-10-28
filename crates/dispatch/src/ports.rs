//! Ports of the publisher and the consumer (T-32 rule 2): `Outbox`, the ledgers with pending
//! pointers, the pending pointers of one ledger and their removal after the ack (§18 OP-34);
//! `Bus`, the NATS JetStream signal (T-17, T-21, T-76); `Pull`, the per-partition durable pull
//! consumers (T-76 rule 6); `Handler`, what a consumer hands each event to; and `Committed`, the
//! cursor scans of committed state a consumer falls back to while NATS is unreachable, resumed
//! from the consumer's cursor (T-21, §18 OP-39). Ledger discovery pages by the last id seen
//! (T-83).

use std::future::Future;
use std::time::Duration;

use work_store::{CommittedRecord, LedgerId, PendingEvent, PointerKey, StoreError};

use crate::domain::{Event, StreamSettings};

/// The outbox of the canonical store.
pub trait Outbox: Send + Sync {
    /// Up to `limit` ledgers with pending pointers above `after`, in ascending byte order
    /// (OP-34, T-83).
    fn ledgers(
        &self,
        after: Option<&LedgerId>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<LedgerId>, StoreError>> + Send;

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

/// One durable pull consumer of one partition (T-76 rule 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullSpec {
    /// Stream name.
    pub stream: String,
    /// Durable consumer name, `<group>-p<p>`.
    pub durable: String,
    /// The partition's subject filter.
    pub filter: String,
    /// Unacknowledged messages the consumer may hold.
    pub max_in_flight: usize,
    /// How long JetStream waits for an ack before redelivering.
    pub ack_wait: Duration,
}

/// A pulled message and the token that settles it.
#[derive(Debug)]
pub struct Inbound<T> {
    /// Structured-mode CloudEvents JSON.
    pub payload: Vec<u8>,
    /// Settles this delivery through [`Pull::settle`].
    pub token: T,
}

/// How a delivery is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settle {
    /// Handled, or a repeat of a handled event.
    Ack,
    /// Not handled now; JetStream redelivers it.
    Retry,
    /// Not a Work event; never redelivered.
    Reject,
}

/// Per-partition durable pull consumers over the T-76 stream.
pub trait Pull: Send + Sync {
    /// Settles one delivery.
    type Token: Send;

    /// Creates the durable consumer or brings its configuration to `spec`.
    fn ensure_consumer(&self, spec: &PullSpec)
    -> impl Future<Output = Result<(), BusError>> + Send;

    /// Up to `max` messages of `spec`'s consumer, waiting at most `wait` for them.
    fn fetch(
        &self,
        spec: &PullSpec,
        max: usize,
        wait: Duration,
    ) -> impl Future<Output = Result<Vec<Inbound<Self::Token>>, BusError>> + Send;

    /// Settles a delivery.
    fn settle(
        &self,
        token: Self::Token,
        how: Settle,
    ) -> impl Future<Output = Result<(), BusError>> + Send;
}

/// The handler did not take an event now; it is offered again (T-18: the receiver re-reads
/// state when in doubt).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("handler: {0}")]
pub struct HandlerError(pub String);

/// What a consumer hands each event to. It may see an event more than once and in any order
/// (T-18); its result never depends on either.
pub trait Handler: Send + Sync {
    /// Takes `event`.
    fn handle(&self, event: &Event) -> impl Future<Output = Result<(), HandlerError>> + Send;
}

/// Committed state, read while NATS is unreachable (T-21, §18 OP-34 rule 2).
pub trait Committed: Send + Sync {
    /// Up to `limit` ledgers with pending pointers above `after`, in ascending byte order
    /// (T-83).
    fn ledgers(
        &self,
        after: Option<&LedgerId>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<LedgerId>, StoreError>> + Send;

    /// The last pointer key of `ledger` whose effect consumer `group` applied (§18 OP-39), or
    /// `None` before the first.
    fn cursor(
        &self,
        ledger: &LedgerId,
        group: &str,
    ) -> impl Future<Output = Result<Option<PointerKey>, StoreError>> + Send;

    /// Up to `limit` pending pointers of `ledger` after `after`, in `(pos, event_id)` order.
    fn pending_after(
        &self,
        ledger: &LedgerId,
        after: Option<&PointerKey>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<PendingEvent>, StoreError>> + Send;

    /// Up to `limit` committed log rows of `ledger` above the cursor position `after`.
    fn log_after(
        &self,
        ledger: &LedgerId,
        after: Option<u64>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<CommittedRecord>, StoreError>> + Send;
}
