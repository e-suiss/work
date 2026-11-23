//! Event dispatcher: outbox to NATS to Relay, webhooks, Executor bindings (T-17). The outbox
//! publisher reads the pointers of one ledger at a time, builds each CloudEvents event from the
//! committed record, publishes it to the T-76 `WORK_EVENTS` stream with `Nats-Msg-Id` and removes
//! the pointer after the JetStream ack (§18 OP-34); NATS is a signal, never canonical (T-21). The
//! consumer pulls per-partition durable consumers and, while NATS is unreachable, falls back to
//! the pending pointers read from its cursor of each ledger (T-18, T-21, T-76, §18 OP-39). Both
//! page through the ledgers with pending pointers by the last id seen (T-83). The Claim
//! delivery worker hands Access the `commitment_active` Claims the sequencer wrote with their
//! records and retries them with a bounded backoff until Access answers (E-8, E-12). The
//! executor doorbell rings each executor's configured webhook, content-free, for every delivery
//! the sequencer wrote, and retries it the same way (E-39, T-105).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

pub use adapters::claims::{AccessClaims, PgClaims};
pub use adapters::doorbell::{HttpRing, PgDoorbells, Webhook};
pub use adapters::relay::RelayCredential;
pub use adapters::{JetStreamBus, JetStreamPull, PgCommitted, PgOutbox, PullToken};
pub use app::claims::{ClaimDeliverer, ClaimError, Delivered};
pub use app::doorbell::{DoorbellError, Doorbells, Rung};
pub use app::{ConsumeError, Consumed, Consumer, DispatchError, Published, Publisher};
pub use domain::claims::ClaimConfig;
pub use domain::doorbell::{DoorbellConfig, RingError};
pub use domain::{
    ConfigError, ConsumerConfig, Event, EventError, Health, PublisherConfig, Seen, StreamSettings,
};
pub use ports::{
    Acked, Bus, BusError, ClaimQueue, ClaimSink, Committed, DoorbellQueue, Handler, HandlerError,
    Inbound, Outbound, Outbox, Pull, PullSpec, Ring, Settle,
};
