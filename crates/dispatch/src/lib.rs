//! Event dispatcher: outbox to NATS to Relay, webhooks, Executor bindings (T-17). The outbox
//! publisher reads the pointers of one ledger at a time, builds each CloudEvents event from the
//! committed record, publishes it to the T-76 `WORK_EVENTS` stream with `Nats-Msg-Id` and removes
//! the pointer after the JetStream ack (§18 OP-34); NATS is a signal, never canonical (T-21).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

pub use adapters::{JetStreamBus, PgOutbox};
pub use app::{DispatchError, Published, Publisher};
pub use domain::{ConfigError, PublisherConfig, StreamSettings};
pub use ports::{Acked, Bus, BusError, Outbound, Outbox};
