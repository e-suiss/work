//! Event dispatcher: outbox to NATS to Relay, webhooks, Executor bindings (T-17). The outbox
//! publisher reads the pointers of one ledger at a time, builds each CloudEvents event from the
//! committed record, publishes it to the T-76 `WORK_EVENTS` stream with `Nats-Msg-Id` and removes
//! the pointer after the JetStream ack (§18 OP-34); NATS is a signal, never canonical (T-21). The
//! consumer pulls per-partition durable consumers and, while NATS is unreachable, falls back to
//! the pending pointers read from its cursor of each ledger (T-18, T-21, T-76, §18 OP-39). Both
//! page through the ledgers with pending pointers by the last id seen (T-83).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

pub use adapters::{JetStreamBus, JetStreamPull, PgCommitted, PgOutbox, PullToken};
pub use app::{ConsumeError, Consumed, Consumer, DispatchError, Published, Publisher};
pub use domain::{
    ConfigError, ConsumerConfig, Event, EventError, Health, PublisherConfig, Seen, StreamSettings,
};
pub use ports::{
    Acked, Bus, BusError, Committed, Handler, HandlerError, Inbound, Outbound, Outbox, Pull,
    PullSpec, Settle,
};
