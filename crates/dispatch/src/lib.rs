//! Event dispatcher: outbox to NATS to Relay, webhooks, Executor bindings (T-17).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
