//! Relay public API client (T-99, T-100, T-17, T-28): the notification intents Work raises from committed records, written into Relay's event request with one mapping, sent at the dated Relay API version Work speaks to the events endpoint Relay's discovery names, and delivered from the outbox, which keeps every intent Relay cannot take now for a later pass with the same idempotency key; waitpoints, escalation policies and ceiling decisions, each only while Relay's discovery offers its capability; and the entry for the events Relay delivers to Work, verified under Relay's product event keys.

pub mod app;
pub mod domain;
pub mod ports;

/// The `Relay-Version` every Relay call carries; it changes only with the code that uses it (T-99 item 2).
pub const RELAY_VERSION: &str = "2026-11-01";
