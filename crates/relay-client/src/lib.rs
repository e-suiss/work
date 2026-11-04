//! Relay public API client: wait points and notification requests, at the dated Relay API version Work speaks (T-99 item 2).

/// The `Relay-Version` every Relay call carries; it changes only with the code that uses it (T-99 item 2).
pub const RELAY_VERSION: &str = "2026-11-01";
