//! HTTP and WebSocket layer for every API family: the REST `/v1` router (P-53, T-35), the one common layer every family goes through, with its trace context and `Request-Id` (P-42), gateway limits (P-33), rate limits (P-54 item 9), idempotency and precondition headers (P-54 items 4 and 5), deprecation headers (P-54 item 1) and JSON spelling (P-54 item 8), RFC 9457 problems (T-98 item 6), the read freshness headers (T-97, T-14), the commitment Declaration write route (P-13, E-45), the generated `OpenAPI` document (T-98 item 1, P-54 item 2) and the event entry `POST /v1/inbound/events` (T-102).

pub mod api;
pub mod common;
pub mod conditional;
pub mod deprecation;
pub mod gateway;
pub mod inbound;
pub mod json;
pub mod openapi;
pub mod position;
pub mod problem;
pub mod rate;
pub mod reads;
pub mod writes;
