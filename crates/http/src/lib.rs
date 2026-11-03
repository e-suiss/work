//! HTTP and WebSocket layer for every API family: RFC 9457 problems (T-98 item 6), the read
//! freshness headers (T-97) and the generated `OpenAPI` document (T-98 item 1, P-54 item 2).

pub mod openapi;
pub mod position;
pub mod problem;
