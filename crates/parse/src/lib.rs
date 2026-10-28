//! Every parser (CBOR, JSON, `CloudEvents`, A2A, MCP); limits apply before decoding (P-7, P-33). The secret scanner of the parser worker lives in [`secret`] (SEC-35).

pub mod secret;
