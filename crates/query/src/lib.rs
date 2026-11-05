//! Query service, permitted next transitions, incremental sync (T-13, T-14, T-26), and the read
//! position token with its bounded wait (T-97); the caller of a request from its Access token
//! (C-9, E-7) and the reads scoped to that caller (P-56, P-57, P-20).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
