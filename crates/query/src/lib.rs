//! Query service, permitted next transitions, incremental sync (T-13, T-14, T-26), and the read
//! position token with its bounded wait (T-97); the caller of a request from its Access token
//! (C-9, E-7), the reads scoped to that caller (P-56, P-57, P-20) and the commitment
//! Declarations it writes under Access's authority (P-13, P-21, E-13, E-45).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
