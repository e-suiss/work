//! The approved schema of the canonical and derived databases against real PostgreSQL 18
//! (T-36 rules 6 and 7, T-37 rule 9): schema security checks and behaviour of every guard.
//! These tests need Docker; `just test-containers` runs them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

mod canonical;
mod derived;
mod env;
mod schema;
