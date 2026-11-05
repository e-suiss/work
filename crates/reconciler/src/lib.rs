//! Reconciler: level-triggered, idempotent sync of expected state (T-12); its adapters keep Work's Access pairing state in the canonical database (T-103).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
