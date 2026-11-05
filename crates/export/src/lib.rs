//! Export and offline verification of a ledger's canonical records (P-2, T-10): the `work-export/1` bundle of the canonical log, the bytes each record was received as and the signed checkpoints, written from canonical tables only and verified without a database, the network or Access, through the kernel; replay into a database is `work-cli rebuild`.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
