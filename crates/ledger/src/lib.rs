//! Work binding of the shared ledger platform (T-7, T-74, P-100, T-85): the genesis that opens a
//! ledger, the `LedgerEnvelope` the sequencer seals for each record, the [`suiss_ledger`] storage
//! port over the store's `work_sequencer` pool, and the leader that takes a ledger under a new
//! epoch and commits batches behind the head compare-and-set and the durability fence. The
//! engine and the encoding come from the shared crates; nothing here re-implements them (T-31).

mod envelope;
mod error;
mod genesis;
mod leader;
mod log;

pub use envelope::{EventPointer, ItemChange, PendingRecord, SealedRecord};
pub use error::LedgerError;
pub use genesis::{GenesisInput, genesis};
pub use leader::Leader;
pub use log::PgLog;
