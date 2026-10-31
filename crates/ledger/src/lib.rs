//! Work binding of the shared ledger platform (T-7, T-74, P-100, T-85): the genesis that opens a
//! ledger, the `LedgerEnvelope` the sequencer seals for each record, the [`suiss_ledger`] storage
//! port over the store's `work_sequencer` pool, and the leader that takes a ledger under a new
//! epoch and commits batches behind the head compare-and-set and the durability fence, fed by
//! an adaptive group commit with a bounded queue (OP-31, OP-41) and the `Clock` port. The
//! engine and the encoding come from the shared crates; nothing here re-implements them (T-31).

mod envelope;
mod error;
mod genesis;
mod group;
mod leader;
mod log;

pub use envelope::{EventPointer, ItemChange, KeyClaim, PendingRecord, SealedRecord};
pub use error::LedgerError;
pub use genesis::{GenesisInput, genesis};
pub use group::{
    Clock, ClockError, Committed, DEFAULT_MAX_BYTES, DEFAULT_MAX_RECORDS, DEFAULT_QUEUE,
    DEFAULT_RETRY_AFTER, GroupCommit, GroupConfig, GroupConfigError, SubmitError,
};
pub use leader::Leader;
pub use log::PgLog;
