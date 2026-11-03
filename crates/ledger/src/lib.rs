//! Work binding of the shared ledger platform (T-7, T-74, P-100, T-85): the genesis that opens a
//! ledger, the `LedgerEnvelope` the sequencer seals for each record, the [`suiss_ledger`] storage
//! port over the store's `work_sequencer` pool, and the leader that takes a ledger under a new
//! epoch and commits batches behind the head compare-and-set and the durability fence, fed by
//! an adaptive group commit with a bounded queue (OP-31, OP-41) and the `Clock` port, and the
//! ledger time adapter behind that port (OP-32, OP-42, OP-43). The engine, the time combiner and
//! the encoding come from the shared crates; nothing here re-implements them (T-31). Records
//! enter through the admission path, which builds each pending record from the kernel's
//! verification, validation and touched items (T-89, T-90). The checkpointer signs each head's
//! checkpoint through `work-signer` as the ledger acknowledgement (P-20, T-88) and mirrors the
//! log to the replica before any witness cosignature is taken (OP-4, OP-33, T-90); the ledgers a
//! process leads are checkpointed on the OP-33 cadence. A ledger's rows beside the log are
//! rebuilt from the canonical log alone through the same append and diffed against the live
//! rows, a difference being a sev-1 signal (OP-1).

mod admit;
mod checkpoint;
mod envelope;
mod error;
mod genesis;
mod group;
mod leader;
mod ledgers;
mod log;
mod rebuild;
mod replica;
pub mod time;
mod witness;

pub use admit::{Arrival, AuthContext, MAX_RECEIVED, Submission, admit};
pub use checkpoint::{
    CheckpointError, Checkpointer, Declaration, DeclarationError, Deployment, SignerClient,
    acknowledgement,
};
pub use envelope::{EventPointer, Inbound, ItemTouch, KeyClaim, PendingRecord, SealedRecord};
pub use error::LedgerError;
pub use genesis::{GenesisInput, genesis};
pub use group::{
    Clock, ClockError, Committed, DEFAULT_MAX_BYTES, DEFAULT_MAX_RECORDS, DEFAULT_QUEUE,
    DEFAULT_RETRY_AFTER, GroupCommit, GroupConfig, GroupConfigError, SubmitError,
};
pub use leader::Leader;
pub use ledgers::{
    CHECKPOINT_TICK, Cadence, CadenceError, CheckpointSetup, CheckpointStats,
    DEFAULT_CHECKPOINT_INTERVAL, DEFAULT_CHECKPOINT_RECORDS, Ledgers, run_checkpoints,
};
pub use log::PgLog;
pub use rebuild::{REBUILD_PAGE, RebuildError, rebuild, rebuild_diff};
pub use replica::{DirectoryReplica, MirrorError};
pub use witness::{Witness, WitnessError, cosignatures};
