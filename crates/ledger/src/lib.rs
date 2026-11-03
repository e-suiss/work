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
//! process leads are checkpointed on the OP-33 cadence, and each mirrored checkpoint is sent to
//! the configured witnesses over C2SP `tlog-witness`, their cosignature times checking ledger
//! time and the checkpoints they hold compared against the ledger's tree (OP-32, SEC-32). A ledger's rows beside the log are
//! rebuilt from the canonical log alone through the same append and diffed against the live
//! rows, a difference being a sev-1 signal (OP-1). Bodies are sealed under three key tiers,
//! the ledger KEK in the PKCS#11 token, a class DEK per subject and retention class and a DEK
//! per part, written with their record and opened, or found unreadable after a crypto-shred, on
//! the read path (OP-45); large ciphertexts may go to an S3-compatible store (T-20). The replica
//! is a directory on a single node or an S3 bucket with Object Lock whose objects are written
//! once (OP-33 item 3).

mod admit;
mod body;
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
#[cfg(feature = "s3")]
mod s3;
pub mod time;
mod witness;
#[cfg(feature = "s3")]
mod worm;

pub use admit::{Arrival, AuthContext, MAX_RECEIVED, Submission, admit};
pub use body::{
    BODY_CONTEXT, BodyEraser, BodyError, BodyKeys, BodyOpening, BodyReader, BodyWriter,
    DEFAULT_CALL_TIMEOUT, DEFAULT_CLASS, InDatabase, MAX_MEDIA_TYPE, MAX_PART, ObjectStore,
    PartRead, SealedPart, context, kek_label, object_key, open_part, seal_part,
};
#[cfg(feature = "s3")]
pub use body::S3Store;
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
pub use replica::{
    AnyReplica, DirectoryReplica, MirrorError, Replica, checkpoint_key, cosignature_key, entry_key,
    leaf, put_checkpoint, put_cosignature, put_entry, received_key,
};
#[cfg(feature = "s3")]
pub use replica::WormReplica;
#[cfg(feature = "s3")]
pub use s3::{S3Config, S3Error, tls_trusting};
pub use witness::{
    Comparison, DEFAULT_WITNESS_TIMEOUT, MAX_WITNESS_PAUSE, WITNESS_RECHECK, WITNESS_TICK, Witness,
    WitnessAnswer, WitnessCallError, WitnessClient, WitnessEndpoint, WitnessError, WitnessPass,
    WitnessRole, WitnessSetup, WitnessStates, cosignatures, run_witnessing, witness_tls,
};
#[cfg(feature = "s3")]
pub use worm::{MAX_RETENTION_DAYS, RETENTION_MODE, Retention, WormError, WormStore};
