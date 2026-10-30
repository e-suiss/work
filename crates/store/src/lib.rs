//! PostgreSQL access for Work (T-36): the bootstrap SQL and migrations of the canonical `work`
//! and the derived `work_derived` databases (OP-2, T-11), the separate migration step (OP-28),
//! and ledger scope in the type system, so no statement runs outside one ledger's row-level
//! security scope (T-13). Work owns all of this DDL, including the `ledger` schema (log, head,
//! outbox, checkpoint) and the consumer cursors of the derived database (OP-39); the shared `suiss-ledger` crate contributes only a pure engine. All SQL
//! of the workspace lives in this crate.

mod cursor;
mod erasure;
mod error;
mod id;
mod idempotency;
mod migrate;
mod outbox;
mod publisher;
mod scope;
mod sequencer;
mod server;

pub use erasure::{ERASURE_SCOPE, ErasureScope};
pub use error::{AppendError, StoreError};
pub use id::{ItemRef, LedgerId};
pub use idempotency::{
    Admission, CLOCK_UNCERTAINTY_MS, CallerRef, HOT_WINDOW_MS, IdempotencyDecision, IdempotencyKey,
    StoredKey, StoredOutcome,
};
pub use migrate::{Cluster, migrate, migrate_from_env};
pub use outbox::{CommittedRecord, PendingEvent, PointerKey};
pub use publisher::{
    DERIVER_ROLE, DeriverPool, DeriverRole, DiscoveryPool, DiscoveryRole, PUBLISHER_ROLE,
    PublisherPool, PublisherRole,
};
pub use scope::{Head, LedgerTx};
pub use sequencer::{
    AppendBatch, Durability, Genesis, ItemHeadRow, LogRow, NewHead, OutboxRow, SEQUENCER_ROLE,
    SequencerPool, StoredHead,
};
pub use server::{connect, server_version_num};

/// The connection pool type, so other crates need no driver dependency.
pub use sqlx::PgPool as Pool;

/// Cluster roles, created once by the database administrator; idempotent (T-8, OP-12).
pub const BOOTSTRAP_ROLES: &str = include_str!("../bootstrap/roles.sql");

/// The two databases, owned by `work_owner`, created once by the administrator (OP-2).
pub const BOOTSTRAP_DATABASES: &str = include_str!("../bootstrap/databases.sql");
