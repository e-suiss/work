use crate::ItemRef;

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database rejected or could not run the statement.
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    /// A migration could not be applied or an applied one changed (OP-28).
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The transaction did not take the ledger scope (T-13).
    #[error("ledger scope was not applied")]
    Scope,
    /// The pool does not log in as the role the operation needs.
    #[error("connected as the wrong database role")]
    Role,
    /// A stored row does not match the model.
    #[error("stored row is malformed")]
    Corrupt,
    /// The ledger has no head: it was never opened or is not visible to the role (P-100).
    #[error("ledger is not opened")]
    NotOpened,
    /// The ledger already has a head (P-100).
    #[error("ledger is already opened")]
    AlreadyOpened,
    /// The stored head does not match the last log row, so leadership is refused (T-85).
    #[error("stored head diverges from the log")]
    Diverged,
    /// The ledger is not led in the node's cell: the request was routed here by a wrong
    /// placement directory entry, so leadership is refused (OP-9 item 5).
    #[error("ledger is not led in this cell")]
    Misrouted,
    /// The node does not support every version the ledger's log has activated, so leadership
    /// is refused (OP-28 item 3).
    #[error("node does not support the ledger's active versions")]
    Unsupported,
    /// Another node holds a live sequencer lease on the ledger (T-85 item 4, §17.12).
    #[error("sequencer lease held by another node")]
    LeaseHeld,
    /// The sequencer lease expired, was released or was taken under a later epoch (§17.12).
    #[error("sequencer lease lost")]
    LeaseLost,
    /// The head is no longer at the expected position under the expected epoch (OP-5, OP-10).
    #[error("head moved or epoch is stale")]
    HeadMoved,
    /// The item's stored version or last position is not the one the batch extends (P-29).
    #[error("item head conflict: {0:?}")]
    ItemConflict(ItemRef),
    /// The caller's idempotency key is already stored in a hot partition (OP-8, OP-36).
    #[error("idempotency key already recorded")]
    KeyReused,
    /// A record with the same record id is already in the ledger (P-79, OP-38 item 5).
    #[error("record already in the ledger")]
    RecordExists,
    /// The inbound event or federated record is already seen in a hot partition (OP-8, OP-38
    /// item 5).
    #[error("inbound event already seen")]
    InboundSeen,
    /// An outbox pointer names an item its record does not touch (T-81 item 2).
    #[error("outbox pointer without its item head: {0:?}")]
    OutboxItem(ItemRef),
    /// A row of the batch breaks the named constraint (T-90, OP-13).
    #[error("row refused by constraint {0}")]
    Constraint(String),
}

/// How [`crate::SequencerPool::append`] failed: the two outcomes the ledger engine tells apart
/// (T-74).
#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    /// Nothing was written, for a reason that is not about leadership; the writer stays leader.
    #[error("append refused: {0}")]
    Refused(StoreError),
    /// The head moved, the epoch is stale, the database failed, or the outcome is unknown; the
    /// writer steps down and rebuilds from storage.
    #[error("append failed: {0}")]
    Failed(StoreError),
}
