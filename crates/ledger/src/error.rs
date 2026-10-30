use work_store::StoreError;

/// Why a ledger operation did not happen.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// A value could not be encoded as deterministic CBOR (P-5).
    #[error("encoding: {0}")]
    Encode(#[from] suiss_crypto::dcbor::EncodeError),
    /// The stored head does not fit the engine: a frontier of the wrong size or a position that
    /// overflows.
    #[error("stored head does not fit the engine")]
    Head,
    /// The leader stepped down after a failed commit and must be acquired again (T-85 item 4).
    #[error("leader stepped down")]
    SteppedDown,
    /// The batch was refused before anything was written; the leader stays (§17.1.1 step 9).
    #[error("batch refused: {0}")]
    Refused(StoreError),
    /// The commit failed or its outcome is unknown; the leader stepped down.
    #[error("commit failed: {0}")]
    Failed(StoreError),
    /// The batch was empty or above the engine's batch ceiling.
    #[error("batch size out of range")]
    BatchSize,
    /// The engine and the store disagree about the batch in flight; the leader stepped down.
    #[error("commit outcome does not match the batch in flight")]
    Outcome,
    /// The store refused the operation.
    #[error(transparent)]
    Store(#[from] StoreError),
}
