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
}
