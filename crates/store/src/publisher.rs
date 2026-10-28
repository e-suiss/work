//! The publisher's pool (T-80, T-17, §18 OP-34): the one place a statement runs without a
//! ledger scope. [`PublisherPool::outbox_ledgers`] calls `ledger.outbox_ledgers`, the `SECURITY
//! DEFINER` function only `work_publisher` may execute, which returns the ids of ledgers with
//! pending outbox pointers and nothing of their rows; everything else goes through a
//! [`LedgerTx`] (T-13).

use sqlx::PgPool;

use crate::{LedgerId, LedgerTx, StoreError};

/// The login role a [`PublisherPool`] must have.
pub const PUBLISHER_ROLE: &str = "work_publisher";

/// A pool checked to act as `work_publisher`. It is not an executor; besides opening a
/// [`LedgerTx`] its only statement is the cross-ledger discovery, so an unscoped query does not
/// compile:
///
/// ```compile_fail
/// # async fn f(p: &work_store::PublisherPool) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PublisherPool {
    pool: PgPool,
}

impl PublisherPool {
    /// Over `pool` after checking that its role is `work_publisher` or holds its privileges
    /// (T-79: the login role is granted at deployment).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        let publisher: bool =
            sqlx::query_scalar("SELECT pg_catalog.pg_has_role(current_user, $1, 'USAGE')")
                .bind(PUBLISHER_ROLE)
                .fetch_one(&pool)
                .await?;
        if !publisher {
            return Err(StoreError::Role);
        }
        Ok(Self { pool })
    }

    /// Up to `limit` ids of ledgers with pending outbox pointers, in ascending byte order.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed id.
    pub async fn outbox_ledgers(&self, limit: u32) -> Result<Vec<LedgerId>, StoreError> {
        let rows: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT l::bytea FROM ledger.outbox_ledgers($1) AS t(l)")
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await?;
        rows.iter()
            .map(|raw| {
                <[u8; 32]>::try_from(raw.as_slice())
                    .map(LedgerId::from_bytes)
                    .map_err(|_| StoreError::Corrupt)
            })
            .collect()
    }

    /// Opens a transaction scoped to `ledger`.
    ///
    /// # Errors
    /// See [`LedgerTx::begin`].
    pub async fn begin(&self, ledger: &LedgerId) -> Result<LedgerTx<'static>, StoreError> {
        LedgerTx::begin(&self.pool, ledger).await
    }
}
