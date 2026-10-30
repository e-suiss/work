//! The discovery pools (T-80, T-82, T-83, T-17, §18 OP-34): the one place a statement runs
//! without a ledger scope. [`DiscoveryPool::outbox_ledgers`] calls `ledger.outbox_ledgers`, the
//! `SECURITY DEFINER` function only `work_publisher` and `work_deriver` may execute, which returns
//! the ids of ledgers with pending outbox pointers after a given id and nothing of their rows;
//! everything else goes through a [`LedgerTx`] (T-13). The publisher holds a [`PublisherPool`],
//! a consumer's fallback to committed state a [`DeriverPool`] (T-21).

use std::marker::PhantomData;

use sqlx::PgPool;

use crate::{LedgerId, LedgerTx, StoreError};

/// The login role a [`PublisherPool`] must have.
pub const PUBLISHER_ROLE: &str = "work_publisher";

/// The login role a [`DeriverPool`] must have (T-82).
pub const DERIVER_ROLE: &str = "work_deriver";

pub(crate) async fn check_role(pool: &PgPool, role: &str) -> Result<(), StoreError> {
    let member: bool =
        sqlx::query_scalar("SELECT pg_catalog.pg_has_role(current_user, $1, 'USAGE')")
            .bind(role)
            .fetch_one(pool)
            .await?;
    if member {
        Ok(())
    } else {
        Err(StoreError::Role)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A role that may discover the ledgers with pending outbox pointers (T-82).
pub trait DiscoveryRole: sealed::Sealed + Send + Sync + 'static {
    /// The login role.
    const NAME: &'static str;
}

/// `work_publisher`: reads and removes outbox pointers (OP-34).
#[derive(Debug, Clone, Copy)]
pub enum PublisherRole {}

/// `work_deriver`: reads outbox pointers and the log, removes nothing (T-82).
#[derive(Debug, Clone, Copy)]
pub enum DeriverRole {}

impl sealed::Sealed for PublisherRole {}
impl sealed::Sealed for DeriverRole {}

impl DiscoveryRole for PublisherRole {
    const NAME: &'static str = PUBLISHER_ROLE;
}

impl DiscoveryRole for DeriverRole {
    const NAME: &'static str = DERIVER_ROLE;
}

/// A pool checked to act as `R`. It is not an executor; besides opening a [`LedgerTx`] its only
/// statement is the cross-ledger discovery, so an unscoped query does not compile:
///
/// ```compile_fail
/// # async fn f(p: &work_store::PublisherPool) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
///
/// ```compile_fail
/// # async fn f(p: &work_store::DeriverPool) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct DiscoveryPool<R> {
    pool: PgPool,
    role: PhantomData<R>,
}

/// The publisher's pool, logged in as `work_publisher`.
pub type PublisherPool = DiscoveryPool<PublisherRole>;

/// A consumer's pool on the canonical database, logged in as `work_deriver` (T-82).
pub type DeriverPool = DiscoveryPool<DeriverRole>;

impl<R: DiscoveryRole> DiscoveryPool<R> {
    /// Over `pool` after checking that its role is `R` or holds its privileges (T-79: the login
    /// role is granted at deployment).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        check_role(&pool, R::NAME).await?;
        Ok(Self {
            pool,
            role: PhantomData,
        })
    }

    /// Up to `limit` ids of ledgers with pending outbox pointers, in ascending byte order, all
    /// above `after` (from the lowest for `None`); a page shorter than `limit` is the last
    /// (T-83).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed id.
    pub async fn outbox_ledgers(
        &self,
        after: Option<&LedgerId>,
        limit: u32,
    ) -> Result<Vec<LedgerId>, StoreError> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT l::bytea FROM ledger.outbox_ledgers($1::bytea::ledger.digest32, $2) AS t(l)",
        )
        .bind(after.map(|l| l.as_bytes().as_slice()))
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
