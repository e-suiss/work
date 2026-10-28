use sqlx::{Acquire, PgConnection, PgPool, Postgres, Transaction};

use crate::{LedgerId, StoreError};

/// A transaction scoped to one ledger (T-13, T-36 rule 3): `begin` sets `app.ledger_id`
/// with `set_config(…, true)` before anything else, so the scope ends with the transaction.
/// It is not an executor; statements run only through the methods of this crate, so an
/// unscoped query does not compile:
///
/// ```compile_fail
/// # async fn f(tx: &mut work_store::LedgerTx<'_>) {
/// sqlx::query("SELECT 1").execute(tx).await;
/// # }
/// ```
pub struct LedgerTx<'c> {
    tx: Transaction<'c, Postgres>,
    ledger: LedgerId,
}

type HeadRow = (i64, i64, Option<Vec<u8>>, Option<i64>);

/// The sequencing head of a ledger (OP-5, OP-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// Position of the last record; `None` before the first.
    pub pos: Option<u64>,
    /// Fencing epoch (OP-10).
    pub epoch: u64,
    /// Leaf hash of the last record.
    pub leaf: Option<[u8; 32]>,
    /// Ledger time of the last record, Unix milliseconds.
    pub recorded_at_ms: Option<i64>,
}

impl LedgerTx<'static> {
    /// Opens a transaction on `pool` scoped to `ledger`.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Scope`] if the setting did not take.
    pub async fn begin(pool: &PgPool, ledger: &LedgerId) -> Result<Self, StoreError> {
        Self::scoped(pool.begin().await?, ledger).await
    }
}

impl<'c> LedgerTx<'c> {
    /// Opens a transaction on `conn` scoped to `ledger`.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Scope`] if the setting did not take.
    pub async fn begin_on(
        conn: &'c mut PgConnection,
        ledger: &LedgerId,
    ) -> Result<Self, StoreError> {
        Self::scoped(conn.begin().await?, ledger).await
    }

    async fn scoped(
        mut tx: Transaction<'c, Postgres>,
        ledger: &LedgerId,
    ) -> Result<Self, StoreError> {
        let hex = ledger.to_hex();
        let set: Option<String> =
            sqlx::query_scalar("SELECT set_config('app.ledger_id', $1, true)")
                .bind(&hex)
                .fetch_one(&mut *tx)
                .await?;
        if set.as_deref() != Some(hex.as_str()) {
            return Err(StoreError::Scope);
        }
        Ok(Self {
            tx,
            ledger: *ledger,
        })
    }

    /// The scope.
    #[must_use]
    pub const fn ledger(&self) -> &LedgerId {
        &self.ledger
    }

    #[allow(dead_code, reason = "the write paths of later stages run through it")]
    pub(crate) fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// The ledger's head, or `None` if the ledger is not opened or not visible to the role.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn head(&mut self) -> Result<Option<Head>, StoreError> {
        let row: Option<HeadRow> = sqlx::query_as(
            "SELECT pos, epoch, head_leaf::bytea, \
             (extract(epoch FROM head_recorded_at) * 1000)::bigint \
             FROM ledger.head WHERE ledger_id = $1",
        )
        .bind(self.ledger.as_bytes().as_slice())
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some((pos, epoch, leaf, recorded_at_ms)) = row else {
            return Ok(None);
        };
        let pos = match pos {
            -1 => None,
            p => Some(u64::try_from(p).map_err(|_| StoreError::Corrupt)?),
        };
        let leaf = leaf
            .map(|l| <[u8; 32]>::try_from(l.as_slice()).map_err(|_| StoreError::Corrupt))
            .transpose()?;
        Ok(Some(Head {
            pos,
            epoch: u64::try_from(epoch).map_err(|_| StoreError::Corrupt)?,
            leaf,
            recorded_at_ms,
        }))
    }

    /// Commits.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn commit(self) -> Result<(), StoreError> {
        Ok(self.tx.commit().await?)
    }

    /// Rolls back.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn rollback(self) -> Result<(), StoreError> {
        Ok(self.tx.rollback().await?)
    }
}
