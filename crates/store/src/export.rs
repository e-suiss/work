//! What an export reads (P-2 items 2 and 3, T-10): [`ExportLog`] reads a ledger's canonical log with the externally signed bytes each record was received as, through [`CanonicalLog`], and its signed checkpoints with the witness cosignatures taken for them; it has no statement but [`EXPORT_READS`], all of them over [`EXPORT_INPUTS`], so a derived view cannot enter a bundle as canonical.

use sqlx::PgPool;

use crate::checkpoint::{StoredCheckpoint, checkpoint_row};
use crate::rebuild::{LOG_PAGE, RECEIVED_PAGE};
use crate::{
    CanonicalEntry, CanonicalLog, CheckpointRow, CosignatureRow, LedgerId, LedgerTx, StoreError,
};

/// The only tables an export reads, every one of them CANONICAL (T-10).
pub const EXPORT_INPUTS: [&str; 5] = [
    "ledger.log",
    "work.log_received",
    "work.received_bytes",
    "ledger.checkpoint",
    "ledger.checkpoint_cosignature",
];

const CHECKPOINTS: &str = include_str!("../queries/export/checkpoints.sql");

const COSIGNATURES: &str = include_str!("../queries/export/cosignatures.sql");

/// The statements of [`ExportLog`], the whole of what an export reads.
pub const EXPORT_READS: [&str; 4] = [LOG_PAGE, RECEIVED_PAGE, CHECKPOINTS, COSIGNATURES];

/// A signed checkpoint with the witness cosignatures taken for it, in witness order.
pub type CosignedCheckpoint = (CheckpointRow, Vec<CosignatureRow>);

/// The canonical rows of a ledger as an export reads them, over a pool logged in as
/// `work_app`. It is not an executor:
///
/// ```compile_fail
/// # async fn f(p: &work_store::ExportLog) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ExportLog {
    log: CanonicalLog,
    pool: PgPool,
}

impl ExportLog {
    /// Over `pool` after checking that its role is `work_app` or holds its privileges.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        let log = CanonicalLog::new(pool.clone()).await?;
        Ok(Self { log, pool })
    }

    /// Up to `limit` entries of `ledger` from position `from` on, in position order, each with
    /// the received bytes linked to it.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range or unknown value.
    pub async fn entries(
        &self,
        ledger: &LedgerId,
        from: u64,
        limit: u32,
    ) -> Result<Vec<CanonicalEntry>, StoreError> {
        self.log.entries(ledger, from, limit).await
    }

    /// Every stored checkpoint of `ledger` in size order, each with its witness cosignatures.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn checkpoints(
        &self,
        ledger: &LedgerId,
    ) -> Result<Vec<CosignedCheckpoint>, StoreError> {
        let id = *ledger.as_bytes();
        let mut tx = LedgerTx::begin_snapshot(&self.pool, ledger).await?;
        let rows = sqlx::query_file_as!(
            StoredCheckpoint,
            "queries/export/checkpoints.sql",
            id.as_slice()
        )
        .fetch_all(tx.conn())
        .await?;
        let cosigned = sqlx::query_file!("queries/export/cosignatures.sql", id.as_slice())
            .fetch_all(tx.conn())
            .await?;
        tx.rollback().await?;
        let mut out = rows
            .into_iter()
            .map(|r| checkpoint_row(r).map(|c| (c, Vec::new())))
            .collect::<Result<Vec<CosignedCheckpoint>, StoreError>>()?;
        for r in cosigned {
            let size = u64::try_from(r.size).map_err(|_| StoreError::Corrupt)?;
            let at = out
                .binary_search_by_key(&size, |(c, _)| c.size)
                .map_err(|_| StoreError::Corrupt)?;
            let (_, list) = out.get_mut(at).ok_or(StoreError::Corrupt)?;
            list.push(CosignatureRow {
                size,
                witness_id: r.witness_id,
                cosigned_at_ms: u64::try_from(r.at).map_err(|_| StoreError::Corrupt)?,
                signature: r.signature,
            });
        }
        Ok(out)
    }
}
