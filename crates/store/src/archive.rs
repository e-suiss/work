//! The archive role's storage (§18 OP-35, OP-34 item 5, OP-37, OP-38 item 4, Access OP-73 rule
//! 4): the cold monthly partitions of `work.idempotency_key` and `work.inbound_seen`, the ledgers
//! a cold partition holds, each ledger's slice as the row text its digest is computed over, the
//! append-only records of verified WORM copies, and the one drop of a partition every slice of
//! which has its record, all as `work_archive`. Row text is rendered in UTC, as the drop
//! function renders it.

use sqlx::PgPool;

use crate::publisher::check_role;
use crate::{LedgerId, LedgerTx, StoreError};

/// The login role an [`ArchivePool`] must have.
pub const ARCHIVE_ROLE: &str = "work_archive";

/// The partitioned tables whose cold partitions are archived (OP-37 item 1).
pub const ARCHIVED_TABLES: [&str; 2] = ["work.idempotency_key", "work.inbound_seen"];

/// One ledger's rows in a cold partition: the text of each row, in the order the digest takes
/// them, with the count and digest the database gives.
#[derive(Clone, PartialEq, Eq)]
pub struct PartitionSlice {
    /// Rows, as the database counts them.
    pub row_count: u64,
    /// SHA-256 of the rows joined by line feeds, as the database computes it.
    pub digest: [u8; 32],
    /// Each row's text, ordered bytewise.
    pub rows: Vec<String>,
}

impl std::fmt::Debug for PartitionSlice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartitionSlice")
            .field("row_count", &self.row_count)
            .finish_non_exhaustive()
    }
}

/// The record of a verified WORM copy of one ledger's slice (OP-35 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveRecord {
    /// The object key of the copy.
    pub object_key: String,
    /// SHA-256 of the copy, the slice digest.
    pub copy_digest: [u8; 32],
    /// Rows in the copy.
    pub row_count: u64,
}

/// The archive role's pool, logged in as `work_archive`.
#[derive(Debug, Clone)]
pub struct ArchivePool {
    pool: PgPool,
}

type SliceRow = (i64, Vec<u8>);
type RecordRow = (String, Vec<u8>, i64);

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn digest(raw: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(raw).map_err(|_| StoreError::Corrupt)
}

/// The parent of `part` by its name, `work.<table>_pYYYYMM`.
fn parent(part: &str) -> Result<&'static str, StoreError> {
    let month = |rest: &str| rest.len() == 6 && rest.bytes().all(|b| b.is_ascii_digit());
    ARCHIVED_TABLES
        .into_iter()
        .find(|t| {
            part.strip_prefix(t)
                .and_then(|r| r.strip_prefix("_p"))
                .is_some_and(month)
        })
        .ok_or_else(|| StoreError::Constraint("not_an_archivable_partition".to_owned()))
}

fn refused(e: sqlx::Error) -> StoreError {
    let message = e.as_database_error().and_then(|d| {
        matches!(
            d.code().as_deref(),
            Some("22000" | "22023" | "55006" | "23505")
        )
        .then(|| d.message().to_owned())
    });
    message.map_or(StoreError::Db(e), StoreError::Constraint)
}

impl ArchivePool {
    /// Over `pool` after checking that its role is `work_archive` or holds its privileges.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        check_role(&pool, ARCHIVE_ROLE).await?;
        Ok(Self { pool })
    }

    /// The database clock in Unix milliseconds, the clock the drop function judges coldness by.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] before 1970.
    pub async fn now_ms(&self) -> Result<u64, StoreError> {
        let ms: i64 = sqlx::query_scalar(
            "SELECT (extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&self.pool)
        .await?;
        unsigned(ms)
    }

    /// The partitions of the archived tables whose range ended at least 30 days ago (OP-36
    /// item 2), by name.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn cold_partitions(&self) -> Result<Vec<String>, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL timezone = 'UTC'")
            .execute(&mut *tx)
            .await?;
        let parts: Vec<String> = sqlx::query_scalar(
            "SELECT c.oid::regclass::text FROM pg_catalog.pg_inherits h \
             JOIN pg_catalog.pg_class c ON c.oid = h.inhrelid \
             WHERE h.inhparent IN ('work.idempotency_key'::regclass, 'work.inbound_seen'::regclass) \
             AND substring(pg_catalog.pg_get_expr(c.relpartbound, c.oid) FROM 'TO \\(''([^'']+)''\\)')::timestamptz \
                 <= pg_catalog.now() - interval '30 days' \
             ORDER BY 1",
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(parts)
    }

    /// The ledgers with rows in the cold partition `part`.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] for a partition that is not archivable or not cold, otherwise
    /// [`StoreError::Db`].
    pub async fn ledgers(&self, part: &str) -> Result<Vec<LedgerId>, StoreError> {
        parent(part)?;
        let mut tx = self.pool.begin().await?;
        let ids: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT l::bytea FROM work.partition_ledgers($1::regclass) l")
                .bind(part)
                .fetch_all(&mut *tx)
                .await
                .map_err(refused)?;
        tx.commit().await?;
        ids.iter()
            .map(|id| digest(id).map(LedgerId::from_bytes))
            .collect()
    }

    /// The slice of `ledger` in the cold partition `part`.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] for a partition that is not archivable, [`StoreError::Corrupt`]
    /// for an out-of-range row, otherwise [`StoreError::Db`].
    pub async fn slice(&self, part: &str, ledger: &LedgerId) -> Result<PartitionSlice, StoreError> {
        let rows_sql = match parent(part)? {
            "work.idempotency_key" => {
                "SELECT t::text FROM work.idempotency_key t WHERE t.tableoid = $1::regclass \
                 ORDER BY t::text COLLATE \"C\""
            }
            _ => {
                "SELECT t::text FROM work.inbound_seen t WHERE t.tableoid = $1::regclass \
                 ORDER BY t::text COLLATE \"C\""
            }
        };
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        sqlx::query("SET LOCAL timezone = 'UTC'")
            .execute(tx.conn())
            .await?;
        let counted: Option<SliceRow> = sqlx::query_as(
            "SELECT row_count, slice_digest::bytea FROM work.partition_slice($1::regclass)",
        )
        .bind(part)
        .fetch_optional(tx.conn())
        .await
        .map_err(refused)?;
        let rows: Vec<String> = sqlx::query_scalar(rows_sql)
            .bind(part)
            .fetch_all(tx.conn())
            .await?;
        tx.commit().await?;
        let (row_count, raw) = counted.ok_or(StoreError::Corrupt)?;
        Ok(PartitionSlice {
            row_count: unsigned(row_count)?,
            digest: digest(&raw)?,
            rows,
        })
    }

    /// The record of the verified copy of `ledger`'s slice of `part`, if one was written.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an out-of-range row, otherwise [`StoreError::Db`].
    pub async fn archived(
        &self,
        part: &str,
        ledger: &LedgerId,
    ) -> Result<Option<ArchiveRecord>, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let row: Option<RecordRow> = sqlx::query_as(
            "SELECT object_key, copy_digest::bytea, row_count FROM work.partition_archive \
             WHERE ledger_id = $1 AND cold_partition = $2",
        )
        .bind(ledger.as_bytes().as_slice())
        .bind(part)
        .fetch_optional(tx.conn())
        .await?;
        tx.commit().await?;
        row.map(|(object_key, raw, n)| {
            Ok(ArchiveRecord {
                object_key,
                copy_digest: digest(&raw)?,
                row_count: unsigned(n)?,
            })
        })
        .transpose()
    }

    /// Records the verified copy of `ledger`'s slice of `part`; a second record of the same
    /// slice is not stored and returns `false`.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] for a refused row, otherwise [`StoreError::Db`].
    pub async fn record(
        &self,
        part: &str,
        ledger: &LedgerId,
        record: &ArchiveRecord,
    ) -> Result<bool, StoreError> {
        let rows = i64::try_from(record.row_count).map_err(|_| StoreError::Corrupt)?;
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let inserted = sqlx::query(
            "INSERT INTO work.partition_archive \
             (ledger_id, cold_partition, object_key, copy_digest, row_count) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (ledger_id, cold_partition) DO NOTHING",
        )
        .bind(ledger.as_bytes().as_slice())
        .bind(part)
        .bind(record.object_key.as_str())
        .bind(record.copy_digest.as_slice())
        .bind(rows)
        .execute(tx.conn())
        .await
        .map_err(refused)?;
        tx.commit().await?;
        Ok(inserted.rows_affected() == 1)
    }

    /// Drops the cold partition `part` through `work.drop_archived_partition` once its rows give
    /// `manifest` and every slice has its record; returns the rows dropped.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] with the function's message (`archive_manifest_mismatch`,
    /// `archive_record_missing`, `partition_still_hot`, `not_an_archivable_partition`), otherwise
    /// [`StoreError::Db`].
    pub async fn drop_partition(&self, part: &str, manifest: &[u8; 32]) -> Result<u64, StoreError> {
        parent(part)?;
        let mut tx = self.pool.begin().await?;
        let total: i64 =
            sqlx::query_scalar("SELECT work.drop_archived_partition($1::regclass, $2)")
                .bind(part)
                .bind(manifest.as_slice())
                .fetch_one(&mut *tx)
                .await
                .map_err(refused)?;
        tx.commit().await?;
        unsigned(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-35 OP-37
    #[test]
    fn op_35_only_monthly_partitions_of_the_two_tables_are_archived() {
        assert_eq!(
            parent("work.idempotency_key_p202607").ok(),
            Some("work.idempotency_key")
        );
        assert_eq!(
            parent("work.inbound_seen_p202612").ok(),
            Some("work.inbound_seen")
        );
        for bad in [
            "work.idempotency_key",
            "work.idempotency_key_p2026",
            "work.idempotency_key_p20260a",
            "work.idempotency_key_p2026071",
            "work.body_part_p202607",
            "ledger.log",
            "work.inbound_seen_p202607; DROP TABLE ledger.log",
        ] {
            assert!(parent(bad).is_err(), "{bad}");
        }
    }
}
