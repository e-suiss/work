//! The checkpointer's storage (P-20, T-88, §18 OP-4, OP-33, OP-46, Access T21): the head and the
//! durability profile it builds a checkpoint from, the signed checkpoints of a ledger, the
//! replica's progress and the witness cosignatures, all as `work_checkpointer` in one
//! ledger-scoped transaction each, and the durability of a record as the view derives it from
//! those rows and the witness line of the signed notes. The database refuses a cosignature for
//! a size the replica does not hold yet (mirror before witness).

use sqlx::PgPool;

use crate::publisher::check_role;
use crate::{Durability, LedgerId, LedgerTx, StoreError};

/// The login role a [`CheckpointerPool`] must have.
pub const CHECKPOINTER_ROLE: &str = "work_checkpointer";

/// The head a checkpoint is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadSnapshot {
    /// Position of the last record.
    pub pos: u64,
    /// Its leaf hash.
    pub leaf: [u8; 32],
    /// Its ledger time, Unix milliseconds.
    pub recorded_at_ms: u64,
    /// Merkle frontier over positions `0..=pos`, largest subtree first.
    pub frontier: Vec<[u8; 32]>,
}

/// A signed checkpoint as stored: the ledger acknowledgement of every record below `size`.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckpointRow {
    /// Tree size.
    pub size: u64,
    /// RFC 9162 root at that size.
    pub root: [u8; 32],
    /// Leaf hash of the record at `size - 1`.
    pub head_leaf: [u8; 32],
    /// When the log signed it, ledger time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// The C2SP signed note, as signed.
    pub signed_note: Vec<u8>,
}

impl std::fmt::Debug for CheckpointRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointRow")
            .field("size", &self.size)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("signed_note", &self.signed_note.len())
            .finish_non_exhaustive()
    }
}

/// A witness cosignature of a stored checkpoint (OP-33).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignatureRow {
    /// Size of the cosigned checkpoint.
    pub size: u64,
    /// The witness, by its configured identifier.
    pub witness_id: String,
    /// The cosignature timestamp, Unix milliseconds.
    pub cosigned_at_ms: u64,
    /// The cosignature line, as received.
    pub signature: Vec<u8>,
}

/// One mirrored log entry: the envelope a leaf hash commits to and the externally signed bytes
/// the record came with (T-90).
#[derive(Clone, PartialEq, Eq)]
pub struct MirrorEntry {
    /// Log position.
    pub pos: u64,
    /// Leaf hash.
    pub leaf: [u8; 32],
    /// Ledger envelope bytes.
    pub envelope_bytes: Vec<u8>,
    /// Received signed bytes, by role, in role order.
    pub received: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Debug for MirrorEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorEntry")
            .field("pos", &self.pos)
            .field("envelope_bytes", &self.envelope_bytes.len())
            .field("received", &self.received.len())
            .finish_non_exhaustive()
    }
}

/// How far a record has come (OP-4), derived from the rows that exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordDurability {
    /// In the log.
    Recorded,
    /// Below the size of a signed checkpoint.
    Included,
    /// Below the size of a checkpoint that declares `witness independent k` and has the
    /// cosignatures of k configured witnesses (OP-46 item 5).
    Witnessed,
}

/// The checkpointer's pool, logged in as `work_checkpointer`. It is not an executor:
///
/// ```compile_fail
/// # async fn f(p: &work_store::CheckpointerPool) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct CheckpointerPool {
    pool: PgPool,
}

pub(crate) struct StoredCheckpoint {
    pub(crate) size: i64,
    pub(crate) root: Vec<u8>,
    pub(crate) head_leaf: Vec<u8>,
    pub(crate) issued_at: i64,
    pub(crate) signed_note: Vec<u8>,
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn digest(raw: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(raw).map_err(|_| StoreError::Corrupt)
}

pub(crate) fn checkpoint_row(row: StoredCheckpoint) -> Result<CheckpointRow, StoreError> {
    Ok(CheckpointRow {
        size: unsigned(row.size)?,
        root: digest(&row.root)?,
        head_leaf: digest(&row.head_leaf)?,
        issued_at_ms: unsigned(row.issued_at)?,
        signed_note: row.signed_note,
    })
}

impl CheckpointerPool {
    /// Over `pool` after checking that its role is `work_checkpointer` or holds its privileges.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        check_role(&pool, CHECKPOINTER_ROLE).await?;
        Ok(Self { pool })
    }

    /// Opens a transaction scoped to `ledger`.
    ///
    /// # Errors
    /// See [`LedgerTx::begin`].
    pub async fn begin(&self, ledger: &LedgerId) -> Result<LedgerTx<'static>, StoreError> {
        LedgerTx::begin(&self.pool, ledger).await
    }

    /// The head of `ledger` with its frontier.
    ///
    /// # Errors
    /// [`StoreError::NotOpened`], [`StoreError::Corrupt`] for an out-of-range row, otherwise
    /// [`StoreError::Db`].
    pub async fn head(&self, ledger: &LedgerId) -> Result<HeadSnapshot, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let row = sqlx::query!(
            r#"SELECT pos AS "pos!", head_leaf::bytea AS "leaf?",
                      (extract(epoch FROM head_recorded_at) * 1000)::bigint AS "at?",
                      frontier AS "frontier!"
               FROM ledger.head WHERE ledger_id = $1"#,
            ledger.as_bytes().as_slice()
        )
        .fetch_optional(tx.conn())
        .await?;
        tx.commit().await?;
        let Some((pos, Some(leaf), Some(at), frontier)) =
            row.map(|r| (r.pos, r.leaf, r.at, r.frontier))
        else {
            return Err(StoreError::NotOpened);
        };
        let pos = unsigned(pos)?;
        let (nodes, rest) = frontier.as_chunks::<32>();
        let size = pos.checked_add(1).ok_or(StoreError::Corrupt)?;
        if !rest.is_empty() || usize::try_from(size.count_ones()).ok() != Some(nodes.len()) {
            return Err(StoreError::Corrupt);
        }
        Ok(HeadSnapshot {
            pos,
            leaf: digest(&leaf)?,
            recorded_at_ms: unsigned(at)?,
            frontier: nodes.to_vec(),
        })
    }

    /// The durability profile of `ledger`, the `durability` line of its checkpoints (OP-27,
    /// OP-46 item 3).
    ///
    /// # Errors
    /// [`StoreError::NotOpened`], [`StoreError::Corrupt`] for an unknown value, otherwise
    /// [`StoreError::Db`].
    pub async fn durability(&self, ledger: &LedgerId) -> Result<Durability, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let profile = sqlx::query_scalar!(
            r#"SELECT durability_profile AS "profile!" FROM work.ledger_profile
               WHERE ledger_id = $1"#,
            ledger.as_bytes().as_slice()
        )
        .fetch_optional(tx.conn())
        .await?;
        tx.commit().await?;
        match profile.as_deref() {
            Some("quorum") => Ok(Durability::Quorum),
            Some("single-node") => Ok(Durability::SingleNode),
            Some(_) => Err(StoreError::Corrupt),
            None => Err(StoreError::NotOpened),
        }
    }

    /// The largest stored checkpoint of `ledger`.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an out-of-range row, otherwise [`StoreError::Db`].
    pub async fn latest(&self, ledger: &LedgerId) -> Result<Option<CheckpointRow>, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let row = sqlx::query_as!(
            StoredCheckpoint,
            r#"SELECT size AS "size!", root::bytea AS "root!", head_leaf::bytea AS "head_leaf!",
                      (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at!",
                      signed_note AS "signed_note!"
               FROM ledger.checkpoint WHERE ledger_id = $1 ORDER BY size DESC LIMIT 1"#,
            ledger.as_bytes().as_slice()
        )
        .fetch_optional(tx.conn())
        .await?;
        tx.commit().await?;
        row.map(checkpoint_row).transpose()
    }

    /// The stored checkpoint of `ledger` at `size`.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an out-of-range row, otherwise [`StoreError::Db`].
    pub async fn at(
        &self,
        ledger: &LedgerId,
        size: u64,
    ) -> Result<Option<CheckpointRow>, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let row = sqlx::query_as!(
            StoredCheckpoint,
            r#"SELECT size AS "size!", root::bytea AS "root!", head_leaf::bytea AS "head_leaf!",
                      (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at!",
                      signed_note AS "signed_note!"
               FROM ledger.checkpoint WHERE ledger_id = $1 AND size = $2"#,
            ledger.as_bytes().as_slice(),
            signed(size)?
        )
        .fetch_optional(tx.conn())
        .await?;
        tx.commit().await?;
        row.map(checkpoint_row).transpose()
    }

    /// Stores a signed checkpoint. The database refuses one whose head leaf is not the log's
    /// leaf at `size - 1` or that was issued before that record's ledger time; a second
    /// checkpoint of the same size is not stored and returns `false`.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] for a checkpoint the log does not match, otherwise
    /// [`StoreError::Db`].
    pub async fn insert(&self, ledger: &LedgerId, row: &CheckpointRow) -> Result<bool, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let inserted = sqlx::query!(
            "INSERT INTO ledger.checkpoint
             (ledger_id, size, root, head_leaf, issued_at, signed_note) VALUES ($1, $2, $3, $4,
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $5::bigint::double precision,
             $6) ON CONFLICT (ledger_id, size) DO NOTHING",
            ledger.as_bytes().as_slice(),
            signed(row.size)?,
            row.root.as_slice(),
            row.head_leaf.as_slice(),
            signed(row.issued_at_ms)?,
            row.signed_note.as_slice()
        )
        .execute(tx.conn())
        .await
        .map_err(refused)?;
        tx.commit().await?;
        Ok(inserted.rows_affected() == 1)
    }

    /// The log entries at positions `from..to`, in position order, with the signed bytes each
    /// record was received as (T-90).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an out-of-range row, otherwise [`StoreError::Db`].
    pub async fn entries(
        &self,
        ledger: &LedgerId,
        from: u64,
        to: u64,
    ) -> Result<Vec<MirrorEntry>, StoreError> {
        let id = ledger.as_bytes().as_slice();
        let mut tx = self.begin(ledger).await?;
        let leaves = sqlx::query!(
            r#"SELECT pos AS "pos!", leaf_hash::bytea AS "leaf!",
                      envelope_bytes AS "envelope_bytes!"
               FROM ledger.log
               WHERE ledger_id = $1 AND pos >= $2 AND pos < $3 ORDER BY pos"#,
            id,
            signed(from)?,
            signed(to)?
        )
        .fetch_all(tx.conn())
        .await?;
        let received = sqlx::query!(
            r#"SELECT r.pos AS "pos!", r.role AS "role!", b.bytes AS "bytes!"
               FROM work.log_received r
               JOIN work.received_bytes b ON b.ledger_id = r.ledger_id AND b.digest = r.digest
               WHERE r.ledger_id = $1 AND r.pos >= $2 AND r.pos < $3 ORDER BY r.pos, r.role"#,
            id,
            signed(from)?,
            signed(to)?
        )
        .fetch_all(tx.conn())
        .await?;
        tx.commit().await?;
        let mut out = Vec::with_capacity(leaves.len());
        for l in leaves {
            out.push(MirrorEntry {
                pos: unsigned(l.pos)?,
                leaf: digest(&l.leaf)?,
                envelope_bytes: l.envelope_bytes,
                received: Vec::new(),
            });
        }
        for r in received {
            let pos = unsigned(r.pos)?;
            let entry = out
                .iter_mut()
                .find(|e| e.pos == pos)
                .ok_or(StoreError::Corrupt)?;
            entry.received.push((r.role, r.bytes));
        }
        Ok(out)
    }

    /// The leaf hashes of the records of `ledger` at positions `0..size`, in position order,
    /// the tree a consistency proof is taken over (OP-33).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] when the log does not hold `size` records, otherwise
    /// [`StoreError::Db`].
    pub async fn leaf_hashes(
        &self,
        ledger: &LedgerId,
        size: u64,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let rows = sqlx::query_scalar!(
            r#"SELECT leaf_hash::bytea AS "leaf!" FROM ledger.log
               WHERE ledger_id = $1 AND pos < $2 ORDER BY pos"#,
            ledger.as_bytes().as_slice(),
            signed(size)?
        )
        .fetch_all(tx.conn())
        .await?;
        tx.commit().await?;
        if u64::try_from(rows.len()).ok() != Some(size) {
            return Err(StoreError::Corrupt);
        }
        rows.iter().map(|raw| digest(raw.as_slice())).collect()
    }

    /// How many records `replica` holds of `ledger`; 0 before its first mirror.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an out-of-range row, otherwise [`StoreError::Db`].
    pub async fn mirrored(&self, ledger: &LedgerId, replica: &str) -> Result<u64, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let size = sqlx::query_scalar!(
            r#"SELECT mirrored_size AS "size!" FROM ledger.replica_progress
               WHERE ledger_id = $1 AND replica_id = $2"#,
            ledger.as_bytes().as_slice(),
            replica
        )
        .fetch_optional(tx.conn())
        .await?;
        tx.commit().await?;
        size.map_or(Ok(0), unsigned)
    }

    /// Records that `replica` holds every record of `ledger` below `size`. The database refuses
    /// a size beyond the head or below the stored one.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] for a refused size, otherwise [`StoreError::Db`].
    pub async fn record_mirrored(
        &self,
        ledger: &LedgerId,
        replica: &str,
        size: u64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin(ledger).await?;
        sqlx::query!(
            "INSERT INTO ledger.replica_progress (ledger_id, replica_id, mirrored_size)
             VALUES ($1, $2, $3) ON CONFLICT (ledger_id, replica_id) DO UPDATE
             SET mirrored_size = EXCLUDED.mirrored_size, updated_at = pg_catalog.now()",
            ledger.as_bytes().as_slice(),
            replica,
            signed(size)?
        )
        .execute(tx.conn())
        .await
        .map_err(refused)?;
        tx.commit().await
    }

    /// Stores a witness cosignature of a stored checkpoint; a second one from the same witness
    /// for the same size is not stored and returns `false`. The database refuses a cosignature
    /// for a size the replica does not hold yet (mirror before witness, Access T21).
    ///
    /// # Errors
    /// [`StoreError::Constraint`] (`witnessed_before_mirrored`), otherwise [`StoreError::Db`].
    pub async fn insert_cosignature(
        &self,
        ledger: &LedgerId,
        row: &CosignatureRow,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let inserted = sqlx::query!(
            "INSERT INTO ledger.checkpoint_cosignature
             (ledger_id, size, witness_id, cosign_kind, cosigned_at, signature)
             VALUES ($1, $2, $3, 'witness',
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $4::bigint::double precision,
             $5) ON CONFLICT (ledger_id, size, witness_id) DO NOTHING",
            ledger.as_bytes().as_slice(),
            signed(row.size)?,
            row.witness_id.as_str(),
            signed(row.cosigned_at_ms)?,
            row.signature.as_slice()
        )
        .execute(tx.conn())
        .await
        .map_err(refused)?;
        tx.commit().await?;
        Ok(inserted.rows_affected() == 1)
    }

    /// The stored witness cosignatures of the checkpoint of `ledger` at `size`, by witness.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an out-of-range row, otherwise [`StoreError::Db`].
    pub async fn cosignatures(
        &self,
        ledger: &LedgerId,
        size: u64,
    ) -> Result<Vec<CosignatureRow>, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let rows = sqlx::query!(
            r#"SELECT witness_id::text AS "witness_id!",
                      (extract(epoch FROM cosigned_at) * 1000)::bigint AS "at!",
                      signature AS "signature!"
               FROM ledger.checkpoint_cosignature
               WHERE ledger_id = $1 AND size = $2 AND cosign_kind = 'witness'
               ORDER BY witness_id"#,
            ledger.as_bytes().as_slice(),
            signed(size)?
        )
        .fetch_all(tx.conn())
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| {
                Ok(CosignatureRow {
                    size,
                    witness_id: r.witness_id,
                    cosigned_at_ms: unsigned(r.at)?,
                    signature: r.signature,
                })
            })
            .collect()
    }
}

fn refused(e: sqlx::Error) -> StoreError {
    let constraint = e.as_database_error().and_then(|d| {
        let code = d.code();
        match code.as_deref() {
            Some("23514" | "23503" | "23505") => Some(
                d.constraint()
                    .map_or_else(|| d.message().to_owned(), str::to_owned),
            ),
            _ => None,
        }
    });
    constraint.map_or(StoreError::Db(e), StoreError::Constraint)
}

impl LedgerTx<'_> {
    /// The durability of the record at `pos`, or `None` when the log has no such record (OP-4).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unknown value, otherwise [`StoreError::Db`].
    pub async fn durability(&mut self, pos: u64) -> Result<Option<RecordDurability>, StoreError> {
        let ledger = *self.ledger();
        let state = sqlx::query_scalar!(
            r#"SELECT durability AS "durability!" FROM ledger.record_durability
               WHERE ledger_id = $1 AND pos = $2"#,
            ledger.as_bytes().as_slice(),
            signed(pos)?
        )
        .fetch_optional(self.conn())
        .await?;
        state
            .map(|s| match s.as_str() {
                "recorded" => Ok(RecordDurability::Recorded),
                "included" => Ok(RecordDurability::Included),
                "witnessed" => Ok(RecordDurability::Witnessed),
                _ => Err(StoreError::Corrupt),
            })
            .transpose()
    }
}
