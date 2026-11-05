//! The caller-scoped reads of the API (P-56, T-13, P-57, P-20): a Work is visible to a Party that wrote a record concerning it or is a Party endpoint of one of those records' relations, so no read lists what its caller took no part in; the state read is the sync-derived item head written in the record's own transaction, never a session; the changes since a position come in the order of the position that last changed each item; and a record's evidence is read as four separate parts: the author signature as received, the ledger's log entry, the checkpoint that covers it with its leaf hashes, and the witness cosignatures of that checkpoint. Every statement runs in a [`LedgerTx`].

use crate::{LedgerTx, StoreError};

/// A Work its caller may read (P-56).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkRow {
    /// The item version, its `ETag` (P-29).
    pub version: u64,
    /// The position of its first record.
    pub first_pos: u64,
    /// The position of its last record.
    pub last_pos: u64,
    /// Ledger time of its first record, Unix milliseconds.
    pub opened_at_ms: i64,
    /// Ledger time of its last record, Unix milliseconds.
    pub updated_at_ms: i64,
}

/// One Work that changed after a position (P-57).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeRow {
    /// The Work's 16 bytes.
    pub work: [u8; 16],
    /// Its version now.
    pub version: u64,
    /// The position that last changed it.
    pub last_pos: u64,
}

/// A record its caller may read, with the parts of its evidence the log holds (P-20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRow {
    /// Its position.
    pub pos: u64,
    /// The fencing epoch it was sequenced in.
    pub epoch: u64,
    /// Ledger time, Unix milliseconds.
    pub recorded_at_ms: i64,
    /// The RFC 9162 leaf hash of its envelope.
    pub leaf_hash: [u8; 32],
    /// The Party that wrote it.
    pub author: String,
    /// The author's `COSE_Sign1` as received, when it was signed.
    pub author_signature: Option<Vec<u8>>,
    /// The digest of the Access `auth_context` of an unsigned human record.
    pub auth_context_ref: Option<[u8; 32]>,
}

/// One witness cosignature of a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosignatureView {
    /// The witness.
    pub witness: String,
    /// `witness` or `rfc3161`.
    pub kind: String,
    /// The time it signs, Unix milliseconds.
    pub cosigned_at_ms: i64,
}

/// The first checkpoint whose tree covers a position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoveringCheckpoint {
    /// Its tree size.
    pub size: u64,
    /// Its root hash.
    pub root: [u8; 32],
    /// The signed note.
    pub signed_note: Vec<u8>,
    /// When it was issued, Unix milliseconds.
    pub issued_at_ms: i64,
    /// Its cosignatures, by witness.
    pub cosignatures: Vec<CosignatureView>,
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn digest(v: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

impl LedgerTx<'_> {
    /// `work` as `party` may read it, or `None` when it does not exist or `party` took no part
    /// in it (P-56: the two are not told apart).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn visible_work(
        &mut self,
        work: &[u8; 16],
        party: &str,
    ) -> Result<Option<WorkRow>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let row = sqlx::query!(
            r#"SELECT i.version AS "version!", w.first_pos::bigint AS "first_pos!",
                      i.last_pos::bigint AS "last_pos!",
                      (extract(epoch FROM f.recorded_at) * 1000)::bigint AS "opened_at_ms!",
                      (extract(epoch FROM l.recorded_at) * 1000)::bigint AS "updated_at_ms!"
               FROM work.work_root w
               JOIN work.item_head i
                 ON i.ledger_id = w.ledger_id AND i.item_kind = 'work' AND i.item_id = $2
               JOIN ledger.log f ON f.ledger_id = w.ledger_id AND f.pos = w.first_pos
               JOIN ledger.log l ON l.ledger_id = i.ledger_id AND l.pos = i.last_pos
               WHERE w.ledger_id = $1 AND w.work_id = pg_catalog.encode($2::bytea, 'hex')::uuid
                 AND EXISTS (
                   SELECT 1 FROM work.log_concerns c
                   JOIN work.record_header h ON h.ledger_id = c.ledger_id AND h.pos = c.pos
                   WHERE c.ledger_id = w.ledger_id AND c.work_id = w.work_id
                     AND (h.author::text = $3 OR EXISTS (
                       SELECT 1 FROM work.log_relation r
                       WHERE r.ledger_id = c.ledger_id AND r.pos = c.pos
                         AND ((r.source_kind = 'party' AND r.source_text = $3)
                           OR (r.target_kind = 'party' AND r.target_text = $3)))))"#,
            ledger.as_slice(),
            work.as_slice(),
            party
        )
        .fetch_optional(self.conn())
        .await?;
        row.map(|r| {
            Ok(WorkRow {
                version: unsigned(r.version)?,
                first_pos: unsigned(r.first_pos)?,
                last_pos: unsigned(r.last_pos)?,
                opened_at_ms: r.opened_at_ms,
                updated_at_ms: r.updated_at_ms,
            })
        })
        .transpose()
    }

    /// Up to `limit` Works visible to `party` whose last change comes after `after`, a position
    /// and the Work last read at it (every Work for `None`), in the order of the position that
    /// last changed each Work and then of the Work (P-57, T-26), so a page boundary never
    /// splits the Works one record changed.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn visible_changes(
        &mut self,
        after: Option<(u64, [u8; 16])>,
        limit: u32,
        party: &str,
    ) -> Result<Vec<ChangeRow>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let (after_pos, after_work) = match after {
            Some((pos, work)) => (signed(pos)?, work.to_vec()),
            None => (-1, Vec::new()),
        };
        let rows = sqlx::query!(
            r#"SELECT i.item_id AS "item_id!", i.version AS "version!",
                      i.last_pos::bigint AS "last_pos!"
               FROM work.item_head i
               WHERE i.ledger_id = $1 AND i.item_kind = 'work'
                 AND (i.last_pos::bigint, i.item_id) > ($2::bigint, $5::bytea)
                 AND EXISTS (
                   SELECT 1 FROM work.log_concerns c
                   JOIN work.record_header h ON h.ledger_id = c.ledger_id AND h.pos = c.pos
                   WHERE c.ledger_id = i.ledger_id
                     AND c.work_id = pg_catalog.encode(i.item_id, 'hex')::uuid
                     AND (h.author::text = $3 OR EXISTS (
                       SELECT 1 FROM work.log_relation r
                       WHERE r.ledger_id = c.ledger_id AND r.pos = c.pos
                         AND ((r.source_kind = 'party' AND r.source_text = $3)
                           OR (r.target_kind = 'party' AND r.target_text = $3)))))
               ORDER BY i.last_pos, i.item_id
               LIMIT $4"#,
            ledger.as_slice(),
            after_pos,
            party,
            i64::from(limit),
            after_work.as_slice()
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(ChangeRow {
                    work: <[u8; 16]>::try_from(r.item_id.as_slice())
                        .map_err(|_| StoreError::Corrupt)?,
                    version: unsigned(r.version)?,
                    last_pos: unsigned(r.last_pos)?,
                })
            })
            .collect()
    }

    /// The record `record` with its log entry and author signature, when `party` wrote it, is a
    /// Party endpoint of its relations, or may read a Work it concerns (P-56, P-20).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn visible_record(
        &mut self,
        record: &[u8; 32],
        party: &str,
    ) -> Result<Option<EvidenceRow>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let row = sqlx::query!(
            r#"SELECT l.pos::bigint AS "pos!", l.epoch AS "epoch!",
                      (extract(epoch FROM l.recorded_at) * 1000)::bigint AS "recorded_at_ms!",
                      l.leaf_hash::bytea AS "leaf_hash!", h.author::text AS "author!",
                      h.auth_context_ref::bytea AS "auth_context_ref?",
                      b.bytes AS "author_signature?"
               FROM ledger.log l
               JOIN work.record_header h ON h.ledger_id = l.ledger_id AND h.pos = l.pos
               LEFT JOIN work.log_received s
                 ON s.ledger_id = l.ledger_id AND s.pos = l.pos AND s.role = 'author_signature'
               LEFT JOIN work.received_bytes b ON b.ledger_id = s.ledger_id AND b.digest = s.digest
               WHERE l.ledger_id = $1 AND l.record_id = $2
                 AND (h.author::text = $3
                   OR EXISTS (
                     SELECT 1 FROM work.log_relation r
                     WHERE r.ledger_id = l.ledger_id AND r.pos = l.pos
                       AND ((r.source_kind = 'party' AND r.source_text = $3)
                         OR (r.target_kind = 'party' AND r.target_text = $3)))
                   OR EXISTS (
                     SELECT 1 FROM work.log_concerns k
                     JOIN work.log_concerns c ON c.ledger_id = k.ledger_id AND c.work_id = k.work_id
                     JOIN work.record_header a ON a.ledger_id = c.ledger_id AND a.pos = c.pos
                     WHERE k.ledger_id = l.ledger_id AND k.pos = l.pos
                       AND (a.author::text = $3 OR EXISTS (
                         SELECT 1 FROM work.log_relation q
                         WHERE q.ledger_id = c.ledger_id AND q.pos = c.pos
                           AND ((q.source_kind = 'party' AND q.source_text = $3)
                             OR (q.target_kind = 'party' AND q.target_text = $3))))))"#,
            ledger.as_slice(),
            record.as_slice(),
            party
        )
        .fetch_optional(self.conn())
        .await?;
        row.map(|r| {
            Ok(EvidenceRow {
                pos: unsigned(r.pos)?,
                epoch: unsigned(r.epoch)?,
                recorded_at_ms: r.recorded_at_ms,
                leaf_hash: digest(&r.leaf_hash)?,
                author: r.author,
                author_signature: r.author_signature,
                auth_context_ref: r.auth_context_ref.as_deref().map(digest).transpose()?,
            })
        })
        .transpose()
    }

    /// The first checkpoint whose tree holds position `pos`, with its cosignatures, or `None`
    /// before one is issued (P-20, OP-33).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn covering_checkpoint(
        &mut self,
        pos: u64,
    ) -> Result<Option<CoveringCheckpoint>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let row = sqlx::query!(
            r#"SELECT size AS "size!", root::bytea AS "root!", signed_note AS "signed_note!",
                      (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at_ms!"
               FROM ledger.checkpoint
               WHERE ledger_id = $1 AND size > $2
               ORDER BY size LIMIT 1"#,
            ledger.as_slice(),
            signed(pos)?
        )
        .fetch_optional(self.conn())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let cosignatures = sqlx::query!(
            r#"SELECT witness_id::text AS "witness!", cosign_kind AS "kind!",
                      (extract(epoch FROM cosigned_at) * 1000)::bigint AS "cosigned_at_ms!"
               FROM ledger.checkpoint_cosignature
               WHERE ledger_id = $1 AND size = $2
               ORDER BY witness_id"#,
            ledger.as_slice(),
            row.size
        )
        .fetch_all(self.conn())
        .await?
        .into_iter()
        .map(|c| CosignatureView {
            witness: c.witness,
            kind: c.kind,
            cosigned_at_ms: c.cosigned_at_ms,
        })
        .collect();
        Ok(Some(CoveringCheckpoint {
            size: unsigned(row.size)?,
            root: digest(&row.root)?,
            signed_note: row.signed_note,
            issued_at_ms: row.issued_at_ms,
            cosignatures,
        }))
    }

    /// The leaf hashes of positions 0 to `size` − 1, in order: the tree of a checkpoint of
    /// `size` (P-101).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed hash or a gap.
    pub async fn leaf_hashes(&mut self, size: u64) -> Result<Vec<[u8; 32]>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let leaves = sqlx::query_scalar!(
            r#"SELECT leaf_hash::bytea AS "leaf!" FROM ledger.log
               WHERE ledger_id = $1 AND pos < $2 ORDER BY pos"#,
            ledger.as_slice(),
            signed(size)?
        )
        .fetch_all(self.conn())
        .await?;
        if u64::try_from(leaves.len()).ok() != Some(size) {
            return Err(StoreError::Corrupt);
        }
        leaves.iter().map(|l| digest(l.as_slice())).collect()
    }
}
