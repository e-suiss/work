//! The body store's rows (§18 OP-2, OP-12, OP-15, OP-45, §15 P-68): each body part's
//! ciphertext, inline or as an object key, written in the append transaction with its wrapped
//! part key; the subject × retention class DEKs wrapped under the ledger KEK; the reads that
//! give a part back with the keys that open it; and the erasure role's one-way steps: a
//! destroyed class DEK, a shredded part key, both refused under an active retention hold and
//! each followed by a tombstone, and the rewrap of a class DEK under a new KEK version. Key
//! material never passes through here: only wrapped keys, which are not secrets (OP-45 item 6).

use sqlx::PgPool;

use crate::publisher::check_role;
use crate::skeleton::refused;
use crate::{LedgerId, LedgerTx, StoreError};

/// The login role an [`ErasurePool`] must have (T-79, OP-45 item 8).
pub const ERASURE_ROLE: &str = "work_erasure";

/// Bytes of an AES-256 key wrapped with AES-KW (RFC 3394), the stored length (OP-45 item 8).
pub const WRAPPED_LEN: usize = 40;

/// A retention class of the shared retention table (OP-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RetentionClass {
    /// `work_record`.
    WorkRecord,
    /// `work_evidence`.
    WorkEvidence,
    /// `work_draft`.
    WorkDraft,
    /// `agent_trace`.
    AgentTrace,
}

impl RetentionClass {
    /// Every body class.
    pub const ALL: [Self; 4] = [
        Self::WorkRecord,
        Self::WorkEvidence,
        Self::WorkDraft,
        Self::AgentTrace,
    ];

    /// The stored `retention_class`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkRecord => "work_record",
            Self::WorkEvidence => "work_evidence",
            Self::WorkDraft => "work_draft",
            Self::AgentTrace => "agent_trace",
        }
    }

    /// The class stored as `class`; `None` for any other text.
    #[must_use]
    pub fn from_stored(class: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == class)
    }
}

/// Where a part's ciphertext is (§17 T-20, OP-2).
#[derive(Clone, PartialEq, Eq)]
pub enum Stored {
    /// In `work.body_part.ciphertext`.
    Inline(Vec<u8>),
    /// In the S3-compatible object store under this key.
    Object(String),
}

impl std::fmt::Debug for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline(c) => f.debug_tuple("Inline").field(&c.len()).finish(),
            Self::Object(k) => f.debug_tuple("Object").field(k).finish(),
        }
    }
}

/// A class DEK as stored: its id, the KEK that wraps it and the wrapped key (OP-45 item 2).
#[derive(Clone, PartialEq, Eq)]
pub struct DekRow {
    /// `dek_id`, a UUID in text form.
    pub dek_id: String,
    /// The PKCS#11 label of the KEK, `work.<ledger hex>.kek.v<n>`.
    pub kek_id: String,
    /// The DEK wrapped under the KEK; `None` once destroyed.
    pub wrapped: Option<[u8; WRAPPED_LEN]>,
}

impl std::fmt::Debug for DekRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DekRow")
            .field("dek_id", &self.dek_id)
            .field("kek_id", &self.kek_id)
            .field("destroyed", &self.wrapped.is_none())
            .finish()
    }
}

/// One encrypted body part written with its record (OP-15, OP-45 items 3 and 4).
#[derive(Clone, PartialEq, Eq)]
pub struct BodyPartRow {
    /// The part name; its commitment is in the same record's skeleton.
    pub part: String,
    /// The class DEK the part key is wrapped under.
    pub dek_id: String,
    /// The part's retention class, the class of that DEK.
    pub class: RetentionClass,
    /// The AES-GCM nonce.
    pub nonce: [u8; 12],
    /// The ciphertext or its object key.
    pub stored: Stored,
    /// SHA-256 of the ciphertext, its content address.
    pub ciphertext_digest: [u8; 32],
    /// The part DEK wrapped under the class DEK.
    pub wrapped_key: [u8; WRAPPED_LEN],
}

impl std::fmt::Debug for BodyPartRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyPartRow")
            .field("part", &self.part)
            .field("class", &self.class)
            .field("stored", &self.stored)
            .finish_non_exhaustive()
    }
}

/// A stored part with what opens it (OP-45): the part key and the class DEK, each `None` once
/// shredded or destroyed, in which case the part is unreadable while its skeleton stays.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredPart {
    /// The part name.
    pub part: String,
    /// Its commitment from the skeleton.
    pub commit: [u8; 32],
    /// Its retention class.
    pub class: RetentionClass,
    /// The AES-GCM nonce.
    pub nonce: [u8; 12],
    /// The ciphertext or its object key.
    pub stored: Stored,
    /// SHA-256 of the ciphertext.
    pub ciphertext_digest: [u8; 32],
    /// The wrapped part key; `None` after redaction.
    pub part_key: Option<[u8; WRAPPED_LEN]>,
    /// The class DEK; its `wrapped` is `None` after subject erasure or retention end.
    pub dek: DekRow,
}

impl std::fmt::Debug for StoredPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredPart")
            .field("part", &self.part)
            .field("class", &self.class)
            .field("stored", &self.stored)
            .field("shredded", &self.part_key.is_none())
            .field("dek", &self.dek)
            .finish_non_exhaustive()
    }
}

/// Why a part's key went away (OP-12, OP-45 item 5), stored as the tombstone's cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shred {
    /// A subject erasure destroyed the class DEK.
    SubjectErasure,
    /// The retention period ended and destroyed the class DEK.
    RetentionExpired,
}

impl Shred {
    const fn cause(self) -> &'static str {
        match self {
            Self::SubjectErasure => "subject_erasure",
            Self::RetentionExpired => "retention_expired",
        }
    }
}

struct DekTuple {
    dek_id: String,
    kek_id: String,
    wrapped_key: Option<Vec<u8>>,
}

struct PartTuple {
    part: String,
    commit: Vec<u8>,
    class: String,
    nonce: Vec<u8>,
    ciphertext: Option<Vec<u8>>,
    object_key: Option<String>,
    digest: Vec<u8>,
    part_key: Option<Vec<u8>>,
    dek_id: String,
    kek_id: String,
    dek: Option<Vec<u8>>,
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn wrapped(raw: Option<Vec<u8>>) -> Result<Option<[u8; WRAPPED_LEN]>, StoreError> {
    raw.map(|w| <[u8; WRAPPED_LEN]>::try_from(w.as_slice()).map_err(|_| StoreError::Corrupt))
        .transpose()
}

fn dek_row(row: DekTuple) -> Result<DekRow, StoreError> {
    Ok(DekRow {
        dek_id: row.dek_id,
        kek_id: row.kek_id,
        wrapped: wrapped(row.wrapped_key)?,
    })
}

fn stored_part(t: PartTuple) -> Result<StoredPart, StoreError> {
    let PartTuple {
        part,
        commit,
        class,
        nonce,
        ciphertext,
        object_key,
        digest,
        part_key,
        dek_id,
        kek_id,
        dek,
    } = t;
    let stored = match (ciphertext, object_key) {
        (Some(c), None) => Stored::Inline(c),
        (None, Some(k)) => Stored::Object(k),
        _ => return Err(StoreError::Corrupt),
    };
    Ok(StoredPart {
        part,
        commit: <[u8; 32]>::try_from(commit.as_slice()).map_err(|_| StoreError::Corrupt)?,
        class: RetentionClass::from_stored(&class).ok_or(StoreError::Corrupt)?,
        nonce: <[u8; 12]>::try_from(nonce.as_slice()).map_err(|_| StoreError::Corrupt)?,
        stored,
        ciphertext_digest: <[u8; 32]>::try_from(digest.as_slice())
            .map_err(|_| StoreError::Corrupt)?,
        part_key: wrapped(part_key)?,
        dek: dek_row(DekTuple {
            dek_id,
            kek_id,
            wrapped_key: dek,
        })?,
    })
}

impl LedgerTx<'_> {
    /// Writes the encrypted parts of the record at `pos` and their wrapped part keys (OP-45
    /// item 8): after its skeleton, since each part names a commitment of it.
    pub(crate) async fn insert_body(
        &mut self,
        pos: u64,
        parts: &[BodyPartRow],
    ) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        let at = signed(pos)?;
        for p in parts {
            let (storage, ciphertext, object_key) = match &p.stored {
                Stored::Inline(c) => ("inline", Some(c.as_slice()), None),
                Stored::Object(k) => ("object_store", None, Some(k.as_str())),
            };
            sqlx::query!(
                "INSERT INTO work.body_part
                 (ledger_id, pos, part, dek_id, retention_class, storage, nonce, ciphertext,
                  object_key, ciphertext_digest)
                 VALUES ($1, $2, $3, $4::text::uuid, $5, $6, $7, $8, $9, $10)",
                ledger.as_slice(),
                at,
                p.part.as_str(),
                p.dek_id.as_str(),
                p.class.as_str(),
                storage,
                p.nonce.as_slice(),
                ciphertext,
                object_key,
                p.ciphertext_digest.as_slice()
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
            sqlx::query!(
                "INSERT INTO work.body_part_key (ledger_id, pos, part, wrapped_key)
                 VALUES ($1, $2, $3, $4)",
                ledger.as_slice(),
                at,
                p.part.as_str(),
                p.wrapped_key.as_slice()
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        Ok(())
    }

    /// The active class DEK of `subject` and `class` (OP-45 item 2), `None` before its first
    /// part or after its destruction.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn active_dek(
        &mut self,
        subject: &str,
        class: RetentionClass,
    ) -> Result<Option<DekRow>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let row = sqlx::query_as!(
            DekTuple,
            r#"SELECT dek_id::text AS "dek_id!", kek_id AS "kek_id!", wrapped_key AS "wrapped_key?"
               FROM work.body_dek
               WHERE ledger_id = $1 AND subject_ref = $2 AND retention_class = $3
                 AND state = 'active'"#,
            ledger.as_slice(),
            subject,
            class.as_str()
        )
        .fetch_optional(self.conn())
        .await?;
        row.map(dek_row).transpose()
    }

    /// The parts of the record at `pos` in part order, each with its commitment and its keys
    /// as stored now (OP-13, OP-45).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn body_parts(&mut self, pos: u64) -> Result<Vec<StoredPart>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query_as!(
            PartTuple,
            r#"SELECT p.part::text AS "part!", c.part_commit::bytea AS "commit!",
                      p.retention_class::text AS "class!", p.nonce AS "nonce!",
                      p.ciphertext AS "ciphertext?", p.object_key AS "object_key?",
                      p.ciphertext_digest::bytea AS "digest!", k.wrapped_key AS "part_key?",
                      d.dek_id::text AS "dek_id!", d.kek_id AS "kek_id!",
                      d.wrapped_key AS "dek?"
               FROM work.body_part p
               JOIN work.body_commitment c
                 ON c.ledger_id = p.ledger_id AND c.pos = p.pos AND c.part = p.part
               JOIN work.body_part_key k
                 ON k.ledger_id = p.ledger_id AND k.pos = p.pos AND k.part = p.part
               JOIN work.body_dek d ON d.ledger_id = p.ledger_id AND d.dek_id = p.dek_id
               WHERE p.ledger_id = $1 AND p.pos = $2
               ORDER BY p.part"#,
            ledger.as_slice(),
            signed(pos)?
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter().map(stored_part).collect()
    }
}

impl crate::SequencerPool {
    /// The active class DEK of `subject` and `class`, written with `kek_id` and `wrapped` when
    /// there is none (OP-45 item 2): a concurrent first write keeps the row that won, which is
    /// the one returned, so the caller unwraps what is stored rather than what it offered.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn class_dek(
        &self,
        ledger: &LedgerId,
        subject: &str,
        class: RetentionClass,
        kek_id: &str,
        wrapped: &[u8; WRAPPED_LEN],
    ) -> Result<DekRow, StoreError> {
        let mut tx = self.begin(ledger).await?;
        sqlx::query!(
            "INSERT INTO work.body_dek
             (ledger_id, subject_ref, retention_class, kek_id, wrapped_key, state)
             VALUES ($1, $2, $3, $4, $5, 'active')
             ON CONFLICT (ledger_id, subject_ref, retention_class) WHERE state = 'active'
             DO NOTHING",
            ledger.as_bytes().as_slice(),
            subject,
            class.as_str(),
            kek_id,
            wrapped.as_slice()
        )
        .execute(tx.conn())
        .await?;
        let row = tx.active_dek(subject, class).await?;
        tx.commit().await?;
        row.ok_or(StoreError::Corrupt)
    }

    /// The active class DEK of `subject` and `class`, if any (OP-45 item 2).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn active_dek(
        &self,
        ledger: &LedgerId,
        subject: &str,
        class: RetentionClass,
    ) -> Result<Option<DekRow>, StoreError> {
        let mut tx = self.begin(ledger).await?;
        let row = tx.active_dek(subject, class).await?;
        tx.commit().await?;
        Ok(row)
    }
}

/// The erasure pool, logged in as `work_erasure` (T-79, OP-45 item 8). It is not an executor;
/// its statements run only through its methods, each in a [`LedgerTx`]:
///
/// ```compile_fail
/// # async fn f(p: &work_store::ErasurePool) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ErasurePool {
    pool: PgPool,
}

impl ErasurePool {
    /// Over `pool` after checking that its role is `work_erasure` or holds its privileges.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        check_role(&pool, ERASURE_ROLE).await?;
        Ok(Self { pool })
    }

    /// Destroys the active class DEK of `subject` and `class` once (OP-12 item 3, OP-45 item 5):
    /// its wrapped key becomes NULL, every part under it gets a tombstone and the row is
    /// terminal. Returns the wrapped key it held, for the DEK cache to forget, or `None` when no
    /// DEK is active.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] under an active retention hold; [`StoreError::Db`] otherwise.
    pub async fn destroy_dek(
        &self,
        ledger: &LedgerId,
        subject: &str,
        class: RetentionClass,
        why: Shred,
    ) -> Result<Option<DekRow>, StoreError> {
        let id = ledger.as_bytes().as_slice();
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let row = sqlx::query_as!(
            DekTuple,
            r#"SELECT dek_id::text AS "dek_id!", kek_id AS "kek_id!", wrapped_key AS "wrapped_key?"
               FROM work.body_dek
               WHERE ledger_id = $1 AND subject_ref = $2 AND retention_class = $3
                 AND state = 'active' FOR UPDATE"#,
            id,
            subject,
            class.as_str()
        )
        .fetch_optional(tx.conn())
        .await?;
        let Some(row) = row.map(dek_row).transpose()? else {
            tx.rollback().await?;
            return Ok(None);
        };
        sqlx::query!(
            "UPDATE work.body_dek
             SET wrapped_key = NULL, state = 'destroyed', destroyed_at = pg_catalog.now()
             WHERE ledger_id = $1 AND dek_id = $2::text::uuid",
            id,
            row.dek_id.as_str()
        )
        .execute(tx.conn())
        .await
        .map_err(refused)?;
        sqlx::query!(
            "INSERT INTO work.body_part_tombstone (ledger_id, pos, part, cause)
             SELECT p.ledger_id, p.pos, p.part, $3::text FROM work.body_part p
             WHERE p.ledger_id = $1 AND p.dek_id = $2::text::uuid
             ON CONFLICT (ledger_id, pos, part) DO NOTHING",
            id,
            row.dek_id.as_str(),
            why.cause()
        )
        .execute(tx.conn())
        .await
        .map_err(refused)?;
        tx.commit().await?;
        Ok(Some(row))
    }

    /// Shreds the key of one part once, the redaction of that part alone (P-25, OP-15,
    /// OP-45 item 5): its wrapped key becomes NULL and the part gets a tombstone. Returns the
    /// wrapped key it held, or `None` when it was already shredded or the part has no key.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] under an active retention hold; [`StoreError::Db`] otherwise.
    pub async fn shred_part(
        &self,
        ledger: &LedgerId,
        pos: u64,
        part: &str,
    ) -> Result<Option<[u8; WRAPPED_LEN]>, StoreError> {
        let id = ledger.as_bytes().as_slice();
        let at = signed(pos)?;
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let key = sqlx::query_scalar!(
            r#"SELECT wrapped_key AS "wrapped_key?" FROM work.body_part_key
               WHERE ledger_id = $1 AND pos = $2 AND part = $3 FOR UPDATE"#,
            id,
            at,
            part
        )
        .fetch_optional(tx.conn())
        .await?;
        let Some(key) = wrapped(key.flatten())? else {
            tx.rollback().await?;
            return Ok(None);
        };
        sqlx::query!(
            "UPDATE work.body_part_key SET wrapped_key = NULL, shredded_at = pg_catalog.now()
             WHERE ledger_id = $1 AND pos = $2 AND part = $3",
            id,
            at,
            part
        )
        .execute(tx.conn())
        .await
        .map_err(refused)?;
        sqlx::query!(
            "INSERT INTO work.body_part_tombstone (ledger_id, pos, part, cause)
             VALUES ($1, $2, $3, 'redacted') ON CONFLICT (ledger_id, pos, part) DO NOTHING",
            id,
            at,
            part
        )
        .execute(tx.conn())
        .await
        .map_err(refused)?;
        tx.commit().await?;
        Ok(Some(key))
    }

    /// Rewraps the active DEK `dek_id` from KEK `from` to KEK `to` (OP-45 item 1): only
    /// `kek_id` and `wrapped_key` change, together; `false` when the DEK is not active under
    /// `from`.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] for a refused change; [`StoreError::Db`] otherwise.
    pub async fn rewrap_dek(
        &self,
        ledger: &LedgerId,
        dek_id: &str,
        from: &str,
        to: &str,
        wrapped: &[u8; WRAPPED_LEN],
    ) -> Result<bool, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let done = sqlx::query!(
            "UPDATE work.body_dek SET kek_id = $4, wrapped_key = $5
             WHERE ledger_id = $1 AND dek_id = $2::text::uuid AND kek_id = $3
               AND state = 'active'",
            ledger.as_bytes().as_slice(),
            dek_id,
            from,
            to,
            wrapped.as_slice()
        )
        .execute(tx.conn())
        .await
        .map_err(refused)?
        .rows_affected();
        tx.commit().await?;
        Ok(done == 1)
    }

    /// The active class DEKs of the ledger wrapped under `kek_id`, for a rotation (OP-45 item 1).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn deks_under(
        &self,
        ledger: &LedgerId,
        kek_id: &str,
    ) -> Result<Vec<DekRow>, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let rows = sqlx::query_as!(
            DekTuple,
            r#"SELECT dek_id::text AS "dek_id!", kek_id AS "kek_id!", wrapped_key AS "wrapped_key?"
               FROM work.body_dek
               WHERE ledger_id = $1 AND kek_id = $2 AND state = 'active' ORDER BY dek_id"#,
            ledger.as_bytes().as_slice(),
            kek_id
        )
        .fetch_all(tx.conn())
        .await?;
        tx.commit().await?;
        rows.into_iter().map(dek_row).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-14 OP-45
    #[test]
    fn op_45_retention_classes_round_trip_their_stored_names() {
        for c in RetentionClass::ALL {
            assert_eq!(RetentionClass::from_stored(c.as_str()), Some(c));
        }
        assert_eq!(RetentionClass::from_stored("audit"), None);
    }
}
