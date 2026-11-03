//! The body store's rows (§18 OP-2, OP-12, OP-15, OP-45, §15 P-68): each body part's
//! ciphertext, inline or as an object key, written in the append transaction with its wrapped
//! part key; the subject × retention class DEKs wrapped under the ledger KEK; the reads that
//! give a part back with the keys that open it; and the erasure role's one-way steps: a
//! destroyed class DEK, a shredded part key, each followed by a tombstone and recorded in
//! `work.erasure_log` as waiting on an active retention hold, shredded until the DEK cache
//! lifetime and the backup window have passed, then completed, and the rewrap of a class DEK
//! under a new KEK version. Key material never passes through here: only wrapped keys, which are
//! not secrets (OP-45 item 6).

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

/// Why a class DEK went away (OP-12, OP-45 item 5), stored as the tombstone's cause and, as the
/// request that removed it, as the erasure's cause.
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

    const fn request(self) -> ErasureCause {
        match self {
            Self::SubjectErasure => ErasureCause::SubjectRequest,
            Self::RetentionExpired => ErasureCause::RetentionExpired,
        }
    }
}

/// The request an erasure answers, the stored `cause` of `work.erasure_log` (OP-14, Access
/// OP-78).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErasureCause {
    /// A data subject asked for the erasure of a class.
    SubjectRequest,
    /// The retention period of a class ended.
    RetentionExpired,
    /// One part was redacted (P-25).
    Redaction,
    /// The tenant closed.
    TenantClosure,
}

impl ErasureCause {
    /// Every cause.
    pub const ALL: [Self; 4] = [
        Self::SubjectRequest,
        Self::RetentionExpired,
        Self::Redaction,
        Self::TenantClosure,
    ];

    /// The stored `cause`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubjectRequest => "subject_request",
            Self::RetentionExpired => "retention_expired",
            Self::Redaction => "redaction",
            Self::TenantClosure => "tenant_closure",
        }
    }

    /// The cause stored as `cause`; `None` for any other text.
    #[must_use]
    pub fn from_stored(cause: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == cause)
    }

    /// The class DEK removal this cause asks for; `None` for a part or the tenant.
    #[must_use]
    pub const fn shred(self) -> Option<Shred> {
        match self {
            Self::SubjectRequest => Some(Shred::SubjectErasure),
            Self::RetentionExpired => Some(Shred::RetentionExpired),
            Self::Redaction | Self::TenantClosure => None,
        }
    }
}

/// Where one erasure stands (OP-45 item 5, Access CR-32 item 3). Times are database time in
/// Unix milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureState {
    /// An active retention hold refuses the key removal; the request waits for its release
    /// (Access OP-74).
    WaitingOnHold,
    /// The key is gone; the erasure is completed only once every DEK cache lifetime and the
    /// backup window have passed, at `settles_at_ms`.
    Shredded {
        /// When the erasure may be reported completed.
        settles_at_ms: i64,
    },
    /// Reported completed, never before its settle time.
    Completed {
        /// When the erasure could be reported completed.
        settles_at_ms: i64,
        /// When it was.
        completed_at_ms: i64,
    },
}

/// What an erasure removes (OP-45 item 8): a class DEK, or the key of one part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErasureTarget {
    /// The class DEK of the row's subject and class.
    Class,
    /// The key of part `part` of the record at `pos`.
    Part {
        /// The record's position.
        pos: u64,
        /// The part name.
        part: String,
    },
}

/// One `work.erasure_log` row with the subject and class of its DEK.
#[derive(Clone, PartialEq, Eq)]
pub struct ErasureRow {
    /// `erasure_id`, a UUID in text form.
    pub erasure_id: String,
    /// The class DEK the erasure concerns.
    pub dek_id: String,
    /// The pseudonymous subject of that DEK.
    pub subject: String,
    /// Its retention class.
    pub class: RetentionClass,
    /// The request it answers.
    pub cause: ErasureCause,
    /// What it removes.
    pub target: ErasureTarget,
    /// Where it stands.
    pub state: ErasureState,
    /// When it was requested.
    pub requested_at_ms: i64,
}

impl std::fmt::Debug for ErasureRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasureRow")
            .field("erasure_id", &self.erasure_id)
            .field("class", &self.class)
            .field("cause", &self.cause)
            .field("target", &self.target)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// The outcome of one erasure request (OP-45 item 5, Access OP-74): a decision, not an error.
#[derive(Clone, PartialEq, Eq)]
pub enum Erased<K> {
    /// Nothing to remove: no active class DEK, no such part, or its key is already gone.
    Nothing,
    /// An active retention hold refuses the removal; the request is recorded as waiting.
    Held {
        /// The waiting erasure.
        erasure_id: String,
    },
    /// The key was removed and the erasure recorded as shredded until it settles.
    Shredded {
        /// The erasure.
        erasure_id: String,
        /// When it may be reported completed.
        settles_at_ms: i64,
        /// The removed key, for the DEK cache to forget.
        key: K,
    },
}

impl<K> Erased<K> {
    /// The same outcome with `f` applied to the removed key.
    #[must_use]
    pub fn map_key<T>(self, f: impl FnOnce(K) -> T) -> Erased<T> {
        match self {
            Self::Nothing => Erased::Nothing,
            Self::Held { erasure_id } => Erased::Held { erasure_id },
            Self::Shredded {
                erasure_id,
                settles_at_ms,
                key,
            } => Erased::Shredded {
                erasure_id,
                settles_at_ms,
                key: f(key),
            },
        }
    }
}

impl<K> std::fmt::Debug for Erased<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nothing => f.write_str("Nothing"),
            Self::Held { erasure_id } => f
                .debug_struct("Held")
                .field("erasure_id", erasure_id)
                .finish(),
            Self::Shredded {
                erasure_id,
                settles_at_ms,
                ..
            } => f
                .debug_struct("Shredded")
                .field("erasure_id", erasure_id)
                .field("settles_at_ms", settles_at_ms)
                .finish_non_exhaustive(),
        }
    }
}

struct ErasureTuple {
    erasure_id: String,
    dek_id: String,
    subject: String,
    class: String,
    cause: String,
    state: String,
    pos: Option<i64>,
    part: Option<String>,
    requested_at: i64,
    settles_at: Option<i64>,
    completed_at: Option<i64>,
}

fn erasure_row(t: ErasureTuple) -> Result<ErasureRow, StoreError> {
    let target = match (t.pos, t.part) {
        (None, None) => ErasureTarget::Class,
        (Some(pos), Some(part)) => ErasureTarget::Part {
            pos: u64::try_from(pos).map_err(|_| StoreError::Corrupt)?,
            part,
        },
        _ => return Err(StoreError::Corrupt),
    };
    let state = match (t.state.as_str(), t.settles_at, t.completed_at) {
        ("waiting_on_hold", None, None) => ErasureState::WaitingOnHold,
        ("shredded", Some(settles_at_ms), None) => ErasureState::Shredded { settles_at_ms },
        ("completed", Some(settles_at_ms), Some(completed_at_ms)) => ErasureState::Completed {
            settles_at_ms,
            completed_at_ms,
        },
        _ => return Err(StoreError::Corrupt),
    };
    Ok(ErasureRow {
        erasure_id: t.erasure_id,
        dek_id: t.dek_id,
        subject: t.subject,
        class: RetentionClass::from_stored(&t.class).ok_or(StoreError::Corrupt)?,
        cause: ErasureCause::from_stored(&t.cause).ok_or(StoreError::Corrupt)?,
        target,
        state,
        requested_at_ms: t.requested_at,
    })
}

fn window_ms(settle: std::time::Duration) -> i64 {
    i64::try_from(settle.as_millis()).unwrap_or(i64::MAX)
}

/// Whether an active retention hold covers the subject or the class of part `part` at `pos`
/// (Access OP-74).
async fn part_held(tx: &mut LedgerTx<'_>, pos: i64, part: &str) -> Result<bool, StoreError> {
    let ledger = *tx.ledger().as_bytes();
    let held = sqlx::query_scalar!(
        r#"SELECT EXISTS (
                   SELECT 1 FROM work.body_part p
                   JOIN work.body_dek d ON d.ledger_id = p.ledger_id AND d.dek_id = p.dek_id
                   JOIN work.retention_hold h ON h.ledger_id = p.ledger_id
                   WHERE p.ledger_id = $1 AND p.pos = $2 AND p.part = $3
                     AND h.state = 'active'
                     AND (h.subject_ref IS NULL OR h.subject_ref = d.subject_ref)
                     AND (h.retention_class IS NULL OR h.retention_class = p.retention_class)
               ) AS "held!""#,
        ledger.as_slice(),
        pos,
        part
    )
    .fetch_one(tx.conn())
    .await?;
    Ok(held)
}

/// The waiting erasure of `dek_id` and `part`, written when there is none (Access OP-74).
async fn waiting(
    tx: &mut LedgerTx<'_>,
    dek_id: &str,
    part: Option<(i64, &str)>,
    cause: ErasureCause,
) -> Result<String, StoreError> {
    let ledger = *tx.ledger().as_bytes();
    let (pos, name) = part.unzip();
    let open = sqlx::query_scalar!(
        r#"SELECT erasure_id::text AS "erasure_id!" FROM work.erasure_log
           WHERE ledger_id = $1 AND dek_id = $2::text::uuid AND state = 'waiting_on_hold'
             AND pos IS NOT DISTINCT FROM $3::bigint AND part IS NOT DISTINCT FROM $4::text
           ORDER BY requested_at, erasure_id LIMIT 1"#,
        ledger.as_slice(),
        dek_id,
        pos,
        name
    )
    .fetch_optional(tx.conn())
    .await?;
    if let Some(id) = open {
        return Ok(id);
    }
    sqlx::query_scalar!(
        r#"INSERT INTO work.erasure_log (ledger_id, dek_id, cause, state, pos, part)
           VALUES ($1, $2::text::uuid, $3, 'waiting_on_hold', $4::bigint, $5::text)
           RETURNING erasure_id::text AS "erasure_id!""#,
        ledger.as_slice(),
        dek_id,
        cause.as_str(),
        pos,
        name
    )
    .fetch_one(tx.conn())
    .await
    .map_err(refused)
}

/// Records the key of `dek_id` and `part` as removed now, settling `window` from now: the
/// waiting erasure becomes shredded, or a shredded one is written (OP-45 item 5).
async fn shredded(
    tx: &mut LedgerTx<'_>,
    dek_id: &str,
    part: Option<(i64, &str)>,
    cause: ErasureCause,
    window: i64,
) -> Result<(String, i64), StoreError> {
    let ledger = *tx.ledger().as_bytes();
    let (pos, name) = part.unzip();
    let resumed = sqlx::query!(
        r#"UPDATE work.erasure_log
           SET state = 'shredded',
               settles_at = pg_catalog.now() + $5::bigint * interval '1 millisecond'
           WHERE ledger_id = $1 AND dek_id = $2::text::uuid AND state = 'waiting_on_hold'
             AND pos IS NOT DISTINCT FROM $3::bigint AND part IS NOT DISTINCT FROM $4::text
           RETURNING erasure_id::text AS "erasure_id!",
                     (extract(epoch FROM settles_at) * 1000)::bigint AS "settles_at!""#,
        ledger.as_slice(),
        dek_id,
        pos,
        name,
        window
    )
    .fetch_all(tx.conn())
    .await
    .map_err(refused)?;
    if let Some(first) = resumed
        .into_iter()
        .min_by(|a, b| a.erasure_id.cmp(&b.erasure_id))
    {
        return Ok((first.erasure_id, first.settles_at));
    }
    let row = sqlx::query!(
        r#"INSERT INTO work.erasure_log (ledger_id, dek_id, cause, state, settles_at, pos, part)
           VALUES ($1, $2::text::uuid, $3, 'shredded',
                   pg_catalog.now() + $4::bigint * interval '1 millisecond', $5::bigint, $6::text)
           RETURNING erasure_id::text AS "erasure_id!",
                     (extract(epoch FROM settles_at) * 1000)::bigint AS "settles_at!""#,
        ledger.as_slice(),
        dek_id,
        cause.as_str(),
        window,
        pos,
        name
    )
    .fetch_one(tx.conn())
    .await
    .map_err(refused)?;
    Ok((row.erasure_id, row.settles_at))
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
    /// its wrapped key becomes NULL, every part under it gets a tombstone, the row is terminal
    /// and the erasure is recorded as shredded until `settle` from now, the DEK cache lifetime
    /// plus the backup window. Under an active retention hold nothing is removed and the request
    /// is recorded as waiting (Access OP-74); without an active DEK, a waiting erasure of a DEK
    /// destroyed meanwhile is settled from its destruction.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] when a hold appears concurrently; [`StoreError::Db`] otherwise.
    pub async fn destroy_dek(
        &self,
        ledger: &LedgerId,
        subject: &str,
        class: RetentionClass,
        why: Shred,
        settle: std::time::Duration,
    ) -> Result<Erased<DekRow>, StoreError> {
        let id = ledger.as_bytes().as_slice();
        let window = window_ms(settle);
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
            sqlx::query!(
                "UPDATE work.erasure_log e
                 SET state = 'shredded',
                     settles_at = coalesce(d.destroyed_at, pg_catalog.now())
                                  + $4::bigint * interval '1 millisecond'
                 FROM work.body_dek d
                 WHERE e.ledger_id = $1 AND e.state = 'waiting_on_hold' AND e.pos IS NULL
                   AND d.ledger_id = e.ledger_id AND d.dek_id = e.dek_id
                   AND d.state = 'destroyed' AND d.subject_ref = $2 AND d.retention_class = $3",
                id,
                subject,
                class.as_str(),
                window
            )
            .execute(tx.conn())
            .await
            .map_err(refused)?;
            tx.commit().await?;
            return Ok(Erased::Nothing);
        };
        let held = sqlx::query_scalar!(
            r#"SELECT EXISTS (
                   SELECT 1 FROM work.retention_hold h
                   WHERE h.ledger_id = $1 AND h.state = 'active'
                     AND (h.subject_ref IS NULL OR h.subject_ref = $2)
                     AND (h.retention_class IS NULL OR h.retention_class = $3)
               ) AS "held!""#,
            id,
            subject,
            class.as_str()
        )
        .fetch_one(tx.conn())
        .await?;
        if held {
            let erasure_id = waiting(&mut tx, &row.dek_id, None, why.request()).await?;
            tx.commit().await?;
            return Ok(Erased::Held { erasure_id });
        }
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
        let (erasure_id, settles_at_ms) =
            shredded(&mut tx, &row.dek_id, None, why.request(), window).await?;
        tx.commit().await?;
        Ok(Erased::Shredded {
            erasure_id,
            settles_at_ms,
            key: row,
        })
    }

    /// Shreds the key of one part once, the redaction of that part alone (P-25, OP-15,
    /// OP-45 item 5): its wrapped key becomes NULL, the part gets a tombstone and the erasure
    /// is recorded as shredded until `settle` from now. Under an active retention hold nothing
    /// is removed and the request is recorded as waiting (Access OP-74); for a key already
    /// shredded, a waiting erasure of it is settled from its shredding.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] when a hold appears concurrently; [`StoreError::Db`] otherwise.
    pub async fn shred_part(
        &self,
        ledger: &LedgerId,
        pos: u64,
        part: &str,
        settle: std::time::Duration,
    ) -> Result<Erased<[u8; WRAPPED_LEN]>, StoreError> {
        let id = ledger.as_bytes().as_slice();
        let at = signed(pos)?;
        let window = window_ms(settle);
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let row = sqlx::query!(
            r#"SELECT k.wrapped_key AS "wrapped_key?", p.dek_id::text AS "dek_id!"
               FROM work.body_part_key k
               JOIN work.body_part p
                 ON p.ledger_id = k.ledger_id AND p.pos = k.pos AND p.part = k.part
               WHERE k.ledger_id = $1 AND k.pos = $2 AND k.part = $3 FOR UPDATE OF k"#,
            id,
            at,
            part
        )
        .fetch_optional(tx.conn())
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(Erased::Nothing);
        };
        let Some(key) = wrapped(row.wrapped_key)? else {
            sqlx::query!(
                "UPDATE work.erasure_log e
                 SET state = 'shredded',
                     settles_at = coalesce(k.shredded_at, pg_catalog.now())
                                  + $4::bigint * interval '1 millisecond'
                 FROM work.body_part_key k
                 WHERE e.ledger_id = $1 AND e.state = 'waiting_on_hold'
                   AND e.pos = $2 AND e.part = $3
                   AND k.ledger_id = e.ledger_id AND k.pos = e.pos AND k.part = e.part
                   AND k.wrapped_key IS NULL",
                id,
                at,
                part,
                window
            )
            .execute(tx.conn())
            .await
            .map_err(refused)?;
            tx.commit().await?;
            return Ok(Erased::Nothing);
        };
        if part_held(&mut tx, at, part).await? {
            let erasure_id = waiting(
                &mut tx,
                &row.dek_id,
                Some((at, part)),
                ErasureCause::Redaction,
            )
            .await?;
            tx.commit().await?;
            return Ok(Erased::Held { erasure_id });
        }
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
        let (erasure_id, settles_at_ms) = shredded(
            &mut tx,
            &row.dek_id,
            Some((at, part)),
            ErasureCause::Redaction,
            window,
        )
        .await?;
        tx.commit().await?;
        Ok(Erased::Shredded {
            erasure_id,
            settles_at_ms,
            key,
        })
    }

    /// Reports completed every shredded erasure of `ledger` whose settle time has passed
    /// (OP-45 item 5): the DEK caches have dropped the key and the backups that held it have
    /// expired. Returns the completed erasures.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn settle(&self, ledger: &LedgerId) -> Result<Vec<String>, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let mut done = sqlx::query_scalar!(
            r#"UPDATE work.erasure_log SET state = 'completed', completed_at = pg_catalog.now()
               WHERE ledger_id = $1 AND state = 'shredded' AND settles_at <= pg_catalog.now()
               RETURNING erasure_id::text AS "erasure_id!""#,
            ledger.as_bytes().as_slice()
        )
        .fetch_all(tx.conn())
        .await
        .map_err(refused)?;
        tx.commit().await?;
        done.sort();
        Ok(done)
    }

    /// Every erasure of `ledger` in request order, with where it stands (OP-45 item 5).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn erasures(&self, ledger: &LedgerId) -> Result<Vec<ErasureRow>, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let rows = sqlx::query_as!(
            ErasureTuple,
            r#"SELECT e.erasure_id::text AS "erasure_id!", e.dek_id::text AS "dek_id!",
                      d.subject_ref::text AS "subject!", d.retention_class::text AS "class!",
                      e.cause AS "cause!", e.state AS "state!", e.pos::bigint AS "pos?",
                      e.part::text AS "part?",
                      (extract(epoch FROM e.requested_at) * 1000)::bigint AS "requested_at!",
                      (extract(epoch FROM e.settles_at) * 1000)::bigint AS "settles_at?",
                      (extract(epoch FROM e.completed_at) * 1000)::bigint AS "completed_at?"
               FROM work.erasure_log e
               JOIN work.body_dek d ON d.ledger_id = e.ledger_id AND d.dek_id = e.dek_id
               WHERE e.ledger_id = $1
               ORDER BY e.requested_at, e.erasure_id"#,
            ledger.as_bytes().as_slice()
        )
        .fetch_all(tx.conn())
        .await?;
        tx.commit().await?;
        rows.into_iter().map(erasure_row).collect()
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

    // OP-14 OP-45 P-25 Access OP-78
    #[test]
    fn op_45_erasure_causes_round_trip_their_stored_names() {
        for c in ErasureCause::ALL {
            assert_eq!(ErasureCause::from_stored(c.as_str()), Some(c));
        }
        assert_eq!(ErasureCause::from_stored("subject_erasure"), None);
        assert_eq!(
            ErasureCause::SubjectRequest.shred(),
            Some(Shred::SubjectErasure)
        );
        assert_eq!(
            ErasureCause::RetentionExpired.shred(),
            Some(Shred::RetentionExpired)
        );
        assert_eq!(ErasureCause::Redaction.shred(), None);
        assert_eq!(ErasureCause::TenantClosure.shred(), None);
        assert_eq!(
            Shred::SubjectErasure.request(),
            ErasureCause::SubjectRequest
        );
    }

    fn tuple(state: &str, settles: Option<i64>, completed: Option<i64>) -> ErasureTuple {
        ErasureTuple {
            erasure_id: "0190d4a8-0000-7000-8000-000000000002".to_owned(),
            dek_id: "0190d4a8-0000-7000-8000-000000000001".to_owned(),
            subject: "party:alice".to_owned(),
            class: "work_record".to_owned(),
            cause: "redaction".to_owned(),
            state: state.to_owned(),
            pos: Some(3),
            part: Some("note".to_owned()),
            requested_at: 1_000,
            settles_at: settles,
            completed_at: completed,
        }
    }

    // OP-45 Access CR-32
    #[test]
    fn op_45_an_erasure_is_waiting_shredded_until_it_settles_or_completed() {
        let read = |t| erasure_row(t).map(|r| r.state).ok();
        assert_eq!(
            read(tuple("waiting_on_hold", None, None)),
            Some(ErasureState::WaitingOnHold)
        );
        assert_eq!(
            read(tuple("shredded", Some(2_000), None)),
            Some(ErasureState::Shredded {
                settles_at_ms: 2_000,
            })
        );
        assert_eq!(
            read(tuple("completed", Some(2_000), Some(2_500))),
            Some(ErasureState::Completed {
                settles_at_ms: 2_000,
                completed_at_ms: 2_500,
            })
        );
        for bad in [
            tuple("waiting_on_hold", Some(2_000), None),
            tuple("shredded", None, None),
            tuple("completed", None, Some(2_500)),
            tuple("completed", Some(2_000), None),
            tuple("deleted", Some(2_000), Some(2_500)),
        ] {
            assert_eq!(read(bad), None);
        }
        let mut class = tuple("shredded", Some(2_000), None);
        class.pos = None;
        class.part = None;
        assert_eq!(
            erasure_row(class).map(|r| r.target).ok(),
            Some(ErasureTarget::Class)
        );
        let mut half = tuple("shredded", Some(2_000), None);
        half.part = None;
        assert!(erasure_row(half).is_err());
        let shown = format!("{:?}", erasure_row(tuple("waiting_on_hold", None, None)));
        assert!(!shown.contains("party:alice"), "{shown}");
    }
}
