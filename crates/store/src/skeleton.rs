//! The rows a record writes beside its log row in the append transaction (OP-2, OP-13, T-90, P-5 item 4): the externally signed bytes exactly as received with their roles, the normalized header, the Works it concerns (first-seen Works get their root), its basis, relations and body commitments, and the inbound event it answers (OP-8, OP-38 item 5); the values come from the kernel's decoding of the record, never from the caller's description of it, and the stored entries read back with their `COSE_Sign1` bytes for verification.

use crate::{ItemRef, LedgerTx, StoreError};

/// What kind of externally signed bytes a row keeps (T-90).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceivedKind {
    /// A Work record's `COSE_Sign1`.
    CoseSign1,
    /// An Access decision receipt.
    AccessDecisionReceipt,
    /// An Access portable authority proof.
    AccessPortableAuthorityProof,
    /// An Access approval act statement.
    AccessApprovalActStatement,
    /// An Access eligibility check.
    AccessEligibilityCheck,
    /// An Access authentication context.
    AccessAuthContext,
    /// A `WebAuthn` assertion.
    WebauthnAssertion,
    /// A counterparty's record.
    ForeignRecord,
}

impl ReceivedKind {
    /// Every kind.
    pub const ALL: [Self; 8] = [
        Self::CoseSign1,
        Self::AccessDecisionReceipt,
        Self::AccessPortableAuthorityProof,
        Self::AccessApprovalActStatement,
        Self::AccessEligibilityCheck,
        Self::AccessAuthContext,
        Self::WebauthnAssertion,
        Self::ForeignRecord,
    ];

    /// The kind stored as `kind`; `None` for any other text.
    #[must_use]
    pub fn from_stored(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == kind)
    }

    /// The stored `kind`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoseSign1 => "cose_sign1",
            Self::AccessDecisionReceipt => "access_decision_receipt",
            Self::AccessPortableAuthorityProof => "access_portable_authority_proof",
            Self::AccessApprovalActStatement => "access_approval_act_statement",
            Self::AccessEligibilityCheck => "access_eligibility_check",
            Self::AccessAuthContext => "access_auth_context",
            Self::WebauthnAssertion => "webauthn_assertion",
            Self::ForeignRecord => "foreign_record",
        }
    }
}

/// What received bytes are to the record that carries them (T-90).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceivedRole {
    /// The author signature; its digest is the envelope `proof_commit` (P-75).
    AuthorSignature,
    /// The proof of the authority exercised (P-13).
    AuthorityProof,
    /// The Access authentication context of an unsigned human record (P-21).
    AuthContext,
    /// A `WebAuthn` assertion.
    WebauthnAssertion,
    /// The counterparty record a federated record comes from.
    FederatedSource,
    /// An evidence presenter's `COSE_Sign1` (P-107 item 3).
    PresenterSignature,
}

impl ReceivedRole {
    /// Every role.
    pub const ALL: [Self; 6] = [
        Self::AuthorSignature,
        Self::AuthorityProof,
        Self::AuthContext,
        Self::WebauthnAssertion,
        Self::FederatedSource,
        Self::PresenterSignature,
    ];

    /// The role stored as `role`; `None` for any other text.
    #[must_use]
    pub fn from_stored(role: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == role)
    }

    /// The stored `role`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorSignature => "author_signature",
            Self::AuthorityProof => "authority_proof",
            Self::AuthContext => "auth_context",
            Self::WebauthnAssertion => "webauthn_assertion",
            Self::FederatedSource => "federated_source",
            Self::PresenterSignature => "presenter_signature",
        }
    }
}

/// Externally signed bytes exactly as received; the database names them by their SHA-256 (T-90).
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedRow {
    /// The kind.
    pub kind: ReceivedKind,
    /// The role for this record.
    pub role: ReceivedRole,
    /// The bytes, 1 to 262 144 of them.
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for ReceivedRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedRow")
            .field("kind", &self.kind)
            .field("role", &self.role)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// The normalized header of a record (OP-2, OP-13, P-11, P-12, P-21, P-75).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRow {
    /// `act`, `declaration` or `claim`.
    pub kind: &'static str,
    /// The subtype URI.
    pub record_type: String,
    /// The author's Party reference.
    pub author: String,
    /// The author's actor type.
    pub author_actor_type: &'static str,
    /// Where the actor type comes from.
    pub author_actor_type_source: &'static str,
    /// The author's `occurred_at`, Unix milliseconds.
    pub occurred_at_ms: Option<u64>,
    /// `admitted` or `quarantined`.
    pub ingest: &'static str,
    /// The quarantine reason code.
    pub ingest_reason: Option<String>,
    /// The envelope `proof_commit`.
    pub proof_commit: Option<[u8; 32]>,
    /// The envelope `auth_context.ref`.
    pub auth_context_ref: Option<[u8; 32]>,
    /// `versions.protocol`.
    pub protocol: (u64, u64),
    /// `versions.schema`.
    pub schema_digest: [u8; 32],
}

/// One endpoint of a normalized relation (P-73).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointRow {
    /// The record itself, a source only.
    This,
    /// A record.
    Record([u8; 32]),
    /// Evidence.
    Evidence([u8; 32]),
    /// A Work.
    Work([u8; 16]),
    /// A Party.
    Party(String),
    /// An external reference.
    External(String),
}

impl EndpointRow {
    fn parts(&self) -> (&'static str, Option<&[u8]>, Option<&str>) {
        match self {
            Self::This => ("self", None, None),
            Self::Record(d) => ("record", Some(d.as_slice()), None),
            Self::Evidence(d) => ("evidence", Some(d.as_slice()), None),
            Self::Work(w) => ("work", Some(w.as_slice()), None),
            Self::Party(p) => ("party", None, Some(p)),
            Self::External(e) => ("external", None, Some(e)),
        }
    }
}

/// One relation of a record, in author order (P-14, P-73).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationRow {
    /// The relation name.
    pub rel: &'static str,
    /// The source.
    pub source: EndpointRow,
    /// The target.
    pub target: EndpointRow,
    /// The qualifier or `derived_from` role URI.
    pub qualifier: Option<String>,
}

/// One body part commitment (P-17, P-68).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyCommitmentRow {
    /// The part name.
    pub part: String,
    /// The commitment.
    pub commit: [u8; 32],
}

/// The skeleton of a decoded record: everything but the body itself (OP-13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton {
    /// The header.
    pub header: HeaderRow,
    /// The Works it concerns, in `concerns` order (C-34).
    pub concerns: Vec<[u8; 16]>,
    /// Its basis (P-28, P-81).
    pub basis: Vec<[u8; 32]>,
    /// Its relations, in author order.
    pub relations: Vec<RelationRow>,
    /// Its body commitments, in author order.
    pub body: Vec<BodyCommitmentRow>,
    /// The compromise window it notices, when it is a SEC-36 notice (WD-123).
    pub notice: Option<NoticeRow>,
}

/// The compromise window a SEC-36 notice states, read from the notice record (WD-123, C-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeRow {
    /// SHA-256 of the Access event's bytes.
    pub event_digest: [u8; 32],
    /// The window's start, Unix milliseconds.
    pub window_from_ms: u64,
    /// The window's end, Unix milliseconds.
    pub window_to_ms: u64,
    /// The compromised kids.
    pub kids: Vec<[u8; 32]>,
    /// The compromised Party.
    pub party: Option<String>,
}

/// Who signed or wrote a record, kept for the SEC-36 lookup of a tenant's ledgers (WD-123).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerRow {
    /// The tenant the record was written for.
    pub tenant: String,
    /// The `kid` of a signed record.
    pub kid: Option<[u8; 32]>,
    /// The author of an unsigned record, written with its `auth_context`.
    pub author: Option<String>,
    /// The device Instance the `auth_context` of an unsigned record names (P-116).
    pub instance: Option<[u8; 16]>,
}

/// An inbound event or federated record a record answers, deduplicated by `source` and `source_id` (OP-8, OP-38 item 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRow {
    /// Log position of the record.
    pub pos: u64,
    /// The event source.
    pub source: String,
    /// The event id at the source.
    pub source_id: String,
    /// The digest of what arrived.
    pub content_digest: [u8; 32],
    /// Ledger time of the record, Unix milliseconds.
    pub seen_at_ms: u64,
}

/// A stored ledger entry with its author signature bytes as received (P-5 item 4, P-75).
#[derive(Clone, PartialEq, Eq)]
pub struct StoredLogEntry {
    /// Log position.
    pub pos: u64,
    /// The `SignedRecord` bytes; the genesis bytes at position 0.
    pub record_bytes: Vec<u8>,
    /// The envelope bytes.
    pub envelope_bytes: Vec<u8>,
    /// The `COSE_Sign1` bytes of a signed record.
    pub cose_sign1: Option<Vec<u8>>,
}

impl std::fmt::Debug for StoredLogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredLogEntry")
            .field("pos", &self.pos)
            .field("record_bytes", &self.record_bytes.len())
            .field("envelope_bytes", &self.envelope_bytes.len())
            .field("cose_sign1", &self.cose_sign1.as_ref().map(Vec::len))
            .finish()
    }
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// A constraint the rows break: nothing of the batch is written and the writer stays leader.
pub(crate) fn refused(e: sqlx::Error) -> StoreError {
    let constraint = e.as_database_error().and_then(|d| {
        d.code()
            .is_some_and(|c| c.starts_with("23"))
            .then(|| d.constraint().unwrap_or_default().to_owned())
    });
    constraint.map_or(StoreError::Db(e), StoreError::Constraint)
}

impl LedgerTx<'_> {
    /// Writes `rows` as received for the record at `pos` (T-90): each digest once, the first position that carried it, then nothing more.
    pub(crate) async fn insert_received(
        &mut self,
        pos: u64,
        rows: &[ReceivedRow],
    ) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        for r in rows {
            sqlx::query!(
                "INSERT INTO work.received_bytes (ledger_id, digest, kind, bytes, first_pos)
                 VALUES ($1, pg_catalog.sha256($3::bytea), $2, $3::bytea, $4)
                 ON CONFLICT (ledger_id, digest) DO NOTHING",
                ledger.as_slice(),
                r.kind.as_str(),
                r.bytes.as_slice(),
                signed(pos)?
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        Ok(())
    }

    /// Links `rows` to the record at `pos` by role (T-90).
    pub(crate) async fn link_received(
        &mut self,
        pos: u64,
        rows: &[ReceivedRow],
    ) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        for r in rows {
            sqlx::query!(
                "INSERT INTO work.log_received (ledger_id, pos, role, digest)
                 VALUES ($1, $2, $3, pg_catalog.sha256($4::bytea))",
                ledger.as_slice(),
                signed(pos)?,
                r.role.as_str(),
                r.bytes.as_slice()
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        Ok(())
    }

    /// Writes the header of the record at `at` (OP-2, OP-13, P-11, P-75).
    async fn insert_header(&mut self, at: i64, h: &HeaderRow) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        let occurred = h.occurred_at_ms.map(signed).transpose()?;
        sqlx::query!(
            "INSERT INTO work.record_header
             (ledger_id, pos, kind, record_type, author, author_actor_type,
              author_actor_type_source, occurred_at, ingest, ingest_reason, proof_commit,
              auth_context_ref, protocol_major, protocol_minor, schema_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7,
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $8::bigint::double precision,
             $9, $10, $11, $12, $13, $14, $15)",
            ledger.as_slice(),
            at,
            h.kind,
            h.record_type.as_str(),
            h.author.as_str(),
            h.author_actor_type,
            h.author_actor_type_source,
            occurred,
            h.ingest,
            h.ingest_reason.as_deref(),
            h.proof_commit.as_ref().map(<[u8; 32]>::as_slice),
            h.auth_context_ref.as_ref().map(<[u8; 32]>::as_slice),
            signed(h.protocol.0)?,
            signed(h.protocol.1)?,
            h.schema_digest.as_slice()
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(())
    }

    /// Writes the skeleton of the record at `pos` (OP-2, OP-13, C-34): its header, a root for each Work seen first here, its `concerns`, basis, relations and body commitments.
    pub(crate) async fn insert_skeleton(
        &mut self,
        pos: u64,
        s: &Skeleton,
    ) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        let id = ledger.as_slice();
        let at = signed(pos)?;
        self.insert_header(at, &s.header).await?;
        for work in &s.concerns {
            sqlx::query!(
                "INSERT INTO work.work_root (ledger_id, work_id, first_pos)
                 VALUES ($1, pg_catalog.encode($2::bytea, 'hex')::uuid, $3)
                 ON CONFLICT (ledger_id, work_id) DO NOTHING",
                id,
                work.as_slice(),
                at
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
            sqlx::query!(
                "INSERT INTO work.log_concerns (ledger_id, work_id, pos)
                 VALUES ($1, pg_catalog.encode($2::bytea, 'hex')::uuid, $3)",
                id,
                work.as_slice(),
                at
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        for basis in &s.basis {
            sqlx::query!(
                "INSERT INTO work.log_basis (ledger_id, pos, basis_record_id) VALUES ($1, $2, $3)",
                id,
                at,
                basis.as_slice()
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        for (ordinal, r) in (0_i64..).zip(&s.relations) {
            let (source_kind, source_bytes, source_text) = r.source.parts();
            let (target_kind, target_bytes, target_text) = r.target.parts();
            sqlx::query!(
                "INSERT INTO work.log_relation
                 (ledger_id, pos, ordinal, rel, source_kind, source_bytes, source_text,
                  target_kind, target_bytes, target_text, qualifier)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                id,
                at,
                ordinal,
                r.rel,
                source_kind,
                source_bytes,
                source_text,
                target_kind,
                target_bytes,
                target_text,
                r.qualifier.as_deref()
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        for b in &s.body {
            sqlx::query!(
                "INSERT INTO work.body_commitment (ledger_id, pos, part, part_commit)
                 VALUES ($1, $2, $3, $4)",
                id,
                at,
                b.part.as_str(),
                b.commit.as_slice()
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        if let Some(n) = &s.notice {
            self.insert_notice(at, n).await?;
        }
        Ok(())
    }

    /// Writes the window of a SEC-36 notice at `at`; a second notice of the same event in the
    /// ledger breaks `compromise_notice_pk` (WD-123).
    async fn insert_notice(&mut self, at: i64, n: &NoticeRow) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        let kids: Vec<Vec<u8>> = n.kids.iter().map(|k| k.to_vec()).collect();
        sqlx::query!(
            "INSERT INTO work.compromise_notice
             (ledger_id, event_digest, pos, window_from, window_to, kids, party)
             VALUES ($1, $2, $3,
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $4::bigint::double precision,
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $5::bigint::double precision,
             $6, $7)",
            ledger.as_slice(),
            n.event_digest.as_slice(),
            at,
            signed(n.window_from_ms)?,
            signed(n.window_to_ms)?,
            kids.as_slice(),
            n.party.as_deref()
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(())
    }

    /// Writes who signed or wrote the record at `pos`, recorded at `recorded_at_ms` (WD-123).
    pub(crate) async fn insert_signer(
        &mut self,
        pos: u64,
        recorded_at_ms: u64,
        row: &SignerRow,
    ) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        sqlx::query!(
            "INSERT INTO work.record_signer (ledger_id, pos, tenant, recorded_at, kid, author, instance)
             VALUES ($1, $2, $3,
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $4::bigint::double precision,
             $5, $6, $7)",
            ledger.as_slice(),
            signed(pos)?,
            row.tenant.as_str(),
            signed(recorded_at_ms)?,
            row.kid.as_ref().map(<[u8; 32]>::as_slice),
            row.author.as_deref(),
            row.instance.as_ref().map(<[u8; 16]>::as_slice)
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(())
    }

    /// Whether `source` and `source_id` are already seen in a hot partition (OP-38 item 5).
    pub(crate) async fn inbound_seen(&mut self, row: &InboundRow) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let seen = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM work.inbound_seen
               WHERE ledger_id = $1 AND source = $2 AND source_id = $3) AS "seen!""#,
            ledger.as_slice(),
            row.source.as_str(),
            row.source_id.as_str()
        )
        .fetch_one(self.conn())
        .await?;
        Ok(seen)
    }

    /// Writes `row` with its record (OP-8, OP-38 item 5); a month without a partition is refused by the database (OP-37).
    pub(crate) async fn insert_inbound(&mut self, row: &InboundRow) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        sqlx::query!(
            "INSERT INTO work.inbound_seen
             (ledger_id, source, source_id, content_digest, result_pos, seen_at)
             VALUES ($1, $2, $3, $4, $5,
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $6::bigint::double precision)",
            ledger.as_slice(),
            row.source.as_str(),
            row.source_id.as_str(),
            row.content_digest.as_slice(),
            signed(row.pos)?,
            signed(row.seen_at_ms)?
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(())
    }

    /// The stored version of `item`, `None` before its first record (P-29).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn item_version(&mut self, item: &ItemRef) -> Result<Option<u64>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let version = sqlx::query_scalar!(
            r#"SELECT version AS "version!" FROM work.item_head
               WHERE ledger_id = $1 AND item_kind = $2 AND item_id = $3"#,
            ledger.as_slice(),
            item.kind(),
            item.id()
        )
        .fetch_optional(self.conn())
        .await?;
        version
            .map(|v| u64::try_from(v).map_err(|_| StoreError::Corrupt))
            .transpose()
    }

    /// How many records concern `work` (C-34), the count a Work's version equals (T-89).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range count.
    pub async fn concerning(&mut self, work: &[u8; 16]) -> Result<u64, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let n = sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM work.log_concerns
               WHERE ledger_id = $1 AND work_id = pg_catalog.encode($2::bytea, 'hex')::uuid"#,
            ledger.as_slice(),
            work.as_slice()
        )
        .fetch_one(self.conn())
        .await?;
        u64::try_from(n).map_err(|_| StoreError::Corrupt)
    }

    /// Up to `limit` stored entries from position `from` on, in position order, each with the `COSE_Sign1` bytes kept for its author signature (P-5 item 4, P-75), so the kernel verifies them from the bytes alone.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn entries(
        &mut self,
        from: u64,
        limit: u32,
    ) -> Result<Vec<StoredLogEntry>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query!(
            r#"SELECT l.pos AS "pos!", l.record_bytes AS "record_bytes!",
                      l.envelope_bytes AS "envelope_bytes!", b.bytes AS "cose_sign1?"
               FROM ledger.log l
               LEFT JOIN work.log_received r
                 ON r.ledger_id = l.ledger_id AND r.pos = l.pos AND r.role = 'author_signature'
               LEFT JOIN work.received_bytes b
                 ON b.ledger_id = r.ledger_id AND b.digest = r.digest
               WHERE l.ledger_id = $1 AND l.pos >= $2
               ORDER BY l.pos LIMIT $3"#,
            ledger.as_slice(),
            signed(from)?,
            i64::from(limit)
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(StoredLogEntry {
                    pos: u64::try_from(r.pos).map_err(|_| StoreError::Corrupt)?,
                    record_bytes: r.record_bytes,
                    envelope_bytes: r.envelope_bytes,
                    cose_sign1: r.cose_sign1,
                })
            })
            .collect()
    }
}
