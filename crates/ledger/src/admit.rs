//! The admission path (OP-5 item 4, T-9, T-89, T-90, P-5 item 4): in the caller's task and
//! outside the sequencer's critical section, the kernel verifies the bytes exactly as received,
//! decodes and validates the record, checks the ledger it declares and names the items it
//! touches; the result is the [`PendingRecord`] the group commit appends with its envelope,
//! received bytes, skeleton, item heads and outbox pointers in one transaction. The envelope's
//! actor types come from Access's identity bindings of the record's Parties, a declared type
//! only as `declared_unverified` (P-12, C-17). Nothing here takes a record id, an item, a
//! version or the source of an actor type from the caller.

use std::fmt::Write as _;

use suiss_crypto::dcbor::Value;
use suiss_crypto::digest::{Digest, sha256};
use work_kernel::codec::{Decoded, decode_record, proof_commit, record_id};
use work_kernel::cose::parse_container;
use work_kernel::id::{PartyRef, RecordId, WorkId};
use work_kernel::items::{self, ItemKey, Touch};
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::{EnvelopeField, Limit, Reason, Schema};
use work_kernel::record::{AuthorityProofKind, Claim, ClaimType, Record};
use work_kernel::relation::{
    ConcernsSource, DerivedRole, DerivedTarget, ReferenceTarget, Relation,
};
use work_kernel::uri::{CORE_ROOT, ExtKey, ExternalRef, TypeUri};
use work_kernel::validate::{
    ActorTypeEntry, ActorTypes, Origin, Outcome, ValidationContext, validate,
};
use work_kernel::verify::{
    SignatureVerifier, UnsignedRecord, VerifyOutcome, verify_signed, verify_unsigned,
};
use work_proto::events::{EventType, Item, RecordFacts};
use work_store::{
    BodyCommitmentRow, EndpointRow, Expect, HeaderRow, ItemRef, LedgerId, ReceivedKind,
    ReceivedRole, ReceivedRow, RelationRow, Skeleton,
};

use crate::actors::{ActorBindings, DeclaredActors};
use crate::auth_context::{self, AuthContext, AuthContextInvalid};
use crate::{
    BodyError, BodyOpening, BodyWriter, Committed, EventPointer, GroupCommit, Inbound, ItemTouch,
    KeyClaim, ObjectStore, PendingRecord, SubmitError,
};

/// Most bytes of one received item (T-90, P-33).
pub const MAX_RECEIVED: usize = 262_144;

/// Why the admission path refused a record; nothing was written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmitError {
    /// The kernel's reason: a signature, CBOR, schema, rule or limit reason.
    #[error("rejected: {0}")]
    Rejected(Reason),
    /// The Access `auth_context` of an unsigned record does not verify or is not bound to it
    /// (P-116 item 4).
    #[error("auth_context_invalid: {0}")]
    AuthContext(AuthContextInvalid),
}

impl From<Reason> for AdmitError {
    fn from(reason: Reason) -> Self {
        Self::Rejected(reason)
    }
}

impl From<AuthContextInvalid> for AdmitError {
    fn from(invalid: AuthContextInvalid) -> Self {
        Self::AuthContext(invalid)
    }
}

/// How a record arrived (P-20, P-21).
#[derive(Clone, Copy)]
pub enum Arrival<'a> {
    /// Tagged `COSE_Sign1` bytes with the `SignedRecord` attached.
    Signed(&'a [u8]),
    /// `SignedRecord` bytes of a human author with the Access `auth_context` artifact bound to
    /// them (P-21 item 3, P-116).
    Unsigned {
        /// The `SignedRecord` bytes.
        record: &'a [u8],
        /// The artifact with what Work looked up to verify it.
        auth_context: AuthContext<'a>,
    },
}

impl std::fmt::Debug for Arrival<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signed(b) => f.debug_tuple("Signed").field(&b.len()).finish(),
            Self::Unsigned {
                record,
                auth_context,
            } => f
                .debug_struct("Unsigned")
                .field("record", &record.len())
                .field("auth_context", auth_context)
                .finish(),
        }
    }
}

/// A write request after the Access lookups: the bytes as received and the inputs the kernel
/// takes that are not record bytes (P-12, P-19, T-65, T-66).
#[derive(Debug, Clone)]
pub struct Submission<'a> {
    /// The record as it arrived.
    pub arrival: Arrival<'a>,
    /// The Parties of the author, every `on_behalf_of` ring and every evidence presenter, with
    /// the type the request declares for each (P-12, EV-35).
    pub declared: &'a DeclaredActors,
    /// The actor types Access's identity bindings name; the envelope takes a Party's type from
    /// here, `access_binding`, and its declared type, `declared_unverified`, only without one
    /// (P-12, C-17).
    pub bindings: &'a ActorBindings,
    /// The origin the Work service supplies (T-66).
    pub origin: Origin,
    /// Extension keys this verifier implements (P-19).
    pub understood_extensions: &'a [ExtKey],
    /// The effective semantic limits (T-65).
    pub limits: SemanticLimits,
    /// The event type of every item the record touches when its wire name gives no catalogued
    /// type (P-38); otherwise the types come from the record (T-98 item 4).
    pub event_type: &'a str,
    /// The W3C `traceparent` of the request (P-42).
    pub traceparent: &'a str,
    /// The idempotency key of the request (OP-8).
    pub idempotency: Option<KeyClaim>,
    /// The inbound event the record answers (OP-8).
    pub inbound: Option<Inbound>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _written = write!(s, "{b:02x}");
        s
    })
}

fn received(kind: ReceivedKind, role: ReceivedRole, bytes: &[u8]) -> Result<ReceivedRow, Reason> {
    if bytes.is_empty() || bytes.len() > MAX_RECEIVED {
        return Err(Reason::LimitExceeded(Limit::Request));
    }
    Ok(ReceivedRow {
        kind,
        role,
        bytes: bytes.to_vec(),
    })
}

fn actor_entry(e: ActorTypeEntry) -> Value {
    Value::Array(vec![
        Value::text(e.actor_type.wire_name()),
        Value::text(e.source.wire_name()),
    ])
}

/// The envelope `actor_type` annotation (P-12, INV-18, EV-35).
pub(crate) fn actor_types(t: &ActorTypes) -> Value {
    let mut map = vec![(Value::text("author"), actor_entry(t.author))];
    if !t.on_behalf_of.is_empty() {
        let rings = t.on_behalf_of.iter().copied().map(actor_entry).collect();
        map.push((Value::text("on_behalf_of"), Value::Array(rings)));
    }
    if !t.evidence.is_empty() {
        let presenters = t.evidence.iter().copied().map(actor_entry).collect();
        map.push((Value::text("evidence"), Value::Array(presenters)));
    }
    Value::Map(map)
}

fn item_ref(key: ItemKey) -> Result<ItemRef, Reason> {
    match key {
        ItemKey::Work(w) => Ok(ItemRef::Work(*w.as_bytes())),
        ItemKey::Commitment(r) => Ok(ItemRef::Commitment(*r.0.as_bytes())),
        ItemKey::Condition(r) => Ok(ItemRef::Condition(*r.0.as_bytes())),
        _ => Err(Reason::ProtocolVersionUnknown),
    }
}

pub(crate) fn touch(t: &Touch) -> Result<ItemTouch, Reason> {
    Ok(ItemTouch {
        item: item_ref(t.item)?,
        expect: match t.expect {
            items::Expect::Next => Expect::Next,
            items::Expect::Version(v) => Expect::Version(v),
        },
        heads: t
            .heads
            .as_ref()
            .map(|h| h.iter().map(|r| *r.0.as_bytes()).collect()),
    })
}

fn record_endpoint(id: &RecordId) -> EndpointRow {
    EndpointRow::Record(*id.0.as_bytes())
}

fn this_or(source: Option<&RecordId>) -> EndpointRow {
    source.map_or(EndpointRow::This, record_endpoint)
}

fn work_endpoint(w: &WorkId) -> EndpointRow {
    EndpointRow::Work(*w.as_bytes())
}

fn party_endpoint(p: &PartyRef) -> EndpointRow {
    EndpointRow::Party(p.as_str().to_owned())
}

fn external_endpoint(e: &ExternalRef) -> EndpointRow {
    EndpointRow::External(e.as_str().to_owned())
}

fn uri(q: Option<&TypeUri>) -> Option<String> {
    q.map(|u| u.as_str().to_owned())
}

fn core_uri(point: &str, name: &str) -> String {
    format!("{CORE_ROOT}{point}/{name}")
}

/// One relation as `log_relation` normalizes it (P-14, P-73).
#[allow(
    clippy::too_many_lines,
    reason = "one arm per canonical relation (P-14)"
)]
fn relation(r: &Relation) -> RelationRow {
    let (rel, source, target, qualifier) = match r {
        Relation::EngagedIn {
            source,
            target,
            qualifier,
        } => (
            "engaged_in",
            party_endpoint(source),
            work_endpoint(target),
            uri(qualifier.as_ref()),
        ),
        Relation::Concerns {
            source,
            target,
            qualifier,
        } => {
            let source = match source {
                ConcernsSource::Record(id) => record_endpoint(id),
                ConcernsSource::External(e) => external_endpoint(e),
            };
            (
                "concerns",
                source,
                work_endpoint(target),
                uri(qualifier.as_ref()),
            )
        }
        Relation::PartOf {
            source,
            target,
            qualifier,
        } => (
            "part_of",
            work_endpoint(source),
            work_endpoint(target),
            uri(qualifier.as_ref()),
        ),
        Relation::Serves {
            source,
            target,
            qualifier,
        } => (
            "serves",
            this_or(source.as_ref()),
            record_endpoint(target),
            uri(qualifier.as_ref()),
        ),
        Relation::Supersedes { target, qualifier } => (
            "supersedes",
            EndpointRow::This,
            record_endpoint(target),
            uri(qualifier.as_ref()),
        ),
        Relation::DerivedFrom {
            source,
            target,
            role,
        } => {
            let target = match target {
                DerivedTarget::Record(id) => record_endpoint(id),
                DerivedTarget::Evidence(d) => EndpointRow::Evidence(*d.as_bytes()),
                DerivedTarget::External(e) => external_endpoint(e),
            };
            let role = match role {
                DerivedRole::Core(c) => core_uri("derived_from", c.wire_name()),
                DerivedRole::Extension(u) => u.as_str().to_owned(),
            };
            ("derived_from", this_or(source.as_ref()), target, Some(role))
        }
        Relation::OnBehalfOf {
            source,
            target,
            qualifier,
        } => (
            "on_behalf_of",
            party_endpoint(source),
            party_endpoint(target),
            uri(qualifier.as_ref()),
        ),
        Relation::References {
            source,
            target,
            qualifier,
        } => {
            let target = match target {
                ReferenceTarget::External(e) => external_endpoint(e),
                ReferenceTarget::Record(id) => record_endpoint(id),
            };
            (
                "references",
                this_or(source.as_ref()),
                target,
                uri(qualifier.as_ref()),
            )
        }
    };
    RelationRow {
        rel,
        source,
        target,
        qualifier,
    }
}

fn record_type(record: &Record) -> String {
    match record {
        Record::Claim(Claim {
            subtype: ClaimType::Core(c),
            ..
        }) => core_uri("claim", c.wire_name()),
        _ => record
            .subtype_uri()
            .map(|u| u.as_str().to_owned())
            .unwrap_or_default(),
    }
}

fn occurred_at(record: &Record) -> Option<u64> {
    match record {
        Record::Act(a) => Some(a.occurred_at.0),
        Record::Declaration(d) => d.occurred_at.map(|t| t.0),
        Record::Claim(c) => Some(c.occurred_at.0),
    }
}

/// The envelope binding of the author: the `proof_commit` of a signed record or the
/// authentication context reference of an unsigned one (P-21, P-75).
#[derive(Clone, Copy)]
pub(crate) struct Binding {
    pub(crate) proof_commit: Option<[u8; 32]>,
    pub(crate) auth_context_ref: Option<[u8; 32]>,
}

/// The skeleton of a decoded record (OP-13, draft table mapping).
pub(crate) fn skeleton(
    record: &Record,
    actors: &ActorTypes,
    quarantine: Option<String>,
    binding: Binding,
) -> Skeleton {
    let core = record.core();
    let header = HeaderRow {
        kind: record.kind().wire_name(),
        record_type: record_type(record),
        author: core.author.as_str().to_owned(),
        author_actor_type: actors.author.actor_type.wire_name(),
        author_actor_type_source: actors.author.source.wire_name(),
        occurred_at_ms: occurred_at(record),
        ingest: if quarantine.is_some() {
            "quarantined"
        } else {
            "admitted"
        },
        ingest_reason: quarantine,
        proof_commit: binding.proof_commit,
        auth_context_ref: binding.auth_context_ref,
        protocol: (core.versions.protocol.major, core.versions.protocol.minor),
        schema_digest: *core.versions.schema.as_bytes(),
    };
    Skeleton {
        header,
        concerns: core.concerns.iter().map(|w| *w.as_bytes()).collect(),
        basis: record.basis().iter().map(|b| *b.0.as_bytes()).collect(),
        relations: core.relations.iter().flatten().map(relation).collect(),
        body: core
            .body
            .iter()
            .flatten()
            .map(|b| BodyCommitmentRow {
                part: b.part.as_str().to_owned(),
                commit: *b.commit.as_bytes(),
            })
            .collect(),
    }
}

pub(crate) fn ingest(quarantine: Option<&str>) -> Value {
    quarantine.map_or_else(
        || Value::text("admitted"),
        |code| Value::Array(vec![Value::text("quarantined"), Value::text(code)]),
    )
}

/// The envelope `auth_context` of an unsigned human record (P-21, P-116 item 3).
pub(crate) fn auth_context_value(reference: &[u8; 32], step_up: bool, assurance: &str) -> Value {
    Value::Map(vec![
        (Value::text("ref"), Digest(*reference).to_value()),
        (Value::text("step_up"), Value::Bool(step_up)),
        (Value::text("assurance"), Value::text(assurance)),
    ])
}

/// A record as it arrived: its `SignedRecord` bytes, the bytes kept as received and how the
/// envelope binds its author.
struct Arrived {
    record_bytes: Vec<u8>,
    received: Vec<ReceivedRow>,
    binding: Binding,
    auth_context: Option<Value>,
}

/// Verifies a signed arrival through `verifier` and keeps its `COSE_Sign1` (P-6, P-75), or
/// verifies the `auth_context` artifact of an unsigned one against its record identifier,
/// names it by Access's `digest` with the assurance and step-up of its payload, and keeps it
/// as received (P-21, P-116).
fn arrive<V: SignatureVerifier + ?Sized>(
    verifier: &V,
    arrival: Arrival<'_>,
) -> Result<Arrived, AdmitError> {
    match arrival {
        Arrival::Signed(cose) => {
            let row = received(ReceivedKind::CoseSign1, ReceivedRole::AuthorSignature, cose)?;
            let payload = parse_container(cose)?
                .payload
                .ok_or(Reason::Schema(Schema::Container))?;
            match verify_signed(verifier, cose, None) {
                VerifyOutcome::Rejected(reason) => return Err(reason.into()),
                VerifyOutcome::Verified(v) if v.record != record_id(&payload) => {
                    return Err(Reason::EnvelopeMismatch(EnvelopeField::Record).into());
                }
                VerifyOutcome::Verified(_) => {}
            }
            Ok(Arrived {
                record_bytes: payload,
                received: vec![row],
                binding: Binding {
                    proof_commit: Some(*proof_commit(cose).as_bytes()),
                    auth_context_ref: None,
                },
                auth_context: None,
            })
        }
        Arrival::Unsigned {
            record,
            auth_context,
        } => {
            let row = received(
                ReceivedKind::AccessAuthContext,
                ReceivedRole::AuthContext,
                auth_context.bytes,
            )?;
            let id = record_id(record);
            let context = auth_context::verify(&auth_context, id.0.as_bytes())?;
            let value = auth_context_value(&context.digest, context.step_up, context.aal);
            Ok(Arrived {
                record_bytes: record.to_vec(),
                received: vec![row],
                binding: Binding {
                    proof_commit: None,
                    auth_context_ref: Some(context.digest),
                },
                auth_context: Some(value),
            })
        }
    }
}

/// What the kernel decided about a record that arrived.
struct Checked {
    quarantine: Option<String>,
    skeleton: Option<Skeleton>,
    touches: Vec<ItemTouch>,
    effective_at: Option<u64>,
    primary: Option<&'static EventType>,
}

/// Decodes and validates the record of `a` against `ledger` (P-11, P-19, P-21, P-87, C-34).
fn check(
    ledger: &LedgerId,
    s: &Submission<'_>,
    actors: &ActorTypes,
    a: &Arrived,
) -> Result<Checked, Reason> {
    if a.record_bytes.len() > MAX_RECEIVED {
        return Err(Reason::LimitExceeded(Limit::Request));
    }
    let record = match decode_record(&a.record_bytes)? {
        Decoded::UnknownProtocol(_) if a.auth_context.is_some() => {
            return Err(Reason::ProtocolVersionUnknown);
        }
        Decoded::UnknownProtocol(_) => {
            return Ok(Checked {
                quarantine: Some(Reason::ProtocolVersionUnknown.to_string()),
                skeleton: None,
                touches: Vec::new(),
                effective_at: None,
                primary: None,
            });
        }
        Decoded::Record(record) => record,
    };
    let core = record.core();
    if a.auth_context.is_some() {
        let unsigned = UnsignedRecord {
            record: record_id(&a.record_bytes),
            author: core.author.clone(),
            actor_type: actors.author.actor_type,
            auth_context: true,
        };
        if let VerifyOutcome::Rejected(reason) = verify_unsigned(unsigned, None) {
            return Err(reason);
        }
    }
    if core.ledger.0.as_bytes() != ledger.as_bytes() {
        return Err(Reason::EnvelopeMismatch(EnvelopeField::Ledger));
    }
    if !s.declared.names(core) {
        return Err(Reason::EnvelopeMismatch(EnvelopeField::ActorType));
    }
    let ctx = ValidationContext {
        origin: s.origin,
        actor_types: actors,
        understood_extensions: s.understood_extensions,
        limits: s.limits,
        recorded_at: None,
    };
    let quarantine = match validate(&record, &ctx) {
        Outcome::Accepted => None,
        Outcome::Quarantined(q) => Some(q.to_string()),
        Outcome::Rejected(reason) => return Err(reason),
    };
    let touches = items::touched(&record)
        .iter()
        .map(touch)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Checked {
        skeleton: Some(skeleton(&record, actors, quarantine.clone(), a.binding)),
        quarantine,
        touches,
        effective_at: record.effective_at().map(|t| t.0),
        primary: RecordFacts::of(&record).primary(),
    })
}

/// The event type of each touched item, in touch order (T-98 item 4): the item the record is
/// about, the first touched item of its primary type's kind, takes the primary type, and every
/// other item takes `<item>.changed`, whose `data.cause` is the primary type. A record whose
/// wire name gives no catalogued type has no cause for a `changed` event, so every item takes
/// `fallback`.
pub(crate) fn pointer_types(
    primary: Option<&EventType>,
    fallback: &str,
    touches: &[ItemTouch],
) -> Vec<String> {
    let Some(primary) = primary else {
        return touches.iter().map(|_| fallback.to_owned()).collect();
    };
    let kind = match primary.item {
        Item::Work => Some("work"),
        Item::Commitment => Some("commitment"),
        Item::Condition | Item::Gate => Some("condition"),
        Item::Record | Item::Ledger => None,
    };
    let subject = touches.iter().position(|t| Some(t.item.kind()) == kind);
    touches
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if Some(i) == subject {
                primary.name.to_owned()
            } else {
                format!("{}.changed", t.item.kind())
            }
        })
        .collect()
}

/// Admits `s` into `ledger` with the kernel (T-89, T-90, P-11, P-19, P-21, P-75, P-87): the
/// `COSE_Sign1` of a signed record is verified through `verifier` and kept as received, its
/// payload is the record; an unsigned record must be a human's with an Access `auth_context`
/// artifact bound to it, verified before the kernel and kept as received (P-116); the record
/// must declare `ledger`; a valid record is admitted or quarantined, a record of a protocol
/// version without a rule set is quarantined when signed and refused when unsigned, since its
/// author cannot be read (P-108); the items come from [`items::touched`] and one pointer is
/// emitted per item.
///
/// # Errors
/// [`AdmitError::Rejected`] with the kernel's [`Reason`]: a signature, CBOR, schema or rule
/// reason, `envelope_mismatch:ledger` for another declared ledger, `envelope_mismatch:record`
/// when the signature covers other bytes, or `limit_exceeded:request` for received bytes above
/// 262 144 bytes; [`AdmitError::AuthContext`] when the artifact does not verify or is not bound
/// to the record.
pub fn admit<V: SignatureVerifier + ?Sized>(
    verifier: &V,
    ledger: &LedgerId,
    s: Submission<'_>,
) -> Result<PendingRecord, AdmitError> {
    let a = arrive(verifier, s.arrival)?;
    let actors = s.declared.derive(s.bindings);
    let c = check(ledger, &s, &actors, &a)?;
    let record_hex = hex(&sha256(&a.record_bytes));
    let types = pointer_types(c.primary, s.event_type, &c.touches);
    let outbox = c
        .touches
        .iter()
        .zip(types)
        .map(|(t, event_type)| EventPointer {
            event_id: format!("{record_hex}.{}.{}", t.item.kind(), hex(t.item.id())),
            event_type,
            traceparent: s.traceparent.to_owned(),
            item: t.item,
        })
        .collect();
    Ok(PendingRecord {
        actor_type: actor_types(&actors),
        proof_commit: a.binding.proof_commit,
        auth_context: a.auth_context,
        ingest: ingest(c.quarantine.as_deref()),
        record_bytes: a.record_bytes,
        received: a.received,
        skeleton: c.skeleton,
        body: Vec::new(),
        items: c.touches,
        outbox,
        idempotency: s.idempotency,
        inbound: s.inbound,
        effective_at: c.effective_at,
    })
}

/// The Access proof given for a record is not the one its `authority` refers to (P-13); nothing
/// was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityProofMismatch {
    /// The record carries no `authority`, or its stored bytes do not decode as a record.
    #[error("the record names no authority")]
    Unnamed,
    /// The record's `authority` names another kind of proof.
    #[error("the authority names another kind of proof")]
    Kind,
    /// The record's `authority` digest is not the SHA-256 of the proof bytes.
    #[error("the authority digest is not the proof's")]
    Digest,
    /// The proof is empty or larger than [`MAX_RECEIVED`].
    #[error("the proof is empty or too large")]
    Size,
}

const fn proof_kind(proof: AuthorityProofKind) -> ReceivedKind {
    match proof {
        AuthorityProofKind::DecisionReceipt => ReceivedKind::AccessDecisionReceipt,
        AuthorityProofKind::PortableAuthorityProof => ReceivedKind::AccessPortableAuthorityProof,
        AuthorityProofKind::ApprovalActStatement => ReceivedKind::AccessApprovalActStatement,
        AuthorityProofKind::EligibilityCheck => ReceivedKind::AccessEligibilityCheck,
    }
}

impl PendingRecord {
    /// Keeps `proof`, the Access proof of `kind` the record's `authority` refers to, exactly as
    /// received beside the record (P-13, P-5 item 4, T-90): the record must name an
    /// `authority` of that kind whose digest is the SHA-256 of `proof`, so the reference is
    /// never invented and the proof is checked again from the log alone.
    ///
    /// # Errors
    /// [`AuthorityProofMismatch`]; the record is unchanged.
    pub fn keep_authority_proof(
        &mut self,
        kind: AuthorityProofKind,
        proof: &[u8],
    ) -> Result<(), AuthorityProofMismatch> {
        let Ok(Decoded::Record(record)) = decode_record(&self.record_bytes) else {
            return Err(AuthorityProofMismatch::Unnamed);
        };
        let authority = record
            .core()
            .authority
            .ok_or(AuthorityProofMismatch::Unnamed)?;
        if authority.proof != kind {
            return Err(AuthorityProofMismatch::Kind);
        }
        if *authority.digest.as_bytes() != sha256(proof) {
            return Err(AuthorityProofMismatch::Digest);
        }
        let row = received(proof_kind(kind), ReceivedRole::AuthorityProof, proof)
            .map_err(|_| AuthorityProofMismatch::Size)?;
        self.received.push(row);
        Ok(())
    }
}

impl GroupCommit {
    /// Admits `s` with the kernel in the caller's task, outside the writer's critical section,
    /// then queues the record and waits until its batch is durable (OP-3, OP-5 item 4).
    ///
    /// # Errors
    /// [`SubmitError::Rejected`] with the kernel's reason when the record is not admitted,
    /// [`SubmitError::AuthContext`] when its `auth_context` does not verify (P-116); otherwise
    /// as [`GroupCommit::submit`].
    pub async fn admit<V: SignatureVerifier + ?Sized>(
        &self,
        verifier: &V,
        s: Submission<'_>,
    ) -> Result<Committed, SubmitError> {
        let record = admit(verifier, self.ledger(), s).map_err(SubmitError::from)?;
        self.submit(record).await
    }

    /// Admits `s` as [`GroupCommit::admit`] does and seals `body`, the openings of the parts its
    /// record commits to, through `writer` before queueing it, so the record, its skeleton and
    /// its encrypted parts with their keys commit in one transaction (OP-45, P-68). The writer
    /// scans the openings for secrets first and a detection refuses the record, which never
    /// enters the log (SEC-35 item 2, P-95 item 2). The parts' data subject is the record's
    /// author (OP-45 item 7); `now_ms` is the time the DEK cache and the object store use.
    ///
    /// # Errors
    /// [`SubmitError::Body`] when an opening names no commitment of the record, does not give
    /// its commitment, carries a secret ([`BodyError::SecretDetected`], naming only the part and
    /// the rule), cannot be scanned or cannot be sealed, and when a record without a skeleton
    /// comes with a body; otherwise as [`GroupCommit::admit`].
    pub async fn admit_with_body<V: SignatureVerifier + ?Sized, O: ObjectStore>(
        &self,
        verifier: &V,
        s: Submission<'_>,
        body: &[BodyOpening],
        writer: &BodyWriter<O>,
        now_ms: u64,
    ) -> Result<Committed, SubmitError> {
        let mut record = admit(verifier, self.ledger(), s).map_err(SubmitError::from)?;
        if !body.is_empty() {
            let skeleton = record
                .skeleton
                .as_ref()
                .ok_or(SubmitError::Body(BodyError::NoSkeleton))?;
            record.body = writer
                .seal(
                    self.ledger(),
                    &skeleton.header.author,
                    &skeleton.body,
                    body,
                    now_ms,
                )
                .await
                .map_err(SubmitError::Body)?;
        }
        self.submit(record).await
    }
}

#[cfg(test)]
mod tests;
