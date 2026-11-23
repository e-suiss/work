//! The rules of a consequential write that are not the kernel's (P-13, P-21, P-105, P-12, E-13, E-45, SEC-36 item 3, T-101 item 7): a commitment Declaration is admitted only under an Access Exercise allowed for the `work:commit` intent that names its ledger and is valid now, whose verified receipt is exactly the proof its `authority` digest names, whose capacity is the record's own and whose agency chain covers every `on_behalf_of` principal; a signed record is checked only against the key Access binds at admission, which must still be held by its Instance, and its author's actor type is that key's Party's `actor_kind`; an unsigned record is a human author's own, so its author must be the caller Access named. The openings a write carries open exactly the body parts its record commits to, each once, within its bounds and to its commitment (P-68, OP-45). Nothing here takes an authority, a capacity or an actor type from the caller.

use std::collections::{BTreeMap, BTreeSet};

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::sha256;
pub use work_access_client::domain::exercise::ExerciseId;
use work_access_client::domain::exercise::{Capacity as Held, Intent, VerifiedExercise};
use work_access_client::domain::keys::{ActorKind, InstanceKey, KernelId, KeyState};
use work_access_client::domain::{b64url, from_b64url};
use work_kernel::catalog::DeclarationSubtype;
use work_kernel::cose::{Algorithm, KeySet, parse_container};
use work_kernel::id::{LedgerId, PartyRef, RecordId};
use work_kernel::record::{AuthorityProofKind, Capacity, Record, RecordCore};
use work_kernel::validate::ActorType;
pub use work_ledger::BodyOpening;
use work_ledger::{BodyError, MAX_MEDIA_TYPE, MAX_PART};
use work_proto::id::ExternalId as _;

pub use crate::domain::control::Form;
pub use crate::domain::kinds::Kind;

/// The Access action namespace of Work (E-45 item 1).
pub const ACTION_NAMESPACE: &str = "work";

/// The action of a commitment operation (E-45 item 2).
pub const COMMIT: &str = "commit";

/// The major version of every Work action (E-45 item 1).
pub const ACTION_MAJOR: u64 = 1;

/// The resource type of a ledger (E-45 item 5).
pub const LEDGER_RESOURCE: &str = "work.ledger";

/// The commitment operations `work:commit` covers, by wire name (E-45 item 2).
pub const COMMIT_OPERATIONS: [&str; 19] = [
    "request",
    "promise",
    "promise_conditional",
    "decline",
    "counter",
    "accept_counter",
    "state",
    "cancel",
    "release",
    "delegate",
    "dispute",
    "defer",
    "resume",
    "notice",
    "revoke_request",
    "revoke_promise",
    "revoke_statement",
    "revoke_acceptance",
    "refuse",
];

/// The actor types a request declares, written only as `declared_unverified` (P-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredTypes {
    /// The author's.
    pub author: ActorType,
    /// One per `on_behalf_of` ring, in chain order.
    pub on_behalf_of: Vec<ActorType>,
    /// One per evidence presenter, in `evidence` order.
    pub evidence: Vec<ActorType>,
}

/// The Access `auth_context` artifact of an unsigned human record, as the client received it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContextGiven {
    /// The tagged `COSE_Sign1`.
    pub artifact: Vec<u8>,
    /// Access's `digest` of it.
    pub digest: [u8; 32],
}

/// The Access Exercise a record's `authority` refers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityGiven {
    /// The Exercise.
    pub exercise: ExerciseId,
    /// The canonical intent envelope the client was approved for.
    pub intent: Vec<u8>,
}

/// One commitment Declaration to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclarationRequest {
    /// The tagged `COSE_Sign1` of a signed record, or the `SignedRecord` bytes of an unsigned
    /// one.
    pub record: Vec<u8>,
    /// The artifact of an unsigned record; its presence makes the record unsigned.
    pub auth_context: Option<AuthContextGiven>,
    /// The Exercise its `authority` refers to.
    pub authority: Option<AuthorityGiven>,
    /// The declared actor types.
    pub declared: DeclaredTypes,
    /// The SHA-256 of the request body, the idempotency digest (OP-8).
    pub digest: [u8; 32],
    /// The `Idempotency-Key`.
    pub idempotency_key: String,
    /// The item version of `If-Match`.
    pub if_match: u64,
    /// The request's W3C `traceparent`.
    pub traceparent: String,
    /// The record kind and commitment a typed endpoint names; `None` for the Declaration
    /// endpoint, which takes any record a caller writes (C-6).
    pub expected: Option<Expected>,
    /// Whether the record is written on the executor contract, which only the executor
    /// assigned to the work writes (RC-41, RC-42, T-105).
    pub executor: bool,
    /// The openings of the body parts the record commits to, in request order (P-68).
    pub body: Vec<BodyOpening>,
}

/// What a typed endpoint names: the record must be of this kind, and a continuation must
/// continue this commitment (C-6, CM-17, RC-17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    /// The record kind.
    pub kind: Kind,
    /// The commitment, by its `request`; `None` for a `request` and a record that continues
    /// no commitment. A control record names it by citing its `request` in `basis`.
    pub commitment: Option<RecordId>,
    /// The shape a control endpoint names beyond the kind: a consultation or an operator
    /// correction (RC-31, RC-40).
    pub form: Option<Form>,
}

/// A written record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// The record.
    pub record: RecordId,
    /// Its position.
    pub pos: u64,
    /// Whether this answers an earlier request with the same key (OP-8).
    pub replayed: bool,
}

/// Why a write wrote nothing.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WriteRefusal {
    /// The request does not say what it must: `400 invalid_request`.
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    /// An `Idempotency-Key` refusal by its problem code.
    #[error("{0}")]
    Idempotency(&'static str),
    /// The item is no longer at the `If-Match` version: `412 precondition_failed`.
    #[error("precondition failed")]
    PreconditionFailed,
    /// No such ledger: `404 not_found`.
    #[error("not found")]
    NotFound,
    /// The kernel's reason: `422 record_rejected`.
    #[error("record rejected: {0}")]
    Rejected(String),
    /// The `auth_context` artifact does not verify: `422 auth_context_invalid`.
    #[error("auth_context invalid: {0}")]
    AuthContext(String),
    /// Access's evidence does not authorise this record: `403 access_denied`.
    #[error("access denied: {0}")]
    Denied(&'static str),
    /// Access cannot be asked, so the authority cannot be verified, fail-closed (T-28):
    /// `503 authority_unverifiable`.
    #[error("authority unverifiable: {0}")]
    Unverifiable(&'static str),
    /// The ledger's queue is full: `503 busy` after `retry_after_s`.
    #[error("busy")]
    Busy {
        /// Seconds to wait.
        retry_after_s: u32,
    },
    /// The commit's outcome is unknown: `503 not_recorded`, asked again with the same key.
    #[error("not recorded")]
    NotRecorded,
    /// A body part carries a secret (SEC-35 item 2, P-95): `422 secret_detected`, naming only
    /// the part and the scanner's rule, never the matched bytes.
    #[error("secret detected (rule {rule}, part {part})")]
    SecretDetected {
        /// The part that matched.
        part: String,
        /// The rule that matched.
        rule: String,
    },
    /// A body part is above its bound (P-33, OP-45): `413 request_too_large`.
    #[error("request too large")]
    TooLarge,
}

/// The bytes of canonical unpadded base64url text, as a write request spells every byte string.
#[must_use]
pub fn base64url(text: &str) -> Option<Vec<u8>> {
    from_b64url(text).ok()
}

/// The kernel actor type of an Access actor kind (P-12, INV-18).
#[must_use]
pub const fn actor_type(kind: ActorKind) -> ActorType {
    match kind {
        ActorKind::Human => ActorType::Human,
        ActorKind::Agent => ActorType::Agent,
        ActorKind::System => ActorType::System,
        ActorKind::Machine => ActorType::Machine,
        ActorKind::Organization => ActorType::Organization,
    }
}

/// The Party reference Work writes for an Access `PartyID`: its unpadded base64url.
#[must_use]
pub fn party_ref(party: &KernelId) -> Option<PartyRef> {
    PartyRef::new(&b64url(&party.0))
}

/// What Access's binding of a signing key gives the signature check: the Party the key is
/// bound to with its actor type, and the key, only while its Instance still holds it.
#[derive(Clone, Debug, Default)]
pub struct Signer {
    /// The key's Party and its actor type.
    pub party: Option<(PartyRef, ActorType)>,
    /// The key, or no key for a key that is unknown, ended or compromised.
    pub keys: KeySet,
}

/// The [`Signer`] of `key`, Access's entry for a signed record's `kid` at admission: an ended
/// key, or one established inside a compromise window, signs nothing, so a record under it is
/// `signature:kid_unknown`, and so is one whose `author` is not the key's Party (P-105, P-113
/// item 6, SEC-36 item 3).
#[must_use]
pub fn signer(key: Option<&InstanceKey>) -> Signer {
    let refused = Signer {
        party: None,
        keys: KeySet {
            keys: BTreeMap::new(),
            allowed: BTreeSet::from([Algorithm::Ed25519, Algorithm::Esp256]),
        },
    };
    let Some(key) = key.filter(|k| k.state == KeyState::Active) else {
        return refused;
    };
    let Some(party) = party_ref(&key.party) else {
        return refused;
    };
    let mut keys = KeySet {
        keys: BTreeMap::new(),
        allowed: BTreeSet::from([key.alg]),
    };
    if keys.insert(key.kid.0, key.key.clone()).is_err() {
        return refused;
    }
    Signer {
        party: Some((party, actor_type(key.actor_kind))),
        keys,
    }
}

/// The `kid` of a tagged `COSE_Sign1`'s protected header.
#[must_use]
pub fn header_kid(cose: &[u8]) -> Option<[u8; 32]> {
    let container = parse_container(cose).ok()?;
    let Value::Map(entries) = dcbor::decode(&container.protected, Limits::CEILING).ok()? else {
        return None;
    };
    entries.iter().find_map(|(k, v)| match (k, v) {
        (Value::Unsigned(4), Value::Bytes(b)) => <[u8; 32]>::try_from(b.as_slice()).ok(),
        _ => None,
    })
}

/// Whether `record` is a core Declaration whose operation `work:commit` covers (E-45 item 3).
#[must_use]
pub fn commit_operation(record: &Record) -> bool {
    match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str())
            .is_some_and(|s| COMMIT_OPERATIONS.contains(&s.wire_name())),
        Record::Act(_) | Record::Claim(_) => false,
    }
}

/// Whether `intent` is the `work:commit` intent of `ledger` valid at `now_ms` (E-45, T-101 note
/// item 7).
///
/// # Errors
/// The stable reason: `intent_action` for another action, `intent_expired` outside its
/// validity, `intent_resource` when it does not name the ledger.
pub fn check_intent(intent: &Intent, ledger: &LedgerId, now_ms: u64) -> Result<(), &'static str> {
    check_action(intent, ledger, now_ms, COMMIT)
}

/// The actions of the records a caller writes, which Work's PEP commits an intent for (E-45
/// item 2, RC-17, RC-31, RC-36, RC-42, RC-48, E-23).
pub const WRITE_ACTIONS: [&str; 14] = [
    COMMIT,
    "close",
    "assign",
    "administrative_close",
    "autonomy_policy_set",
    "claim",
    "condition",
    "stop_request",
    "stop_respond",
    "control",
    "agent_ceiling_decide",
    "org_rule_set",
    "write",
    "executor_dispatch",
];

/// Whether `intent` is the intent of one of [`WRITE_ACTIONS`] on `ledger` valid at `now_ms`
/// (E-45 items 2, 3, T-101 item 2).
///
/// # Errors
/// As [`check_intent`].
pub fn check_write_intent(
    intent: &Intent,
    ledger: &LedgerId,
    now_ms: u64,
) -> Result<(), &'static str> {
    let action = WRITE_ACTIONS
        .into_iter()
        .find(|a| intent.action == *a)
        .ok_or("intent_action")?;
    check_action(intent, ledger, now_ms, action)
}

/// Whether `intent` is the `work:<action>` intent of `ledger` valid at `now_ms` (E-45 items 2,
/// 3).
///
/// # Errors
/// As [`check_intent`].
pub fn check_action(
    intent: &Intent,
    ledger: &LedgerId,
    now_ms: u64,
    action: &str,
) -> Result<(), &'static str> {
    if intent.namespace != ACTION_NAMESPACE
        || intent.action != action
        || intent.major != ACTION_MAJOR
    {
        return Err("intent_action");
    }
    if !intent.valid_at(now_ms) {
        return Err("intent_expired");
    }
    if !intent.names(LEDGER_RESOURCE, &ledger.to_external()) {
        return Err("intent_resource");
    }
    Ok(())
}

/// Whether the verified Exercise is the proof `core`'s `authority` names and carries its single
/// capacity (P-13 items 1 and 4, E-13, SEC-4): the `authority` is a decision receipt whose digest
/// is the SHA-256 of the receipt bytes as Access sent them; `own` matches `own` and `FOR(P)`
/// matches `FOR(P)`; every `on_behalf_of` principal is the capacity's Party or a principal of
/// the receipt's agency chain, whose last agent is the author.
///
/// # Errors
/// The stable reason: `authority_kind`, `authority_digest`, `capacity_mismatch`,
/// `on_behalf_of_uncovered` or `agency_agent`.
pub fn check_authority(core: &RecordCore, exercise: &VerifiedExercise) -> Result<(), &'static str> {
    let authority = core.authority.ok_or("authority_kind")?;
    if authority.proof != AuthorityProofKind::DecisionReceipt {
        return Err("authority_kind");
    }
    if *authority.digest.as_bytes() != sha256(&exercise.receipt) {
        return Err("authority_digest");
    }
    let matches = match (&core.capacity, exercise.capacity) {
        (Some(Capacity::Own), Held::Own) => true,
        (Some(Capacity::For(p)), Held::For(held)) => party_ref(&held).as_ref() == Some(p),
        _ => false,
    };
    if !matches {
        return Err("capacity_mismatch");
    }
    let mut covered: Vec<PartyRef> = Vec::new();
    if let Held::For(held) = exercise.capacity {
        covered.extend(party_ref(&held));
    }
    covered.extend(
        exercise
            .agency
            .iter()
            .filter_map(|l| party_ref(&l.principal)),
    );
    let rings = core.on_behalf_of.as_deref().unwrap_or_default();
    if !rings.iter().all(|r| covered.contains(r)) {
        return Err("on_behalf_of_uncovered");
    }
    if let Some(last) = exercise.agency.last()
        && party_ref(&last.agent).as_ref() != Some(&core.author)
    {
        return Err("agency_agent");
    }
    Ok(())
}

/// Whether `openings` open exactly the body parts `core` commits to (P-68, OP-45): every
/// opening names a part the record commits to, once, within the bounds of its content and media
/// type, and gives the part's commitment; and every committed part is opened, since a part the
/// write path does not seal could never be read.
///
/// # Errors
/// [`WriteRefusal::Invalid`] with `body_part` for an opening of a part the record does not
/// commit to or one opened twice, `body_commitment` for an opening that does not give its
/// commitment, `body_unopened` for a committed part without an opening;
/// [`WriteRefusal::TooLarge`] for a part above its bound.
pub fn check_openings(core: &RecordCore, openings: &[BodyOpening]) -> Result<(), WriteRefusal> {
    let committed = core.body.as_deref().unwrap_or_default();
    for (i, o) in openings.iter().enumerate() {
        if openings.iter().take(i).any(|p| p.part == o.part) {
            return Err(WriteRefusal::Invalid("body_part"));
        }
        let commit = committed
            .iter()
            .find(|c| c.part.as_str() == o.part)
            .ok_or(WriteRefusal::Invalid("body_part"))?;
        if o.content.len() > MAX_PART || o.media_type.len() > MAX_MEDIA_TYPE {
            return Err(WriteRefusal::TooLarge);
        }
        if o.commitment().map_err(|e| body_refusal(&e))? != *commit.commit.as_bytes() {
            return Err(WriteRefusal::Invalid("body_commitment"));
        }
    }
    if committed
        .iter()
        .any(|c| !openings.iter().any(|o| o.part == c.part.as_str()))
    {
        return Err(WriteRefusal::Invalid("body_unopened"));
    }
    Ok(())
}

/// The refusal of a body the store did not seal (SEC-35 item 2, P-95, OP-45): a secret names
/// only its part and rule; a part outside its commitment or bound is the caller's to correct;
/// a scan without a verdict, a key or a store that failed is `not_recorded`, fail-closed, and
/// the same request may be sent again.
#[must_use]
pub fn body_refusal(error: &BodyError) -> WriteRefusal {
    match error {
        BodyError::SecretDetected { part, rule } => WriteRefusal::SecretDetected {
            part: part.clone(),
            rule: rule.clone(),
        },
        BodyError::UnknownPart(_) | BodyError::DuplicatePart(_) | BodyError::NoSkeleton => {
            WriteRefusal::Invalid("body_part")
        }
        BodyError::Commitment(_) => WriteRefusal::Invalid("body_commitment"),
        BodyError::TooLarge(_) => WriteRefusal::TooLarge,
        _ => WriteRefusal::NotRecorded,
    }
}

#[cfg(test)]
mod tests;
