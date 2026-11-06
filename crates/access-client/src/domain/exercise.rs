//! The Exercise a consequential record refers to (T-101 item 7 and its note, P-13, E-13; Access OP-149 m.9, m.11, CR-58 m.1, `kernel.cddl` `receipt`): the `ExerciseID` of a nonce in a domain, the intent envelope the client was approved for with the digest Work recomputes itself, and the `exercise` and `exercise_agency` answers. An answer is used only when it names the asked Exercise and domain, is `allowed` for exactly that intent, and carries its decision receipt, whose `COSE_Sign1` verifies with usage `receipt` under the domain key its `key_excerpt` binds to Domain Metadata and whose payload names the same domain, Exercise and intent, Work's own PEP as audience and a time not after Work's; the capacity and the agency chain are read from that verified receipt only. An answer without a receipt is no authority proof.

use access_kernel::ais::SKEW_MS;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Capacity as AccessCapacity;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::meta;
use access_kernel::receipt::{self, Receipt};
use serde::Deserialize;
use serde_json::Value;
use suiss_crypto::cose;
use suiss_crypto::sig::PureBackend;

use crate::domain::keys::{DomainId, KernelId};
use crate::domain::metadata::{DomainMetadata, KeyUsage, operational_key, unverified_payload};
use crate::domain::{AccessError, b64url, fixed_b64url, from_b64url};

/// An `ExerciseID`: 32 bytes, 43 characters of unpadded base64url on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExerciseId(pub [u8; 32]);

impl ExerciseId {
    /// Reads the wire text.
    ///
    /// # Errors
    /// [`AccessError::Identifier`].
    pub fn parse(text: &str) -> Result<Self, AccessError> {
        fixed_b64url(text).map(Self)
    }

    /// The wire text.
    #[must_use]
    pub fn text(&self) -> String {
        b64url(&self.0)
    }

    /// The `ExerciseID` of `nonce` in `domain`:
    /// `SHA-256("access/exercise/v1" ‖ 0x00 ‖ dCBOR([DomainID, nonce]))` (Access OP-141 m.6).
    ///
    /// # Errors
    /// [`AccessError::Identifier`] for a nonce beyond the structural limits.
    pub fn of(domain: &DomainId, nonce: &[u8]) -> Result<Self, AccessError> {
        meta::exercise_id(&Digest(domain.0), nonce)
            .map(|d| Self(d.0))
            .map_err(|_| AccessError::Identifier("nonce"))
    }
}

/// One resource an intent names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    /// The owning namespace, such as `work.ledger`.
    pub namespace: String,
    /// The path segments.
    pub path: Vec<String>,
}

/// The intent envelope a client was approved for, read from its canonical bytes; its digest is
/// recomputed by Work, never taken from the client or from Access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// The intent digest (`access/intent/v1`).
    pub digest: [u8; 32],
    /// The action's namespace.
    pub namespace: String,
    /// The action's name.
    pub action: String,
    /// The action's major version.
    pub major: u64,
    /// The resources, primary first.
    pub resources: Vec<Resource>,
    /// The first instant of its validity, Unix milliseconds.
    pub valid_from_ms: u64,
    /// The last instant of its validity, Unix milliseconds.
    pub valid_until_ms: u64,
}

impl Intent {
    /// Reads the deterministic CBOR `IntentEnvelope` and recomputes its digest.
    ///
    /// # Errors
    /// [`AccessError::Answer`] (`intent`) for bytes that are not a canonical envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccessError> {
        let bad = || AccessError::Answer("intent");
        let envelope = IntentEnvelope::from_bytes(bytes).map_err(|_| bad())?;
        if envelope.to_bytes().map_err(|_| bad())? != bytes {
            return Err(bad());
        }
        let digest = intent_digest(&envelope).map_err(|_| bad())?;
        Ok(Self {
            digest: digest.0,
            namespace: envelope.action.namespace.clone(),
            action: envelope.action.name.clone(),
            major: envelope.action.major,
            resources: envelope
                .resources
                .iter()
                .map(|r| Resource {
                    namespace: r.namespace.clone(),
                    path: r.path.clone(),
                })
                .collect(),
            valid_from_ms: envelope.validity.from,
            valid_until_ms: envelope.validity.until,
        })
    }

    /// Whether the intent is valid at `now_ms`.
    #[must_use]
    pub const fn valid_at(&self, now_ms: u64) -> bool {
        self.valid_from_ms <= now_ms && now_ms <= self.valid_until_ms
    }

    /// Whether the intent names the resource `namespace` with the single path segment `id`.
    #[must_use]
    pub fn names(&self, namespace: &str, id: &str) -> bool {
        self.resources.iter().any(|r| {
            r.namespace == namespace && r.path.len() == 1 && r.path.first().is_some_and(|p| p == id)
        })
    }
}

/// The capacity an Exercise's actor declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capacity {
    /// For itself.
    Own,
    /// For the Party it names.
    For(KernelId),
}

/// One link of the chain an Exercise's actor acted on behalf of, from the principal to the
/// agent (Access OP-149 m.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgencyLink {
    /// The Mandate the agent acted under.
    pub mandate: KernelId,
    /// The Party acted for.
    pub principal: KernelId,
    /// The Party that acted.
    pub agent: KernelId,
}

/// An Exercise whose decision receipt verified: what a record's `authority` may refer to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExercise {
    /// The Exercise.
    pub exercise: ExerciseId,
    /// Its domain.
    pub domain: DomainId,
    /// The ledger position of its decision record.
    pub position: u64,
    /// The intent digest it was allowed for.
    pub intent: [u8; 32],
    /// The actor's Instance, absent for an anonymous actor.
    pub instance: Option<KernelId>,
    /// The capacity of the verified receipt.
    pub capacity: Capacity,
    /// The agency chain of the verified receipt, principal first.
    pub agency: Vec<AgencyLink>,
    /// The receipt's trusted time, Unix milliseconds.
    pub iat: u64,
    /// The receipt `COSE_Sign1` exactly as Access sent it; a record's `authority` digest is
    /// computed over these bytes and they are kept as received.
    pub receipt: Vec<u8>,
    /// The binding-signed excerpt of the receipt key, kept for offline verification.
    pub excerpt: Vec<u8>,
}

/// What the verifier expects of an answer.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    /// The Exercise asked for.
    pub exercise: &'a ExerciseId,
    /// The domain asked in.
    pub domain: &'a DomainId,
    /// The intent the client was approved for.
    pub intent: &'a Intent,
    /// The PEP the receipt is addressed to, the `x5t#S256` of Work's PEP certificate (T-101
    /// item 3, Access OP-149 m.11).
    pub audience: &'a str,
    /// Work's time, Unix milliseconds.
    pub now_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptWire {
    payload: String,
    cose_sign1: Option<String>,
    key_excerpt: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExerciseWire {
    exercise: String,
    domain: String,
    status: String,
    position: String,
    intent: String,
    instance: Option<String>,
    receipt: Option<ReceiptWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkWire {
    mandate: String,
    principal: String,
    agent: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgencyWire {
    exercise: String,
    domain: String,
    capacity: Value,
    agency: Vec<LinkWire>,
    receipt: ReceiptWire,
}

fn answer(code: &'static str) -> AccessError {
    AccessError::Answer(code)
}

fn capacity_of(c: AccessCapacity) -> Capacity {
    match c {
        AccessCapacity::Own => Capacity::Own,
        AccessCapacity::For(id) => Capacity::For(KernelId(id.0)),
    }
}

fn wire_capacity(v: &Value) -> Result<Capacity, AccessError> {
    match v {
        Value::String(s) if s == "own" => Ok(Capacity::Own),
        Value::Object(m) if m.len() == 1 => m
            .get("for")
            .and_then(Value::as_str)
            .map(|p| KernelId::parse(p).map(Capacity::For))
            .ok_or_else(|| answer("capacity"))?
            .map_err(|_| answer("capacity")),
        _ => Err(answer("capacity")),
    }
}

fn kernel_id(text: &str, code: &'static str) -> Result<KernelId, AccessError> {
    KernelId::parse(text).map_err(|_| answer(code))
}

fn named(exercise: &str, domain: &str, expected: &Expected<'_>) -> Result<(), AccessError> {
    named_as(exercise, domain, expected.exercise, expected.domain)
}

fn named_as(
    exercise: &str,
    domain: &str,
    asked: &ExerciseId,
    asked_domain: &DomainId,
) -> Result<(), AccessError> {
    if ExerciseId::parse(exercise).ok() != Some(*asked) {
        return Err(answer("exercise-mismatch"));
    }
    if DomainId::parse(domain).ok() != Some(*asked_domain) {
        return Err(answer("exercise-domain"));
    }
    Ok(())
}

/// Verifies the receipt of an answer against `metadata` and what `expected` names.
fn verify_receipt(
    metadata: &DomainMetadata,
    wire: &ReceiptWire,
    expected: &Expected<'_>,
) -> Result<(Receipt, Vec<u8>, Vec<u8>), AccessError> {
    let (r, sign1, excerpt) = signed_receipt(
        metadata,
        wire,
        expected.exercise,
        expected.domain,
        expected.now_ms,
    )?;
    if r.intent.0 != expected.intent.digest {
        return Err(answer("receipt-intent"));
    }
    if r.audience != expected.audience {
        return Err(answer("receipt-audience"));
    }
    Ok((r, sign1, excerpt))
}

/// The receipt of an answer, signed under the domain key its excerpt binds to `metadata`, for
/// the asked Exercise and domain and not after `now_ms`.
fn signed_receipt(
    metadata: &DomainMetadata,
    wire: &ReceiptWire,
    exercise: &ExerciseId,
    domain: &DomainId,
    now_ms: u64,
) -> Result<(Receipt, Vec<u8>, Vec<u8>), AccessError> {
    let (Some(sign1), Some(excerpt)) = (&wire.cose_sign1, &wire.key_excerpt) else {
        return Err(answer("receipt-missing"));
    };
    let malformed = |_| answer("receipt-malformed");
    let sign1 = from_b64url(sign1).map_err(malformed)?;
    let excerpt = from_b64url(excerpt).map_err(malformed)?;
    let payload = from_b64url(&wire.payload).map_err(malformed)?;
    let unverified = unverified_payload(&sign1).map_err(|_| answer("receipt-malformed"))?;
    let claimed = Receipt::from_bytes(&unverified).map_err(|_| answer("receipt-malformed"))?;
    let key = operational_key(
        metadata,
        &domain.0,
        &excerpt,
        KeyUsage::Receipt,
        claimed.iat,
    )
    .map_err(|_| answer("receipt-key"))?;
    let verified = cose::verify_sign1(&PureBackend, &sign1, &key.key_set(), receipt::CONTENT_TYPE)
        .map_err(|_| answer("receipt-signature"))?;
    if verified.payload != payload {
        return Err(answer("receipt-payload"));
    }
    let r = Receipt::from_bytes(&verified.payload).map_err(|_| answer("receipt-malformed"))?;
    if r.domain.0 != domain.0 || metadata.domain != domain.0 {
        return Err(answer("receipt-domain"));
    }
    if r.exercise.0 != exercise.0 {
        return Err(answer("receipt-exercise"));
    }
    if r.iat > now_ms.saturating_add(SKEW_MS) {
        return Err(answer("receipt-future"));
    }
    Ok((r, sign1, excerpt))
}

/// A contribution Exercise an approver made on Access's Approval Surface, as the Exercise query
/// answers it: what the approval return hands back as a proof of the next commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedContribution {
    /// The contribution Exercise.
    pub exercise: ExerciseId,
    /// Its domain.
    pub domain: DomainId,
    /// The ledger position of its decision record.
    pub position: u64,
    /// The intent digest of the contribution.
    pub intent: [u8; 32],
    /// The approver's Instance, absent for an anonymous approver.
    pub instance: Option<KernelId>,
    /// The receipt's trusted time, Unix milliseconds.
    pub iat: u64,
}

/// Verifies an `exercise` answer for a contribution Exercise (T-101 item 7, E-17; Access
/// §9.14.1 step 4): it names the asked Exercise and domain, is `allowed`, and carries its
/// decision receipt signed under the domain's receipt key for the same Exercise, domain, intent
/// and Instance and not after `now_ms`. The surface commits a contribution over Access's own
/// PEP, so its receipt is not addressed to Work's; Work does not act on a contribution, it only
/// hands it back to Access's decision point as the proof of the next commit, and Access decides
/// what it proves.
///
/// # Errors
/// [`AccessError::Answer`]: `exercise` for a body outside the schema, `exercise-mismatch`,
/// `exercise-domain`, `exercise-status`, `receipt-missing`, `receipt-intent`,
/// `receipt-instance`, and the `receipt-*` code of the receipt check that fails.
pub fn verify_contribution(
    metadata: &DomainMetadata,
    body: &[u8],
    exercise: &ExerciseId,
    domain: &DomainId,
    now_ms: u64,
) -> Result<VerifiedContribution, AccessError> {
    let wire: ExerciseWire = serde_json::from_slice(body).map_err(|_| answer("exercise"))?;
    named_as(&wire.exercise, &wire.domain, exercise, domain)?;
    if wire.status != "allowed" {
        return Err(answer("exercise-status"));
    }
    let intent = fixed_b64url::<32>(&wire.intent).map_err(|_| answer("exercise"))?;
    let position = wire.position.parse().map_err(|_| answer("exercise"))?;
    let instance = wire
        .instance
        .as_deref()
        .map(|i| kernel_id(i, "exercise"))
        .transpose()?;
    let receipt = wire
        .receipt
        .as_ref()
        .ok_or_else(|| answer("receipt-missing"))?;
    let (r, _, _) = signed_receipt(metadata, receipt, exercise, domain, now_ms)?;
    if r.intent.0 != intent {
        return Err(answer("receipt-intent"));
    }
    if r.instance.map(|i| KernelId(i.0)) != instance {
        return Err(answer("receipt-instance"));
    }
    Ok(VerifiedContribution {
        exercise: *exercise,
        domain: *domain,
        position,
        intent,
        instance,
        iat: r.iat,
    })
}

fn verified(
    expected: &Expected<'_>,
    position: u64,
    instance: Option<KernelId>,
    (r, sign1, excerpt): (Receipt, Vec<u8>, Vec<u8>),
) -> VerifiedExercise {
    VerifiedExercise {
        exercise: *expected.exercise,
        domain: *expected.domain,
        position,
        intent: r.intent.0,
        instance,
        capacity: capacity_of(r.capacity),
        agency: r
            .agency
            .into_iter()
            .map(|l| AgencyLink {
                mandate: KernelId(l.mandate.0),
                principal: KernelId(l.principal.0),
                agent: KernelId(l.agent.0),
            })
            .collect(),
        iat: r.iat,
        receipt: sign1,
        excerpt,
    }
}

/// Verifies an `exercise` answer (T-101 note item 7): the asked Exercise and domain, `allowed`,
/// the expected intent, and a receipt that verifies and names the same Exercise, intent and
/// actor Instance.
///
/// # Errors
/// [`AccessError::Answer`]: `exercise` for a body outside the schema, `exercise-mismatch`,
/// `exercise-domain`, `exercise-status`, `exercise-intent`, `receipt-missing` for an Exercise
/// without its receipt, and the `receipt-*` code of the receipt check that fails.
pub fn verify_exercise(
    metadata: &DomainMetadata,
    body: &[u8],
    expected: &Expected<'_>,
) -> Result<VerifiedExercise, AccessError> {
    let wire: ExerciseWire = serde_json::from_slice(body).map_err(|_| answer("exercise"))?;
    named(&wire.exercise, &wire.domain, expected)?;
    if wire.status != "allowed" {
        return Err(answer("exercise-status"));
    }
    if fixed_b64url::<32>(&wire.intent).ok() != Some(expected.intent.digest) {
        return Err(answer("exercise-intent"));
    }
    let position = wire.position.parse().map_err(|_| answer("exercise"))?;
    let instance = wire
        .instance
        .as_deref()
        .map(|i| kernel_id(i, "exercise"))
        .transpose()?;
    let receipt = wire
        .receipt
        .as_ref()
        .ok_or_else(|| answer("receipt-missing"))?;
    let checked = verify_receipt(metadata, receipt, expected)?;
    if checked.0.instance.map(|i| KernelId(i.0)) != instance {
        return Err(answer("receipt-instance"));
    }
    Ok(verified(expected, position, instance, checked))
}

/// Verifies the decision receipt an allowed evaluation carries (Access §9.8, L2-RCP-2) as
/// [`verify_exercise`] verifies an Exercise answer's: under the domain key its `excerpt` binds to
/// Domain Metadata, for the asked Exercise, domain and intent, addressed to Work's PEP.
///
/// # Errors
/// [`AccessError::Answer`]: the `receipt-*` code of the receipt check that fails.
pub fn verify_decision_receipt(
    metadata: &DomainMetadata,
    sign1: &[u8],
    excerpt: &[u8],
    expected: &Expected<'_>,
) -> Result<VerifiedExercise, AccessError> {
    let payload = unverified_payload(sign1).map_err(|_| answer("receipt-malformed"))?;
    let wire = ReceiptWire {
        payload: b64url(&payload),
        cose_sign1: Some(b64url(sign1)),
        key_excerpt: Some(b64url(excerpt)),
    };
    let checked = verify_receipt(metadata, &wire, expected)?;
    let instance = checked.0.instance.map(|i| KernelId(i.0));
    let position = checked.0.record;
    Ok(verified(expected, position, instance, checked))
}

/// Verifies an `exercise_agency` answer (Access OP-149 m.11): the asked Exercise and domain, a
/// receipt that verifies as for [`verify_exercise`], and a capacity and chain that are the
/// verified receipt's own.
///
/// # Errors
/// [`AccessError::Answer`]: `agency` for a body outside the schema, `exercise-mismatch`,
/// `exercise-domain`, `agency-mismatch` when the answer's capacity or chain is not the
/// receipt's, and the `receipt-*` code of the receipt check that fails.
pub fn verify_agency(
    metadata: &DomainMetadata,
    body: &[u8],
    expected: &Expected<'_>,
) -> Result<VerifiedExercise, AccessError> {
    let wire: AgencyWire = serde_json::from_slice(body).map_err(|_| answer("agency"))?;
    named(&wire.exercise, &wire.domain, expected)?;
    let capacity = wire_capacity(&wire.capacity)?;
    let chain = wire
        .agency
        .iter()
        .map(|l| {
            Ok(AgencyLink {
                mandate: kernel_id(&l.mandate, "agency")?,
                principal: kernel_id(&l.principal, "agency")?,
                agent: kernel_id(&l.agent, "agency")?,
            })
        })
        .collect::<Result<Vec<_>, AccessError>>()?;
    let checked = verify_receipt(metadata, &wire.receipt, expected)?;
    let instance = checked.0.instance.map(|i| KernelId(i.0));
    let position = checked.0.record;
    let out = verified(expected, position, instance, checked);
    if out.capacity != capacity || out.agency != chain {
        return Err(answer("agency-mismatch"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
