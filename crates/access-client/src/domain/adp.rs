//! Work's PEP at the Access decision point (T-101 item 2 and its note, P-13, E-13, E-17, P-116 item 6; Access L1-ADP-5 to L1-ADP-12, OP-149 m.9, XI-7): the canonical `work:commit` intent of a ledger and its ADP JSON form, the Actor Intent Statement the actor's own device Instance signs over it (Work never signs for a human), the check that a statement is the one Work's PEP commits, the `AuthZEN` evaluation body, the decision Access answers read as allow, deny or `REQUIRE_ACTION`, the authentication terms of a step-up Access asks the actor to meet, and the typed authority request a `REQUIRE_ACTION` is pushed to the Approval Surface with. Work sets no assurance threshold of its own: a step-up is what Access's terms say, verbatim.

use std::collections::BTreeMap;

use access_kernel::ais::{SKEW_MS, Statement as Ais};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::codec::explanation_from_value;
use access_kernel::combinator::{Capacity as AccessCapacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue, intent_digest};
use access_kernel::meta::{ExerciseBasis, HoldingRef};
use access_kernel::model::{ActionRef, EqValue, Id, PurposeRef, ResourceRef, Window};
use serde_json::{Map, Value, json};
use suiss_crypto::dcbor::{self, Limits};

use crate::domain::exercise::{Capacity, ExerciseId};
use crate::domain::keys::{DomainId, KernelId};
use crate::domain::metadata::unverified_payload;
use crate::domain::{AccessError, b64url, fixed_b64url, from_b64url};

/// The resource type of a ledger (E-45 item 5).
pub const LEDGER_RESOURCE: &str = "work.ledger";

/// The mode of every Exercise Work's PEP commits.
pub const MODE: &str = "commit";

/// The intent parameter that names the ledger of a `work:commit`.
pub const LEDGER_PARAM: &str = "ledger";

/// The intent parameter that binds the Declaration bytes of a `work:commit`.
pub const DECLARATION_PARAM: &str = "declaration";

/// The longest `reason` an authority request carries (Access `authority-request.cddl`).
pub const MAX_REASON: usize = 1024;

/// The blocker classes Access explains a refusal with (Access E43).
pub const BLOCKER_CLASSES: [&str; 10] = [
    "no-covering-authority",
    "outside-instance-limits",
    "restricted",
    "budget-exhausted",
    "ended",
    "capacity-mismatch",
    "source-not-accepted",
    "schema-not-accepted",
    "nonce-closed",
    "foreign-status-unavailable",
];

/// An action as an intent names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// The namespace, `work`.
    pub namespace: String,
    /// The name, such as `commit`.
    pub name: String,
    /// The major version.
    pub major: u64,
    /// The digest of the pinned action schema.
    pub schema: [u8; 32],
}

/// A holding of a Grant, the basis an actor exercises it on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holding {
    /// The Grant.
    pub grant: KernelId,
    /// Its holder.
    pub holder: KernelId,
    /// The position that opened the episode.
    pub since: u64,
}

impl Holding {
    fn kernel(self) -> HoldingRef {
        HoldingRef {
            grant: Id(self.grant.0),
            holder: Id(self.holder.0),
            since: self.since,
        }
    }

    /// The ADP JSON form, `{"holding": {grant, holder, since}}`.
    #[must_use]
    pub fn json(&self) -> Value {
        json!({"holding": {
            "grant": self.grant.text(),
            "holder": self.holder.text(),
            "since": self.since,
        }})
    }
}

fn kernel_capacity(capacity: Capacity) -> AccessCapacity {
    match capacity {
        Capacity::Own => AccessCapacity::Own,
        Capacity::For(p) => AccessCapacity::For(Id(p.0)),
    }
}

/// The ADP JSON form of a capacity: `"own"` or `{"for": party}`.
#[must_use]
pub fn capacity_json(capacity: Capacity) -> Value {
    match capacity {
        Capacity::Own => Value::from("own"),
        Capacity::For(p) => json!({"for": p.text()}),
    }
}

fn bad_intent() -> AccessError {
    AccessError::Answer("intent")
}

/// The canonical `IntentEnvelope` of `action` over the ledger `ledger` (`led_…`, the
/// `work.ledger` resource), with the ledger and the Declaration bytes as its parameters, valid
/// from `valid_from_ms` to `valid_until_ms` (E-45, Access `intent.cddl`).
///
/// # Errors
/// [`AccessError::Answer`] (`intent`) for an envelope beyond the structural limits or an empty
/// window.
pub fn commit_intent(
    action: &Action,
    ledger: &str,
    declaration: &[u8],
    valid_from_ms: u64,
    valid_until_ms: u64,
) -> Result<Vec<u8>, AccessError> {
    if valid_until_ms < valid_from_ms {
        return Err(bad_intent());
    }
    let envelope = IntentEnvelope {
        action: ActionRef {
            namespace: action.namespace.clone(),
            name: action.name.clone(),
            major: action.major,
            schema: Digest(action.schema),
        },
        resources: vec![ResourceRef {
            namespace: LEDGER_RESOURCE.to_owned(),
            path: vec![ledger.to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::from([
            (
                DECLARATION_PARAM.to_owned(),
                ParamValue::Eq(EqValue::Bytes(declaration.to_vec())),
            ),
            (
                LEDGER_PARAM.to_owned(),
                ParamValue::Eq(EqValue::Text(ledger.to_owned())),
            ),
        ]),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: valid_from_ms,
            until: valid_until_ms,
        },
    };
    envelope.to_bytes().map_err(|_| bad_intent())
}

fn canonical(bytes: &[u8]) -> Result<IntentEnvelope, AccessError> {
    let envelope = IntentEnvelope::from_bytes(bytes).map_err(|_| bad_intent())?;
    if envelope.to_bytes().map_err(|_| bad_intent())? != bytes {
        return Err(bad_intent());
    }
    Ok(envelope)
}

/// The intent digest of canonical envelope bytes (`access/intent/v1`).
///
/// # Errors
/// [`AccessError::Answer`] (`intent`).
pub fn intent_digest_of(bytes: &[u8]) -> Result<[u8; 32], AccessError> {
    intent_digest(&canonical(bytes)?)
        .map(|d| d.0)
        .map_err(|_| bad_intent())
}

fn window_json(w: &Window) -> Value {
    json!({"from": w.from, "until": w.until})
}

fn resource_json(r: &ResourceRef) -> Value {
    let mut out = Map::new();
    out.insert("namespace".to_owned(), Value::from(r.namespace.as_str()));
    out.insert("path".to_owned(), json!(r.path));
    if r.incarnation != 0 {
        out.insert("incarnation".to_owned(), Value::from(r.incarnation));
    }
    Value::Object(out)
}

fn purpose_json(p: &PurposeRef) -> Value {
    match p {
        PurposeRef::Code(c) => json!({"code": c}),
        PurposeRef::Work(d) => json!({"work": b64url(&d.0)}),
        PurposeRef::Aim(d) => json!({"aim": b64url(&d.0)}),
    }
}

fn eq_json(e: &EqValue) -> Value {
    match e {
        EqValue::Text(t) => Value::from(t.as_str()),
        EqValue::Bytes(b) => json!({"bytes": b64url(b)}),
        EqValue::Int(i) => Value::from(*i),
        EqValue::Bool(b) => Value::from(*b),
    }
}

fn param_json(p: &ParamValue) -> Value {
    match p {
        ParamValue::Enum(s) => json!({"enum": s}),
        ParamValue::Eq(e) => json!({"eq": eq_json(e)}),
        ParamValue::Amount { value, unit } => json!({"amount": {"value": value, "unit": unit}}),
        ParamValue::Count(n) => json!({"count": n}),
        ParamValue::Interval(w) => json!({"interval": window_json(w)}),
        ParamValue::Resource(r) => json!({"resource": resource_json(r)}),
        ParamValue::Subject(id) => json!({"subject": b64url(&id.0)}),
        ParamValue::Purpose(p) => json!({"purpose": purpose_json(p)}),
        ParamValue::Flag(b) => json!({"flag": b}),
    }
}

fn context_json(c: &ContextRefs) -> Value {
    let mut out = Map::new();
    for (name, d) in [
        ("work", c.work),
        ("commitment", c.commitment),
        ("step", c.step),
        ("upstream_exercise", c.upstream_exercise),
    ] {
        if let Some(d) = d {
            out.insert(name.to_owned(), Value::from(b64url(&d.0)));
        }
    }
    Value::Object(out)
}

/// The ADP JSON form of canonical envelope bytes, the evaluation's `context.intent`
/// (Access L1-ADP-8): every byte string and digest unpadded base64url.
///
/// # Errors
/// [`AccessError::Answer`] (`intent`) for bytes that are not a canonical envelope.
pub fn intent_json(bytes: &[u8]) -> Result<Value, AccessError> {
    let e = canonical(bytes)?;
    let mut out = Map::new();
    out.insert(
        "action".to_owned(),
        json!({
            "namespace": e.action.namespace,
            "name": e.action.name,
            "major": e.action.major,
            "schema": b64url(&e.action.schema.0),
        }),
    );
    out.insert(
        "resources".to_owned(),
        Value::Array(e.resources.iter().map(resource_json).collect()),
    );
    out.insert("validity".to_owned(), window_json(&e.validity));
    if !e.params.is_empty() {
        out.insert(
            "params".to_owned(),
            Value::Object(
                e.params
                    .iter()
                    .map(|(k, v)| (k.clone(), param_json(v)))
                    .collect(),
            ),
        );
    }
    if !e.opaque.is_empty() {
        out.insert(
            "opaque".to_owned(),
            Value::Object(
                e.opaque
                    .iter()
                    .map(|(k, d)| (k.clone(), Value::from(b64url(&d.0))))
                    .collect(),
            ),
        );
    }
    if let Some(r) = &e.recipient {
        out.insert("recipient".to_owned(), Value::from(b64url(&r.0)));
    }
    if let Some(p) = &e.purpose {
        out.insert("purpose".to_owned(), purpose_json(p));
    }
    if e.context != ContextRefs::default() {
        out.insert("context".to_owned(), context_json(&e.context));
    }
    Ok(Value::Object(out))
}

/// What the actor's Actor Intent Statement says, and what Work's PEP commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement<'a> {
    /// The governing domain.
    pub domain: &'a DomainId,
    /// The Exercise nonce, 16 to 64 bytes.
    pub nonce: &'a [u8],
    /// The intent digest.
    pub intent: &'a [u8; 32],
    /// The PEP that commits it: the `x5t#S256` of Work's PEP certificate.
    pub pep: &'a str,
    /// The declared capacity.
    pub capacity: Capacity,
    /// The declared basis.
    pub basis: Holding,
}

impl Statement<'_> {
    fn kernel(&self, iat_ms: u64) -> Ais {
        Ais {
            domain: Digest(self.domain.0),
            nonce: self.nonce.to_vec(),
            intent: Digest(*self.intent),
            mode: Mode::Commit,
            pep: self.pep.to_owned(),
            capacity: kernel_capacity(self.capacity),
            basis: ExerciseBasis::Holding(self.basis.kernel()),
            iat: iat_ms,
            exercise: None,
        }
    }

    /// The deterministic CBOR the actor's device Instance signs at `iat_ms`, as the payload of a
    /// tagged `COSE_Sign1` with content type `application/access-ais+cbor` (Access L2-SIG-1).
    ///
    /// # Errors
    /// [`AccessError::Answer`] (`ais`) for a statement beyond the structural limits.
    pub fn to_sign(&self, iat_ms: u64) -> Result<Vec<u8>, AccessError> {
        self.kernel(iat_ms)
            .to_bytes()
            .map_err(|_| AccessError::Answer("ais"))
    }

    /// Whether `ais` states exactly this commit, signed within Access's skew of `now_ms`
    /// (Access CR-55 m.9); its signature is Access's to verify.
    ///
    /// # Errors
    /// [`AccessError::Answer`]: `ais` for bytes that are not a statement, `ais-mismatch` for one
    /// that states another commit, `ais-time` for one signed outside the skew.
    pub fn check(&self, ais: &[u8], now_ms: u64) -> Result<(), AccessError> {
        let payload = unverified_payload(ais).map_err(|_| AccessError::Answer("ais"))?;
        let stated = Ais::from_bytes(&payload).map_err(|_| AccessError::Answer("ais"))?;
        if stated != self.kernel(stated.iat) {
            return Err(AccessError::Answer("ais-mismatch"));
        }
        if stated.iat.abs_diff(now_ms) > SKEW_MS {
            return Err(AccessError::Answer("ais-time"));
        }
        Ok(())
    }
}

/// A proof an evaluation relies on (Access L1-ADP-12, OP-149 m.33 (c)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proof {
    /// The contribution Exercise of an approval, `{"contribution": …}`.
    Contribution(ExerciseId),
    /// A Claim by its `ClaimID`, such as the approver's `authentication` Claim the Approval
    /// Surface returned, `{"claim_ref": …}`.
    Claim(KernelId),
}

impl Proof {
    /// The ADP JSON form.
    #[must_use]
    pub fn json(&self) -> Value {
        match self {
            Self::Contribution(e) => json!({"contribution": e.text()}),
            Self::Claim(c) => json!({"claim_ref": c.text()}),
        }
    }
}

/// One `AuthZEN` evaluation Work's PEP commits (Access L1-ADP-5): the actor's Party, the
/// intent, the statement and its AIS, and the proofs it relies on.
#[derive(Clone, Debug)]
pub struct Evaluation<'a> {
    /// The actor Party, the caller Access named.
    pub party: &'a str,
    /// The canonical envelope bytes.
    pub intent: &'a [u8],
    /// What the AIS states.
    pub statement: Statement<'a>,
    /// The AIS, a tagged `COSE_Sign1` by the actor's device Instance key.
    pub ais: &'a [u8],
    /// The contributions and Claims it relies on (Access L1-ADP-12).
    pub proofs: &'a [Proof],
}

impl Evaluation<'_> {
    /// The request body.
    ///
    /// # Errors
    /// [`AccessError::Answer`] (`intent`) for bytes that are not a canonical envelope.
    pub fn body(&self) -> Result<Vec<u8>, AccessError> {
        let envelope = canonical(self.intent)?;
        let first = envelope.resources.first().ok_or_else(bad_intent)?;
        let mut context = Map::new();
        context.insert(
            "domain".to_owned(),
            Value::from(b64url(&self.statement.domain.0)),
        );
        context.insert("mode".to_owned(), Value::from(MODE));
        context.insert(
            "nonce".to_owned(),
            Value::from(b64url(self.statement.nonce)),
        );
        context.insert("intent".to_owned(), intent_json(self.intent)?);
        context.insert("basis".to_owned(), self.statement.basis.json());
        context.insert(
            "capacity".to_owned(),
            capacity_json(self.statement.capacity),
        );
        context.insert("ais".to_owned(), Value::from(b64url(self.ais)));
        if !self.proofs.is_empty() {
            context.insert(
                "proofs".to_owned(),
                Value::Array(self.proofs.iter().map(Proof::json).collect()),
            );
        }
        let body = json!({
            "subject": {"type": "access_party", "id": self.party},
            "action": {"name": envelope.action.name},
            "resource": {"type": first.namespace, "id": first.path.join("/")},
            "context": context,
        });
        serde_json::to_vec(&body).map_err(|_| bad_intent())
    }
}

/// The decision Access answered an evaluation with (Access L1-ADP-10), in the requester's view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Allowed: the Exercise and, once signed, its decision receipt and key excerpt.
    Allow {
        /// The Exercise.
        exercise: ExerciseId,
        /// The receipt `COSE_Sign1` and its key excerpt.
        receipt: Option<(Vec<u8>, Vec<u8>)>,
    },
    /// Denied: the blockers, as Access shows them to the requester.
    Deny {
        /// The blockers.
        blockers: Vec<Value>,
    },
    /// Not yet: the terms the request still lacks.
    RequireAction {
        /// The unmet terms.
        unmet: Vec<Value>,
        /// The blockers, when any.
        blockers: Vec<Value>,
    },
}

fn listed(context: &Value, name: &str) -> Vec<Value> {
    context
        .get(name)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The members of an ADP `context` that are its explanation (Access E43, `explanation.cddl`).
pub const EXPLANATION_MEMBERS: [&str; 4] = ["outcome", "blockers", "unmet", "relied_on"];

/// Whether the explanation members of an ADP `context` are an explanation in one of Access's
/// scopes as Access's kernel reads it (`explanation_from_value`; Access OP-149 m.33 (a)): their
/// JSON form mapped to its canonical CBOR and decoded by Access's own decoder.
#[must_use]
pub fn explained(context: &Value) -> bool {
    let Some(members) = context.as_object() else {
        return false;
    };
    let explanation: Map<String, Value> = members
        .iter()
        .filter(|(k, _)| EXPLANATION_MEMBERS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    work_proto::explanation::from_json(&Value::Object(explanation))
        .ok()
        .and_then(|e| e.encode().ok())
        .and_then(|bytes| dcbor::decode(&bytes, Limits::CEILING).ok())
        .is_some_and(|value| explanation_from_value(&value).is_ok())
}

impl Decision {
    /// Reads the `200` answer, whose `context` explains the decision in the requester's scope.
    ///
    /// # Errors
    /// [`AccessError::Answer`] (`decision`) for an answer outside the contract or a `context`
    /// whose explanation [`explained`] refuses.
    pub fn from_json(body: &[u8]) -> Result<Self, AccessError> {
        let bad = || AccessError::Answer("decision");
        let v: Value = serde_json::from_slice(body).map_err(|_| bad())?;
        let allowed = v.get("decision").and_then(Value::as_bool).ok_or_else(bad)?;
        let context = v.get("context").filter(|c| explained(c)).ok_or_else(bad)?;
        let outcome = context.get("outcome").and_then(Value::as_str);
        match (allowed, outcome) {
            (true, Some("allow")) => {
                let exercise = context
                    .get("exercise")
                    .and_then(Value::as_str)
                    .and_then(|e| ExerciseId::parse(e).ok())
                    .ok_or_else(bad)?;
                let part = |k: &str| {
                    context
                        .get("receipt")
                        .and_then(|r| r.get(k))
                        .and_then(Value::as_str)
                        .and_then(|s| from_b64url(s).ok())
                };
                Ok(Self::Allow {
                    exercise,
                    receipt: part("sign1").zip(part("excerpt")),
                })
            }
            (false, Some("deny")) => Ok(Self::Deny {
                blockers: listed(context, "blockers"),
            }),
            (false, Some("require_action")) => Ok(Self::RequireAction {
                unmet: listed(context, "unmet"),
                blockers: listed(context, "blockers"),
            }),
            _ => Err(bad()),
        }
    }
}

fn term_member<'a>(unmet: &'a Value, name: &str) -> Option<&'a str> {
    unmet
        .get("term")
        .and_then(|t| t.get(name))
        .and_then(Value::as_str)
}

fn proof_kind(unmet: &Value) -> Option<&str> {
    term_member(unmet, "proof_kind")
}

/// The proof kind, and the class of a `claim` term, of a step-up (Access OP-149 m.33 (c)).
pub const AUTHENTICATION: &str = "authentication";

/// The unmet authentication terms of a `REQUIRE_ACTION`, as Access wrote them: the step-up the
/// actor meets at Access (P-116 item 6, E-7; Access OP-149 m.33 (c)), an `authentication` proof
/// or an `authentication` Claim, which the approver's passkey assertion on the Approval Surface
/// meets beside the approval. Work adds no threshold.
#[must_use]
pub fn step_up(unmet: &[Value]) -> Vec<Value> {
    unmet
        .iter()
        .filter(|u| match proof_kind(u) {
            Some(AUTHENTICATION) => true,
            Some("claim") => term_member(u, "class") == Some(AUTHENTICATION),
            _ => false,
        })
        .cloned()
        .collect()
}

/// Whether a `REQUIRE_ACTION` asks for an approval, a contribution term (Access §9.14.1).
#[must_use]
pub fn needs_approval(unmet: &[Value]) -> bool {
    unmet.iter().any(|u| proof_kind(u) == Some("contribution"))
}

/// The stable code of a denial: the class of its first blocker Access names, `denied` for none.
#[must_use]
pub fn denial_code(blockers: &[Value]) -> &'static str {
    blockers
        .first()
        .and_then(|b| b.get("class"))
        .and_then(Value::as_str)
        .and_then(|c| BLOCKER_CLASSES.iter().find(|k| **k == c))
        .copied()
        .unwrap_or("denied")
}

/// Whether `reason` is a reason an authority request may carry: 1 to 1024 bytes, no control
/// character.
#[must_use]
pub fn valid_reason(reason: &str) -> bool {
    !reason.is_empty() && reason.len() <= MAX_REASON && !reason.chars().any(char::is_control)
}

/// The typed authority request of a `REQUIRE_ACTION` (Access XI-7, OP-149 m.9,
/// `authority-request.cddl`): who asks, the intent's action, primary resource and parameters,
/// the capacity, Work's reason, the decision it answers and when it expires. Access never stores
/// it beyond its expiry; the Approval Surface shows the render the decision point kept.
#[derive(Clone, Debug)]
pub struct AuthorityRequest<'a> {
    /// The asking Party.
    pub party: &'a str,
    /// The canonical envelope bytes.
    pub intent: &'a [u8],
    /// What the actor stated.
    pub statement: Statement<'a>,
    /// Why, as Work shows it.
    pub reason: &'a str,
    /// When the request expires, Unix milliseconds.
    pub expires_at_ms: u64,
}

impl AuthorityRequest<'_> {
    /// The JSON form (`authority-request.schema.json`).
    ///
    /// # Errors
    /// [`AccessError::Answer`]: `intent` for bytes that are not a canonical envelope, `reason`
    /// for a reason [`valid_reason`] refuses.
    pub fn json(&self) -> Result<Value, AccessError> {
        if !valid_reason(self.reason) {
            return Err(AccessError::Answer("reason"));
        }
        let intent = intent_json(self.intent)?;
        let resource = intent
            .get("resources")
            .and_then(|r| r.get(0))
            .cloned()
            .ok_or_else(bad_intent)?;
        let action = intent.get("action").cloned().ok_or_else(bad_intent)?;
        Ok(json!({
            "requester": {"party": self.party},
            "action": action,
            "resource": resource,
            "params": intent.get("params").cloned().unwrap_or_else(|| json!({})),
            "capacity": capacity_json(self.statement.capacity),
            "reason": self.reason,
            "require_action": {
                "domain": b64url(&self.statement.domain.0),
                "nonce": b64url(self.statement.nonce),
                "intent": b64url(self.statement.intent),
            },
            "expires_at": self.expires_at_ms,
        }))
    }
}

/// Reads a holding in its ADP JSON form.
///
/// # Errors
/// [`AccessError::Identifier`] (`basis`).
pub fn holding_from_json(v: &Value) -> Result<Holding, AccessError> {
    let bad = || AccessError::Identifier("basis");
    let h = v.get("holding").ok_or_else(bad)?;
    let id = |name: &str| {
        h.get(name)
            .and_then(Value::as_str)
            .and_then(|t| fixed_b64url::<16>(t).ok())
            .map(KernelId)
            .ok_or_else(bad)
    };
    Ok(Holding {
        grant: id("grant")?,
        holder: id("holder")?,
        since: h.get("since").and_then(Value::as_u64).ok_or_else(bad)?,
    })
}

#[cfg(test)]
mod tests;
