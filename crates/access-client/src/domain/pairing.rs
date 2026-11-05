//! Work's pairing with a tenant's realms (T-103 items 2–6, Access OP-149 m.16 (a), m.17b (e), m.19 (d)): the challenge Access hands out, what must hold before Work signs anything, the intent digests Work recomputes itself from the challenge fields (L0-ENC-23, the self-signed `instance_create` and `party_register` intents), the Actor Intent Statements the service key signs, the pairing request and its result, and what each answer changes in Work's realm table.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::ais::Statement;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::meta::{ActorKind, ExerciseBasis, NAMESPACE, Payload, Root, kind, object_id};
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::schema::{ActionSchema, EffectClass, action_digest};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use serde::Deserialize;

use crate::domain::tenants::SnapshotRealm;
use crate::domain::x509::{days_from_civil, digits};
use crate::domain::{AccessError, b64url, fixed_b64url, from_b64url};

/// The least time a challenge must still be valid for Work to sign it, ms (T-103 item 2, PD).
pub const MIN_VALIDITY_MS: u64 = 60_000;

/// Most targets one pairing request carries (Access OP-149 m.16 (d)).
pub const MAX_TARGETS: usize = 64;

/// Failed runs in a row after which a realm counts as unpaired and the operator is told
/// (T-103 item 4, PD).
pub const STALLED_RUNS: u64 = 3;

/// The resource namespace a self-signed intent names its Party in.
pub const PARTY_NAMESPACE: &str = "access.party";

/// The intent parameter that carries the meta payload's digest.
pub const PAYLOAD_PARAM: &str = "payload";

/// Appended to the challenge to form the `party_register` nonce (Access OP-149 m.17b (e)).
pub const REGISTER_NONCE_SUFFIX: u8 = 0x01;

/// Whether `text` is a canonical lower-case UUID, as Access writes realm and stream ids.
#[must_use]
pub fn is_uuid(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// A realm id in Access's spelling, a canonical lower-case UUID (P-112 item 4).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RealmId(String);

impl RealmId {
    /// Reads `text`.
    ///
    /// # Errors
    /// [`AccessError::Identifier`] for anything else.
    pub fn parse(text: &str) -> Result<Self, AccessError> {
        if is_uuid(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(AccessError::Identifier("realm"))
        }
    }

    /// The UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One of the two Exercises a challenge names: its nonce and Access's intent digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exercise {
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent digest Access gave, checked before anything is signed.
    pub intent: [u8; 32],
}

/// An `unpaired` target: what the product's Exercises must name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unpaired {
    /// The realm.
    pub realm: RealmId,
    /// The realm's governing domain id.
    pub domain: [u8; 32],
    /// The Genesis bootstrap Grant the Exercises name as `public` basis.
    pub basis: [u8; 16],
    /// The PEP the statements address: the identity plane.
    pub pep: String,
    /// Work's service Party in the domain.
    pub party: [u8; 16],
    /// The `kid` Access registered for the service key.
    pub kid: [u8; 32],
    /// The challenge, the `instance_create` nonce.
    pub challenge: [u8; 32],
    /// Start of the intents' validity, Unix milliseconds.
    pub valid_from_ms: u64,
    /// End of it; the challenge is not accepted later.
    pub valid_until_ms: u64,
    /// `instance_create`.
    pub instance_create: Exercise,
    /// `party_register`, while the Party is new.
    pub party_register: Option<Exercise>,
}

/// A `paired` target: the Instance an earlier pairing with the current service key opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paired {
    /// The realm.
    pub realm: RealmId,
    /// Work's service Party.
    pub party: [u8; 16],
    /// Work's service Instance.
    pub instance: [u8; 16],
    /// RFC 7638 thumbprint of the service key.
    pub kid: [u8; 32],
}

/// One target of a challenge or pairing answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Paired already; stored without signing (T-103 item 2).
    Paired(Paired),
    /// To be signed once every check holds.
    Unpaired(Box<Unpaired>),
    /// Refused by the authority plane, with its code (T-103 item 6).
    Refused {
        /// The realm.
        realm: RealmId,
        /// Why.
        code: String,
    },
}

impl Target {
    /// The realm it is of.
    #[must_use]
    pub fn realm(&self) -> &RealmId {
        match self {
            Self::Paired(p) => &p.realm,
            Self::Unpaired(c) => &c.realm,
            Self::Refused { realm, .. } => realm,
        }
    }
}

#[derive(Deserialize)]
struct ExerciseWire {
    nonce: String,
    intent: String,
}

#[derive(Deserialize)]
struct TargetWire {
    realm: String,
    status: String,
    domain: Option<String>,
    basis: Option<String>,
    pep: Option<String>,
    party: Option<String>,
    instance: Option<String>,
    kid: Option<String>,
    challenge: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    instance_create: Option<ExerciseWire>,
    party_register: Option<ExerciseWire>,
    code: Option<String>,
}

#[derive(Deserialize)]
struct AnswerWire {
    tenant: String,
    targets: Vec<TargetWire>,
    event_stream: Option<String>,
}

const TARGET: AccessError = AccessError::Answer("pairing target");

fn need(field: Option<&str>) -> Result<&str, AccessError> {
    field.ok_or(TARGET)
}

fn exercise(w: &ExerciseWire) -> Result<Exercise, AccessError> {
    let nonce = from_b64url(&w.nonce).map_err(|_| TARGET)?;
    if !(16..=64).contains(&nonce.len()) {
        return Err(TARGET);
    }
    Ok(Exercise {
        nonce,
        intent: fixed_b64url(&w.intent).map_err(|_| TARGET)?,
    })
}

/// Unix milliseconds of RFC 3339 UTC text `YYYY-MM-DDTHH:MM:SS[.f{1,3}]Z`, the only form Access
/// writes; finer fractions cannot name the millisecond the intents were digested at.
#[must_use]
pub fn rfc3339_ms(text: &str) -> Option<u64> {
    let (head, rest) = text.as_bytes().split_at_checked(19)?;
    let at = |i: usize, c: u8| head.get(i) == Some(&c);
    if !(at(4, b'-') && at(7, b'-') && at(10, b'T') && at(13, b':') && at(16, b':')) {
        return None;
    }
    let num = |from: usize, to: usize| head.get(from..to).and_then(digits);
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let millis = match rest {
        b"Z" => 0,
        [b'.', frac @ .., b'Z'] if (1..=3).contains(&frac.len()) => {
            let scale = match frac.len() {
                1 => 100,
                2 => 10,
                _ => 1,
            };
            digits(frac)?.checked_mul(scale)?
        }
        _ => return None,
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    days_from_civil(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?
        .checked_mul(1000)?
        .checked_add(millis)
}

fn target(w: &TargetWire) -> Result<Target, AccessError> {
    let realm = RealmId::parse(&w.realm)?;
    match w.status.as_str() {
        "paired" => Ok(Target::Paired(Paired {
            realm,
            party: fixed_b64url(need(w.party.as_deref())?).map_err(|_| TARGET)?,
            instance: fixed_b64url(need(w.instance.as_deref())?).map_err(|_| TARGET)?,
            kid: fixed_b64url(need(w.kid.as_deref())?).map_err(|_| TARGET)?,
        })),
        "refused" => {
            let code = need(w.code.as_deref())?;
            if code.is_empty() || code.len() > 128 {
                return Err(TARGET);
            }
            Ok(Target::Refused {
                realm,
                code: code.to_owned(),
            })
        }
        "unpaired" => {
            let time = |t: Option<&str>| need(t).and_then(|t| rfc3339_ms(t).ok_or(TARGET));
            Ok(Target::Unpaired(Box::new(Unpaired {
                realm,
                domain: fixed_b64url(need(w.domain.as_deref())?).map_err(|_| TARGET)?,
                basis: fixed_b64url(need(w.basis.as_deref())?).map_err(|_| TARGET)?,
                pep: need(w.pep.as_deref())?.to_owned(),
                party: fixed_b64url(need(w.party.as_deref())?).map_err(|_| TARGET)?,
                kid: fixed_b64url(need(w.kid.as_deref())?).map_err(|_| TARGET)?,
                challenge: fixed_b64url(need(w.challenge.as_deref())?).map_err(|_| TARGET)?,
                valid_from_ms: time(w.valid_from.as_deref())?,
                valid_until_ms: time(w.valid_until.as_deref())?,
                instance_create: exercise(w.instance_create.as_ref().ok_or(TARGET)?)?,
                party_register: w.party_register.as_ref().map(exercise).transpose()?,
            })))
        }
        _ => Err(TARGET),
    }
}

/// An answer of either pairing route: `PairingChallenges` or `PairingResult`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The tenant, `tnt_…`.
    pub tenant: String,
    /// One target per realm.
    pub targets: Vec<Target>,
    /// The client's SSF push stream, on a pairing result once a target is paired.
    pub event_stream: Option<String>,
}

impl Answer {
    /// Reads the answer for `tenant`; every target names a distinct realm.
    ///
    /// # Errors
    /// [`AccessError::Answer`] or [`AccessError::Identifier`].
    pub fn from_json(body: &[u8], tenant: &str) -> Result<Self, AccessError> {
        let w: AnswerWire =
            serde_json::from_slice(body).map_err(|_| AccessError::Answer("pairing"))?;
        if w.tenant != tenant {
            return Err(AccessError::Answer("tenant"));
        }
        if w.event_stream.as_deref().is_some_and(|s| !is_uuid(s)) {
            return Err(AccessError::Answer("event_stream"));
        }
        let targets = w
            .targets
            .iter()
            .map(target)
            .collect::<Result<Vec<_>, _>>()?;
        let realms: BTreeSet<&RealmId> = targets.iter().map(Target::realm).collect();
        if realms.len() != targets.len() {
            return Err(AccessError::Answer("pairing targets"));
        }
        Ok(Self {
            tenant: w.tenant,
            targets,
            event_stream: w.event_stream,
        })
    }
}

/// Why Work does not sign a challenge; each opens an operator signal (T-103 item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsignable {
    /// `kid` is not the thumbprint of Work's service key.
    Kid,
    /// The `instance_create` nonce is not the challenge.
    Nonce,
    /// The `party_register` nonce is not the challenge followed by `0x01`.
    RegisterNonce,
    /// Less than [`MIN_VALIDITY_MS`] is left, or the window is reversed.
    Validity,
    /// The basis is not the Genesis bootstrap Grant of the domain.
    Basis,
    /// The PEP name is empty or longer than 255 bytes.
    Pep,
    /// The recomputed `instance_create` intent digest differs from Access's.
    InstanceIntent,
    /// The recomputed `party_register` intent digest differs from Access's.
    RegisterIntent,
    /// An intent or statement does not encode.
    Encoding,
}

impl Unsignable {
    /// The stable code the operator signal carries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Kid => "pairing-kid",
            Self::Nonce => "pairing-nonce",
            Self::RegisterNonce => "pairing-register-nonce",
            Self::Validity => "pairing-validity",
            Self::Basis => "pairing-basis",
            Self::Pep => "pairing-pep",
            Self::InstanceIntent => "pairing-instance-intent",
            Self::RegisterIntent => "pairing-register-intent",
            Self::Encoding => "pairing-encoding",
        }
    }
}

/// The `party_register` nonce of `challenge`.
#[must_use]
pub fn register_nonce(challenge: &[u8]) -> Vec<u8> {
    let mut n = challenge.to_vec();
    n.push(REGISTER_NONCE_SUFFIX);
    n
}

/// The basis a self-signed registration names: the Genesis bootstrap Grant of `domain`, held by
/// the public (L0-META-7).
#[must_use]
pub fn bootstrap_basis(domain: &[u8; 32]) -> ExerciseBasis {
    ExerciseBasis::Public(object_id(&Digest(*domain), kind::GRANT, 0))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            s.extend(HEX.get(usize::from(nibble)).map(|&c| char::from(c)));
        }
    }
    s
}

/// The reference of a core meta-action (L0-META-1): namespace `access`, major 1, the digest of
/// its reversible Action Schema.
#[must_use]
pub fn core_action(name: &str) -> ActionRef {
    let schema = ActionSchema {
        name: name.to_owned(),
        major: 1,
        effect: EffectClass::Reversible,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::new(),
        resource_types: BTreeSet::new(),
        render: None,
    };
    ActionRef {
        namespace: NAMESPACE.to_owned(),
        name: name.to_owned(),
        major: 1,
        schema: action_digest(&schema),
    }
}

/// The intent the service key signs for `payload` of `party` over `validity`:
/// `access/<action>` on `access.party:[hex(party)]` with the payload's digest in
/// `opaque["payload"]`.
///
/// # Errors
/// [`Unsignable::Encoding`].
pub fn self_signed_intent(
    payload: &Payload,
    party: Id,
    validity: Window,
) -> Result<IntentEnvelope, Unsignable> {
    let digest = payload.digest().map_err(|_| Unsignable::Encoding)?;
    Ok(IntentEnvelope {
        action: core_action(payload.action()),
        resources: vec![ResourceRef {
            namespace: PARTY_NAMESPACE.to_owned(),
            path: vec![hex(&party.0)],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::from([(PAYLOAD_PARAM.to_owned(), digest)]),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity,
    })
}

/// The `instance_create` intent digest of Work's service key for the challenge's Party and
/// window, recomputed by Work.
///
/// # Errors
/// [`Unsignable::Encoding`].
pub fn instance_create_digest(
    challenge: &Unpaired,
    service: &PublicKey,
) -> Result<[u8; 32], Unsignable> {
    let party = Id(challenge.party);
    let payload = Payload::InstanceCreate {
        party,
        key: service.clone(),
        mandate: None,
    };
    digest_of(&payload, party, challenge)
}

/// The `party_register` intent digest of a system Party that roots itself, recomputed by Work.
///
/// # Errors
/// [`Unsignable::Encoding`].
pub fn party_register_digest(challenge: &Unpaired) -> Result<[u8; 32], Unsignable> {
    let party = Id(challenge.party);
    let payload = Payload::PartyRegister {
        party,
        root: Root::Sole(party),
        actor_kind: ActorKind::System,
    };
    digest_of(&payload, party, challenge)
}

fn digest_of(payload: &Payload, party: Id, c: &Unpaired) -> Result<[u8; 32], Unsignable> {
    let validity = Window {
        from: c.valid_from_ms,
        until: c.valid_until_ms,
    };
    let envelope = self_signed_intent(payload, party, validity)?;
    intent_digest(&envelope)
        .map(|d| d.0)
        .map_err(|_| Unsignable::Encoding)
}

/// The deterministic CBOR statements the service key signs for one challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statements {
    /// Over the `instance_create` intent.
    pub instance_create: Vec<u8>,
    /// Over the `party_register` intent, exactly when the challenge names it.
    pub party_register: Option<Vec<u8>>,
}

fn statement(
    c: &Unpaired,
    nonce: &[u8],
    intent: [u8; 32],
    basis: ExerciseBasis,
    now_ms: u64,
) -> Result<Vec<u8>, Unsignable> {
    Statement {
        domain: Digest(c.domain),
        nonce: nonce.to_vec(),
        intent: Digest(intent),
        mode: Mode::Commit,
        pep: c.pep.clone(),
        capacity: Capacity::Own,
        basis,
        iat: now_ms,
        exercise: None,
    }
    .to_bytes()
    .map_err(|_| Unsignable::Encoding)
}

/// Every check of T-103 item 2 on `c` for Work's `service` key at `now_ms`, and the statements
/// to sign once they hold: Access's digests are compared with Work's own and never signed as
/// given.
///
/// # Errors
/// [`Unsignable`]: nothing of the challenge is signed.
pub fn statements(
    c: &Unpaired,
    service: &PublicKey,
    now_ms: u64,
) -> Result<Statements, Unsignable> {
    if c.kid != thumbprint(service) {
        return Err(Unsignable::Kid);
    }
    if c.instance_create.nonce != c.challenge {
        return Err(Unsignable::Nonce);
    }
    if c.party_register
        .as_ref()
        .is_some_and(|r| r.nonce != register_nonce(&c.challenge))
    {
        return Err(Unsignable::RegisterNonce);
    }
    let left = c.valid_until_ms.checked_sub(now_ms);
    if c.valid_from_ms > c.valid_until_ms || left.is_none_or(|l| l < MIN_VALIDITY_MS) {
        return Err(Unsignable::Validity);
    }
    let basis = bootstrap_basis(&c.domain);
    if basis != ExerciseBasis::Public(Id(c.basis)) {
        return Err(Unsignable::Basis);
    }
    if c.pep.is_empty() || c.pep.len() > 255 {
        return Err(Unsignable::Pep);
    }
    let create = instance_create_digest(c, service)?;
    if create != c.instance_create.intent {
        return Err(Unsignable::InstanceIntent);
    }
    let party_register = match &c.party_register {
        None => None,
        Some(r) => {
            let register = party_register_digest(c)?;
            if register != r.intent {
                return Err(Unsignable::RegisterIntent);
            }
            Some(statement(c, &r.nonce, register, basis, now_ms)?)
        }
    };
    Ok(Statements {
        instance_create: statement(c, &c.instance_create.nonce, create, basis, now_ms)?,
        party_register,
    })
}

/// One signed answer of a challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// The realm.
    pub realm: RealmId,
    /// The challenge answered.
    pub challenge: [u8; 32],
    /// The tagged `COSE_Sign1` over the `instance_create` statement.
    pub ais: Vec<u8>,
    /// The tagged `COSE_Sign1` over the `party_register` statement.
    pub register_ais: Option<Vec<u8>>,
}

/// The `POST <pairing>` body of 1 to [`MAX_TARGETS`] answers.
///
/// # Errors
/// [`AccessError::Answer`] for none or too many.
pub fn pairing_body(answers: &[Signed]) -> Result<Vec<u8>, AccessError> {
    if answers.is_empty() || answers.len() > MAX_TARGETS {
        return Err(AccessError::Answer("pairing targets"));
    }
    let targets: Vec<serde_json::Value> = answers
        .iter()
        .map(|a| {
            let mut t = serde_json::json!({
                "realm": a.realm.as_str(),
                "challenge": b64url(&a.challenge),
                "ais": b64url(&a.ais),
            });
            if let (Some(r), Some(m)) = (&a.register_ais, t.as_object_mut()) {
                m.insert("register_ais".to_owned(), b64url(r).into());
            }
            t
        })
        .collect();
    Ok(serde_json::json!({ "targets": targets })
        .to_string()
        .into_bytes())
}

/// What the store keeps of a realm (T-103 item 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairState {
    /// Not paired yet.
    Unpaired,
    /// Paired.
    Paired,
    /// Refused.
    Refused,
    /// Left the snapshot.
    Retired,
}

/// One stored realm, as the pairing step reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRealm {
    /// The realm.
    pub realm: RealmId,
    /// Its state.
    pub state: PairState,
    /// The `kid` it is paired or challenged under.
    pub kid: Option<[u8; 32]>,
}

/// One change to Work's realm table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealmChange {
    /// A realm of the snapshot, stored as `unpaired` the first time.
    Seen {
        /// The realm.
        realm: RealmId,
        /// Its issuer.
        issuer: String,
        /// Its slug.
        slug: String,
    },
    /// Every realm of the tenant but `live` is retired.
    Retire {
        /// The realms of the snapshot.
        live: Vec<RealmId>,
    },
    /// A challenge was handed out.
    Unpaired {
        /// The realm.
        realm: RealmId,
        /// Its governing domain.
        domain: [u8; 32],
        /// Work's service Party.
        party: [u8; 16],
        /// The registered `kid`.
        kid: [u8; 32],
    },
    /// Paired, now or before; the failed runs start again.
    Paired {
        /// The realm.
        realm: RealmId,
        /// Its governing domain, when the answer came with a challenge.
        domain: Option<[u8; 32]>,
        /// Work's service Party.
        party: [u8; 16],
        /// Work's service Instance.
        instance: [u8; 16],
        /// The `kid`.
        kid: [u8; 32],
    },
    /// Refused with `code`.
    Refused {
        /// The realm.
        realm: RealmId,
        /// Access's code.
        code: String,
    },
    /// The run did not end paired for the realm.
    Failed {
        /// The realm.
        realm: RealmId,
    },
}

/// The changes a tenant snapshot makes: each live realm is seen, every other realm of the
/// tenant is retired (P-115 note, Access OP-73).
#[must_use]
pub fn snapshot_changes(realms: &[SnapshotRealm]) -> Vec<RealmChange> {
    let mut out: Vec<RealmChange> = realms
        .iter()
        .map(|r| RealmChange::Seen {
            realm: r.id.clone(),
            issuer: r.issuer.clone(),
            slug: r.slug.clone(),
        })
        .collect();
    out.push(RealmChange::Retire {
        live: realms.iter().map(|r| r.id.clone()).collect(),
    });
    out
}

/// Whether a tenant needs a challenge: a realm of `live` is not stored as paired under the
/// service key `kid` (T-103 item 1).
#[must_use]
pub fn needs_pairing(live: &[RealmId], stored: &[StoredRealm], kid: &[u8; 32]) -> bool {
    live.iter().any(|realm| {
        !stored
            .iter()
            .any(|s| s.realm == *realm && s.state == PairState::Paired && s.kid == Some(*kid))
    })
}

/// Whether one more attempt with a new challenge may follow a failed pairing call (T-103
/// item 4): `400 invalid-challenge`, `503` or a network failure.
#[must_use]
pub fn retryable(error: &AccessError) -> bool {
    match error {
        AccessError::Refused { status: 400, code } => code == "invalid-challenge",
        AccessError::Refused { status, .. } => *status == 503,
        AccessError::Transport(_) | AccessError::Timeout => true,
        _ => false,
    }
}

/// What one answer of either route asks of the step.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Changes to store.
    pub changes: Vec<RealmChange>,
    /// The challenges whose checks held, with their statements to sign.
    pub sign: Vec<(RealmId, [u8; 32], Statements)>,
    /// Refused realms with Access's code.
    pub refused: Vec<(RealmId, String)>,
    /// Challenges Work does not sign, and why.
    pub unsignable: Vec<(RealmId, Unsignable)>,
}

/// The plan of a challenge answer for Work's `service` key at `now_ms`: `paired` targets are
/// stored as they are, `unpaired` ones are stored and, when every check holds, signed, and
/// `refused` ones are stored with their code; a target that is not signed or is refused counts
/// as a failed run.
#[must_use]
pub fn plan_challenges(answer: &Answer, service: &PublicKey, now_ms: u64) -> Plan {
    let mut plan = Plan::default();
    for t in &answer.targets {
        match t {
            Target::Paired(p) => plan.changes.push(paired_change(p)),
            Target::Refused { realm, code } => refused(&mut plan, realm, code),
            Target::Unpaired(c) => {
                plan.changes.push(RealmChange::Unpaired {
                    realm: c.realm.clone(),
                    domain: c.domain,
                    party: c.party,
                    kid: c.kid,
                });
                match statements(c, service, now_ms) {
                    Ok(s) => plan.sign.push((c.realm.clone(), c.challenge, s)),
                    Err(e) => {
                        plan.unsignable.push((c.realm.clone(), e));
                        plan.changes.push(RealmChange::Failed {
                            realm: c.realm.clone(),
                        });
                    }
                }
            }
        }
    }
    plan
}

/// The plan of a pairing result for the realms `answered`: `paired` targets are stored, refused
/// ones are stored with their code, and an answered realm the result leaves out or names
/// `unpaired` counts as a failed run.
#[must_use]
pub fn plan_result(answer: &Answer, answered: &[RealmId]) -> Plan {
    let mut plan = Plan::default();
    for realm in answered {
        match answer.targets.iter().find(|t| t.realm() == realm) {
            Some(Target::Paired(p)) => plan.changes.push(paired_change(p)),
            Some(Target::Refused { realm, code }) => refused(&mut plan, realm, code),
            Some(Target::Unpaired(_)) | None => plan.changes.push(RealmChange::Failed {
                realm: realm.clone(),
            }),
        }
    }
    plan
}

fn paired_change(p: &Paired) -> RealmChange {
    RealmChange::Paired {
        realm: p.realm.clone(),
        domain: None,
        party: p.party,
        instance: p.instance,
        kid: p.kid,
    }
}

fn refused(plan: &mut Plan, realm: &RealmId, code: &str) {
    plan.changes.push(RealmChange::Refused {
        realm: realm.clone(),
        code: code.to_owned(),
    });
    plan.changes.push(RealmChange::Failed {
        realm: realm.clone(),
    });
    plan.refused.push((realm.clone(), code.to_owned()));
}

#[cfg(test)]
pub(crate) mod tests;
