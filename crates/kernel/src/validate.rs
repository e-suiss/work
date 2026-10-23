//! Record rules as a pure function over a decoded record and explicit context: origin (T-66), actor types from Access (P-12), understood extensions (P-19) and narrowed limits (T-65); the result is a decision, never an error.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::catalog::{
    ActSubtype, CancelReason, ClaimSubtype, ConditionType, Consequence, CoreEvidenceType,
    DeclarationSubtype, DeclineReason, GateForm, NoticeType, StopAnswer, StopType, WaitReason,
    consequence,
};
use crate::id::{PartyRef, Time, canonical_text_cmp};
use crate::limits::SemanticLimits;
use crate::reason::{
    EnvelopeField, Limit, ListField, NonCanonicalCbor, QuarantineReason, Reason, Schema, SetField,
    wire_enum,
};
use crate::record::{
    Audience, Capacity, ClaimType, EvidenceSubject, EvidenceType, ParamScalar, ParamValue,
    PracticePin, Record, RecordCore, Visibility,
};
use crate::relation::{DerivedRole, DerivedTarget, ReferenceTarget, Relation, RelationName};
use crate::rules::RuleSet;
use crate::uri::{ExtKey, TypeUri};

wire_enum! {
    /// Whether a Party wrote the record on its own initiative or automation did (INV-20, T-66).
    Origin {
        /// The author's own request.
        Direct => "direct",
        /// A platform, sync keeper, scheduler or policy.
        Automation => "automation",
    }
}

wire_enum! {
    /// The actor type of a Party (P-12); an input to visibility and policy, never to authority (INV-23).
    ActorType {
        /// A human.
        Human => "human",
        /// An AI agent.
        Agent => "agent",
        /// A system.
        System => "system",
        /// A machine.
        Machine => "machine",
        /// An organization.
        Organization => "organization",
    }
}

wire_enum! {
    /// Where an actor type comes from (P-12).
    ActorTypeSource {
        /// The Party's identity binding in Access.
        AccessBinding => "access_binding",
        /// The author's declaration, not verified.
        DeclaredUnverified => "declared_unverified",
    }
}

/// One actor type with its source (P-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorTypeEntry {
    /// The actor type.
    pub actor_type: ActorType,
    /// Its source.
    pub source: ActorTypeSource,
}

/// Actor types of the author and of every `on_behalf_of` ring, as the ledger writes them into the envelope (P-12, INV-18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorTypes {
    /// The author's actor type.
    pub author: ActorTypeEntry,
    /// One entry per `on_behalf_of` ring, in chain order.
    pub on_behalf_of: Vec<ActorTypeEntry>,
}

/// Verifier inputs that are not record bytes.
#[derive(Clone, Copy, Debug)]
pub struct ValidationContext<'a> {
    /// The origin the Work service supplies (T-66).
    pub origin: Origin,
    /// Actor types from Access (P-12).
    pub actor_types: &'a ActorTypes,
    /// Extension keys this verifier implements (P-19).
    pub understood_extensions: &'a [ExtKey],
    /// The effective semantic limits (T-65).
    pub limits: SemanticLimits,
    /// The envelope `recorded_at`, when the ledger has assigned it (P-27, P-80).
    pub recorded_at: Option<Time>,
}

/// The decision about one record (P-11, P-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The record is admitted.
    Accepted,
    /// The record is written but held for attention (P-19, P-87, SEC-18).
    Quarantined(QuarantineReason),
    /// The record is not admitted, with a reason (P-11).
    Rejected(Reason),
}

/// Applies the rules of the record's own protocol version in a fixed order; the first failing rule decides, and a record of a version without a rule set is quarantined (T-4 rule 4, P-87).
#[must_use]
pub fn validate(record: &Record, ctx: &ValidationContext<'_>) -> Outcome {
    match RuleSet::of(record) {
        None => Outcome::Quarantined(QuarantineReason::ProtocolVersionUnknown),
        Some(RuleSet::V1_0) => match check_v1_0(record, ctx) {
            Err(reason) => Outcome::Rejected(reason),
            Ok(()) => quarantine(record.core(), ctx.understood_extensions)
                .map_or(Outcome::Accepted, Outcome::Quarantined),
        },
    }
}

fn check_v1_0(record: &Record, ctx: &ValidationContext<'_>) -> Result<(), Reason> {
    let core = record.core();
    schema(record)?;
    limits(record, ctx.limits)?;
    bounds(core)?;
    set_order(core)?;
    map_order(core)?;
    duplicates(core)?;
    visibility_scope(core)?;
    critical_present(core)?;
    capacity(core)?;
    actor_rings(core, ctx.actor_types)?;
    authority(record)?;
    capacity_present(record)?;
    producer(core, ctx.actor_types)?;
    mapped(record)?;
    params(record)?;
    retroactive(record, ctx.recorded_at)?;
    attribution(record, ctx)
}

fn reject_if(condition: bool, reason: Reason) -> Result<(), Reason> {
    if condition { Err(reason) } else { Ok(()) }
}

fn is_empty<T>(list: Option<&Vec<T>>) -> bool {
    list.is_some_and(Vec::is_empty)
}

fn visibilities(core: &RecordCore) -> impl Iterator<Item = &Visibility> {
    core::iter::once(&core.visibility).chain(
        core.evidence
            .iter()
            .flatten()
            .filter_map(|e| e.visibility.as_ref()),
    )
}

fn parties(visibility: &Visibility) -> &[PartyRef] {
    match &visibility.see {
        Audience::Parties(p) => p,
        Audience::Work | Audience::Author => &[],
    }
}

// P-72 P-81 P-5
fn schema(record: &Record) -> Result<(), Reason> {
    let core = record.core();
    let declaration = matches!(record, Record::Declaration(_));
    reject_if(
        declaration && core.basis.is_none(),
        Reason::Schema(Schema::RequiredField),
    )?;
    let empty_list = (!declaration && is_empty(core.basis.as_ref()))
        || is_empty(core.on_behalf_of.as_ref())
        || is_empty(core.relations.as_ref())
        || is_empty(core.correlation.as_ref())
        || is_empty(core.evidence.as_ref())
        || is_empty(core.body.as_ref())
        || is_empty(core.critical.as_ref());
    reject_if(empty_list, Reason::Schema(Schema::EmptyOptionalList))?;
    let empty_map = is_empty(core.ext.as_ref())
        || is_empty(core.params.as_ref())
        || is_empty(core.versions.practices.as_ref());
    reject_if(empty_map, Reason::Schema(Schema::EmptyOptionalMap))?;
    let no_parties =
        visibilities(core).any(|v| matches!(&v.see, Audience::Parties(p) if p.is_empty()));
    reject_if(no_parties, Reason::Schema(Schema::RequiredField))
}

fn catalog_text<T>(value: &ParamValue, parse: impl Fn(&str) -> Option<T>) -> bool {
    matches!(value, ParamValue::Scalar(ParamScalar::Text(t)) if parse(t).is_some())
}

// P-71 P-85 P-93
fn parent_code(text: &str) -> &str {
    match text.split_once(':') {
        Some((code, sub)) if TypeUri::parse(sub).is_some() => code,
        _ => text,
    }
}

fn reason_code<T>(value: &ParamValue, parse: impl Fn(&str) -> Option<T>) -> bool {
    catalog_text(value, |t| parse(parent_code(t)))
}

fn condition_type_ok(value: &ParamValue, practices: &[PracticePin]) -> bool {
    catalog_text(value, |t| {
        ConditionType::from_uri(t).map(|_| ()).or_else(|| {
            TypeUri::parse(t)
                .filter(|u| !u.is_core() && pinned(u, practices))
                .map(|_| ())
        })
    })
}

#[derive(Clone, Copy)]
enum ParamKind {
    DeclineReason,
    CancelReason,
    NoticeType,
    StopType,
    StopAnswer,
    ConditionType,
    WaitReason,
    GateForm,
    Address,
    Deadline,
    Criterion,
}

struct ParamKey {
    name: &'static str,
    kind: ParamKind,
    required: bool,
}

const fn key(name: &'static str, kind: ParamKind, required: bool) -> ParamKey {
    ParamKey {
        name,
        kind,
        required,
    }
}

// P-80 P-85 P-92 CM-20 CM-30 RC-36 ST-11 ST-12 ST-27
const DECLINE: &[ParamKey] = &[key("reason", ParamKind::DeclineReason, true)];
const CANCEL: &[ParamKey] = &[key("reason", ParamKind::CancelReason, true)];
const NOTICE: &[ParamKey] = &[key("notice_type", ParamKind::NoticeType, true)];
const STOP_REQUEST: &[ParamKey] = &[key("stop_type", ParamKind::StopType, true)];
const STOP_RESPONSE: &[ParamKey] = &[key("response", ParamKind::StopAnswer, true)];
const OPEN_CONDITION: &[ParamKey] = &[
    key("condition_type", ParamKind::ConditionType, true),
    key("wait_reason", ParamKind::WaitReason, true),
    key("gate_form", ParamKind::GateForm, false),
    key("address", ParamKind::Address, true),
    key("deadline", ParamKind::Deadline, true),
    key("criterion", ParamKind::Criterion, true),
];

const fn param_keys(subtype: DeclarationSubtype) -> &'static [ParamKey] {
    match subtype {
        DeclarationSubtype::Decline => DECLINE,
        DeclarationSubtype::Cancel => CANCEL,
        DeclarationSubtype::Notice => NOTICE,
        DeclarationSubtype::StopRequest => STOP_REQUEST,
        DeclarationSubtype::StopResponse => STOP_RESPONSE,
        DeclarationSubtype::OpenCondition => OPEN_CONDITION,
        _ => &[],
    }
}

fn kind_ok(kind: ParamKind, value: &ParamValue, practices: &[PracticePin]) -> bool {
    match kind {
        ParamKind::DeclineReason => reason_code(value, DeclineReason::from_wire_name),
        ParamKind::CancelReason => reason_code(value, CancelReason::from_wire_name),
        ParamKind::NoticeType => reason_code(value, NoticeType::from_wire_name),
        ParamKind::StopType => catalog_text(value, StopType::from_wire_name),
        ParamKind::StopAnswer => catalog_text(value, StopAnswer::from_wire_name),
        ParamKind::ConditionType => condition_type_ok(value, practices),
        ParamKind::WaitReason => catalog_text(value, WaitReason::from_wire_name),
        ParamKind::GateForm => catalog_text(value, GateForm::from_wire_name),
        ParamKind::Address => catalog_text(value, |t| {
            PartyRef::new(t)
                .map(|_| ())
                .or_else(|| TypeUri::parse(t).map(|_| ()))
        }),
        ParamKind::Deadline => {
            matches!(value, ParamValue::Scalar(ParamScalar::Uint(_)))
                || matches!(value, ParamValue::Scalar(ParamScalar::Text(t)) if t == DEADLINE_NONE)
        }
        ParamKind::Criterion => catalog_text(value, TypeUri::parse),
    }
}

fn scalars(value: &ParamValue) -> &[ParamScalar] {
    match value {
        ParamValue::Scalar(s) => core::slice::from_ref(s),
        ParamValue::List(items) => items,
    }
}

fn scalar_ok(scalar: &ParamScalar) -> bool {
    match scalar {
        ParamScalar::Text(t) => PartyRef::new(t).is_some() || TypeUri::parse(t).is_some(),
        ParamScalar::Uint(_)
        | ParamScalar::Bool(_)
        | ParamScalar::Digest(_)
        | ParamScalar::WorkId(_) => true,
    }
}

fn text_param<'a>(record: &'a Record, name: &str) -> Option<&'a str> {
    match record.param(name) {
        Some(ParamValue::Scalar(ParamScalar::Text(t))) => Some(t),
        _ => None,
    }
}

// ST-10 ST-27 P-85
fn gate_form_ok(record: &Record) -> bool {
    let gate_form = text_param(record, "gate_form").and_then(GateForm::from_wire_name);
    let present = record.param("gate_form").is_some();
    match text_param(record, "condition_type").and_then(ConditionType::from_uri) {
        Some(ConditionType::Acceptance) => gate_form == Some(GateForm::DeliveryAcceptance),
        Some(ConditionType::Decision | ConditionType::Resource) => {
            matches!(
                gate_form,
                Some(GateForm::Approval | GateForm::PreActionReview)
            )
        }
        Some(
            ConditionType::Authority
            | ConditionType::Information
            | ConditionType::Commitment
            | ConditionType::ExternalEvent
            | ConditionType::Time
            | ConditionType::ThirdParty,
        ) => !present,
        None => true,
    }
}

// P-80 P-85
fn params(record: &Record) -> Result<(), Reason> {
    let core = record.core();
    let practices = core.versions.practices.as_deref().unwrap_or_default();
    let subtype = record.subtype_uri();
    let core_subtype = subtype.is_none_or(TypeUri::is_core);
    let declaration = match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str()),
        Record::Act(_) | Record::Claim(_) => None,
    };
    for param in core.params.iter().flatten() {
        let name = param.name.as_str();
        let value = &param.value;
        let shape_ok = !scalars(value).is_empty() && scalars(value).iter().all(scalar_ok);
        let ok = shape_ok
            && if name == EFFECTIVE_AT {
                matches!(record, Record::Declaration(_))
                    && matches!(value, ParamValue::Scalar(ParamScalar::Uint(_)))
            } else if let Some(d) = declaration {
                param_keys(d)
                    .iter()
                    .find(|k| k.name == name)
                    .is_some_and(|k| kind_ok(k.kind, value, practices))
            } else {
                !core_subtype
            };
        reject_if(!ok, Reason::Schema(Schema::Params))?;
    }
    if let Some(d) = declaration {
        let complete = param_keys(d)
            .iter()
            .all(|k| !k.required || record.param(k.name).is_some());
        let gate_ok = d != DeclarationSubtype::OpenCondition || gate_form_ok(record);
        reject_if(!(complete && gate_ok), Reason::Schema(Schema::Params))?;
    }
    Ok(())
}

const EFFECTIVE_AT: &str = "effective_at";
const DEADLINE_NONE: &str = "none";
const MAX_ITEMS: usize = 256;
const MAX_PRODUCER_VERSION: usize = 255;
const MAX_IDENTIFIER: usize = 1024;

// P-33 T-65 SEC-18
fn limits(record: &Record, limits: SemanticLimits) -> Result<(), Reason> {
    let core = record.core();
    let counts = [
        (Limit::Basis, record.basis().len()),
        (
            Limit::OnBehalfOf,
            core.on_behalf_of.as_ref().map_or(0, Vec::len),
        ),
        (
            Limit::Relations,
            core.relations.as_ref().map_or(0, Vec::len),
        ),
        (Limit::Concerns, core.concerns.len()),
    ];
    for (limit, count) in counts {
        let max = limits.max(limit).unwrap_or(0);
        reject_if(count > max, Reason::LimitExceeded(limit))?;
    }
    Ok(())
}

fn within(len: usize, max: usize) -> bool {
    (1..=max).contains(&len)
}

// P-5 P-7 P-15 P-16 P-33 EV-3 SEC-18
fn bounds(core: &RecordCore) -> Result<(), Reason> {
    let lists = [
        core.correlation.as_ref().map_or(0, Vec::len),
        core.evidence.as_ref().map_or(0, Vec::len),
        core.body.as_ref().map_or(0, Vec::len),
        core.params.as_ref().map_or(0, Vec::len),
        core.ext.as_ref().map_or(0, Vec::len),
        core.critical.as_ref().map_or(0, Vec::len),
        core.versions.practices.as_ref().map_or(0, Vec::len),
    ];
    let items_over = lists.iter().any(|&n| n > MAX_ITEMS)
        || visibilities(core).any(|v| parties(v).len() > MAX_ITEMS)
        || core
            .params
            .iter()
            .flatten()
            .any(|p| scalars(&p.value).len() > MAX_ITEMS);
    reject_if(items_over, Reason::LimitExceeded(Limit::Items))?;
    let producer_ok = core
        .producer
        .as_ref()
        .is_none_or(|p| within(p.version.len(), MAX_PRODUCER_VERSION));
    let correlation_ok = core
        .correlation
        .iter()
        .flatten()
        .all(|c| within(c.id.len(), MAX_IDENTIFIER));
    let subjects_ok = core.evidence.iter().flatten().all(|e| match &e.subject {
        EvidenceSubject::StableId(id) => within(id.len(), MAX_IDENTIFIER),
        EvidenceSubject::Digest(_) => true,
    });
    reject_if(
        !(producer_ok && correlation_ok && subjects_ok),
        Reason::LimitExceeded(Limit::String),
    )
}

fn strictly_ascending<T>(items: &[T], cmp: impl Fn(&T, &T) -> Ordering) -> bool {
    items
        .windows(2)
        .all(|w| matches!(w, [a, b] if cmp(a, b) == Ordering::Less))
}

// P-72 P-69 P-77
fn set_order(core: &RecordCore) -> Result<(), Reason> {
    reject_if(
        !strictly_ascending(core.basis.as_deref().unwrap_or_default(), Ord::cmp),
        Reason::NonCanonicalSetOrder(SetField::Basis),
    )?;
    reject_if(
        !strictly_ascending(&core.concerns, Ord::cmp),
        Reason::NonCanonicalSetOrder(SetField::Concerns),
    )?;
    reject_if(
        !strictly_ascending(
            core.critical.as_deref().unwrap_or_default(),
            TypeUri::canonical_cmp,
        ),
        Reason::NonCanonicalSetOrder(SetField::Critical),
    )?;
    reject_if(
        visibilities(core).any(|v| !strictly_ascending(parties(v), Ord::cmp)),
        Reason::NonCanonicalSetOrder(SetField::Visibility),
    )
}

fn map_keys_canonical<'a>(keys: impl Iterator<Item = &'a str>) -> Result<(), Reason> {
    let mut previous: Option<&str> = None;
    for key in keys {
        if let Some(p) = previous {
            match canonical_text_cmp(p, key) {
                Ordering::Less => {}
                Ordering::Equal => {
                    return Err(Reason::NonCanonicalCbor(NonCanonicalCbor::DuplicateMapKey));
                }
                Ordering::Greater => {
                    return Err(Reason::NonCanonicalCbor(NonCanonicalCbor::UnsortedMapKeys));
                }
            }
        }
        previous = Some(key);
    }
    Ok(())
}

// P-5 P-69 P-80
fn map_order(core: &RecordCore) -> Result<(), Reason> {
    map_keys_canonical(core.ext.iter().flatten().map(|e| e.key.as_str()))?;
    map_keys_canonical(core.params.iter().flatten().map(|p| p.name.as_str()))?;
    map_keys_canonical(
        core.versions
            .practices
            .iter()
            .flatten()
            .map(|p| p.namespace.as_str()),
    )
}

fn has_repeat_key<'a, T, K: Ord>(items: &'a [T], key: impl Fn(&'a T) -> K) -> bool {
    let mut keys: Vec<K> = items.iter().map(key).collect();
    keys.sort_unstable();
    keys.windows(2).any(|w| matches!(w, [a, b] if a == b))
}

fn has_repeat<'a, T: PartialEq, K: Ord>(items: &'a [T], key: impl Fn(&'a T) -> K) -> bool {
    let mut sorted: Vec<(K, &'a T)> = items.iter().map(|item| (key(item), item)).collect();
    sorted.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    sorted.chunk_by(|a, b| a.0 == b.0).any(|run| {
        run.iter()
            .enumerate()
            .any(|(i, a)| run.iter().skip(i.saturating_add(1)).any(|b| a.1 == b.1))
    })
}

fn relation_key(relation: &Relation) -> (RelationName, &[u8]) {
    let target: &[u8] = match relation {
        Relation::EngagedIn { target, .. }
        | Relation::Concerns { target, .. }
        | Relation::PartOf { target, .. } => target.as_bytes(),
        Relation::Serves { target, .. } | Relation::Supersedes { target, .. } => {
            target.0.as_bytes()
        }
        Relation::DerivedFrom { target, .. } => match target {
            DerivedTarget::Record(r) => r.0.as_bytes(),
            DerivedTarget::Evidence(d) => d.as_bytes(),
            DerivedTarget::External(e) => e.as_str().as_bytes(),
        },
        Relation::OnBehalfOf { target, .. } => target.as_str().as_bytes(),
        Relation::References { target, .. } => match target {
            ReferenceTarget::Record(r) => r.0.as_bytes(),
            ReferenceTarget::External(e) => e.as_str().as_bytes(),
        },
    };
    (relation.name(), target)
}

// P-72 P-78 P-77
fn duplicates(core: &RecordCore) -> Result<(), Reason> {
    let chain = core.on_behalf_of.as_deref().unwrap_or_default();
    let checks = [
        (
            has_repeat(core.relations.as_deref().unwrap_or_default(), relation_key),
            ListField::Relations,
        ),
        (
            has_repeat(core.evidence.as_deref().unwrap_or_default(), |e| {
                e.signature
            }),
            ListField::Evidence,
        ),
        (
            has_repeat_key(core.correlation.as_deref().unwrap_or_default(), |c| {
                (c.scheme.as_str(), c.id.as_str())
            }),
            ListField::Correlation,
        ),
        (
            has_repeat_key(core.body.as_deref().unwrap_or_default(), |b| &b.part),
            ListField::Body,
        ),
        (has_repeat_key(chain, |p| p), ListField::OnBehalfOf),
    ];
    for (repeated, field) in checks {
        reject_if(repeated, Reason::DuplicateEntry(field))?;
    }
    Ok(())
}

// P-77
fn visibility_scope(core: &RecordCore) -> Result<(), Reason> {
    reject_if(
        core.concerns.is_empty() && visibilities(core).any(|v| v.see == Audience::Work),
        Reason::VisibilityNoWork,
    )?;
    let chain = core.on_behalf_of.as_deref().unwrap_or_default();
    reject_if(
        visibilities(core).any(|v| {
            parties(v)
                .iter()
                .any(|p| p == &core.author || chain.contains(p))
        }),
        Reason::DuplicateEntry(ListField::Visibility),
    )
}

// INV-4 P-24 P-80
fn retroactive(record: &Record, recorded_at: Option<Time>) -> Result<(), Reason> {
    reject_if(
        matches!((record.effective_at(), recorded_at), (Some(e), Some(r)) if e < r),
        Reason::RetroactiveDeclaration,
    )
}

// P-69
fn critical_present(core: &RecordCore) -> Result<(), Reason> {
    let ext = core.ext.as_deref().unwrap_or_default();
    let dangling = core
        .critical
        .iter()
        .flatten()
        .any(|k| !ext.iter().any(|e| &e.key == k));
    reject_if(dangling, Reason::ExtensionCriticalDangling)
}

// P-13 E-13
fn capacity(core: &RecordCore) -> Result<(), Reason> {
    let consistent = match (core.on_behalf_of.as_deref(), &core.capacity) {
        (Some(chain), Some(Capacity::For(principal))) => chain.first() == Some(principal),
        (Some(_), _) | (None, Some(Capacity::For(_))) => false,
        (None, _) => true,
    };
    reject_if(!consistent, Reason::CapacityMismatch)
}

// INV-18 P-12
fn actor_rings(core: &RecordCore, actor_types: &ActorTypes) -> Result<(), Reason> {
    let rings = core.on_behalf_of.as_ref().map_or(0, Vec::len);
    reject_if(
        actor_types.on_behalf_of.len() != rings,
        Reason::EnvelopeMismatch(EnvelopeField::ActorType),
    )
}

// P-13 P-83 C-32 INV-23
fn authority(record: &Record) -> Result<(), Reason> {
    reject_if(
        consequence(record) == Consequence::Consequential && record.core().authority.is_none(),
        Reason::AuthorityMissing,
    )
}

// P-13 P-83
fn capacity_present(record: &Record) -> Result<(), Reason> {
    reject_if(
        consequence(record) == Consequence::Consequential && record.core().capacity.is_none(),
        Reason::CapacityMissing,
    )
}

// P-15
fn producer(core: &RecordCore, actor_types: &ActorTypes) -> Result<(), Reason> {
    reject_if(
        actor_types.author.actor_type == ActorType::Agent && core.producer.is_none(),
        Reason::ProducerMissing,
    )
}

fn pinned(uri: &TypeUri, practices: &[PracticePin]) -> bool {
    practices.iter().any(|p| uri.is_under(&p.namespace))
}

// C-5 C-27 PR-3 PR-5 P-71 P-82
fn mapped(record: &Record) -> Result<(), Reason> {
    let core = record.core();
    let practices = core.versions.practices.as_deref().unwrap_or_default();
    let extension_ok = |uri: &TypeUri| !uri.is_core() && pinned(uri, practices);
    let subtype_ok = match record {
        Record::Claim(c) => match &c.subtype {
            ClaimType::Core(_) => true,
            ClaimType::Extension(uri) => {
                ClaimSubtype::from_uri(uri.as_str()).is_some() || extension_ok(uri)
            }
        },
        Record::Declaration(d) => {
            DeclarationSubtype::from_uri(d.subtype.as_str()).is_some() || extension_ok(&d.subtype)
        }
        Record::Act(a) => {
            ActSubtype::from_uri(a.subtype.as_str()).is_some() || extension_ok(&a.subtype)
        }
    };
    let evidence_ok = core
        .evidence
        .iter()
        .flatten()
        .all(|e| match &e.evidence_type {
            EvidenceType::Core(_) => true,
            EvidenceType::Extension(uri) => {
                CoreEvidenceType::from_uri(uri.as_str()).is_some() || extension_ok(uri)
            }
        });
    let roles_ok = core.relations.iter().flatten().all(|r| match r {
        Relation::DerivedFrom {
            role: DerivedRole::Extension(uri),
            ..
        } => extension_ok(uri),
        other => other.qualifier().is_none_or(extension_ok),
    });
    reject_if(
        !(subtype_ok && evidence_ok && roles_ok),
        Reason::UnmappedExtensionValue,
    )
}

// INV-20 T-66 T-68 P-81
fn attribution(record: &Record, ctx: &ValidationContext<'_>) -> Result<(), Reason> {
    let author = ctx.actor_types.author;
    let attributed = author.actor_type == ActorType::System
        && author.source == ActorTypeSource::AccessBinding
        && !record.basis().is_empty();
    reject_if(
        ctx.origin == Origin::Automation && !attributed,
        Reason::UnattributedAutomation,
    )
}

// P-19 P-69
fn quarantine(core: &RecordCore, understood: &[ExtKey]) -> Option<QuarantineReason> {
    core.critical
        .iter()
        .flatten()
        .any(|k| !understood.contains(k))
        .then_some(QuarantineReason::ExtensionCriticalUnknown)
}

/// Extension fields this verifier does not understand; they are preserved and not interpreted (P-19).
pub fn uninterpreted_extensions<'r>(
    record: &'r Record,
    understood: &'r [ExtKey],
) -> impl Iterator<Item = &'r crate::record::Extension> {
    record
        .core()
        .ext
        .iter()
        .flatten()
        .filter(move |e| !understood.contains(&e.key))
}
