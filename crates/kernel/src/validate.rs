//! Record rules as a pure function over a decoded record and explicit context: origin (T-66), actor types from Access (P-12), understood extensions (P-19) and narrowed limits (T-65); the result is a decision, never an error.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::catalog::{
    ActSubtype, AggregationRule, AimDuration, AmendmentChange, CancelReason, ChangePolicy,
    ClaimSubtype, CommitmentKind, ConditionType, Consequence, CoreDerivedRole, CoreEvidenceType,
    DeclarationSubtype, DeclineReason, DeferReason, DisputeReason, GateForm, HandoverReason,
    NoticeType, ProposalStep, RedactReason, RefuseReason, RejectReason, RevokeReason, StopAnswer,
    StopType, WaitReason, consequence,
};
use crate::id::{PartyRef, Time, canonical_text_cmp};
use crate::limits::SemanticLimits;
use crate::reason::{
    EnvelopeField, Limit, ListField, NonCanonicalCbor, QuarantineReason, Reason, Schema, SetField,
    wire_enum,
};
use crate::record::{
    Audience, Capacity, ClaimType, EvidenceSubject, EvidenceType, ParamScalar, ParamValue,
    PartName, PracticePin, Record, RecordCore, Visibility,
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

/// Actor types of the author, of every `on_behalf_of` ring and of every evidence presenter, as the ledger writes them into the envelope (P-12, INV-18, EV-35).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorTypes {
    /// The author's actor type.
    pub author: ActorTypeEntry,
    /// One entry per `on_behalf_of` ring, in chain order.
    pub on_behalf_of: Vec<ActorTypeEntry>,
    /// One entry per evidence reference's presenter, in `evidence` order (EV-35).
    pub evidence: Vec<ActorTypeEntry>,
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
        Some(RuleSet::V1_0) => outcome_v1_0(record, ctx),
        #[cfg(test)]
        Some(RuleSet::TestV1_1) => outcome_v1_0(record, ctx),
    }
}

fn outcome_v1_0(record: &Record, ctx: &ValidationContext<'_>) -> Outcome {
    match check_v1_0(record, ctx) {
        Err(reason) => Outcome::Rejected(reason),
        Ok(()) => quarantine(record.core(), ctx.understood_extensions)
            .map_or(Outcome::Accepted, Outcome::Quarantined),
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
    attributed(record)?;
    authority(record)?;
    capacity_present(record)?;
    producer(core, ctx.actor_types)?;
    mapped(record)?;
    continuity(core)?;
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
    RedactParts,
    RedactReason,
    Party,
    RecordRef,
    RecordSet,
    AimDuration,
    Items,
    ItemCount,
    Time,
    Flag,
    Bool,
    Count,
    Percent,
    PartyList,
    CommitmentKind,
    RejectReason,
    RefuseReason,
    RevokeReason,
    DisputeReason,
    DeferReason,
    HandoverReason,
    ChangePolicy,
    AggregationRule,
    ProposalStep,
    AmendmentChange,
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

// P-111 P-92
const REDACT: &[ParamKey] = &[
    key("parts", ParamKind::RedactParts, true),
    key("reason", ParamKind::RedactReason, true),
    key("target", ParamKind::RecordRef, true),
];

// C-11 CM-4 CM-6 CM-7 CM-8 CM-9 CM-24 CM-27 CM-39 CM-54 CM-57 CM-60 C-44
const REQUEST: &[ParamKey] = &[
    key("acceptor", ParamKind::Party, true),
    key("aggregation", ParamKind::AggregationRule, false),
    key("aggregation_k", ParamKind::Count, false),
    key("aggregation_percent", ParamKind::Percent, false),
    key("aggregation_veto", ParamKind::Flag, false),
    key("aim", ParamKind::RecordRef, false),
    key("change_policy", ParamKind::ChangePolicy, false),
    key("commitment_kind", ParamKind::CommitmentKind, false),
    key("conditions", ParamKind::RecordSet, false),
    key("due", ParamKind::Time, false),
    key("evidence_required", ParamKind::Flag, false),
    key("four_eyes_waived", ParamKind::Flag, false),
    key("high_impact", ParamKind::Flag, false),
    key("item_count", ParamKind::ItemCount, false),
    key("obligor", ParamKind::Party, false),
    key("participants", ParamKind::PartyList, false),
    key("queue", ParamKind::RecordRef, false),
    key("respond_by", ParamKind::Time, false),
];

const ITEMS: ParamKey = key("items", ParamKind::Items, false);

// CM-17 CM-22 CM-23 CM-56
const PROMISE: &[ParamKey] = &[key("amendment", ParamKind::RecordRef, false), ITEMS];
const PROMISE_CONDITIONAL: &[ParamKey] = &[
    ITEMS,
    key("precondition", ParamKind::RecordRef, true),
    key("valid_until", ParamKind::Time, true),
];
const DECLINE_ITEMS: &[ParamKey] = &[ITEMS, key("reason", ParamKind::DeclineReason, true)];

// CM-21 CM-56
const COUNTER: &[ParamKey] = &[
    key("acceptor", ParamKind::Party, false),
    key("amendment", ParamKind::RecordRef, false),
    key("conditions", ParamKind::RecordSet, false),
    key("due", ParamKind::Time, false),
    key("evidence_required", ParamKind::Bool, false),
    key("high_impact", ParamKind::Bool, false),
    key("item_count", ParamKind::ItemCount, false),
    key("respond_by", ParamKind::Time, false),
];
const ACCEPT_COUNTER: &[ParamKey] = &[key("counter", ParamKind::RecordRef, true)];

// CM-23 CM-25 CM-26 CM-40 CM-41 CM-61
const STATE: &[ParamKey] = &[ITEMS];
const ACCEPT: &[ParamKey] = &[
    key("criterion_undefined", ParamKind::Flag, false),
    key("implicit", ParamKind::Flag, false),
    ITEMS,
    key("statement", ParamKind::RecordRef, true),
];
const REJECT: &[ParamKey] = &[
    ITEMS,
    key("reason", ParamKind::RejectReason, true),
    key("statement", ParamKind::RecordRef, true),
];

// CM-43 CM-44 CM-45
const DELEGATE: &[ParamKey] = &[
    key("context", ParamKind::RecordSet, false),
    key("handover_reason", ParamKind::HandoverReason, false),
    key("obligor", ParamKind::Party, false),
    key("proposal", ParamKind::RecordRef, false),
    key("stateful", ParamKind::Bool, false),
    key("step", ParamKind::ProposalStep, true),
];
const ASSIGN: &[ParamKey] = &[
    key("obligee", ParamKind::Party, false),
    key("proposal", ParamKind::RecordRef, false),
    key("step", ParamKind::ProposalStep, true),
];
const HANDOFF_NOTE: &[ParamKey] = &[
    key("context", ParamKind::RecordSet, false),
    key("handover_reason", ParamKind::HandoverReason, true),
    key("stateful", ParamKind::Bool, true),
];

// CM-17 CM-35 CM-36 CM-61
const DISPUTE: &[ParamKey] = &[
    key("disputed", ParamKind::RecordRef, true),
    key("reason", ParamKind::DisputeReason, true),
];
const DEFER: &[ParamKey] = &[
    key("reason", ParamKind::DeferReason, true),
    key("resume_at", ParamKind::Time, false),
    key("resume_on", ParamKind::RecordRef, false),
];
const RESUME: &[ParamKey] = &[key("deferral", ParamKind::RecordRef, true)];
const REVOKE: &[ParamKey] = &[key("reason", ParamKind::RevokeReason, true)];
const ALLOW: &[ParamKey] = &[key("revocation", ParamKind::RecordRef, true)];
const REFUSE: &[ParamKey] = &[
    key("amendment", ParamKind::RecordRef, false),
    key("reason", ParamKind::RefuseReason, true),
    key("revocation", ParamKind::RecordRef, false),
];

// CM-39 CM-56 CM-57 CM-60
const AMEND: &[ParamKey] = &[
    key("acceptor", ParamKind::Party, false),
    key("change", ParamKind::AmendmentChange, false),
    key("change_policy", ParamKind::ChangePolicy, false),
    key("conditions", ParamKind::RecordSet, false),
    key("due", ParamKind::Time, false),
    key("evidence_required", ParamKind::Bool, false),
    key("four_eyes_waived", ParamKind::Bool, false),
    key("high_impact", ParamKind::Bool, false),
    key("item_count", ParamKind::ItemCount, false),
];

// CM-32 CM-41
const DECLARE_OBSOLETE: &[ParamKey] = &[key("parent", ParamKind::RecordRef, true)];
const IMPLICIT_TERMS: &[ParamKey] = &[
    ITEMS,
    key("window", ParamKind::Count, false),
    key("withdrawn", ParamKind::Flag, false),
];

// C-10 C-44
const AIM: &[ParamKey] = &[
    key("criterion", ParamKind::Criterion, false),
    key("duration", ParamKind::AimDuration, true),
    key("judge", ParamKind::Party, false),
];

/// The `params` keys of a core Declaration that name a Party in an attributed slot (C-44).
const fn attributed_keys(subtype: DeclarationSubtype) -> &'static [&'static str] {
    match subtype {
        DeclarationSubtype::Request => &["acceptor", "obligor", "participants"],
        DeclarationSubtype::Aim => &["judge"],
        DeclarationSubtype::Delegate => &["obligor"],
        DeclarationSubtype::Assign => &["obligee"],
        DeclarationSubtype::Counter | DeclarationSubtype::Amend => &["acceptor"],
        _ => &[],
    }
}

const fn param_keys(subtype: DeclarationSubtype) -> &'static [ParamKey] {
    match subtype {
        DeclarationSubtype::Request => REQUEST,
        DeclarationSubtype::Aim => AIM,
        DeclarationSubtype::Decline => DECLINE_ITEMS,
        DeclarationSubtype::Promise => PROMISE,
        DeclarationSubtype::PromiseConditional => PROMISE_CONDITIONAL,
        DeclarationSubtype::Counter => COUNTER,
        DeclarationSubtype::AcceptCounter => ACCEPT_COUNTER,
        DeclarationSubtype::State => STATE,
        DeclarationSubtype::Accept => ACCEPT,
        DeclarationSubtype::Reject => REJECT,
        DeclarationSubtype::Delegate => DELEGATE,
        DeclarationSubtype::Assign => ASSIGN,
        DeclarationSubtype::HandoffNote => HANDOFF_NOTE,
        DeclarationSubtype::Dispute => DISPUTE,
        DeclarationSubtype::Defer => DEFER,
        DeclarationSubtype::Resume => RESUME,
        DeclarationSubtype::RevokeRequest
        | DeclarationSubtype::RevokePromise
        | DeclarationSubtype::RevokeStatement
        | DeclarationSubtype::RevokeAcceptance => REVOKE,
        DeclarationSubtype::Allow => ALLOW,
        DeclarationSubtype::Refuse => REFUSE,
        DeclarationSubtype::Amend => AMEND,
        DeclarationSubtype::DeclareObsolete => DECLARE_OBSOLETE,
        DeclarationSubtype::ImplicitAcceptanceTerms => IMPLICIT_TERMS,
        DeclarationSubtype::Cancel => CANCEL,
        DeclarationSubtype::Notice => NOTICE,
        DeclarationSubtype::StopRequest => STOP_REQUEST,
        DeclarationSubtype::StopResponse => STOP_RESPONSE,
        DeclarationSubtype::OpenCondition => OPEN_CONDITION,
        DeclarationSubtype::Redact => REDACT,
        _ => &[],
    }
}

/// Whether the subtype's closed `params` map takes the optional `effective_at`; `redact`'s does not (P-80 item 4, P-111 item 2).
fn takes_effective_at(subtype: Option<DeclarationSubtype>) -> bool {
    subtype != Some(DeclarationSubtype::Redact)
}

// P-111 P-68 P-72
fn part_names_ok(value: &ParamValue) -> bool {
    let ParamValue::List(items) = value else {
        return false;
    };
    let named = items
        .iter()
        .all(|s| matches!(s, ParamScalar::Text(t) if PartName::parse(t).is_some()));
    named && strictly_ascending(items, text_scalar_cmp)
}

fn text_scalar_cmp(a: &ParamScalar, b: &ParamScalar) -> Ordering {
    match (a, b) {
        (ParamScalar::Text(a), ParamScalar::Text(b)) => canonical_text_cmp(a, b),
        _ => Ordering::Equal,
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
        ParamKind::RedactParts => part_names_ok(value),
        ParamKind::RedactReason => catalog_text(value, RedactReason::from_wire_name),
        ParamKind::Party => catalog_text(value, PartyRef::new),
        ParamKind::RecordRef => matches!(value, ParamValue::Scalar(ParamScalar::Digest(_))),
        ParamKind::RecordSet => record_set_ok(value),
        ParamKind::AimDuration => catalog_text(value, AimDuration::from_wire_name),
        ParamKind::Items => items_ok(value),
        ParamKind::ItemCount => uint_in(value, 1, MAX_ITEMS_U64),
        ParamKind::Time => uint_in(value, 0, u64::MAX),
        ParamKind::Flag => matches!(value, ParamValue::Scalar(ParamScalar::Bool(true))),
        ParamKind::Bool => matches!(value, ParamValue::Scalar(ParamScalar::Bool(_))),
        ParamKind::Count => uint_in(value, 1, u64::MAX),
        ParamKind::Percent => uint_in(value, 1, 100),
        ParamKind::PartyList => party_list_ok(value),
        ParamKind::CommitmentKind => catalog_text(value, CommitmentKind::from_wire_name),
        ParamKind::RejectReason => reason_code(value, RejectReason::from_wire_name),
        ParamKind::RefuseReason => reason_code(value, RefuseReason::from_wire_name),
        ParamKind::RevokeReason => reason_code(value, RevokeReason::from_wire_name),
        ParamKind::DisputeReason => reason_code(value, DisputeReason::from_wire_name),
        ParamKind::DeferReason => reason_code(value, DeferReason::from_wire_name),
        ParamKind::HandoverReason => reason_code(value, HandoverReason::from_wire_name),
        ParamKind::ChangePolicy => catalog_text(value, ChangePolicy::from_wire_name),
        ParamKind::AggregationRule => catalog_text(value, AggregationRule::from_wire_name),
        ParamKind::ProposalStep => catalog_text(value, ProposalStep::from_wire_name),
        ParamKind::AmendmentChange => catalog_text(value, AmendmentChange::from_wire_name),
    }
}

fn uint_in(value: &ParamValue, min: u64, max: u64) -> bool {
    matches!(value, ParamValue::Scalar(ParamScalar::Uint(n)) if (min..=max).contains(n))
}

// CM-23 P-72
fn items_ok(value: &ParamValue) -> bool {
    let ParamValue::List(items) = value else {
        return false;
    };
    let numbers: Option<Vec<u64>> = items
        .iter()
        .map(|s| match s {
            ParamScalar::Uint(n) if *n < MAX_ITEMS_U64 => Some(*n),
            _ => None,
        })
        .collect();
    numbers.is_some_and(|n| strictly_ascending(&n, Ord::cmp))
}

// CM-55 P-78
fn party_list_ok(value: &ParamValue) -> bool {
    let ParamValue::List(items) = value else {
        return false;
    };
    let parties: Option<Vec<PartyRef>> = items
        .iter()
        .map(|s| match s {
            ParamScalar::Text(t) => PartyRef::new(t),
            _ => None,
        })
        .collect();
    parties.is_some_and(|p| !has_repeat_key(&p, |x| x))
}

// C-11 P-72
fn record_set_ok(value: &ParamValue) -> bool {
    let ParamValue::List(items) = value else {
        return false;
    };
    let digests: Option<Vec<_>> = items
        .iter()
        .map(|s| match s {
            ParamScalar::Digest(d) => Some(*d),
            _ => None,
        })
        .collect();
    digests.is_some_and(|d| strictly_ascending(&d, Ord::cmp))
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

// P-80 P-85 P-111
fn params(record: &Record) -> Result<(), Reason> {
    let core = record.core();
    let practices = core.versions.practices.as_deref().unwrap_or_default();
    let subtype = record.subtype_uri();
    let core_subtype = subtype.is_none_or(TypeUri::is_core);
    let declaration = match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str()),
        Record::Act(_) | Record::Claim(_) => None,
    };
    reject_if(
        declaration == Some(DeclarationSubtype::Redact) && record.supersedes().next().is_some(),
        Reason::Schema(Schema::Relation),
    )?;
    for param in core.params.iter().flatten() {
        let name = param.name.as_str();
        let value = &param.value;
        let shape_ok = !scalars(value).is_empty() && scalars(value).iter().all(scalar_ok);
        let ok = shape_ok
            && if name == EFFECTIVE_AT {
                matches!(record, Record::Declaration(_))
                    && takes_effective_at(declaration)
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
        let two_sided = d != DeclarationSubtype::Request
            || record.param("obligor").is_some() != record.param("queue").is_some();
        reject_if(
            !(complete && gate_ok && two_sided),
            Reason::Schema(Schema::Params),
        )?;
        commitment_shape(record, d)?;
    }
    Ok(())
}

fn present(record: &Record, names: &[&str]) -> usize {
    names.iter().filter(|n| record.param(n).is_some()).count()
}

fn has_part(record: &Record, name: &str) -> bool {
    record
        .core()
        .body
        .iter()
        .flatten()
        .any(|b| b.part.as_str() == name)
}

/// The free-text parts of a handover note, one body part each (CM-45).
const HANDOVER_PARTS: &[&str] = &["summary", "done", "changed", "open_questions", "next_steps"];

/// The term keys a counter-offer or a terms amendment changes (CM-21, CM-56).
const TERM_KEYS: &[&str] = &[
    "acceptor",
    "conditions",
    "due",
    "evidence_required",
    "high_impact",
    "item_count",
    "respond_by",
];

// CM-54 CM-55
fn aggregation_ok(record: &Record) -> bool {
    let rule = text_param(record, "aggregation").and_then(AggregationRule::from_wire_name);
    let participants = match record.param("participants") {
        Some(ParamValue::List(p)) => Some(p.len()),
        _ => None,
    };
    let k = match record.param("aggregation_k") {
        Some(ParamValue::Scalar(ParamScalar::Uint(n))) => Some(*n),
        _ => None,
    };
    let percent = record.param("aggregation_percent").is_some();
    let veto = record.param("aggregation_veto").is_some();
    match (rule, participants) {
        (None, None) => k.is_none() && !percent && !veto,
        (Some(AggregationRule::KOfN), Some(n)) => {
            !percent && k.is_some_and(|k| usize::try_from(k).is_ok_and(|k| k <= n))
        }
        (Some(AggregationRule::Percentage), Some(_)) => percent && k.is_none(),
        (Some(_), Some(_)) => k.is_none() && !percent,
        _ => false,
    }
}

// CM-25 C-29
fn fulfils(record: &Record) -> bool {
    record.core().relations.iter().flatten().any(|r| {
        matches!(
            r,
            Relation::DerivedFrom {
                source: Some(_),
                target: DerivedTarget::Record(_),
                role: DerivedRole::Core(CoreDerivedRole::Fulfills),
            }
        )
    })
}

fn step_param(record: &Record) -> Option<ProposalStep> {
    text_param(record, "step").and_then(ProposalStep::from_wire_name)
}

/// The cross-key rules of the commitment subtypes' `params` (P-80, P-92, CM-17).
fn commitment_params_ok(record: &Record, subtype: DeclarationSubtype) -> bool {
    match subtype {
        DeclarationSubtype::Request => aggregation_ok(record),
        DeclarationSubtype::Counter => {
            present(record, TERM_KEYS) > 0 || record.core().body.is_some()
        }
        DeclarationSubtype::Delegate => match step_param(record) {
            Some(ProposalStep::Proposal) => {
                present(record, &["obligor", "handover_reason", "stateful"]) == 3
                    && record.param("proposal").is_none()
            }
            Some(ProposalStep::Acceptance) => {
                record.param("proposal").is_some()
                    && present(
                        record,
                        &["obligor", "handover_reason", "stateful", "context"],
                    ) == 0
            }
            None => false,
        },
        DeclarationSubtype::Assign => match step_param(record) {
            Some(ProposalStep::Proposal) => {
                record.param("obligee").is_some() && record.param("proposal").is_none()
            }
            Some(ProposalStep::Acceptance) => {
                record.param("proposal").is_some() && record.param("obligee").is_none()
            }
            None => false,
        },
        DeclarationSubtype::Defer => present(record, &["resume_at", "resume_on"]) <= 1,
        DeclarationSubtype::Refuse => present(record, &["revocation", "amendment"]) == 1,
        DeclarationSubtype::Amend => {
            if record.param("change").is_some() {
                present(record, &["change_policy", "four_eyes_waived"]) == 0
                    && present(record, TERM_KEYS) > 0
            } else {
                let terms = [
                    "acceptor",
                    "conditions",
                    "due",
                    "evidence_required",
                    "item_count",
                ];
                present(record, &terms) == 0
                    && !matches!(
                        record.param("high_impact"),
                        Some(ParamValue::Scalar(ParamScalar::Bool(false)))
                    )
            }
        }
        DeclarationSubtype::ImplicitAcceptanceTerms => {
            present(record, &["window", "withdrawn"]) == 1
                && (record.param("items").is_none() || record.param("window").is_some())
        }
        _ => true,
    }
}

/// The body parts and relations a commitment subtype requires (CM-17, CM-25, CM-33, CM-45, CM-61): the handover note's free-text parts, a `note` beside a bare `other` reason, the justification of an administrative close, the fulfilment of a `state`, and the validity basis of an `expire`.
fn commitment_shape(record: &Record, subtype: DeclarationSubtype) -> Result<(), Reason> {
    reject_if(
        !commitment_params_ok(record, subtype),
        Reason::Schema(Schema::Params),
    )?;
    let handover = subtype == DeclarationSubtype::HandoffNote
        || (subtype == DeclarationSubtype::Delegate
            && step_param(record) == Some(ProposalStep::Proposal));
    let other = ["reason", "handover_reason"]
        .iter()
        .any(|k| text_param(record, k) == Some("other"));
    let parts_missing = (handover && !HANDOVER_PARTS.iter().all(|p| has_part(record, p)))
        || ((other || subtype == DeclarationSubtype::AdministrativeClose)
            && !has_part(record, "note"));
    reject_if(
        parts_missing || (subtype == DeclarationSubtype::Expire && record.basis().is_empty()),
        Reason::Schema(Schema::RequiredField),
    )?;
    reject_if(
        subtype == DeclarationSubtype::State && !fulfils(record),
        Reason::Schema(Schema::Relation),
    )
}

const EFFECTIVE_AT: &str = "effective_at";
const DEADLINE_NONE: &str = "none";
const MAX_ITEMS: usize = 256;
const MAX_ITEMS_U64: u64 = 256;
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
            DerivedTarget::Work(w) => w.as_bytes(),
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

/// Checks that the `actor_type` annotation has one entry per `on_behalf_of` ring and one per evidence presenter (P-12, INV-18, EV-35).
///
/// # Errors
///
/// `envelope_mismatch:actor_type`.
pub(crate) fn actor_rings(core: &RecordCore, actor_types: &ActorTypes) -> Result<(), Reason> {
    let rings = core.on_behalf_of.as_ref().map_or(0, Vec::len);
    let presenters = core.evidence.as_ref().map_or(0, Vec::len);
    reject_if(
        actor_types.on_behalf_of.len() != rings || actor_types.evidence.len() != presenters,
        Reason::EnvelopeMismatch(EnvelopeField::ActorType),
    )
}

/// True when a Party slot holds a Reference: an absolute HTTPS URI names a type or an external object, never a Party (C-44, C-13, P-70).
fn names_reference(party: &str) -> bool {
    TypeUri::parse(party).is_some()
}

fn reference_scalar(scalar: &ParamScalar) -> bool {
    match scalar {
        ParamScalar::Text(t) => names_reference(t),
        ParamScalar::Digest(_) | ParamScalar::WorkId(_) => true,
        ParamScalar::Uint(_) | ParamScalar::Bool(_) => false,
    }
}

/// Checks that every attributed slot is a Party, never a Reference: the author, each `on_behalf_of` ring, the capacity principal, each evidence presenter, the Party ends of `engaged_in` and `on_behalf_of`, and the obligor, acceptor and judge of a core `request` or `aim` (C-44, C-20).
///
/// # Errors
///
/// `envelope_mismatch:actor_type`: the slot cannot carry the Access actor type the envelope annotates.
fn attributed(record: &Record) -> Result<(), Reason> {
    let core = record.core();
    let principal = match &core.capacity {
        Some(Capacity::For(p)) => Some(p),
        Some(Capacity::Own) | None => None,
    };
    let relation_parties = core.relations.iter().flatten().flat_map(|r| match r {
        Relation::EngagedIn { source, .. } => [Some(source), None],
        Relation::OnBehalfOf { source, target, .. } => [Some(source), Some(target)],
        _ => [None, None],
    });
    let field_reference = core::iter::once(&core.author)
        .chain(core.on_behalf_of.iter().flatten())
        .chain(principal)
        .chain(core.evidence.iter().flatten().map(|e| &e.presenter))
        .chain(relation_parties.flatten())
        .any(|p| names_reference(p.as_str()));
    let keys = match record {
        Record::Declaration(d) => {
            DeclarationSubtype::from_uri(d.subtype.as_str()).map_or(&[][..], attributed_keys)
        }
        Record::Act(_) | Record::Claim(_) => &[],
    };
    let param_reference = keys.iter().any(|k| {
        record
            .param(k)
            .is_some_and(|v| scalars(v).iter().any(reference_scalar))
    });
    reject_if(
        field_reference || param_reference,
        Reason::EnvelopeMismatch(EnvelopeField::ActorType),
    )
}

/// Checks the continuity of a split or merge: the record concerns the new Work and none of the earlier Works it derives from (C-43, C-8).
///
/// # Errors
///
/// `schema:relation`.
fn continuity(core: &RecordCore) -> Result<(), Reason> {
    let mut earlier = core
        .relations
        .iter()
        .flatten()
        .filter_map(|r| match r {
            Relation::DerivedFrom {
                target: DerivedTarget::Work(w),
                ..
            } => Some(w),
            _ => None,
        })
        .peekable();
    let derives = earlier.peek().is_some();
    let looped = earlier.any(|w| core.concerns.contains(w));
    reject_if(
        looped || (derives && core.concerns.is_empty()),
        Reason::Schema(Schema::Relation),
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
