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
    EnvelopeField, Limit, ListField, NonCanonicalCbor, Reason, Schema, SetField, wire_enum,
};
use crate::record::{
    Audience, Capacity, ClaimType, EvidenceType, ParamScalar, ParamValue, PracticePin, Record,
    RecordCore, Visibility,
};
use crate::relation::{DerivedRole, Relation};
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
    /// The record is written but held for attention (P-19, SEC-18).
    Quarantined(Reason),
    /// The record is not admitted, with a reason (P-11).
    Rejected(Reason),
}

/// Applies the record rules in a fixed order; the first failing rule decides.
#[must_use]
pub fn validate(record: &Record, ctx: &ValidationContext<'_>) -> Outcome {
    match check(record, ctx) {
        Err(reason) => Outcome::Rejected(reason),
        Ok(()) => quarantine(record.core(), ctx.understood_extensions)
            .map_or(Outcome::Accepted, Outcome::Quarantined),
    }
}

fn check(record: &Record, ctx: &ValidationContext<'_>) -> Result<(), Reason> {
    let core = record.core();
    schema(record)?;
    limits(record, ctx.limits)?;
    set_order(core)?;
    map_order(core)?;
    duplicates(core)?;
    visibility_scope(core)?;
    critical_present(core)?;
    capacity(core)?;
    actor_rings(core, ctx.actor_types)?;
    authority(record)?;
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

fn condition_type_ok(value: &ParamValue, practices: &[PracticePin]) -> bool {
    catalog_text(value, |t| {
        ConditionType::from_uri(t).map(|_| ()).or_else(|| {
            TypeUri::parse(t)
                .filter(|u| !u.is_core() && pinned(u, practices))
                .map(|_| ())
        })
    })
}

fn core_param_ok(
    subtype: DeclarationSubtype,
    name: &str,
    value: &ParamValue,
    practices: &[PracticePin],
) -> bool {
    match (subtype, name) {
        (DeclarationSubtype::Decline, "reason") => {
            catalog_text(value, DeclineReason::from_wire_name)
        }
        (DeclarationSubtype::Cancel, "reason") => catalog_text(value, CancelReason::from_wire_name),
        (DeclarationSubtype::Notice, "notice_type") => {
            catalog_text(value, NoticeType::from_wire_name)
        }
        (DeclarationSubtype::StopRequest, "stop_type") => {
            catalog_text(value, StopType::from_wire_name)
        }
        (DeclarationSubtype::StopResponse, "response") => {
            catalog_text(value, StopAnswer::from_wire_name)
        }
        (DeclarationSubtype::OpenCondition, "condition_type") => {
            condition_type_ok(value, practices)
        }
        (DeclarationSubtype::OpenCondition, "wait_reason") => {
            catalog_text(value, WaitReason::from_wire_name)
        }
        (DeclarationSubtype::OpenCondition, "gate_form") => {
            catalog_text(value, GateForm::from_wire_name)
        }
        _ => false,
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
        let shape_ok = match value {
            ParamValue::Scalar(_) => true,
            ParamValue::List(items) => !items.is_empty() && items.len() <= MAX_PARAM_ITEMS,
        };
        let ok = shape_ok
            && if name == EFFECTIVE_AT {
                matches!(record, Record::Declaration(_))
                    && matches!(value, ParamValue::Scalar(ParamScalar::Uint(_)))
            } else if let Some(d) = declaration {
                core_param_ok(d, name, value, practices)
            } else {
                !core_subtype
            };
        reject_if(!ok, Reason::Schema(Schema::Params))?;
    }
    Ok(())
}

const EFFECTIVE_AT: &str = "effective_at";
const MAX_PARAM_ITEMS: usize = 256;

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

fn strictly_ascending<T>(items: &[T], cmp: impl Fn(&T, &T) -> Ordering) -> bool {
    items
        .windows(2)
        .all(|w| matches!(w, [a, b] if cmp(a, b) == Ordering::Less))
}

fn party_cmp(a: &PartyRef, b: &PartyRef) -> Ordering {
    canonical_text_cmp(a.as_str(), b.as_str())
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
        visibilities(core).any(|v| !strictly_ascending(parties(v), party_cmp)),
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

fn has_repeat<T>(items: &[T], same: impl Fn(&T, &T) -> bool) -> bool {
    items
        .iter()
        .enumerate()
        .any(|(i, a)| items.iter().skip(i.saturating_add(1)).any(|b| same(a, b)))
}

// P-78 P-77
fn duplicates(core: &RecordCore) -> Result<(), Reason> {
    let chain = core.on_behalf_of.as_deref().unwrap_or_default();
    let checks = [
        (
            has_repeat(core.relations.as_deref().unwrap_or_default(), PartialEq::eq),
            ListField::Relations,
        ),
        (
            has_repeat(core.evidence.as_deref().unwrap_or_default(), PartialEq::eq),
            ListField::Evidence,
        ),
        (
            has_repeat(
                core.correlation.as_deref().unwrap_or_default(),
                PartialEq::eq,
            ),
            ListField::Correlation,
        ),
        (
            has_repeat(core.body.as_deref().unwrap_or_default(), |a, b| {
                a.part == b.part
            }),
            ListField::Body,
        ),
        (has_repeat(chain, PartialEq::eq), ListField::OnBehalfOf),
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

// C-5 PR-3 PR-5 P-71 P-82
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
        _ => true,
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
fn quarantine(core: &RecordCore, understood: &[ExtKey]) -> Option<Reason> {
    core.critical
        .iter()
        .flatten()
        .any(|k| !understood.contains(k))
        .then_some(Reason::ExtensionCriticalUnknown)
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
