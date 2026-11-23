use alloc::vec::Vec;

use super::{ParamKey, ParamKind, catalog_text, has_repeat_key, key, present, reason_code};
use crate::catalog::{DeclarationSubtype, ForwardReason};
use crate::id::PartyRef;
use crate::record::{ParamScalar, ParamValue, Record};
use crate::relation::Relation;
use crate::responsibility::{
    DistributionMethod, LeaseExpiry, PARTICIPATION_KEY, ParticipationPolicy, PrincipalGuarantee,
    Regime,
};
use crate::uri::TypeUri;

/// The value kinds of the responsibility `params` (P-80, RC-9, RC-11, RC-17, RC-21, RC-48).
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Group,
    GroupList,
    TextList,
    UriList,
    Distribution,
    LeaseExpiry,
    Regime,
    Guarantee,
    ForwardReason,
    WorkRef,
}

const fn duty(name: &'static str, kind: Kind, required: bool) -> ParamKey {
    key(name, ParamKind::Duty(kind), required)
}

// RC-10 RC-11 RC-12 RC-13 RC-14 RC-18 RC-21 RC-24
const QUEUE_DEFINITION: &[ParamKey] = &[
    duty("candidate_group", Kind::Group, false),
    key("candidates", ParamKind::PartyList, false),
    duty("distribution", Kind::Distribution, false),
    key("excluded", ParamKind::PartyList, false),
    key("lease", ParamKind::Count, false),
    duty("lease_expiry", Kind::LeaseExpiry, false),
    key("owner", ParamKind::Party, true),
    key("ping_pong_threshold", ParamKind::Count, false),
    duty("skills", Kind::UriList, false),
    key("start_within", ParamKind::Count, false),
    key("wip_limit", ParamKind::Count, false),
];

// RC-48
const ORG_RULE: &[ParamKey] = &[
    key("fallback", ParamKind::Party, true),
    key("organization", ParamKind::Party, true),
    duty("parties", Kind::TextList, false),
    duty("party_groups", Kind::GroupList, false),
    duty("regime", Kind::Regime, false),
    duty("role_groups", Kind::GroupList, false),
    duty("roles", Kind::TextList, false),
];

// RC-14 RC-17
const FORWARD: &[ParamKey] = &[
    key("candidates", ParamKind::PartyList, false),
    key("queue", ParamKind::RecordRef, false),
    duty("reason", Kind::ForwardReason, true),
];

// RC-17
const PARTY: &[ParamKey] = &[key("party", ParamKind::Party, true)];

// RC-17 RC-22 RC-23
const OFFER: &[ParamKey] = &[
    key("inputs", ParamKind::RecordSet, false),
    key("party", ParamKind::Party, true),
    key("policy", ParamKind::RecordRef, false),
];

// RC-9
const WAIVER: &[ParamKey] = &[
    key("commitment", ParamKind::RecordRef, false),
    duty("guarantee", Kind::Guarantee, true),
    key("until", ParamKind::Time, false),
    duty("work", Kind::WorkRef, false),
];

// RC-5 RC-7
const ACKNOWLEDGEMENT: &[ParamKey] = &[key("proposal", ParamKind::RecordRef, false)];

/// The closed `params` map of a responsibility subtype; `claim`, `unclaim` and `renew_lease` take only `effective_at` (P-80, RC-17).
pub(super) const fn keys(subtype: DeclarationSubtype) -> &'static [ParamKey] {
    match subtype {
        DeclarationSubtype::QueueDefinition => QUEUE_DEFINITION,
        DeclarationSubtype::OrgRule => ORG_RULE,
        DeclarationSubtype::Forward => FORWARD,
        DeclarationSubtype::Nominate | DeclarationSubtype::Reassign => PARTY,
        DeclarationSubtype::Offer => OFFER,
        DeclarationSubtype::Waiver => WAIVER,
        DeclarationSubtype::Acknowledgement => ACKNOWLEDGEMENT,
        _ => &[],
    }
}

/// The `params` keys of a responsibility subtype that name a Party in an attributed slot (C-44, RC-45).
pub(super) const fn attributed_keys(subtype: DeclarationSubtype) -> &'static [&'static str] {
    match subtype {
        DeclarationSubtype::QueueDefinition => &["candidates", "excluded", "owner"],
        DeclarationSubtype::OrgRule => &["fallback", "organization", "parties"],
        DeclarationSubtype::Forward => &["candidates"],
        DeclarationSubtype::Nominate | DeclarationSubtype::Offer | DeclarationSubtype::Reassign => {
            &["party"]
        }
        _ => &[],
    }
}

fn texts(value: &ParamValue) -> Option<Vec<&str>> {
    let ParamValue::List(items) = value else {
        return None;
    };
    items
        .iter()
        .map(|s| match s {
            ParamScalar::Text(t) if PartyRef::new(t).is_some() => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

fn list_len(record: &Record, name: &str) -> Option<usize> {
    match record.param(name) {
        Some(ParamValue::List(items)) => Some(items.len()),
        _ => None,
    }
}

pub(super) fn kind_ok(kind: Kind, value: &ParamValue) -> bool {
    match kind {
        Kind::Group => catalog_text(value, PartyRef::new),
        Kind::GroupList => texts(value).is_some_and(|t| !has_repeat_key(&t, |x| *x)),
        Kind::TextList => texts(value).is_some(),
        Kind::UriList => match value {
            ParamValue::List(items) => items
                .iter()
                .all(|s| matches!(s, ParamScalar::Text(t) if TypeUri::parse(t).is_some())),
            ParamValue::Scalar(_) => false,
        },
        Kind::Distribution => catalog_text(value, DistributionMethod::from_wire_name),
        Kind::LeaseExpiry => catalog_text(value, LeaseExpiry::from_wire_name),
        Kind::Regime => catalog_text(value, Regime::from_wire_name),
        Kind::Guarantee => catalog_text(value, |t| {
            PrincipalGuarantee::from_wire_name(t).filter(|g| g.waivable())
        }),
        Kind::ForwardReason => reason_code(value, ForwardReason::from_wire_name),
        Kind::WorkRef => matches!(value, ParamValue::Scalar(ParamScalar::WorkId(_))),
    }
}

fn paired(record: &Record, keys: &str, values: &str) -> bool {
    list_len(record, keys) == list_len(record, values)
}

fn group_texts<'r>(record: &'r Record, name: &str) -> Vec<&'r str> {
    record.param(name).and_then(texts).unwrap_or_default()
}

/// The cross-key rules of the responsibility subtypes: one candidate set, a lease with its expiry behaviour, paired group lists naming each group once, one forwarding target, decision inputs only with a policy version, and one waiver scope (RC-9, RC-11, RC-17, RC-18, RC-22, RC-48).
pub(super) fn shape_ok(record: &Record, subtype: DeclarationSubtype) -> bool {
    match subtype {
        DeclarationSubtype::QueueDefinition => {
            present(record, &["candidates", "candidate_group"]) == 1
                && present(record, &["lease", "lease_expiry"]) != 1
        }
        DeclarationSubtype::OrgRule => {
            let mut groups = group_texts(record, "party_groups");
            groups.extend(group_texts(record, "role_groups"));
            paired(record, "party_groups", "parties")
                && paired(record, "role_groups", "roles")
                && !has_repeat_key(&groups, |x| *x)
        }
        DeclarationSubtype::Forward => present(record, &["queue", "candidates"]) == 1,
        DeclarationSubtype::Offer => {
            record.param("inputs").is_none() || record.param("policy").is_some()
        }
        DeclarationSubtype::Waiver => present(record, &["commitment", "work"]) == 1,
        _ => true,
    }
}

/// Whether a record may carry the participation policy: a catalog value beside exactly one `engaged_in` relation (RC-44).
pub(super) fn participation_ok(record: &Record, value: &ParamValue) -> bool {
    let engaged = record
        .core()
        .relations
        .iter()
        .flatten()
        .filter(|r| matches!(r, Relation::EngagedIn { .. }))
        .count();
    engaged == 1 && catalog_text(value, ParticipationPolicy::from_wire_name)
}

/// Whether `name` is the participation key (RC-44).
pub(super) fn is_participation(name: &str) -> bool {
    name == PARTICIPATION_KEY
}
