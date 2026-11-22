use alloc::vec::Vec;

use crate::catalog::CoreDerivedRole;
use crate::id::{PartyRef, RecordId, Time};
use crate::record::{Capacity, ParamScalar, ParamValue, Record};
use crate::relation::{DerivedRole, DerivedTarget, Relation};

pub(crate) fn digest(record: &Record, name: &str) -> Option<RecordId> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Digest(d)) => Some(RecordId(*d)),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

pub(crate) fn text<'r>(record: &'r Record, name: &str) -> Option<&'r str> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Text(t)) => Some(t),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

pub(crate) fn party(record: &Record, name: &str) -> Option<PartyRef> {
    text(record, name).and_then(PartyRef::new)
}

pub(crate) fn uint(record: &Record, name: &str) -> Option<u64> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Uint(n)) => Some(*n),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

pub(crate) fn time(record: &Record, name: &str) -> Option<Time> {
    uint(record, name).map(Time)
}

pub(crate) fn flag(record: &Record, name: &str) -> Option<bool> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Bool(b)) => Some(*b),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

pub(crate) fn digests(record: &Record, name: &str) -> Option<Vec<RecordId>> {
    match record.param(name)? {
        ParamValue::List(items) => Some(
            items
                .iter()
                .filter_map(|s| match s {
                    ParamScalar::Digest(d) => Some(RecordId(*d)),
                    _ => None,
                })
                .collect(),
        ),
        ParamValue::Scalar(_) => None,
    }
}

pub(crate) fn parties(record: &Record, name: &str) -> Option<Vec<PartyRef>> {
    match record.param(name)? {
        ParamValue::List(items) => Some(
            items
                .iter()
                .filter_map(|s| match s {
                    ParamScalar::Text(t) => PartyRef::new(t),
                    _ => None,
                })
                .collect(),
        ),
        ParamValue::Scalar(_) => None,
    }
}

pub(crate) fn items(record: &Record) -> Option<Vec<u16>> {
    match record.param("items")? {
        ParamValue::List(items) => Some(
            items
                .iter()
                .filter_map(|s| match s {
                    ParamScalar::Uint(n) => u16::try_from(*n).ok(),
                    _ => None,
                })
                .collect(),
        ),
        ParamValue::Scalar(_) => None,
    }
}

pub(crate) fn has_part(record: &Record, name: &str) -> bool {
    record
        .core()
        .body
        .iter()
        .flatten()
        .any(|b| b.part.as_str() == name)
}

pub(crate) fn has_body(record: &Record) -> bool {
    record.core().body.as_ref().is_some_and(|b| !b.is_empty())
}

pub(crate) fn has_evidence(record: &Record) -> bool {
    record
        .core()
        .evidence
        .as_ref()
        .is_some_and(|e| !e.is_empty())
}

/// The Party a record speaks for: the capacity principal, or the author (P-13, E-13).
pub(crate) fn acting(record: &Record) -> &PartyRef {
    match &record.core().capacity {
        Some(Capacity::For(p)) => p,
        Some(Capacity::Own) | None => &record.core().author,
    }
}

/// The author, every `on_behalf_of` ring and the capacity principal, without repeats (E-13, CM-38).
pub(crate) fn chain(record: &Record) -> Vec<PartyRef> {
    let core = record.core();
    let mut out: Vec<PartyRef> = Vec::new();
    let principal = match &core.capacity {
        Some(Capacity::For(p)) => Some(p),
        Some(Capacity::Own) | None => None,
    };
    let all = core::iter::once(&core.author)
        .chain(core.on_behalf_of.iter().flatten())
        .chain(principal);
    for p in all {
        if !out.contains(p) {
            out.push(p.clone());
        }
    }
    out
}

/// The records a `state` cites as fulfilling the commitment: the sources of its `derived_from` relations in the `fulfills` role (CM-25, C-29).
pub(crate) fn fulfilments(record: &Record) -> Vec<RecordId> {
    record
        .core()
        .relations
        .iter()
        .flatten()
        .filter_map(|r| match r {
            Relation::DerivedFrom {
                source: Some(source),
                target: DerivedTarget::Record(_),
                role: DerivedRole::Core(CoreDerivedRole::Fulfills),
            } => Some(*source),
            _ => None,
        })
        .collect()
}

/// The parents a `request` supports: its `derived_from` record targets in the `supports` role (CM-46, C-28).
pub(crate) fn supported(record: &Record) -> Vec<RecordId> {
    record
        .core()
        .relations
        .iter()
        .flatten()
        .filter_map(|r| match r {
            Relation::DerivedFrom {
                source: None,
                target: DerivedTarget::Record(target),
                role: DerivedRole::Core(CoreDerivedRole::Supports),
            } => Some(*target),
            _ => None,
        })
        .collect()
}
