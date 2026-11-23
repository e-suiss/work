use alloc::vec::Vec;

use super::chains;
use crate::catalog::DeclarationSubtype;
use crate::commitment::params;
use crate::derive::{Derivation, Effect, Entry};
use crate::id::{PartyRef, RecordId, Time, WorkId};
use crate::reason::wire_enum;
use crate::record::{ParamScalar, ParamValue, Record};

wire_enum! {
    /// The principal's guarantees towards the Parties acting on its behalf: four can never be waived, three can only be narrowed by a scoped, recorded waiver (RC-9).
    PrincipalGuarantee {
        /// Seeing and reviewing who acts on its behalf and what they do.
        Oversight => "oversight",
        /// Reviewing the evidence.
        EvidenceReview => "evidence_review",
        /// Revoking for the future, as far as its own authority allows.
        ProspectiveRevocation => "prospective_revocation",
        /// Notice of failures and violations.
        FailureNotice => "failure_notice",
        /// Attention before an irreversible action.
        AdvanceNotice => "advance_notice",
        /// Intervention as far as the executor's capability allows.
        Intervention => "intervention",
        /// Immediate notification.
        ImmediateNotice => "immediate_notice",
    }
}

impl PrincipalGuarantee {
    /// Whether a scoped, recorded waiver may narrow the guarantee (RC-9).
    #[must_use]
    pub const fn waivable(self) -> bool {
        matches!(
            self,
            Self::AdvanceNotice | Self::Intervention | Self::ImmediateNotice
        )
    }
}

/// What a waiver covers: one commitment or one Work; a waiver is never unscoped (RC-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaiverScope {
    /// One commitment, by its `request`.
    Commitment(RecordId),
    /// One Work.
    Work(WorkId),
}

/// A principal's waiver: one waivable guarantee, its scope and optional end; it widens no authority (RC-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiver {
    /// The `waiver` record.
    pub record: RecordId,
    /// The principal it speaks for.
    pub principal: PartyRef,
    /// The guarantee narrowed.
    pub guarantee: PrincipalGuarantee,
    /// What it covers.
    pub scope: WaiverScope,
    /// When it ends, if declared.
    pub until: Option<Time>,
}

impl Waiver {
    /// The waiver a core `waiver` Declaration declares; `None` for any other record, a guarantee that cannot be waived or a waiver without exactly one scope, which the record rules reject (RC-9).
    #[must_use]
    pub fn of(record: &Record, id: RecordId) -> Option<Self> {
        if chains::subtype_of(record)? != DeclarationSubtype::Waiver {
            return None;
        }
        let guarantee = params::text(record, "guarantee")
            .and_then(PrincipalGuarantee::from_wire_name)
            .filter(|g| g.waivable())?;
        let work = match record.param("work") {
            Some(ParamValue::Scalar(ParamScalar::WorkId(w))) => Some(*w),
            _ => None,
        };
        let scope = match (params::digest(record, "commitment"), work) {
            (Some(c), None) => WaiverScope::Commitment(c),
            (None, Some(w)) => WaiverScope::Work(w),
            _ => return None,
        };
        Some(Self {
            record: id,
            principal: params::acting(record).clone(),
            guarantee,
            scope,
            until: params::time(record, "until"),
        })
    }
}

/// The waivers in force on the ledger: normative `waiver` records no admitted record supersedes (RC-9).
#[must_use]
pub fn waivers(entries: &[Entry<'_>], derivation: &Derivation) -> Vec<Waiver> {
    entries
        .iter()
        .zip(&derivation.records)
        .filter(|(e, d)| {
            d.id == e.id() && d.effect == Effect::Normative && d.superseded_by.is_empty()
        })
        .filter_map(|(e, _)| Waiver::of(e.record(), e.id()))
        .collect()
}

/// Each of the seven guarantees of `principal` for a commitment in a Work at ledger time `now`, and whether it is in force: the four that cannot be waived always are; the other three unless a waiver of that principal covers the commitment or the Work and has not ended (RC-9).
#[must_use]
pub fn guarantees(
    waivers: &[Waiver],
    principal: &PartyRef,
    commitment: Option<RecordId>,
    work: Option<WorkId>,
    now: Time,
) -> Vec<(PrincipalGuarantee, bool)> {
    PrincipalGuarantee::ALL
        .iter()
        .map(|g| {
            let waived = g.waivable()
                && waivers.iter().any(|w| {
                    w.guarantee == *g
                        && &w.principal == principal
                        && w.until.is_none_or(|u| now < u)
                        && match w.scope {
                            WaiverScope::Commitment(c) => commitment == Some(c),
                            WaiverScope::Work(x) => work == Some(x),
                        }
                });
            (*g, !waived)
        })
        .collect()
}
