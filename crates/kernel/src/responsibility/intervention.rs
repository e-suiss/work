use alloc::vec::Vec;

use crate::id::{PartyRef, RecordId, Time};
use crate::reason::wire_enum;

/// A control lease as the takeover record gives it: the Party that took control, from when, until when if it was handed back, and the record (RC-8, RC-33).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlSpan {
    /// The `control_lease` record.
    pub record: RecordId,
    /// The Party that took control.
    pub party: PartyRef,
    /// The takeover record's ledger time.
    pub from: Time,
    /// When control was handed back, if it was.
    pub until: Option<Time>,
}

/// An action report: the Party it speaks for and its ledger time (RC-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActBy {
    /// The Act record.
    pub record: RecordId,
    /// Its author.
    pub party: PartyRef,
    /// Its ledger time.
    pub at: Time,
}

wire_enum! {
    /// Whose responsibility an action is around a takeover (RC-8).
    InterventionMark {
        /// The intervening Party acted under its control lease; its responsibility starts at the takeover record.
        UnderLease => "under_lease",
        /// A Party in a coordination role acted without a control lease: an out-of-coordination intervention, visible as such.
        OutsideCoordination => "outside_coordination",
    }
}

fn covers(span: &ControlSpan, act: &ActBy) -> bool {
    span.party == act.party && span.from <= act.at && span.until.is_none_or(|u| act.at < u)
}

/// Marks the actions around takeovers: an action of a Party under its own control lease is that Party's from the takeover record on, never before it; an action of a coordinating Party (dispatcher, monitor) without a lease covering it is an out-of-coordination intervention; every other action is unmarked (RC-8).
#[must_use]
pub fn interventions(
    acts: &[ActBy],
    leases: &[ControlSpan],
    coordinators: &[PartyRef],
) -> Vec<(RecordId, InterventionMark)> {
    acts.iter()
        .filter_map(|act| {
            if leases.iter().any(|l| covers(l, act)) {
                Some((act.record, InterventionMark::UnderLease))
            } else if coordinators.contains(&act.party) {
                Some((act.record, InterventionMark::OutsideCoordination))
            } else {
                None
            }
        })
        .collect()
}
