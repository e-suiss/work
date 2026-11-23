use crate::commitment::params;
use crate::derive::{Admission, Derivation, Entry};
use crate::id::{PartyRef, RecordId, WorkId};
use crate::reason::wire_enum;
use crate::record::Record;
use crate::relation::Relation;

wire_enum! {
    /// An agent's participation policy, a declared parameter of its `engaged_in` relation: when it speaks or acts, which is not what it may do without asking (autonomy), and it creates no authority (RC-44).
    ParticipationPolicy {
        /// Only when named or asked.
        OnCall => "on_call",
        /// Joins the work's events on its own with comments or suggestions.
        Proactive => "proactive",
        /// Works only on commitments assigned to it.
        AssignedOnly => "assigned_only",
    }
}

/// The `params` key that carries the participation policy beside exactly one `engaged_in` relation (RC-44).
pub const PARTICIPATION_KEY: &str = "participation";

/// The value the interface suggests when the Party adding the agent declares none (RC-44).
pub const SUGGESTED_PARTICIPATION: ParticipationPolicy = ParticipationPolicy::OnCall;

/// The participation policy in force for an agent in a Work, and the record that declared it (RC-44).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participation {
    /// The policy.
    pub policy: ParticipationPolicy,
    /// The declaring record.
    pub record: RecordId,
    /// The Party it speaks for.
    pub declared_by: PartyRef,
}

fn engages(record: &Record, agent: &PartyRef, work: &WorkId) -> Option<ParticipationPolicy> {
    let policy =
        params::text(record, PARTICIPATION_KEY).and_then(ParticipationPolicy::from_wire_name)?;
    record
        .core()
        .relations
        .iter()
        .flatten()
        .any(|r| matches!(r, Relation::EngagedIn { source, target, .. } if source == agent && target == work))
        .then_some(policy)
}

/// The participation policy of `agent` in `work`: the Party that adds the agent declares it with its first `engaged_in`, and only a principal of the agent (`principals`, from Access) changes it later; everyone in the Work sees it; `None` when none is declared, and the interface then suggests [`SUGGESTED_PARTICIPATION`] (RC-44).
#[must_use]
pub fn participation(
    entries: &[Entry<'_>],
    derivation: &Derivation,
    agent: &PartyRef,
    work: &WorkId,
    principals: &[PartyRef],
) -> Option<Participation> {
    let mut current: Option<Participation> = None;
    for (entry, derived) in entries.iter().zip(&derivation.records) {
        if derived.id != entry.id() || derived.admission != Admission::Admitted {
            continue;
        }
        let Some(policy) = engages(entry.record(), agent, work) else {
            continue;
        };
        let by = params::acting(entry.record());
        if current.is_none() || principals.contains(by) {
            current = Some(Participation {
                policy,
                record: entry.id(),
                declared_by: by.clone(),
            });
        }
    }
    current
}
