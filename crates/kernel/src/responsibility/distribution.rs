use alloc::vec::Vec;

use super::allocation::HoldVia;
use super::queue::DistributionMethod;
use crate::commitment::CommitmentView;
use crate::id::{PartyRef, RecordId};
use crate::ontology::Obligor;

/// One distribution decision as recorded: the offer, the Party offered, who decided, the policy version and the inputs it used; reproducible from the records, and never a ranking of Parties (RC-22, RC-23).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributionDecision {
    /// The `offer` or `reassign` record.
    pub record: RecordId,
    /// The Party offered.
    pub offered: PartyRef,
    /// Who decided: the queue owner or the Party applying the policy.
    pub by: PartyRef,
    /// The queue definition version, for a decision of the policy.
    pub policy: Option<RecordId>,
    /// The method of that version.
    pub method: Option<DistributionMethod>,
    /// The capability statements and bids it used.
    pub inputs: Vec<RecordId>,
}

/// The distribution decisions of a commitment, in ledger order (RC-22).
#[must_use]
pub fn decisions(view: &CommitmentView) -> Vec<DistributionDecision> {
    view.allocation
        .offers
        .iter()
        .map(|o| DistributionDecision {
            record: o.record,
            offered: o.to.clone(),
            by: o.by.clone(),
            policy: o.policy,
            method: o.method,
            inputs: o.inputs.clone(),
        })
        .collect()
}

/// The open workload of one Party, a derived view: open commitments it is bound to as obligor, those of them it claimed from a pool, and its running executions as the caller derives them (RC-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload {
    /// The Party.
    pub party: PartyRef,
    /// Open commitments it is bound to as obligor.
    pub open: u32,
    /// Of those, the ones it claimed.
    pub claimed: u32,
    /// Running executions.
    pub running: u32,
}

impl Workload {
    /// Whether the open workload passes a declared WIP limit, which raises the overload signal; the policy declares the limit, Work never ranks by it (RC-24).
    #[must_use]
    pub fn overloaded(&self, wip_limit: Option<u64>) -> bool {
        wip_limit.is_some_and(|limit| u64::from(self.open) > limit)
    }
}

/// The open workload of `party` over the derived commitments (RC-24).
#[must_use]
pub fn workload(views: &[CommitmentView], party: &PartyRef, running: u32) -> Workload {
    let mut open: u32 = 0;
    let mut claimed: u32 = 0;
    for view in views.iter().filter(|v| !v.is_terminal()) {
        let bound = matches!(&view.obligor, Obligor::Party(p) if p == party);
        let Some(hold) = view.allocation.hold.as_ref().filter(|_| bound) else {
            continue;
        };
        open = open.saturating_add(1);
        if hold.via == HoldVia::Claim {
            claimed = claimed.saturating_add(1);
        }
    }
    Workload {
        party: party.clone(),
        open,
        claimed,
        running,
    }
}
