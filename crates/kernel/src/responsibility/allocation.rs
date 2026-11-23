use alloc::vec::Vec;

use super::queue::{DistributionMethod, Lease, LeaseExpiry, QueueVersion};
use crate::catalog::DeclarationSubtype;
use crate::commitment::{AccessAnswer, CommitmentState, CommitmentView, Operation, StepOutcome};
use crate::id::{PartyRef, RecordId, Time};
use crate::ontology::Obligor;
use crate::reason::wire_enum;

wire_enum! {
    /// The closed responsibility operation set, apart from the commitment operations; adding one is a protocol decision (RC-17).
    ResponsibilityOperation {
        /// A candidate takes pooled work and counts as having promised.
        Claim => "claim",
        /// The claiming obligor returns the work to the pool; no cancellation and no §9 release.
        Unclaim => "unclaim",
        /// The work moves to another queue or candidate set, with a reason.
        Forward => "forward",
        /// A Party is named as a candidate; it is no obligor until it accepts.
        Nominate => "nominate",
        /// The work is offered to a named Party, who answers with a §9 operation.
        Offer => "offer",
        /// A new Party is offered the work; the obligor stays until the debt changes hands by §9 delegation.
        Reassign => "reassign",
        /// The obligor extends its ownership lease.
        RenewLease => "renew_lease",
    }
}

/// What a responsibility operation does on the commitment axis (RC-17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommitmentEffect {
    /// The §9 `promise` effect: `requested` becomes `promised`.
    Promise,
    /// `promised` returns to `requested`; this is no §9 `release`.
    ReturnToRequested,
    /// The commitment state does not change.
    Unchanged,
}

impl ResponsibilityOperation {
    /// The closed set (RC-17).
    pub const CLOSED_SET: &'static [Self] = Self::ALL;

    /// The operation a core Declaration subtype is, if it is one (P-71, RC-17).
    #[must_use]
    pub const fn of(subtype: DeclarationSubtype) -> Option<Self> {
        Some(match subtype {
            DeclarationSubtype::ClaimResponsibility => Self::Claim,
            DeclarationSubtype::Unclaim => Self::Unclaim,
            DeclarationSubtype::Forward => Self::Forward,
            DeclarationSubtype::Nominate => Self::Nominate,
            DeclarationSubtype::Offer => Self::Offer,
            DeclarationSubtype::Reassign => Self::Reassign,
            DeclarationSubtype::RenewLease => Self::RenewLease,
            _ => return None,
        })
    }

    /// The core Declaration subtype of the operation (P-71).
    #[must_use]
    pub const fn subtype(self) -> DeclarationSubtype {
        match self {
            Self::Claim => DeclarationSubtype::ClaimResponsibility,
            Self::Unclaim => DeclarationSubtype::Unclaim,
            Self::Forward => DeclarationSubtype::Forward,
            Self::Nominate => DeclarationSubtype::Nominate,
            Self::Offer => DeclarationSubtype::Offer,
            Self::Reassign => DeclarationSubtype::Reassign,
            Self::RenewLease => DeclarationSubtype::RenewLease,
        }
    }

    /// The commitment-axis mapping of RC-17: `claim` has the §9 `promise` effect, `unclaim` returns to `requested`, every other operation leaves the state as it is.
    #[must_use]
    pub const fn commitment_effect(self) -> CommitmentEffect {
        match self {
            Self::Claim => CommitmentEffect::Promise,
            Self::Unclaim => CommitmentEffect::ReturnToRequested,
            Self::Forward | Self::Nominate | Self::Offer | Self::Reassign | Self::RenewLease => {
                CommitmentEffect::Unchanged
            }
        }
    }
}

wire_enum! {
    /// The assignment axis: who the obligor is and how it is decided, apart from the execution axis (RC-15, RC-16).
    AllocationState {
        /// In the pool: candidates exist, nobody took it.
        Pooled => "pooled",
        /// Offered to a named Party, or asked of it directly; its answer is awaited.
        Offered => "offered",
        /// The obligor is known; a declared lease is running.
        Held => "held",
        /// Nobody took it: the start deadline passed or the policy found no candidate.
        FailedToAssign => "failed_to_assign",
    }
}

wire_enum! {
    /// How the obligor in force came to hold the work.
    HoldVia {
        /// By `claim` from the pool.
        Claim => "claim",
        /// By a §9 `promise` or an accepted counter-offer, without an offer.
        Promise => "promise",
        /// By answering an offer.
        Offer => "offer",
        /// By an accepted §9 delegation.
        Delegation => "delegation",
    }
}

/// The obligor's hold on the work: the record that bound it, when, how, whether a bid award binds it, the last lease renewal, its chain and the lease declared when it was taken from the pool (RC-18, RC-25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hold {
    /// The binding record.
    pub record: RecordId,
    /// The obligor.
    pub party: PartyRef,
    /// The binding record's ledger time.
    pub since: Time,
    /// How it was taken.
    pub via: HoldVia,
    /// Awarded by a bid: withdrawal only through §9 revocation or cancellation (RC-25).
    pub binding: bool,
    /// The ledger time of the last renewal: the binding, a `renew_lease`, a `state` or a `notice` of the obligor.
    pub renewed: Time,
    /// The author, `on_behalf_of` rings and capacity principal of the binding record, the upper links of accountability (RC-5).
    pub chain: Vec<PartyRef>,
    /// The lease declared when the work was taken from the pool; none for a direct promise (RC-18).
    pub lease: Option<Lease>,
}

/// An offer of pooled work to a named Party, with the policy version and inputs of a policy's decision (RC-17, RC-22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// The `offer` or `reassign` record.
    pub record: RecordId,
    /// The Party offered.
    pub to: PartyRef,
    /// Who offered.
    pub by: PartyRef,
    /// The queue definition version the decision used, for an offer by the distribution policy.
    pub policy: Option<RecordId>,
    /// The method of that policy version.
    pub method: Option<DistributionMethod>,
    /// The inputs the decision used: capability statements and bids, all Claims (RC-23).
    pub inputs: Vec<RecordId>,
}

/// A nomination: a candidate named, who is no obligor until it accepts (RC-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nomination {
    /// The `nominate` record.
    pub record: RecordId,
    /// The Party named.
    pub party: PartyRef,
    /// Who named it.
    pub by: PartyRef,
}

/// Where forwarded work goes (RC-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardTarget {
    /// Another queue.
    Queue(RecordId),
    /// Another candidate set.
    Candidates(Vec<PartyRef>),
}

/// One forwarding, counted for ping-pong (RC-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forwarding {
    /// The `forward` record.
    pub record: RecordId,
    /// Who forwarded.
    pub by: PartyRef,
    /// Where to.
    pub target: ForwardTarget,
    /// When.
    pub at: Time,
}

/// What an assignment history entry records (RC-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AllocationAct {
    /// A responsibility operation.
    Responsibility(ResponsibilityOperation),
    /// A commitment operation that binds, declines an offer or hands the debt over.
    Commitment(Operation),
    /// An explicit taking-over of accountability, or the acceptance of a transfer.
    Acknowledgement,
}

/// One assignment history entry: who, to whom, when, under which policy version, and its result; reassignment never erases one (RC-19).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationEvent {
    /// The record.
    pub record: RecordId,
    /// What it is.
    pub act: AllocationAct,
    /// The Party it speaks for.
    pub by: PartyRef,
    /// The Party it names, if any.
    pub to: Option<PartyRef>,
    /// Its ledger time.
    pub at: Time,
    /// The queue definition version in force.
    pub policy: Option<RecordId>,
    /// Its result; a refused record stays recorded.
    pub outcome: StepOutcome,
}

/// The assignment of a commitment as its records derive it: the queue and the definition version in force, a forwarded candidate set, since when it is pooled, the open offer, nominations, the hold, forwardings, every offer made and the history (RC-10…RC-25).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Allocation {
    /// The queue the work is in, or came from.
    pub queue: Option<RecordId>,
    /// The definition version of that queue in force.
    pub definition: Option<QueueVersion>,
    /// A candidate set the work was forwarded to.
    pub candidates: Option<Vec<PartyRef>>,
    /// The ledger time the work entered or returned to the pool.
    pub pooled_since: Option<Time>,
    /// The open offer.
    pub offer: Option<Offer>,
    /// Every applied offer, the distribution decisions (RC-22).
    pub offers: Vec<Offer>,
    /// The nominations.
    pub nominations: Vec<Nomination>,
    /// The obligor's hold.
    pub hold: Option<Hold>,
    /// Every forwarding.
    pub forwards: Vec<Forwarding>,
    /// Every assignment record and its result (RC-19).
    pub history: Vec<AllocationEvent>,
}

impl Allocation {
    /// The assignment of a commitment its `request` opens: pooled from its ledger time when it names a queue (RC-10).
    #[must_use]
    pub fn opened(obligor: &Obligor, at: Time) -> Self {
        match obligor {
            Obligor::Queue(q) => Self {
                queue: Some(*q),
                pooled_since: Some(at),
                ..Self::default()
            },
            Obligor::Party(_) => Self::default(),
        }
    }

    /// Whether `party` may take the work as far as the records tell: a forwarded candidate set, else the queue definition in force; `None` when Access alone decides (RC-11, RC-20).
    #[must_use]
    pub fn admits(&self, party: &PartyRef) -> Option<bool> {
        let excluded = self
            .definition
            .as_ref()
            .is_some_and(|d| d.definition.excluded.contains(party));
        if excluded {
            return Some(false);
        }
        match (&self.candidates, &self.definition) {
            (Some(list), _) => Some(list.contains(party)),
            (None, Some(d)) => d.definition.admits(party),
            (None, None) => None,
        }
    }

    /// Whether `party` owns the queue in force; `None` when no definition is known.
    #[must_use]
    pub fn owned_by(&self, party: &PartyRef) -> Option<bool> {
        self.definition
            .as_ref()
            .map(|d| &d.definition.owner == party)
    }
}

/// How the ownership lease stands at a ledger time (RC-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseStatus {
    /// No lease: none was declared, or the work is not held from a queue; the commitment clock governs (RC-18).
    NoLease,
    /// Running until this time.
    Running(Time),
    /// Ran out at this time; the declared behaviour applies.
    Expired {
        /// When it ran out.
        at: Time,
        /// What happens now.
        expiry: LeaseExpiry,
    },
}

/// The lease at ledger time `now`: it runs from the hold's last renewal or the latest `activity` time after the binding (progress reports and liveness signals the caller derives) for the declared length (RC-18).
#[must_use]
pub fn lease_status(view: &CommitmentView, now: Time, activity: &[Time]) -> LeaseStatus {
    let Some(hold) = &view.allocation.hold else {
        return LeaseStatus::NoLease;
    };
    let Some(lease) = hold.lease else {
        return LeaseStatus::NoLease;
    };
    let last = activity
        .iter()
        .copied()
        .filter(|t| *t >= hold.since)
        .chain(core::iter::once(hold.renewed))
        .max()
        .unwrap_or(hold.renewed);
    match last.0.checked_add(lease.duration) {
        None => LeaseStatus::Running(Time(u64::MAX)),
        Some(end) if now.0 < end => LeaseStatus::Running(Time(end)),
        Some(end) => LeaseStatus::Expired {
            at: Time(end),
            expiry: lease.expiry,
        },
    }
}

fn start_missed(view: &CommitmentView, now: Time) -> bool {
    let within = view
        .allocation
        .definition
        .as_ref()
        .and_then(|d| d.definition.start_within);
    match (view.allocation.pooled_since, within) {
        (Some(since), Some(within)) => since.0.checked_add(within).is_some_and(|d| now.0 >= d),
        _ => false,
    }
}

/// The assignment axis at ledger time `now`, independent of the execution axis: `held` once a Party is bound; for a direct request `offered`; for pooled work `offered` while an offer or a counter-offer is open and `pooled` otherwise, both becoming `failed_to_assign` once the start deadline passed or the policy found no candidate (`candidates_found`, from Access membership) (RC-13, RC-15, RC-16).
#[must_use]
pub fn allocation_state(
    view: &CommitmentView,
    now: Time,
    candidates_found: Option<bool>,
) -> AllocationState {
    if view.allocation.hold.is_some() && matches!(view.obligor, Obligor::Party(_)) {
        return AllocationState::Held;
    }
    match view.obligor {
        Obligor::Party(_) => AllocationState::Offered,
        Obligor::Queue(_) => {
            if !view.is_terminal() && (start_missed(view, now) || candidates_found == Some(false)) {
                return AllocationState::FailedToAssign;
            }
            let countered = view
                .items
                .iter()
                .any(|i| i.state == CommitmentState::Countered);
            if view.allocation.offer.is_some() || countered {
                AllocationState::Offered
            } else {
                AllocationState::Pooled
            }
        }
    }
}

/// The ping-pong count and forwarding chain of a commitment, always visible, and whether it passed the queue's declared threshold (RC-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PingPong {
    /// How many times the work was forwarded.
    pub count: usize,
    /// The targets, in order.
    pub chain: Vec<ForwardTarget>,
    /// Whether the count passed the declared threshold.
    pub over: bool,
}

/// The ping-pong count of a commitment (RC-14).
#[must_use]
pub fn ping_pong(view: &CommitmentView) -> PingPong {
    let count = view.allocation.forwards.len();
    let threshold = view
        .allocation
        .definition
        .as_ref()
        .and_then(|d| d.definition.ping_pong_threshold);
    PingPong {
        count,
        chain: view
            .allocation
            .forwards
            .iter()
            .map(|f| f.target.clone())
            .collect(),
        over: threshold.is_some_and(|t| u64::try_from(count).is_ok_and(|c| c > t)),
    }
}

wire_enum! {
    /// Attention signals of the assignment axis, addressed to the queue owner (RC-13, RC-14, RC-18).
    AllocationSignalKind {
        /// Nobody took the work.
        FailedToAssign => "failed_to_assign",
        /// The forwarding count passed the threshold.
        PingPong => "ping_pong",
        /// The ownership lease ran out.
        LeaseExpired => "lease_expired",
    }
}

/// An assignment attention signal for the queue owner; for an expired lease that returns to the pool, the Work service Party also writes the `unclaim` (RC-13, RC-14, RC-18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationSignal {
    /// Its kind.
    pub kind: AllocationSignalKind,
    /// The queue owner it goes to, when the definition is known.
    pub to: Option<PartyRef>,
    /// Whether the Work service Party now writes an `unclaim` naming the hold in `basis`.
    pub unclaim_due: bool,
}

/// The assignment signals at ledger time `now` (RC-13, RC-14, RC-18).
#[must_use]
pub fn allocation_signals(
    view: &CommitmentView,
    now: Time,
    activity: &[Time],
    candidates_found: Option<bool>,
) -> Vec<AllocationSignal> {
    let owner = view
        .allocation
        .definition
        .as_ref()
        .map(|d| d.definition.owner.clone());
    let signal = |kind, unclaim_due| AllocationSignal {
        kind,
        to: owner.clone(),
        unclaim_due,
    };
    let mut out = Vec::new();
    if view.is_terminal() {
        return out;
    }
    if allocation_state(view, now, candidates_found) == AllocationState::FailedToAssign {
        out.push(signal(AllocationSignalKind::FailedToAssign, false));
    }
    if ping_pong(view).over {
        out.push(signal(AllocationSignalKind::PingPong, false));
    }
    if let LeaseStatus::Expired { expiry, .. } = lease_status(view, now, activity) {
        out.push(signal(
            AllocationSignalKind::LeaseExpired,
            expiry == LeaseExpiry::ReturnToPool,
        ));
    }
    out
}

/// A wait for access: assignment grants no access, so a held commitment whose obligor Access does not allow the work waits for an authority decision (RC-20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessWait {
    /// The obligor waiting.
    pub party: PartyRef,
    /// What Access answers.
    pub answer: AccessAnswer,
}

/// The "access awaited" wait of a held commitment, from Access's answer for its obligor; nothing in the assignment widens access (RC-20).
#[must_use]
pub fn access_wait(view: &CommitmentView, obligor_access: AccessAnswer) -> Option<AccessWait> {
    let hold = view.allocation.hold.as_ref()?;
    (!view.is_terminal() && obligor_access != AccessAnswer::Allow).then(|| AccessWait {
        party: hold.party.clone(),
        answer: obligor_access,
    })
}
