use alloc::vec::Vec;

use super::fold::{
    AccessAnswer, Input, Proposed, Records, is_obligee, is_obligor, is_principal, require,
    set_state, whole,
};
use super::operation::Operation;
use super::params;
use super::state::CommitmentState as S;
use super::transitions::{Caller, Missing};
use super::view::{ActiveEnd, ActiveEndCause, CommitmentView, Proposal, Refusal, StepOutcome};
use crate::catalog::DeclarationSubtype;
use crate::id::PartyRef;
use crate::ontology::Obligor;
use crate::record::Record;
use crate::responsibility::{
    AccountabilitySource, AssignmentAct, AssignmentEvent, DistributionMethod, Explicit,
    ForwardTarget, Forwarding, Hold, HoldVia, LeaseExpiry, Nomination, Offer, QueueVersion,
    ResponsibilityOperation, in_force,
};
use crate::validate::ActorType;

/// What a Declaration in a commitment chain is to the fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Act {
    Commitment(Operation),
    Responsibility(ResponsibilityOperation),
    Acknowledgement,
}

pub(super) fn act_of(record: &Record) -> Option<Act> {
    let Record::Declaration(d) = record else {
        return None;
    };
    let subtype = DeclarationSubtype::from_uri(d.subtype.as_str())?;
    if subtype == DeclarationSubtype::Acknowledgement {
        return Some(Act::Acknowledgement);
    }
    Operation::of(subtype)
        .map(Act::Commitment)
        .or_else(|| ResponsibilityOperation::of(subtype).map(Act::Responsibility))
}

/// Sets the queue definition version in force before ledger position `before` (RC-19).
pub(super) fn refresh(view: &mut CommitmentView, queues: &[QueueVersion], before: u64) {
    if let Some(queue) = view.assignment.queue {
        view.assignment.definition = in_force(queues, queue, before).cloned();
    }
}

/// Whether `party` may take pooled work as far as the records tell (RC-11).
pub(super) fn may_take(view: &CommitmentView, party: &PartyRef) -> bool {
    !matches!(view.obligor, Obligor::Queue(_)) || view.assignment.admits(party) != Some(false)
}

/// Records the hold a binding §9 operation gives: by answering the open offer or by promising; a lease only for work taken from the pool, and a bid award binds (RC-18, RC-25).
pub(super) fn bound(view: &mut CommitmentView, input: &Input<'_>, party: &PartyRef, pooled: bool) {
    let assignment = &mut view.assignment;
    let offer = assignment.offer.take();
    if assignment.hold.is_some() {
        return;
    }
    let answered = offer.as_ref().filter(|o| &o.to == party);
    let via = if answered.is_some() {
        HoldVia::Offer
    } else {
        HoldVia::Promise
    };
    let binding = answered.is_some_and(|o| o.method == Some(DistributionMethod::Bid));
    let lease = if pooled {
        assignment
            .definition
            .as_ref()
            .and_then(|d| d.definition.lease)
    } else {
        None
    };
    assignment.hold = Some(Hold {
        record: input.id,
        party: party.clone(),
        since: input.recorded_at,
        via,
        binding,
        renewed: input.recorded_at,
        chain: params::chain(input.record),
        lease,
    });
}

/// Records the hold an accepted §9 delegation gives the new obligor (CM-44, RC-17).
pub(super) fn delegated(view: &mut CommitmentView, input: &Input<'_>, to: &PartyRef) {
    view.assignment.hold = Some(Hold {
        record: input.id,
        party: to.clone(),
        since: input.recorded_at,
        via: HoldVia::Delegation,
        binding: false,
        renewed: input.recorded_at,
        chain: params::chain(input.record),
        lease: None,
    });
}

fn event(
    view: &mut CommitmentView,
    input: &Input<'_>,
    act: AssignmentAct,
    to: Option<PartyRef>,
    outcome: StepOutcome,
) {
    let policy = view.assignment.definition.as_ref().map(|d| d.version);
    view.assignment.history.push(AssignmentEvent {
        record: input.id,
        act,
        by: params::acting(input.record).clone(),
        to,
        at: input.recorded_at,
        policy,
        outcome,
    });
}

/// Keeps the commitment operations that bind, decline an offer or hand the debt over in the assignment history, and lets the obligor's own `state` and `notice` renew its lease (RC-18, RC-19).
pub(super) fn record_commitment(
    view: &mut CommitmentView,
    input: &Input<'_>,
    op: Operation,
    outcome: StepOutcome,
) {
    let applied = outcome == StepOutcome::Applied;
    if applied
        && matches!(op, Operation::State | Operation::Notice)
        && let Some(hold) = view.assignment.hold.as_mut()
    {
        hold.renewed = input.recorded_at;
    }
    let to = match op {
        Operation::Promise if input.record.param("amendment").is_some() => return,
        Operation::Promise
        | Operation::PromiseConditional
        | Operation::AcceptCounter
        | Operation::Decline => None,
        Operation::Delegate => params::party(input.record, "obligor"),
        _ => return,
    };
    event(view, input, AssignmentAct::Commitment(op), to, outcome);
}

fn forward_target(record: &Record) -> Option<ForwardTarget> {
    match (
        params::digest(record, "queue"),
        params::parties(record, "candidates"),
    ) {
        (Some(q), None) => Some(ForwardTarget::Queue(q)),
        (None, Some(c)) => Some(ForwardTarget::Candidates(c)),
        _ => None,
    }
}

fn pooled(view: &CommitmentView) -> bool {
    matches!(view.obligor, Obligor::Queue(_))
}

fn explicit_is(view: &CommitmentView, party: &PartyRef) -> bool {
    view.accountability
        .explicit
        .as_ref()
        .is_some_and(|e| &e.party == party)
}

fn claim_allowed(view: &CommitmentView) -> bool {
    view.assignment
        .definition
        .as_ref()
        .is_none_or(|d| d.definition.distribution == DistributionMethod::Pull)
}

fn plan(
    view: &CommitmentView,
    input: &Input<'_>,
    op: ResponsibilityOperation,
    records: &dyn Records,
) -> Result<Vec<u16>, Refusal> {
    require(!view.items.is_empty(), Refusal::StateNotPermitted)?;
    require(!view.is_terminal(), Refusal::TerminalOutcome)?;
    let record = input.record;
    let who = params::acting(record);
    match op {
        ResponsibilityOperation::Claim => {
            require(pooled(view), Refusal::StateNotPermitted)?;
            require(claim_allowed(view), Refusal::PolicyMethod)?;
            require(may_take(view, who), Refusal::NotACandidate)?;
            whole(view, &[S::Requested])
        }
        ResponsibilityOperation::Unclaim => plan_unclaim(view, input, who),
        ResponsibilityOperation::Forward => {
            require(pooled(view), Refusal::StateNotPermitted)?;
            require(
                view.assignment.owned_by(who) != Some(false),
                Refusal::WrongRole,
            )?;
            let target = forward_target(record).ok_or(Refusal::MissingContent)?;
            if let ForwardTarget::Queue(q) = &target {
                require(view.assignment.queue != Some(*q), Refusal::WrongTarget)?;
            }
            whole(view, &[S::Requested]).map(|_| Vec::new())
        }
        ResponsibilityOperation::Nominate => {
            let party = params::party(record, "party").ok_or(Refusal::MissingContent)?;
            let role = view.assignment.owned_by(who) == Some(true)
                || is_obligee(view, who)
                || explicit_is(view, who);
            require(role, Refusal::WrongRole)?;
            require(!is_obligor(view, &party), Refusal::WrongTarget)?;
            Ok(Vec::new())
        }
        ResponsibilityOperation::Offer => plan_offer(view, input, who, records),
        ResponsibilityOperation::Reassign => plan_reassign(view, record, who),
        ResponsibilityOperation::RenewLease => {
            let hold = view
                .assignment
                .hold
                .as_ref()
                .ok_or(Refusal::StateNotPermitted)?;
            require(is_obligor(view, who), Refusal::WrongRole)?;
            let lease = hold.lease.ok_or(Refusal::NoLease)?;
            let running = hold
                .renewed
                .0
                .checked_add(lease.duration)
                .is_none_or(|end| input.recorded_at.0 < end);
            require(
                running || lease.expiry == LeaseExpiry::KeepAndSignal,
                Refusal::LeaseExpired,
            )?;
            Ok(Vec::new())
        }
    }
}

fn plan_unclaim(
    view: &CommitmentView,
    input: &Input<'_>,
    who: &PartyRef,
) -> Result<Vec<u16>, Refusal> {
    let hold = view
        .assignment
        .hold
        .as_ref()
        .ok_or(Refusal::StateNotPermitted)?;
    require(view.assignment.queue.is_some(), Refusal::StateNotPermitted)?;
    if input.service() && !is_obligor(view, who) {
        let lease = hold.lease.ok_or(Refusal::NoLease)?;
        require(
            lease.expiry == LeaseExpiry::ReturnToPool,
            Refusal::PolicyMethod,
        )?;
        require(
            input.record.basis().contains(&hold.record),
            Refusal::MissingContent,
        )?;
        let due = hold.renewed.0.checked_add(lease.duration);
        require(
            due.is_some_and(|d| input.recorded_at.0 >= d),
            Refusal::NotYetDue,
        )?;
    } else {
        require(is_obligor(view, who), Refusal::WrongRole)?;
        require(!hold.binding, Refusal::BindingAward)?;
    }
    let pending = &view.pending;
    require(
        pending.delegation.is_none() && pending.revocation.is_none() && pending.amendment.is_none(),
        Refusal::AlreadyPending,
    )?;
    whole(view, &[S::Promised])
}

fn plan_offer(
    view: &CommitmentView,
    input: &Input<'_>,
    who: &PartyRef,
    records: &dyn Records,
) -> Result<Vec<u16>, Refusal> {
    let record = input.record;
    require(pooled(view), Refusal::StateNotPermitted)?;
    require(view.assignment.offer.is_none(), Refusal::AlreadyPending)?;
    let to = params::party(record, "party").ok_or(Refusal::MissingContent)?;
    require(may_take(view, &to), Refusal::NotACandidate)?;
    let owner = view.assignment.owned_by(who);
    match params::digest(record, "policy") {
        None => require(owner != Some(false), Refusal::WrongRole)?,
        Some(policy) => {
            require(input.service() || owner == Some(true), Refusal::WrongRole)?;
            let definition = view
                .assignment
                .definition
                .as_ref()
                .ok_or(Refusal::WrongTarget)?;
            require(definition.version == policy, Refusal::WrongTarget)?;
            let inputs = params::digests(record, "inputs").unwrap_or_default();
            let needs_inputs = matches!(
                definition.definition.distribution,
                DistributionMethod::Bid | DistributionMethod::Skill
            );
            require(!needs_inputs || !inputs.is_empty(), Refusal::MissingContent)?;
            let claims = inputs.iter().all(|i| {
                records
                    .record(i)
                    .is_none_or(|r| matches!(r, Record::Claim(_)))
            });
            require(claims, Refusal::WrongTarget)?;
        }
    }
    whole(view, &[S::Requested]).map(|_| Vec::new())
}

fn plan_reassign(
    view: &CommitmentView,
    record: &Record,
    who: &PartyRef,
) -> Result<Vec<u16>, Refusal> {
    let to = params::party(record, "party").ok_or(Refusal::MissingContent)?;
    let role = view.assignment.owned_by(who) == Some(true)
        || explicit_is(view, who)
        || is_obligee(view, who)
        || is_principal(view, who);
    require(role, Refusal::WrongRole)?;
    require(!is_obligor(view, &to), Refusal::WrongTarget)?;
    if pooled(view) {
        require(may_take(view, &to), Refusal::NotACandidate)?;
        return whole(view, &[S::Requested]).map(|_| Vec::new());
    }
    require(view.pending.delegation.is_none(), Refusal::AlreadyPending)?;
    whole(view, &[S::ConditionallyPromised, S::Promised]).map(|_| Vec::new())
}

fn offer_of(view: &CommitmentView, input: &Input<'_>, to: PartyRef) -> Offer {
    let policy = params::digest(input.record, "policy");
    Offer {
        record: input.id,
        to,
        by: params::acting(input.record).clone(),
        policy,
        method: policy
            .and(view.assignment.definition.as_ref())
            .map(|d| d.definition.distribution),
        inputs: params::digests(input.record, "inputs").unwrap_or_default(),
    }
}

fn apply(
    view: &mut CommitmentView,
    input: &Input<'_>,
    op: ResponsibilityOperation,
    targets: &[u16],
    queues: &[QueueVersion],
) {
    let record = input.record;
    let who = params::acting(record).clone();
    let at = input.recorded_at;
    match op {
        ResponsibilityOperation::Claim => {
            set_state(view, targets, S::Promised, None);
            view.obligor = Obligor::Party(who.clone());
            let lease = view
                .assignment
                .definition
                .as_ref()
                .and_then(|d| d.definition.lease);
            view.assignment.offer = None;
            view.assignment.hold = Some(Hold {
                record: input.id,
                party: who,
                since: at,
                via: HoldVia::Claim,
                binding: false,
                renewed: at,
                chain: params::chain(record),
                lease,
            });
        }
        ResponsibilityOperation::Unclaim => {
            set_state(view, targets, S::Requested, None);
            if let (Obligor::Party(old), Some(queue)) = (&view.obligor, view.assignment.queue) {
                view.active_ends.push(ActiveEnd {
                    obligor: old.clone(),
                    record: input.id,
                    cause: ActiveEndCause::Unclaimed,
                });
                view.obligor = Obligor::Queue(queue);
            }
            view.assignment.hold = None;
            view.assignment.pooled_since = Some(at);
        }
        ResponsibilityOperation::Forward => {
            let Some(target) = forward_target(record) else {
                return;
            };
            match &target {
                ForwardTarget::Queue(q) => {
                    view.obligor = Obligor::Queue(*q);
                    view.assignment.queue = Some(*q);
                    view.assignment.candidates = None;
                    refresh(view, queues, input.position);
                }
                ForwardTarget::Candidates(list) => {
                    view.assignment.candidates = Some(list.clone());
                }
            }
            view.assignment.offer = None;
            view.assignment.pooled_since = Some(at);
            view.assignment.forwards.push(Forwarding {
                record: input.id,
                by: who,
                target,
                at,
            });
        }
        ResponsibilityOperation::Nominate => {
            if let Some(party) = params::party(record, "party") {
                view.assignment.nominations.push(Nomination {
                    record: input.id,
                    party,
                    by: who,
                });
            }
        }
        ResponsibilityOperation::Offer | ResponsibilityOperation::Reassign => {
            let Some(to) = params::party(record, "party") else {
                return;
            };
            if pooled(view) {
                let offer = offer_of(view, input, to);
                view.assignment.offers.push(offer.clone());
                view.assignment.offer = Some(offer);
            } else {
                view.pending.delegation = Some(Proposal {
                    record: input.id,
                    to,
                });
            }
        }
        ResponsibilityOperation::RenewLease => {
            if let Some(hold) = view.assignment.hold.as_mut() {
                hold.renewed = at;
            }
        }
    }
}

/// Applies one responsibility record to the commitment its chain derives, or keeps it refused with its reason; every record stays in the assignment history (RC-17, RC-19).
pub(super) fn step(
    view: &mut CommitmentView,
    input: &Input<'_>,
    op: ResponsibilityOperation,
    records: &dyn Records,
    queues: &[QueueVersion],
) {
    let to = params::party(input.record, "party");
    let outcome = match plan(view, input, op, records) {
        Ok(targets) => {
            apply(view, input, op, &targets, queues);
            StepOutcome::Applied
        }
        Err(refusal) => StepOutcome::Refused(refusal),
    };
    event(view, input, AssignmentAct::Responsibility(op), to, outcome);
}

fn plan_acknowledge(view: &CommitmentView, input: &Input<'_>) -> Result<bool, Refusal> {
    require(!view.items.is_empty(), Refusal::StateNotPermitted)?;
    require(!view.is_terminal(), Refusal::TerminalOutcome)?;
    let record = input.record;
    let who = params::acting(record);
    require(
        !(input.actor == Some(ActorType::Agent) && who == &record.core().author),
        Refusal::NotAccountable,
    )?;
    match params::digest(record, "proposal") {
        Some(proposal) => {
            let transfer = view
                .accountability
                .transfer
                .as_ref()
                .ok_or(Refusal::NothingPending)?;
            require(transfer.record == proposal, Refusal::WrongTarget)?;
            require(&transfer.to == who, Refusal::WrongRole)?;
            Ok(true)
        }
        None => {
            require(
                view.accountability.explicit.is_none(),
                Refusal::StateNotPermitted,
            )?;
            Ok(false)
        }
    }
}

/// Applies an `acknowledgement` in a commitment chain: an explicit taking-over of accountability while none is explicit, or the acceptance of the open transfer by the Party proposed; an agent never takes accountability (RC-5, RC-6, RC-7).
pub(super) fn acknowledge(view: &mut CommitmentView, input: &Input<'_>) {
    let outcome = match plan_acknowledge(view, input) {
        Ok(transferred) => {
            view.accountability.explicit = Some(Explicit {
                party: params::acting(input.record).clone(),
                record: input.id,
                source: if transferred {
                    AccountabilitySource::Transferred
                } else {
                    AccountabilitySource::TakenOver
                },
            });
            view.accountability.transfer = None;
            StepOutcome::Applied
        }
        Err(refusal) => StepOutcome::Refused(refusal),
    };
    event(view, input, AssignmentAct::Acknowledgement, None, outcome);
}

/// The validity check of a proposed responsibility record or `acknowledgement` against the commitment its chain derives: the author's role, the commitment's state and assignment, the queue's candidates and distribution policy, the lease, and Access, whose answer is needed for a `claim` like for every other operation since assignment grants no access (RC-17, RC-18, RC-20, RC-21, RC-25, RC-5, RC-7).
///
/// # Errors
///
/// The [`Refusal`] of the first rule that fails.
pub fn check_responsibility(
    view: &CommitmentView,
    proposed: &Proposed<'_>,
    records: &dyn Records,
) -> Result<AssignmentAct, Refusal> {
    let input = Input::proposed(proposed);
    let act = match act_of(proposed.record) {
        Some(Act::Responsibility(op)) => {
            plan(view, &input, op, records)?;
            AssignmentAct::Responsibility(op)
        }
        Some(Act::Acknowledgement) => {
            plan_acknowledge(view, &input)?;
            AssignmentAct::Acknowledgement
        }
        Some(Act::Commitment(_)) | None => return Err(Refusal::NotAResponsibilityOperation),
    };
    match proposed.access {
        AccessAnswer::Allow => Ok(act),
        AccessAnswer::Deny => Err(Refusal::AccessDenied),
        AccessAnswer::Require => Err(Refusal::AccessPending),
        AccessAnswer::StepUp if proposed.step_up => Ok(act),
        AccessAnswer::StepUp => Err(Refusal::StepUpRequired),
    }
}

/// One responsibility operation the caller may write now, with Access's answer and what is missing; a suggestion that the write checks again (RC-17, P-55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedResponsibility {
    /// The operation.
    pub operation: ResponsibilityOperation,
    /// What Access answers.
    pub access: AccessAnswer,
    /// What is still missing.
    pub missing: Vec<Missing>,
}

fn permitted(view: &CommitmentView, party: &PartyRef, op: ResponsibilityOperation) -> bool {
    let requested = whole(view, &[S::Requested]).is_ok();
    let owner = view.assignment.owned_by(party) == Some(true);
    let hold = view.assignment.hold.as_ref();
    match op {
        ResponsibilityOperation::Claim => {
            pooled(view) && requested && claim_allowed(view) && may_take(view, party)
        }
        ResponsibilityOperation::Unclaim => {
            view.assignment.queue.is_some()
                && is_obligor(view, party)
                && hold.is_some_and(|h| !h.binding)
                && whole(view, &[S::Promised]).is_ok()
        }
        ResponsibilityOperation::Forward => pooled(view) && owner && requested,
        ResponsibilityOperation::Nominate => {
            owner || is_obligee(view, party) || explicit_is(view, party)
        }
        ResponsibilityOperation::Offer => {
            pooled(view) && owner && requested && view.assignment.offer.is_none()
        }
        ResponsibilityOperation::Reassign => {
            let role = owner
                || explicit_is(view, party)
                || is_obligee(view, party)
                || is_principal(view, party);
            let state = if pooled(view) {
                requested
            } else {
                view.pending.delegation.is_none()
                    && whole(view, &[S::ConditionallyPromised, S::Promised]).is_ok()
            };
            role && state
        }
        ResponsibilityOperation::RenewLease => {
            is_obligor(view, party) && hold.is_some_and(|h| h.lease.is_some())
        }
    }
}

/// The responsibility operations the caller may write now, from its roles, the commitment's state and assignment, and Access's answer from `access` (RC-17, P-55).
#[must_use]
pub fn allowed_responsibility(
    view: &CommitmentView,
    caller: &Caller<'_>,
    access: &dyn Fn(ResponsibilityOperation) -> AccessAnswer,
) -> Vec<AllowedResponsibility> {
    if view.items.is_empty() || view.is_terminal() {
        return Vec::new();
    }
    ResponsibilityOperation::ALL
        .iter()
        .copied()
        .filter(|op| permitted(view, caller.party, *op))
        .map(|operation| {
            let answer = access(operation);
            let missing = match answer {
                AccessAnswer::Allow => Vec::new(),
                AccessAnswer::Deny => Vec::from([Missing::AccessDenied]),
                AccessAnswer::Require => Vec::from([Missing::AccessPending]),
                AccessAnswer::StepUp if caller.step_up => Vec::new(),
                AccessAnswer::StepUp => Vec::from([Missing::StepUp]),
            };
            AllowedResponsibility {
                operation,
                access: answer,
                missing,
            }
        })
        .collect()
}
