use alloc::vec::Vec;

use super::fold::{AccessAnswer, Facts, counterparty};
use super::operation::{Actor, Operation, Permit, RULES, Transition};
use super::state::CommitmentState;
use super::view::{Address, CommitmentView, RevocationKind};
use crate::catalog::ProposalStep;
use crate::id::{PartyRef, RecordId};
use crate::ontology::Obligor;
use crate::validate::ActorType;

/// The Party asking which transitions it may make now (P-55).
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    /// The Party it acts as.
    pub party: &'a PartyRef,
    /// Its Access actor type.
    pub actor: ActorType,
    /// Whether its Access authentication carries a step-up.
    pub step_up: bool,
}

/// What a transition still needs (P-55, CM-40).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missing {
    /// An Access step-up, for a high impact acceptance or because Access asks for it.
    StepUp,
    /// An open gate among the commitment's Conditions.
    Gate(RecordId),
    /// Access denies it.
    AccessDenied,
    /// An Access requirement is outstanding.
    AccessPending,
}

/// One transition the caller may make now, with Access's answer and what is missing; a suggestion that the write checks again (CM-19, P-55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowed {
    /// The operation.
    pub operation: Operation,
    /// The record of a two-record operation this is (CM-44).
    pub step: Option<ProposalStep>,
    /// The items it applies to.
    pub items: Vec<u16>,
    /// What Access answers.
    pub access: AccessAnswer,
    /// What is still missing.
    pub missing: Vec<Missing>,
}

fn roles(view: &CommitmentView, caller: &Caller<'_>) -> Vec<Actor> {
    let party = caller.party;
    let obligor = matches!(&view.obligor, Obligor::Party(o) if o == party);
    let proposed = [&view.pending.delegation, &view.pending.transfer]
        .into_iter()
        .flatten()
        .any(|p| &p.to == party);
    let counter = view
        .pending
        .revocation
        .as_ref()
        .and_then(|r| counterparty(view, r.kind))
        .is_some_and(|c| c == party);
    let checks = [
        (&view.obligee == party, Actor::Obligee),
        (
            obligor || matches!(view.obligor, Obligor::Queue(_)),
            Actor::ObligorCandidate,
        ),
        (obligor, Actor::Obligor),
        (&view.acceptor == party, Actor::Acceptor),
        (view.principal.contains(party), Actor::Principal),
        (counter, Actor::Counterparty),
        (proposed, Actor::ProposedParty),
        (caller.actor == ActorType::System, Actor::WorkService),
        (true, Actor::Authorised),
    ];
    checks
        .into_iter()
        .filter(|(held, _)| *held)
        .map(|(_, actor)| actor)
        .collect()
}

fn step_of(op: Operation, permit: &Permit) -> Option<ProposalStep> {
    match (op, permit.to) {
        (Operation::Delegate | Operation::Assign, Transition::Opens) => {
            Some(ProposalStep::Proposal)
        }
        (Operation::Delegate | Operation::Assign, _) => Some(ProposalStep::Acceptance),
        _ => None,
    }
}

fn pending_for(view: &CommitmentView, op: Operation, permit: &Permit, party: &PartyRef) -> bool {
    let pending = &view.pending;
    match (op, permit.to) {
        (Operation::Promise | Operation::Counter, Transition::Answers | Transition::Opens) => {
            pending.amendment.is_some()
        }
        (Operation::AcceptCounter, _) => pending.counter.is_some(),
        (Operation::Accept | Operation::Reject, _) => view.statement.is_some(),
        (Operation::Resume, _) => view.deferral.is_some(),
        (Operation::Defer, _) => view.deferral.is_none(),
        (
            Operation::RevokeRequest
            | Operation::RevokePromise
            | Operation::RevokeStatement
            | Operation::RevokeAcceptance,
            _,
        ) => pending.revocation.is_none(),
        (Operation::Allow | Operation::Refuse, Transition::Answers)
            if permit.by.contains(&Actor::Counterparty) =>
        {
            pending.revocation.is_some()
        }
        (Operation::Refuse, _) => pending.amendment.is_some(),
        (Operation::Dispute, _) => {
            !view.rejected.is_empty()
                || pending
                    .revocation
                    .as_ref()
                    .is_some_and(|r| r.kind == RevocationKind::Acceptance)
        }
        (Operation::Delegate, Transition::Opens) => pending.delegation.is_none(),
        (Operation::Delegate, _) => pending.delegation.as_ref().is_some_and(|p| &p.to == party),
        (Operation::Assign, Transition::Opens) => pending.transfer.is_none(),
        (Operation::Assign, _) => pending.transfer.as_ref().is_some_and(|p| &p.to == party),
        (Operation::Expire, _) => view.terms.respond_by.is_some() || view.precondition.is_some(),
        _ => true,
    }
}

fn applies(view: &CommitmentView, op: Operation, permit: &Permit) -> Vec<u16> {
    let terminal_ok = matches!(
        op,
        Operation::RevokeAcceptance | Operation::Allow | Operation::Refuse | Operation::Dispute
    );
    if view.is_terminal() && !terminal_ok {
        return Vec::new();
    }
    view.items
        .iter()
        .filter(|i| permit.from.contains(&i.state))
        .map(|i| i.index)
        .collect()
}

fn missing(
    view: &CommitmentView,
    op: Operation,
    caller: &Caller<'_>,
    access: AccessAnswer,
    open_gates: &[RecordId],
) -> Vec<Missing> {
    let mut out = Vec::new();
    match access {
        AccessAnswer::Allow => {}
        AccessAnswer::Deny => out.push(Missing::AccessDenied),
        AccessAnswer::Require => out.push(Missing::AccessPending),
        AccessAnswer::StepUp if caller.step_up => {}
        AccessAnswer::StepUp => out.push(Missing::StepUp),
    }
    let high = op == Operation::Accept && view.terms.high_impact && !caller.step_up;
    if high && !out.contains(&Missing::StepUp) {
        out.push(Missing::StepUp);
    }
    let gated = matches!(
        op,
        Operation::Promise | Operation::PromiseConditional | Operation::State | Operation::Accept
    );
    if gated {
        out.extend(
            open_gates
                .iter()
                .filter(|g| view.conditions.contains(g))
                .map(|g| Missing::Gate(*g)),
        );
    }
    out
}

/// The transitions the caller may make now, from the operation table and the commitment's derived state (CM-19, P-55): for each, the items it applies to, Access's answer from `access`, and what is still missing, such as a step-up or one of `open_gates`; the client never recomputes the rules, and the write checks them again.
#[must_use]
pub fn allowed(
    view: &CommitmentView,
    caller: &Caller<'_>,
    open_gates: &[RecordId],
    access: &dyn Fn(Operation) -> AccessAnswer,
) -> Vec<Allowed> {
    let held = roles(view, caller);
    let mut out: Vec<Allowed> = Vec::new();
    if view.items.is_empty() {
        return out;
    }
    for rule in RULES {
        let op = rule.operation;
        if op == Operation::Request {
            continue;
        }
        for permit in rule.permits {
            if !permit.by.iter().any(|a| held.contains(a))
                || !pending_for(view, op, permit, caller.party)
            {
                continue;
            }
            let items = applies(view, op, permit);
            if items.is_empty() {
                continue;
            }
            let step = step_of(op, permit);
            if let Some(entry) = out.iter_mut().find(|a| a.operation == op && a.step == step) {
                for item in items {
                    if !entry.items.contains(&item) {
                        entry.items.push(item);
                    }
                }
                continue;
            }
            let answer = access(op);
            out.push(Allowed {
                operation: op,
                step,
                items,
                access: answer,
                missing: missing(view, op, caller, answer, open_gates),
            });
        }
    }
    out
}

/// Who holds the next move on a commitment (CM-58).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mover {
    /// A Party.
    Party(PartyRef),
    /// The queue owner of a commitment without an obligor yet.
    Queue(RecordId),
    /// The Party or address a precondition is addressed to.
    Address(Address),
    /// The precondition's addressee, whose record is not known here.
    PreconditionAddressee(RecordId),
    /// The accountable Party, once the budget is exhausted.
    Accountable,
}

fn push(out: &mut Vec<Mover>, mover: Mover) {
    if !out.contains(&mover) {
        out.push(mover);
    }
}

fn obligor_mover(view: &CommitmentView) -> Mover {
    match &view.obligor {
        Obligor::Party(p) => Mover::Party(p.clone()),
        Obligor::Queue(q) => Mover::Queue(*q),
    }
}

/// Who holds the next move, derived from the state (CM-58): an open revocation request is the counterparty's, a pending terms amendment the obligor's and a pending proposal the proposed Party's; then by item state `requested` the obligor candidate, the Party pooled work is offered to, or the queue (RC-17), `countered` the obligee, `conditionally_promised` the precondition's addressee, `promised` the obligor and `stated` the acceptor; an exhausted budget is the accountable Party's.
#[must_use]
pub fn next_moves(view: &CommitmentView, facts: &Facts<'_>) -> Vec<Mover> {
    let mut out = Vec::new();
    if let Some(revocation) = &view.pending.revocation
        && let Some(party) = counterparty(view, revocation.kind)
    {
        push(&mut out, Mover::Party(party.clone()));
    }
    if view.pending.amendment.is_some() {
        push(&mut out, obligor_mover(view));
    }
    for proposal in [&view.pending.delegation, &view.pending.transfer]
        .into_iter()
        .flatten()
    {
        push(&mut out, Mover::Party(proposal.to.clone()));
    }
    for item in view.open_items() {
        let mover = match item.state {
            CommitmentState::Requested => match (&view.obligor, &view.assignment.offer) {
                (Obligor::Queue(_), Some(offer)) => Mover::Party(offer.to.clone()),
                _ => obligor_mover(view),
            },
            CommitmentState::Promised => obligor_mover(view),
            CommitmentState::Countered => Mover::Party(view.obligee.clone()),
            CommitmentState::Stated => Mover::Party(view.acceptor.clone()),
            _ => match &view.precondition {
                Some(p) => p
                    .address
                    .clone()
                    .map_or(Mover::PreconditionAddressee(p.condition), Mover::Address),
                None => obligor_mover(view),
            },
        };
        push(&mut out, mover);
    }
    if facts.budget_exhausted && !view.is_terminal() {
        push(&mut out, Mover::Accountable);
    }
    out
}
