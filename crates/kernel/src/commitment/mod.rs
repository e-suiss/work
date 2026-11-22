//! The commitment lifecycle (§9): the thirteen closed states, the closed operation set with its author, state, result and content table, a pure fold that derives each commitment per item from its Declarations in ledger order without storing a state, the validity check, the allowed next transitions, the next move, the implicit acceptance rule, multi-party aggregation, the support chain and the end of `commitment.active` (CM-1…CM-60, E-8, E-12).

mod aggregate;
mod fold;
mod operation;
mod params;
mod state;
mod support;
mod transitions;
mod view;

pub use aggregate::{
    AggregateError, AggregateOutcome, AggregateStatus, AggregationPolicy, Answer, aggregate, needed,
};
pub use fold::{
    AccessAnswer, Facts, ImplicitAcceptance, Policy, Proposed, Records, check, derive_commitments,
    implicit_acceptance, offer_gaps,
};
pub use operation::{Actor, Content, Operation, OperationRule, Permit, RULES, Transition};
pub use state::{CommitmentState, Summary};
pub use support::{SupportCause, SupportSignal, support_chain, support_signals};
pub use transitions::{Allowed, Caller, Missing, Mover, allowed, next_moves};
pub use view::{
    ActiveEnd, ActiveEndCause, Address, Closing, CommitmentView, Deadline, Deferral, EvidenceRule,
    ImplicitTerms, Initiator, Item, Notice, OfferField, Pending, Precondition, Proposal, Refusal,
    Revocation, RevocationKind, Statement, Step, StepOutcome, TermChange, Terms,
};
