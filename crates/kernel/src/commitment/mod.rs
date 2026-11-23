//! The commitment lifecycle (§9): the thirteen closed states, the closed operation set with its author, state, result and content table, a pure fold that derives each commitment per item from its Declarations in ledger order without storing a state, the validity check, the allowed next transitions, the next move, the implicit acceptance rule, multi-party aggregation, the support chain, the time Conditions, the end of `commitment.active`, and the responsibility operations and accountability records folded into the same lifecycle (CM-1…CM-64, E-8, E-12, RC-5, RC-7, RC-17…RC-20).

mod aggregate;
mod fold;
mod operation;
pub(crate) mod params;
mod responsibility;
mod state;
mod support;
mod timing;
mod transitions;
mod view;

pub use aggregate::{
    AggregateError, AggregateOutcome, AggregateStatus, AggregationPolicy, Answer, aggregate, needed,
};
pub use fold::{
    AccessAnswer, Facts, ImplicitAcceptance, Policy, Proposed, Records, active_ends_of, check,
    derive_commitments, implicit_acceptance, offer_gaps,
};
pub use operation::{Actor, Content, Operation, OperationRule, Permit, RULES, Transition};
pub use responsibility::{AllowedResponsibility, allowed_responsibility, check_responsibility};
pub use state::{CommitmentState, Summary};
pub use support::{SupportCause, SupportSignal, support_chain, support_signals};
pub use timing::{
    BudgetProjection, ClockProjection, Definition, Definitions, MAX_DEPTH, MAX_DUE,
    PeriodicProjection, REPORT_EXT_KEY, REPORT_PARTS, TimeInputs, TimeProjection, clock_events,
    clock_signals, condition_of, definition_records, event_names, project as project_time,
    zones_named,
};
pub use transitions::{Allowed, Caller, Missing, Mover, allowed, next_moves};
pub use view::{
    ActiveEnd, ActiveEndCause, Address, Closing, CommitmentView, Deadline, Deferral, EvidenceRule,
    ImplicitTerms, Initiator, Item, Notice, OfferField, Pending, Precondition, Proposal, Refusal,
    Revocation, RevocationKind, Statement, Step, StepOutcome, TermChange, Terms,
};
