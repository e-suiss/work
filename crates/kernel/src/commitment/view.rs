use alloc::vec::Vec;

use super::aggregate::AggregationPolicy;
use super::operation::Operation;
use super::state::{CommitmentState, Summary};
use crate::catalog::{ChangePolicy, CommitmentKind, NoticeType};
use crate::id::{PartyRef, RecordId, Time};
use crate::ontology::Obligor;
use crate::reason::wire_enum;
use crate::uri::TypeUri;

wire_enum! {
    /// Why the derivation or the validity check refuses an operation; the record stays recorded and visible, it only has no effect on the commitment (CM-19, CM-34).
    Refusal {
        /// The record is no commitment Declaration.
        NotACommitmentOperation => "not_a_commitment_operation",
        /// The author is not in a role the operation permits.
        WrongRole => "wrong_role",
        /// The commitment is not in a state the operation permits.
        StateNotPermitted => "state_not_permitted",
        /// Every item reached a terminal outcome, which never changes (CM-34).
        TerminalOutcome => "terminal_outcome",
        /// Required content is missing (CM-17).
        MissingContent => "missing_content",
        /// The record names a counter-offer, statement, proposal, revocation, deferral or record that is not the open one.
        WrongTarget => "wrong_target",
        /// The record names an item the commitment does not have.
        UnknownItem => "unknown_item",
        /// There is nothing open for the record to answer.
        NothingPending => "nothing_pending",
        /// A request or proposal of this kind is already open.
        AlreadyPending => "already_pending",
        /// The declared time or event the record relies on has not come (CM-31, CM-41).
        NotYetDue => "not_yet_due",
        /// The four-eyes rule forbids this acceptor (CM-38).
        FourEyes => "four_eyes",
        /// The acceptance needs evidence references (CM-27).
        EvidenceRequired => "evidence_required",
        /// The commitment is marked high impact and the acceptance carries no Access step-up (CM-40, CM-60).
        StepUpRequired => "step_up_required",
        /// An offer with an agent side lacks one of its six fields (CM-7).
        IncompleteOffer => "incomplete_offer",
        /// Institution policy forbids waiving four eyes (CM-39).
        WaiverForbidden => "waiver_forbidden",
        /// The executor declares no control capability for this change policy (CM-57).
        ControlNotSupported => "control_not_supported",
        /// Access denies the author this operation (CM-19).
        AccessDenied => "access_denied",
        /// An Access requirement is still outstanding (CM-19).
        AccessPending => "access_pending",
        /// The acceptance does not say whether the acceptance criterion was undefined as the offer left it (CM-7).
        CriterionUndefined => "criterion_undefined",
        /// The commitment type's own rule is not met (CM-9, CM-10, CM-11, CM-46).
        KindRequirement => "kind_requirement",
    }
}

wire_enum! {
    /// The six fields of an offer (CM-7).
    OfferField {
        /// An Aim reference or a one-sentence purpose.
        Purpose => "purpose",
        /// The expected form of delivery.
        Delivery => "delivery",
        /// What is in and out of scope.
        Scope => "scope",
        /// The acceptance criterion.
        AcceptanceCriterion => "acceptance_criterion",
        /// The acceptor.
        Acceptor => "acceptor",
        /// The due time.
        Due => "due",
    }
}

wire_enum! {
    /// Who started a terminal outcome (CM-30).
    Initiator {
        /// The obligor.
        Obligor => "obligor",
        /// The obligee.
        Obligee => "obligee",
        /// The acceptor.
        Acceptor => "acceptor",
        /// A principal of the obligee side.
        Principal => "principal",
        /// An administrative Party.
        Administrator => "administrator",
        /// The Work service Party.
        WorkService => "work_service",
    }
}

wire_enum! {
    /// The four revocation requests (CM-35).
    RevocationKind {
        /// Of the request, by the obligee.
        Request => "request",
        /// Of the promise, by the obligor.
        Promise => "promise",
        /// Of the statement, by the obligor.
        Statement => "statement",
        /// Of the acceptance, by the acceptor.
        Acceptance => "acceptance",
    }
}

wire_enum! {
    /// Why the obligor's `commitment.active` ends (E-8, E-12).
    ActiveEndCause {
        /// The debt passed to a new obligor.
        Delegated => "delegated",
        /// The commitment reached a terminal outcome.
        Closed => "closed",
    }
}

/// One item of a commitment and its derived state (CM-23).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The item number, from 0.
    pub index: u16,
    /// The derived state.
    pub state: CommitmentState,
    /// The record and initiator of a terminal outcome.
    pub closing: Option<Closing>,
}

/// The record that closed an item and who started it (CM-30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Closing {
    /// The closing record.
    pub record: RecordId,
    /// Who started it.
    pub initiator: Initiator,
}

/// A declared deadline and the record that declared it (CM-24, CM-31).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    /// The deadline.
    pub at: Time,
    /// The record whose validity it is.
    pub declared_by: RecordId,
}

/// Whether accepting needs evidence: by the declared criterion, or because the Aim is truth-based (CM-27).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EvidenceRule {
    /// The acceptance criterion asks for evidence.
    pub declared: bool,
    /// The Aim is judged by truth, not by a Party.
    pub truth_aim: bool,
}

/// The terms in force (CM-6…CM-9, CM-57, CM-60).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The commitment type.
    pub kind: CommitmentKind,
    /// The number of items, at least one.
    pub item_count: u16,
    /// The due time.
    pub due: Option<Time>,
    /// The answer deadline of the open offer (CM-24).
    pub respond_by: Option<Deadline>,
    /// Whether accepting needs evidence.
    pub evidence: EvidenceRule,
    /// The explicit high impact mark (CM-60).
    pub high_impact: bool,
    /// The obligee's four-eyes waiver (CM-39).
    pub four_eyes_waived: bool,
    /// How instruction changes reach running work (CM-57).
    pub change_policy: ChangePolicy,
    /// The multi-party aggregation policy (CM-54).
    pub aggregation: Option<AggregationPolicy>,
    /// The offer fields left undefined, visible as such (CM-7).
    pub undefined: Vec<OfferField>,
}

/// Changed terms a counter-offer or terms amendment carries, applied when accepted (CM-21, CM-56).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TermChange {
    /// The counter-offer or amendment.
    pub record: RecordId,
    /// The Party it speaks for.
    pub by: PartyRef,
    /// A new acceptor (CM-37).
    pub acceptor: Option<PartyRef>,
    /// New Conditions.
    pub conditions: Option<Vec<RecordId>>,
    /// A new due time.
    pub due: Option<Time>,
    /// A new evidence requirement.
    pub evidence_required: Option<bool>,
    /// A new high impact mark (CM-60).
    pub high_impact: Option<bool>,
    /// A new number of items.
    pub item_count: Option<u16>,
    /// A new answer deadline.
    pub respond_by: Option<Time>,
    /// The offer fields it defines.
    pub defines: Vec<OfferField>,
}

/// An open revocation request (CM-35).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// The request.
    pub record: RecordId,
    /// Its kind.
    pub kind: RevocationKind,
}

/// An open delegation or assignment proposal (CM-43, CM-44).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The proposal.
    pub record: RecordId,
    /// The Party proposed.
    pub to: PartyRef,
}

/// What is open and waits for the other side.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Pending {
    /// The open counter-offer (CM-21).
    pub counter: Option<TermChange>,
    /// The open terms amendment (CM-56).
    pub amendment: Option<TermChange>,
    /// The open revocation request (CM-35).
    pub revocation: Option<Revocation>,
    /// The open delegation proposal (CM-44).
    pub delegation: Option<Proposal>,
    /// The open assignment proposal (CM-43).
    pub assignment: Option<Proposal>,
}

/// The statement in force (CM-25…CM-28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// The `state` record.
    pub record: RecordId,
    /// Its ledger time; the implicit acceptance window starts here (CM-41).
    pub recorded_at: Time,
    /// The items stated.
    pub items: Vec<u16>,
    /// Whether it carries evidence; without, it shows as stated without evidence (CM-27).
    pub evidenced: bool,
    /// Whether an agent wrote it, which the four-eyes rule guards (CM-38).
    pub by_agent: bool,
    /// The agent and the Parties that launched it (CM-38).
    pub chain: Vec<PartyRef>,
}

/// An open deferral (CM-17, ST-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deferral {
    /// The `defer` record.
    pub record: RecordId,
    /// The declared return time.
    pub resume_at: Option<Time>,
    /// The declared return event, a Condition.
    pub resume_on: Option<RecordId>,
}

/// The obligee's prior explicit implicit acceptance terms in force (CM-41).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImplicitTerms {
    /// The `implicit_acceptance_terms` record.
    pub record: RecordId,
    /// The window after the statement, in milliseconds.
    pub window: u64,
    /// The items covered; `None` for every item.
    pub items: Option<Vec<u16>>,
    /// The declarer and its principals, whom the four-eyes rule also guards (CM-42).
    pub declarer: Vec<PartyRef>,
}

/// Where a precondition is addressed (ST-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// A Party.
    Party(PartyRef),
    /// A typed external address.
    Uri(TypeUri),
}

/// The precondition of a conditional promise (CM-22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Precondition {
    /// The `promise_conditional` record.
    pub record: RecordId,
    /// The `open_condition` record.
    pub condition: RecordId,
    /// The validity; past it unmet, the commitment can expire.
    pub valid_until: Time,
    /// Where the Condition is addressed, when its record is known.
    pub address: Option<Address>,
}

/// A notice the obligor gave (CM-58).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The `notice` record.
    pub record: RecordId,
    /// Its type.
    pub notice_type: NoticeType,
}

/// The end of an obligor's `commitment.active`, which Work publishes as a `false` Claim; Work only ends it, never starts it (E-8, E-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveEnd {
    /// The obligor whose commitment is no longer active.
    pub obligor: PartyRef,
    /// The record that ended it.
    pub record: RecordId,
    /// Why.
    pub cause: ActiveEndCause,
}

/// The result of one commitment record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// The record took effect.
    Applied,
    /// The record is refused, with a reason; it stays recorded (CM-19).
    Refused(Refusal),
}

/// One commitment record and its result, in ledger order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    /// The record.
    pub record: RecordId,
    /// The operation.
    pub operation: Operation,
    /// Its result.
    pub outcome: StepOutcome,
}

/// A commitment as its records derive it; no field is stored, every one is recomputed from the records (CM-2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentView {
    /// The `request` that opened it, its identity (P-112).
    pub root: RecordId,
    /// Whether the request itself took effect.
    pub opening: StepOutcome,
    /// The obligee in force, after any assignment (CM-43).
    pub obligee: PartyRef,
    /// The obligor in force, after any delegation (CM-44), or the queue.
    pub obligor: Obligor,
    /// The acceptor in force (CM-37).
    pub acceptor: PartyRef,
    /// The `on_behalf_of` chain of the request (CM-5).
    pub principal: Vec<PartyRef>,
    /// The requester and its principals, whom the four-eyes rule guards (CM-38).
    pub requester: Vec<PartyRef>,
    /// The Aim.
    pub aim: Option<RecordId>,
    /// The Conditions in force.
    pub conditions: Vec<RecordId>,
    /// The parent commitments it supports (CM-46).
    pub supports: Vec<RecordId>,
    /// The items and their states (CM-23).
    pub items: Vec<Item>,
    /// The terms in force.
    pub terms: Terms,
    /// The offer version, raised by every counter-offer and terms change in the offer phase (CM-21).
    pub offer_version: u32,
    /// The instruction version, raised by every instruction change (CM-56).
    pub instruction_version: u32,
    /// What waits for the other side.
    pub pending: Pending,
    /// The statement in force.
    pub statement: Option<Statement>,
    /// The implicit acceptance terms in force (CM-41).
    pub implicit: Option<ImplicitTerms>,
    /// The precondition of a conditional promise (CM-22).
    pub precondition: Option<Precondition>,
    /// The open deferral.
    pub deferral: Option<Deferral>,
    /// Consecutive rejections since the last acceptance (CM-26).
    pub rejections: u32,
    /// Every rejection, which a dispute may name (CM-26, CM-36).
    pub rejected: Vec<RecordId>,
    /// The records that raised the dispute marker: disputes and refused revocations (CM-36).
    pub disputes: Vec<RecordId>,
    /// An allowed revocation of acceptance, from which a reopening commitment may derive (CM-35).
    pub reopening: Option<RecordId>,
    /// Records the statements cited as fulfilling it (CM-25).
    pub fulfilments: Vec<RecordId>,
    /// The notices given (CM-58).
    pub notices: Vec<Notice>,
    /// The accepted delegations (CM-44).
    pub handovers: Vec<RecordId>,
    /// The ends of `commitment.active` to publish (E-8, E-12).
    pub active_ends: Vec<ActiveEnd>,
    /// Every commitment record after the request and its result, in ledger order.
    pub steps: Vec<Step>,
}

impl CommitmentView {
    /// The commitment-level summary of its items (CM-23).
    #[must_use]
    pub fn summary(&self) -> Summary {
        let mut states = self.items.iter().map(|i| i.state);
        match states.next() {
            Some(first) if states.all(|s| s == first) => Summary::Uniform(first),
            Some(_) => Summary::Mixed,
            None => Summary::Uniform(CommitmentState::Requested),
        }
    }

    /// Whether every item reached a terminal outcome (CM-34).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !self.items.is_empty() && self.items.iter().all(|i| i.state.is_terminal())
    }

    /// The items that are not terminal.
    pub fn open_items(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| !i.state.is_terminal())
    }

    /// The state of one item.
    #[must_use]
    pub fn state_of(&self, index: u16) -> Option<CommitmentState> {
        self.items
            .iter()
            .find(|i| i.index == index)
            .map(|i| i.state)
    }

    /// Whether the dispute marker is raised; it is no state (CM-36).
    #[must_use]
    pub fn disputed(&self) -> bool {
        !self.disputes.is_empty()
    }

    /// Whether the statement in force carries no evidence: stated, without evidence (CM-27).
    #[must_use]
    pub fn unevidenced(&self) -> bool {
        self.statement.as_ref().is_some_and(|s| !s.evidenced)
    }

    /// Whether a deferral is open, which makes the summary category `deferred` (ST-7).
    #[must_use]
    pub const fn deferred(&self) -> bool {
        self.deferral.is_some()
    }

    /// Whether accepting needs evidence under the terms and the policy input (CM-27).
    #[must_use]
    pub const fn evidence_required(&self, policy_requires: bool) -> bool {
        self.terms.evidence.declared || self.terms.evidence.truth_aim || policy_requires
    }
}
