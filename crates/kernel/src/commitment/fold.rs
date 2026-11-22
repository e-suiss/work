use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::aggregate::AggregationPolicy;
use super::operation::Operation;
use super::params;
use super::state::CommitmentState as S;
use super::view::{
    ActiveEnd, ActiveEndCause, Address, Closing, CommitmentView, Deadline, Deferral, EvidenceRule,
    ImplicitTerms, Initiator, Item, Notice, OfferField, Pending, Precondition, Proposal, Refusal,
    Revocation, RevocationKind, Statement, Step, StepOutcome, TermChange, Terms,
};
use crate::catalog::{
    AggregationRule, AmendmentChange, ChangePolicy, CommitmentKind, DeclarationSubtype, NoticeType,
    ProposalStep,
};
use crate::derive::{Derivation, Effect, Entry};
use crate::id::{PartyRef, RecordId, Time};
use crate::ontology::{Aim, Commitment, Evaluation, Obligor};
use crate::reason::wire_enum;
use crate::record::Record;
use crate::uri::TypeUri;
use crate::validate::ActorType;

/// Policy inputs the commitment rules read (CM-27, CM-39, P-31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Policy {
    /// Institution policy asks for evidence on every acceptance.
    pub evidence_required: bool,
    /// Institution policy forbids waiving four eyes.
    pub four_eyes_waiver_forbidden: bool,
}

/// Facts besides the records that the commitment derivation depends on (P-31).
#[derive(Clone, Copy, Debug, Default)]
pub struct Facts<'a> {
    /// Conditions met, each with the ledger position of the record that met it; the Condition lifecycle derives them, and a Condition absent here is unmet (CM-22, CM-17).
    pub conditions_met: &'a [(RecordId, u64)],
    /// The policy inputs.
    pub policy: Policy,
    /// Whether the budget Condition is exhausted, which hands the next move to the accountable Party (CM-49, CM-58).
    pub budget_exhausted: bool,
}

/// Records by identifier, for the rules that read another record: the Aim, a precondition's address (CM-22, CM-27).
pub trait Records {
    /// The record with this identifier, if known.
    fn record(&self, id: &RecordId) -> Option<&Record>;
}

impl Records for BTreeMap<RecordId, &Record> {
    fn record(&self, id: &RecordId) -> Option<&Record> {
        self.get(id).copied()
    }
}

wire_enum! {
    /// What Access answers for an operation; an input to the validity check and the allowed transitions (CM-19, P-55).
    AccessAnswer {
        /// Allowed.
        Allow => "allow",
        /// Denied.
        Deny => "deny",
        /// Allowed after a step-up.
        StepUp => "step_up",
        /// A requirement is outstanding.
        Require => "require",
    }
}

/// A record proposed for writing and the facts its validity needs besides its bytes (CM-19).
#[derive(Clone, Copy, Debug)]
pub struct Proposed<'r> {
    /// The identifier the record will have.
    pub id: RecordId,
    /// The record.
    pub record: &'r Record,
    /// The ledger position it will take.
    pub position: u64,
    /// The ledger time it will take.
    pub recorded_at: Time,
    /// The author's Access actor type.
    pub author_actor: ActorType,
    /// Whether the author's Access authentication carries a step-up.
    pub step_up: bool,
    /// What Access answers for the author and this operation.
    pub access: AccessAnswer,
    /// Whether a side of the commitment is an agent, which makes the six offer fields required (CM-7).
    pub agent_side: bool,
    /// Whether the executor declares the control capability `interrupt` and `rollback` need (CM-57).
    pub control_supported: bool,
}

/// How the implicit acceptance of the statement in force stands at a ledger time (CM-41, CM-42).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImplicitAcceptance {
    /// Nothing is stated.
    NotStated,
    /// No prior explicit terms: silence is no acceptance, the commitment awaits acceptance.
    NoTerms,
    /// The window ends at this time.
    Waiting(Time),
    /// The window ended and the Work service may write the implicit `accept`.
    Due,
    /// The window ended but the acceptance cannot be implicit; the commitment awaits acceptance, time passed (CM-42).
    Blocked(Refusal),
}

struct Input<'r> {
    id: RecordId,
    record: &'r Record,
    position: u64,
    recorded_at: Time,
    actor: Option<ActorType>,
    step_up: bool,
}

impl<'r> Input<'r> {
    fn of(entry: &Entry<'r>) -> Self {
        Self {
            id: entry.id(),
            record: entry.record(),
            position: entry.position(),
            recorded_at: entry.recorded_at(),
            actor: entry.author_actor(),
            step_up: entry.step_up(),
        }
    }

    fn service(&self) -> bool {
        self.actor == Some(ActorType::System)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    Amendment,
    ByObligee,
    Proposal,
    Acceptance,
    Implicit,
    Instruction,
    TermsNow,
    TermsPending,
    Withdraw,
}

struct Plan {
    targets: Vec<u16>,
    mode: Mode,
}

impl Plan {
    const fn new(targets: Vec<u16>, mode: Mode) -> Self {
        Self { targets, mode }
    }
}

fn operation_of(record: &Record) -> Option<Operation> {
    match record {
        Record::Declaration(d) => {
            DeclarationSubtype::from_uri(d.subtype.as_str()).and_then(Operation::of)
        }
        Record::Act(_) | Record::Claim(_) => None,
    }
}

/// The offer fields a `request` leaves undefined (CM-7): the purpose is an Aim or a `purpose` body part, delivery, scope and the acceptance criterion are body parts, the due time is `params.due`, and the acceptor is always written (CM-6).
#[must_use]
pub fn offer_gaps(request: &Record) -> Vec<OfferField> {
    let present = |field: OfferField| match field {
        OfferField::Purpose => {
            request.param("aim").is_some() || params::has_part(request, "purpose")
        }
        OfferField::Delivery => params::has_part(request, "delivery"),
        OfferField::Scope => params::has_part(request, "scope"),
        OfferField::AcceptanceCriterion => params::has_part(request, "acceptance_criterion"),
        OfferField::Acceptor => request.param("acceptor").is_some(),
        OfferField::Due => request.param("due").is_some(),
    };
    OfferField::ALL
        .iter()
        .copied()
        .filter(|f| !present(*f))
        .collect()
}

fn defined_fields(record: &Record) -> Vec<OfferField> {
    let mut out = Vec::new();
    let parts = [
        ("purpose", OfferField::Purpose),
        ("delivery", OfferField::Delivery),
        ("scope", OfferField::Scope),
        ("acceptance_criterion", OfferField::AcceptanceCriterion),
    ];
    for (part, field) in parts {
        if params::has_part(record, part) {
            out.push(field);
        }
    }
    if record.param("due").is_some() {
        out.push(OfferField::Due);
    }
    out
}

fn aggregation_of(record: &Record) -> Option<AggregationPolicy> {
    let rule = params::text(record, "aggregation").and_then(AggregationRule::from_wire_name)?;
    let threshold = match rule {
        AggregationRule::KOfN => params::uint(record, "aggregation_k"),
        AggregationRule::Percentage => params::uint(record, "aggregation_percent"),
        AggregationRule::All | AggregationRule::Any | AggregationRule::Sequential => Some(0),
    }?;
    Some(AggregationPolicy {
        rule,
        threshold: u32::try_from(threshold).ok()?,
        veto: params::flag(record, "aggregation_veto") == Some(true),
        participants: params::parties(record, "participants")?,
    })
}

fn item_count(record: &Record) -> u16 {
    params::uint(record, "item_count")
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}

fn opening_refusal(input: &Input<'_>, view: &CommitmentView) -> Option<Refusal> {
    let agent = input.actor == Some(ActorType::Agent);
    if agent && !view.terms.undefined.is_empty() {
        return Some(Refusal::IncompleteOffer);
    }
    let kind_ok = match view.terms.kind {
        CommitmentKind::Standard => true,
        CommitmentKind::SubCommitment => !view.supports.is_empty(),
        CommitmentKind::PeriodicUpdate | CommitmentKind::FollowUp => !view.conditions.is_empty(),
        CommitmentKind::HelpRequest => input.actor.is_none_or(|a| a == ActorType::Agent),
    };
    (!kind_ok).then_some(Refusal::KindRequirement)
}

fn open(input: &Input<'_>, records: &dyn Records) -> Option<CommitmentView> {
    let record = input.record;
    let core = Commitment::of(record)?;
    let truth_aim = core
        .aim
        .and_then(|a| records.record(&a))
        .and_then(Aim::of)
        .is_some_and(|a| a.evaluation == Evaluation::Truth);
    let count = item_count(record);
    let terms = Terms {
        kind: params::text(record, "commitment_kind")
            .and_then(CommitmentKind::from_wire_name)
            .unwrap_or(CommitmentKind::Standard),
        item_count: count,
        due: params::time(record, "due"),
        respond_by: params::time(record, "respond_by").map(|at| Deadline {
            at,
            declared_by: input.id,
        }),
        evidence: EvidenceRule {
            declared: params::flag(record, "evidence_required") == Some(true),
            truth_aim,
        },
        high_impact: params::flag(record, "high_impact") == Some(true),
        four_eyes_waived: params::flag(record, "four_eyes_waived") == Some(true),
        change_policy: params::text(record, "change_policy")
            .and_then(ChangePolicy::from_wire_name)
            .unwrap_or(ChangePolicy::Queue),
        aggregation: aggregation_of(record),
        undefined: offer_gaps(record),
    };
    let mut view = CommitmentView {
        root: input.id,
        opening: StepOutcome::Applied,
        obligee: core.obligee,
        obligor: core.obligor,
        acceptor: core.acceptor,
        principal: core.principal,
        requester: params::chain(record),
        aim: core.aim,
        conditions: core.conditions,
        supports: params::supported(record),
        items: Vec::new(),
        terms,
        offer_version: 0,
        instruction_version: 0,
        pending: Pending::default(),
        statement: None,
        implicit: None,
        precondition: None,
        deferral: None,
        rejections: 0,
        rejected: Vec::new(),
        disputes: Vec::new(),
        reopening: None,
        fulfilments: Vec::new(),
        notices: Vec::new(),
        handovers: Vec::new(),
        active_ends: Vec::new(),
        steps: Vec::new(),
    };
    if let Some(refusal) = opening_refusal(input, &view) {
        view.opening = StepOutcome::Refused(refusal);
    } else {
        view.items = (0..count)
            .map(|index| Item {
                index,
                state: S::Requested,
                closing: None,
            })
            .collect();
    }
    Some(view)
}

/// Folds the commitments of a derived ledger sequence (CM-2): every supersede chain rooted in a `request` is one commitment, and its records with normative effect apply in ledger order; a record the commitment rules refuse stays recorded with its reason and changes nothing (CM-19, CM-34). The same records give the same commitments everywhere.
#[must_use]
pub fn derive_commitments(
    entries: &[Entry<'_>],
    derivation: &Derivation,
    facts: &Facts<'_>,
) -> Vec<CommitmentView> {
    let records: BTreeMap<RecordId, &Record> =
        entries.iter().map(|e| (e.id(), e.record())).collect();
    let mut roots: BTreeMap<RecordId, RecordId> = BTreeMap::new();
    let mut slots: BTreeMap<RecordId, usize> = BTreeMap::new();
    let mut views: Vec<CommitmentView> = Vec::new();
    for (entry, derived) in entries.iter().zip(&derivation.records) {
        let counted = matches!(derived.effect, Effect::Normative | Effect::Conflicted);
        if derived.id != entry.id() || !counted || !matches!(entry.record(), Record::Declaration(_))
        {
            continue;
        }
        let root = match entry.record().supersedes().next() {
            None => entry.id(),
            Some(target) => match roots.get(target) {
                Some(root) => *root,
                None => continue,
            },
        };
        roots.insert(entry.id(), root);
        let Some(op) = operation_of(entry.record()) else {
            continue;
        };
        if derived.effect != Effect::Normative {
            continue;
        }
        let input = Input::of(entry);
        if root == entry.id() {
            if op == Operation::Request
                && let Some(view) = open(&input, &records)
            {
                slots.insert(root, views.len());
                views.push(view);
            }
        } else if let Some(view) = slots.get(&root).and_then(|&i| views.get_mut(i)) {
            step(view, &input, op, &records, facts);
        }
    }
    for view in &mut views {
        settle(view, facts, u64::MAX);
    }
    views
}

/// The validity check of a proposed commitment record against the commitment its chain derives (CM-19): the author is in a role the operation permits, the commitment is in a permitted state, the required content is there, and Access allows it; `view` is `None` for a `request`. The answer is a decision, never an error, and a refusal says why.
///
/// # Errors
///
/// The [`Refusal`] of the first rule that fails.
pub fn check(
    view: Option<&CommitmentView>,
    proposed: &Proposed<'_>,
    records: &dyn Records,
    facts: &Facts<'_>,
) -> Result<Operation, Refusal> {
    let op = operation_of(proposed.record).ok_or(Refusal::NotACommitmentOperation)?;
    let input = Input {
        id: proposed.id,
        record: proposed.record,
        position: proposed.position,
        recorded_at: proposed.recorded_at,
        actor: Some(proposed.author_actor),
        step_up: proposed.step_up,
    };
    let policy =
        params::text(proposed.record, "change_policy").and_then(ChangePolicy::from_wire_name);
    if matches!(
        policy,
        Some(ChangePolicy::Interrupt | ChangePolicy::Rollback)
    ) && !proposed.control_supported
    {
        return Err(Refusal::ControlNotSupported);
    }
    if params::flag(proposed.record, "four_eyes_waived") == Some(true)
        && facts.policy.four_eyes_waiver_forbidden
    {
        return Err(Refusal::WaiverForbidden);
    }
    match (op, view) {
        (Operation::Request, None) => {
            let opened = open(&input, records).ok_or(Refusal::MissingContent)?;
            if let StepOutcome::Refused(refusal) = opened.opening {
                return Err(refusal);
            }
            if proposed.agent_side && !opened.terms.undefined.is_empty() {
                return Err(Refusal::IncompleteOffer);
            }
        }
        (Operation::Request, Some(_)) => return Err(Refusal::StateNotPermitted),
        (_, None) => return Err(Refusal::NothingPending),
        (_, Some(view)) => {
            plan(view, &input, op, facts)?;
        }
    }
    match proposed.access {
        AccessAnswer::Allow => Ok(op),
        AccessAnswer::Deny => Err(Refusal::AccessDenied),
        AccessAnswer::Require => Err(Refusal::AccessPending),
        AccessAnswer::StepUp if proposed.step_up => Ok(op),
        AccessAnswer::StepUp => Err(Refusal::StepUpRequired),
    }
}

/// How the implicit acceptance of the statement in force stands at ledger time `now` (CM-41, CM-42): the window starts at the statement's ledger time; past it, the Work service writes an `accept` marked implicit only when no evidence, four-eyes or step-up rule blocks it.
#[must_use]
pub fn implicit_acceptance(
    view: &CommitmentView,
    now: Time,
    facts: &Facts<'_>,
) -> ImplicitAcceptance {
    let Some(statement) = &view.statement else {
        return ImplicitAcceptance::NotStated;
    };
    let Some(terms) = &view.implicit else {
        return ImplicitAcceptance::NoTerms;
    };
    let due = statement
        .recorded_at
        .0
        .checked_add(terms.window)
        .unwrap_or(u64::MAX);
    if now.0 < due {
        return ImplicitAcceptance::Waiting(Time(due));
    }
    if view.terms.high_impact {
        return ImplicitAcceptance::Blocked(Refusal::StepUpRequired);
    }
    if !four_eyes_ok(view, statement, &terms.declarer, facts) {
        return ImplicitAcceptance::Blocked(Refusal::FourEyes);
    }
    if view.evidence_required(facts.policy.evidence_required) && !statement.evidenced {
        return ImplicitAcceptance::Blocked(Refusal::EvidenceRequired);
    }
    ImplicitAcceptance::Due
}

fn step(
    view: &mut CommitmentView,
    input: &Input<'_>,
    op: Operation,
    records: &dyn Records,
    facts: &Facts<'_>,
) {
    settle(view, facts, input.position);
    let outcome = match plan(view, input, op, facts) {
        Ok(plan) => {
            apply(view, input, op, &plan, records);
            StepOutcome::Applied
        }
        Err(refusal) => StepOutcome::Refused(refusal),
    };
    view.steps.push(Step {
        record: input.id,
        operation: op,
        outcome,
    });
    let closed = view
        .active_ends
        .iter()
        .any(|e| e.cause == ActiveEndCause::Closed);
    let obligor = match &view.obligor {
        Obligor::Party(o) => Some(o.clone()),
        Obligor::Queue(_) => None,
    };
    if outcome == StepOutcome::Applied
        && view.is_terminal()
        && !closed
        && let Some(obligor) = obligor
    {
        view.active_ends.push(ActiveEnd {
            obligor,
            record: input.id,
            cause: ActiveEndCause::Closed,
        });
    }
}

// CM-22 CM-3
fn settle(view: &mut CommitmentView, facts: &Facts<'_>, before: u64) {
    let Some(precondition) = &view.precondition else {
        return;
    };
    let met = facts
        .conditions_met
        .iter()
        .any(|(c, at)| *c == precondition.condition && *at < before);
    if !met {
        return;
    }
    for item in &mut view.items {
        if item.state == S::ConditionallyPromised {
            item.state = S::Promised;
        }
    }
    view.precondition = None;
}

fn require(condition: bool, refusal: Refusal) -> Result<(), Refusal> {
    if condition { Ok(()) } else { Err(refusal) }
}

fn is_obligee(view: &CommitmentView, party: &PartyRef) -> bool {
    &view.obligee == party
}

fn is_obligor(view: &CommitmentView, party: &PartyRef) -> bool {
    matches!(&view.obligor, Obligor::Party(o) if o == party)
}

fn is_candidate(view: &CommitmentView, party: &PartyRef) -> bool {
    match &view.obligor {
        Obligor::Party(o) => o == party,
        Obligor::Queue(_) => true,
    }
}

fn is_principal(view: &CommitmentView, party: &PartyRef) -> bool {
    view.principal.contains(party)
}

fn all_open_in(view: &CommitmentView, allowed: &[S]) -> bool {
    let mut open = view.open_items().peekable();
    open.peek().is_some() && open.all(|i| allowed.contains(&i.state))
}

fn any_in(view: &CommitmentView, state: S) -> bool {
    view.items.iter().any(|i| i.state == state)
}

fn whole(view: &CommitmentView, allowed: &[S]) -> Result<Vec<u16>, Refusal> {
    require(all_open_in(view, allowed), Refusal::StateNotPermitted)?;
    Ok(view.open_items().map(|i| i.index).collect())
}

fn per_item(view: &CommitmentView, record: &Record, allowed: &[S]) -> Result<Vec<u16>, Refusal> {
    let Some(chosen) = params::items(record) else {
        let targets: Vec<u16> = view
            .open_items()
            .filter(|i| allowed.contains(&i.state))
            .map(|i| i.index)
            .collect();
        require(!targets.is_empty(), Refusal::StateNotPermitted)?;
        return Ok(targets);
    };
    for index in &chosen {
        let state = view.state_of(*index).ok_or(Refusal::UnknownItem)?;
        if !allowed.contains(&state) {
            return Err(if state.is_terminal() {
                Refusal::TerminalOutcome
            } else {
                Refusal::StateNotPermitted
            });
        }
    }
    require(!chosen.is_empty(), Refusal::MissingContent)?;
    Ok(chosen)
}

fn term_change(record: &Record, id: RecordId) -> TermChange {
    TermChange {
        record: id,
        by: params::acting(record).clone(),
        acceptor: params::party(record, "acceptor"),
        conditions: params::digests(record, "conditions"),
        due: params::time(record, "due"),
        evidence_required: params::flag(record, "evidence_required"),
        high_impact: params::flag(record, "high_impact"),
        item_count: params::uint(record, "item_count").and_then(|n| u16::try_from(n).ok()),
        respond_by: params::time(record, "respond_by"),
        defines: defined_fields(record),
    }
}

fn changes_terms(change: &TermChange, record: &Record) -> bool {
    change.acceptor.is_some()
        || change.conditions.is_some()
        || change.due.is_some()
        || change.evidence_required.is_some()
        || change.high_impact.is_some()
        || change.item_count.is_some()
        || change.respond_by.is_some()
        || params::has_body(record)
}

fn check_terms(view: &CommitmentView, change: &TermChange) -> Result<(), Refusal> {
    require(
        change.item_count.is_none_or(|n| n >= view.terms.item_count),
        Refusal::WrongTarget,
    )
}

fn four_eyes_ok(
    view: &CommitmentView,
    statement: &Statement,
    acceptor_side: &[PartyRef],
    facts: &Facts<'_>,
) -> bool {
    let waived = view.terms.four_eyes_waived && !facts.policy.four_eyes_waiver_forbidden;
    if !statement.by_agent || waived {
        return true;
    }
    !acceptor_side
        .iter()
        .any(|p| view.requester.contains(p) || statement.chain.contains(p))
}

pub(super) fn counterparty(view: &CommitmentView, kind: RevocationKind) -> Option<&PartyRef> {
    match kind {
        RevocationKind::Request | RevocationKind::Acceptance => match &view.obligor {
            Obligor::Party(o) => Some(o),
            Obligor::Queue(_) => None,
        },
        RevocationKind::Promise => Some(&view.obligee),
        RevocationKind::Statement => Some(&view.acceptor),
    }
}

fn plan(
    view: &CommitmentView,
    input: &Input<'_>,
    op: Operation,
    facts: &Facts<'_>,
) -> Result<Plan, Refusal> {
    let answers_terminal = matches!(
        op,
        Operation::RevokeAcceptance | Operation::Allow | Operation::Refuse | Operation::Dispute
    );
    require(!view.items.is_empty(), Refusal::StateNotPermitted)?;
    require(
        !view.is_terminal() || answers_terminal,
        Refusal::TerminalOutcome,
    )?;
    let record = input.record;
    let who = params::acting(record);
    match op {
        Operation::Request => Err(Refusal::StateNotPermitted),
        Operation::Promise => plan_promise(view, record, who),
        Operation::PromiseConditional | Operation::Decline => plan_answer(view, record, op, who),
        Operation::Counter => plan_counter(view, input, who),
        Operation::AcceptCounter => plan_accept_counter(view, record, who),
        Operation::State | Operation::Reject => plan_result(view, record, op, who),
        Operation::Accept => plan_accept(view, input, who, facts),
        Operation::Cancel
        | Operation::Release
        | Operation::DeclareObsolete
        | Operation::AdministrativeClose => plan_close(view, record, op, who),
        Operation::Delegate => plan_delegate(view, record, who),
        Operation::Assign => plan_assign(view, record, who),
        Operation::Dispute => plan_dispute(view, record, who),
        Operation::Defer | Operation::Notice => plan_marker(view, op, who),
        Operation::Resume => plan_resume(view, input, who, facts),
        Operation::RevokeRequest
        | Operation::RevokePromise
        | Operation::RevokeStatement
        | Operation::RevokeAcceptance => plan_revoke(view, op, who),
        Operation::Allow => plan_allow(view, record, who),
        Operation::Refuse => plan_refuse(view, record, who),
        Operation::Amend => plan_amend(view, input, who, facts),
        Operation::Expire => plan_expire(view, input),
        Operation::ImplicitAcceptanceTerms => plan_implicit_terms(view, record, who),
    }
}

fn plan_answer(
    view: &CommitmentView,
    record: &Record,
    op: Operation,
    who: &PartyRef,
) -> Result<Plan, Refusal> {
    require(is_candidate(view, who), Refusal::WrongRole)?;
    if op == Operation::PromiseConditional {
        require(
            params::digest(record, "precondition").is_some()
                && params::time(record, "valid_until").is_some(),
            Refusal::MissingContent,
        )?;
    }
    let targets = per_item(view, record, &[S::Requested])?;
    Ok(Plan::new(targets, Mode::Normal))
}

fn plan_result(
    view: &CommitmentView,
    record: &Record,
    op: Operation,
    who: &PartyRef,
) -> Result<Plan, Refusal> {
    if op == Operation::State {
        require(is_obligor(view, who), Refusal::WrongRole)?;
        let targets = per_item(view, record, &[S::Promised])?;
        require(
            !params::fulfilments(record).is_empty(),
            Refusal::MissingContent,
        )?;
        return Ok(Plan::new(targets, Mode::Normal));
    }
    require(&view.acceptor == who, Refusal::WrongRole)?;
    let statement = view.statement.as_ref().ok_or(Refusal::StateNotPermitted)?;
    require(
        params::digest(record, "statement") == Some(statement.record),
        Refusal::WrongTarget,
    )?;
    let targets = per_item(view, record, &[S::Stated])?;
    Ok(Plan::new(targets, Mode::Normal))
}

fn plan_close(
    view: &CommitmentView,
    record: &Record,
    op: Operation,
    who: &PartyRef,
) -> Result<Plan, Refusal> {
    let allowed: &[S] = match op {
        Operation::Cancel => {
            require(is_obligor(view, who), Refusal::WrongRole)?;
            &[S::ConditionallyPromised, S::Promised, S::Stated]
        }
        Operation::Release => {
            require(is_obligee(view, who), Refusal::WrongRole)?;
            S::OPEN
        }
        Operation::DeclareObsolete => {
            require(
                is_obligee(view, who) || is_principal(view, who),
                Refusal::WrongRole,
            )?;
            require(
                params::digest(record, "parent").is_some(),
                Refusal::MissingContent,
            )?;
            S::OPEN
        }
        _ => S::OPEN,
    };
    Ok(Plan::new(whole(view, allowed)?, Mode::Normal))
}

fn plan_marker(view: &CommitmentView, op: Operation, who: &PartyRef) -> Result<Plan, Refusal> {
    if op == Operation::Notice {
        require(is_obligor(view, who), Refusal::WrongRole)?;
        return Ok(Plan::new(Vec::new(), Mode::Normal));
    }
    require(
        is_obligee(view, who) || is_obligor(view, who),
        Refusal::WrongRole,
    )?;
    require(view.deferral.is_none(), Refusal::AlreadyPending)?;
    let before = [
        S::Requested,
        S::Countered,
        S::ConditionallyPromised,
        S::Promised,
    ];
    whole(view, &before)?;
    Ok(Plan::new(Vec::new(), Mode::Normal))
}

fn plan_promise(view: &CommitmentView, record: &Record, who: &PartyRef) -> Result<Plan, Refusal> {
    if let Some(amendment) = params::digest(record, "amendment") {
        let pending = view
            .pending
            .amendment
            .as_ref()
            .ok_or(Refusal::NothingPending)?;
        require(is_obligor(view, who), Refusal::WrongRole)?;
        require(pending.record == amendment, Refusal::WrongTarget)?;
        let targets = view.open_items().map(|i| i.index).collect();
        return Ok(Plan::new(targets, Mode::Amendment));
    }
    require(is_candidate(view, who), Refusal::WrongRole)?;
    let targets = per_item(view, record, &[S::Requested])?;
    Ok(Plan::new(targets, Mode::Normal))
}

fn plan_counter(view: &CommitmentView, input: &Input<'_>, who: &PartyRef) -> Result<Plan, Refusal> {
    let record = input.record;
    let change = term_change(record, input.id);
    require(changes_terms(&change, record), Refusal::MissingContent)?;
    check_terms(view, &change)?;
    if let Some(amendment) = params::digest(record, "amendment") {
        let pending = view
            .pending
            .amendment
            .as_ref()
            .ok_or(Refusal::NothingPending)?;
        require(is_obligor(view, who), Refusal::WrongRole)?;
        require(pending.record == amendment, Refusal::WrongTarget)?;
        return Ok(Plan::new(Vec::new(), Mode::Amendment));
    }
    if is_candidate(view, who) && all_open_in(view, &[S::Requested]) {
        return Ok(Plan::new(whole(view, &[S::Requested])?, Mode::Normal));
    }
    if is_obligee(view, who) && all_open_in(view, &[S::Countered]) {
        return Ok(Plan::new(whole(view, &[S::Countered])?, Mode::ByObligee));
    }
    Err(if is_candidate(view, who) || is_obligee(view, who) {
        Refusal::StateNotPermitted
    } else {
        Refusal::WrongRole
    })
}

fn plan_accept_counter(
    view: &CommitmentView,
    record: &Record,
    who: &PartyRef,
) -> Result<Plan, Refusal> {
    require(is_obligee(view, who), Refusal::WrongRole)?;
    let counter = view
        .pending
        .counter
        .as_ref()
        .ok_or(Refusal::NothingPending)?;
    require(
        params::digest(record, "counter") == Some(counter.record),
        Refusal::WrongTarget,
    )?;
    if view.pending.amendment.is_some() {
        let targets = view.open_items().map(|i| i.index).collect();
        return Ok(Plan::new(targets, Mode::Amendment));
    }
    Ok(Plan::new(whole(view, &[S::Countered])?, Mode::Normal))
}

fn plan_accept(
    view: &CommitmentView,
    input: &Input<'_>,
    who: &PartyRef,
    facts: &Facts<'_>,
) -> Result<Plan, Refusal> {
    let record = input.record;
    let statement = view.statement.as_ref().ok_or(Refusal::StateNotPermitted)?;
    require(
        params::digest(record, "statement") == Some(statement.record),
        Refusal::WrongTarget,
    )?;
    let targets = per_item(view, record, &[S::Stated])?;
    let implicit = params::flag(record, "implicit") == Some(true);
    let mode = if implicit {
        require(input.service(), Refusal::WrongRole)?;
        let terms = view.implicit.as_ref().ok_or(Refusal::NothingPending)?;
        require(
            record.basis().contains(&terms.record),
            Refusal::MissingContent,
        )?;
        let covered = terms
            .items
            .as_ref()
            .is_none_or(|items| targets.iter().all(|t| items.contains(t)));
        require(covered, Refusal::WrongTarget)?;
        let due = statement.recorded_at.0.checked_add(terms.window);
        require(
            due.is_some_and(|d| input.recorded_at.0 >= d),
            Refusal::NotYetDue,
        )?;
        require(!view.terms.high_impact, Refusal::StepUpRequired)?;
        require(
            four_eyes_ok(view, statement, &terms.declarer, facts),
            Refusal::FourEyes,
        )?;
        Mode::Implicit
    } else {
        require(&view.acceptor == who, Refusal::WrongRole)?;
        require(
            !view.terms.high_impact || input.step_up,
            Refusal::StepUpRequired,
        )?;
        require(
            four_eyes_ok(view, statement, &params::chain(record), facts),
            Refusal::FourEyes,
        )?;
        Mode::Normal
    };
    require(
        !view.evidence_required(facts.policy.evidence_required) || params::has_evidence(record),
        Refusal::EvidenceRequired,
    )?;
    let undefined = view
        .terms
        .undefined
        .contains(&OfferField::AcceptanceCriterion);
    require(
        (params::flag(record, "criterion_undefined") == Some(true)) == undefined,
        Refusal::CriterionUndefined,
    )?;
    Ok(Plan::new(targets, mode))
}

fn plan_delegate(view: &CommitmentView, record: &Record, who: &PartyRef) -> Result<Plan, Refusal> {
    let delegable = [S::ConditionallyPromised, S::Promised];
    let step = params::text(record, "step").and_then(ProposalStep::from_wire_name);
    match step.ok_or(Refusal::MissingContent)? {
        ProposalStep::Proposal => {
            require(is_obligor(view, who), Refusal::WrongRole)?;
            require(view.pending.delegation.is_none(), Refusal::AlreadyPending)?;
            let to = params::party(record, "obligor").ok_or(Refusal::MissingContent)?;
            require(!is_obligor(view, &to), Refusal::WrongTarget)?;
            Ok(Plan::new(whole(view, &delegable)?, Mode::Proposal))
        }
        ProposalStep::Acceptance => {
            let proposal = view
                .pending
                .delegation
                .as_ref()
                .ok_or(Refusal::NothingPending)?;
            require(
                params::digest(record, "proposal") == Some(proposal.record),
                Refusal::WrongTarget,
            )?;
            require(&proposal.to == who, Refusal::WrongRole)?;
            Ok(Plan::new(whole(view, &delegable)?, Mode::Acceptance))
        }
    }
}

fn plan_assign(view: &CommitmentView, record: &Record, who: &PartyRef) -> Result<Plan, Refusal> {
    let step = params::text(record, "step").and_then(ProposalStep::from_wire_name);
    match step.ok_or(Refusal::MissingContent)? {
        ProposalStep::Proposal => {
            require(is_obligee(view, who), Refusal::WrongRole)?;
            require(view.pending.assignment.is_none(), Refusal::AlreadyPending)?;
            let to = params::party(record, "obligee").ok_or(Refusal::MissingContent)?;
            require(!is_obligee(view, &to), Refusal::WrongTarget)?;
            Ok(Plan::new(whole(view, S::OPEN)?, Mode::Proposal))
        }
        ProposalStep::Acceptance => {
            let proposal = view
                .pending
                .assignment
                .as_ref()
                .ok_or(Refusal::NothingPending)?;
            require(
                params::digest(record, "proposal") == Some(proposal.record),
                Refusal::WrongTarget,
            )?;
            require(&proposal.to == who, Refusal::WrongRole)?;
            Ok(Plan::new(whole(view, S::OPEN)?, Mode::Acceptance))
        }
    }
}

fn plan_dispute(view: &CommitmentView, record: &Record, who: &PartyRef) -> Result<Plan, Refusal> {
    require(is_obligor(view, who), Refusal::WrongRole)?;
    let disputed = params::digest(record, "disputed").ok_or(Refusal::MissingContent)?;
    let revocation = view
        .pending
        .revocation
        .as_ref()
        .is_some_and(|r| r.kind == RevocationKind::Acceptance && r.record == disputed);
    require(
        revocation || view.rejected.contains(&disputed),
        Refusal::WrongTarget,
    )?;
    Ok(Plan::new(Vec::new(), Mode::Normal))
}

fn plan_resume(
    view: &CommitmentView,
    input: &Input<'_>,
    who: &PartyRef,
    facts: &Facts<'_>,
) -> Result<Plan, Refusal> {
    let deferral = view.deferral.as_ref().ok_or(Refusal::NothingPending)?;
    require(
        params::digest(input.record, "deferral") == Some(deferral.record),
        Refusal::WrongTarget,
    )?;
    if is_obligee(view, who) || is_obligor(view, who) {
        return Ok(Plan::new(Vec::new(), Mode::Normal));
    }
    require(input.service(), Refusal::WrongRole)?;
    require(
        input.record.basis().contains(&deferral.record),
        Refusal::MissingContent,
    )?;
    let at = deferral.resume_at.is_some_and(|t| t <= input.recorded_at);
    let on = deferral.resume_on.is_some_and(|c| {
        facts
            .conditions_met
            .iter()
            .any(|(m, pos)| *m == c && *pos < input.position)
    });
    require(at || on, Refusal::NotYetDue)?;
    Ok(Plan::new(Vec::new(), Mode::Normal))
}

fn plan_revoke(view: &CommitmentView, op: Operation, who: &PartyRef) -> Result<Plan, Refusal> {
    require(view.pending.revocation.is_none(), Refusal::AlreadyPending)?;
    let (role, state_ok) = match op {
        Operation::RevokeRequest => (is_obligee(view, who), view.open_items().next().is_some()),
        Operation::RevokePromise => (
            is_obligor(view, who),
            all_open_in(view, &[S::ConditionallyPromised, S::Promised]),
        ),
        Operation::RevokeStatement => (
            is_obligor(view, who),
            view.statement.is_some() && any_in(view, S::Stated),
        ),
        _ => (&view.acceptor == who, any_in(view, S::Accepted)),
    };
    require(role, Refusal::WrongRole)?;
    require(state_ok, Refusal::StateNotPermitted)?;
    Ok(Plan::new(Vec::new(), Mode::Normal))
}

fn plan_allow(view: &CommitmentView, record: &Record, who: &PartyRef) -> Result<Plan, Refusal> {
    let revocation = view
        .pending
        .revocation
        .as_ref()
        .ok_or(Refusal::NothingPending)?;
    require(
        params::digest(record, "revocation") == Some(revocation.record),
        Refusal::WrongTarget,
    )?;
    require(
        counterparty(view, revocation.kind) == Some(who),
        Refusal::WrongRole,
    )?;
    Ok(Plan::new(Vec::new(), Mode::Normal))
}

fn plan_refuse(view: &CommitmentView, record: &Record, who: &PartyRef) -> Result<Plan, Refusal> {
    if let Some(amendment) = params::digest(record, "amendment") {
        let pending = view
            .pending
            .amendment
            .as_ref()
            .ok_or(Refusal::NothingPending)?;
        require(pending.record == amendment, Refusal::WrongTarget)?;
        require(is_obligor(view, who), Refusal::WrongRole)?;
        return Ok(Plan::new(Vec::new(), Mode::Amendment));
    }
    plan_allow(view, record, who)
}

fn plan_amend(
    view: &CommitmentView,
    input: &Input<'_>,
    who: &PartyRef,
    facts: &Facts<'_>,
) -> Result<Plan, Refusal> {
    let record = input.record;
    let obligee_side = is_obligee(view, who) || is_principal(view, who);
    let terms = params::text(record, "change").and_then(AmendmentChange::from_wire_name)
        == Some(AmendmentChange::Terms);
    if !terms {
        let raises_only = params::flag(record, "high_impact") == Some(true)
            && record.param("change_policy").is_none()
            && record.param("four_eyes_waived").is_none();
        require(
            obligee_side || (is_obligor(view, who) && raises_only),
            Refusal::WrongRole,
        )?;
        if let Some(waived) = params::flag(record, "four_eyes_waived") {
            require(is_obligee(view, who), Refusal::WrongRole)?;
            require(
                !waived || !facts.policy.four_eyes_waiver_forbidden,
                Refusal::WaiverForbidden,
            )?;
        }
        return Ok(Plan::new(Vec::new(), Mode::Instruction));
    }
    require(obligee_side, Refusal::WrongRole)?;
    let change = term_change(record, input.id);
    require(changes_terms(&change, record), Refusal::MissingContent)?;
    check_terms(view, &change)?;
    if all_open_in(view, &[S::Requested, S::Countered]) {
        return Ok(Plan::new(Vec::new(), Mode::TermsNow));
    }
    require(view.pending.amendment.is_none(), Refusal::AlreadyPending)?;
    Ok(Plan::new(Vec::new(), Mode::TermsPending))
}

fn plan_expire(view: &CommitmentView, input: &Input<'_>) -> Result<Plan, Refusal> {
    require(input.service(), Refusal::WrongRole)?;
    let basis = input.record.basis();
    let mut targets: Vec<u16> = Vec::new();
    let mut declared = false;
    if let Some(deadline) = view.terms.respond_by
        && basis.contains(&deadline.declared_by)
    {
        declared = true;
        require(input.recorded_at >= deadline.at, Refusal::NotYetDue)?;
        targets.extend(
            view.open_items()
                .filter(|i| matches!(i.state, S::Requested | S::Countered))
                .map(|i| i.index),
        );
    }
    if let Some(precondition) = &view.precondition
        && basis.contains(&precondition.record)
    {
        declared = true;
        require(
            input.recorded_at >= precondition.valid_until,
            Refusal::NotYetDue,
        )?;
        targets.extend(
            view.open_items()
                .filter(|i| i.state == S::ConditionallyPromised)
                .map(|i| i.index),
        );
    }
    require(declared, Refusal::MissingContent)?;
    require(!targets.is_empty(), Refusal::StateNotPermitted)?;
    Ok(Plan::new(targets, Mode::Normal))
}

fn plan_implicit_terms(
    view: &CommitmentView,
    record: &Record,
    who: &PartyRef,
) -> Result<Plan, Refusal> {
    require(is_obligee(view, who), Refusal::WrongRole)?;
    if params::flag(record, "withdrawn") == Some(true) {
        require(view.implicit.is_some(), Refusal::NothingPending)?;
        return Ok(Plan::new(Vec::new(), Mode::Withdraw));
    }
    require(
        params::uint(record, "window").is_some_and(|w| w >= 1),
        Refusal::MissingContent,
    )?;
    require(!any_in(view, S::Stated), Refusal::StateNotPermitted)?;
    if let Some(items) = params::items(record) {
        require(
            items.iter().all(|i| view.state_of(*i).is_some()),
            Refusal::UnknownItem,
        )?;
    }
    Ok(Plan::new(Vec::new(), Mode::Normal))
}

fn set_state(view: &mut CommitmentView, targets: &[u16], state: S, closing: Option<Closing>) {
    for item in &mut view.items {
        if targets.contains(&item.index) {
            item.state = state;
            if state.is_terminal() {
                item.closing = closing;
            }
        }
    }
}

fn move_states(view: &mut CommitmentView, from: S, to: S) {
    for item in &mut view.items {
        if item.state == from {
            item.state = to;
        }
    }
}

fn apply_terms(view: &mut CommitmentView, change: TermChange, joining: S) {
    if let Some(acceptor) = change.acceptor {
        view.acceptor = acceptor;
    }
    if let Some(conditions) = change.conditions {
        view.conditions = conditions;
    }
    if let Some(due) = change.due {
        view.terms.due = Some(due);
    }
    if let Some(required) = change.evidence_required {
        view.terms.evidence.declared = required;
    }
    if let Some(high) = change.high_impact {
        view.terms.high_impact = high;
    }
    if let Some(at) = change.respond_by {
        view.terms.respond_by = Some(Deadline {
            at,
            declared_by: change.record,
        });
    }
    if let Some(count) = change.item_count {
        for index in view.terms.item_count..count {
            view.items.push(Item {
                index,
                state: joining,
                closing: None,
            });
        }
        view.terms.item_count = view.terms.item_count.max(count);
    }
    view.terms.undefined.retain(|f| !change.defines.contains(f));
}

fn bind_queue(view: &mut CommitmentView, party: &PartyRef) {
    if matches!(view.obligor, Obligor::Queue(_)) {
        view.obligor = Obligor::Party(party.clone());
    }
}

fn keep_statement(view: &mut CommitmentView) {
    if !any_in(view, S::Stated) {
        view.statement = None;
    } else if let Some(statement) = &mut view.statement {
        let stated: Vec<u16> = view
            .items
            .iter()
            .filter(|i| i.state == S::Stated)
            .map(|i| i.index)
            .collect();
        statement.items = stated;
    }
}

fn closing(id: RecordId, initiator: Initiator) -> Option<Closing> {
    Some(Closing {
        record: id,
        initiator,
    })
}

fn apply(
    view: &mut CommitmentView,
    input: &Input<'_>,
    op: Operation,
    plan: &Plan,
    records: &dyn Records,
) {
    match op {
        Operation::Request => {}
        Operation::Promise | Operation::PromiseConditional | Operation::Decline => {
            apply_answer(view, input, op, plan, records);
        }
        Operation::Counter => apply_counter(view, input, plan),
        Operation::AcceptCounter => apply_accept_counter(view, plan),
        Operation::State => apply_state(view, input, &plan.targets),
        Operation::Accept | Operation::Reject => apply_result(view, input, op, plan),
        Operation::Cancel
        | Operation::Release
        | Operation::DeclareObsolete
        | Operation::Expire
        | Operation::AdministrativeClose => apply_close(view, input, op, plan),
        Operation::Delegate => apply_delegate(view, input.record, input.id, plan),
        Operation::Assign => apply_assign(view, input.record, input.id, plan),
        Operation::Allow => apply_allow(view, input.id),
        Operation::Refuse if plan.mode == Mode::Amendment => {
            view.pending.amendment = None;
            view.pending.counter = None;
        }
        Operation::Refuse => {
            view.pending.revocation = None;
            view.disputes.push(input.id);
        }
        Operation::Amend => apply_amend(view, input, plan),
        Operation::Dispute
        | Operation::Defer
        | Operation::Resume
        | Operation::RevokeRequest
        | Operation::RevokePromise
        | Operation::RevokeStatement
        | Operation::RevokeAcceptance
        | Operation::Notice
        | Operation::ImplicitAcceptanceTerms => apply_marker(view, input, op, plan),
    }
}

fn apply_answer(
    view: &mut CommitmentView,
    input: &Input<'_>,
    op: Operation,
    plan: &Plan,
    records: &dyn Records,
) {
    let record = input.record;
    let who = params::acting(record).clone();
    let targets = plan.targets.as_slice();
    match op {
        Operation::Promise if plan.mode == Mode::Amendment => accept_amendment(view, None),
        Operation::Promise => {
            set_state(view, targets, S::Promised, None);
            bind_queue(view, &who);
        }
        Operation::PromiseConditional => {
            set_state(view, targets, S::ConditionallyPromised, None);
            bind_queue(view, &who);
            if let (Some(condition), Some(valid_until)) = (
                params::digest(record, "precondition"),
                params::time(record, "valid_until"),
            ) {
                view.precondition = Some(Precondition {
                    record: input.id,
                    condition,
                    valid_until,
                    address: address_of(records, &condition),
                });
            }
        }
        _ => set_state(
            view,
            targets,
            S::Declined,
            closing(input.id, Initiator::Obligor),
        ),
    }
}

fn apply_accept_counter(view: &mut CommitmentView, plan: &Plan) {
    let counter = view.pending.counter.take();
    if plan.mode == Mode::Amendment {
        accept_amendment(view, counter);
    } else if let Some(change) = counter {
        let by = change.by.clone();
        apply_terms(view, change, S::Promised);
        set_state(view, &plan.targets, S::Promised, None);
        bind_queue(view, &by);
        view.terms.respond_by = None;
    }
}

fn apply_result(view: &mut CommitmentView, input: &Input<'_>, op: Operation, plan: &Plan) {
    if op == Operation::Reject {
        set_state(view, &plan.targets, S::Promised, None);
        view.rejections = view.rejections.saturating_add(1);
        view.rejected.push(input.id);
    } else {
        let initiator = if plan.mode == Mode::Implicit {
            Initiator::WorkService
        } else {
            Initiator::Acceptor
        };
        set_state(
            view,
            &plan.targets,
            S::Accepted,
            closing(input.id, initiator),
        );
        view.rejections = 0;
    }
    keep_statement(view);
}

fn apply_close(view: &mut CommitmentView, input: &Input<'_>, op: Operation, plan: &Plan) {
    let who = params::acting(input.record);
    let (state, initiator) = match op {
        Operation::Cancel => (S::Cancelled, Initiator::Obligor),
        Operation::Release => (S::Released, Initiator::Obligee),
        Operation::DeclareObsolete if is_obligee(view, who) => (S::Obsolete, Initiator::Obligee),
        Operation::DeclareObsolete => (S::Obsolete, Initiator::Principal),
        Operation::Expire => (S::Expired, Initiator::WorkService),
        _ => (S::ClosedAdministratively, Initiator::Administrator),
    };
    set_state(view, &plan.targets, state, closing(input.id, initiator));
}

fn apply_marker(view: &mut CommitmentView, input: &Input<'_>, op: Operation, plan: &Plan) {
    let record = input.record;
    let id = input.id;
    match op {
        Operation::Dispute => view.disputes.push(id),
        Operation::Defer => {
            view.deferral = Some(Deferral {
                record: id,
                resume_at: params::time(record, "resume_at"),
                resume_on: params::digest(record, "resume_on"),
            });
        }
        Operation::Resume => view.deferral = None,
        Operation::RevokeRequest => revoke(view, id, RevocationKind::Request),
        Operation::RevokePromise => revoke(view, id, RevocationKind::Promise),
        Operation::RevokeStatement => revoke(view, id, RevocationKind::Statement),
        Operation::RevokeAcceptance => revoke(view, id, RevocationKind::Acceptance),
        Operation::Notice => {
            let notice_type = params::text(record, "notice_type").and_then(|t| {
                NoticeType::from_wire_name(t.split_once(':').map_or(t, |(code, _)| code))
            });
            if let Some(notice_type) = notice_type {
                view.notices.push(Notice {
                    record: id,
                    notice_type,
                });
            }
        }
        _ if plan.mode == Mode::Withdraw => view.implicit = None,
        _ => {
            view.implicit = params::uint(record, "window").map(|window| ImplicitTerms {
                record: id,
                window,
                items: params::items(record),
                declarer: params::chain(record),
            });
        }
    }
}

fn revoke(view: &mut CommitmentView, record: RecordId, kind: RevocationKind) {
    view.pending.revocation = Some(Revocation { record, kind });
}

fn address_of(records: &dyn Records, condition: &RecordId) -> Option<Address> {
    let text = params::text(records.record(condition)?, "address")?;
    TypeUri::parse(text)
        .map(Address::Uri)
        .or_else(|| PartyRef::new(text).map(Address::Party))
}

fn accept_amendment(view: &mut CommitmentView, counter: Option<TermChange>) {
    let change = counter.or_else(|| view.pending.amendment.take());
    view.pending.amendment = None;
    view.pending.counter = None;
    if let Some(change) = change {
        apply_terms(view, change, S::Promised);
    }
    move_states(view, S::Stated, S::Promised);
    view.statement = None;
}

fn apply_counter(view: &mut CommitmentView, input: &Input<'_>, plan: &Plan) {
    let change = term_change(input.record, input.id);
    match plan.mode {
        Mode::Amendment => view.pending.counter = Some(change),
        Mode::ByObligee => {
            apply_terms(view, change, S::Requested);
            set_state(view, &plan.targets, S::Requested, None);
            view.pending.counter = None;
            view.offer_version = view.offer_version.saturating_add(1);
        }
        _ => {
            if let Some(at) = change.respond_by {
                view.terms.respond_by = Some(Deadline {
                    at,
                    declared_by: input.id,
                });
            }
            set_state(view, &plan.targets, S::Countered, None);
            view.pending.counter = Some(change);
            view.offer_version = view.offer_version.saturating_add(1);
        }
    }
}

fn apply_state(view: &mut CommitmentView, input: &Input<'_>, targets: &[u16]) {
    let record = input.record;
    set_state(view, targets, S::Stated, None);
    view.fulfilments.extend(params::fulfilments(record));
    let items = view
        .items
        .iter()
        .filter(|i| i.state == S::Stated)
        .map(|i| i.index)
        .collect();
    view.statement = Some(Statement {
        record: input.id,
        recorded_at: input.recorded_at,
        items,
        evidenced: params::has_evidence(record),
        by_agent: input.actor == Some(ActorType::Agent),
        chain: params::chain(record),
    });
}

fn apply_delegate(view: &mut CommitmentView, record: &Record, id: RecordId, plan: &Plan) {
    if plan.mode == Mode::Proposal {
        view.pending.delegation =
            params::party(record, "obligor").map(|to| Proposal { record: id, to });
        return;
    }
    if let Some(proposal) = view.pending.delegation.take() {
        if let Obligor::Party(old) = &view.obligor {
            view.active_ends.push(ActiveEnd {
                obligor: old.clone(),
                record: id,
                cause: ActiveEndCause::Delegated,
            });
        }
        view.obligor = Obligor::Party(proposal.to);
        view.handovers.push(proposal.record);
    }
}

fn apply_assign(view: &mut CommitmentView, record: &Record, id: RecordId, plan: &Plan) {
    if plan.mode == Mode::Proposal {
        view.pending.assignment =
            params::party(record, "obligee").map(|to| Proposal { record: id, to });
        return;
    }
    if let Some(proposal) = view.pending.assignment.take() {
        view.obligee = proposal.to;
    }
}

fn apply_allow(view: &mut CommitmentView, id: RecordId) {
    let Some(revocation) = view.pending.revocation.take() else {
        return;
    };
    let open: Vec<u16> = view.open_items().map(|i| i.index).collect();
    match revocation.kind {
        RevocationKind::Request => {
            set_state(view, &open, S::Withdrawn, closing(id, Initiator::Obligee));
        }
        RevocationKind::Promise => {
            set_state(view, &open, S::Withdrawn, closing(id, Initiator::Obligor));
        }
        RevocationKind::Statement => {
            move_states(view, S::Stated, S::Promised);
            view.statement = None;
        }
        RevocationKind::Acceptance => view.reopening = Some(revocation.record),
    }
}

fn apply_amend(view: &mut CommitmentView, input: &Input<'_>, plan: &Plan) {
    let record = input.record;
    match plan.mode {
        Mode::Instruction => {
            if params::flag(record, "high_impact") == Some(true) {
                view.terms.high_impact = true;
            }
            if let Some(waived) = params::flag(record, "four_eyes_waived") {
                view.terms.four_eyes_waived = waived;
            }
            if let Some(policy) =
                params::text(record, "change_policy").and_then(ChangePolicy::from_wire_name)
            {
                view.terms.change_policy = policy;
            }
            view.instruction_version = view.instruction_version.saturating_add(1);
        }
        Mode::TermsNow => {
            apply_terms(view, term_change(record, input.id), S::Requested);
            move_states(view, S::Countered, S::Requested);
            view.pending.counter = None;
            view.offer_version = view.offer_version.saturating_add(1);
        }
        _ => view.pending.amendment = Some(term_change(record, input.id)),
    }
}
