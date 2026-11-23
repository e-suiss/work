//! Normative basis and autonomy (RC-26 … RC-29, RC-49): an agent action stands on Aim, Commitment, an `on_behalf_of` chain, Access authority evidence and the principal's autonomy policy, never on content, tool output or chat alone; autonomy is a Work policy inside Access authority, evaluated per action from its risk with the result of the shared restriction engine as an input, and it yields `proceed`, `proceed_and_notify`, `require_gate` or `deny`; an Access `deny` is final, the principal's policy only narrows unless the principal's own Declaration expands it, an expansion always notifies, and an agent's self-reported confidence is no input.

use alloc::string::String;
use alloc::vec::Vec;

use crate::catalog::DeclarationSubtype;
use crate::commitment::AccessAnswer;
use crate::control::body::{AutonomyPolicy, DEFAULT_BULK_THRESHOLD, DEFAULT_NEAR_BOUNDARY};
use crate::derive::Restriction;
use crate::id::{PartyRef, RecordId};
use crate::reason::wire_enum;
use crate::record::{Capacity, ParamScalar, ParamValue, Record};
use crate::validate::ActorType;

wire_enum! {
    /// A component of an agent action's normative basis that is missing (RC-26).
    BasisGap {
        /// No `on_behalf_of` chain to a principal.
        OnBehalfOf => "on_behalf_of",
        /// No Access authority evidence.
        Authority => "authority",
        /// No Aim, neither in the basis nor named by the commitment.
        Aim => "aim",
        /// No commitment.
        Commitment => "commitment",
        /// No autonomy policy Declaration of the principal.
        AutonomyPolicy => "autonomy_policy",
        /// A premise the caller does not know.
        UnknownPremise => "unknown_premise",
        /// The premises are only content: Acts and Claims such as tool output, chat or a seen page.
        ContentOnly => "content_only",
    }
}

/// The principal an agent acts for: the capacity principal, or the root of its `on_behalf_of` chain (E-13).
#[must_use]
pub fn principal_of(record: &Record) -> Option<&PartyRef> {
    let core = record.core();
    match &core.capacity {
        Some(Capacity::For(p)) => Some(p),
        Some(Capacity::Own) | None => core.on_behalf_of.as_ref().and_then(|c| c.last()),
    }
}

fn acting(record: &Record) -> &PartyRef {
    match &record.core().capacity {
        Some(Capacity::For(p)) => p,
        Some(Capacity::Own) | None => &record.core().author,
    }
}

fn declaration(record: &Record) -> Option<DeclarationSubtype> {
    match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str()),
        Record::Act(_) | Record::Claim(_) => None,
    }
}

fn names_aim(record: &Record) -> bool {
    matches!(
        record.param("aim"),
        Some(ParamValue::Scalar(ParamScalar::Digest(_)))
    )
}

/// Checks the normative basis of a record an agent writes (RC-26, INV-21, INV-22): `premises` resolves the record's `basis`; a record by any other actor type passes, since the rule binds agents.
///
/// # Errors
/// Every [`BasisGap`], in declaration order.
pub fn check_basis(
    record: &Record,
    author: ActorType,
    premises: &[(RecordId, &Record)],
) -> Result<(), Vec<BasisGap>> {
    if author != ActorType::Agent {
        return Ok(());
    }
    let core = record.core();
    let principal = principal_of(record);
    let mut found: Vec<&Record> = Vec::new();
    let mut unknown = false;
    for id in record.basis() {
        match premises.iter().find(|(p, _)| p == id) {
            Some((_, premise)) => found.push(premise),
            None => unknown = true,
        }
    }
    let subtypes: Vec<(DeclarationSubtype, &Record)> = found
        .iter()
        .filter_map(|r| declaration(r).map(|d| (d, *r)))
        .collect();
    let commitment = subtypes.iter().any(|(d, _)| {
        matches!(
            d,
            DeclarationSubtype::Request
                | DeclarationSubtype::Promise
                | DeclarationSubtype::PromiseConditional
                | DeclarationSubtype::AcceptCounter
        )
    });
    let aim = subtypes.iter().any(|(d, r)| {
        *d == DeclarationSubtype::Aim || (*d == DeclarationSubtype::Request && names_aim(r))
    });
    let policy = subtypes.iter().any(|(d, r)| {
        *d == DeclarationSubtype::AutonomyPolicy && principal.is_some_and(|p| acting(r) == p)
    });
    let mut gaps = Vec::new();
    if core.on_behalf_of.as_ref().is_none_or(Vec::is_empty) || principal.is_none() {
        gaps.push(BasisGap::OnBehalfOf);
    }
    if core.authority.is_none() {
        gaps.push(BasisGap::Authority);
    }
    if !aim {
        gaps.push(BasisGap::Aim);
    }
    if !commitment {
        gaps.push(BasisGap::Commitment);
    }
    if !policy {
        gaps.push(BasisGap::AutonomyPolicy);
    }
    if unknown {
        gaps.push(BasisGap::UnknownPremise);
    }
    if !found.is_empty() && subtypes.is_empty() {
        gaps.push(BasisGap::ContentOnly);
    }
    if gaps.is_empty() { Ok(()) } else { Err(gaps) }
}

wire_enum! {
    /// The four results of an autonomy evaluation (RC-27).
    AutonomyOutcome {
        /// Act without asking.
        Proceed => "proceed",
        /// Act and notify the principal.
        ProceedAndNotify => "proceed_and_notify",
        /// A gate decides first (ST-25).
        RequireGate => "require_gate",
        /// Do not act.
        Deny => "deny",
    }
}

wire_enum! {
    /// Why an evaluation reached its outcome (RC-27, RC-28, RC-49).
    AutonomyCause {
        /// Access denied; no gate or waiver overrides it.
        AccessDeny => "access_deny",
        /// The principal's restriction rule set denied.
        PolicyDeny => "policy_deny",
        /// Access asks for a step-up.
        StepUp => "step_up",
        /// Access has an outstanding requirement.
        AccessRequire => "access_require",
        /// The action uses at least the nearness share of an Access numeric limit.
        NearBoundary => "near_boundary",
        /// The action touches more objects than the bulk threshold.
        Bulk => "bulk",
        /// The action cannot be undone.
        Irreversible => "irreversible",
        /// The action binds another party.
        BindsOtherParty => "binds_other_party",
        /// The principal's restriction rule set requires a condition.
        PolicyRequire => "policy_require",
        /// High-impact or weakly evidenced work is a suggestion first.
        Suggest => "suggest",
        /// The principal's expansion lifted a default gate.
        Expanded => "expanded",
        /// The principal asked to be notified.
        Notify => "notify",
    }
}

wire_enum! {
    /// How strongly external signals back the work: evidence strength, independent verification, past accuracy (ST-36); never the agent's own confidence.
    Evidence {
        /// Backed.
        Strong => "strong",
        /// Weakly backed.
        Weak => "weak",
    }
}

wire_enum! {
    /// The impact class of the work (CM-60).
    Impact {
        /// Ordinary.
        Normal => "normal",
        /// High impact.
        High => "high",
    }
}

/// One Access numeric limit for the action and the use it would reach with the action (RC-49).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitUse {
    /// The limit Access reports.
    pub limit: u64,
    /// The use after the action.
    pub after: u64,
}

/// The risk inputs of one agent action (RC-28, RC-49).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRisk<'a> {
    /// The Access action name.
    pub action: &'a str,
    /// Records or external objects the action touches.
    pub objects: u64,
    /// Whether the action can be undone.
    pub reversible: bool,
    /// Whether the action binds another party.
    pub binds_other_party: bool,
    /// The impact class.
    pub impact: Impact,
    /// The external evidence class.
    pub evidence: Evidence,
}

/// What Access answered for the action (RC-27).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessView<'a> {
    /// The answer.
    pub answer: AccessAnswer,
    /// The numeric limits Access reports for the action.
    pub limits: &'a [LimitUse],
}

/// The result of an autonomy evaluation (RC-27, RC-28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Autonomy {
    /// The outcome.
    pub outcome: AutonomyOutcome,
    /// Every cause, in evaluation order.
    pub causes: Vec<AutonomyCause>,
    /// The agent only suggests; the action is accepted separately and one by one (RC-28).
    pub suggest: bool,
}

fn near(limits: &[LimitUse], permille: u16) -> bool {
    limits.iter().any(|l| {
        u128::from(l.after).saturating_mul(1000)
            >= u128::from(l.limit).saturating_mul(u128::from(permille))
    })
}

/// Evaluates an agent action (RC-27, RC-28, RC-29, RC-49): `restriction` is the verdict of the principal's restriction rule set from the shared engine, `NoObjection` when the policy names none; without a policy the defaults apply.
#[must_use]
pub fn evaluate(
    risk: &ActionRisk<'_>,
    access: &AccessView<'_>,
    policy: Option<&AutonomyPolicy>,
    restriction: Restriction,
) -> Autonomy {
    let deny = |cause| Autonomy {
        outcome: AutonomyOutcome::Deny,
        causes: alloc::vec![cause],
        suggest: false,
    };
    if access.answer == AccessAnswer::Deny {
        return deny(AutonomyCause::AccessDeny);
    }
    if restriction == Restriction::Deny {
        return deny(AutonomyCause::PolicyDeny);
    }
    let bulk = policy.map_or(DEFAULT_BULK_THRESHOLD, AutonomyPolicy::bulk);
    let nearness = policy.map_or(DEFAULT_NEAR_BOUNDARY, AutonomyPolicy::near);
    let expanded =
        policy.is_some_and(|p| p.expanded_actions.iter().any(|a| a.as_str() == risk.action));
    let mut causes = Vec::new();
    let mut lifted = false;
    match access.answer {
        AccessAnswer::StepUp => causes.push(AutonomyCause::StepUp),
        AccessAnswer::Require => causes.push(AutonomyCause::AccessRequire),
        AccessAnswer::Allow | AccessAnswer::Deny => {}
    }
    if near(access.limits, nearness) {
        causes.push(AutonomyCause::NearBoundary);
    } else if near(access.limits, DEFAULT_NEAR_BOUNDARY) {
        lifted = true;
    }
    if risk.objects > bulk {
        causes.push(AutonomyCause::Bulk);
    } else if risk.objects > DEFAULT_BULK_THRESHOLD {
        lifted = true;
    }
    if !risk.reversible {
        if expanded {
            lifted = true;
        } else {
            causes.push(AutonomyCause::Irreversible);
        }
    }
    if risk.binds_other_party {
        if expanded {
            lifted = true;
        } else {
            causes.push(AutonomyCause::BindsOtherParty);
        }
    }
    if restriction == Restriction::Require {
        causes.push(AutonomyCause::PolicyRequire);
    }
    let suggest = risk.impact == Impact::High
        || risk.evidence == Evidence::Weak
        || policy.is_some_and(|p| p.suggest);
    if suggest {
        causes.push(AutonomyCause::Suggest);
    }
    if !causes.is_empty() {
        return Autonomy {
            outcome: AutonomyOutcome::RequireGate,
            causes,
            suggest,
        };
    }
    if lifted {
        causes.push(AutonomyCause::Expanded);
    }
    if policy.is_some_and(|p| p.notify) {
        causes.push(AutonomyCause::Notify);
    }
    let outcome = if causes.is_empty() {
        AutonomyOutcome::Proceed
    } else {
        AutonomyOutcome::ProceedAndNotify
    };
    Autonomy {
        outcome,
        causes,
        suggest,
    }
}

wire_enum! {
    /// Why an autonomy policy Declaration does not take effect (RC-27, RC-29).
    PolicyRefusal {
        /// The record is not an `autonomy_policy` Declaration.
        NotAPolicy => "not_a_policy",
        /// It does not speak for the principal.
        NotPrincipal => "not_principal",
        /// An expansion written by anyone but the principal in person, or by an agent.
        ExpansionNotByPrincipal => "expansion_not_by_principal",
    }
}

/// Checks that an autonomy policy is the principal's Declaration (RC-27, RC-29): a narrowing policy speaks for the principal, an expansion is written by the principal in person and never by an agent.
///
/// # Errors
/// The [`PolicyRefusal`].
pub fn admit_policy(
    record: &Record,
    policy: &AutonomyPolicy,
    principal: &PartyRef,
    author: ActorType,
) -> Result<(), PolicyRefusal> {
    if declaration(record) != Some(DeclarationSubtype::AutonomyPolicy) {
        return Err(PolicyRefusal::NotAPolicy);
    }
    if acting(record) != principal {
        return Err(PolicyRefusal::NotPrincipal);
    }
    if policy.expansion && (&record.core().author != principal || author == ActorType::Agent) {
        return Err(PolicyRefusal::ExpansionNotByPrincipal);
    }
    Ok(())
}

wire_enum! {
    /// Why a deviation from a coordination rule is not a reasoned event (RC-29).
    DeviationRefusal {
        /// The deviation does not cite the rule it departs from in its basis.
        Uncited => "uncited",
        /// The deviation carries no `note` body part with its reason.
        Unreasoned => "unreasoned",
    }
}

/// Checks that a deviation from the coordination rule `rule` is a reasoned event, not an error (RC-29): it cites the rule in its basis and gives its reason in the `note` body part.
///
/// # Errors
/// The [`DeviationRefusal`].
pub fn check_deviation(record: &Record, rule: &RecordId) -> Result<(), DeviationRefusal> {
    if !record.basis().contains(rule) {
        return Err(DeviationRefusal::Uncited);
    }
    let reasoned = record
        .core()
        .body
        .iter()
        .flatten()
        .any(|b| b.part.as_str() == "note");
    if !reasoned {
        return Err(DeviationRefusal::Unreasoned);
    }
    Ok(())
}

/// One gate decision on an agent action, the input to an autonomy suggestion (RC-29).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateOutcome<'a> {
    /// The Access action name.
    pub action: &'a str,
    /// Whether the gate approved.
    pub approved: bool,
}

/// A suggestion to expand autonomy for an action; it takes effect only through the principal's Declaration (RC-29).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpansionSuggestion {
    /// The Access action name.
    pub action: String,
    /// The approvals in a row that back it.
    pub approvals: usize,
}

/// The actions whose latest `at_least` gate decisions in a row were all approved, in first-seen order (RC-29); `at_least` is the caller's policy and zero suggests nothing.
#[must_use]
pub fn suggest_expansions(
    decisions: &[GateOutcome<'_>],
    at_least: usize,
) -> Vec<ExpansionSuggestion> {
    let mut out: Vec<ExpansionSuggestion> = Vec::new();
    if at_least == 0 {
        return out;
    }
    let mut actions: Vec<&str> = Vec::new();
    for d in decisions {
        if !actions.contains(&d.action) {
            actions.push(d.action);
        }
    }
    for action in actions {
        let streak = decisions
            .iter()
            .rev()
            .filter(|d| d.action == action)
            .take_while(|d| d.approved)
            .count();
        if streak >= at_least {
            out.push(ExpansionSuggestion {
                action: String::from(action),
                approvals: streak,
            });
        }
    }
    out
}
