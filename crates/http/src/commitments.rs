//! The commitment family of the REST API (CM-17, CM-19, C-6, P-55, CM-58, CM-2, E-45, P-54 items 4 and 5): one typed write per operation of the closed set, so an agent writes only typed operations, `POST /v1/ledgers/{ledger}/commitments` for a `request` and `POST /v1/ledgers/{ledger}/commitments/{commitment}/<operation>` for every other one, each taking the signed record of exactly that operation with its Access evidence, one `Idempotency-Key` and the `If-Match` of the commitment's version, and naming the Access action of its operation; the kernel checks every operation against the commitment its records derive before anything is written, and a refused one is answered `422 record_rejected` with the kernel's reason and kept under its key. `GET /v1/ledgers/{ledger}/commitments/{commitment}` reads the commitment as its records derive it, with the transitions the caller may make now, what each still needs and who holds the next move; nothing of it is stored.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use axum::{Extension, Router};
use serde::Serialize;
use utoipa::ToSchema;
use work_kernel::budget::{Choice, Measure};
use work_kernel::clock::{ClockError, ClockState, Target, Tier};
use work_kernel::commitment::{
    ActiveEnd, Address, Allowed, BudgetProjection, ClockProjection, CommitmentView,
    ImplicitAcceptance, Item, Missing, Mover, Operation, PeriodicProjection, Step, StepOutcome,
    SupportSignal,
};
use work_kernel::id::{LedgerId, RecordId, Time};
use work_kernel::ontology::Obligor;
use work_proto::id::{CommitmentId, ExternalId as _};
use work_query::domain::commitments::{CommitmentRead, action_of};
use work_query::domain::writes::{Expected, Kind, Written};

use crate::common::RequestContext;
use crate::conditional::etag;
use crate::json::rfc3339_millis;
use crate::position::{WORK_POSITION, min_position, position_header};
use crate::problem::{Problem, ProblemCode};
use crate::reads::{ApiServices, caller_of, read_problem};
use crate::writes::{declaration_request, write_problem};

/// A written commitment record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct CommitmentWritten {
    /// The ledger, `led_…`.
    pub ledger: String,
    /// The commitment, `cmt_…`, named by its `request`.
    pub commitment: String,
    /// The record, `rec_…`.
    pub record: String,
    /// Its position.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub pos: u64,
    /// True when the answer is that of the request first sent with this `Idempotency-Key`.
    pub replayed: bool,
}

/// One item of a commitment and its derived state (CM-23).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ItemAnswer {
    /// The item's index.
    pub index: u16,
    /// One of the thirteen states (CM-14).
    pub state: String,
    /// The record that closed it, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<String>,
    /// Who started its terminal outcome (CM-30).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator: Option<String>,
}

/// The terms in force (CM-6, CM-7, CM-8, CM-60).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct TermsAnswer {
    /// The commitment type label (CM-9).
    pub kind: String,
    /// The number of items.
    pub item_count: u16,
    /// The due time, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due: Option<String>,
    /// The response deadline, RFC 3339 UTC (CM-24).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub respond_by: Option<String>,
    /// Whether acceptance needs evidence by declaration or a truth Aim (CM-27).
    pub evidence_required: bool,
    /// The explicit high impact mark (CM-60).
    pub high_impact: bool,
    /// Whether the obligee waived four eyes (CM-39).
    pub four_eyes_waived: bool,
    /// The change policy (CM-57).
    pub change_policy: String,
    /// The offer fields left undefined (CM-7).
    pub undefined: Vec<String>,
}

/// A record waiting for the other side, with the Party it proposes or the kind it asks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PendingAnswer {
    /// What waits: `counter`, `amendment`, `revocation`, `delegation` or `transfer`.
    pub what: String,
    /// The record, `rec_…`.
    pub record: String,
    /// The Party a delegation or transfer proposes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// The revocation asked: `request`, `promise`, `statement` or `acceptance`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// The statement in force (CM-25, CM-27).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct StatementAnswer {
    /// The `state` record, `rec_…`.
    pub record: String,
    /// Its ledger time, RFC 3339 UTC.
    pub recorded_at: String,
    /// The items it states.
    pub items: Vec<u16>,
    /// Whether it carries evidence; without, it is stated without evidence.
    pub evidenced: bool,
    /// Whether an agent wrote it.
    pub by_agent: bool,
}

/// A notice the obligor gave (CM-58).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct NoticeAnswer {
    /// The `notice` record, `rec_…`.
    pub record: String,
    /// `at_risk`, `cannot_complete` or `obsolete_suggested`.
    pub notice_type: String,
}

/// An end of an obligor's `commitment.active` (E-8, E-12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ActiveEndAnswer {
    /// The obligor whose commitment is no longer active.
    pub obligor: String,
    /// The record that ended it, `rec_…`.
    pub record: String,
    /// `delegated` or `closed`.
    pub cause: String,
}

/// One commitment record after the request and its result, in ledger order (CM-19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct StepAnswer {
    /// The record, `rec_…`.
    pub record: String,
    /// The operation's wire name.
    pub operation: String,
    /// `applied` or `refused`.
    pub outcome: String,
    /// The kernel's reason of a refused record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One transition the caller may make now (CM-19, P-55).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AllowedAnswer {
    /// The operation's wire name.
    pub operation: String,
    /// `proposal` or `acceptance` of a two-record operation (CM-44).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// The items it applies to.
    pub items: Vec<u16>,
    /// The Access action it asks for, `work:<action>` (E-45).
    pub action: String,
    /// What Access answers: `allow`, `deny`, `step_up` or `require`; Access decides each one
    /// when it is written, so it is `require` until then.
    pub access: String,
    /// What it still needs: `step_up`, `access_denied`, `access_pending` or `gate:<rec_…>`.
    pub missing: Vec<String>,
}

/// Who holds the next move (CM-58).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct MoverAnswer {
    /// `party`, `queue`, `address`, `precondition_addressee` or `accountable`.
    pub kind: String,
    /// The Party, the queue's `rec_…`, the address or the precondition's `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// A signal a supporting commitment raises (CM-47).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct SignalAnswer {
    /// The supporting commitment, `cmt_…`.
    pub child: String,
    /// The cause.
    pub cause: String,
    /// The record that raised it, `rec_…`.
    pub record: String,
    /// The Party to notify.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<String>,
}

/// How the implicit acceptance of the statement in force stands (CM-41, CM-42).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ImplicitAnswer {
    /// `not_stated`, `no_terms`, `waiting`, `due` or `blocked`.
    pub status: String,
    /// When the window ends, RFC 3339 UTC, while waiting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<String>,
    /// Why it cannot be implicit, when blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A commitment as its records derive it at the ledger's head; no field is stored (CM-2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct CommitmentAnswer {
    /// The ledger, `led_…`.
    pub ledger: String,
    /// The commitment, `cmt_…`.
    pub commitment: String,
    /// The version of the commitment, also the `ETag` its next record names in `If-Match`.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub version: u64,
    /// One state when every item is in it, otherwise `mixed`, which is no state (CM-23).
    pub summary: String,
    /// The items and their states.
    pub items: Vec<ItemAnswer>,
    /// The obligee in force.
    pub obligee: String,
    /// The obligor in force; absent while a queue holds the debtor side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obligor: Option<String>,
    /// The queue's `rec_…` while it holds the debtor side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// The acceptor in force (CM-37).
    pub acceptor: String,
    /// The `on_behalf_of` chain of the request (CM-5).
    pub principal: Vec<String>,
    /// The terms in force.
    pub terms: TermsAnswer,
    /// The offer version (CM-21).
    pub offer_version: u32,
    /// The instruction version (CM-56).
    pub instruction_version: u32,
    /// What waits for the other side.
    pub pending: Vec<PendingAnswer>,
    /// The statement in force.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<StatementAnswer>,
    /// The open deferral's `rec_…`; the summary category is then `deferred` (ST-7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferral: Option<String>,
    /// Consecutive rejections since the last acceptance (CM-26).
    pub rejections: u32,
    /// Every rejection, `rec_…` (CM-26).
    pub rejected: Vec<String>,
    /// The records that raised the dispute marker, which is no state (CM-36).
    pub disputes: Vec<String>,
    /// The records the statements cited as fulfilling it (CM-25).
    pub fulfilments: Vec<String>,
    /// The accepted delegations (CM-44).
    pub handovers: Vec<String>,
    /// The notices given (CM-58).
    pub notices: Vec<NoticeAnswer>,
    /// The ends of `commitment.active` Work publishes (E-8, E-12).
    pub active_ends: Vec<ActiveEndAnswer>,
    /// Every commitment record after the request and its result (CM-19).
    pub steps: Vec<StepAnswer>,
    /// How the implicit acceptance stands.
    pub implicit_acceptance: ImplicitAnswer,
    /// The transitions the caller may make now (P-55).
    pub allowed: Vec<AllowedAnswer>,
    /// Who holds the next move (CM-58).
    pub next_move: Vec<MoverAnswer>,
    /// The signals of the commitments that support it, their clocks and periodic updates
    /// included (CM-47).
    pub signals: Vec<SignalAnswer>,
    /// Its clocks, periodic updates and budgets at the evaluation time (CM-48, CM-50, CM-53).
    pub time: TimeAnswer,
    /// The ledger time the answer reflects, RFC 3339 UTC.
    pub at: String,
    /// The positions the answer reflects, `pos_…` (T-97 item 2).
    pub position: String,
}

fn time(t: Time) -> String {
    rfc3339_millis(i64::try_from(t.0).unwrap_or(i64::MAX)).unwrap_or_default()
}

fn rec(id: &RecordId) -> String {
    id.to_external()
}

fn recs(ids: &[RecordId]) -> Vec<String> {
    ids.iter().map(rec).collect()
}

fn item(i: &Item) -> ItemAnswer {
    ItemAnswer {
        index: i.index,
        state: i.state.wire_name().to_owned(),
        closed_by: i.closing.as_ref().map(|c| rec(&c.record)),
        initiator: i
            .closing
            .as_ref()
            .map(|c| c.initiator.wire_name().to_owned()),
    }
}

fn pending(view: &CommitmentView) -> Vec<PendingAnswer> {
    let p = &view.pending;
    let mut out = Vec::new();
    for (what, change) in [("counter", &p.counter), ("amendment", &p.amendment)] {
        if let Some(c) = change {
            out.push(PendingAnswer {
                what: what.to_owned(),
                record: rec(&c.record),
                to: None,
                kind: None,
            });
        }
    }
    if let Some(r) = &p.revocation {
        out.push(PendingAnswer {
            what: "revocation".to_owned(),
            record: rec(&r.record),
            to: None,
            kind: Some(r.kind.wire_name().to_owned()),
        });
    }
    for (what, proposal) in [("delegation", &p.delegation), ("transfer", &p.transfer)] {
        if let Some(d) = proposal {
            out.push(PendingAnswer {
                what: what.to_owned(),
                record: rec(&d.record),
                to: Some(d.to.as_str().to_owned()),
                kind: None,
            });
        }
    }
    out
}

fn step(s: &Step) -> StepAnswer {
    let (outcome, reason) = match s.outcome {
        StepOutcome::Applied => ("applied", None),
        StepOutcome::Refused(r) => ("refused", Some(r.wire_name().to_owned())),
    };
    StepAnswer {
        record: rec(&s.record),
        operation: s.operation.wire_name().to_owned(),
        outcome: outcome.to_owned(),
        reason,
    }
}

fn missing(m: &Missing) -> String {
    match m {
        Missing::StepUp => "step_up".to_owned(),
        Missing::Gate(g) => format!("gate:{}", rec(g)),
        Missing::AccessDenied => "access_denied".to_owned(),
        Missing::AccessPending => "access_pending".to_owned(),
    }
}

fn allowed(a: &Allowed) -> AllowedAnswer {
    AllowedAnswer {
        operation: a.operation.wire_name().to_owned(),
        step: a.step.map(|s| s.wire_name().to_owned()),
        items: a.items.clone(),
        action: action_of(a.operation).map_or_else(String::new, |n| format!("work:{n}")),
        access: a.access.wire_name().to_owned(),
        missing: a.missing.iter().map(missing).collect(),
    }
}

fn mover(m: &Mover) -> MoverAnswer {
    let (kind, id) = match m {
        Mover::Party(p) => ("party", Some(p.as_str().to_owned())),
        Mover::Queue(q) => ("queue", Some(rec(q))),
        Mover::Address(Address::Party(p)) => ("address", Some(p.as_str().to_owned())),
        Mover::Address(Address::Uri(u)) => ("address", Some(u.as_str().to_owned())),
        Mover::PreconditionAddressee(c) => ("precondition_addressee", Some(rec(c))),
        Mover::Accountable => ("accountable", None),
    };
    MoverAnswer {
        kind: kind.to_owned(),
        id,
    }
}

fn signal(s: &SupportSignal) -> SignalAnswer {
    SignalAnswer {
        child: CommitmentId(s.child).to_external(),
        cause: s.cause.wire_name().to_owned(),
        record: rec(&s.record),
        notify: s.notify.as_ref().map(|p| p.as_str().to_owned()),
    }
}

fn implicit(i: ImplicitAcceptance) -> ImplicitAnswer {
    let (status, ends_at, reason) = match i {
        ImplicitAcceptance::NotStated => ("not_stated", None, None),
        ImplicitAcceptance::NoTerms => ("no_terms", None, None),
        ImplicitAcceptance::Waiting(at) => ("waiting", Some(time(at)), None),
        ImplicitAcceptance::Due => ("due", None, None),
        ImplicitAcceptance::Blocked(r) => ("blocked", None, Some(r.wire_name().to_owned())),
    };
    ImplicitAnswer {
        status: status.to_owned(),
        ends_at,
        reason,
    }
}

fn active_end(e: &ActiveEnd) -> ActiveEndAnswer {
    ActiveEndAnswer {
        obligor: e.obligor.as_str().to_owned(),
        record: rec(&e.record),
        cause: e.cause.wire_name().to_owned(),
    }
}

/// A tier a clock reached (CM-51).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ReachedAnswer {
    /// `warning` or `breach`.
    pub tier: String,
    /// The warning tier in permille of the duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permille: Option<u16>,
    /// When it was reached, RFC 3339 UTC.
    pub at: String,
    /// The definition version in effect then.
    pub version: u32,
}

/// A clock of the commitment, projected at the evaluation time (CM-50, CM-51, CM-52).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ClockAnswer {
    /// The clock Condition the request lists, `rec_…`.
    pub condition: String,
    /// The Condition record whose definition is in effect, `rec_…`.
    pub definition: String,
    /// `response`, `start` or `finish`.
    pub target: String,
    /// `not_started`, `running`, `paused` or `met`; absent when it cannot be projected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The definition version in effect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Counted milliseconds so far.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub elapsed_ms: u64,
    /// Counted milliseconds left of the duration.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub remaining_ms: u64,
    /// The highest warning tier reached, in permille.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<u16>,
    /// When it breached, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breached_at: Option<String>,
    /// Every tier reached, in order.
    pub reached: Vec<ReachedAnswer>,
    /// Since when a valid wait pauses it, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_since: Option<String>,
    /// When its target was met, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub met_at: Option<String>,
    /// When the next tier is reached if nothing else happens, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_change: Option<String>,
    /// Later Condition records that did not continue its definition, `rec_…`.
    pub ignored: Vec<String>,
    /// Why it cannot be projected: `order`, `version`, `calendar`, `rule` or `overflow`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One expected report of a periodic update (CM-53).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct DueAnswer {
    /// The expected time, RFC 3339 UTC.
    pub expected: String,
    /// The last time a report still counts, RFC 3339 UTC.
    pub deadline: String,
    /// The ledger time of the report that met it, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    /// Whether it was missed: a breach signal.
    pub missed: bool,
}

/// A periodic update of the commitment, projected at the evaluation time (CM-53, CM-64).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PeriodicAnswer {
    /// The periodic Condition the request lists, `rec_…`.
    pub condition: String,
    /// The Condition record whose definition is in effect, `rec_…`.
    pub definition: String,
    /// The expected reports up to the evaluation time.
    pub due: Vec<DueAnswer>,
    /// How many were missed.
    pub missed: u32,
    /// The deadline of the next report not yet in, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_deadline: Option<String>,
    /// The report Claims counted.
    pub reports: u32,
    /// Report Claims not counted.
    pub ignored_reports: u32,
    /// Later Condition records that did not continue its definition, `rec_…`.
    pub ignored: Vec<String>,
    /// Why it cannot be projected: `order`, `version`, `calendar`, `rule` or `overflow`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A budget of the commitment (CM-48, CM-49).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct BudgetAnswer {
    /// The budget Condition the request lists, `rec_…`.
    pub condition: String,
    /// The Condition record whose definition is in effect, `rec_…`.
    pub definition: String,
    /// `effort`, `money`, `operations` or `tokens`.
    pub measure: String,
    /// The ISO 4217 currency of a money budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// The limit in the measure's unit.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub limit: u64,
    /// Consumption reported by the commitment's obligor.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub own: u64,
    /// Consumption rolled up from its sub-commitments.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub children: u64,
    /// Both together.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub consumed: u64,
    /// What is left of the limit.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub remaining: u64,
    /// The highest warning tier reached, in permille.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<u16>,
    /// Whether consumption reached the limit; the accountable Party then holds the next move.
    pub exhausted: bool,
    /// The choices asked of the accountable Party once exhausted: `continue`, `reshape`, `drop`.
    pub decision: Vec<String>,
    /// Consumption Claims not counted.
    pub ignored_claims: u32,
    /// Sub-commitment totals in another measure.
    pub unmatched: u32,
    /// Later Condition records that did not continue its definition, `rec_…`.
    pub ignored: Vec<String>,
    /// Why it cannot be evaluated: `overflow`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The clocks, periodic updates and budgets of the commitment; nothing of it is stored (CM-51).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct TimeAnswer {
    /// The evaluation time, RFC 3339 UTC.
    pub evaluated_at: String,
    /// The tzdb release the clocks and periodic updates count in (CM-64).
    pub tzdb: String,
    /// The clocks.
    pub clocks: Vec<ClockAnswer>,
    /// The periodic updates.
    pub periodic: Vec<PeriodicAnswer>,
    /// The budgets.
    pub budgets: Vec<BudgetAnswer>,
    /// Listed time Conditions whose definition did not open, `rec_…`.
    pub undefined: Vec<String>,
}

const fn clock_error(e: ClockError) -> &'static str {
    match e {
        ClockError::Order => "order",
        ClockError::Version => "version",
        ClockError::Calendar(_) => "calendar",
        ClockError::Rule(_) => "rule",
        ClockError::Overflow => "overflow",
    }
}

const fn clock_state(s: ClockState) -> &'static str {
    match s {
        ClockState::NotStarted => "not_started",
        ClockState::Running => "running",
        ClockState::Paused => "paused",
        ClockState::Met => "met",
    }
}

const fn target(t: Target) -> &'static str {
    match t {
        Target::Response => "response",
        Target::Start => "start",
        Target::Finish => "finish",
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn clock(c: &ClockProjection) -> ClockAnswer {
    let mut out = ClockAnswer {
        condition: rec(&c.condition),
        definition: rec(&c.definition),
        target: target(c.target).to_owned(),
        state: None,
        version: None,
        elapsed_ms: 0,
        remaining_ms: 0,
        warning: None,
        breached_at: None,
        reached: Vec::new(),
        paused_since: None,
        met_at: None,
        next_change: None,
        ignored: recs(&c.ignored),
        error: None,
    };
    match &c.view {
        Ok(v) => {
            out.state = Some(clock_state(v.state).to_owned());
            out.version = Some(v.version);
            out.elapsed_ms = v.elapsed;
            out.remaining_ms = v.remaining;
            out.warning = v.warning;
            out.breached_at = v.breached.map(time);
            out.reached = v
                .reached
                .iter()
                .map(|r| ReachedAnswer {
                    tier: match r.tier {
                        Tier::Warning(_) => "warning",
                        Tier::Breach => "breach",
                    }
                    .to_owned(),
                    permille: match r.tier {
                        Tier::Warning(p) => Some(p),
                        Tier::Breach => None,
                    },
                    at: time(r.at),
                    version: r.version,
                })
                .collect();
            out.paused_since = v.paused_since.map(time);
            out.met_at = v.met_at.map(time);
            out.next_change = v.next_change.map(time);
        }
        Err(e) => out.error = Some(clock_error(*e).to_owned()),
    }
    out
}

fn periodic(p: &PeriodicProjection) -> PeriodicAnswer {
    let mut out = PeriodicAnswer {
        condition: rec(&p.condition),
        definition: rec(&p.definition),
        due: Vec::new(),
        missed: 0,
        next_deadline: None,
        reports: count(p.reports),
        ignored_reports: count(p.ignored_reports),
        ignored: recs(&p.ignored),
        error: None,
    };
    match &p.view {
        Ok(v) => {
            out.due = v
                .due
                .iter()
                .map(|d| DueAnswer {
                    expected: time(d.expected),
                    deadline: time(d.deadline),
                    report: d.report.map(time),
                    missed: d.missed,
                })
                .collect();
            out.missed = count(v.missed);
            out.next_deadline = v.next_deadline.map(time);
        }
        Err(e) => out.error = Some(clock_error(*e).to_owned()),
    }
    out
}

fn budget(b: &BudgetProjection) -> BudgetAnswer {
    let (measure, currency) = match b.budget.measure {
        Measure::Effort => ("effort", None),
        Measure::Money(c) => ("money", Some(c.code().to_owned())),
        Measure::Operations => ("operations", None),
        Measure::Tokens => ("tokens", None),
    };
    let mut out = BudgetAnswer {
        condition: rec(&b.condition),
        definition: rec(&b.definition),
        measure: measure.to_owned(),
        currency,
        limit: b.budget.limit,
        own: 0,
        children: 0,
        consumed: 0,
        remaining: b.budget.limit,
        warning: None,
        exhausted: false,
        decision: Vec::new(),
        ignored_claims: 0,
        unmatched: 0,
        ignored: recs(&b.ignored),
        error: None,
    };
    match &b.view {
        Ok(v) => {
            out.own = v.own;
            out.children = v.children;
            out.consumed = v.consumed;
            out.remaining = v.remaining;
            out.warning = v.warning;
            out.exhausted = v.exhausted;
            out.decision = v
                .decision
                .iter()
                .flat_map(|d| d.choices)
                .map(|c| {
                    match c {
                        Choice::Continue => "continue",
                        Choice::Reshape => "reshape",
                        Choice::Drop => "drop",
                    }
                    .to_owned()
                })
                .collect();
            out.ignored_claims = count(v.ignored);
            out.unmatched = count(v.unmatched);
        }
        Err(_) => out.error = Some("overflow".to_owned()),
    }
    out
}

fn time_answer(read: &CommitmentRead) -> TimeAnswer {
    TimeAnswer {
        evaluated_at: time(Time(read.evaluated_at_ms)),
        tzdb: read.tzdb.to_owned(),
        clocks: read.time.clocks.iter().map(clock).collect(),
        periodic: read.time.periodic.iter().map(periodic).collect(),
        budgets: read.time.budgets.iter().map(budget).collect(),
        undefined: recs(&read.time.undefined),
    }
}

impl CommitmentAnswer {
    /// The answer of `read`.
    #[must_use]
    pub fn of(read: &CommitmentRead) -> Self {
        let v = &read.view;
        let (obligor, queue) = match &v.obligor {
            Obligor::Party(p) => (Some(p.as_str().to_owned()), None),
            Obligor::Queue(q) => (None, Some(rec(q))),
        };
        let t = &v.terms;
        Self {
            ledger: read.ledger.to_external(),
            commitment: CommitmentId(v.root).to_external(),
            version: read.version,
            summary: v.summary().wire_name().to_owned(),
            items: v.items.iter().map(item).collect(),
            obligee: v.obligee.as_str().to_owned(),
            obligor,
            queue,
            acceptor: v.acceptor.as_str().to_owned(),
            principal: v.principal.iter().map(|p| p.as_str().to_owned()).collect(),
            terms: TermsAnswer {
                kind: t.kind.wire_name().to_owned(),
                item_count: t.item_count,
                due: t.due.map(time),
                respond_by: t.respond_by.as_ref().map(|d| time(d.at)),
                evidence_required: v.evidence_required(false),
                high_impact: t.high_impact,
                four_eyes_waived: t.four_eyes_waived,
                change_policy: t.change_policy.wire_name().to_owned(),
                undefined: t
                    .undefined
                    .iter()
                    .map(|f| f.wire_name().to_owned())
                    .collect(),
            },
            offer_version: v.offer_version,
            instruction_version: v.instruction_version,
            pending: pending(v),
            statement: v.statement.as_ref().map(|s| StatementAnswer {
                record: rec(&s.record),
                recorded_at: time(s.recorded_at),
                items: s.items.clone(),
                evidenced: s.evidenced,
                by_agent: s.by_agent,
            }),
            deferral: v.deferral.as_ref().map(|d| rec(&d.record)),
            rejections: v.rejections,
            rejected: recs(&v.rejected),
            disputes: recs(&v.disputes),
            fulfilments: recs(&v.fulfilments),
            handovers: recs(&v.handovers),
            notices: v
                .notices
                .iter()
                .map(|n| NoticeAnswer {
                    record: rec(&n.record),
                    notice_type: n.notice_type.wire_name().to_owned(),
                })
                .collect(),
            active_ends: v.active_ends.iter().map(active_end).collect(),
            steps: v.steps.iter().map(step).collect(),
            implicit_acceptance: implicit(read.implicit),
            allowed: read.next.allowed.iter().map(allowed).collect(),
            next_move: read.next.moves.iter().map(mover).collect(),
            signals: read.signals.iter().map(signal).collect(),
            time: time_answer(read),
            at: time(Time(read.at_ms)),
            position: read.position.to_external(),
        }
    }
}

pub(crate) fn written(ledger: &LedgerId, commitment: &RecordId, w: &Written) -> Response {
    let body = CommitmentWritten {
        ledger: ledger.to_external(),
        commitment: CommitmentId(*commitment).to_external(),
        record: w.record.to_external(),
        pos: w.pos,
        replayed: w.replayed,
    };
    let json = HeaderValue::from_static("application/json");
    (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, json)],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

/// What one typed write names besides its body.
pub(crate) struct Typed<'a> {
    pub(crate) kind: Kind,
    pub(crate) ledger: &'a str,
    pub(crate) commitment: Option<&'a str>,
}

pub(crate) async fn write(
    services: &ApiServices,
    typed: Typed<'_>,
    context: &RequestContext,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let caller = match caller_of(services, method, uri, headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let Ok(ledger) = LedgerId::parse_external(typed.ledger) else {
        return Problem::new(ProblemCode::InvalidId).into_response();
    };
    let commitment = match typed.commitment.map(CommitmentId::parse_external) {
        None => None,
        Some(Ok(c)) => Some(c.0),
        Some(Err(_)) => return Problem::new(ProblemCode::InvalidId).into_response(),
    };
    let mut request = match declaration_request(body, headers, context.traceparent().to_string()) {
        Ok(request) => request,
        Err(problem) => return problem.into_response(),
    };
    request.expected = Some(Expected {
        kind: typed.kind,
        commitment,
    });
    match services.writes.declare(&caller, &ledger, &request).await {
        Ok(w) => written(&ledger, &commitment.unwrap_or(w.record), &w),
        Err(refused) => write_problem(refused).into_response(),
    }
}

/// Opens a commitment with a `request`.
///
/// The body carries the signed `request` record and the Access Exercise of `work:commit` it
/// was written under. The kernel checks the request before anything is written: its required
/// fields, and every offer field when a side is an agent (CM-6, CM-7); a refused request is
/// answered with the kernel's reason and kept under its `Idempotency-Key`. A commitment is
/// opened only by a `request` and needs no Practice or template (CM-12).
#[utoipa::path(
    post,
    path = "/v1/ledgers/{ledger}/commitments",
    operation_id = "create_commitment",
    tag = "commitments",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
        ("If-Match" = String, Header, description = "The strong ETag of the version of the first Work the request concerns, `\"0\"` before its first record.")
    ),
    request_body(content = crate::writes::NewDeclaration, content_type = "application/json"),
    responses(
        (status = 201, description = "The commitment is open.", body = CommitmentWritten, headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "A body, identifier or header that does not open, or a record that is not a `request`.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
            content_type = "application/problem+json", headers(
            ("WWW-Authenticate" = String, description = "The DPoP challenge."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 403, description = "The Access evidence does not authorise this record.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 404, description = "No such ledger.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 412, description = "The Work is no longer at the If-Match version.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 413, description = "A body part is above its bound.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 422, description = "The kernel refused the record, with its reason; a refused commitment operation is kept under its key; or a body part carries a secret.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 428, description = "No If-Match.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 429, description = "The caller has spent its quota.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds until the next window.")
        )),
        (status = 503, description = "Access cannot be reached, the ledger is busy, or the outcome is being checked; send the same request again.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds to wait when the ledger is busy.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:commit")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn create_commitment(
    State(services): State<Arc<ApiServices>>,
    Path(ledger): Path<String>,
    Extension(context): Extension<RequestContext>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let typed = Typed {
        kind: Kind::Commitment(Operation::Request),
        ledger: &ledger,
        commitment: None,
    };
    write(&services, typed, &context, &method, &uri, &headers, &body).await
}

macro_rules! operation {
    ($name:ident, $operation:expr, $path:tt, $id:tt, $action:tt, $doc:tt) => {
        #[doc = $doc]
        #[utoipa::path(
            post,
            path = $path,
            operation_id = $id,
            tag = "commitments",
            params(
                ("ledger" = String, Path, description = "The ledger, `led_…`."),
                ("commitment" = String, Path, description = "The commitment, `cmt_…`."),
                ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
                ("If-Match" = String, Header, description = "The strong ETag of the commitment's version.")
            ),
            request_body(content = crate::writes::NewDeclaration, content_type = "application/json"),
            responses(
                (status = 201, description = "The record is in the ledger.", body = CommitmentWritten, headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 400, description = "A body, identifier or header that does not open, a record of another operation, or one that does not continue this commitment.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("WWW-Authenticate" = String, description = "The DPoP challenge."),
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 403, description = "The Access evidence does not authorise this record.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 404, description = "No such ledger.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 412, description = "The commitment is no longer at the If-Match version: another record changed it first.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 413, description = "A body part is above its bound.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 422, description = "The kernel refused the operation for this commitment, with its reason (`commitment`, the refusal); the refusal is kept under its key; or a body part carries a secret.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 428, description = "No If-Match.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 429, description = "The caller has spent its quota.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota."),
                    ("Retry-After" = String, description = "Seconds until the next window.")
                )),
                (status = 503, description = "Access cannot be reached, the ledger is busy, or the outcome is being checked; send the same request again.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota."),
                    ("Retry-After" = String, description = "Seconds to wait when the ledger is busy.")
                ))
            ),
            security(("access_token" = [])),
            extensions(("x-work-action" = json!($action)))
        )]
        #[allow(
            clippy::needless_pass_by_value,
            reason = "axum hands extractors over by value"
        )]
        pub async fn $name(
            State(services): State<Arc<ApiServices>>,
            Path((ledger, commitment)): Path<(String, String)>,
            Extension(context): Extension<RequestContext>,
            method: Method,
            uri: Uri,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            let typed = Typed {
                kind: Kind::Commitment($operation),
                ledger: &ledger,
                commitment: Some(&commitment),
            };
            write(&services, typed, &context, &method, &uri, &headers, &body).await
        }
    };
}

operation!(
    promise,
    Operation::Promise,
    "/v1/ledgers/{ledger}/commitments/{commitment}/promise",
    "promise_commitment",
    "work:commit",
    "Promises a requested commitment (CM-17)."
);
operation!(
    promise_conditional,
    Operation::PromiseConditional,
    "/v1/ledgers/{ledger}/commitments/{commitment}/promise-conditional",
    "promise_commitment_conditionally",
    "work:commit",
    "Promises under an addressed precondition with a validity (CM-22)."
);
operation!(
    decline,
    Operation::Decline,
    "/v1/ledgers/{ledger}/commitments/{commitment}/decline",
    "decline_commitment",
    "work:commit",
    "Declines a request with a reason code, before any promise (CM-20)."
);
operation!(
    counter,
    Operation::Counter,
    "/v1/ledgers/{ledger}/commitments/{commitment}/counter",
    "counter_commitment",
    "work:commit",
    "Offers changed terms (CM-21)."
);
operation!(
    accept_counter,
    Operation::AcceptCounter,
    "/v1/ledgers/{ledger}/commitments/{commitment}/accept-counter",
    "accept_commitment_counter",
    "work:commit",
    "Accepts the obligor candidate's counter-offer, which binds the obligor (CM-21)."
);
operation!(
    state,
    Operation::State,
    "/v1/ledgers/{ledger}/commitments/{commitment}/state",
    "state_commitment",
    "work:commit",
    "States the work done with its fulfilment references; a statement is never an acceptance (CM-25, CM-28)."
);
operation!(
    accept,
    Operation::Accept,
    "/v1/ledgers/{ledger}/commitments/{commitment}/accept",
    "accept_commitment",
    "work:close",
    "Accepts the statement in force; only the acceptor accepts (CM-37, CM-38, CM-40)."
);
operation!(
    reject,
    Operation::Reject,
    "/v1/ledgers/{ledger}/commitments/{commitment}/reject",
    "reject_commitment",
    "work:close",
    "Rejects the statement in force back to execution, with a reason (CM-26)."
);
operation!(
    cancel,
    Operation::Cancel,
    "/v1/ledgers/{ledger}/commitments/{commitment}/cancel",
    "cancel_commitment",
    "work:commit",
    "The obligor's unilateral withdrawal, with a reason code (CM-29, CM-30)."
);
operation!(
    release,
    Operation::Release,
    "/v1/ledgers/{ledger}/commitments/{commitment}/release",
    "release_commitment",
    "work:commit",
    "The obligee's release of the obligor, never counted against the obligor (CM-29)."
);
operation!(
    delegate,
    Operation::Delegate,
    "/v1/ledgers/{ledger}/commitments/{commitment}/delegate",
    "delegate_commitment",
    "work:commit",
    "Proposes or accepts a delegation of the debt; the old obligor stays bound until the new one accepts (CM-43, CM-44)."
);
operation!(
    assign,
    Operation::Assign,
    "/v1/ledgers/{ledger}/commitments/{commitment}/assign",
    "assign_commitment",
    "work:assign",
    "Proposes or accepts an assignment of the claim; the acceptor does not change (CM-43)."
);
operation!(
    dispute,
    Operation::Dispute,
    "/v1/ledgers/{ledger}/commitments/{commitment}/dispute",
    "dispute_commitment",
    "work:commit",
    "Disputes a rejection or a revocation of acceptance; the state does not change (CM-36)."
);
operation!(
    defer,
    Operation::Defer,
    "/v1/ledgers/{ledger}/commitments/{commitment}/defer",
    "defer_commitment",
    "work:commit",
    "Defers without changing the state (CM-17)."
);
operation!(
    resume,
    Operation::Resume,
    "/v1/ledgers/{ledger}/commitments/{commitment}/resume",
    "resume_commitment",
    "work:commit",
    "Closes the open deferral (CM-17)."
);
operation!(
    revoke_request,
    Operation::RevokeRequest,
    "/v1/ledgers/{ledger}/commitments/{commitment}/revoke-request",
    "revoke_commitment_request",
    "work:commit",
    "Asks to withdraw the request; the counterparty allows or refuses (CM-35)."
);
operation!(
    revoke_promise,
    Operation::RevokePromise,
    "/v1/ledgers/{ledger}/commitments/{commitment}/revoke-promise",
    "revoke_commitment_promise",
    "work:commit",
    "Asks to withdraw the promise (CM-35)."
);
operation!(
    revoke_statement,
    Operation::RevokeStatement,
    "/v1/ledgers/{ledger}/commitments/{commitment}/revoke-statement",
    "revoke_commitment_statement",
    "work:commit",
    "Asks to withdraw the statement (CM-35)."
);
operation!(
    revoke_acceptance,
    Operation::RevokeAcceptance,
    "/v1/ledgers/{ledger}/commitments/{commitment}/revoke-acceptance",
    "revoke_commitment_acceptance",
    "work:commit",
    "Asks to withdraw the acceptance; a terminal outcome never changes (CM-34, CM-35)."
);
operation!(
    allow,
    Operation::Allow,
    "/v1/ledgers/{ledger}/commitments/{commitment}/allow",
    "allow_commitment_revocation",
    "work:commit",
    "Allows the open revocation request (CM-35)."
);
operation!(
    refuse,
    Operation::Refuse,
    "/v1/ledgers/{ledger}/commitments/{commitment}/refuse",
    "refuse_commitment_request",
    "work:commit",
    "Refuses the open revocation request or terms amendment, with a reason (CM-35, CM-56)."
);
operation!(
    amend,
    Operation::Amend,
    "/v1/ledgers/{ledger}/commitments/{commitment}/amend",
    "amend_commitment",
    "work:commit",
    "A new instruction or terms version (CM-56)."
);
operation!(
    notice,
    Operation::Notice,
    "/v1/ledgers/{ledger}/commitments/{commitment}/notice",
    "notice_commitment",
    "work:commit",
    "The obligor's notice: at risk, cannot complete or obsolete suggested (CM-58)."
);
operation!(
    declare_obsolete,
    Operation::DeclareObsolete,
    "/v1/ledgers/{ledger}/commitments/{commitment}/declare-obsolete",
    "declare_commitment_obsolete",
    "work:commit",
    "Closes as obsolete, naming the parent that went away (CM-32)."
);
operation!(
    administrative_close,
    Operation::AdministrativeClose,
    "/v1/ledgers/{ledger}/commitments/{commitment}/administrative-close",
    "close_commitment_administratively",
    "work:administrative_close",
    "Closes administratively with a justification (CM-33)."
);
operation!(
    implicit_acceptance_terms,
    Operation::ImplicitAcceptanceTerms,
    "/v1/ledgers/{ledger}/commitments/{commitment}/implicit-acceptance-terms",
    "declare_commitment_implicit_acceptance_terms",
    "work:autonomy_policy_set",
    "The obligee's prior explicit terms for implicit acceptance, or their withdrawal (CM-41)."
);

/// Reads a commitment.
///
/// Every field is derived from the commitment's records in one snapshot of the ledger; nothing
/// is stored (CM-2). The answer names the transitions the caller may make now with the Access
/// action each asks for and what each still needs (P-55), and who holds the next move (CM-58);
/// the write checks every rule again. A caller with no role on the commitment does not see it.
#[utoipa::path(
    get,
    path = "/v1/ledgers/{ledger}/commitments/{commitment}",
    operation_id = "get_commitment",
    tag = "commitments",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("commitment" = String, Path, description = "The commitment, `cmt_…`."),
        ("Work-Min-Position" = Option<String>, Header, description = "A position token the answer must reflect (T-97).")
    ),
    responses(
        (status = 200, description = "The commitment.", body = CommitmentAnswer, headers(
            ("ETag" = String, description = "The commitment's version."),
            ("Work-Position" = String, description = "The positions the answer reflects."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "An identifier or position that does not open.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
            content_type = "application/problem+json", headers(
            ("WWW-Authenticate" = String, description = "The DPoP challenge."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 404, description = "No such commitment, or the caller has no role on it.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 429, description = "The caller has spent its quota.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds until the next window.")
        )),
        (status = 503, description = "Access or the database cannot be reached.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:read")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn get_commitment(
    State(services): State<Arc<ApiServices>>,
    Path((ledger, commitment)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let (Ok(ledger), Ok(commitment)) = (
        LedgerId::parse_external(&ledger),
        CommitmentId::parse_external(&commitment),
    ) else {
        return Problem::new(ProblemCode::InvalidId).into_response();
    };
    let min = match min_position(&headers) {
        Ok(min) => min,
        Err(refused) => return crate::position::refusal(refused).into_response(),
    };
    match services
        .reads
        .commitment(&caller, &ledger, &commitment.0, min.as_ref())
        .await
    {
        Ok(read) => {
            let json = HeaderValue::from_static("application/json");
            let mut response = (
                [(header::CONTENT_TYPE, json)],
                serde_json::to_vec(&CommitmentAnswer::of(&read)).unwrap_or_default(),
            )
                .into_response();
            let h = response.headers_mut();
            h.insert(WORK_POSITION, position_header(&read.position));
            h.insert(header::ETAG, etag(read.version));
            response
        }
        Err(refused) => read_problem(refused).into_response(),
    }
}

/// The commitment routes: the typed write of every operation a caller writes and the read.
pub fn routes() -> Router<Arc<ApiServices>> {
    let typed: [(&str, MethodRouter<Arc<ApiServices>>); 26] = [
        ("promise", post(promise)),
        ("promise-conditional", post(promise_conditional)),
        ("decline", post(decline)),
        ("counter", post(counter)),
        ("accept-counter", post(accept_counter)),
        ("state", post(state)),
        ("accept", post(accept)),
        ("reject", post(reject)),
        ("cancel", post(cancel)),
        ("release", post(release)),
        ("delegate", post(delegate)),
        ("assign", post(assign)),
        ("dispute", post(dispute)),
        ("defer", post(defer)),
        ("resume", post(resume)),
        ("revoke-request", post(revoke_request)),
        ("revoke-promise", post(revoke_promise)),
        ("revoke-statement", post(revoke_statement)),
        ("revoke-acceptance", post(revoke_acceptance)),
        ("allow", post(allow)),
        ("refuse", post(refuse)),
        ("amend", post(amend)),
        ("notice", post(notice)),
        ("declare-obsolete", post(declare_obsolete)),
        ("administrative-close", post(administrative_close)),
        ("implicit-acceptance-terms", post(implicit_acceptance_terms)),
    ];
    typed.into_iter().fold(
        Router::new()
            .route("/v1/ledgers/{ledger}/commitments", post(create_commitment))
            .route(
                "/v1/ledgers/{ledger}/commitments/{commitment}",
                get(get_commitment),
            ),
        |router, (operation, route)| {
            router.route(
                &format!("/v1/ledgers/{{ledger}}/commitments/{{commitment}}/{operation}"),
                route,
            )
        },
    )
}

#[cfg(test)]
mod tests;
