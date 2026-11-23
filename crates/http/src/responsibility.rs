//! The responsibility family of the REST API (RC-1…RC-25, RC-44, RC-48, C-6, E-45): one typed write per responsibility operation of the closed set, `POST /v1/ledgers/{ledger}/commitments/{commitment}/<operation>` under `work:claim` or `work:assign`, the explicit taking-over or acceptance of accountability as an `acknowledgement` in the commitment chain under `work:condition` (its transfer proposal is the commitment `amend` carrying `accountable`), and the Declarations that continue no commitment: queue definitions and their new versions by `supersedes` (`work:assign`), organisation rules (`work:org_rule_set`), waivers (`work:autonomy_policy_set`) and the participation policy beside one `engaged_in` (`work:write`); each takes the signed record of exactly that kind with its Access evidence, one `Idempotency-Key` and an `If-Match`, the kernel and the ledger-state checks refuse before anything is written, `422 record_rejected` with the reason `["responsibility", code]`. `GET /v1/ledgers/{ledger}/queues/{queue}` and `GET /v1/ledgers/{ledger}/parties/{party}/workload` read a queue and a Party's open workload as the records derive them, and the commitment read carries its `responsibility`; nothing of it is stored.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use axum::{Extension, Router};
use serde::Serialize;
use utoipa::ToSchema;
use work_kernel::catalog::DeclarationSubtype;
use work_kernel::commitment::{AllowedResponsibility, CommitmentView, StepOutcome};
use work_kernel::id::{LedgerId, PartyRef, RecordId, Time};
use work_kernel::responsibility::{
    Accountability, AllocationAct, AllocationEvent, Candidates, ForwardTarget, Hold, LeaseStatus,
    Offer, PingPong, QueueVersion, ResponsibilityOperation,
};
use work_proto::id::{CommitmentId, ExternalId as _};
use work_query::domain::commitments::CommitmentRead;
use work_query::domain::kinds::responsibility_action;
use work_query::domain::responsibility::{QueueRead, Responsibility, WorkloadRead};
use work_query::domain::writes::Kind;

use crate::commitments::{AllowedAnswer, Typed, write};
use crate::common::RequestContext;
use crate::control::{
    ControlAnswer, ControlAutonomyAnswer, ControlAxesAnswer, ControlInterventionAnswer,
    ControlRequestAnswer, ControlStopAnswer,
};
use crate::json::rfc3339_millis;
use crate::position::{WORK_POSITION, min_position, position_header};
use crate::problem::{Problem, ProblemCode};
use crate::reads::{ApiServices, caller_of, read_problem};

fn at(t: Time) -> String {
    rfc3339_millis(i64::try_from(t.0).unwrap_or(i64::MAX)).unwrap_or_default()
}

fn rec(id: &RecordId) -> String {
    id.to_external()
}

fn party(p: &PartyRef) -> String {
    p.as_str().to_owned()
}

fn parties(list: &[PartyRef]) -> Vec<String> {
    list.iter().map(party).collect()
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// One link of the accountability chain, in the order the derivation walks it (RC-5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ChainLinkAnswer {
    /// The Party.
    pub party: String,
    /// Where it comes from: `explicit`, `taken_over`, `transferred`, `on_behalf_of`, `obligor`,
    /// `queue_owner`, `requester` or `org_rule`.
    pub source: String,
    /// Access reports it disabled, so the derivation passes over it (RC-7).
    pub disabled: bool,
}

/// An open accountability transfer, awaiting the new Party's acceptance (RC-7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct TransferAnswer {
    /// The `amend` that proposed it, `rec_…`.
    pub record: String,
    /// The Party proposed.
    pub to: String,
}

/// The obligor's hold on the work (RC-18, RC-25).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct HoldAnswer {
    /// The obligor.
    pub party: String,
    /// The binding record, `rec_…`.
    pub record: String,
    /// When it was bound, RFC 3339 UTC.
    pub since: String,
    /// `claim`, `promise`, `offer` or `delegation`.
    pub via: String,
    /// Awarded by a bid: withdrawal only through §9 revocation or cancellation (RC-25).
    pub binding: bool,
    /// The last renewal, RFC 3339 UTC.
    pub renewed: String,
}

/// An offer of pooled work to a named Party, a distribution decision (RC-17, RC-22).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct OfferAnswer {
    /// The `offer` or `reassign`, `rec_…`.
    pub record: String,
    /// The Party offered.
    pub to: String,
    /// Who offered.
    pub by: String,
    /// The queue definition version the policy decision used, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// That version's distribution method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The capability statements and bids it used, `rec_…` (RC-23).
    pub inputs: Vec<String>,
}

/// A nomination: a candidate named, no obligor until it accepts (RC-17).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct NominationAnswer {
    /// The `nominate`, `rec_…`.
    pub record: String,
    /// The Party named.
    pub party: String,
    /// Who named it.
    pub by: String,
}

/// The assignment axis of a commitment (RC-10, RC-15, RC-16, RC-17).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AllocationAnswer {
    /// `pooled`, `offered`, `held` or `failed_to_assign`.
    pub state: String,
    /// The queue the work is in or came from, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// The queue definition version in force, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// A candidate set the work was forwarded to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<String>>,
    /// Since when it is pooled, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pooled_since: Option<String>,
    /// The obligor's hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<HoldAnswer>,
    /// The open offer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer: Option<OfferAnswer>,
    /// Every applied offer, the distribution decisions (RC-22).
    pub decisions: Vec<OfferAnswer>,
    /// The nominations.
    pub nominations: Vec<NominationAnswer>,
    /// The assignment signals for the queue owner: `failed_to_assign`, `ping_pong` or
    /// `lease_expired` (RC-13, RC-14, RC-18).
    pub signals: Vec<String>,
}

/// The ownership lease (RC-18).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct LeaseAnswer {
    /// `no_lease`, `running` or `expired`.
    pub status: String,
    /// When it runs or ran out, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// What its end does: `return_to_pool` or `keep_and_signal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    /// Its declared length in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<String>,
    /// The hold record it runs on, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold: Option<String>,
}

/// Where a forwarding sent the work (RC-14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ForwardAnswer {
    /// Another queue, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// Another candidate set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<String>>,
}

/// The ping-pong count, always visible (RC-14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PingPongAnswer {
    /// How many times the work was forwarded.
    pub count: u32,
    /// The forwarding targets, in order.
    pub chain: Vec<ForwardAnswer>,
    /// The threshold the queue in force declares.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<String>,
    /// Whether the count passed it.
    pub threshold_exceeded: bool,
}

/// One assignment history entry: who, to whom, why, when, under which policy version and its
/// result; reassignment never erases one (RC-19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct HistoryAnswer {
    /// The record, `rec_…`.
    pub record: String,
    /// The responsibility or commitment operation's wire name, or `acknowledgement`.
    pub act: String,
    /// The Party it speaks for.
    pub by: String,
    /// The Party it names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// The reason a forwarding gives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// Its ledger time, RFC 3339 UTC.
    pub at: String,
    /// The queue definition version in force, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// `applied` or `refused`.
    pub outcome: String,
    /// The kernel's reason of a refused record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The responsibility of a commitment as its records derive it (RC-1…RC-25).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ResponsibilityAnswer {
    /// The single accountable Party; absent only when it falls to an organisation the ledger
    /// does not name (RC-1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accountable: Option<String>,
    /// Where it comes from: `explicit`, `taken_over`, `transferred`, `on_behalf_of`, `obligor`,
    /// `queue_owner`, `requester` or `org_rule`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Derived rather than declared or accepted (RC-5).
    pub derived: bool,
    /// A disabled Party fell away: no one is responsible until a new Party accepts (RC-7).
    pub unowned: bool,
    /// The organisation rule version the derivation used, `rec_…` (RC-48).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The internal responsible under the `organization` regime (RC-48).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<String>,
    /// An open accountability transfer (RC-7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer: Option<TransferAnswer>,
    /// The accountability chain (RC-5).
    pub chain: Vec<ChainLinkAnswer>,
    /// The assignment axis.
    pub allocation: AllocationAnswer,
    /// The ownership lease.
    pub lease: LeaseAnswer,
    /// The ping-pong count and forwarding chain.
    pub ping_pong: PingPongAnswer,
    /// The assignment history.
    pub history: Vec<HistoryAnswer>,
    /// The executor: the obligor in force; only its Claims count (RC-41).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
    /// The executor's capability declaration in force, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// The control requests Work offers now: only those the capability declaration, the
    /// integration depth and the control mode allow (RC-3, RC-34).
    pub offered_requests: Vec<ControlRequestAnswer>,
    /// The autonomy of the caller's moves (RC-27, RC-28, RC-49).
    pub autonomy: ControlAutonomyAnswer,
    /// Authority, control mode, execution, liveness and the driver, as separate axes; absent
    /// without an executor (RC-30, RC-32, RC-33, ST-4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<ControlAxesAnswer>,
    /// Every stop request and how it stands (RC-36, RC-38).
    pub stops: Vec<ControlStopAnswer>,
    /// The actions around takeovers (RC-8).
    pub interventions: Vec<ControlInterventionAnswer>,
}

fn hold(h: &Hold) -> HoldAnswer {
    HoldAnswer {
        party: party(&h.party),
        record: rec(&h.record),
        since: at(h.since),
        via: h.via.wire_name().to_owned(),
        binding: h.binding,
        renewed: at(h.renewed),
    }
}

fn offer(o: &Offer) -> OfferAnswer {
    OfferAnswer {
        record: rec(&o.record),
        to: party(&o.to),
        by: party(&o.by),
        policy: o.policy.as_ref().map(rec),
        method: o.method.map(|m| m.wire_name().to_owned()),
        inputs: o.inputs.iter().map(rec).collect(),
    }
}

fn forward_target(target: &ForwardTarget) -> ForwardAnswer {
    match target {
        ForwardTarget::Queue(q) => ForwardAnswer {
            queue: Some(rec(q)),
            candidates: None,
        },
        ForwardTarget::Candidates(list) => ForwardAnswer {
            queue: None,
            candidates: Some(parties(list)),
        },
    }
}

const fn lease_status(status: LeaseStatus) -> (&'static str, Option<Time>) {
    match status {
        LeaseStatus::NoLease => ("no_lease", None),
        LeaseStatus::Running(end) => ("running", Some(end)),
        LeaseStatus::Expired { at, .. } => ("expired", Some(at)),
    }
}

fn act(a: AllocationAct) -> String {
    match a {
        AllocationAct::Responsibility(op) => op.wire_name().to_owned(),
        AllocationAct::Commitment(op) => op.wire_name().to_owned(),
        AllocationAct::Acknowledgement => "acknowledgement".to_owned(),
    }
}

fn history_entry(e: &AllocationEvent, why: Option<&String>) -> HistoryAnswer {
    let (outcome, reason) = match e.outcome {
        StepOutcome::Applied => ("applied", None),
        StepOutcome::Refused(r) => ("refused", Some(r.wire_name().to_owned())),
    };
    HistoryAnswer {
        record: rec(&e.record),
        act: act(e.act),
        by: party(&e.by),
        to: e.to.as_ref().map(party),
        why: why.cloned(),
        at: at(e.at),
        policy: e.policy.as_ref().map(rec),
        outcome: outcome.to_owned(),
        reason,
    }
}

fn ping_pong(p: &PingPong, view: &CommitmentView) -> PingPongAnswer {
    PingPongAnswer {
        count: count(p.count),
        chain: p.chain.iter().map(forward_target).collect(),
        threshold: view
            .allocation
            .definition
            .as_ref()
            .and_then(|d| d.definition.ping_pong_threshold)
            .map(|t| t.to_string()),
        threshold_exceeded: p.over,
    }
}

fn accountable(a: Option<&Accountability>) -> (Option<String>, Option<String>) {
    a.map_or((None, None), |a| {
        (Some(party(&a.party)), Some(a.source.wire_name().to_owned()))
    })
}

impl ResponsibilityAnswer {
    /// The responsibility of the commitment `read` names.
    #[must_use]
    pub fn of(read: &CommitmentRead) -> Self {
        let r: &Responsibility = &read.responsibility;
        let v = &read.view;
        let a = r.accountability.as_ref();
        let (holder_lease, hold_record) = v
            .allocation
            .hold
            .as_ref()
            .map_or((None, None), |h| (h.lease, Some(rec(&h.record))));
        let (status, expires) = lease_status(r.lease);
        let (accountable, source) = accountable(a);
        let control = ControlAnswer::of(&read.control);
        Self {
            accountable,
            source,
            derived: a.is_none_or(|a| a.derived),
            unowned: a.is_some_and(|a| a.unowned),
            rule: a.and_then(|a| a.rule.as_ref()).map(rec),
            internal: a.and_then(|a| a.internal.as_ref()).map(party),
            transfer: a.and_then(|a| a.transfer.as_ref()).map(|t| TransferAnswer {
                record: rec(&t.record),
                to: party(&t.to),
            }),
            chain: r
                .chain
                .iter()
                .map(|l| ChainLinkAnswer {
                    party: party(&l.party),
                    source: l.source.wire_name().to_owned(),
                    disabled: l.disabled,
                })
                .collect(),
            allocation: AllocationAnswer {
                state: r.state.wire_name().to_owned(),
                queue: v.allocation.queue.as_ref().map(rec),
                policy: v.allocation.definition.as_ref().map(|d| rec(&d.version)),
                candidates: v.allocation.candidates.as_deref().map(parties),
                pooled_since: v.allocation.pooled_since.map(at),
                holder: v.allocation.hold.as_ref().map(hold),
                offer: v.allocation.offer.as_ref().map(offer),
                decisions: v.allocation.offers.iter().map(offer).collect(),
                nominations: v
                    .allocation
                    .nominations
                    .iter()
                    .map(|n| NominationAnswer {
                        record: rec(&n.record),
                        party: party(&n.party),
                        by: party(&n.by),
                    })
                    .collect(),
                signals: r
                    .signals
                    .iter()
                    .map(|s| s.kind.wire_name().to_owned())
                    .collect(),
            },
            lease: LeaseAnswer {
                status: status.to_owned(),
                expires_at: expires.map(at),
                expiry: holder_lease.map(|l| l.expiry.wire_name().to_owned()),
                duration_ms: holder_lease.map(|l| l.duration.to_string()),
                hold: hold_record.filter(|_| holder_lease.is_some()),
            },
            ping_pong: ping_pong(&r.ping_pong, v),
            history: v
                .allocation
                .history
                .iter()
                .map(|e| history_entry(e, r.reasons.get(&e.record)))
                .collect(),
            executor: control.executor,
            capability: control.capability,
            offered_requests: control.offered_requests,
            autonomy: control.autonomy,
            control: control.control,
            stops: control.stops,
            interventions: control.interventions,
        }
    }
}

/// The allowed entry of a responsibility operation the caller may write now (RC-17, P-55).
pub(crate) fn allowed(a: &AllowedResponsibility) -> AllowedAnswer {
    AllowedAnswer {
        operation: a.operation.wire_name().to_owned(),
        step: None,
        items: Vec::new(),
        action: format!("work:{}", responsibility_action(a.operation)),
        access: a.access.wire_name().to_owned(),
        missing: a.missing.iter().map(crate::commitments::missing).collect(),
    }
}

/// A queue definition version (RC-10, RC-11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct QueueVersionAnswer {
    /// The version record, `rec_…`.
    pub record: String,
    /// Its position.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub pos: u64,
    /// The owner it names.
    pub owner: String,
    /// Its author and `on_behalf_of` chain.
    pub author_chain: Vec<String>,
}

/// The queue definition in force (RC-11, RC-12, RC-13, RC-14, RC-18, RC-21, RC-24).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct QueueDefinitionAnswer {
    /// The single Party responsible for the work in the queue.
    pub owner: String,
    /// The listed candidates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<String>>,
    /// The Access group or role whose members are candidates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_group: Option<String>,
    /// `push`, `pull`, `bid` or `skill`.
    pub distribution: String,
    /// How long pooled work may wait, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_within_ms: Option<String>,
    /// The ownership lease length, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_ms: Option<String>,
    /// What the lease's end does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expiry: Option<String>,
    /// Parties that may not take work from it.
    pub excluded: Vec<String>,
    /// The forwarding count above which the owner gets a signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ping_pong_threshold: Option<String>,
    /// The open workload above which a Party is overloaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wip_limit: Option<String>,
    /// The capabilities a skill-based policy matches.
    pub skills: Vec<String>,
}

/// One open commitment of a queue (RC-10, RC-15, RC-16).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct QueueItemAnswer {
    /// The commitment, `cmt_…`.
    pub commitment: String,
    /// `pooled`, `offered`, `held` or `failed_to_assign`.
    pub state: String,
    /// The obligor holding it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// The Party its open offer names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offered_to: Option<String>,
    /// Since when it is pooled, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pooled_since: Option<String>,
    /// Its forwarding count.
    pub ping_pong: u32,
    /// `no_lease`, `running` or `expired`.
    pub lease: String,
    /// When its lease runs or ran out, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<String>,
}

/// An attention signal of a queue for its owner (RC-13, RC-14, RC-18, RC-24).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct QueueSignalAnswer {
    /// `failed_to_assign`, `ping_pong`, `lease_expired` or `overload`.
    pub kind: String,
    /// The commitment it is about, `cmt_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// The overloaded Party.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
}

/// A queue as its records derive it; no field is stored (RC-10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct QueueAnswer {
    /// The ledger, `led_…`.
    pub ledger: String,
    /// The queue, the root of its definition chain, `rec_…`.
    pub queue: String,
    /// The version in force, `rec_…`.
    pub version: String,
    /// The definition in force.
    pub definition: QueueDefinitionAnswer,
    /// Every version in ledger order.
    pub versions: Vec<QueueVersionAnswer>,
    /// The queue's accountable Party (RC-7, RC-12).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accountable: Option<String>,
    /// Where it comes from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accountable_source: Option<String>,
    /// The open commitments in the queue or taken from it.
    pub work: Vec<QueueItemAnswer>,
    /// The attention signals.
    pub signals: Vec<QueueSignalAnswer>,
    /// The ledger time the answer reflects, RFC 3339 UTC.
    pub at: String,
    /// The positions the answer reflects, `pos_…`.
    pub position: String,
}

fn definition(v: &QueueVersion) -> QueueDefinitionAnswer {
    let d = &v.definition;
    let (candidates, candidate_group) = match &d.candidates {
        Candidates::Parties(list) => (Some(parties(list)), None),
        Candidates::Group(g) => (None, Some(g.clone())),
    };
    QueueDefinitionAnswer {
        owner: party(&d.owner),
        candidates,
        candidate_group,
        distribution: d.distribution.wire_name().to_owned(),
        start_within_ms: d.start_within.map(|n| n.to_string()),
        lease_ms: d.lease.map(|l| l.duration.to_string()),
        lease_expiry: d.lease.map(|l| l.expiry.wire_name().to_owned()),
        excluded: parties(&d.excluded),
        ping_pong_threshold: d.ping_pong_threshold.map(|n| n.to_string()),
        wip_limit: d.wip_limit.map(|n| n.to_string()),
        skills: d.skills.iter().map(|s| s.as_str().to_owned()).collect(),
    }
}

impl QueueAnswer {
    /// The answer of `read`, `None` for a queue without a version.
    #[must_use]
    pub fn of(read: &QueueRead) -> Option<Self> {
        let q = &read.view;
        let current = q.versions.last()?;
        let (accountable, accountable_source) = accountable(q.accountability.as_ref());
        let mut signals: Vec<QueueSignalAnswer> = q
            .work
            .iter()
            .flat_map(|item| {
                item.signals.iter().map(|s| QueueSignalAnswer {
                    kind: s.wire_name().to_owned(),
                    commitment: Some(CommitmentId(item.commitment).to_external()),
                    party: None,
                })
            })
            .collect();
        signals.extend(q.overloaded.iter().map(|w| QueueSignalAnswer {
            kind: "overload".to_owned(),
            commitment: None,
            party: Some(party(&w.party)),
        }));
        Some(Self {
            ledger: read.ledger.to_external(),
            queue: rec(&q.queue),
            version: rec(&current.version),
            definition: definition(current),
            versions: q
                .versions
                .iter()
                .map(|v| QueueVersionAnswer {
                    record: rec(&v.version),
                    pos: v.position,
                    owner: party(&v.definition.owner),
                    author_chain: parties(&v.author_chain),
                })
                .collect(),
            accountable,
            accountable_source,
            work: q
                .work
                .iter()
                .map(|item| {
                    let (lease, expires) = lease_status(item.lease);
                    QueueItemAnswer {
                        commitment: CommitmentId(item.commitment).to_external(),
                        state: item.state.wire_name().to_owned(),
                        holder: item.holder.as_ref().map(party),
                        offered_to: item.offered.as_ref().map(party),
                        pooled_since: item.pooled_since.map(at),
                        ping_pong: count(item.ping_pong.count),
                        lease: lease.to_owned(),
                        lease_expires_at: expires.map(at),
                    }
                })
                .collect(),
            signals,
            at: at(Time(read.at_ms)),
            position: read.position.to_external(),
        })
    }
}

/// One open commitment a Party holds (RC-18, RC-24).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct HeldAnswer {
    /// The commitment, `cmt_…`.
    pub commitment: String,
    /// The queue it was taken from, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// `claim`, `promise`, `offer` or `delegation`.
    pub via: String,
    /// Since when, RFC 3339 UTC.
    pub since: String,
}

/// A WIP limit a queue in force declares for a Party it lists (RC-24).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct WipLimitAnswer {
    /// The queue, `rec_…`.
    pub queue: String,
    /// The limit.
    pub wip_limit: String,
    /// Whether the open workload passes it.
    pub overloaded: bool,
}

/// The open workload of one Party, a derived view; no field is stored (RC-24).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct WorkloadAnswer {
    /// The ledger, `led_…`.
    pub ledger: String,
    /// The Party.
    pub party: String,
    /// Open commitments it is bound to as obligor.
    pub open: u32,
    /// Of those, the ones it claimed from a pool.
    pub claimed: u32,
    /// Running executions; not derived by this read, so 0.
    pub running: u32,
    /// Whether any WIP limit that lists it is passed.
    pub overloaded: bool,
    /// The open commitments it holds.
    pub held: Vec<HeldAnswer>,
    /// The WIP limits of the queues in force that list it.
    pub limits: Vec<WipLimitAnswer>,
    /// The ledger time the answer reflects, RFC 3339 UTC.
    pub at: String,
    /// The positions the answer reflects, `pos_…`.
    pub position: String,
}

impl WorkloadAnswer {
    /// The answer of `read`.
    #[must_use]
    pub fn of(read: &WorkloadRead) -> Self {
        let w = &read.view;
        Self {
            ledger: read.ledger.to_external(),
            party: party(&w.workload.party),
            open: w.workload.open,
            claimed: w.workload.claimed,
            running: w.workload.running,
            overloaded: w.limits.iter().any(|l| l.overloaded),
            held: w
                .held
                .iter()
                .map(|h| HeldAnswer {
                    commitment: CommitmentId(h.commitment).to_external(),
                    queue: h.queue.as_ref().map(rec),
                    via: h.via.wire_name().to_owned(),
                    since: at(h.since),
                })
                .collect(),
            limits: w
                .limits
                .iter()
                .map(|l| WipLimitAnswer {
                    queue: rec(&l.queue),
                    wip_limit: l.limit.to_string(),
                    overloaded: l.overloaded,
                })
                .collect(),
            at: at(Time(read.at_ms)),
            position: read.position.to_external(),
        }
    }
}

macro_rules! continuation {
    ($name:ident, $kind:expr, $path:tt, $id:tt, $action:tt, $doc:tt) => {
        #[doc = $doc]
        #[utoipa::path(
            post,
            path = $path,
            operation_id = $id,
            tag = "responsibility",
            params(
                ("ledger" = String, Path, description = "The ledger, `led_…`."),
                ("commitment" = String, Path, description = "The commitment, `cmt_…`."),
                ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
                ("If-Match" = String, Header, description = "The strong ETag of the commitment's version.")
            ),
            request_body(content = crate::writes::NewDeclaration, content_type = "application/json"),
            responses(
                (status = 201, description = "The record is in the ledger.", body = crate::commitments::CommitmentWritten, headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 400, description = "A body, identifier or header that does not open, a record of another kind, or one that does not continue this commitment.", body = Problem,
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
                (status = 422, description = "The kernel refused the record for this commitment, with its reason (`responsibility`, the refusal); the refusal is kept under its key; or a body part carries a secret.", body = Problem,
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
                kind: $kind,
                ledger: &ledger,
                commitment: Some(&commitment),
            };
            write(&services, typed, &context, &method, &uri, &headers, &body).await
        }
    };
}

macro_rules! declaration {
    ($name:ident, $kind:expr, $path:tt, $id:tt, $action:tt, $doc:tt) => {
        #[doc = $doc]
        #[utoipa::path(
            post,
            path = $path,
            operation_id = $id,
            tag = "responsibility",
            params(
                ("ledger" = String, Path, description = "The ledger, `led_…`."),
                ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
                ("If-Match" = String, Header, description = "The strong ETag of the version of the first Work the record concerns, `\"0\"` when it concerns none.")
            ),
            request_body(content = crate::writes::NewDeclaration, content_type = "application/json"),
            responses(
                (status = 201, description = "The record is in the ledger.", body = crate::commitments::CommitmentWritten, headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 400, description = "A body, identifier or header that does not open, or a record of another kind.", body = Problem,
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
                (status = 422, description = "The kernel or the ledger-state check refused the record, with its reason (`responsibility`, the refusal); the refusal is kept under its key; or a body part carries a secret.", body = Problem,
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
            Path(ledger): Path<String>,
            Extension(context): Extension<RequestContext>,
            method: Method,
            uri: Uri,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            let typed = Typed {
                kind: $kind,
                ledger: &ledger,
                commitment: None,
            };
            write(&services, typed, &context, &method, &uri, &headers, &body).await
        }
    };
}

continuation!(
    claim,
    Kind::Responsibility(ResponsibilityOperation::Claim),
    "/v1/ledgers/{ledger}/commitments/{commitment}/claim",
    "claim_commitment",
    "work:claim",
    "A candidate takes pooled work from a `pull` queue and counts as having promised (RC-17, RC-11)."
);
continuation!(
    unclaim,
    Kind::Responsibility(ResponsibilityOperation::Unclaim),
    "/v1/ledgers/{ledger}/commitments/{commitment}/unclaim",
    "unclaim_commitment",
    "work:claim",
    "The claiming obligor returns the work to the pool; no cancellation and no release (RC-17)."
);
continuation!(
    forward,
    Kind::Responsibility(ResponsibilityOperation::Forward),
    "/v1/ledgers/{ledger}/commitments/{commitment}/forward",
    "forward_commitment",
    "work:assign",
    "Moves pooled work to another queue or candidate set, with a reason (RC-17, RC-14)."
);
continuation!(
    nominate,
    Kind::Responsibility(ResponsibilityOperation::Nominate),
    "/v1/ledgers/{ledger}/commitments/{commitment}/nominate",
    "nominate_for_commitment",
    "work:assign",
    "Names a candidate, who is no obligor until it accepts (RC-17)."
);
continuation!(
    offer_work,
    Kind::Responsibility(ResponsibilityOperation::Offer),
    "/v1/ledgers/{ledger}/commitments/{commitment}/offer",
    "offer_commitment",
    "work:assign",
    "Offers pooled work to a named Party, by hand or by the distribution policy (RC-17, RC-21, RC-22)."
);
continuation!(
    reassign,
    Kind::Responsibility(ResponsibilityOperation::Reassign),
    "/v1/ledgers/{ledger}/commitments/{commitment}/reassign",
    "reassign_commitment",
    "work:assign",
    "Offers the work to a new Party; the obligor stays until the debt changes hands by delegation (RC-17)."
);
continuation!(
    renew_lease,
    Kind::Responsibility(ResponsibilityOperation::RenewLease),
    "/v1/ledgers/{ledger}/commitments/{commitment}/renew-lease",
    "renew_commitment_lease",
    "work:claim",
    "The obligor extends its ownership lease (RC-18)."
);
continuation!(
    acknowledge,
    Kind::Declaration(DeclarationSubtype::Acknowledgement),
    "/v1/ledgers/{ledger}/commitments/{commitment}/acknowledge",
    "acknowledge_commitment_accountability",
    "work:condition",
    "Takes over accountability while none is explicit, or accepts the open transfer an `amend` carrying `accountable` proposed, naming it in `proposal`; an agent never takes accountability (RC-5, RC-7)."
);
declaration!(
    create_queue,
    Kind::Declaration(DeclarationSubtype::QueueDefinition),
    "/v1/ledgers/{ledger}/queues",
    "create_queue_definition",
    "work:assign",
    "Defines a queue, or a new version of one by superseding the version in force; its owner must be a human or an organisation (RC-10, RC-11, RC-12)."
);
declaration!(
    create_org_rule,
    Kind::Declaration(DeclarationSubtype::OrgRule),
    "/v1/ledgers/{ledger}/org-rules",
    "create_org_rule",
    "work:org_rule_set",
    "Declares an organisation's rule: group resolutions, the fallback Party and the regime; one chain per organisation, a new version supersedes the version in force (RC-48)."
);
declaration!(
    create_waiver,
    Kind::Declaration(DeclarationSubtype::Waiver),
    "/v1/ledgers/{ledger}/waivers",
    "create_waiver",
    "work:autonomy_policy_set",
    "A principal narrows one waivable guarantee for one commitment or one Work (RC-9)."
);
declaration!(
    create_participation,
    Kind::Claim,
    "/v1/ledgers/{ledger}/participation",
    "declare_participation",
    "work:write",
    "Declares an agent's participation policy, the `participation` parameter of an `observation` beside exactly one `engaged_in` of the agent; only a principal of the agent changes it later (RC-44)."
);

fn json_response<T: Serialize>(body: &T) -> Response {
    let json = HeaderValue::from_static("application/json");
    (
        [(header::CONTENT_TYPE, json)],
        serde_json::to_vec(body).unwrap_or_default(),
    )
        .into_response()
}

/// Reads a queue.
///
/// The definition in force and every version, the queue's accountable Party, its open work with
/// each commitment's assignment state, and its attention signals: nobody took the work,
/// ping-pong past the threshold, an expired lease, and listed candidates over the WIP limit; all
/// derived from the records in one snapshot. Only the queue's owner, a listed candidate or an
/// author of one of its versions reads it.
#[utoipa::path(
    get,
    path = "/v1/ledgers/{ledger}/queues/{queue}",
    operation_id = "get_queue",
    tag = "responsibility",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("queue" = String, Path, description = "The queue, the root of its definition chain, `rec_…`."),
        ("Work-Min-Position" = Option<String>, Header, description = "A position token the answer must reflect (T-97).")
    ),
    responses(
        (status = 200, description = "The queue.", body = QueueAnswer, headers(
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
        (status = 404, description = "No such queue, or the caller may not read it.", body = Problem,
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
pub async fn get_queue(
    State(services): State<Arc<ApiServices>>,
    Path((ledger, queue)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let (Ok(ledger), Ok(queue)) = (
        LedgerId::parse_external(&ledger),
        RecordId::parse_external(&queue),
    ) else {
        return Problem::new(ProblemCode::InvalidId).into_response();
    };
    let min = match min_position(&headers) {
        Ok(min) => min,
        Err(refused) => return crate::position::refusal(refused).into_response(),
    };
    match services
        .reads
        .queue(&caller, &ledger, &queue, min.as_ref())
        .await
    {
        Ok(read) => {
            let Some(answer) = QueueAnswer::of(&read) else {
                return Problem::new(ProblemCode::NotFound).into_response();
            };
            let mut response = json_response(&answer);
            response
                .headers_mut()
                .insert(WORK_POSITION, position_header(&read.position));
            response
        }
        Err(refused) => read_problem(refused).into_response(),
    }
}

/// Reads a Party's open workload.
///
/// The open commitments the Party is bound to as obligor, those it claimed from a pool, the work
/// it holds and the WIP limits of the queues in force that list it, with the overload each one
/// raises; all derived from the records in one snapshot, and never a ranking. Only the Party
/// itself or the owner of a queue that lists it reads it.
#[utoipa::path(
    get,
    path = "/v1/ledgers/{ledger}/parties/{party}/workload",
    operation_id = "get_party_workload",
    tag = "responsibility",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("party" = String, Path, description = "The Party, `pty_…`."),
        ("Work-Min-Position" = Option<String>, Header, description = "A position token the answer must reflect (T-97).")
    ),
    responses(
        (status = 200, description = "The workload.", body = WorkloadAnswer, headers(
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
        (status = 404, description = "No such ledger, or the caller may not read this workload.", body = Problem,
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
pub async fn get_party_workload(
    State(services): State<Arc<ApiServices>>,
    Path((ledger, party)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let (Ok(ledger), Ok(party)) = (
        LedgerId::parse_external(&ledger),
        PartyRef::parse_external(&party),
    ) else {
        return Problem::new(ProblemCode::InvalidId).into_response();
    };
    let min = match min_position(&headers) {
        Ok(min) => min,
        Err(refused) => return crate::position::refusal(refused).into_response(),
    };
    match services
        .reads
        .workload(&caller, &ledger, &party, min.as_ref())
        .await
    {
        Ok(read) => {
            let mut response = json_response(&WorkloadAnswer::of(&read));
            response
                .headers_mut()
                .insert(WORK_POSITION, position_header(&read.position));
            response
        }
        Err(refused) => read_problem(refused).into_response(),
    }
}

/// The responsibility routes: one typed write per responsibility operation and the
/// accountability acknowledgement in a commitment chain, the Declarations that continue no
/// commitment, and the queue and workload reads.
pub fn routes() -> Router<Arc<ApiServices>> {
    let typed: [(&str, MethodRouter<Arc<ApiServices>>); 8] = [
        ("claim", post(claim)),
        ("unclaim", post(unclaim)),
        ("forward", post(forward)),
        ("nominate", post(nominate)),
        ("offer", post(offer_work)),
        ("reassign", post(reassign)),
        ("renew-lease", post(renew_lease)),
        ("acknowledge", post(acknowledge)),
    ];
    typed.into_iter().fold(
        Router::new()
            .route("/v1/ledgers/{ledger}/queues", post(create_queue))
            .route("/v1/ledgers/{ledger}/queues/{queue}", get(get_queue))
            .route("/v1/ledgers/{ledger}/org-rules", post(create_org_rule))
            .route("/v1/ledgers/{ledger}/waivers", post(create_waiver))
            .route(
                "/v1/ledgers/{ledger}/participation",
                post(create_participation),
            )
            .route(
                "/v1/ledgers/{ledger}/parties/{party}/workload",
                get(get_party_workload),
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
