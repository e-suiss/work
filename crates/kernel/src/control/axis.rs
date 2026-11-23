//! The control axis (RC-30 … RC-35, ST-4): authority, control and execution are separate derived fields from separate sources (an Access answer, the executor's control mode Claim, the executor's status Claims), so a revoked authority never reads as a stopped execution; liveness comes from heartbeats against the declared interval and a missing heartbeat reads stale or unknown, never running; attention request, consultation and takeover are distinct record kinds; one driver drives an execution environment unless a time-bound control lease admits a second; Work offers only the requests the executor's capability declaration, integration depth and control mode allow; taking control runs through pause, confirmation, lease, release with a handover note and revalidation; an oversight requirement is visible and never enforced by Work; a provider failure offers the declared options.

use alloc::vec::Vec;

use crate::catalog::{ChangePolicy, ConditionType, DeclarationSubtype, StopType};
use crate::control::body::{
    Capability, ControlLease, ControlMode, ControlModeReport, Depth, ExecutionState, Heartbeat,
    Operation, RequestKind, StatusReport,
};
use crate::id::{PartyRef, RecordId, Time};
use crate::reason::wire_enum;
use crate::record::{ParamScalar, ParamValue, Record};

/// One executor report as derivation reads it: the record, its author, its ledger time and its decoded body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reported<T> {
    /// The record carrying the body.
    pub record: RecordId,
    /// Its author.
    pub author: PartyRef,
    /// Its ledger time.
    pub at: Time,
    /// The decoded body.
    pub body: T,
}

/// The latest report by `author` at or before `now`, by ledger time then ledger order.
#[must_use]
pub fn latest<'r, T>(
    reports: &'r [Reported<T>],
    author: &PartyRef,
    now: Time,
) -> Option<&'r Reported<T>> {
    reports
        .iter()
        .filter(|r| &r.author == author && r.at <= now)
        .fold(None, |best: Option<&Reported<T>>, r| match best {
            Some(b) if b.at > r.at => Some(b),
            _ => Some(r),
        })
}

wire_enum! {
    /// The authority axis, from Access (RC-30).
    AuthorityAxis {
        /// Authority is granted.
        Granted => "granted",
        /// Authority is revoked; the execution may still run.
        Revoked => "revoked",
        /// Unknown.
        Unknown => "unknown",
    }
}

wire_enum! {
    /// The liveness axis (ST-4).
    Liveness {
        /// A heartbeat arrived within the stale line.
        Live => "live",
        /// The declared interval passed without a heartbeat.
        Stale => "stale",
        /// No heartbeat was ever received.
        Unknown => "unknown",
        /// The executor left on purpose.
        Departed => "departed",
        /// No heartbeat is expected.
        NotApplicable => "not_applicable",
    }
}

wire_enum! {
    /// The execution axis, only from executor Claims (RC-30, RC-38).
    ExecutionAxis {
        /// Running.
        Running => "running",
        /// Paused.
        Paused => "paused",
        /// Stopped, as the executor confirmed.
        Stopped => "stopped",
        /// Failed.
        Failed => "failed",
        /// Completed.
        Completed => "completed",
        /// Unknown: no report, or liveness is stale or unknown.
        Unknown => "unknown",
    }
}

/// The default stale line as a multiple of the declared heartbeat interval (ST-4 item 5).
pub const DEFAULT_STALE_FACTOR: u64 = 2;

/// The liveness of `executor` at `now` (ST-4): not applicable without a declared interval, unknown without a heartbeat, departed after a graceful departure, stale once `factor` intervals pass without one.
#[must_use]
pub fn liveness(
    capability: Option<&Capability>,
    heartbeats: &[Reported<Heartbeat>],
    executor: &PartyRef,
    now: Time,
    factor: u64,
) -> Liveness {
    let Some(interval) = capability.and_then(|c| c.heartbeat) else {
        return Liveness::NotApplicable;
    };
    let Some(last) = latest(heartbeats, executor, now) else {
        return Liveness::Unknown;
    };
    if last.body.departing {
        return Liveness::Departed;
    }
    let line = last
        .at
        .0
        .saturating_add(interval.saturating_mul(factor.max(1)));
    if now.0 > line {
        Liveness::Stale
    } else {
        Liveness::Live
    }
}

/// The execution axis of `executor` at `now` (RC-30, RC-38, ST-4): the latest status Claim of the executor alone; a running or paused execution reads unknown once liveness is stale or unknown, an ended one keeps its end.
#[must_use]
pub fn execution(
    status: &[Reported<StatusReport>],
    executor: &PartyRef,
    liveness: Liveness,
    now: Time,
) -> ExecutionAxis {
    let Some(last) = latest(status, executor, now) else {
        return ExecutionAxis::Unknown;
    };
    if !last.body.status.is_final() && matches!(liveness, Liveness::Stale | Liveness::Unknown) {
        return ExecutionAxis::Unknown;
    }
    match last.body.status {
        ExecutionState::Running => ExecutionAxis::Running,
        ExecutionState::Paused => ExecutionAxis::Paused,
        ExecutionState::Stopped => ExecutionAxis::Stopped,
        ExecutionState::Failed => ExecutionAxis::Failed,
        ExecutionState::Completed => ExecutionAxis::Completed,
    }
}

/// The control mode `executor` claims at `now`; none when it has claimed none (RC-32).
#[must_use]
pub fn control_mode(
    modes: &[Reported<ControlModeReport>],
    executor: &PartyRef,
    now: Time,
) -> Option<ControlMode> {
    latest(modes, executor, now).map(|r| r.body.mode)
}

/// Who drives an execution environment and under which lease (RC-33).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Driver {
    /// The responsible driver.
    pub party: PartyRef,
    /// The `control_lease` grant in force, when a second driver drives.
    pub lease: Option<RecordId>,
}

fn released(leases: &[Reported<ControlLease>], grant: &RecordId, now: Time) -> bool {
    leases.iter().any(|r| {
        matches!(&r.body, ControlLease::Release { lease, released: at }
            if lease == &grant.0 && *at <= now && r.at <= now)
    })
}

fn grant_window(lease: &ControlLease) -> Option<(&PartyRef, Time, Time)> {
    match lease {
        ControlLease::Grant {
            driver,
            from,
            until,
            ..
        } => Some((driver, *from, *until)),
        ControlLease::Release { .. } => None,
    }
}

/// The driver at `now` (RC-33): the driver of the earliest unreleased grant whose window holds `now`, else `default`.
#[must_use]
pub fn driver_at(default: &PartyRef, leases: &[Reported<ControlLease>], now: Time) -> Driver {
    let active = leases
        .iter()
        .filter(|r| r.at <= now)
        .filter_map(|r| grant_window(&r.body).map(|w| (r, w)))
        .filter(|(r, (_, from, until))| {
            *from <= now && now < *until && !released(leases, &r.record, now)
        })
        .min_by_key(|(r, _)| r.at);
    match active {
        Some((r, (driver, _, _))) => Driver {
            party: driver.clone(),
            lease: Some(r.record),
        },
        None => Driver {
            party: default.clone(),
            lease: None,
        },
    }
}

wire_enum! {
    /// Why a control lease record does not take effect (RC-33).
    LeaseRefusal {
        /// The window overlaps another unreleased grant: there is one second driver at most.
        SecondDriver => "second_driver",
        /// The default driver needs no lease.
        AlreadyDriving => "already_driving",
        /// The release names no known grant.
        UnknownLease => "unknown_lease",
        /// Only the lease's driver or its grantor releases it.
        NotHolder => "not_holder",
        /// The grant is already released.
        AlreadyReleased => "already_released",
    }
}

/// Checks a new control lease record against the leases recorded before it (RC-33).
///
/// # Errors
/// The [`LeaseRefusal`].
pub fn check_lease(
    new: &Reported<ControlLease>,
    earlier: &[Reported<ControlLease>],
    default: &PartyRef,
) -> Result<(), LeaseRefusal> {
    match &new.body {
        ControlLease::Grant {
            driver,
            from,
            until,
            ..
        } => {
            if driver == default {
                return Err(LeaseRefusal::AlreadyDriving);
            }
            let overlaps = earlier.iter().any(|r| {
                grant_window(&r.body).is_some_and(|(_, f, u)| {
                    f < *until && *from < u && !released(earlier, &r.record, *from)
                })
            });
            if overlaps {
                return Err(LeaseRefusal::SecondDriver);
            }
            Ok(())
        }
        ControlLease::Release { lease, .. } => {
            let grant = earlier
                .iter()
                .find(|r| &r.record.0 == lease && grant_window(&r.body).is_some())
                .ok_or(LeaseRefusal::UnknownLease)?;
            let holder = grant_window(&grant.body).is_some_and(|(d, _, _)| d == &new.author);
            if !(holder || grant.author == new.author) {
                return Err(LeaseRefusal::NotHolder);
            }
            if released(earlier, &grant.record, Time(u64::MAX)) {
                return Err(LeaseRefusal::AlreadyReleased);
            }
            Ok(())
        }
    }
}

wire_enum! {
    /// The three intervention kinds, never folded into one (RC-31).
    Intervention {
        /// "Look at this": an `attention_request` Declaration.
        AttentionRequest => "attention_request",
        /// The doer asks and keeps control: a decision or information wait (`open_condition`).
        Consultation => "consultation",
        /// Control passes to another driver: a `control_lease` Declaration.
        Takeover => "takeover",
    }
}

/// The intervention kind a record is, if any (RC-31).
#[must_use]
pub fn intervention_of(record: &Record) -> Option<Intervention> {
    let Record::Declaration(d) = record else {
        return None;
    };
    match DeclarationSubtype::from_uri(d.subtype.as_str())? {
        DeclarationSubtype::AttentionRequest => Some(Intervention::AttentionRequest),
        DeclarationSubtype::ControlLease => Some(Intervention::Takeover),
        DeclarationSubtype::OpenCondition => match record.param("condition_type") {
            Some(ParamValue::Scalar(ParamScalar::Text(t)))
                if matches!(
                    ConditionType::from_uri(t),
                    Some(ConditionType::Decision | ConditionType::Information)
                ) =>
            {
                Some(Intervention::Consultation)
            }
            _ => None,
        },
        _ => None,
    }
}

/// A request Work can deliver to an executor (RC-42).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// What is asked.
    pub kind: RequestKind,
    /// The stop type of a `stop`.
    pub stop_type: Option<StopType>,
    /// The change policy of a `change`.
    pub change_policy: Option<ChangePolicy>,
}

wire_enum! {
    /// Why Work does not offer or deliver a request (RC-3, RC-32, RC-34, RC-43).
    RequestRefusal {
        /// The executor declared no capability.
        Undeclared => "undeclared",
        /// The executor integrates read only and takes no request.
        ReadOnly => "read_only",
        /// A traffic light executor takes only start, stop, resume and the budget notice.
        Depth => "depth",
        /// The capability declaration does not support it.
        Unsupported => "unsupported",
        /// The control mode does not allow it.
        Mode => "mode",
        /// Control can only be given back under a lease.
        NoLease => "no_lease",
        /// The request lacks its stop type or change policy.
        Malformed => "malformed",
    }
}

/// Checks that a request is valid for the executor (RC-3, RC-32, RC-34, RC-43): declared, allowed by the integration depth and the control mode; a stop and the budget notice stay valid in every mode.
///
/// # Errors
/// The [`RequestRefusal`].
pub fn check_request(
    request: Request,
    capability: Option<&Capability>,
    mode: Option<ControlMode>,
    lease_active: bool,
) -> Result<(), RequestRefusal> {
    let capability = capability.ok_or(RequestRefusal::Undeclared)?;
    match capability.depth {
        Depth::ReadOnly => return Err(RequestRefusal::ReadOnly),
        Depth::TrafficLight
            if !matches!(
                request.kind,
                RequestKind::Start
                    | RequestKind::Stop
                    | RequestKind::Resume
                    | RequestKind::BudgetExhausted
            ) =>
        {
            return Err(RequestRefusal::Depth);
        }
        Depth::Full | Depth::TrafficLight => {}
    }
    let supported = |yes: bool| {
        if yes {
            Ok(())
        } else {
            Err(RequestRefusal::Unsupported)
        }
    };
    let allowed = |yes: bool| {
        if yes {
            Ok(())
        } else {
            Err(RequestRefusal::Mode)
        }
    };
    match request.kind {
        RequestKind::Start | RequestKind::BudgetExhausted => Ok(()),
        RequestKind::Stop => {
            let stop = request.stop_type.ok_or(RequestRefusal::Malformed)?;
            supported(capability.stop_types.contains(&stop))
        }
        RequestKind::Resume => {
            supported(capability.supports(Operation::PauseResume))?;
            allowed(mode.is_some())
        }
        RequestKind::Takeover => {
            supported(capability.supports(Operation::Takeover))?;
            allowed(mode == Some(ControlMode::Automatic) && !lease_active)
        }
        RequestKind::ReturnControl => {
            supported(capability.supports(Operation::Takeover))?;
            allowed(matches!(
                mode,
                Some(ControlMode::Intervened | ControlMode::Manual)
            ))?;
            if lease_active {
                Ok(())
            } else {
                Err(RequestRefusal::NoLease)
            }
        }
        RequestKind::Change => {
            let policy = request.change_policy.ok_or(RequestRefusal::Malformed)?;
            supported(capability.change_policies.contains(&policy))?;
            allowed(matches!(
                mode,
                Some(ControlMode::Automatic | ControlMode::Intervened)
            ))
        }
    }
}

/// Every request Work offers for the executor now (RC-3, RC-34): only what [`check_request`] allows, so an unsupported button is never shown.
#[must_use]
pub fn offered_requests(
    capability: Option<&Capability>,
    mode: Option<ControlMode>,
    lease_active: bool,
) -> Vec<Request> {
    let plain = |kind| Request {
        kind,
        stop_type: None,
        change_policy: None,
    };
    let mut all = alloc::vec![plain(RequestKind::Start)];
    all.extend(StopType::ALL.iter().map(|s| Request {
        kind: RequestKind::Stop,
        stop_type: Some(*s),
        change_policy: None,
    }));
    all.extend(
        [
            RequestKind::Resume,
            RequestKind::Takeover,
            RequestKind::ReturnControl,
        ]
        .map(plain),
    );
    all.extend(
        [ChangePolicy::Interrupt, ChangePolicy::Rollback].map(|p| Request {
            kind: RequestKind::Change,
            stop_type: None,
            change_policy: Some(p),
        }),
    );
    all.push(plain(RequestKind::BudgetExhausted));
    all.into_iter()
        .filter(|r| check_request(*r, capability, mode, lease_active).is_ok())
        .collect()
}

wire_enum! {
    /// The steps of taking control (RC-34).
    FlowStep {
        /// A pause was requested.
        PauseRequested => "pause_requested",
        /// The executor confirmed the pause or reached a checkpoint.
        Paused => "paused",
        /// A control lease was granted.
        Leased => "leased",
        /// Control was given back with a handover note.
        Released => "released",
        /// The assumptions were checked again.
        Revalidated => "revalidated",
        /// The work resumed.
        Resumed => "resumed",
        /// The work was planned again.
        Replanned => "replanned",
    }
}

/// One event of a take-control flow; a release says whether its handover note is recorded (RC-34).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowEvent {
    /// A pause request.
    PauseRequested,
    /// The executor's pause confirmation or checkpoint.
    Paused,
    /// A control lease grant.
    Leased,
    /// The release of the lease.
    Released {
        /// Whether the releasing driver wrote the handover note (§9.11).
        handover: bool,
    },
    /// The assumptions were checked again.
    Revalidated,
    /// The work resumed.
    Resumed,
    /// The work was planned again.
    Replanned,
}

/// Why a take-control flow does not hold (RC-34).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowError {
    /// The executor does not declare pause and takeover, so the flow is not offered.
    Unsupported,
    /// The event at this index comes out of order.
    OutOfOrder(usize),
    /// The release at this index has no handover note.
    HandoverMissing(usize),
}

/// Checks a take-control flow and returns the step it reached (RC-34): pause request, executor confirmation or checkpoint, lease, release with a handover note, revalidation, then resume or replan.
///
/// # Errors
/// The [`FlowError`].
pub fn take_control(
    capability: &Capability,
    events: &[FlowEvent],
) -> Result<Option<FlowStep>, FlowError> {
    if !(capability.supports(Operation::PauseResume) && capability.supports(Operation::Takeover)) {
        return Err(FlowError::Unsupported);
    }
    let mut step: Option<FlowStep> = None;
    for (i, event) in events.iter().enumerate() {
        let next = match (step, *event) {
            (None, FlowEvent::PauseRequested) => FlowStep::PauseRequested,
            (Some(FlowStep::PauseRequested), FlowEvent::Paused) => FlowStep::Paused,
            (Some(FlowStep::Paused), FlowEvent::Leased) => FlowStep::Leased,
            (Some(FlowStep::Leased), FlowEvent::Released { handover: true }) => FlowStep::Released,
            (Some(FlowStep::Leased), FlowEvent::Released { handover: false }) => {
                return Err(FlowError::HandoverMissing(i));
            }
            (Some(FlowStep::Released), FlowEvent::Revalidated) => FlowStep::Revalidated,
            (Some(FlowStep::Revalidated), FlowEvent::Resumed) => FlowStep::Resumed,
            (Some(FlowStep::Revalidated), FlowEvent::Replanned) => FlowStep::Replanned,
            _ => return Err(FlowError::OutOfOrder(i)),
        };
        step = Some(next);
    }
    Ok(step)
}

wire_enum! {
    /// Whether the observer an oversight requirement asks for is attached, as the executor claims (RC-35).
    Observer {
        /// Attached.
        Attached => "attached",
        /// Absent.
        Absent => "absent",
        /// No Claim.
        Unknown => "unknown",
    }
}

/// An oversight requirement as Work shows it (RC-35): defined in Access, enforced by the executor, only visible in Work; it gates nothing here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OversightView<'a> {
    /// The Access role an observer must hold.
    pub role: &'a str,
    /// The observer state.
    pub observer: Observer,
}

/// The view of an oversight requirement for the Access role `role` with the executor's latest attachment Claim (RC-35).
#[must_use]
pub fn oversight(role: &str, attached: Option<bool>) -> OversightView<'_> {
    OversightView {
        role,
        observer: match attached {
            Some(true) => Observer::Attached,
            Some(false) => Observer::Absent,
            None => Observer::Unknown,
        },
    }
}

wire_enum! {
    /// What a model or provider failure offers (RC-35).
    FailureOption {
        /// Wait.
        Wait => "wait",
        /// Keep the Party and change the model underneath.
        SwapModel => "swap_model",
        /// Hand over to a new Party (§9.11).
        Handover => "handover",
        /// A human takes control.
        HumanTakeover => "human_takeover",
    }
}

/// The options a provider failure offers (RC-35): waiting always, a model swap for an agent doer, a handover when the commitment can be delegated, a human takeover when the executor declares takeover.
#[must_use]
pub fn failure_options(
    capability: Option<&Capability>,
    agent_doer: bool,
    delegable: bool,
) -> Vec<FailureOption> {
    let mut out = alloc::vec![FailureOption::Wait];
    if agent_doer {
        out.push(FailureOption::SwapModel);
    }
    if delegable {
        out.push(FailureOption::Handover);
    }
    if capability.is_some_and(|c| c.supports(Operation::Takeover)) {
        out.push(FailureOption::HumanTakeover);
    }
    out
}

/// The three separate axes of an execution and its driver (RC-30, RC-33).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Axes {
    /// From Access.
    pub authority: AuthorityAxis,
    /// From the executor's control mode Claim.
    pub control: Option<ControlMode>,
    /// From the executor's status Claims.
    pub execution: ExecutionAxis,
    /// From the executor's heartbeats.
    pub liveness: Liveness,
    /// The responsible driver.
    pub driver: Driver,
}

/// The executor reports the axes are derived from.
#[derive(Clone, Copy, Debug)]
pub struct ExecutorFacts<'a> {
    /// The executor; reports by anyone else do not count.
    pub executor: &'a PartyRef,
    /// The capability declaration in force.
    pub capability: Option<&'a Capability>,
    /// Status Claims.
    pub status: &'a [Reported<StatusReport>],
    /// Control mode Claims.
    pub modes: &'a [Reported<ControlModeReport>],
    /// Heartbeats.
    pub heartbeats: &'a [Reported<Heartbeat>],
    /// Control lease records.
    pub leases: &'a [Reported<ControlLease>],
    /// The stale line as a multiple of the heartbeat interval.
    pub stale_factor: u64,
}

/// Derives the axes at `now` (RC-30, RC-32, RC-33, ST-1, ST-4); `authority` is the Access answer and changes nothing else.
#[must_use]
pub fn axes(authority: AuthorityAxis, facts: &ExecutorFacts<'_>, now: Time) -> Axes {
    let live = liveness(
        facts.capability,
        facts.heartbeats,
        facts.executor,
        now,
        facts.stale_factor,
    );
    Axes {
        authority,
        control: control_mode(facts.modes, facts.executor, now),
        execution: execution(facts.status, facts.executor, live, now),
        liveness: live,
        driver: driver_at(facts.executor, facts.leases, now),
    }
}
