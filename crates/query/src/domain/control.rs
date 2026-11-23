//! The control of one commitment as its records derive it (RC-3, RC-8, RC-26 … RC-43, ST-4, SEC-7, WD-149, WD-150 item 19): a control record names its commitment by citing the commitment's `request`, or a control record of it, in `basis`; the executor is the obligor in force and only its capability, status, control mode and heartbeat Claims on the commitment's Work count (RC-41); their `work/control/1` bodies come from the `definition` parts the caller opened. The write checks of the control records and of an operator correction, and the read projection (the requests offered, the autonomy of the caller's moves, the control axes, the stop requests, the interventions and the lease activity), are both computed here from the same records; nothing is stored.

use std::collections::BTreeMap;

use suiss_crypto::dcbor::{self, Limits, Value};
use work_kernel::catalog::{ChangePolicy, DeclarationSubtype};
use work_kernel::commitment::{AccessAnswer, Allowed, CommitmentView, Operation};
use work_kernel::control::autonomy::{
    AccessView, ActionRisk, Autonomy, BasisGap, Evidence, Impact, PolicyRefusal, admit_policy,
    check_basis, evaluate, principal_of,
};
use work_kernel::control::axis::{
    AuthorityAxis, Axes, DEFAULT_STALE_FACTOR, ExecutorFacts, Intervention, LeaseRefusal, Reported,
    Request, RequestRefusal, axes, check_lease, check_request, driver_at, intervention_of, latest,
    offered_requests,
};
use work_kernel::control::body::{
    AutonomyPolicy, Capability, ControlBodyError, ControlLease, ControlMode, ControlModeReport,
    Heartbeat, RequestKind, StatusReport,
};
use work_kernel::control::executor::{
    CAPABILITY_EXT_KEY, CONTROL_MODE_EXT_KEY, HEARTBEAT_EXT_KEY, STATUS_EXT_KEY,
};
use work_kernel::control::stop::{
    CorrectionRefusal, ForceSource, ResponseRefusal, ResumeRefusal, StopFacts, StopView,
    check_correction, check_response, check_resume, stop_type_of, stops,
};
use work_kernel::derive::Restriction;
use work_kernel::id::{PartyRef, RecordId, Time, WorkId};
use work_kernel::ontology::{Commitment, Obligor};
use work_kernel::record::{Capacity, ParamScalar, ParamValue, Record};
use work_kernel::responsibility::{
    ActBy, ControlSpan, InterventionMark, LeaseStatus, interventions, lease_status,
};
use work_kernel::validate::ActorType;

use crate::domain::commitments::{action_of, commitment_of};
use crate::domain::kinds::{FORCED_STOP_EXT_KEY, Kind, executor_key, kind_of};

/// One record of the ledger as the control projection reads it.
#[derive(Clone, Copy, Debug)]
pub struct Logged<'r> {
    /// The record.
    pub id: RecordId,
    /// Its ledger position.
    pub pos: u64,
    /// Its ledger time.
    pub at: Time,
    /// Its author's Access actor type, from the envelope.
    pub actor: Option<ActorType>,
    /// The record.
    pub record: &'r Record,
}

/// The opened `definition` parts, by record.
pub type Opened = BTreeMap<RecordId, Vec<u8>>;

/// The shape a typed control write names beyond the record kind (C-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// An `open_condition` of decision or information type: the doer asks and keeps control (RC-31).
    Consultation,
    /// An `amend` whose change policy is `interrupt` or `rollback`: an operator correction (RC-40, CM-57).
    Correction,
}

fn subtype(record: &Record) -> Option<DeclarationSubtype> {
    match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str()),
        Record::Act(_) | Record::Claim(_) => None,
    }
}

/// The interrupting or rolling back change policy an `amend` carries, which makes it an operator correction (RC-40, CM-57).
#[must_use]
pub fn correction_policy(record: &Record) -> Option<ChangePolicy> {
    if subtype(record) != Some(DeclarationSubtype::Amend) {
        return None;
    }
    match record.param("change_policy") {
        Some(ParamValue::Scalar(ParamScalar::Text(t))) => ChangePolicy::from_wire_name(t)
            .filter(|p| matches!(p, ChangePolicy::Interrupt | ChangePolicy::Rollback)),
        _ => None,
    }
}

/// Whether `record` has the shape `form` names (C-6).
#[must_use]
pub fn has_form(record: &Record, form: Form) -> bool {
    match form {
        Form::Consultation => intervention_of(record) == Some(Intervention::Consultation),
        Form::Correction => correction_policy(record).is_some(),
    }
}

/// The source of a recorded forced stop: the deterministic CBOR text of its extension value (RC-37).
#[must_use]
pub fn force_source(record: &Record) -> Option<ForceSource> {
    let ext = record
        .core()
        .ext
        .iter()
        .flatten()
        .find(|e| e.key.as_str() == FORCED_STOP_EXT_KEY)?;
    match dcbor::decode(&ext.value.0, Limits::CEILING).ok()? {
        Value::Text(t) => ForceSource::from_wire_name(&t),
        _ => None,
    }
}

/// Whether `record` is a control record a commitment's control reads: a stop request, its answer and its lifting, a control lease, a handover note, an attention request, a consultation or a recorded forced stop (RC-31, RC-33, RC-34, RC-36 … RC-40).
#[must_use]
pub fn is_control(record: &Record) -> bool {
    match subtype(record) {
        Some(
            DeclarationSubtype::StopRequest
            | DeclarationSubtype::StopResponse
            | DeclarationSubtype::ResumeAfterStop
            | DeclarationSubtype::ControlLease
            | DeclarationSubtype::HandoffNote
            | DeclarationSubtype::AttentionRequest,
        ) => true,
        Some(DeclarationSubtype::OpenCondition) => {
            intervention_of(record) == Some(Intervention::Consultation)
        }
        Some(_) => false,
        None => {
            matches!(record, Record::Claim(_)) && executor_key(record) == Some(FORCED_STOP_EXT_KEY)
        }
    }
}

/// The commitment, by its `request`, that `record` names in its `basis`: the first basis record that opens or continues a commitment, or that is a control record of one.
#[must_use]
pub fn named(
    record: &Record,
    views: &[CommitmentView],
    members: &BTreeMap<RecordId, RecordId>,
) -> Option<RecordId> {
    record.basis().iter().find_map(|b| {
        commitment_of(views, b)
            .map(|v| v.root)
            .or_else(|| members.get(b).copied())
    })
}

/// The commitment each control record of `logged` names, in ledger order.
#[must_use]
pub fn members(logged: &[Logged<'_>], views: &[CommitmentView]) -> BTreeMap<RecordId, RecordId> {
    let mut out = BTreeMap::new();
    for l in logged {
        if is_control(l.record)
            && let Some(root) = named(l.record, views, &out)
        {
            out.insert(l.id, root);
        }
    }
    out
}

/// The executor of a commitment: its obligor in force; none while a queue holds the debtor side (RC-41).
#[must_use]
pub const fn executor(view: &CommitmentView) -> Option<&PartyRef> {
    match &view.obligor {
        Obligor::Party(p) => Some(p),
        Obligor::Queue(_) => None,
    }
}

fn works_of(logged: &[Logged<'_>], root: &RecordId) -> Vec<WorkId> {
    logged
        .iter()
        .find(|l| l.id == *root)
        .map(|l| l.record.core().concerns.clone())
        .unwrap_or_default()
}

fn on_works(l: &Logged<'_>, works: &[WorkId]) -> bool {
    l.record.core().concerns.iter().any(|w| works.contains(w))
}

/// The Claims of `executor` with one of the executor coordination extension keys on `works`, in ledger order (RC-41, RC-42).
fn claims<'a, 'r>(
    logged: &'a [Logged<'r>],
    executor: &'a PartyRef,
    works: &'a [WorkId],
    key: &'static str,
) -> impl Iterator<Item = &'a Logged<'r>> {
    logged.iter().filter(move |l| {
        matches!(l.record, Record::Claim(_))
            && &l.record.core().author == executor
            && executor_key(l.record) == Some(key)
            && on_works(l, works)
    })
}

fn reported<T>(l: &Logged<'_>, body: T) -> Reported<T> {
    Reported {
        record: l.id,
        author: l.record.core().author.clone(),
        at: l.at,
        body,
    }
}

fn decoded<'a, 'r, T>(
    found: impl Iterator<Item = &'a Logged<'r>>,
    opened: &Opened,
    decode: fn(&[u8]) -> Result<T, ControlBodyError>,
) -> Vec<Reported<T>>
where
    'r: 'a,
{
    found
        .filter_map(|l| {
            let body = decode(opened.get(&l.id)?).ok()?;
            Some(reported(l, body))
        })
        .collect()
}

/// The control leases of the commitment `root`, decoded from their opened `definition` parts, in ledger order (RC-33).
fn leases(
    logged: &[Logged<'_>],
    members: &BTreeMap<RecordId, RecordId>,
    root: &RecordId,
    opened: &Opened,
) -> Vec<Reported<ControlLease>> {
    decoded(
        logged.iter().filter(|l| {
            subtype(l.record) == Some(DeclarationSubtype::ControlLease)
                && members.get(&l.id) == Some(root)
        }),
        opened,
        ControlLease::decode,
    )
}

/// Whether a recorded forced stop counts: the executor records an enforcement, a system Party an Access revocation (RC-37).
#[must_use]
pub fn forced_counts(
    source: ForceSource,
    author: &PartyRef,
    actor: Option<ActorType>,
    executor: &PartyRef,
) -> bool {
    match source {
        ForceSource::Enforcement => author == executor,
        ForceSource::AccessRevocation => actor == Some(ActorType::System),
    }
}

fn forced(
    logged: &[Logged<'_>],
    members: &BTreeMap<RecordId, RecordId>,
    root: &RecordId,
    executor: &PartyRef,
) -> Vec<Reported<ForceSource>> {
    logged
        .iter()
        .filter(|l| members.get(&l.id) == Some(root))
        .filter_map(|l| {
            let source = force_source(l.record)?;
            forced_counts(source, &l.record.core().author, l.actor, executor)
                .then(|| reported(l, source))
        })
        .collect()
}

fn acting(record: &Record) -> &PartyRef {
    match &record.core().capacity {
        Some(Capacity::For(p)) => p,
        Some(Capacity::Own) | None => &record.core().author,
    }
}

/// The autonomy policy in force for `principals`: the latest `autonomy_policy` Declaration speaking for one of them whose body opens and that is the principal's own (RC-27, RC-29).
#[must_use]
pub fn policy_in_force(
    logged: &[Logged<'_>],
    opened: &Opened,
    principals: &[PartyRef],
) -> Option<(RecordId, AutonomyPolicy)> {
    logged
        .iter()
        .rev()
        .filter(|l| {
            subtype(l.record) == Some(DeclarationSubtype::AutonomyPolicy)
                && principals.contains(acting(l.record))
        })
        .find_map(|l| {
            let body = AutonomyPolicy::decode(opened.get(&l.id)?).ok()?;
            let principal = principal_of(l.record).unwrap_or(&l.record.core().author);
            admit_policy(
                l.record,
                &body,
                principal,
                l.actor.unwrap_or(ActorType::Agent),
            )
            .ok()?;
            Some((l.id, body))
        })
}

fn latest_pos<'a, 'r>(found: impl Iterator<Item = &'a Logged<'r>>) -> Option<(RecordId, u64)>
where
    'r: 'a,
{
    found.last().map(|l| (l.id, l.pos))
}

/// The records whose `definition` part the control of `view` reads, with their positions: its control leases, the executor's latest capability, control mode and heartbeat Claims and every status Claim, and the autonomy policies of `principals` (RC-27, RC-33, RC-42).
#[must_use]
pub fn wanted(
    logged: &[Logged<'_>],
    view: &CommitmentView,
    views: &[CommitmentView],
    principals: &[PartyRef],
) -> Vec<(RecordId, u64)> {
    let members = members(logged, views);
    let mut out: Vec<(RecordId, u64)> = logged
        .iter()
        .filter(|l| {
            let lease = subtype(l.record) == Some(DeclarationSubtype::ControlLease)
                && members.get(&l.id) == Some(&view.root);
            let policy = subtype(l.record) == Some(DeclarationSubtype::AutonomyPolicy)
                && principals.contains(acting(l.record));
            lease || policy
        })
        .map(|l| (l.id, l.pos))
        .collect();
    if let Some(executor) = executor(view) {
        let works = works_of(logged, &view.root);
        for key in [CAPABILITY_EXT_KEY, CONTROL_MODE_EXT_KEY, HEARTBEAT_EXT_KEY] {
            out.extend(latest_pos(claims(logged, executor, &works, key)));
        }
        out.extend(claims(logged, executor, &works, STATUS_EXT_KEY).map(|l| (l.id, l.pos)));
    }
    out.sort_by_key(|(_, pos)| *pos);
    out.dedup();
    out
}

/// What the executor declares and claims of one execution at a time (RC-32, RC-33, RC-42).
#[derive(Clone, Debug)]
pub struct Execution {
    /// The executor: the obligor in force.
    pub executor: PartyRef,
    /// The capability declaration in force and its record.
    pub capability: Option<(RecordId, Capability)>,
    /// The status Claims.
    pub status: Vec<Reported<StatusReport>>,
    /// The control mode Claims.
    pub modes: Vec<Reported<ControlModeReport>>,
    /// The heartbeats whose bodies opened.
    pub heartbeats: Vec<Reported<Heartbeat>>,
    /// The ledger times of the executor's status and heartbeat Claims, opened or not: the activity that renews its ownership lease (RC-18, WD-150 item 19).
    pub activity: Vec<Time>,
    /// The commitment's control leases.
    pub leases: Vec<Reported<ControlLease>>,
    /// The recorded forced stops that count.
    pub forced: Vec<Reported<ForceSource>>,
}

impl Execution {
    /// The control mode the executor claims at `now`.
    #[must_use]
    pub fn mode(&self, now: Time) -> Option<ControlMode> {
        latest(&self.modes, &self.executor, now).map(|r| r.body.mode)
    }

    /// Whether a control lease drives the execution at `now` (RC-33).
    #[must_use]
    pub fn lease_active(&self, now: Time) -> bool {
        driver_at(&self.executor, &self.leases, now).lease.is_some()
    }

    /// The capability declaration in force.
    #[must_use]
    pub fn declared(&self) -> Option<&Capability> {
        self.capability.as_ref().map(|(_, c)| c)
    }
}

/// The execution of `view` at `now` from `logged` and the opened `definition` parts; none without an executor (RC-41).
#[must_use]
pub fn execution(
    logged: &[Logged<'_>],
    view: &CommitmentView,
    members: &BTreeMap<RecordId, RecordId>,
    opened: &Opened,
    now: Time,
) -> Option<Execution> {
    let executor = executor(view)?.clone();
    let works = works_of(logged, &view.root);
    let capabilities = decoded(
        claims(logged, &executor, &works, CAPABILITY_EXT_KEY),
        opened,
        Capability::decode,
    );
    let capability = latest(&capabilities, &executor, now).map(|r| (r.record, r.body.clone()));
    let activity = logged
        .iter()
        .filter(|l| {
            l.at <= now
                && matches!(l.record, Record::Claim(_))
                && l.record.core().author == executor
                && matches!(
                    executor_key(l.record),
                    Some(STATUS_EXT_KEY | HEARTBEAT_EXT_KEY)
                )
                && on_works(l, &works)
        })
        .map(|l| l.at)
        .collect();
    Some(Execution {
        status: decoded(
            claims(logged, &executor, &works, STATUS_EXT_KEY),
            opened,
            StatusReport::decode,
        ),
        modes: decoded(
            claims(logged, &executor, &works, CONTROL_MODE_EXT_KEY),
            opened,
            ControlModeReport::decode,
        ),
        heartbeats: decoded(
            claims(logged, &executor, &works, HEARTBEAT_EXT_KEY),
            opened,
            Heartbeat::decode,
        ),
        leases: leases(logged, members, &view.root, opened),
        forced: forced(logged, members, &view.root, &executor),
        capability,
        activity,
        executor,
    })
}

/// The autonomy of one move the caller may make (RC-27, RC-28, RC-49).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoveAutonomy {
    /// The Access action, `work:<action>`.
    pub action: String,
    /// The commitment operation, for a commitment move.
    pub operation: Option<Operation>,
    /// The control request, for a control move.
    pub request: Option<Request>,
    /// The evaluation.
    pub autonomy: Autonomy,
}

/// Whether a commitment operation can be undone and whether it binds another party (RC-28): a terminal outcome is irreversible, an acceptance, an accepted counter-offer, a delegation, an assignment and a new instruction bind the other side.
#[must_use]
pub const fn operation_risk(op: Operation) -> (bool, bool) {
    let irreversible = matches!(
        op,
        Operation::Accept
            | Operation::Cancel
            | Operation::Release
            | Operation::Decline
            | Operation::AdministrativeClose
            | Operation::DeclareObsolete
    );
    let binds = matches!(
        op,
        Operation::Accept
            | Operation::AcceptCounter
            | Operation::Delegate
            | Operation::Assign
            | Operation::Amend
    );
    (!irreversible, binds)
}

/// The Access action of a control request the caller writes, with whether it binds another party; the start permission and the budget notice are Work's own deliveries and none (E-45, RC-42).
#[must_use]
pub const fn request_action(kind: RequestKind) -> Option<(&'static str, bool)> {
    match kind {
        RequestKind::Stop | RequestKind::Resume => Some(("stop_request", false)),
        RequestKind::Takeover | RequestKind::ReturnControl => Some(("control", false)),
        RequestKind::Change => Some(("commit", true)),
        RequestKind::Start | RequestKind::BudgetExhausted => None,
    }
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The autonomy of each move under `policy` or the defaults (RC-27, RC-28, RC-49): Access decides each move when it is written and its deny is final, so the evaluation is the one inside an Access allow; a policy naming a restriction rule set the read does not evaluate gates every move.
#[must_use]
pub fn autonomy(
    view: &CommitmentView,
    allowed: &[Allowed],
    offered: &[Request],
    policy: Option<&AutonomyPolicy>,
) -> Vec<MoveAutonomy> {
    let restriction = if policy.is_some_and(|p| p.rule_set.is_some()) {
        Restriction::Require
    } else {
        Restriction::NoObjection
    };
    let access = AccessView {
        answer: AccessAnswer::Allow,
        limits: &[],
    };
    let impact = if view.terms.high_impact {
        Impact::High
    } else {
        Impact::Normal
    };
    let judge = |action: &str, objects: u64, reversible: bool, binds: bool| {
        let risk = ActionRisk {
            action,
            objects,
            reversible,
            binds_other_party: binds,
            impact,
            evidence: Evidence::Strong,
        };
        evaluate(&risk, &access, policy, restriction)
    };
    let mut out = Vec::new();
    for a in allowed {
        let Some(name) = action_of(a.operation) else {
            continue;
        };
        let action = format!("work:{name}");
        let (reversible, binds) = operation_risk(a.operation);
        let autonomy = judge(&action, count(a.items.len()), reversible, binds);
        out.push(MoveAutonomy {
            action,
            operation: Some(a.operation),
            request: None,
            autonomy,
        });
    }
    for r in offered {
        let Some((name, binds)) = request_action(r.kind) else {
            continue;
        };
        let action = format!("work:{name}");
        let autonomy = judge(&action, count(view.items.len()), true, binds);
        out.push(MoveAutonomy {
            action,
            operation: None,
            request: Some(*r),
            autonomy,
        });
    }
    out
}

/// What the control read of one commitment needs besides the fold.
#[derive(Clone, Copy, Debug)]
pub struct ControlInputs<'a> {
    /// The ledger's records in order.
    pub logged: &'a [Logged<'a>],
    /// The commitment.
    pub view: &'a CommitmentView,
    /// Every commitment of the ledger.
    pub views: &'a [CommitmentView],
    /// The `definition` parts [`wanted`] named, as opened.
    pub opened: &'a Opened,
    /// The caller.
    pub caller: &'a PartyRef,
    /// The commitment moves the caller may make now.
    pub allowed: &'a [Allowed],
    /// The evaluation time.
    pub now: Time,
}

/// The control of one commitment at a time; nothing of it is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRead {
    /// The executor: the obligor in force.
    pub executor: Option<PartyRef>,
    /// The capability declaration in force.
    pub capability: Option<RecordId>,
    /// The control requests Work offers now: only those the capability declaration, the integration depth and the control mode allow (RC-3, RC-34).
    pub offered: Vec<Request>,
    /// The autonomy policy in force; the defaults apply without one (RC-49).
    pub policy: Option<RecordId>,
    /// The autonomy of each move the caller may make.
    pub autonomy: Vec<MoveAutonomy>,
    /// The authority, control, execution and liveness axes and the driver; none without an executor (RC-30, RC-33, ST-4).
    pub axes: Option<Axes>,
    /// Every stop request (RC-36 … RC-40).
    pub stops: Vec<StopView>,
    /// The actions around takeovers (RC-8).
    pub interventions: Vec<(RecordId, InterventionMark)>,
    /// The executor's activity times that renew its ownership lease (WD-150 item 19).
    pub activity: Vec<Time>,
    /// The ownership lease with that activity (RC-18).
    pub lease: LeaseStatus,
}

fn principals(view: &CommitmentView, caller: &PartyRef) -> Vec<PartyRef> {
    let mut out = vec![caller.clone()];
    for p in &view.principal {
        if !out.contains(p) {
            out.push(p.clone());
        }
    }
    out
}

/// The Parties whose autonomy policy a read of `view` by `caller` evaluates: the caller and the commitment's principals (RC-27).
#[must_use]
pub fn policy_principals(view: &CommitmentView, caller: &PartyRef) -> Vec<PartyRef> {
    principals(view, caller)
}

fn coordinators(view: &CommitmentView, executor: Option<&PartyRef>) -> Vec<PartyRef> {
    let mut out: Vec<PartyRef> = Vec::new();
    for p in [&view.obligee, &view.acceptor]
        .into_iter()
        .chain(view.principal.iter())
    {
        if Some(p) != executor && !out.contains(p) {
            out.push(p.clone());
        }
    }
    out
}

fn spans(leases: &[Reported<ControlLease>]) -> Vec<ControlSpan> {
    leases
        .iter()
        .filter_map(|r| match &r.body {
            ControlLease::Grant { driver, .. } => Some(ControlSpan {
                record: r.record,
                party: driver.clone(),
                from: r.at,
                until: leases.iter().find_map(|x| match &x.body {
                    ControlLease::Release { lease, released } if *lease == r.record.0 => {
                        Some(*released)
                    }
                    _ => None,
                }),
            }),
            ControlLease::Release { .. } => None,
        })
        .collect()
}

fn acts(logged: &[Logged<'_>], works: &[WorkId], now: Time) -> Vec<ActBy> {
    logged
        .iter()
        .filter(|l| l.at <= now && matches!(l.record, Record::Act(_)) && on_works(l, works))
        .map(|l| ActBy {
            record: l.id,
            party: l.record.core().author.clone(),
            at: l.at,
        })
        .collect()
}

/// The control of `inputs.view` at `inputs.now` (RC-3, RC-8, RC-27 … RC-40, ST-4, WD-150 item 19).
#[must_use]
pub fn project(inputs: &ControlInputs<'_>) -> ControlRead {
    let ControlInputs {
        logged,
        view,
        views,
        opened,
        caller,
        allowed,
        now,
    } = *inputs;
    let members = members(logged, views);
    let execution = execution(logged, view, &members, opened, now);
    let capability = execution.as_ref().and_then(Execution::declared);
    let offered = execution.as_ref().map_or_else(Vec::new, |e| {
        offered_requests(capability, e.mode(now), e.lease_active(now))
    });
    let policy = policy_in_force(logged, opened, &principals(view, caller));
    let moves = autonomy(view, allowed, &offered, policy.as_ref().map(|(_, p)| p));
    let works = works_of(logged, &view.root);
    let principal = view.principal.last().unwrap_or(&view.obligee);
    let declarations: Vec<(RecordId, Time, &Record)> = logged
        .iter()
        .filter(|l| {
            matches!(l.record, Record::Declaration(_)) && members.get(&l.id) == Some(&view.root)
        })
        .map(|l| (l.id, l.at, l.record))
        .collect();
    let (control, stop_views, marks, activity) = match &execution {
        Some(e) => {
            let revoked = e
                .forced
                .iter()
                .any(|f| f.at <= now && f.body == ForceSource::AccessRevocation);
            let authority = if revoked {
                AuthorityAxis::Revoked
            } else {
                AuthorityAxis::Unknown
            };
            let facts = ExecutorFacts {
                executor: &e.executor,
                capability,
                status: &e.status,
                modes: &e.modes,
                heartbeats: &e.heartbeats,
                leases: &e.leases,
                stale_factor: DEFAULT_STALE_FACTOR,
            };
            let stop_views = stops(
                &StopFacts {
                    records: &declarations,
                    executor: &e.executor,
                    principal,
                    capability,
                    status: &e.status,
                    forced: &e.forced,
                },
                now,
            );
            let spans = spans(&e.leases);
            let acts = acts(logged, &works, now);
            let marks = interventions(&acts, &spans, &coordinators(view, Some(&e.executor)));
            (
                Some(axes(authority, &facts, now)),
                stop_views,
                marks,
                e.activity.clone(),
            )
        }
        None => (None, Vec::new(), Vec::new(), Vec::new()),
    };
    ControlRead {
        executor: execution.as_ref().map(|e| e.executor.clone()),
        capability: execution
            .as_ref()
            .and_then(|e| e.capability.as_ref().map(|(id, _)| *id)),
        offered,
        policy: policy.map(|(id, _)| id),
        autonomy: moves,
        axes: control,
        stops: stop_views,
        interventions: marks,
        lease: lease_status(view, now, &activity),
        activity,
    }
}

/// Why a control record or an operator correction is refused at its write; its reason is `control:<code>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRefusal {
    /// A stop, lease or forced stop record names no commitment in its `basis`.
    NoCommitment,
    /// The commitment has no executor: a queue holds its debtor side.
    NoExecutor,
    /// A forced stop's source is missing, or its author may not record it (RC-37).
    ForcedSource,
    /// The `definition` part is not a `work/control/1` body of its kind; the member it refused.
    Definition(&'static str),
    /// An agent action's normative basis lacks a component (RC-26).
    Basis(BasisGap),
    /// The autonomy policy does not take effect (RC-27, RC-29).
    Policy(PolicyRefusal),
    /// The control lease does not take effect (RC-33).
    Lease(LeaseRefusal),
    /// The request is not one the executor takes (RC-3, RC-32, RC-34, SEC-7).
    Request(RequestRefusal),
    /// The stop response does not answer (RC-36, RC-38).
    Response(ResponseRefusal),
    /// The resumption does not cite its stop request (RC-40).
    Resume(ResumeRefusal),
    /// The correction's version does not grow (RC-40).
    Correction(CorrectionRefusal),
}

impl ControlRefusal {
    /// The reason the write answers: `control:<code>`.
    #[must_use]
    pub fn reason(&self) -> String {
        let code = match self {
            Self::NoCommitment => "no_commitment".to_owned(),
            Self::NoExecutor => "no_executor".to_owned(),
            Self::ForcedSource => "forced_source".to_owned(),
            Self::Definition(member) => format!("definition:{member}"),
            Self::Basis(gap) => format!("basis:{}", gap.wire_name()),
            Self::Policy(r) => r.wire_name().to_owned(),
            Self::Lease(r) => r.wire_name().to_owned(),
            Self::Request(r) => r.wire_name().to_owned(),
            Self::Response(r) => r.wire_name().to_owned(),
            Self::Resume(r) => r.wire_name().to_owned(),
            Self::Correction(r) => r.wire_name().to_owned(),
        };
        format!("control:{code}")
    }
}

/// One control record or operator correction a caller asks to write.
#[derive(Clone, Copy, Debug)]
pub struct ControlAsked<'a> {
    /// The record.
    pub record: &'a Record,
    /// Its identifier.
    pub id: RecordId,
    /// Its author's Access actor type.
    pub author_actor: ActorType,
    /// The ledger time the write takes.
    pub now: Time,
    /// The opening of its `definition` part, when it carries one.
    pub definition: Option<&'a [u8]>,
}

/// The ledger a control write is checked against.
#[derive(Clone, Copy, Debug)]
pub struct ControlLog<'a> {
    /// The ledger's records in order.
    pub logged: &'a [Logged<'a>],
    /// Every commitment of the ledger.
    pub views: &'a [CommitmentView],
    /// The `definition` parts [`wanted`] named for the commitment the record names, as opened.
    pub opened: &'a Opened,
}

/// The commitment a control record or correction concerns: the one its `basis` names, or the one a correction continues.
#[must_use]
pub fn concerned(record: &Record, log: &ControlLog<'_>) -> Option<RecordId> {
    if correction_policy(record).is_some() {
        return record
            .supersedes()
            .next()
            .and_then(|t| commitment_of(log.views, t))
            .map(|v| v.root);
    }
    named(record, log.views, &members(log.logged, log.views))
}

/// Whether the write of `record` is one [`check_control`] decides.
#[must_use]
pub fn checked(record: &Record) -> bool {
    match kind_of(record) {
        Some(Kind::Declaration(s)) => matches!(
            s,
            DeclarationSubtype::AutonomyPolicy
                | DeclarationSubtype::ControlLease
                | DeclarationSubtype::StopRequest
                | DeclarationSubtype::StopResponse
                | DeclarationSubtype::ResumeAfterStop
        ),
        Some(Kind::Executor(key)) => key == FORCED_STOP_EXT_KEY,
        Some(Kind::Commitment(Operation::Amend)) => correction_policy(record).is_some(),
        _ => false,
    }
}

fn agent_basis(asked: &ControlAsked<'_>, log: &ControlLog<'_>) -> Result<(), ControlRefusal> {
    let premises: Vec<(RecordId, &Record)> = log
        .logged
        .iter()
        .filter(|l| asked.record.basis().contains(&l.id))
        .map(|l| (l.id, l.record))
        .collect();
    check_basis(asked.record, asked.author_actor, &premises).map_err(|gaps| {
        ControlRefusal::Basis(gaps.first().copied().unwrap_or(BasisGap::UnknownPremise))
    })
}

fn body<T>(
    asked: &ControlAsked<'_>,
    decode: fn(&[u8]) -> Result<T, ControlBodyError>,
) -> Result<T, ControlRefusal> {
    let bytes = asked
        .definition
        .ok_or(ControlRefusal::Definition("definition"))?;
    decode(bytes).map_err(|e| ControlRefusal::Definition(e.0))
}

fn requests<'a>(
    log: &ControlLog<'a>,
    members: &BTreeMap<RecordId, RecordId>,
    root: &RecordId,
) -> Vec<(RecordId, &'a Record)> {
    log.logged
        .iter()
        .filter(|l| members.get(&l.id) == Some(root) && stop_type_of(l.record).is_some())
        .map(|l| (l.id, l.record))
        .collect()
}

fn ask(e: &Execution, now: Time, request: Request) -> Result<(), ControlRefusal> {
    check_request(request, e.declared(), e.mode(now), e.lease_active(now))
        .map_err(ControlRefusal::Request)
}

/// Checks a control lease against the commitment's leases of its environment; a grant is a takeover the executor takes, standing on its normative basis when an agent writes it (RC-26, RC-33, RC-34).
fn lease_record(
    asked: &ControlAsked<'_>,
    log: &ControlLog<'_>,
    e: &Execution,
) -> Result<(), ControlRefusal> {
    let lease = body(asked, ControlLease::decode)?;
    let environment = match &lease {
        ControlLease::Grant { environment, .. } => Some(environment.clone()),
        ControlLease::Release { .. } => None,
    };
    let earlier: Vec<Reported<ControlLease>> = e
        .leases
        .iter()
        .filter(|r| match (&r.body, &environment) {
            (
                ControlLease::Grant {
                    environment: env, ..
                },
                Some(wanted),
            ) => env == wanted,
            _ => true,
        })
        .cloned()
        .collect();
    let new = Reported {
        record: asked.id,
        author: asked.record.core().author.clone(),
        at: asked.now,
        body: lease,
    };
    check_lease(&new, &earlier, &e.executor).map_err(ControlRefusal::Lease)?;
    if environment.is_some() {
        ask(
            e,
            asked.now,
            Request {
                kind: RequestKind::Takeover,
                stop_type: None,
                change_policy: None,
            },
        )?;
        agent_basis(asked, log)?;
    }
    Ok(())
}

/// Checks a control record or an operator correction against the records before it (RC-3, RC-26, RC-27, RC-29, RC-33, RC-36 … RC-40, SEC-7): an autonomy policy is the principal's own; a lease is checked against the commitment's leases of its environment, and a grant is a takeover the executor takes; a stop request, a resumption and a correction are requests the capability declaration and the control mode allow; a stop response answers one stop request; a resumption cites its stop request; a correction's derived version grows; a forced stop names its source and comes from the executor or a system Party; a lease grant and a resumption an agent writes stand on their normative basis.
///
/// # Errors
/// The [`ControlRefusal`].
pub fn check_control(asked: &ControlAsked<'_>, log: &ControlLog<'_>) -> Result<(), ControlRefusal> {
    let record = asked.record;
    if subtype(record) == Some(DeclarationSubtype::AutonomyPolicy) {
        let policy = body(asked, AutonomyPolicy::decode)?;
        let principal = principal_of(record).unwrap_or(&record.core().author);
        return admit_policy(record, &policy, principal, asked.author_actor)
            .map_err(ControlRefusal::Policy);
    }
    if !checked(record) {
        return Ok(());
    }
    let members = members(log.logged, log.views);
    let root = concerned(record, log).ok_or(ControlRefusal::NoCommitment)?;
    let view = log
        .views
        .iter()
        .find(|v| v.root == root)
        .ok_or(ControlRefusal::NoCommitment)?;
    let e = execution(log.logged, view, &members, log.opened, asked.now)
        .ok_or(ControlRefusal::NoExecutor)?;
    let requested = |kind, stop_type, change_policy| {
        ask(
            &e,
            asked.now,
            Request {
                kind,
                stop_type,
                change_policy,
            },
        )
    };
    if let Some(policy) = correction_policy(record) {
        requested(RequestKind::Change, None, Some(policy))?;
        let previous = u64::from(view.instruction_version);
        return check_correction(
            (previous > 0).then_some(previous),
            previous.saturating_add(1),
        )
        .map_err(ControlRefusal::Correction);
    }
    if kind_of(record) == Some(Kind::Executor(FORCED_STOP_EXT_KEY)) {
        let source = force_source(record).ok_or(ControlRefusal::ForcedSource)?;
        return if forced_counts(
            source,
            &record.core().author,
            Some(asked.author_actor),
            &e.executor,
        ) {
            Ok(())
        } else {
            Err(ControlRefusal::ForcedSource)
        };
    }
    match subtype(record) {
        Some(DeclarationSubtype::ControlLease) => lease_record(asked, log, &e),
        Some(DeclarationSubtype::StopRequest) => {
            requested(RequestKind::Stop, stop_type_of(record), None)
        }
        Some(DeclarationSubtype::StopResponse) => {
            check_response(record, &requests(log, &members, &root), &e.executor)
                .map_err(ControlRefusal::Response)
        }
        Some(DeclarationSubtype::ResumeAfterStop) => {
            check_resume(record, &requests(log, &members, &root))
                .map_err(ControlRefusal::Resume)?;
            requested(RequestKind::Resume, None, None)?;
            agent_basis(asked, log)
        }
        _ => Ok(()),
    }
}

/// Whether the executor of the commitment a request opens or a record continues declares the interrupting or rolling back change policy the record carries, which the commitment rules need (CM-57, RC-3, SEC-7).
#[must_use]
pub fn control_supported(record: &Record, log: &ControlLog<'_>, now: Time) -> bool {
    let policy = match record.param("change_policy") {
        Some(ParamValue::Scalar(ParamScalar::Text(t))) => ChangePolicy::from_wire_name(t),
        _ => None,
    };
    let Some(policy) =
        policy.filter(|p| matches!(p, ChangePolicy::Interrupt | ChangePolicy::Rollback))
    else {
        return false;
    };
    let declared = |executor: &PartyRef, works: &[WorkId]| {
        let found = decoded(
            claims(log.logged, executor, works, CAPABILITY_EXT_KEY),
            log.opened,
            Capability::decode,
        );
        latest(&found, executor, now).is_some_and(|c| c.body.change_policies.contains(&policy))
    };
    let continued = record
        .supersedes()
        .next()
        .and_then(|t| commitment_of(log.views, t));
    match continued {
        Some(view) => {
            executor(view).is_some_and(|x| declared(x, &works_of(log.logged, &view.root)))
        }
        None => Commitment::of(record).is_some_and(|c| match &c.obligor {
            Obligor::Party(p) => declared(p, &record.core().concerns),
            Obligor::Queue(_) => false,
        }),
    }
}

/// The records whose `definition` part [`control_supported`] reads for `record`: the latest capability Claim of the executor it names.
#[must_use]
pub fn capability_wanted(
    record: &Record,
    logged: &[Logged<'_>],
    views: &[CommitmentView],
) -> Vec<(RecordId, u64)> {
    let continued = record
        .supersedes()
        .next()
        .and_then(|t| commitment_of(views, t));
    let (executor, works) = match continued {
        Some(view) => match executor(view) {
            Some(x) => (x.clone(), works_of(logged, &view.root)),
            None => return Vec::new(),
        },
        None => match Commitment::of(record).map(|c| c.obligor) {
            Some(Obligor::Party(p)) => (p, record.core().concerns.clone()),
            _ => return Vec::new(),
        },
    };
    latest_pos(claims(logged, &executor, &works, CAPABILITY_EXT_KEY))
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests;
