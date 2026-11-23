#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use work_kernel::catalog::{CommitmentKind, StopType};
use work_kernel::commitment::{CommitmentState, EvidenceRule, Item, Pending, StepOutcome, Terms};
use work_kernel::control::autonomy::{AutonomyCause, AutonomyOutcome};
use work_kernel::control::axis::{ExecutionAxis, Liveness};
use work_kernel::control::body::{Depth, ExecutionState, Operation as ControlOperation};
use work_kernel::control::stop::StopProgress;
use work_kernel::id::{Digest, LedgerId};
use work_kernel::record::{
    Act, Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Claim, ClaimType, Declaration,
    ExtValue, Extension, Param, PartName, ProtocolVersion, RecordCore, VersionVector, Visibility,
};
use work_kernel::relation::Relation;
use work_kernel::responsibility::{Accountable, Allocation};
use work_kernel::uri::{ExtKey, TypeUri};

use super::*;

const ALICE: &str = "party:acme:alice";
const BOB: &str = "party:acme:bob";
const ARM: &str = "party:acme:robot-arm-3";
const AGENT: &str = "party:acme:agent-procure-7";
const SYS: &str = "party:acme:work-service";
const CORE: &str = "https://suiss.app/ns/work/";
const SESSION: &str = "urn:session:robot-arm-3:1";
const MINUTE: u64 = 60_000;

fn party(s: &str) -> PartyRef {
    PartyRef::new(s).unwrap()
}

fn id(n: u8) -> RecordId {
    RecordId(Digest::sha256([n; 32]))
}

fn work() -> WorkId {
    WorkId::from_bytes([7; 16])
}

fn core(author: &str) -> RecordCore {
    RecordCore {
        author: party(author),
        on_behalf_of: None,
        capacity: Some(Capacity::Own),
        basis: None,
        visibility: Visibility {
            see: Audience::Work,
            search_excluded: false,
            agent_context_excluded: false,
        },
        ledger: LedgerId(Digest::sha256([1; 32])),
        concerns: vec![work()],
        relations: None,
        authority: Some(AuthorityRef {
            proof: AuthorityProofKind::DecisionReceipt,
            digest: Digest::sha256([2; 32]),
        }),
        producer: None,
        correlation: None,
        evidence: None,
        body: None,
        params: None,
        versions: VersionVector {
            protocol: ProtocolVersion { major: 1, minor: 0 },
            schema: Digest::sha256([3; 32]),
            practices: None,
        },
        ext: None,
        critical: None,
    }
}

fn core_mut(record: &mut Record) -> &mut RecordCore {
    match record {
        Record::Act(r) => &mut r.core,
        Record::Declaration(r) => &mut r.core,
        Record::Claim(r) => &mut r.core,
    }
}

fn text(s: &str) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Text(s.to_owned()))
}

fn decl(author: &str, name: &str, params: &[(&str, ParamValue)], basis: &[RecordId]) -> Record {
    let mut params: Vec<Param> = params
        .iter()
        .map(|(k, v)| Param {
            name: PartName::parse(k).unwrap(),
            value: v.clone(),
        })
        .collect();
    params.sort_by(|a, b| work_kernel::id::canonical_text_cmp(a.name.as_str(), b.name.as_str()));
    let mut c = core(author);
    c.params = (!params.is_empty()).then_some(params);
    let mut b = basis.to_vec();
    b.sort();
    c.basis = (!b.is_empty()).then_some(b);
    Record::Declaration(Declaration {
        subtype: TypeUri::parse(&format!("{CORE}declaration/{name}")).unwrap(),
        occurred_at: None,
        core: c,
    })
}

fn with_note(mut record: Record) -> Record {
    core_mut(&mut record).body = Some(vec![BodyCommitment {
        part: PartName::parse("note").unwrap(),
        commit: Digest::sha256([4; 32]),
    }]);
    record
}

fn claim(author: &str, key: &str, value: Vec<u8>) -> Record {
    Record::Claim(Claim {
        subtype: ClaimType::from_uri(TypeUri::parse(&format!("{CORE}claim/observation")).unwrap()),
        occurred_at: Time(1),
        core: RecordCore {
            capacity: None,
            authority: None,
            ext: Some(vec![Extension {
                key: ExtKey::parse(key).unwrap(),
                value: ExtValue(value),
            }]),
            ..core(author)
        },
    })
}

fn act(author: &str) -> Record {
    Record::Act(Act {
        subtype: TypeUri::parse(&format!("{CORE}act/action")).unwrap(),
        occurred_at: Time(1),
        core: core(author),
    })
}

fn cbor_text(s: &str) -> Vec<u8> {
    dcbor::encode(&Value::text(s), Limits::CEILING).unwrap()
}

fn view() -> CommitmentView {
    CommitmentView {
        root: id(1),
        opening: StepOutcome::Applied,
        obligee: party(ALICE),
        obligor: Obligor::Party(party(ARM)),
        acceptor: party(ALICE),
        principal: vec![party(ALICE)],
        requester: vec![party(ALICE)],
        aim: None,
        conditions: Vec::new(),
        supports: Vec::new(),
        items: vec![Item {
            index: 0,
            state: CommitmentState::Promised,
            closing: None,
        }],
        terms: Terms {
            kind: CommitmentKind::Standard,
            item_count: 1,
            due: None,
            respond_by: None,
            evidence: EvidenceRule::default(),
            high_impact: false,
            four_eyes_waived: false,
            change_policy: ChangePolicy::Queue,
            aggregation: None,
            undefined: Vec::new(),
        },
        offer_version: 1,
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
        allocation: Allocation::default(),
        accountability: Accountable::default(),
    }
}

fn capability(operations: Vec<ControlOperation>, stop_types: Vec<StopType>) -> Vec<u8> {
    Capability {
        operations,
        stop_types,
        change_policies: Vec::new(),
        non_cancellable: Vec::new(),
        safe_state: None,
        checkpoints: false,
        heartbeat: Some(5_000),
        depth: Depth::Full,
    }
    .encode()
    .unwrap()
}

fn full() -> Vec<u8> {
    Capability {
        operations: vec![
            ControlOperation::Cancel,
            ControlOperation::PauseResume,
            ControlOperation::Takeover,
        ],
        stop_types: vec![
            StopType::FinishThenStop,
            StopType::Immediate,
            StopType::Pause,
        ],
        change_policies: vec![ChangePolicy::Interrupt, ChangePolicy::Rollback],
        non_cancellable: Vec::new(),
        safe_state: None,
        checkpoints: true,
        heartbeat: Some(5_000),
        depth: Depth::Full,
    }
    .encode()
    .unwrap()
}

fn mode(mode: ControlMode) -> Vec<u8> {
    ControlModeReport { mode, lease: None }.encode().unwrap()
}

fn status(status: ExecutionState) -> Vec<u8> {
    StatusReport {
        status,
        done: String::new(),
        need: String::new(),
        step: None,
    }
    .encode()
    .unwrap()
}

fn heartbeat() -> Vec<u8> {
    Heartbeat {
        session: SESSION.to_owned(),
        seq: 1,
        departing: false,
    }
    .encode()
    .unwrap()
}

fn grant(driver: &str, environment: &str, from: u64, until: u64) -> Vec<u8> {
    ControlLease::Grant {
        driver: party(driver),
        environment: environment.to_owned(),
        from: Time(from),
        until: Time(until),
        reason: "inspect the weld".to_owned(),
    }
    .encode()
    .unwrap()
}

fn policy(change: impl FnOnce(&mut AutonomyPolicy)) -> Vec<u8> {
    let mut p = AutonomyPolicy {
        version: 1,
        rule_set: None,
        bulk_threshold: None,
        near_boundary: None,
        notify: false,
        suggest: false,
        expanded_actions: Vec::new(),
        expansion: false,
    };
    change(&mut p);
    p.encode().unwrap()
}

/// A ledger of records with their times, actor types and opened `definition` parts.
struct Ledger {
    records: Vec<(RecordId, u64, Option<ActorType>, Record)>,
    opened: Opened,
    views: Vec<CommitmentView>,
}

impl Ledger {
    fn new() -> Self {
        let mut l = Self {
            records: Vec::new(),
            opened: Opened::new(),
            views: vec![view()],
        };
        l.push(
            1,
            0,
            ActorType::Human,
            decl(ALICE, "request", &[], &[]),
            None,
        );
        l
    }

    fn push(&mut self, n: u8, at: u64, actor: ActorType, record: Record, body: Option<Vec<u8>>) {
        if let Some(b) = body {
            self.opened.insert(id(n), b);
        }
        self.records.push((id(n), at, Some(actor), record));
    }

    fn executor(&mut self, n: u8, at: u64, key: &str, body: Vec<u8>) {
        self.push(
            n,
            at,
            ActorType::Machine,
            claim(ARM, key, vec![0xf5]),
            Some(body),
        );
    }

    fn logged(&self) -> Vec<Logged<'_>> {
        self.records
            .iter()
            .enumerate()
            .map(|(i, (rid, at, actor, record))| Logged {
                id: *rid,
                pos: u64::try_from(i).unwrap(),
                at: Time(*at),
                actor: *actor,
                record,
            })
            .collect()
    }

    fn check(
        &self,
        n: u8,
        record: &Record,
        actor: ActorType,
        now: u64,
        body: Option<&[u8]>,
    ) -> Result<(), String> {
        let logged = self.logged();
        let log = ControlLog {
            logged: &logged,
            views: &self.views,
            opened: &self.opened,
        };
        check_control(
            &ControlAsked {
                record,
                id: id(n),
                author_actor: actor,
                now: Time(now),
                definition: body,
            },
            &log,
        )
        .map_err(|r| r.reason())
    }

    fn read(&self, caller: &str, allowed: &[Allowed], now: u64) -> ControlRead {
        let logged = self.logged();
        let view = view();
        project(&ControlInputs {
            logged: &logged,
            view: &view,
            views: &self.views,
            opened: &self.opened,
            caller: &party(caller),
            allowed,
            now: Time(now),
        })
    }
}

fn stop_request(stop_type: &str) -> Record {
    decl(
        ALICE,
        "stop_request",
        &[("stop_type", text(stop_type))],
        &[id(1)],
    )
}

// RC-3 RC-34 RC-42
#[test]
fn rc_3_only_the_requests_the_capability_declares_are_offered() {
    let mut l = Ledger::new();
    assert_eq!(l.read(ALICE, &[], MINUTE).offered, Vec::new());
    l.executor(
        10,
        1_000,
        CAPABILITY_EXT_KEY,
        capability(vec![ControlOperation::PauseResume], vec![StopType::Pause]),
    );
    l.executor(
        11,
        1_000,
        CONTROL_MODE_EXT_KEY,
        mode(ControlMode::Automatic),
    );
    let read = l.read(ALICE, &[], 2_000);
    assert_eq!(read.capability, Some(id(10)));
    let stops: Vec<Option<StopType>> = read
        .offered
        .iter()
        .filter(|r| r.kind == RequestKind::Stop)
        .map(|r| r.stop_type)
        .collect();
    assert_eq!(stops, [Some(StopType::Pause)]);
    assert!(read.offered.iter().any(|r| r.kind == RequestKind::Resume));
    assert!(
        !read
            .offered
            .iter()
            .any(|r| matches!(r.kind, RequestKind::Takeover | RequestKind::Change))
    );
}

// SEC-7 RC-3 RC-36
#[test]
fn sec_7_a_stop_the_capability_does_not_support_is_refused() {
    let mut l = Ledger::new();
    let immediate = stop_request("immediate");
    assert_eq!(
        l.check(30, &immediate, ActorType::Human, 2_000, None),
        Err("control:undeclared".to_owned())
    );
    l.executor(
        10,
        1_000,
        CAPABILITY_EXT_KEY,
        capability(vec![ControlOperation::PauseResume], vec![StopType::Pause]),
    );
    assert_eq!(
        l.check(30, &immediate, ActorType::Human, 2_000, None),
        Err("control:unsupported".to_owned())
    );
    assert_eq!(
        l.check(30, &stop_request("pause"), ActorType::Human, 2_000, None),
        Ok(())
    );
    let unnamed = decl(ALICE, "stop_request", &[("stop_type", text("pause"))], &[]);
    assert_eq!(
        l.check(30, &unnamed, ActorType::Human, 2_000, None),
        Err("control:no_commitment".to_owned())
    );
}

// RC-33 RC-34
#[test]
fn rc_33_one_second_driver_and_only_its_holder_releases_the_lease() {
    let mut l = Ledger::new();
    l.executor(10, 1_000, CAPABILITY_EXT_KEY, full());
    l.executor(
        11,
        1_000,
        CONTROL_MODE_EXT_KEY,
        mode(ControlMode::Automatic),
    );
    let first = grant(BOB, "weld-cell", 1_000, 600_000);
    assert_eq!(
        l.check(
            20,
            &decl(ALICE, "control_lease", &[], &[id(1)]),
            ActorType::Human,
            2_000,
            Some(first.as_slice())
        ),
        Ok(())
    );
    l.push(
        20,
        2_000,
        ActorType::Human,
        decl(ALICE, "control_lease", &[], &[id(1)]),
        Some(first),
    );
    let second = grant(ALICE, "weld-cell", 3_000, 300_000);
    assert_eq!(
        l.check(
            21,
            &decl(BOB, "control_lease", &[], &[id(1)]),
            ActorType::Human,
            3_000,
            Some(second.as_slice())
        ),
        Err("control:second_driver".to_owned())
    );
    let release = ControlLease::Release {
        lease: id(20).0,
        released: Time(4_000),
    }
    .encode()
    .unwrap();
    let by = |author| decl(author, "control_lease", &[], &[id(1), id(20)]);
    assert_eq!(
        l.check(
            22,
            &by(AGENT),
            ActorType::Agent,
            4_000,
            Some(release.as_slice())
        ),
        Err("control:not_holder".to_owned())
    );
    assert_eq!(
        l.check(
            22,
            &by(BOB),
            ActorType::Human,
            4_000,
            Some(release.as_slice())
        ),
        Ok(())
    );
    assert_eq!(
        l.check(22, &by(BOB), ActorType::Human, 4_000, Some(&[0xa0][..])),
        Err("control:definition:driver".to_owned())
    );
    assert_eq!(
        l.read(ALICE, &[], 3_000).axes.unwrap().driver.party,
        party(BOB)
    );
}

// RC-36 RC-38
#[test]
fn rc_36_only_the_doer_answers_one_stop_request_and_a_refusal_gives_its_reason() {
    let mut l = Ledger::new();
    l.executor(10, 1_000, CAPABILITY_EXT_KEY, full());
    l.push(30, 2_000, ActorType::Human, stop_request("pause"), None);
    let answer = |author, response| {
        decl(
            author,
            "stop_response",
            &[("response", text(response))],
            &[id(1), id(30)],
        )
    };
    assert_eq!(
        l.check(31, &answer(BOB, "accept"), ActorType::Human, 3_000, None),
        Err("control:not_doer".to_owned())
    );
    assert_eq!(
        l.check(31, &answer(ARM, "refuse"), ActorType::Machine, 3_000, None),
        Err("control:unreasoned".to_owned())
    );
    assert_eq!(
        l.check(
            31,
            &with_note(answer(ARM, "refuse")),
            ActorType::Machine,
            3_000,
            None
        ),
        Ok(())
    );
    l.push(
        31,
        3_000,
        ActorType::Machine,
        with_note(answer(ARM, "refuse")),
        None,
    );
    let read = l.read(ALICE, &[], 4_000);
    assert_eq!(read.stops.len(), 1);
    assert_eq!(read.stops[0].progress, StopProgress::Refused);
    assert!(read.stops[0].revocation_path);
}

// RC-40 CM-57
#[test]
fn rc_40_a_resumption_cites_its_stop_and_a_correction_needs_its_declared_policy() {
    let mut l = Ledger::new();
    l.executor(
        10,
        1_000,
        CAPABILITY_EXT_KEY,
        capability(vec![ControlOperation::PauseResume], vec![StopType::Pause]),
    );
    l.executor(
        11,
        1_000,
        CONTROL_MODE_EXT_KEY,
        mode(ControlMode::Automatic),
    );
    l.push(30, 2_000, ActorType::Human, stop_request("pause"), None);
    let uncited = decl(ALICE, "resume_after_stop", &[], &[id(1)]);
    assert_eq!(
        l.check(32, &uncited, ActorType::Human, 3_000, None),
        Err("control:uncited".to_owned())
    );
    let cited = decl(ALICE, "resume_after_stop", &[], &[id(1), id(30)]);
    assert_eq!(l.check(32, &cited, ActorType::Human, 3_000, None), Ok(()));
    assert_eq!(
        l.check(32, &cited, ActorType::Agent, 3_000, None),
        Err("control:basis:on_behalf_of".to_owned())
    );
    let mut correction = decl(ALICE, "amend", &[("change_policy", text("interrupt"))], &[]);
    core_mut(&mut correction).relations = Some(vec![Relation::Supersedes {
        target: id(1),
        qualifier: None,
    }]);
    assert!(has_form(&correction, Form::Correction));
    assert_eq!(
        l.check(33, &correction, ActorType::Human, 3_000, None),
        Err("control:unsupported".to_owned())
    );
    l.executor(12, 2_500, CAPABILITY_EXT_KEY, full());
    assert_eq!(
        l.check(33, &correction, ActorType::Human, 3_000, None),
        Ok(())
    );
    let logged = l.logged();
    let log = ControlLog {
        logged: &logged,
        views: &l.views,
        opened: &l.opened,
    };
    assert!(control_supported(&correction, &log, Time(3_000)));
    assert_eq!(
        check_correction(Some(1), 1),
        Err(work_kernel::control::stop::CorrectionRefusal::NotMonotonic)
    );
}

// RC-29 RC-27 RC-49
#[test]
fn rc_29_only_the_principal_in_person_expands_autonomy() {
    let l = Ledger::new();
    let wider = policy(|p| {
        p.bulk_threshold = Some(20);
        p.expansion = true;
    });
    let mut by_agent = decl(AGENT, "autonomy_policy", &[], &[]);
    let c = core_mut(&mut by_agent);
    c.on_behalf_of = Some(vec![party(ALICE)]);
    c.capacity = Some(Capacity::For(party(ALICE)));
    assert_eq!(
        l.check(
            40,
            &by_agent,
            ActorType::Agent,
            1_000,
            Some(wider.as_slice())
        ),
        Err("control:expansion_not_by_principal".to_owned())
    );
    let own = decl(ALICE, "autonomy_policy", &[], &[]);
    assert_eq!(
        l.check(40, &own, ActorType::Human, 1_000, Some(wider.as_slice())),
        Ok(())
    );
    let mut not_for = decl(AGENT, "autonomy_policy", &[], &[]);
    core_mut(&mut not_for).on_behalf_of = Some(vec![party(ALICE)]);
    assert_eq!(
        l.check(
            40,
            &not_for,
            ActorType::Agent,
            1_000,
            Some(policy(|_| {}).as_slice())
        ),
        Err("control:not_principal".to_owned())
    );
    assert_eq!(
        l.check(40, &own, ActorType::Human, 1_000, None),
        Err("control:definition:definition".to_owned())
    );
}

fn allowed(operation: Operation) -> Allowed {
    Allowed {
        operation,
        step: None,
        items: vec![0],
        access: AccessAnswer::Require,
        missing: Vec::new(),
    }
}

// RC-27 RC-28 RC-49
#[test]
fn rc_27_the_policy_in_force_decides_the_autonomy_of_each_move() {
    let mut l = Ledger::new();
    let moves = [allowed(Operation::Notice), allowed(Operation::Accept)];
    let read = l.read(ALICE, &moves, 1_000);
    assert_eq!(read.policy, None);
    assert_eq!(read.autonomy[0].action, "work:commit");
    assert_eq!(read.autonomy[0].autonomy.outcome, AutonomyOutcome::Proceed);
    assert_eq!(
        read.autonomy[1].autonomy.outcome,
        AutonomyOutcome::RequireGate
    );
    assert!(
        read.autonomy[1]
            .autonomy
            .causes
            .contains(&AutonomyCause::Irreversible)
    );
    l.push(
        40,
        2_000,
        ActorType::Human,
        decl(ALICE, "autonomy_policy", &[], &[]),
        Some(policy(|p| p.notify = true)),
    );
    let read = l.read(ALICE, &moves, 3_000);
    assert_eq!(read.policy, Some(id(40)));
    assert_eq!(
        read.autonomy[0].autonomy.outcome,
        AutonomyOutcome::ProceedAndNotify
    );
    l.push(
        41,
        4_000,
        ActorType::Human,
        decl(ALICE, "autonomy_policy", &[], &[]),
        Some(policy(|p| {
            p.version = 2;
            p.rule_set = Some(Digest::sha256([9; 32]));
        })),
    );
    let read = l.read(ALICE, &moves, 5_000);
    assert_eq!(read.policy, Some(id(41)));
    assert_eq!(
        read.autonomy[0].autonomy.outcome,
        AutonomyOutcome::RequireGate
    );
    assert!(
        read.autonomy[0]
            .autonomy
            .causes
            .contains(&AutonomyCause::PolicyRequire)
    );
}

// ST-4 RC-30
#[test]
fn st_4_liveness_is_stale_at_twice_the_declared_heartbeat_interval() {
    let mut l = Ledger::new();
    l.executor(10, 1_000, CAPABILITY_EXT_KEY, full());
    l.executor(13, 100_000, STATUS_EXT_KEY, status(ExecutionState::Running));
    l.executor(12, 100_000, HEARTBEAT_EXT_KEY, heartbeat());
    let live = l.read(ALICE, &[], 109_000).axes.unwrap();
    assert_eq!(live.liveness, Liveness::Live);
    assert_eq!(live.execution, ExecutionAxis::Running);
    assert_eq!(live.authority, AuthorityAxis::Unknown);
    let stale = l.read(ALICE, &[], 111_000).axes.unwrap();
    assert_eq!(stale.liveness, Liveness::Stale);
    assert_eq!(stale.execution, ExecutionAxis::Unknown);
}

// RC-37 RC-38 RC-30
#[test]
fn rc_37_a_forced_stop_counts_only_from_the_executor_or_a_system_party() {
    let mut l = Ledger::new();
    l.executor(10, 1_000, CAPABILITY_EXT_KEY, full());
    l.push(30, 2_000, ActorType::Human, stop_request("pause"), None);
    let forced = |author, source| {
        let mut r = claim(author, FORCED_STOP_EXT_KEY, cbor_text(source));
        core_mut(&mut r).basis = Some(vec![id(1)]);
        r
    };
    assert_eq!(
        l.check(
            50,
            &forced(BOB, "enforcement"),
            ActorType::Human,
            3_000,
            None
        ),
        Err("control:forced_source".to_owned())
    );
    assert_eq!(
        l.check(
            50,
            &forced(ARM, "enforcement"),
            ActorType::Machine,
            3_000,
            None
        ),
        Ok(())
    );
    assert_eq!(
        l.check(
            50,
            &forced(ARM, "unplugged"),
            ActorType::Machine,
            3_000,
            None
        ),
        Err("control:forced_source".to_owned())
    );
    assert!(is_control(&forced(SYS, "access_revocation")));
    l.push(
        50,
        3_000,
        ActorType::System,
        forced(SYS, "access_revocation"),
        None,
    );
    let read = l.read(ALICE, &[], 4_000);
    assert_eq!(read.axes.unwrap().authority, AuthorityAxis::Revoked);
    assert_eq!(read.stops[0].forced, Some(id(50)));
    assert_eq!(
        read.stops[0].state,
        work_kernel::control::stop::StopState::Unknown
    );
}

// RC-8 RC-33
#[test]
fn rc_8_an_act_under_a_control_lease_is_the_drivers_and_one_without_is_outside_coordination() {
    let mut l = Ledger::new();
    l.push(
        20,
        2_000,
        ActorType::Human,
        decl(ALICE, "control_lease", &[], &[id(1)]),
        Some(grant(BOB, "weld-cell", 2_000, 600_000)),
    );
    l.push(60, 3_000, ActorType::Human, act(BOB), None);
    l.push(61, 3_000, ActorType::Human, act(ALICE), None);
    l.push(62, 3_000, ActorType::Machine, act(ARM), None);
    let read = l.read(ALICE, &[], 4_000);
    assert_eq!(
        read.interventions,
        [
            (id(60), InterventionMark::UnderLease),
            (id(61), InterventionMark::OutsideCoordination)
        ]
    );
}

// RC-18 RC-41
#[test]
fn rc_18_the_executors_status_and_heartbeats_are_its_lease_activity_and_no_one_elses() {
    let mut l = Ledger::new();
    l.executor(13, 5_000, STATUS_EXT_KEY, status(ExecutionState::Running));
    l.executor(12, 6_000, HEARTBEAT_EXT_KEY, heartbeat());
    l.push(
        14,
        7_000,
        ActorType::Human,
        claim(BOB, HEARTBEAT_EXT_KEY, vec![0xf5]),
        Some(heartbeat()),
    );
    let read = l.read(ALICE, &[], 8_000);
    assert_eq!(read.activity, [Time(5_000), Time(6_000)]);
    assert_eq!(read.executor, Some(party(ARM)));
    assert_eq!(read.lease, LeaseStatus::NoLease);
}

// C-6 RC-31 RC-40
#[test]
fn c_6_a_consultation_and_a_correction_are_shapes_of_their_record_kinds() {
    let consultation = decl(
        ALICE,
        "open_condition",
        &[("condition_type", text(&format!("{CORE}condition/decision")))],
        &[id(1)],
    );
    assert!(has_form(&consultation, Form::Consultation));
    assert!(is_control(&consultation));
    let wait = decl(
        ALICE,
        "open_condition",
        &[("condition_type", text(&format!("{CORE}condition/time")))],
        &[id(1)],
    );
    assert!(!has_form(&wait, Form::Consultation));
    let amend = decl(ALICE, "amend", &[("change_policy", text("queue"))], &[]);
    assert!(!has_form(&amend, Form::Correction));
    assert_eq!(correction_policy(&amend), None);
}
