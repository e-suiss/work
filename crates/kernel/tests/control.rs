//! Responsibility control over typed records and decoded contract bodies: the `work/control/1` bodies against their vectors in `conformance/vectors/control`, the normative basis of agent actions, autonomy, the control axis, the single driver and its lease, stop requests and the executor coordination contract.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code"
)]

use serde_json::Value;
use work_kernel::catalog::{ChangePolicy, ClaimSubtype, StopAnswer, StopType};
use work_kernel::commitment::AccessAnswer;
use work_kernel::control::autonomy::{
    AccessView, ActionRisk, AutonomyCause, AutonomyOutcome, BasisGap, DeviationRefusal, Evidence,
    GateOutcome, Impact, LimitUse, PolicyRefusal, admit_policy, check_basis, check_deviation,
    evaluate, principal_of, suggest_expansions,
};
use work_kernel::control::axis::{
    AuthorityAxis, DEFAULT_STALE_FACTOR, ExecutionAxis, ExecutorFacts, FailureOption, FlowError,
    FlowEvent, FlowStep, Intervention, LeaseRefusal, Liveness, Observer, Reported, Request,
    RequestRefusal, axes, check_lease, check_request, control_mode, driver_at, execution,
    failure_options, intervention_of, liveness, offered_requests, oversight, take_control,
};
use work_kernel::control::body::{
    AttemptOutcome, AutonomyPolicy, Binding, CDDL, CONTRACT, Capability, CommitmentDelivery,
    ControlBodyError, ControlLease, ControlMode, ControlModeReport, Depth, ExecutionState,
    Handover, Heartbeat, Operation, ProgressEvent, ProgressReport, RequestDelivery, RequestKind,
    RequestResponse, SessionReport, StatusReport,
};
use work_kernel::control::executor::{
    EffectGuarantee, SingleUse, SingleUseRefusal, Use, acted_upon, attempts, check_single_use,
    counted, effect_guarantee, report_record,
};
use work_kernel::control::stop::{
    CorrectionRefusal, ForceSource, ResponseRefusal, ResumeRefusal, StopFacts, StopProgress,
    StopState, StopTiming, answer_of, check_correction, check_response, check_resume, stop_timing,
    stop_type_of, stops,
};
use work_kernel::derive::Restriction;
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time};
use work_kernel::record::{
    Act, Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Claim, ClaimType,
    Declaration, Kind, Param, ParamScalar, ParamValue, PartName, ProtocolVersion, Record,
    RecordCore, VersionVector, Visibility,
};
use work_kernel::uri::TypeUri;
use work_kernel::validate::ActorType;

const BODIES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/control/bodies.json"
));
const SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/cddl/work-control.cddl"
));

const ALICE: &str = "party:acme:alice";
const BOB: &str = "party:acme:bob";
const AGENT: &str = "party:acme:agent-procure-7";
const ARM: &str = "party:acme:robot-arm-3";
const CORE: &str = "https://suiss.app/ns/work/";
const SESSION: &str = "urn:session:agent-procure-7:42";
const MINUTE: u64 = 60_000;

fn party(s: &str) -> PartyRef {
    PartyRef::new(s).unwrap()
}

fn id(n: u8) -> RecordId {
    RecordId(Digest::sha256([n; 32]))
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn core(author: &str) -> RecordCore {
    RecordCore {
        author: party(author),
        on_behalf_of: None,
        capacity: Some(Capacity::Own),
        basis: Some(vec![]),
        visibility: Visibility {
            see: Audience::Author,
            search_excluded: false,
            agent_context_excluded: false,
        },
        ledger: LedgerId(Digest::sha256([1; 32])),
        concerns: vec![],
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

fn decl(author: &str, name: &str, params: &[(&str, ParamValue)]) -> Record {
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
    Record::Declaration(Declaration {
        subtype: TypeUri::parse(&format!("{CORE}declaration/{name}")).unwrap(),
        occurred_at: None,
        core: c,
    })
}

fn act(author: &str) -> Record {
    Record::Act(Act {
        subtype: TypeUri::parse(&format!("{CORE}act/action")).unwrap(),
        occurred_at: Time(1),
        core: RecordCore {
            basis: None,
            ..core(author)
        },
    })
}

fn observation(author: &str) -> Record {
    Record::Claim(Claim {
        subtype: ClaimType::from_uri(TypeUri::parse(&format!("{CORE}claim/observation")).unwrap()),
        occurred_at: Time(1),
        core: RecordCore {
            capacity: None,
            basis: None,
            authority: None,
            ..core(author)
        },
    })
}

fn core_mut(record: &mut Record) -> &mut RecordCore {
    match record {
        Record::Act(r) => &mut r.core,
        Record::Declaration(r) => &mut r.core,
        Record::Claim(r) => &mut r.core,
    }
}

fn with_basis(mut record: Record, basis: &[RecordId]) -> Record {
    let mut b = basis.to_vec();
    b.sort();
    core_mut(&mut record).basis = Some(b);
    record
}

fn with_note(mut record: Record) -> Record {
    core_mut(&mut record).body = Some(vec![BodyCommitment {
        part: PartName::parse("note").unwrap(),
        commit: Digest::sha256([4; 32]),
    }]);
    record
}

fn for_principal(mut record: Record, principal: &str) -> Record {
    let c = core_mut(&mut record);
    c.on_behalf_of = Some(vec![party(principal)]);
    c.capacity = Some(Capacity::For(party(principal)));
    record
}

fn text(s: &str) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Text(s.to_owned()))
}

fn digest(r: RecordId) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Digest(r.0))
}

fn reported<T>(record: u8, author: &str, at: u64, body: T) -> Reported<T> {
    Reported {
        record: id(record),
        author: party(author),
        at: Time(at),
        body,
    }
}

fn policy(version: u32) -> AutonomyPolicy {
    AutonomyPolicy {
        version,
        rule_set: None,
        bulk_threshold: None,
        near_boundary: None,
        notify: false,
        suggest: false,
        expanded_actions: vec![],
        expansion: false,
    }
}

fn full_capability() -> Capability {
    Capability {
        operations: vec![
            Operation::Cancel,
            Operation::Takeover,
            Operation::PauseResume,
        ],
        stop_types: vec![
            StopType::Pause,
            StopType::Immediate,
            StopType::FinishThenStop,
        ],
        change_policies: vec![ChangePolicy::Rollback, ChangePolicy::Interrupt],
        non_cancellable: vec!["weld_seam".to_owned()],
        safe_state: Some("home_position".to_owned()),
        checkpoints: true,
        heartbeat: Some(5_000),
        depth: Depth::Full,
    }
}

fn status(state: ExecutionState, step: Option<&str>) -> StatusReport {
    StatusReport {
        status: state,
        done: String::new(),
        need: String::new(),
        step: step.map(str::to_owned),
    }
}

fn check_case<T: std::fmt::Debug>(
    case: &Value,
    decode: fn(&[u8]) -> Result<T, ControlBodyError>,
    encode: fn(&T) -> Result<Vec<u8>, ControlBodyError>,
) {
    let name = case["id"].as_str().unwrap();
    let bytes = unhex(case["cbor"].as_str().unwrap());
    match decode(&bytes) {
        Ok(body) => {
            assert!(case["valid"] == true, "{name}: accepted {body:?}");
            assert_eq!(encode(&body).unwrap(), bytes, "{name}");
        }
        Err(ControlBodyError(member)) => {
            assert!(case["valid"] == false, "{name}: refused {member}");
            assert_eq!(member, case["refused"].as_str().unwrap(), "{name}");
        }
    }
}

// RC-42
#[test]
fn rc_42_contract_bodies_match_their_vectors() {
    let v: Value = serde_json::from_str(BODIES).unwrap();
    assert_eq!(v["contract"], CONTRACT);
    assert_eq!(CDDL, SCHEMA);
    let cases = v["cases"].as_array().unwrap();
    let mut roots: Vec<&str> = Vec::new();
    for case in cases {
        let root = case["root"].as_str().unwrap();
        if !roots.contains(&root) {
            roots.push(root);
        }
        match root {
            "autonomy-policy" => check_case(case, AutonomyPolicy::decode, AutonomyPolicy::encode),
            "control-lease" => check_case(case, ControlLease::decode, ControlLease::encode),
            "capability" => check_case(case, Capability::decode, Capability::encode),
            "commitment-delivery" => {
                check_case(case, CommitmentDelivery::decode, CommitmentDelivery::encode);
            }
            "request" => check_case(case, RequestDelivery::decode, RequestDelivery::encode),
            "request-response" => {
                check_case(case, RequestResponse::decode, RequestResponse::encode);
            }
            "report" => check_case(case, ProgressReport::decode, ProgressReport::encode),
            "status-report" => check_case(case, StatusReport::decode, StatusReport::encode),
            "control-mode" => {
                check_case(case, ControlModeReport::decode, ControlModeReport::encode)
            }
            "handover" => check_case(case, Handover::decode, Handover::encode),
            "heartbeat" => check_case(case, Heartbeat::decode, Heartbeat::encode),
            "session" => check_case(case, SessionReport::decode, SessionReport::encode),
            other => panic!("no decoder for {other}"),
        }
    }
    assert_eq!(roots.len(), 12);
    assert!(
        cases
            .iter()
            .any(|c| c["valid"] == false && c["schema_valid"] == true)
    );
}

// RC-42
#[test]
fn rc_42_reports_travel_as_their_record_kinds_and_never_carry_raw_thought() {
    assert_eq!(report_record(ProgressEvent::Action), (Kind::Act, None));
    assert_eq!(
        report_record(ProgressEvent::PlanUpdate),
        (Kind::Claim, Some(ClaimSubtype::Assumption))
    );
    for event in [
        ProgressEvent::Question,
        ProgressEvent::Answer,
        ProgressEvent::Error,
        ProgressEvent::RationaleSummary,
    ] {
        assert_eq!(
            report_record(event),
            (Kind::Claim, Some(ClaimSubtype::Observation))
        );
    }
    let raw = ProgressReport {
        event: ProgressEvent::RationaleSummary,
        session: SESSION.to_owned(),
        summary: "the cheaper supplier misses the due date".to_owned(),
        trace: Some("first I looked at".to_owned()),
        relies_on: vec![],
        binding: None,
    };
    assert_eq!(raw.encode(), Err(ControlBodyError("trace")));
}

// RC-42
#[test]
fn rc_42_missing_liveness_reads_stale_or_unknown_never_running() {
    let cap = full_capability();
    let arm = party(ARM);
    let running = [reported(
        20,
        ARM,
        1_000,
        status(ExecutionState::Running, None),
    )];
    let beats = [reported(
        21,
        ARM,
        1_000,
        Heartbeat {
            session: SESSION.to_owned(),
            seq: 1,
            departing: false,
        },
    )];
    let live = liveness(Some(&cap), &beats, &arm, Time(11_000), DEFAULT_STALE_FACTOR);
    assert_eq!(live, Liveness::Live);
    assert_eq!(
        execution(&running, &arm, live, Time(11_000)),
        ExecutionAxis::Running
    );
    let stale = liveness(Some(&cap), &beats, &arm, Time(11_001), DEFAULT_STALE_FACTOR);
    assert_eq!(stale, Liveness::Stale);
    assert_eq!(
        execution(&running, &arm, stale, Time(11_001)),
        ExecutionAxis::Unknown
    );
    let never = liveness(Some(&cap), &[], &arm, Time(11_001), DEFAULT_STALE_FACTOR);
    assert_eq!(never, Liveness::Unknown);
    assert_eq!(
        execution(&running, &arm, never, Time(11_001)),
        ExecutionAxis::Unknown
    );
    let done = [reported(
        22,
        ARM,
        2_000,
        status(ExecutionState::Completed, None),
    )];
    assert_eq!(
        execution(&done, &arm, stale, Time(90_000)),
        ExecutionAxis::Completed
    );
    let leaving = [reported(
        23,
        ARM,
        1_000,
        Heartbeat {
            session: SESSION.to_owned(),
            seq: 2,
            departing: true,
        },
    )];
    assert_eq!(
        liveness(
            Some(&cap),
            &leaving,
            &arm,
            Time(99_000),
            DEFAULT_STALE_FACTOR
        ),
        Liveness::Departed
    );
    let silent = Capability {
        heartbeat: None,
        ..full_capability()
    };
    assert_eq!(
        liveness(Some(&silent), &[], &arm, Time(99_000), DEFAULT_STALE_FACTOR),
        Liveness::NotApplicable
    );
    let foreign = [reported(
        24,
        BOB,
        1_000,
        Heartbeat {
            session: SESSION.to_owned(),
            seq: 3,
            departing: false,
        },
    )];
    assert_eq!(
        liveness(
            Some(&cap),
            &foreign,
            &arm,
            Time(2_000),
            DEFAULT_STALE_FACTOR
        ),
        Liveness::Unknown
    );
}

fn agent_basis() -> (Record, Vec<(RecordId, Record)>) {
    let aim = decl(ALICE, "aim", &[("duration", text("one_shot"))]);
    let request = decl(
        ALICE,
        "request",
        &[("acceptor", text(ALICE)), ("obligor", text(AGENT))],
    );
    let policy = decl(ALICE, "autonomy_policy", &[]);
    let premises = vec![(id(1), aim), (id(2), request), (id(3), policy)];
    let action = with_basis(for_principal(act(AGENT), ALICE), &[id(1), id(2), id(3)]);
    (action, premises)
}

// RC-26
#[test]
fn rc_26_an_agent_action_stands_on_aim_commitment_chain_authority_and_policy() {
    let (action, premises) = agent_basis();
    let refs: Vec<(RecordId, &Record)> = premises.iter().map(|(i, r)| (*i, r)).collect();
    assert_eq!(principal_of(&action), Some(&party(ALICE)));
    assert_eq!(check_basis(&action, ActorType::Agent, &refs), Ok(()));
    let named = decl(
        ALICE,
        "request",
        &[
            ("acceptor", text(ALICE)),
            ("aim", digest(id(1))),
            ("obligor", text(AGENT)),
        ],
    );
    let via_request = with_basis(for_principal(act(AGENT), ALICE), &[id(4), id(3)]);
    let refs = [(id(4), &named), (id(3), refs[2].1)];
    assert_eq!(check_basis(&via_request, ActorType::Agent, &refs), Ok(()));
    let mut unauthorised = via_request.clone();
    core_mut(&mut unauthorised).authority = None;
    core_mut(&mut unauthorised).on_behalf_of = None;
    core_mut(&mut unauthorised).capacity = Some(Capacity::Own);
    assert_eq!(
        check_basis(&unauthorised, ActorType::Agent, &refs),
        Err(vec![
            BasisGap::OnBehalfOf,
            BasisGap::Authority,
            BasisGap::AutonomyPolicy
        ])
    );
    let foreign_policy = decl(BOB, "autonomy_policy", &[]);
    let refs = [(id(4), &named), (id(3), &foreign_policy)];
    assert_eq!(
        check_basis(&via_request, ActorType::Agent, &refs),
        Err(vec![BasisGap::AutonomyPolicy])
    );
}

// RC-26
#[test]
fn rc_26_content_tool_output_or_chat_alone_is_no_basis() {
    let tool_output = observation("party:acme:erp-connector");
    let chat = observation(BOB);
    let action = with_basis(for_principal(act(AGENT), ALICE), &[id(5), id(6)]);
    let refs = [(id(5), &tool_output), (id(6), &chat)];
    assert_eq!(
        check_basis(&action, ActorType::Agent, &refs),
        Err(vec![
            BasisGap::Aim,
            BasisGap::Commitment,
            BasisGap::AutonomyPolicy,
            BasisGap::ContentOnly
        ])
    );
    let off_record = for_principal(act(AGENT), ALICE);
    assert_eq!(
        check_basis(&off_record, ActorType::Agent, &[]),
        Err(vec![
            BasisGap::Aim,
            BasisGap::Commitment,
            BasisGap::AutonomyPolicy
        ])
    );
    let unknown = with_basis(for_principal(act(AGENT), ALICE), &[id(9)]);
    assert!(
        check_basis(&unknown, ActorType::Agent, &[])
            .unwrap_err()
            .contains(&BasisGap::UnknownPremise)
    );
    assert_eq!(check_basis(&off_record, ActorType::Human, &[]), Ok(()));
}

fn risk(action: &str) -> ActionRisk<'_> {
    ActionRisk {
        action,
        objects: 1,
        reversible: true,
        binds_other_party: false,
        impact: Impact::Normal,
        evidence: Evidence::Strong,
    }
}

fn view(limits: &[LimitUse]) -> AccessView<'_> {
    AccessView {
        answer: AccessAnswer::Allow,
        limits,
    }
}

fn allow() -> AccessView<'static> {
    AccessView {
        answer: AccessAnswer::Allow,
        limits: &[],
    }
}

// RC-27
#[test]
fn rc_27_access_deny_is_final_and_autonomy_stays_inside_authority() {
    let mut wide = policy(2);
    wide.bulk_threshold = Some(1_000);
    wide.expanded_actions = vec!["erp.order.release".to_owned()];
    wide.expansion = true;
    let denied = AccessView {
        answer: AccessAnswer::Deny,
        limits: &[],
    };
    let out = evaluate(
        &risk("erp.order.release"),
        &denied,
        Some(&wide),
        Restriction::NoObjection,
    );
    assert_eq!(out.outcome, AutonomyOutcome::Deny);
    assert_eq!(out.causes, vec![AutonomyCause::AccessDeny]);
    let out = evaluate(
        &risk("erp.order.release"),
        &allow(),
        Some(&wide),
        Restriction::Deny,
    );
    assert_eq!(out.outcome, AutonomyOutcome::Deny);
    assert_eq!(out.causes, vec![AutonomyCause::PolicyDeny]);
    let out = evaluate(
        &risk("erp.order.read"),
        &allow(),
        None,
        Restriction::Require,
    );
    assert_eq!(out.outcome, AutonomyOutcome::RequireGate);
    assert_eq!(out.causes, vec![AutonomyCause::PolicyRequire]);
    let step_up = AccessView {
        answer: AccessAnswer::StepUp,
        limits: &[],
    };
    let out = evaluate(
        &risk("erp.order.release"),
        &step_up,
        Some(&wide),
        Restriction::NoObjection,
    );
    assert_eq!(out.outcome, AutonomyOutcome::RequireGate);
    assert_eq!(out.causes, vec![AutonomyCause::StepUp]);
    let out = evaluate(
        &risk("erp.order.read"),
        &allow(),
        None,
        Restriction::NoObjection,
    );
    assert_eq!(out.outcome, AutonomyOutcome::Proceed);
    assert!(out.causes.is_empty());
}

// RC-28
#[test]
fn rc_28_irreversible_binding_actions_require_a_gate_by_default() {
    let irreversible = ActionRisk {
        reversible: false,
        ..risk("erp.payment.send")
    };
    let out = evaluate(&irreversible, &allow(), None, Restriction::NoObjection);
    assert_eq!(out.outcome, AutonomyOutcome::RequireGate);
    assert_eq!(out.causes, vec![AutonomyCause::Irreversible]);
    let binding = ActionRisk {
        binds_other_party: true,
        ..risk("erp.order.place")
    };
    let out = evaluate(&binding, &allow(), None, Restriction::NoObjection);
    assert_eq!(out.causes, vec![AutonomyCause::BindsOtherParty]);
    assert!(!out.suggest);
}

// RC-28
#[test]
fn rc_28_high_impact_or_weakly_evidenced_work_is_a_suggestion() {
    for r in [
        ActionRisk {
            impact: Impact::High,
            ..risk("erp.order.read")
        },
        ActionRisk {
            evidence: Evidence::Weak,
            ..risk("erp.order.read")
        },
    ] {
        let out = evaluate(&r, &allow(), None, Restriction::NoObjection);
        assert_eq!(out.outcome, AutonomyOutcome::RequireGate);
        assert_eq!(out.causes, vec![AutonomyCause::Suggest]);
        assert!(out.suggest);
    }
    let mut cautious = policy(2);
    cautious.suggest = true;
    let out = evaluate(
        &risk("erp.order.read"),
        &allow(),
        Some(&cautious),
        Restriction::NoObjection,
    );
    assert!(out.suggest);
    let confident = unhex("a26776657273696f6e016a636f6e666964656e6365185a");
    assert_eq!(
        AutonomyPolicy::decode(&confident),
        Err(ControlBodyError("member"))
    );
}

// RC-29
#[test]
fn rc_29_only_the_principal_expands_autonomy_and_an_expansion_notifies() {
    let mut wide = policy(2);
    wide.expanded_actions = vec!["erp.order.release".to_owned()];
    wide.expansion = true;
    let narrow = policy(3);
    let alice = party(ALICE);
    let by_alice = decl(ALICE, "autonomy_policy", &[]);
    assert_eq!(
        admit_policy(&by_alice, &wide, &alice, ActorType::Human),
        Ok(())
    );
    let by_agent = for_principal(decl(AGENT, "autonomy_policy", &[]), ALICE);
    assert_eq!(
        admit_policy(&by_agent, &narrow, &alice, ActorType::Agent),
        Ok(())
    );
    assert_eq!(
        admit_policy(&by_agent, &wide, &alice, ActorType::Agent),
        Err(PolicyRefusal::ExpansionNotByPrincipal)
    );
    assert_eq!(
        admit_policy(
            &decl(BOB, "autonomy_policy", &[]),
            &narrow,
            &alice,
            ActorType::Human
        ),
        Err(PolicyRefusal::NotPrincipal)
    );
    assert_eq!(
        admit_policy(
            &decl(ALICE, "waiver", &[]),
            &narrow,
            &alice,
            ActorType::Human
        ),
        Err(PolicyRefusal::NotAPolicy)
    );
    let mut sneaky = policy(4);
    sneaky.bulk_threshold = Some(20);
    assert_eq!(sneaky.encode(), Err(ControlBodyError("expansion")));
    let irreversible = ActionRisk {
        reversible: false,
        ..risk("erp.order.release")
    };
    let out = evaluate(
        &irreversible,
        &allow(),
        Some(&wide),
        Restriction::NoObjection,
    );
    assert_eq!(out.outcome, AutonomyOutcome::ProceedAndNotify);
    assert_eq!(out.causes, vec![AutonomyCause::Expanded]);
    let other = ActionRisk {
        reversible: false,
        ..risk("erp.payment.send")
    };
    let out = evaluate(&other, &allow(), Some(&wide), Restriction::NoObjection);
    assert_eq!(out.outcome, AutonomyOutcome::RequireGate);
    let mut notify = policy(5);
    notify.notify = true;
    let out = evaluate(
        &risk("erp.order.read"),
        &allow(),
        Some(&notify),
        Restriction::NoObjection,
    );
    assert_eq!(out.outcome, AutonomyOutcome::ProceedAndNotify);
    assert_eq!(out.causes, vec![AutonomyCause::Notify]);
}

// RC-29
#[test]
fn rc_29_a_deviation_is_a_reasoned_event_and_repeats_only_suggest() {
    let rule = id(7);
    let plain = decl(AGENT, "notice", &[("notice_type", text("at_risk"))]);
    assert_eq!(
        check_deviation(&plain, &rule),
        Err(DeviationRefusal::Uncited)
    );
    let cited = with_basis(plain, &[rule]);
    assert_eq!(
        check_deviation(&cited, &rule),
        Err(DeviationRefusal::Unreasoned)
    );
    assert_eq!(check_deviation(&with_note(cited), &rule), Ok(()));
    let decisions = [
        GateOutcome {
            action: "erp.order.release",
            approved: false,
        },
        GateOutcome {
            action: "erp.order.release",
            approved: true,
        },
        GateOutcome {
            action: "mail.send",
            approved: true,
        },
        GateOutcome {
            action: "erp.order.release",
            approved: true,
        },
        GateOutcome {
            action: "erp.order.release",
            approved: true,
        },
    ];
    let suggested = suggest_expansions(&decisions, 3);
    assert_eq!(suggested.len(), 1);
    assert_eq!(suggested[0].action, "erp.order.release");
    assert_eq!(suggested[0].approvals, 3);
    assert!(suggest_expansions(&decisions, 4).is_empty());
    assert!(suggest_expansions(&decisions, 0).is_empty());
}

// RC-49
#[test]
fn rc_49_bulk_over_ten_objects_and_eighty_percent_of_a_limit_are_near_the_boundary() {
    let ten = ActionRisk {
        objects: 10,
        ..risk("crm.contact.update")
    };
    let eleven = ActionRisk {
        objects: 11,
        ..risk("crm.contact.update")
    };
    assert_eq!(
        evaluate(&ten, &allow(), None, Restriction::NoObjection).outcome,
        AutonomyOutcome::Proceed
    );
    let out = evaluate(&eleven, &allow(), None, Restriction::NoObjection);
    assert_eq!(out.causes, vec![AutonomyCause::Bulk]);
    let under = [LimitUse {
        limit: 10_000,
        after: 7_999,
    }];
    let at = [
        LimitUse {
            limit: 10_000,
            after: 100,
        },
        LimitUse {
            limit: 10_000,
            after: 8_000,
        },
    ];
    assert_eq!(
        evaluate(&risk("pay"), &view(&under), None, Restriction::NoObjection).outcome,
        AutonomyOutcome::Proceed
    );
    let out = evaluate(&risk("pay"), &view(&at), None, Restriction::NoObjection);
    assert_eq!(out.causes, vec![AutonomyCause::NearBoundary]);
    let mut narrow = policy(2);
    narrow.bulk_threshold = Some(3);
    narrow.near_boundary = Some(500);
    let four = ActionRisk {
        objects: 4,
        ..risk("crm.contact.update")
    };
    let half = [LimitUse {
        limit: 10_000,
        after: 5_000,
    }];
    let out = evaluate(&four, &view(&half), Some(&narrow), Restriction::NoObjection);
    assert_eq!(
        out.causes,
        vec![AutonomyCause::NearBoundary, AutonomyCause::Bulk]
    );
    let mut wide = policy(3);
    wide.bulk_threshold = Some(50);
    wide.near_boundary = Some(950);
    wide.expansion = true;
    let out = evaluate(&eleven, &view(&at), Some(&wide), Restriction::NoObjection);
    assert_eq!(out.outcome, AutonomyOutcome::ProceedAndNotify);
    assert_eq!(out.causes, vec![AutonomyCause::Expanded]);
    let huge = [LimitUse {
        limit: u64::MAX,
        after: u64::MAX,
    }];
    assert_eq!(
        evaluate(&risk("pay"), &view(&huge), None, Restriction::NoObjection).causes,
        vec![AutonomyCause::NearBoundary]
    );
}

// RC-30
#[test]
fn rc_30_revoked_authority_is_not_a_stopped_execution() {
    let cap = full_capability();
    let arm = party(ARM);
    let status_reports = [reported(
        30,
        ARM,
        1_000,
        status(ExecutionState::Running, None),
    )];
    let modes = [reported(
        31,
        ARM,
        1_000,
        ControlModeReport {
            mode: ControlMode::Automatic,
            lease: None,
        },
    )];
    let beats = [reported(
        32,
        ARM,
        3_000,
        Heartbeat {
            session: SESSION.to_owned(),
            seq: 4,
            departing: false,
        },
    )];
    let facts = ExecutorFacts {
        executor: &arm,
        capability: Some(&cap),
        status: &status_reports,
        modes: &modes,
        heartbeats: &beats,
        leases: &[],
        stale_factor: DEFAULT_STALE_FACTOR,
    };
    let revoked = axes(AuthorityAxis::Revoked, &facts, Time(4_000));
    assert_eq!(revoked.authority, AuthorityAxis::Revoked);
    assert_eq!(revoked.execution, ExecutionAxis::Running);
    assert_eq!(revoked.control, Some(ControlMode::Automatic));
    assert_eq!(revoked.liveness, Liveness::Live);
    assert_eq!(revoked.driver.party, arm);
    let granted = axes(AuthorityAxis::Granted, &facts, Time(4_000));
    assert_eq!(granted.execution, revoked.execution);
    assert_eq!(control_mode(&modes, &party(BOB), Time(4_000)), None);
}

// RC-31
#[test]
fn rc_31_attention_consultation_and_takeover_are_distinct_records() {
    let attention = decl(ALICE, "attention_request", &[]);
    let consultation = decl(
        AGENT,
        "open_condition",
        &[
            ("address", text(ALICE)),
            ("condition_type", text(&format!("{CORE}condition/decision"))),
            (
                "criterion",
                text("https://procurement.example/criterion/supplier"),
            ),
            ("deadline", text("none")),
            ("wait_reason", text("internal")),
        ],
    );
    let resource = decl(
        AGENT,
        "open_condition",
        &[("condition_type", text(&format!("{CORE}condition/resource")))],
    );
    let takeover = decl(ALICE, "control_lease", &[]);
    assert_eq!(
        intervention_of(&attention),
        Some(Intervention::AttentionRequest)
    );
    assert_eq!(
        intervention_of(&consultation),
        Some(Intervention::Consultation)
    );
    assert_eq!(intervention_of(&takeover), Some(Intervention::Takeover));
    assert_eq!(intervention_of(&resource), None);
    assert_eq!(intervention_of(&observation(ALICE)), None);
    let agent = party(AGENT);
    assert_eq!(driver_at(&agent, &[], Time(5)).party, agent);
}

fn request(kind: RequestKind) -> Request {
    Request {
        kind,
        stop_type: None,
        change_policy: None,
    }
}

fn stop(stop_type: StopType) -> Request {
    Request {
        kind: RequestKind::Stop,
        stop_type: Some(stop_type),
        change_policy: None,
    }
}

// RC-32
#[test]
fn rc_32_the_control_mode_limits_the_valid_requests() {
    let cap = full_capability();
    let change = Request {
        kind: RequestKind::Change,
        stop_type: None,
        change_policy: Some(ChangePolicy::Interrupt),
    };
    let auto = Some(ControlMode::Automatic);
    let manual = Some(ControlMode::Manual);
    assert_eq!(
        check_request(request(RequestKind::Takeover), Some(&cap), auto, false),
        Ok(())
    );
    assert_eq!(
        check_request(request(RequestKind::Takeover), Some(&cap), manual, true),
        Err(RequestRefusal::Mode)
    );
    assert_eq!(
        check_request(request(RequestKind::ReturnControl), Some(&cap), auto, false),
        Err(RequestRefusal::Mode)
    );
    assert_eq!(
        check_request(
            request(RequestKind::ReturnControl),
            Some(&cap),
            manual,
            false
        ),
        Err(RequestRefusal::NoLease)
    );
    assert_eq!(
        check_request(
            request(RequestKind::ReturnControl),
            Some(&cap),
            manual,
            true
        ),
        Ok(())
    );
    assert_eq!(check_request(change, Some(&cap), auto, false), Ok(()));
    assert_eq!(
        check_request(change, Some(&cap), manual, true),
        Err(RequestRefusal::Mode)
    );
    for mode in [None, auto, manual, Some(ControlMode::Intervened)] {
        assert_eq!(
            check_request(stop(StopType::Immediate), Some(&cap), mode, false),
            Ok(())
        );
        assert_eq!(
            check_request(
                request(RequestKind::BudgetExhausted),
                Some(&cap),
                mode,
                false
            ),
            Ok(())
        );
    }
    assert_eq!(
        check_request(request(RequestKind::Resume), Some(&cap), None, false),
        Err(RequestRefusal::Mode)
    );
}

// RC-33
#[test]
fn rc_33_one_driver_and_a_time_bound_lease_for_a_second() {
    let agent = party(AGENT);
    let grant = ControlLease::Grant {
        driver: party(ALICE),
        environment: "browser:session/7".to_owned(),
        from: Time(10 * MINUTE),
        until: Time(25 * MINUTE),
        reason: "correct the supplier address".to_owned(),
    };
    let lease = reported(40, ALICE, 9 * MINUTE, grant.clone());
    assert_eq!(check_lease(&lease, &[], &agent), Ok(()));
    let leases = [lease.clone()];
    assert_eq!(driver_at(&agent, &leases, Time(9 * MINUTE)).party, agent);
    let during = driver_at(&agent, &leases, Time(12 * MINUTE));
    assert_eq!(during.party, party(ALICE));
    assert_eq!(during.lease, Some(id(40)));
    assert_eq!(driver_at(&agent, &leases, Time(25 * MINUTE)).party, agent);
    let second = reported(
        41,
        BOB,
        11 * MINUTE,
        ControlLease::Grant {
            driver: party(BOB),
            environment: "browser:session/7".to_owned(),
            from: Time(20 * MINUTE),
            until: Time(30 * MINUTE),
            reason: "look at the order".to_owned(),
        },
    );
    assert_eq!(
        check_lease(&second, &leases, &agent),
        Err(LeaseRefusal::SecondDriver)
    );
    let own = reported(
        42,
        AGENT,
        11 * MINUTE,
        ControlLease::Grant {
            driver: agent.clone(),
            environment: "browser:session/7".to_owned(),
            from: Time(30 * MINUTE),
            until: Time(40 * MINUTE),
            reason: "drive".to_owned(),
        },
    );
    assert_eq!(
        check_lease(&own, &leases, &agent),
        Err(LeaseRefusal::AlreadyDriving)
    );
    let release = |record: u8, author: &str| {
        reported(
            record,
            author,
            15 * MINUTE,
            ControlLease::Release {
                lease: id(40).0,
                released: Time(15 * MINUTE),
            },
        )
    };
    assert_eq!(
        check_lease(&release(43, BOB), &leases, &agent),
        Err(LeaseRefusal::NotHolder)
    );
    let given_back = release(44, ALICE);
    assert_eq!(check_lease(&given_back, &leases, &agent), Ok(()));
    let leases = [lease, given_back];
    assert_eq!(driver_at(&agent, &leases, Time(16 * MINUTE)).party, agent);
    assert_eq!(
        check_lease(&release(45, ALICE), &leases, &agent),
        Err(LeaseRefusal::AlreadyReleased)
    );
    assert_eq!(check_lease(&second, &leases, &agent), Ok(()));
    let unknown = reported(
        46,
        ALICE,
        15 * MINUTE,
        ControlLease::Release {
            lease: id(99).0,
            released: Time(15 * MINUTE),
        },
    );
    assert_eq!(
        check_lease(&unknown, &leases, &agent),
        Err(LeaseRefusal::UnknownLease)
    );
    let backwards = ControlLease::Grant {
        driver: party(ALICE),
        environment: "browser:session/7".to_owned(),
        from: Time(5),
        until: Time(5),
        reason: "r".to_owned(),
    };
    assert_eq!(backwards.encode(), Err(ControlBodyError("until")));
    assert!(grant.encode().is_ok());
}

// RC-34
#[test]
fn rc_34_taking_control_runs_through_a_release_with_a_handover_note() {
    let cap = full_capability();
    let flow = [
        FlowEvent::PauseRequested,
        FlowEvent::Paused,
        FlowEvent::Leased,
        FlowEvent::Released { handover: true },
        FlowEvent::Revalidated,
        FlowEvent::Resumed,
    ];
    assert_eq!(take_control(&cap, &flow), Ok(Some(FlowStep::Resumed)));
    let replanned = [
        FlowEvent::PauseRequested,
        FlowEvent::Paused,
        FlowEvent::Leased,
        FlowEvent::Released { handover: true },
        FlowEvent::Revalidated,
        FlowEvent::Replanned,
    ];
    assert_eq!(
        take_control(&cap, &replanned),
        Ok(Some(FlowStep::Replanned))
    );
    assert_eq!(take_control(&cap, &flow[..4]), Ok(Some(FlowStep::Released)));
    let silent = [
        FlowEvent::PauseRequested,
        FlowEvent::Paused,
        FlowEvent::Leased,
        FlowEvent::Released { handover: false },
    ];
    assert_eq!(
        take_control(&cap, &silent),
        Err(FlowError::HandoverMissing(3))
    );
    let unconfirmed = [FlowEvent::PauseRequested, FlowEvent::Leased];
    assert_eq!(
        take_control(&cap, &unconfirmed),
        Err(FlowError::OutOfOrder(1))
    );
    let blind = [
        FlowEvent::PauseRequested,
        FlowEvent::Paused,
        FlowEvent::Leased,
        FlowEvent::Released { handover: true },
        FlowEvent::Resumed,
    ];
    assert_eq!(take_control(&cap, &blind), Err(FlowError::OutOfOrder(4)));
    let no_takeover = Capability {
        operations: vec![Operation::Cancel, Operation::PauseResume],
        ..full_capability()
    };
    assert_eq!(
        take_control(&no_takeover, &flow),
        Err(FlowError::Unsupported)
    );
}

// RC-34
#[test]
fn rc_34_an_unsupported_intervention_is_never_offered() {
    let cap = full_capability();
    let auto = Some(ControlMode::Automatic);
    let all = offered_requests(Some(&cap), auto, false);
    assert!(all.contains(&request(RequestKind::Takeover)));
    assert!(all.contains(&stop(StopType::Pause)));
    assert!(!all.contains(&request(RequestKind::ReturnControl)));
    let stop_only = Capability {
        operations: vec![Operation::Cancel],
        stop_types: vec![StopType::Immediate],
        change_policies: vec![],
        ..full_capability()
    };
    assert_eq!(
        offered_requests(Some(&stop_only), auto, false),
        vec![
            request(RequestKind::Start),
            stop(StopType::Immediate),
            request(RequestKind::BudgetExhausted)
        ]
    );
    assert_eq!(
        check_request(stop(StopType::Pause), Some(&stop_only), auto, false),
        Err(RequestRefusal::Unsupported)
    );
    assert_eq!(
        check_request(
            request(RequestKind::Takeover),
            Some(&stop_only),
            auto,
            false
        ),
        Err(RequestRefusal::Unsupported)
    );
    assert!(offered_requests(None, auto, false).is_empty());
    assert_eq!(
        check_request(request(RequestKind::Start), None, auto, false),
        Err(RequestRefusal::Undeclared)
    );
}

// RC-35
#[test]
fn rc_35_oversight_is_only_visible_and_a_provider_failure_offers_options() {
    let view = oversight("access:role:line-supervisor", None);
    assert_eq!(view.role, "access:role:line-supervisor");
    assert_eq!(view.observer, Observer::Unknown);
    assert_eq!(
        oversight("access:role:line-supervisor", Some(false)).observer,
        Observer::Absent
    );
    assert_eq!(
        oversight("access:role:line-supervisor", Some(true)).observer,
        Observer::Attached
    );
    let cap = full_capability();
    assert_eq!(
        check_request(
            request(RequestKind::Start),
            Some(&cap),
            Some(ControlMode::Automatic),
            false
        ),
        Ok(())
    );
    assert_eq!(
        failure_options(Some(&cap), true, true),
        vec![
            FailureOption::Wait,
            FailureOption::SwapModel,
            FailureOption::Handover,
            FailureOption::HumanTakeover
        ]
    );
    assert_eq!(
        failure_options(None, false, false),
        vec![FailureOption::Wait]
    );
}

struct StopLedger {
    records: Vec<(RecordId, Time, Record)>,
}

impl StopLedger {
    fn refs(&self) -> Vec<(RecordId, Time, &Record)> {
        self.records.iter().map(|(i, t, r)| (*i, *t, r)).collect()
    }
}

fn stop_request(stop_type: &str) -> Record {
    decl(ALICE, "stop_request", &[("stop_type", text(stop_type))])
}

fn stop_response(answer: &str, request: RecordId) -> Record {
    with_basis(
        decl(ARM, "stop_response", &[("response", text(answer))]),
        &[request],
    )
}

// RC-36
#[test]
fn rc_36_a_stop_request_reads_pending_until_the_doer_answers() {
    let arm = party(ARM);
    let alice = party(ALICE);
    let cap = full_capability();
    let mut ledger = StopLedger {
        records: vec![(id(50), Time(1_000), stop_request("finish_then_stop"))],
    };
    let facts = |refs: &[(RecordId, Time, &Record)]| -> Vec<StopProgress> {
        let f = StopFacts {
            records: refs,
            executor: &arm,
            principal: &alice,
            capability: Some(&cap),
            status: &[],
            forced: &[],
        };
        stops(&f, Time(10_000)).iter().map(|s| s.progress).collect()
    };
    assert_eq!(facts(&ledger.refs()), vec![StopProgress::Pending]);
    ledger.records.push((
        id(51),
        Time(2_000),
        stop_response("finish_then_stop", id(50)),
    ));
    assert_eq!(facts(&ledger.refs()), vec![StopProgress::FinishingThenStop]);
    ledger
        .records
        .push((id(52), Time(3_000), stop_response("accept", id(50))));
    assert_eq!(facts(&ledger.refs()), vec![StopProgress::Accepted]);
    let typed = stop_request("pause:https://plant.example/stop/shift_end");
    assert_eq!(stop_type_of(&typed), Some(StopType::Pause));
    assert_eq!(
        answer_of(&stop_response("refuse", id(50))),
        Some(StopAnswer::Refuse)
    );
    let request = stop_request("immediate");
    let requests = [(id(50), &request)];
    assert_eq!(
        check_response(&stop_response("accept", id(50)), &requests, &arm),
        Ok(())
    );
    assert_eq!(
        check_response(&stop_response("refuse", id(50)), &requests, &arm),
        Err(ResponseRefusal::Unreasoned)
    );
    assert_eq!(
        check_response(&with_note(stop_response("refuse", id(50))), &requests, &arm),
        Ok(())
    );
    assert_eq!(
        check_response(&stop_response("accept", id(59)), &requests, &arm),
        Err(ResponseRefusal::Uncited)
    );
    assert_eq!(
        check_response(&stop_response("accept", id(50)), &requests, &alice),
        Err(ResponseRefusal::NotDoer)
    );
    assert_eq!(
        check_response(&request, &requests, &arm),
        Err(ResponseRefusal::NotAResponse)
    );
}

// RC-37
#[test]
fn rc_37_a_forced_stop_is_recorded_and_never_confirms_the_stop() {
    let arm = party(ARM);
    let alice = party(ALICE);
    let ledger = StopLedger {
        records: vec![(id(60), Time(1_000), stop_request("immediate"))],
    };
    let refs = ledger.refs();
    let forced = [reported(
        61,
        "party:acme:work-service",
        2_000,
        ForceSource::AccessRevocation,
    )];
    let f = StopFacts {
        records: &refs,
        executor: &arm,
        principal: &alice,
        capability: None,
        status: &[],
        forced: &forced,
    };
    let view = &stops(&f, Time(5_000))[0];
    assert_eq!(view.forced, Some(id(61)));
    assert_eq!(view.state, StopState::Unknown);
    assert_eq!(view.progress, StopProgress::Pending);
    assert!(view.revocation_path);
}

// RC-38
#[test]
fn rc_38_only_the_executor_claim_shows_stopped_and_a_refusal_reaches_attention() {
    let arm = party(ARM);
    let bob = party(BOB);
    let ledger = StopLedger {
        records: vec![
            (id(70), Time(1_000), stop_request("immediate")),
            (
                id(71),
                Time(2_000),
                with_note(stop_response("refuse", id(70))),
            ),
            (id(72), Time(3_000), stop_request("pause")),
            (id(73), Time(3_500), stop_response("accept", id(72))),
        ],
    };
    let refs = ledger.refs();
    let claims = [
        reported(74, BOB, 4_000, status(ExecutionState::Paused, None)),
        reported(75, ARM, 5_000, status(ExecutionState::Paused, None)),
    ];
    let f = StopFacts {
        records: &refs,
        executor: &arm,
        principal: &bob,
        capability: None,
        status: &claims,
        forced: &[],
    };
    let at_4500 = stops(&f, Time(4_500));
    assert_eq!(at_4500[1].progress, StopProgress::Accepted);
    assert_eq!(at_4500[1].state, StopState::Unknown);
    let at_6000 = stops(&f, Time(6_000));
    let refused = &at_6000[0];
    assert_eq!(refused.progress, StopProgress::Refused);
    assert_eq!(refused.attention, vec![party(ALICE), bob.clone()]);
    assert!(refused.revocation_path);
    assert_eq!(refused.state, StopState::Unknown);
    let paused = &at_6000[1];
    assert_eq!(paused.state, StopState::Confirmed);
    assert_eq!(paused.confirmation, Some(id(75)));
    assert!(paused.attention.is_empty());
    assert!(!paused.revocation_path);
}

// RC-39
#[test]
fn rc_39_a_non_cancellable_step_finishes_before_the_stop_applies() {
    let cap = full_capability();
    assert_eq!(
        stop_timing(Some("weld_seam"), Some(&cap)),
        StopTiming::AfterStep("weld_seam".to_owned())
    );
    assert_eq!(
        stop_timing(Some("move_to_part"), Some(&cap)),
        StopTiming::Now
    );
    assert_eq!(stop_timing(None, Some(&cap)), StopTiming::Now);
    let arm = party(ARM);
    let alice = party(ALICE);
    let ledger = StopLedger {
        records: vec![(id(80), Time(2_000), stop_request("immediate"))],
    };
    let refs = ledger.refs();
    let welding = [reported(
        81,
        ARM,
        1_000,
        status(ExecutionState::Running, Some("weld_seam")),
    )];
    let f = StopFacts {
        records: &refs,
        executor: &arm,
        principal: &alice,
        capability: Some(&cap),
        status: &welding,
        forced: &[],
    };
    assert_eq!(
        stops(&f, Time(2_500))[0].timing,
        StopTiming::AfterStep("weld_seam".to_owned())
    );
}

// RC-40
#[test]
fn rc_40_resuming_takes_its_own_declaration_and_never_happens_by_itself() {
    let arm = party(ARM);
    let alice = party(ALICE);
    let mut ledger = StopLedger {
        records: vec![
            (id(90), Time(1_000), stop_request("immediate")),
            (id(91), Time(1_500), stop_response("accept", id(90))),
        ],
    };
    let claims = [
        reported(92, ARM, 2_000, status(ExecutionState::Stopped, None)),
        reported(93, ARM, 3_000, status(ExecutionState::Running, None)),
    ];
    let derive = |refs: &[(RecordId, Time, &Record)]| {
        let f = StopFacts {
            records: refs,
            executor: &arm,
            principal: &alice,
            capability: None,
            status: &claims,
            forced: &[],
        };
        stops(&f, Time(4_000)).remove(0)
    };
    let view = derive(&ledger.refs());
    assert_eq!(view.state, StopState::Confirmed);
    assert_eq!(view.resumed, None);
    assert!(view.restarted_without_resume);
    let resume = with_basis(decl(ALICE, "resume_after_stop", &[]), &[id(90)]);
    let request = stop_request("immediate");
    assert_eq!(check_resume(&resume, &[(id(90), &request)]), Ok(()));
    assert_eq!(
        check_resume(
            &decl(ALICE, "resume_after_stop", &[]),
            &[(id(90), &request)]
        ),
        Err(ResumeRefusal::Uncited)
    );
    assert_eq!(
        check_resume(&decl(ALICE, "resume", &[]), &[(id(90), &request)]),
        Err(ResumeRefusal::NotAResume)
    );
    ledger.records.push((id(94), Time(2_500), resume));
    let view = derive(&ledger.refs());
    assert_eq!(view.resumed, Some(id(94)));
    assert!(!view.restarted_without_resume);
    assert_eq!(check_correction(None, 1), Ok(()));
    assert_eq!(check_correction(Some(3), 4), Ok(()));
    assert_eq!(
        check_correction(Some(3), 3),
        Err(CorrectionRefusal::NotMonotonic)
    );
    assert_eq!(
        check_correction(None, 0),
        Err(CorrectionRefusal::NotMonotonic)
    );
}

fn action_report(
    record: u8,
    author: &str,
    relies_on: Vec<Digest>,
    idempotent: bool,
) -> Reported<ProgressReport> {
    reported(
        record,
        author,
        1_000,
        ProgressReport {
            event: ProgressEvent::Action,
            session: SESSION.to_owned(),
            summary: "released purchase order PO-4471".to_owned(),
            trace: None,
            relies_on,
            binding: Some(Binding {
                authority_context: Digest::sha256([8; 32]),
                idempotency_key: "po-4471-release-1".to_owned(),
                external_idempotent: idempotent,
            }),
        },
    )
}

// RC-41
#[test]
fn rc_41_only_reports_of_an_assigned_executor_count() {
    let executors = [party(AGENT)];
    let reports = [
        action_report(100, AGENT, vec![id(1).0], true),
        action_report(
            101,
            "party:suiss:access-executor-service",
            vec![id(1).0],
            true,
        ),
    ];
    let counted_reports = counted(&reports, &executors);
    assert_eq!(counted_reports.len(), 1);
    assert_eq!(counted_reports[0].record, id(100));
    let service = [party("party:suiss:access-executor-service")];
    assert_eq!(counted(&reports, &service)[0].record, id(101));
}

// RC-43
#[test]
fn rc_43_attempts_are_grouped_by_session_and_keep_their_reasons() {
    let executors = [party(AGENT)];
    let commitment = id(1).0;
    let session =
        |n: u8, s: &str, attempt: u32, outcome: Option<AttemptOutcome>, reason: Option<&str>| {
            reported(
                n,
                AGENT,
                u64::from(n),
                SessionReport {
                    session: s.to_owned(),
                    commitment,
                    attempt,
                    outcome,
                    reason: reason.map(str::to_owned),
                },
            )
        };
    let reports = [
        session(110, "urn:session:agent-procure-7:41", 1, None, None),
        session(
            111,
            "urn:session:agent-procure-7:41",
            1,
            Some(AttemptOutcome::Failed),
            Some("the supplier portal rejected the login"),
        ),
        session(112, SESSION, 2, None, None),
        reported(
            113,
            AGENT,
            113,
            SessionReport {
                session: "urn:session:agent-procure-7:9".to_owned(),
                commitment: id(2).0,
                attempt: 1,
                outcome: None,
                reason: None,
            },
        ),
    ];
    let grouped = attempts(&commitment, &reports, &executors);
    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped[0].attempt, 1);
    assert_eq!(grouped[0].outcome, Some(AttemptOutcome::Failed));
    assert_eq!(
        grouped[0].reason.as_deref(),
        Some("the supplier portal rejected the login")
    );
    assert_eq!(grouped[0].records, vec![id(110), id(111)]);
    assert_eq!(grouped[1].session, SESSION);
    assert_eq!(grouped[1].outcome, None);
}

// RC-43
#[test]
fn rc_43_the_integration_depth_bounds_what_work_delivers() {
    let auto = Some(ControlMode::Automatic);
    let read_only = Capability {
        operations: vec![],
        stop_types: vec![],
        change_policies: vec![],
        non_cancellable: vec![],
        safe_state: None,
        checkpoints: false,
        heartbeat: None,
        depth: Depth::ReadOnly,
    };
    assert!(offered_requests(Some(&read_only), auto, false).is_empty());
    assert_eq!(
        check_request(stop(StopType::Immediate), Some(&read_only), auto, false),
        Err(RequestRefusal::ReadOnly)
    );
    let traffic = Capability {
        operations: vec![Operation::Cancel, Operation::PauseResume],
        stop_types: vec![StopType::Pause, StopType::Immediate],
        change_policies: vec![],
        depth: Depth::TrafficLight,
        ..read_only.clone()
    };
    assert_eq!(
        offered_requests(Some(&traffic), auto, false),
        vec![
            request(RequestKind::Start),
            stop(StopType::Immediate),
            stop(StopType::Pause),
            request(RequestKind::Resume),
            request(RequestKind::BudgetExhausted)
        ]
    );
    assert_eq!(
        check_request(request(RequestKind::Takeover), Some(&traffic), auto, false),
        Err(RequestRefusal::Depth)
    );
    let takeover_light = Capability {
        operations: vec![Operation::Takeover],
        ..traffic.clone()
    };
    assert_eq!(takeover_light.encode(), Err(ControlBodyError("stop_types")));
}

// SEC-15
#[test]
fn sec_15_an_authority_context_binds_exactly_one_idempotency_key() {
    let a = Digest::sha256([8; 32]);
    let b = Digest::sha256([9; 32]);
    let used = [Use {
        context: &a,
        key: "po-4471-release-1",
    }];
    assert_eq!(
        check_single_use(
            &used,
            Use {
                context: &b,
                key: "po-4471-release-2"
            }
        ),
        Ok(SingleUse::Fresh)
    );
    assert_eq!(
        check_single_use(
            &used,
            Use {
                context: &a,
                key: "po-4471-release-1"
            }
        ),
        Ok(SingleUse::Replay)
    );
    assert_eq!(
        check_single_use(
            &used,
            Use {
                context: &a,
                key: "po-4471-release-2"
            }
        ),
        Err(SingleUseRefusal::ContextReused)
    );
    assert_eq!(
        check_single_use(
            &used,
            Use {
                context: &b,
                key: "po-4471-release-1"
            }
        ),
        Err(SingleUseRefusal::KeyReused)
    );
    let once = action_report(120, AGENT, vec![], true);
    let maybe = action_report(121, AGENT, vec![], false);
    assert_eq!(effect_guarantee(&once.body), EffectGuarantee::Once);
    assert_eq!(effect_guarantee(&maybe.body), EffectGuarantee::Unclaimed);
    let question = ProgressReport {
        event: ProgressEvent::Question,
        binding: None,
        ..maybe.body.clone()
    };
    assert_eq!(effect_guarantee(&question), EffectGuarantee::Unclaimed);
    let unbound = ProgressReport {
        binding: None,
        ..maybe.body
    };
    assert_eq!(unbound.encode(), Err(ControlBodyError("authority_context")));
}

// OP-4
#[test]
fn op_4_a_record_is_acted_upon_once_the_executor_reports_an_act_on_it() {
    let executors = [party(AGENT)];
    let question = reported(
        131,
        AGENT,
        900,
        ProgressReport {
            event: ProgressEvent::Question,
            session: SESSION.to_owned(),
            summary: "which plant?".to_owned(),
            trace: None,
            relies_on: vec![id(1).0],
            binding: None,
        },
    );
    let reports = [
        question,
        action_report(132, "party:acme:intruder", vec![id(1).0], true),
        action_report(133, AGENT, vec![id(1).0, id(2).0], true),
    ];
    assert_eq!(acted_upon(&id(1), &reports, &executors), Some(id(133)));
    assert_eq!(acted_upon(&id(2), &reports, &executors), Some(id(133)));
    assert_eq!(acted_upon(&id(3), &reports, &executors), None);
}
