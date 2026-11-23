#![allow(clippy::unwrap_used, reason = "test code")]

use work_kernel::catalog::{StopAnswer, StopType};
use work_kernel::control::axis::Reported;
use work_kernel::control::body::{AttemptOutcome, Binding, ExecutionState, ProgressEvent};
use work_kernel::control::executor::{
    SingleUse, SingleUseRefusal, Use, acted_upon, check_single_use,
};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time};
use work_kernel::record::{
    Act, Audience, AuthorityProofKind, AuthorityRef, Capacity, Claim, Declaration, ExtValue,
    Extension, Param, ParamScalar, ParamValue, PartName, ProtocolVersion, RecordCore,
    VersionVector, Visibility,
};
use work_kernel::uri::{ExtKey, TypeUri};

use super::*;

const CORE: &str = "https://suiss.app/ns/work/";
const EXECUTOR: &str = "party:acme:agent-procure-7";

fn id(n: u8) -> RecordId {
    RecordId(Digest::sha256([n; 32]))
}

fn core(ext: Option<&str>, basis: &[RecordId], params: &[(&str, &str)]) -> RecordCore {
    RecordCore {
        author: PartyRef::new(EXECUTOR).unwrap(),
        on_behalf_of: None,
        capacity: Some(Capacity::Own),
        basis: Some(basis.to_vec()),
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
        params: (!params.is_empty()).then(|| {
            params
                .iter()
                .map(|(k, v)| Param {
                    name: PartName::parse(k).unwrap(),
                    value: ParamValue::Scalar(ParamScalar::Text((*v).to_owned())),
                })
                .collect()
        }),
        versions: VersionVector {
            protocol: ProtocolVersion { major: 1, minor: 0 },
            schema: Digest::sha256([3; 32]),
            practices: None,
        },
        ext: ext.map(|key| {
            vec![Extension {
                key: ExtKey::parse(key).unwrap(),
                value: ExtValue(vec![0xf6]),
            }]
        }),
        critical: None,
    }
}

fn claim(subtype: &str, ext: Option<&str>) -> Record {
    Record::Claim(Claim {
        subtype: ClaimType::from_uri(TypeUri::parse(&format!("{CORE}claim/{subtype}")).unwrap()),
        occurred_at: Time(1),
        core: core(ext, &[], &[]),
    })
}

fn act(ext: Option<&str>) -> Record {
    Record::Act(Act {
        subtype: TypeUri::parse(&format!("{CORE}act/action")).unwrap(),
        occurred_at: Time(1),
        core: core(ext, &[], &[]),
    })
}

fn decl(name: &str, basis: &[RecordId], params: &[(&str, &str)]) -> Record {
    Record::Declaration(Declaration {
        subtype: TypeUri::parse(&format!("{CORE}declaration/{name}")).unwrap(),
        occurred_at: None,
        core: core(None, basis, params),
    })
}

fn report(event: ProgressEvent, binding: Option<Binding>) -> Vec<u8> {
    ProgressReport {
        event,
        session: "urn:session:1".to_owned(),
        summary: "bought the parts".to_owned(),
        trace: None,
        relies_on: vec![id(9).0],
        binding,
    }
    .encode()
    .unwrap()
}

fn binding(context: u8, key: &str) -> Binding {
    Binding {
        authority_context: Digest::sha256([context; 32]),
        idempotency_key: key.to_owned(),
        external_idempotent: true,
    }
}

// RC-42 RC-43
#[test]
fn rc_42_each_contract_element_travels_as_a_record_of_its_fixed_kind() {
    let observation = |key| claim("observation", Some(key));
    assert_eq!(
        element_of(&observation(CAPABILITY_EXT_KEY), false),
        Some(Element::Capability)
    );
    assert_eq!(
        element_of(&observation(STATUS_EXT_KEY), false),
        Some(Element::Status)
    );
    assert_eq!(
        element_of(&observation(CONTROL_MODE_EXT_KEY), false),
        Some(Element::ControlMode)
    );
    assert_eq!(
        element_of(&observation(HEARTBEAT_EXT_KEY), false),
        Some(Element::Heartbeat)
    );
    assert_eq!(
        element_of(&observation(SESSION_EXT_KEY), false),
        Some(Element::Session)
    );
    assert_eq!(
        element_of(&claim("assumption", Some(REPORT_EXT_KEY)), false),
        Some(Element::Report)
    );
    assert_eq!(
        element_of(&act(Some(REPORT_EXT_KEY)), false),
        Some(Element::Report)
    );
    assert_eq!(element_of(&act(None), true), None);
    assert_eq!(
        element_of(&decl("stop_response", &[], &[]), false),
        Some(Element::StopResponse)
    );
    assert_eq!(element_of(&decl("handoff_note", &[], &[]), false), None);
    assert_eq!(
        element_of(&decl("handoff_note", &[], &[]), true),
        Some(Element::Handover)
    );
    assert_eq!(element_of(&claim("observation", None), false), None);
    assert_eq!(
        element_of(&claim("observation", None), true),
        Some(Element::RequestResponse)
    );
}

// RC-42
#[test]
fn rc_42_a_body_that_does_not_decode_is_refused_naming_its_member() {
    let status = claim("observation", Some(STATUS_EXT_KEY));
    let root = id(1);
    assert_eq!(
        check_body(Element::Status, &status, &root, None),
        Err(ExecutorRefusal::Definition("body"))
    );
    assert_eq!(
        check_body(Element::Status, &status, &root, Some(&[0xff])),
        Err(ExecutorRefusal::Definition("cbor"))
    );
    let wrong = report(ProgressEvent::Question, None);
    assert_eq!(
        check_body(Element::Status, &status, &root, Some(&wrong)),
        Err(ExecutorRefusal::Definition("member"))
    );
    let ok = StatusReport {
        status: ExecutionState::Running,
        done: String::new(),
        need: String::new(),
        step: None,
    }
    .encode()
    .unwrap();
    assert_eq!(
        check_body(Element::Status, &status, &root, Some(&ok)),
        Ok(None)
    );
    assert_eq!(
        ExecutorRefusal::Definition("status").reason(),
        "definition:status"
    );
    assert_eq!(
        ExecutorRefusal::NotExecutor.reason(),
        "control:not_executor"
    );
}

// RC-43 C-38
#[test]
fn rc_43_a_report_travels_as_the_record_kind_its_event_takes_and_a_session_names_its_commitment() {
    let root = id(1);
    let action = report(ProgressEvent::Action, Some(binding(4, "cmt_x/rec_y")));
    let as_claim = claim("observation", Some(REPORT_EXT_KEY));
    assert_eq!(
        check_body(Element::Report, &as_claim, &root, Some(&action)),
        Err(ExecutorRefusal::Definition("event"))
    );
    let plan = report(ProgressEvent::PlanUpdate, None);
    assert_eq!(
        check_body(Element::Report, &as_claim, &root, Some(&plan)),
        Err(ExecutorRefusal::Definition("event"))
    );
    let assumption = claim("assumption", Some(REPORT_EXT_KEY));
    assert_eq!(
        check_body(Element::Report, &assumption, &root, Some(&plan)),
        Ok(None)
    );
    let session = |commitment: RecordId| {
        SessionReport {
            session: "urn:session:1".to_owned(),
            commitment: commitment.0,
            attempt: 2,
            outcome: Some(AttemptOutcome::Failed),
            reason: Some("timeout".to_owned()),
        }
        .encode()
        .unwrap()
    };
    let claim = claim("observation", Some(SESSION_EXT_KEY));
    assert_eq!(
        check_body(Element::Session, &claim, &root, Some(&session(root))),
        Ok(None)
    );
    assert_eq!(
        check_body(Element::Session, &claim, &root, Some(&session(id(2)))),
        Err(ExecutorRefusal::Definition("commitment"))
    );
}

// SEC-15 OP-4
#[test]
fn sec_15_an_action_report_binds_one_context_to_one_key_and_the_same_pair_is_a_replay() {
    let root = id(1);
    let action = report(ProgressEvent::Action, Some(binding(4, "cmt_x/rec_y")));
    let given = check_body(
        Element::Report,
        &act(Some(REPORT_EXT_KEY)),
        &root,
        Some(&action),
    )
    .unwrap()
    .unwrap();
    assert_eq!(given.authority, *Digest::sha256([4; 32]).as_bytes());
    assert_eq!(given.key, "cmt_x/rec_y");
    assert_eq!(given.relies_on, vec![*id(9).0.as_bytes()]);
    let first = Digest::sha256([4; 32]);
    let other = Digest::sha256([5; 32]);
    let used = [Use {
        context: &first,
        key: "cmt_x/rec_y",
    }];
    assert_eq!(check_single_use(&used, used[0]), Ok(SingleUse::Replay));
    assert_eq!(
        check_single_use(
            &used,
            Use {
                context: &first,
                key: "cmt_x/rec_z"
            }
        ),
        Err(SingleUseRefusal::ContextReused)
    );
    assert_eq!(
        check_single_use(
            &used,
            Use {
                context: &other,
                key: "cmt_x/rec_y"
            }
        ),
        Err(SingleUseRefusal::KeyReused)
    );
    assert_eq!(
        ExecutorRefusal::Control(SingleUseRefusal::KeyReused.wire_name()).reason(),
        "control:key_reused"
    );
    assert_eq!(
        execution_key(root, id(2)),
        format!(
            "{}/{}",
            CommitmentId(root).to_external(),
            id(2).to_external()
        )
    );
}

// OP-4 RC-41
#[test]
fn op_4_a_record_is_acted_upon_by_the_first_action_of_the_executor_relying_on_it() {
    let executor = PartyRef::new(EXECUTOR).unwrap();
    let stranger = PartyRef::new("party:acme:mallory").unwrap();
    let reported = |record: u8, author: &PartyRef, event| Reported {
        record: id(record),
        author: author.clone(),
        at: Time(u64::from(record)),
        body: ProgressReport::decode(&report(
            event,
            (event == ProgressEvent::Action).then(|| binding(record, "k")),
        ))
        .unwrap(),
    };
    let reports = [
        reported(20, &stranger, ProgressEvent::Action),
        reported(21, &executor, ProgressEvent::Question),
        reported(22, &executor, ProgressEvent::Action),
        reported(23, &executor, ProgressEvent::Action),
    ];
    assert_eq!(
        acted_upon(&id(9), &reports, std::slice::from_ref(&executor)),
        Some(id(22))
    );
    assert_eq!(acted_upon(&id(8), &reports, &[executor]), None);
}

// RC-36 RC-40 RC-42
#[test]
fn rc_42_a_stop_request_and_a_resume_deliver_their_request_and_other_records_none() {
    let stop = decl("stop_request", &[], &[("stop_type", "pause")]);
    let delivered = request_of(&stop, id(5), None).unwrap();
    assert_eq!(delivered.kind, RequestKind::Stop);
    assert_eq!(delivered.stop_type, Some(StopType::Pause));
    assert_eq!(delivered.record, id(5).0);
    assert_eq!(
        RequestDelivery::decode(&delivered.encode().unwrap()).unwrap(),
        delivered
    );
    assert_eq!(
        request_of(&decl("stop_request", &[], &[]), id(5), None),
        None
    );
    let resume = decl("resume_after_stop", &[id(5)], &[]);
    assert_eq!(
        request_of(&resume, id(6), None).map(|r| r.kind),
        Some(RequestKind::Resume)
    );
    assert_eq!(
        request_of(&decl("control_lease", &[], &[]), id(7), None),
        None
    );
    assert_eq!(request_of(&claim("observation", None), id(7), None), None);
    let response = RequestResponse {
        request: id(5).0,
        answer: StopAnswer::Accept,
        reason: None,
        applied_version: None,
    }
    .encode()
    .unwrap();
    let answering = claim("observation", None);
    assert_eq!(
        check_body(
            Element::RequestResponse,
            &answering,
            &id(1),
            Some(&response)
        ),
        Err(ExecutorRefusal::Definition("request"))
    );
    let stop_response = decl("stop_response", &[id(5)], &[("response", "refuse")]);
    assert_eq!(
        check_body(
            Element::StopResponse,
            &stop_response,
            &id(1),
            Some(&response)
        ),
        Err(ExecutorRefusal::Definition("answer"))
    );
    assert_eq!(
        check_body(Element::StopResponse, &stop_response, &id(1), None),
        Ok(None)
    );
}
