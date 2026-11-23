use work_kernel::catalog::StopType;
use work_kernel::control::autonomy::{Autonomy, AutonomyCause, AutonomyOutcome};
use work_kernel::control::axis::{AuthorityAxis, Driver, ExecutionAxis, Liveness};
use work_kernel::control::body::{ControlMode, RequestKind};
use work_kernel::control::stop::{StopProgress, StopState};
use work_kernel::id::{Digest, PartyRef};
use work_kernel::responsibility::{InterventionMark, LeaseExpiry};

use super::*;

// E-45 RC-31 RC-33 RC-36 RC-37 RC-40 RC-27 C-6 P-54
#[test]
fn e_45_every_control_record_has_one_typed_write_naming_its_action() {
    let doc = crate::openapi::value().unwrap();
    let paths = doc["paths"].as_object().unwrap();
    let scoped = [
        ("control-leases", "work:control"),
        ("handoff-notes", "work:control"),
        ("attention-requests", "work:condition"),
        ("consultations", "work:condition"),
        ("stop-requests", "work:stop_request"),
        ("stop-responses", "work:stop_respond"),
        ("forced-stops", "work:write"),
        ("resume-after-stop", "work:stop_request"),
        ("corrections", "work:commit"),
    ];
    let mut all: Vec<(String, &str)> = scoped
        .iter()
        .map(|(p, a)| {
            (
                format!("/v1/ledgers/{{ledger}}/commitments/{{commitment}}/{p}"),
                *a,
            )
        })
        .collect();
    all.push((
        "/v1/ledgers/{ledger}/autonomy-policies".to_owned(),
        "work:autonomy_policy_set",
    ));
    for (path, action) in &all {
        let post = &paths[path.as_str()]["post"];
        assert_eq!(post["x-work-action"], *action, "{path}");
        let headers: Vec<&str> = post["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["in"] == "header")
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(headers.contains(&"Idempotency-Key"), "{path}");
        assert!(headers.contains(&"If-Match"), "{path}");
        assert!(post["responses"]["422"].is_object(), "{path}");
    }
    assert!(paths.contains_key("/v1/ledgers/{ledger}/commitments/{commitment}/resume"));
    let schema = &doc["components"]["schemas"]["CommitmentAnswer"]["properties"]["control"];
    assert!(schema.is_object());
}

fn party(s: &str) -> PartyRef {
    PartyRef::new(s).unwrap()
}

// RC-3 RC-27 RC-30 RC-36 RC-8 RC-18 ST-4
#[test]
fn rc_30_the_control_of_a_commitment_is_answered_by_its_wire_names() {
    let lease = RecordId(Digest::sha256([5; 32]));
    let stop_record = RecordId(Digest::sha256([6; 32]));
    let read = ControlRead {
        executor: Some(party("party:acme:robot-arm-3")),
        capability: None,
        offered: vec![Request {
            kind: RequestKind::Stop,
            stop_type: Some(StopType::Pause),
            change_policy: None,
        }],
        policy: None,
        autonomy: vec![MoveAutonomy {
            action: "work:close".to_owned(),
            operation: Some(Operation::Accept),
            request: None,
            autonomy: Autonomy {
                outcome: AutonomyOutcome::RequireGate,
                causes: vec![AutonomyCause::Irreversible],
                suggest: false,
            },
        }],
        axes: Some(Axes {
            authority: AuthorityAxis::Revoked,
            control: Some(ControlMode::Intervened),
            execution: ExecutionAxis::Unknown,
            liveness: Liveness::Stale,
            driver: Driver {
                party: party("party:acme:bob"),
                lease: Some(lease),
            },
        }),
        stops: vec![StopView {
            request: stop_record,
            requester: party("party:acme:alice"),
            stop_type: StopType::FinishThenStop,
            progress: StopProgress::Refused,
            response: None,
            confirmation: None,
            state: StopState::Unknown,
            forced: None,
            timing: StopTiming::AfterStep("weld_seam".to_owned()),
            attention: vec![party("party:acme:alice")],
            revocation_path: true,
            resumed: None,
            restarted_without_resume: false,
        }],
        interventions: vec![(lease, InterventionMark::OutsideCoordination)],
        activity: vec![Time(0)],
        lease: LeaseStatus::Expired {
            at: Time(1_000),
            expiry: LeaseExpiry::KeepAndSignal,
        },
    };
    let answer = ControlAnswer::of(&read);
    assert_eq!(answer.offered_requests[0].kind, "stop");
    assert_eq!(
        answer.offered_requests[0].stop_type.as_deref(),
        Some("pause")
    );
    assert_eq!(answer.autonomy.moves[0].outcome, "require_gate");
    assert_eq!(answer.autonomy.moves[0].causes, ["irreversible"]);
    let control = answer.control.unwrap();
    assert_eq!(control.authority, "revoked");
    assert_eq!(control.execution, "unknown");
    assert_eq!(control.liveness, "stale");
    assert_eq!(control.mode.as_deref(), Some("intervened"));
    assert_eq!(control.driver.lease, Some(lease.to_external()));
    assert_eq!(answer.stops[0].progress, "refused");
    assert_eq!(answer.stops[0].after_step.as_deref(), Some("weld_seam"));
    assert_eq!(answer.interventions[0].mark, "outside_coordination");
    assert_eq!(answer.lease.status, "expired");
    assert_eq!(answer.lease.expiry.as_deref(), Some("keep_and_signal"));
    assert_eq!(answer.lease.activity, ["1970-01-01T00:00:00.000Z"]);
}
