use work_kernel::commitment::Refusal;
use work_kernel::id::{Digest, PartyRef};

use super::*;

// C-6 CM-17 E-45 P-54
#[test]
fn c_6_every_operation_a_caller_writes_has_one_typed_write_naming_its_action() {
    let doc = crate::openapi::value().unwrap();
    let paths = doc["paths"].as_object().unwrap();
    for op in Operation::CLOSED_SET
        .iter()
        .chain(&[Operation::ImplicitAcceptanceTerms])
    {
        let Some(action) = action_of(*op) else {
            continue;
        };
        let path = if *op == Operation::Request {
            "/v1/ledgers/{ledger}/commitments".to_owned()
        } else {
            format!(
                "/v1/ledgers/{{ledger}}/commitments/{{commitment}}/{}",
                op.wire_name().replace('_', "-")
            )
        };
        let post = &paths[path.as_str()]["post"];
        assert_eq!(post["x-work-action"], format!("work:{action}"), "{path}");
        let headers: Vec<&str> = post["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["in"] == "header")
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(headers.contains(&"Idempotency-Key"), "{path}");
        assert!(headers.contains(&"If-Match"), "{path}");
    }
    assert!(
        !paths.contains_key("/v1/ledgers/{ledger}/commitments/{commitment}/expire"),
        "expire is the Work service's own record"
    );
    assert_eq!(
        paths["/v1/ledgers/{ledger}/commitments/{commitment}"]["get"]["x-work-action"],
        "work:read"
    );
}

// P-55 CM-58 CM-42 CM-15
#[test]
fn p_55_what_a_transition_still_needs_and_the_next_move_are_spelled_by_their_wire_names() {
    let gate = RecordId(Digest::sha256([7; 32]));
    assert_eq!(missing(&Missing::StepUp), "step_up");
    assert_eq!(missing(&Missing::AccessPending), "access_pending");
    assert_eq!(
        missing(&Missing::Gate(gate)),
        format!("gate:{}", gate.to_external())
    );
    let party = PartyRef::new("party:acme:alice").unwrap();
    assert_eq!(
        mover(&Mover::Party(party)),
        MoverAnswer {
            kind: "party".to_owned(),
            id: Some("party:acme:alice".to_owned()),
        }
    );
    assert_eq!(mover(&Mover::Accountable).id, None);
    let blocked = implicit(ImplicitAcceptance::Blocked(Refusal::FourEyes));
    assert_eq!(blocked.status, "blocked");
    assert_eq!(blocked.reason.as_deref(), Some("four_eyes"));
    let waiting = implicit(ImplicitAcceptance::Waiting(Time(0)));
    assert_eq!(waiting.ends_at.as_deref(), Some("1970-01-01T00:00:00.000Z"));
    assert_ne!(
        work_kernel::commitment::CommitmentState::Promised.wire_name(),
        work_kernel::commitment::CommitmentState::Accepted.wire_name()
    );
}
