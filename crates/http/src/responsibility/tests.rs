use work_kernel::commitment::Operation;
use work_kernel::id::Digest;
use work_kernel::responsibility::LeaseExpiry;
use work_query::domain::kinds::declaration_action;

use super::*;

fn post_of<'a>(doc: &'a serde_json::Value, path: &str) -> &'a serde_json::Value {
    &doc["paths"][path]["post"]
}

fn header_names(operation: &serde_json::Value) -> Vec<&str> {
    operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["in"] == "header")
        .map(|p| p["name"].as_str().unwrap())
        .collect()
}

// C-6 RC-17 E-45 P-54
#[test]
fn c_6_every_responsibility_operation_has_one_typed_write_naming_its_action() {
    let doc = crate::openapi::value().unwrap();
    for op in ResponsibilityOperation::CLOSED_SET {
        let path = format!(
            "/v1/ledgers/{{ledger}}/commitments/{{commitment}}/{}",
            op.wire_name().replace('_', "-")
        );
        let post = post_of(&doc, &path);
        assert_eq!(
            post["x-work-action"],
            format!("work:{}", responsibility_action(*op)),
            "{path}"
        );
        let headers = header_names(post);
        assert!(headers.contains(&"Idempotency-Key"), "{path}");
        assert!(headers.contains(&"If-Match"), "{path}");
    }
}

// RC-5 RC-7 RC-10 RC-48 RC-9 RC-44 E-45
#[test]
fn rc_5_accountability_queues_rules_waivers_and_participation_write_under_their_actions() {
    let doc = crate::openapi::value().unwrap();
    for (path, subtype) in [
        (
            "/v1/ledgers/{ledger}/commitments/{commitment}/acknowledge",
            Some(DeclarationSubtype::Acknowledgement),
        ),
        (
            "/v1/ledgers/{ledger}/queues",
            Some(DeclarationSubtype::QueueDefinition),
        ),
        (
            "/v1/ledgers/{ledger}/org-rules",
            Some(DeclarationSubtype::OrgRule),
        ),
        (
            "/v1/ledgers/{ledger}/waivers",
            Some(DeclarationSubtype::Waiver),
        ),
        ("/v1/ledgers/{ledger}/participation", None),
    ] {
        let post = post_of(&doc, path);
        let action = subtype.map_or(Some("write"), declaration_action).unwrap();
        assert_eq!(post["x-work-action"], format!("work:{action}"), "{path}");
        let headers = header_names(post);
        assert!(headers.contains(&"Idempotency-Key"), "{path}");
        assert!(headers.contains(&"If-Match"), "{path}");
    }
    assert_eq!(
        post_of(&doc, "/v1/ledgers/{ledger}/commitments/{commitment}/amend")["x-work-action"],
        "work:commit",
        "a transfer is proposed by the amend that carries accountable"
    );
    for path in [
        "/v1/ledgers/{ledger}/queues/{queue}",
        "/v1/ledgers/{ledger}/parties/{party}/workload",
    ] {
        assert_eq!(doc["paths"][path]["get"]["x-work-action"], "work:read");
    }
    assert!(
        doc["components"]["schemas"]["CommitmentAnswer"]["properties"]
            .get("responsibility")
            .is_some()
    );
}

// RC-18 RC-14 RC-19
#[test]
fn rc_18_the_lease_forwardings_and_history_are_answered_by_their_wire_names() {
    let q = RecordId(Digest::sha256([5; 32]));
    let end = Time(61_000);
    assert_eq!(lease_status(LeaseStatus::NoLease), ("no_lease", None));
    assert_eq!(
        lease_status(LeaseStatus::Running(end)),
        ("running", Some(end))
    );
    assert_eq!(
        lease_status(LeaseStatus::Expired {
            at: end,
            expiry: LeaseExpiry::ReturnToPool,
        }),
        ("expired", Some(end))
    );
    assert_eq!(
        forward_target(&ForwardTarget::Queue(q)).queue,
        Some(rec(&q))
    );
    let alice = PartyRef::new("party:acme:alice").unwrap();
    assert_eq!(
        forward_target(&ForwardTarget::Candidates(vec![alice])).candidates,
        Some(vec!["party:acme:alice".to_owned()])
    );
    assert_eq!(
        act(AllocationAct::Responsibility(
            ResponsibilityOperation::RenewLease
        )),
        "renew_lease"
    );
    assert_eq!(act(AllocationAct::Acknowledgement), "acknowledgement");
    assert_eq!(
        act(AllocationAct::Commitment(Operation::Promise)),
        "promise"
    );
}
