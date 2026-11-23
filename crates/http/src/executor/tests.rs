#![allow(clippy::unwrap_used, reason = "test code")]

use work_kernel::id::{Digest, RecordId};
use work_query::domain::reads::Delivery;

use super::*;

// RC-42 E-45
#[test]
fn rc_42_every_executor_element_has_one_typed_write_naming_its_action() {
    let doc = crate::openapi::value().unwrap();
    let paths = doc["paths"].as_object().unwrap();
    for (element, action) in [
        ("capability", "work:write"),
        ("status", "work:write"),
        ("control-mode", "work:write"),
        ("heartbeat", "work:write"),
        ("session", "work:write"),
        ("reports", "work:write"),
        ("responses", "work:stop_respond"),
        ("request-responses", "work:write"),
        ("handover", "work:control"),
    ] {
        let path = format!("/v1/ledgers/{{ledger}}/commitments/{{commitment}}/executor/{element}");
        let post = &paths[path.as_str()]["post"];
        assert_eq!(post["x-work-action"], action, "{path}");
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
    assert_eq!(
        paths["/v1/ledgers/{ledger}/executor/deliveries"]["get"]["x-work-action"],
        "work:read"
    );
}

// P-54
#[test]
fn p_54_the_delivery_read_takes_a_cursor_and_a_wait_of_at_most_thirty_seconds() {
    let uri = |q: &str| Uri::try_from(format!("/v1/ledgers/l/executor/deliveries{q}")).unwrap();
    assert_eq!(DeliveriesQuery::of(&uri("")).unwrap(), (0, 0));
    assert_eq!(
        DeliveriesQuery::of(&uri("?after=17&wait=30")).unwrap(),
        (17, 30)
    );
    assert!(DeliveriesQuery::of(&uri("?wait=31")).is_err());
    assert!(DeliveriesQuery::of(&uri("?after=x")).is_err());
    assert!(DeliveriesQuery::of(&uri("?after=1&after=2")).is_err());
}

// RC-42 E-39 P-54
#[test]
fn rc_42_a_delivery_is_answered_with_decimal_numbers_and_its_body_in_base64url() {
    let read = Deliveries {
        deliveries: vec![Delivery {
            seq: 17,
            kind: "commitment",
            commitment: RecordId(Digest::sha256([1; 32])),
            record: RecordId(Digest::sha256([2; 32])),
            body: vec![0xa0],
            at_ms: 1_792_749_600_000,
        }],
        cursor: 17,
    };
    let answer = serde_json::to_value(DeliveriesAnswer::of(&read)).unwrap();
    assert_eq!(answer["cursor"], "17");
    let first = &answer["deliveries"][0];
    assert_eq!(first["seq"], "17");
    assert_eq!(first["kind"], "commitment");
    assert_eq!(first["body"], "oA");
    assert_eq!(first["at"], "2026-10-23T10:00:00.000Z");
    assert_eq!(
        first["commitment"],
        CommitmentId(RecordId(Digest::sha256([1; 32]))).to_external()
    );
    assert!(first.get("addressee").is_none());
}
