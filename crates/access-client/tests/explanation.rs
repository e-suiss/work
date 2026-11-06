//! Work's decision explanation against Access's kernel (PR-11, PR-17; Access E43, A25 item 4): every example of Access's `explanation.json` that Work's `explanation.cddl` check accepts, Access's `decision_from_value` accepts too, and both write it back to the same deterministic CBOR; what one refuses the other refuses.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use access_kernel::combinator::codec::{decision_from_value, decision_value};
use serde_json::Value as Json;
use suiss_crypto::dcbor::{self, Limits, Value};
use work_proto::explanation::{Explanation, from_json, to_json};

const VECTORS: &str = include_str!("../../../conformance/vectors/access/explanation.json");

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn agree(id: &str, value: &Value) -> bool {
    let work = Explanation::from_value(value.clone()).is_ok();
    let access = decision_from_value(value).is_ok();
    assert_eq!(work, access, "{id}: work {work}, access {access}");
    work
}

fn with(value: &Value, name: &str, member: Value) -> Value {
    let Value::Map(entries) = value else {
        panic!("a map");
    };
    let mut entries: Vec<(Value, Value)> = entries
        .iter()
        .filter(|(k, _)| *k != Value::text(name))
        .cloned()
        .collect();
    entries.push((Value::text(name), member));
    let mut keyed: Vec<(Vec<u8>, (Value, Value))> = entries
        .into_iter()
        .map(|(k, v)| (dcbor::encode(&k, Limits::CEILING).unwrap(), (k, v)))
        .collect();
    keyed.sort_by(|x, y| x.0.cmp(&y.0));
    Value::Map(keyed.into_iter().map(|(_, kv)| kv).collect())
}

// PR-11 PR-17
#[test]
fn pr_11_pr_17_work_and_the_access_kernel_agree_on_access_s_explanation_examples() {
    let file: Json = serde_json::from_str(VECTORS).unwrap();
    let mut valid = Vec::new();
    for case in file["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if case["valid"] != true {
            assert!(from_json(&case["json"]).is_err(), "{id}");
            continue;
        }
        let cbor = hex(case["cbor"].as_str().unwrap());
        let value = dcbor::decode(&cbor, Limits::CEILING).unwrap();
        assert!(agree(id, &value), "{id}");
        let work = Explanation::decode(&cbor).unwrap();
        assert_eq!(work.encode().unwrap(), cbor, "{id}");
        assert_eq!(from_json(&case["json"]).unwrap(), work, "{id}");
        assert_eq!(to_json(&work).unwrap(), case["json"], "{id}");
        let decision = decision_from_value(&value).unwrap();
        let back = dcbor::encode(&decision_value(&decision), Limits::CEILING).unwrap();
        assert_eq!(back, cbor, "{id}");
        valid.push(value);
    }
    assert_eq!(valid.len(), 7);
    let bare = &valid[1];
    let deny = &valid[2];
    let refused = [
        ("unknown-member", with(bare, "reason", Value::text("x"))),
        (
            "unknown-outcome",
            with(bare, "outcome", Value::text("no_objection")),
        ),
        ("empty-blockers", with(deny, "blockers", Value::Array(Vec::new()))),
        ("empty-relied-on", with(bare, "relied_on", Value::Array(Vec::new()))),
        (
            "short-proof-id",
            with(
                bare,
                "relied_on",
                Value::Array(vec![Value::Bytes(vec![0x11; 15])]),
            ),
        ),
        (
            "repeated-proof-id",
            with(
                bare,
                "relied_on",
                Value::Array(vec![
                    Value::Bytes(vec![0x11; 16]),
                    Value::Bytes(vec![0x11; 16]),
                ]),
            ),
        ),
        (
            "unordered-proof-ids",
            with(
                bare,
                "relied_on",
                Value::Array(vec![
                    Value::Bytes(vec![0x22; 16]),
                    Value::Bytes(vec![0x11; 16]),
                ]),
            ),
        ),
        ("not-a-map", Value::Array(vec![Value::text("allow")])),
    ];
    for (id, value) in &refused {
        assert!(!agree(id, value), "{id}");
    }
}
