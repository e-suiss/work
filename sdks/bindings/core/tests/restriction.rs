//! Restriction rule evaluation of the bindings' front end, with its explanation in the format shared with Access (PR-11), natively against `conformance/vectors/restriction/restriction.json`, which the server's engine, WebAssembly and Swift answer the same way: each answer is the JSON the vector states, byte for byte (T-23, PR-17, PR-23, T-5, T-37).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::BTreeMap;

use serde_json::{Value, json};
use work_bindings_core::evaluate_restriction;

const RESTRICTION: &str =
    include_str!("../../../../conformance/vectors/restriction/restriction.json");

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let entries: BTreeMap<&String, &Value> = map.iter().collect();
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), sorted(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn same(id: &str, got: &str, want: &Value) {
    assert_eq!(got, sorted(want).to_string(), "{id}");
}

fn vectors() -> Value {
    serde_json::from_str(RESTRICTION).unwrap()
}

// T-23 PR-11 PR-17 PR-23 T-5 T-37
#[test]
fn t_23_pr_17_restriction_vectors_through_bindings_core() {
    let file = vectors();
    let cases = file["cases"].as_array().unwrap();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let rule_set = &file["rule_sets"][case["rule_set"].as_str().unwrap()];
        assert!(rule_set.is_object(), "{id}");
        let got = evaluate_restriction(&rule_set.to_string(), &case["request"].to_string());
        same(id, &got, &case["expect"]);
    }
    assert_eq!(cases.len(), 25);
    for outcome in ["no_objection", "require", "deny"] {
        assert!(
            cases.iter().any(|c| c["expect"]["outcome"] == outcome),
            "{outcome}"
        );
    }
    for case in cases {
        let has = case["expect"].get("explanation").is_some();
        let explains = matches!(case["expect"]["outcome"].as_str(), Some("require" | "deny"));
        assert_eq!(has, explains, "{}", case["id"]);
    }
    assert!(
        cases
            .iter()
            .any(|c| c["expect"]["error"]["code"] == "restriction_compile_refused")
    );
}

// T-23 T-5
#[test]
fn t_23_input_that_does_not_fit_is_an_input_error() {
    let file = vectors();
    let rule_set = file["rule_sets"]["main"].to_string();
    let request = file["cases"][0]["request"].to_string();
    same(
        "rule set json",
        &evaluate_restriction("{", &request),
        &json!({ "error": { "code": "invalid_json" } }),
    );
    same(
        "request json",
        &evaluate_restriction(&rule_set, "["),
        &json!({ "error": { "code": "invalid_json" } }),
    );
    let invalid_rule_set = json!({ "error": { "code": "invalid_rule_set" } });
    for bad in [
        json!({}),
        json!({ "schema": "" }),
        json!({ "schema": "", "policies": 1 }),
        json!({ "schema": "", "policies": "", "limits": {} }),
        json!({ "schema": "", "policies": "", "ref": "MzMz" }),
        json!({ "schema": "", "policies": "", "requirements": { "rs": [] } }),
        json!({ "schema": "", "policies": "", "requirements": { "rs": [{ "class": "kyc" }] } }),
        json!([]),
    ] {
        let text = bad.to_string();
        same(
            &text,
            &evaluate_restriction(&text, &request),
            &invalid_rule_set,
        );
    }
    let invalid_request = json!({ "error": { "code": "invalid_request" } });
    let mut extra = file["cases"][0]["request"].clone();
    extra["actor"] = json!("x");
    let mut missing = file["cases"][0]["request"].clone();
    missing.as_object_mut().unwrap().remove("entities");
    let mut object_context = file["cases"][0]["request"].clone();
    object_context["context"] = json!({});
    for bad in [extra, missing, object_context] {
        let text = bad.to_string();
        same(
            &text,
            &evaluate_restriction(&rule_set, &text),
            &invalid_request,
        );
    }
}
