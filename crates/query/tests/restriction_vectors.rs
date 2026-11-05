//! The server's restriction path, [`RestrictionLimits`] and [`RuleVerdict`], against `conformance/vectors/restriction/restriction.json`, the vectors the bindings answer natively, in WebAssembly and in Swift: the same rule set and request give the same verdict on the server and in every client (T-23, PR-17, PR-23, T-37).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::{Value, json};
use suiss_restriction::RequestJson;
use work_query::domain::restriction::{COMPILE_REFUSED, RestrictionLimits, RuleVerdict};

const RESTRICTION: &str = include_str!("../../../conformance/vectors/restriction/restriction.json");

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}

fn verdict(v: RuleVerdict) -> Value {
    match v {
        RuleVerdict::NoObjection => json!({ "outcome": "no_objection" }),
        RuleVerdict::Require(refs) => json!({ "outcome": "require", "requirements": refs }),
        RuleVerdict::Deny {
            policies,
            attention,
        } => json!({ "outcome": "deny", "policies": policies, "attention": attention }),
    }
}

fn server(rule_set: &Value, request: &Value) -> Value {
    let limits = RestrictionLimits::default();
    match limits.compile(text(rule_set, "schema"), text(rule_set, "policies")) {
        Ok(engine) => verdict(RuleVerdict::of(engine.evaluate(&RequestJson {
            principal: text(request, "principal"),
            action: text(request, "action"),
            resource: text(request, "resource"),
            context: text(request, "context"),
            entities: text(request, "entities"),
        }))),
        Err(refused) => {
            json!({ "error": { "code": COMPILE_REFUSED, "code_detail": refused.code() } })
        }
    }
}

// T-23 PR-17 PR-23 T-37
#[test]
fn t_23_pr_17_the_server_engine_answers_the_shared_restriction_vectors() {
    let file: Value = serde_json::from_str(RESTRICTION).unwrap();
    let cases = file["cases"].as_array().unwrap();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let rule_set = &file["rule_sets"][text(case, "rule_set")];
        assert_eq!(server(rule_set, &case["request"]), case["expect"], "{id}");
    }
    assert_eq!(cases.len(), 24);
}
