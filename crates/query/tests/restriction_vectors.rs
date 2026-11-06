//! The server's restriction path, [`RestrictionLimits`] and [`RuleVerdict`] with its explanation in the format shared with Access, against `conformance/vectors/restriction/restriction.json`, the vectors the bindings answer natively, in WebAssembly and in Swift: the same rule set and request give the same verdict and explanation on the server and in every client (T-23, PR-11, PR-17, PR-23, T-37).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::{Value, json};
use suiss_restriction::RequestJson;
use work_proto::explanation::{Requirements, from_json, reference_from_json, to_json};
use work_query::domain::restriction::{
    COMPILE_REFUSED, REQUIRE_UNNAMED, RestrictionLimits, RuleVerdict, requirements_named,
};

const RESTRICTION: &str = include_str!("../../../conformance/vectors/restriction/restriction.json");

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}

fn verdict(v: RuleVerdict, reference: Option<&[u8; 16]>, requirements: &Requirements) -> Value {
    let explanation = v.explanation(reference, requirements).unwrap();
    let mut out = match v {
        RuleVerdict::NoObjection => json!({ "outcome": "no_objection" }),
        RuleVerdict::Require(refs) => json!({ "outcome": "require", "requirements": refs }),
        RuleVerdict::Deny {
            policies,
            attention,
        } => json!({ "outcome": "deny", "policies": policies, "attention": attention }),
    };
    if let Some(e) = explanation {
        let json = to_json(&e).unwrap();
        assert_eq!(from_json(&json).unwrap(), e);
        out["explanation"] = json;
    }
    out
}

fn server(rule_set: &Value, request: &Value) -> Value {
    let limits = RestrictionLimits::default();
    let reference = rule_set.get("ref").map(|r| reference_from_json(r).unwrap());
    let requirements = rule_set
        .get("requirements")
        .map_or_else(Requirements::default, |r| {
            Requirements::from_json(r).unwrap()
        });
    match limits.compile(text(rule_set, "schema"), text(rule_set, "policies")) {
        Ok(engine) if !requirements_named(&engine, &requirements) => {
            json!({ "error": { "code": COMPILE_REFUSED, "code_detail": REQUIRE_UNNAMED } })
        }
        Ok(engine) => verdict(
            RuleVerdict::of(engine.evaluate(&RequestJson {
                principal: text(request, "principal"),
                action: text(request, "action"),
                resource: text(request, "resource"),
                context: text(request, "context"),
                entities: text(request, "entities"),
            })),
            reference.as_ref(),
            &requirements,
        ),
        Err(refused) => {
            json!({ "error": { "code": COMPILE_REFUSED, "code_detail": refused.code() } })
        }
    }
}

// T-23 PR-11 PR-17 PR-23 T-37
#[test]
fn t_23_pr_17_the_server_engine_answers_the_shared_restriction_vectors() {
    let file: Value = serde_json::from_str(RESTRICTION).unwrap();
    let cases = file["cases"].as_array().unwrap();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let rule_set = &file["rule_sets"][text(case, "rule_set")];
        assert_eq!(server(rule_set, &case["request"]), case["expect"], "{id}");
    }
    assert_eq!(cases.len(), 25);
}
