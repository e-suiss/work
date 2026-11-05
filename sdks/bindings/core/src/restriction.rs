//! Restriction rule evaluation for clients and third-party verifiers through the shared `suiss-restriction` engine (T-23, PR-17, PR-23): the binding compiles one rule set under the limits the server compiles under and writes the engine's answer as the verdict the server derives from it, so the same rule set and request give the same answer natively, in WebAssembly and through uniffi.

use serde_json::{Map, Value, json};
use suiss_restriction::{Denial, Engine, InputRejected, Limits, Narrow, Outcome, RequestJson};

use crate::decode::{Mapped, exact_keys, object, required, text};
use crate::project::compact;
use crate::{error, input_error, parse};

// PR-23
const RULE_SET_POLICIES: usize = 64;

// PR-23
const COMPILE_REFUSED: &str = "restriction_compile_refused";

const RULE_SET_FIELDS: &[&str] = &["schema", "policies"];
const REQUEST_FIELDS: &[&str] = &["principal", "action", "resource", "context", "entities"];

struct RuleSet<'a> {
    schema: &'a str,
    policies: &'a str,
}

fn rule_set(v: &Value) -> Mapped<RuleSet<'_>> {
    let m = object(v)?;
    exact_keys(m, RULE_SET_FIELDS)?;
    Ok(RuleSet {
        schema: text(required(m, "schema")?)?,
        policies: text(required(m, "policies")?)?,
    })
}

fn request(v: &Value) -> Mapped<RequestJson<'_>> {
    let m = object(v)?;
    exact_keys(m, REQUEST_FIELDS)?;
    Ok(RequestJson {
        principal: text(required(m, "principal")?)?,
        action: text(required(m, "action")?)?,
        resource: text(required(m, "resource")?)?,
        context: text(required(m, "context")?)?,
        entities: text(required(m, "entities")?)?,
    })
}

fn deny(policies: Vec<String>, attention: bool) -> Value {
    json!({ "outcome": "deny", "policies": policies, "attention": attention })
}

fn verdict(answer: Result<Outcome, InputRejected>) -> Value {
    match answer {
        Ok(Outcome::NoObjection) => json!({ "outcome": "no_objection" }),
        Ok(Outcome::Require(refs)) => json!({ "outcome": "require", "requirements": refs }),
        Ok(Outcome::Deny(Denial::Forbid { policies, .. })) => deny(policies, false),
        Ok(Outcome::Deny(Denial::EvaluationError | Denial::Internal)) | Err(InputRejected) => {
            deny(Vec::new(), true)
        }
    }
}

/// Evaluates one restriction rule set against one request with the shared engine, under the `esuiss-restriction` default limits narrowed to 64 policies, as the server compiles and evaluates it (T-23, PR-23).
///
/// `rule_set` is `{"schema", "policies"}`: the Cedar schema and the policy source as text. `request` is `{"principal", "action", "resource", "context", "entities"}`: entity UIDs as Cedar text, and the context object and the entity array as JSON text handed to the engine unchanged.
///
/// Returns `{"outcome":"no_objection"}`, `{"outcome":"require","requirements":[<ref>…]}` or `{"outcome":"deny","policies":[<id>…],"attention":<bool>}`; `NO_OBJECTION` is not a permission (PR-17 item 2). `attention` is set for an input over a limit or outside the schema and for an evaluation error, which deny without naming a policy (PR-17 item 3, PR-23 item 4). A rule set that does not compile returns `{"error":{"code":"restriction_compile_refused","code_detail":<crate code>}}`; input that is not JSON or does not fit returns `{"error":{"code":"invalid_json"}}`, `{"error":{"code":"invalid_rule_set"}}` or `{"error":{"code":"invalid_request"}}`.
#[must_use]
pub fn evaluate_restriction(rule_set_json: &str, request_json: &str) -> String {
    let (Some(rule_set_value), Some(request_value)) = (parse(rule_set_json), parse(request_json))
    else {
        return input_error("invalid_json");
    };
    let Ok(rules) = rule_set(&rule_set_value) else {
        return input_error("invalid_rule_set");
    };
    let Ok(req) = request(&request_value) else {
        return input_error("invalid_request");
    };
    let Ok(limits) = Limits::default().narrowed(Narrow::Policies(RULE_SET_POLICIES)) else {
        return input_error("invalid_rule_set");
    };
    match Engine::compile(rules.schema, rules.policies, limits) {
        Ok(engine) => compact(verdict(engine.evaluate(&req))),
        Err(refused) => {
            let mut detail = Map::new();
            detail.insert("code_detail".to_owned(), Value::from(refused.code()));
            error(COMPILE_REFUSED, detail)
        }
    }
}
