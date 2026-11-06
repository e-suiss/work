//! Restriction rule evaluation for clients and third-party verifiers through the shared `suiss-restriction` engine (T-23, PR-11, PR-17, PR-23): the binding compiles one rule set under the limits the server compiles under and writes the engine's answer as the verdict the server derives from it, with its explanation in the format shared with Access, so the same rule set and request give the same answer natively, in WebAssembly and through uniffi.

use serde_json::{Map, Value, json};
use suiss_restriction::{Denial, Engine, InputRejected, Limits, Narrow, Outcome, RequestJson};
use work_proto::explanation::{Requirements, RuleOutcome, explain, reference_from_json, to_json};

use crate::decode::{Mapped, exact_keys, object, required, text};
use crate::project::compact;
use crate::{error, input_error, parse};

// PR-23
const RULE_SET_POLICIES: usize = 64;

// PR-23
const COMPILE_REFUSED: &str = "restriction_compile_refused";

// PR-11 PR-17
const REQUIRE_UNNAMED: &str = "policy-require";

const RULE_SET_FIELDS: &[&str] = &["schema", "policies", "ref", "requirements"];
const REQUEST_FIELDS: &[&str] = &["principal", "action", "resource", "context", "entities"];

struct RuleSet<'a> {
    schema: &'a str,
    policies: &'a str,
    reference: Option<[u8; 16]>,
    requirements: Requirements,
}

fn rule_set(v: &Value) -> Option<RuleSet<'_>> {
    let m = object(v).ok()?;
    exact_keys(m, RULE_SET_FIELDS).ok()?;
    let reference = match m.get("ref") {
        Some(r) => Some(reference_from_json(r).ok()?),
        None => None,
    };
    let requirements = match m.get("requirements") {
        Some(r) => Requirements::from_json(r).ok()?,
        None => Requirements::default(),
    };
    Some(RuleSet {
        schema: text(required(m, "schema").ok()?).ok()?,
        policies: text(required(m, "policies").ok()?).ok()?,
        reference,
        requirements,
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

fn deny(policies: &[String], attention: bool) -> Value {
    json!({ "outcome": "deny", "policies": policies, "attention": attention })
}

fn verdict(answer: &Result<Outcome, InputRejected>, rules: &RuleSet<'_>) -> Value {
    let (mut out, outcome) = match answer {
        Ok(Outcome::NoObjection) => (
            json!({ "outcome": "no_objection" }),
            RuleOutcome::NoObjection,
        ),
        Ok(Outcome::Require(refs)) => (
            json!({ "outcome": "require", "requirements": refs }),
            RuleOutcome::Require(refs),
        ),
        Ok(Outcome::Deny(Denial::Forbid { policies, .. })) => {
            (deny(policies, false), RuleOutcome::Deny)
        }
        Ok(Outcome::Deny(Denial::EvaluationError | Denial::Internal)) | Err(InputRejected) => {
            (deny(&[], true), RuleOutcome::Deny)
        }
    };
    let explained = explain(outcome, rules.reference.as_ref(), &rules.requirements)
        .ok()
        .flatten()
        .and_then(|e| to_json(&e).ok());
    if let (Some(e), Some(m)) = (explained, out.as_object_mut()) {
        m.insert("explanation".to_owned(), e);
    }
    out
}

/// Evaluates one restriction rule set against one request with the shared engine, under the `esuiss-restriction` default limits narrowed to 64 policies, as the server compiles and evaluates it (T-23, PR-23), and explains the answer in the format shared with Access (PR-11, PR-17, Access E43).
///
/// `rule_set` is `{"schema", "policies", "ref"?, "requirements"?}`: the Cedar schema and the policy source as text, the rule set's 16-byte reference as unpadded base64url, and the requirement terms of each `@require` reference (`{"<reference>": [<term>…]}`, Access's JSON form). `request` is `{"principal", "action", "resource", "context", "entities"}`: entity UIDs as Cedar text, and the context object and the entity array as JSON text handed to the engine unchanged.
///
/// Returns `{"outcome":"no_objection"}`, `{"outcome":"require","requirements":[<ref>…],"explanation":…}` or `{"outcome":"deny","policies":[<id>…],"attention":<bool>,"explanation":…}`; `NO_OBJECTION` is not a permission (PR-17 item 2). `attention` is set for an input over a limit or outside the schema and for an evaluation error, which deny without naming a policy (PR-17 item 3, PR-23 item 4). `explanation` is `urn:suiss:access:schema:explanation:1`: a `restricted` blocker at `domain-policy`, subcoded `restricted/policy:<ref>` when the rule set has a reference, or one unmet term per requirement term at `domain-policy`. A rule set that does not compile returns `{"error":{"code":"restriction_compile_refused","code_detail":<crate code>}}`, and one with an `@require` reference its `requirements` do not name `code_detail` `policy-require`; input that is not JSON or does not fit returns `{"error":{"code":"invalid_json"}}`, `{"error":{"code":"invalid_rule_set"}}` or `{"error":{"code":"invalid_request"}}`.
#[must_use]
pub fn evaluate_restriction(rule_set_json: &str, request_json: &str) -> String {
    let (Some(rule_set_value), Some(request_value)) = (parse(rule_set_json), parse(request_json))
    else {
        return input_error("invalid_json");
    };
    let Some(rules) = rule_set(&rule_set_value) else {
        return input_error("invalid_rule_set");
    };
    let Ok(req) = request(&request_value) else {
        return input_error("invalid_request");
    };
    let Ok(limits) = Limits::default().narrowed(Narrow::Policies(RULE_SET_POLICIES)) else {
        return input_error("invalid_rule_set");
    };
    let refused = |code: &str| {
        let mut detail = Map::new();
        detail.insert("code_detail".to_owned(), Value::from(code));
        error(COMPILE_REFUSED, detail)
    };
    match Engine::compile(rules.schema, rules.policies, limits) {
        Ok(engine) => {
            let named = engine.policies().is_some_and(|policies| {
                policies
                    .iter()
                    .all(|p| p.require.is_none_or(|r| rules.requirements.names(r)))
            });
            if named {
                compact(verdict(&engine.evaluate(&req), &rules))
            } else {
                refused(REQUIRE_UNNAMED)
            }
        }
        Err(compile) => refused(compile.code()),
    }
}
