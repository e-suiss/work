//! JSON front end shared by the Work kernel bindings (T-5, T-31): it maps the `decoded` JSON projection of records and their verifier inputs onto kernel types, calls `work_kernel::validate` or `work_kernel::derive::derive`, and writes the kernel's answer as compact JSON with sorted keys, so every binding returns the same bytes for the same input (T-37, INV-7, INV-8).

#![forbid(unsafe_code)]

mod decode;
mod derivation;

use serde_json::{Map, Value, json};
use work_kernel::id::Time;
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::{Reason, Schema};
use work_kernel::uri::ExtKey;
use work_kernel::validate::{
    ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin, Outcome, ValidationContext,
    validate,
};

use decode::{Mapped, ext_key, list, object, optional, pair, required, text, uint};

const MISSING: Reason = Reason::Schema(Schema::RequiredField);

const CONTEXT_FIELDS: &[&str] = &[
    "origin",
    "actor_type",
    "understood_extensions",
    "recorded_at",
];

pub(crate) fn error(code: &str, extra: Map<String, Value>) -> String {
    let mut detail = extra;
    detail.insert("code".to_owned(), Value::from(code));
    json!({ "error": detail }).to_string()
}

pub(crate) fn input_error(code: &str) -> String {
    error(code, Map::new())
}

pub(crate) fn parse(input: &str) -> Option<Value> {
    serde_json::from_str(input).ok()
}

fn actor_entry(v: &Value) -> Mapped<ActorTypeEntry> {
    let (actor_type, source) = pair(v)?;
    Ok(ActorTypeEntry {
        actor_type: ActorType::from_wire_name(text(actor_type)?).ok_or(MISSING)?,
        source: ActorTypeSource::from_wire_name(text(source)?).ok_or(MISSING)?,
    })
}

struct Context {
    origin: Origin,
    actor_types: ActorTypes,
    understood: Vec<ExtKey>,
    recorded_at: Option<Time>,
}

fn context(v: &Value) -> Mapped<Context> {
    let m = object(v)?;
    if m.keys().any(|k| !CONTEXT_FIELDS.contains(&k.as_str())) {
        return Err(MISSING);
    }
    let actors = object(required(m, "actor_type")?)?;
    if actors.keys().any(|k| k != "author" && k != "on_behalf_of") {
        return Err(MISSING);
    }
    Ok(Context {
        origin: Origin::from_wire_name(text(required(m, "origin")?)?).ok_or(MISSING)?,
        actor_types: ActorTypes {
            author: actor_entry(required(actors, "author")?)?,
            on_behalf_of: optional(actors, "on_behalf_of", |l| list(l, actor_entry))?
                .unwrap_or_default(),
        },
        understood: list(required(m, "understood_extensions")?, |k| ext_key(text(k)?))?,
        recorded_at: optional(m, "recorded_at", uint)?.map(Time),
    })
}

/// Validates one record given as its `decoded` JSON projection against a verifier context shaped like a vector `context` (`origin`, `actor_type` as the envelope's `ActorTypeAnnotation`, `understood_extensions`, optional `recorded_at`), under the default semantic limits.
///
/// Returns `{"outcome":"accept"}`, `{"outcome":"reject","reason":<code>}` or `{"outcome":"quarantine","reason":<code>}`; a record the projection cannot carry is a `schema:*` rejection. Input that is not JSON or a context that does not fit returns `{"error":{"code":"invalid_json"}}` or `{"error":{"code":"invalid_context"}}`.
#[must_use]
pub fn validate_record(decoded: &str, context_json: &str) -> String {
    let (Some(decoded), Some(context_value)) = (parse(decoded), parse(context_json)) else {
        return input_error("invalid_json");
    };
    let Ok(ctx) = context(&context_value) else {
        return input_error("invalid_context");
    };
    let outcome = match decode::record(&decoded) {
        Err(reason) => Outcome::Rejected(reason),
        Ok(record) => validate(
            &record,
            &ValidationContext {
                origin: ctx.origin,
                actor_types: &ctx.actor_types,
                understood_extensions: &ctx.understood,
                limits: SemanticLimits::DEFAULT,
                recorded_at: ctx.recorded_at,
            },
        ),
    };
    match outcome {
        Outcome::Accepted => json!({ "outcome": "accept" }),
        Outcome::Rejected(reason) => json!({ "outcome": "reject", "reason": reason.to_string() }),
        Outcome::Quarantined(reason) => {
            json!({ "outcome": "quarantine", "reason": reason.to_string() })
        }
    }
    .to_string()
}

pub use derivation::derive_records;
