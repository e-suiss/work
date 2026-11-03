//! The `OpenAPI` 3.1 document of the REST API (T-98 item 1, P-54 item 2): generated from the `utoipa` derives of this crate with every object's keys in sorted order, written to `sdks/openapi/work-v1.json` by `cargo xtask openapi` and compared byte for byte by `cargo xtask check openapi`, which also checks that every operation names one Access action (E-45 item 3).

use serde_json::{Map, Value};
use utoipa::OpenApi as _;

use crate::problem::{FieldError, Problem, ProblemCode};

/// The committed document, relative to the workspace root.
pub const DOCUMENT: &str = "sdks/openapi/work-v1.json";

/// The operation extension naming the Access action (E-45 item 3).
pub const ACTION_EXTENSION: &str = "x-work-action";

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Work API",
        version = "1",
        description = "The Work REST API. Errors are RFC 9457 problems; every operation names the Access action it asks for in x-work-action."
    ),
    components(schemas(Problem, ProblemCode, FieldError))
)]
struct Api;

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect::<Map<String, Value>>(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// The document as a JSON value.
///
/// # Errors
/// The serialisation error.
pub fn value() -> Result<Value, serde_json::Error> {
    Ok(sorted(serde_json::to_value(Api::openapi())?))
}

/// The document as pretty JSON with a trailing newline.
///
/// # Errors
/// The serialisation error.
pub fn document() -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(&value()?)?;
    text.push('\n');
    Ok(text)
}
