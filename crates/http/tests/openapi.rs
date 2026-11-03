//! The committed `OpenAPI` document is the one the code generates, and every operation in it
//! names exactly one action of the Access catalog (T-98 items 1 and 2, E-45 item 3).

use std::path::Path;

use serde_json::Value;
use work_http::openapi::{ACTION_EXTENSION, DOCUMENT, document, value};
use work_proto::action::Action;

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

// T-98
#[test]
fn t_98_the_committed_openapi_document_is_the_generated_one() {
    let generated = document().unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(DOCUMENT);
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "{DOCUMENT} is stale; regenerate it with `cargo xtask openapi` (T-98)"
    );
    let doc = value().unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    let codes = doc["components"]["schemas"]["ProblemCode"]["enum"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(codes, 21);
}

// E-45 T-98
#[test]
fn e_45_every_api_operation_names_exactly_one_action() {
    let doc = value().unwrap();
    let paths = doc["paths"].as_object().unwrap();
    for (path, item) in paths {
        for method in METHODS {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let action = operation.get(ACTION_EXTENSION).and_then(Value::as_str);
            assert!(
                action.and_then(Action::parse).is_some(),
                "{method} {path} names no action of the catalog: {action:?}"
            );
        }
    }
}
