//! The API contracts (T-98): `cargo xtask openapi` writes `sdks/openapi/work-v1.json` from the `work-http` derives, `cargo xtask asyncapi` writes `sdks/asyncapi/work-events.yaml`, `work-live.yaml` and the versioned event `data` schemas from the `work_proto::events` table, `cargo xtask check openapi` and `check asyncapi` regenerate and compare them byte for byte, the `OpenAPI` check also lints every operation (E-45 item 3, P-54 items 4, 5 and 9), and the `event-catalog` check refuses a kernel wire name that has no event type.

#[path = "contracts_asyncapi.rs"]
pub(crate) mod asyncapi;
#[path = "contracts_openapi.rs"]
pub(crate) mod openapi;
#[path = "contracts_source.rs"]
pub(crate) mod source;

use std::path::{Path, PathBuf};

use crate::{Check, Violation};

/// The checks that run with every `cargo xtask check`.
pub(crate) fn checks() -> Vec<Check> {
    vec![Check {
        name: "event-catalog",
        run: source::check_event_catalog,
    }]
}

pub(crate) fn violation(rule: &'static str, path: &str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

pub(crate) fn write(root: &Path, rel: &str, text: &str) -> Result<(), String> {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))
}
