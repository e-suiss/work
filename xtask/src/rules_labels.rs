//! Component labels (T-10, T-11, T-75): the registry in `xtask/component-labels.toml` gives every §17.5 component, or each part of a component its row splits, exactly one T-10 label and its "never" rule with the tests that enforce it or what is still open; every table of the migrations belongs to exactly one registered part, a CANONICAL or SYNC-DERIVED table only to a part of that label, a DERIVED or PROJECTION table only to a DERIVED or PROJECTION part, and a DERIVED, PROJECTION or OPERATIONAL part owns no CANONICAL or SYNC-DERIVED table, so derived and operational data never become a normative input.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::deps::COMPONENTS;
use crate::rules::derived::{LABELS, Schema, is_migration};
use crate::rules::files::{read, rel, walk};

const RULE: &str = "component-labels";

/// The component label registry (T-10).
pub(crate) const REGISTRY_FILE: &str = "xtask/component-labels.toml";

/// The §17.5 component rows, in table order.
pub(crate) const ROWS: &[&str] = &[
    "api-gateway",
    "request-verifier",
    "ledger-sequencer",
    "canonical-store",
    "checkpoint-witness",
    "replica-mirror",
    "signer",
    "reconciler",
    "timers",
    "derivation-workers",
    "query-service",
    "event-dispatcher",
    "federation-gateway",
    "live-layer",
    "placement-directory",
    "export-replay",
];

const NORMATIVE: &[&str] = &["CANONICAL", "SYNC-DERIVED"];
const ADVISORY: &[&str] = &["DERIVED", "PROJECTION"];

/// One registered component or component part.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Component {
    pub(crate) name: String,
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) crates: Vec<String>,
    #[serde(default)]
    pub(crate) tables: Vec<String>,
    pub(crate) never: String,
    #[serde(default)]
    pub(crate) enforced_by: Vec<String>,
    #[serde(default)]
    pub(crate) open: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    #[serde(default)]
    component: Vec<Component>,
}

/// Parses the registry.
pub(crate) fn parse(text: &str) -> Result<Vec<Component>, String> {
    toml::from_str::<Registry>(text)
        .map(|r| r.component)
        .map_err(|e| format!("{REGISTRY_FILE}: {e}"))
}

/// What the registry is checked against: the component rows, the label of every table the migrations create, and whether a crate path or a test link exists.
pub(crate) struct Facts<'a> {
    pub(crate) rows: &'a [&'a str],
    pub(crate) tables: &'a BTreeMap<String, String>,
    pub(crate) crate_exists: &'a dyn Fn(&str) -> bool,
    pub(crate) test_exists: &'a dyn Fn(&str) -> bool,
}

fn part_violations(c: &Component, facts: &Facts<'_>, out: &mut Vec<String>) {
    let name = &c.name;
    let row = name.split('/').next().unwrap_or_default();
    if !facts.rows.contains(&row) {
        out.push(format!("`{name}` is not a §17.5 component (T-10)"));
    }
    if !LABELS.contains(&c.label.as_str()) {
        out.push(format!(
            "`{name}` carries `{}`, not exactly one T-10 label ({})",
            c.label,
            LABELS.join(", ")
        ));
    }
    if c.never.trim().is_empty() {
        if !c.enforced_by.is_empty() || !c.open.trim().is_empty() {
            out.push(format!(
                "`{name}` has no never rule but lists tests or open work (T-10)"
            ));
        }
    } else if c.enforced_by.is_empty() && c.open.trim().is_empty() {
        out.push(format!(
            "`{name}`'s never rule names no enforcing test and nothing open (T-10)"
        ));
    }
    for t in &c.enforced_by {
        if !(facts.test_exists)(t) {
            out.push(format!(
                "`{name}`: the test link `{t}` does not resolve (T-10)"
            ));
        }
    }
    for k in &c.crates {
        if !(facts.crate_exists)(k) {
            out.push(format!("`{name}`: crate `{k}` does not exist (T-10)"));
        }
    }
    for table in &c.tables {
        let Some(label) = facts.tables.get(table) else {
            out.push(format!(
                "`{name}` owns `{table}`, a table no migration creates (T-10)"
            ));
            continue;
        };
        let part = c.label.as_str();
        let normative = NORMATIVE.contains(&label.as_str());
        let advisory = ADVISORY.contains(&label.as_str());
        let fits = !LABELS.contains(&part)
            || (normative && label.as_str() == part)
            || (advisory && ADVISORY.contains(&part))
            || (!normative && !advisory);
        if !fits {
            out.push(format!(
                "`{name}` is {part} and owns the {label} table `{table}`; derived and operational parts never own canonical data, and canonical data belongs to a part of its own label (T-10, T-11)"
            ));
        }
    }
}

/// Registry problems against `facts` (T-10, T-11, T-75).
pub(crate) fn registry_violations(components: &[Component], facts: &Facts<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut names: BTreeMap<&str, usize> = BTreeMap::new();
    let mut owners: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for c in components {
        let n = names.entry(c.name.as_str()).or_default();
        *n = n.saturating_add(1);
        for t in &c.tables {
            owners.entry(t.as_str()).or_default().push(c.name.as_str());
        }
        part_violations(c, facts, &mut out);
    }
    for (name, n) in names.iter().filter(|(_, n)| **n > 1) {
        out.push(format!("`{name}` is registered {n} times (T-10)"));
    }
    for row in facts.rows {
        let registered = components
            .iter()
            .any(|c| c.name.split('/').next() == Some(*row));
        if !registered {
            out.push(format!("§17.5 component `{row}` has no label (T-10)"));
        }
    }
    for component in COMPONENTS {
        let path = format!("crates/{component}");
        if !components.iter().any(|c| c.crates.contains(&path)) {
            out.push(format!(
                "component crate `{path}` is in no registered component (T-10)"
            ));
        }
    }
    for table in facts.tables.keys() {
        match owners.get(table.as_str()).map(Vec::as_slice) {
            None | Some([]) => out.push(format!(
                "table `{table}` belongs to no registered component (T-10, T-75)"
            )),
            Some([_]) => {}
            Some(many) => out.push(format!(
                "table `{table}` belongs to {} components (T-10)",
                many.join(", ")
            )),
        }
    }
    out
}

fn schema_labels(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut schema = Schema::default();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if is_migration(&rel_path) {
            schema.apply(&rel_path, &read(&path)?);
        }
    }
    Ok(schema
        .labels()
        .map(|(k, l)| (k.to_owned(), l.to_owned()))
        .collect())
}

fn committed(root: &Path) -> Result<Vec<String>, String> {
    let components = parse(&read(&root.join(REGISTRY_FILE))?)?;
    let tables = schema_labels(root)?;
    let crate_exists = |k: &str| root.join(k).join("Cargo.toml").is_file();
    let test_exists = |t: &str| crate::catalog::scan::link_exists(root, t);
    let facts = Facts {
        rows: ROWS,
        tables: &tables,
        crate_exists: &crate_exists,
        test_exists: &test_exists,
    };
    Ok(registry_violations(&components, &facts))
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(committed(root)?
        .into_iter()
        .map(|message| Violation {
            rule: RULE,
            path: PathBuf::from(REGISTRY_FILE),
            message,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROWS_UNDER_TEST: &[&str] = &["store", "views"];

    const GOOD: &str = r#"
[[component]]
name = "store/log"
label = "CANONICAL"
crates = ["crates/reconciler", "crates/timers", "crates/views", "crates/query", "crates/dispatch"]
tables = ["ledger.log", "work.body_dek"]
never = "only the sequencer writes the log"
enforced_by = ["store::t_1"]

[[component]]
name = "store/sync"
label = "SYNC-DERIVED"
crates = ["crates/federation", "crates/agents", "crates/live", "crates/export"]
tables = ["ledger.head"]
never = ""

[[component]]
name = "views"
label = "DERIVED"
tables = ["derived.timer_v1", "derived.consumer_cursor"]
never = "is never a normative transition input"
open = "not written"
"#;

    fn tables() -> BTreeMap<String, String> {
        [
            ("ledger.log", "CANONICAL"),
            ("work.body_dek", "OPERATIONAL"),
            ("ledger.head", "SYNC-DERIVED"),
            ("derived.timer_v1", "DERIVED"),
            ("derived.consumer_cursor", "OPERATIONAL"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    fn lint(text: &str, tables: &BTreeMap<String, String>) -> Vec<String> {
        let components = parse(text).unwrap();
        let crate_exists = |k: &str| k.starts_with("crates/");
        let test_exists = |t: &str| t == "store::t_1";
        let facts = Facts {
            rows: ROWS_UNDER_TEST,
            tables,
            crate_exists: &crate_exists,
            test_exists: &test_exists,
        };
        registry_violations(&components, &facts)
    }

    fn swap(text: &str, from: &str, to: &str) -> String {
        assert!(text.contains(from), "{from}");
        text.replace(from, to)
    }

    // T-10
    #[test]
    fn t_10_every_component_carries_exactly_one_label_and_its_never_rule() {
        let found = lint(GOOD, &tables());
        assert!(found.is_empty(), "{found:?}");
        let changes = [
            ("label = \"DERIVED\"", "label = \"DERIVED + PROJECTION\""),
            ("open = \"not written\"\n", ""),
            ("never = \"\"", "never = \"\"\nopen = \"x\""),
            (
                "enforced_by = [\"store::t_1\"]",
                "enforced_by = [\"store::t_2\"]",
            ),
            ("name = \"store/sync\"", "name = \"cache/sync\""),
            ("name = \"store/sync\"", "name = \"store/log\""),
            ("crates = [\"crates/federation\", ", "crates = ["),
            ("\"crates/views\", ", "\"bins/views\", \"crates/views\", "),
        ];
        for (from, to) in changes {
            let text = swap(GOOD, from, to);
            let found = lint(&text, &tables());
            assert_eq!(found.len(), 1, "{text}\n{found:?}");
        }
        assert!(parse("[[component]]\nname = \"a\"\n").is_err());
    }

    // T-10 T-11 T-75
    #[test]
    fn t_10_derived_projection_and_operational_components_own_no_canonical_table() {
        let moved = swap(GOOD, "tables = [\"ledger.head\"]\n", "");
        let to_views = swap(
            &moved,
            "tables = [\"derived.timer_v1\", ",
            "tables = [\"ledger.head\", \"derived.timer_v1\", ",
        );
        assert_eq!(lint(&to_views, &tables()).len(), 1);
        let operational = swap(GOOD, "label = \"DERIVED\"", "label = \"OPERATIONAL\"");
        assert_eq!(lint(&operational, &tables()).len(), 1);
        let canonical_timer = swap(
            GOOD,
            "tables = [\"ledger.log\", \"work.body_dek\"]",
            "tables = [\"ledger.log\", \"work.body_dek\", \"derived.timer_v1\"]",
        );
        let found = lint(&canonical_timer, &tables());
        assert_eq!(found.len(), 2, "{found:?}");
        let mut relabelled = tables();
        relabelled.insert("ledger.head".to_owned(), "CANONICAL".to_owned());
        assert_eq!(lint(GOOD, &relabelled).len(), 1);
    }

    // T-10 T-75
    #[test]
    fn t_10_every_table_belongs_to_exactly_one_component() {
        let mut more = tables();
        more.insert("work.item_head".to_owned(), "SYNC-DERIVED".to_owned());
        assert_eq!(lint(GOOD, &more).len(), 1);
        let unknown = swap(
            GOOD,
            "[\"ledger.head\"]",
            "[\"ledger.head\", \"work.gone\"]",
        );
        assert_eq!(lint(&unknown, &tables()).len(), 1);
    }

    // T-10 T-11 T-75
    #[test]
    fn t_10_the_committed_registry_labels_every_component_and_table() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let found = committed(root).unwrap();
        assert!(found.is_empty(), "{found:?}");
        assert!(!schema_labels(root).unwrap().is_empty());
    }
}
