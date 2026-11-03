//! Reads the contract sources from the Rust text, since xtask depends on no workspace crate (T-31 rule 4): the event type table of `crates/proto/src/events.rs`, the action names of `crates/proto/src/action.rs` and the wire names of the kernel catalog; `event-catalog` (T-98 item 5) refuses a kernel wire name with neither an event type nor an `UNCATALOGUED` entry.

use std::collections::BTreeSet;
use std::path::Path;

use crate::Violation;
use crate::contracts::violation;

pub(crate) const EVENTS_RS: &str = "crates/proto/src/events.rs";
pub(crate) const ACTIONS_RS: &str = "crates/proto/src/action.rs";
pub(crate) const KERNEL_CATALOG_RS: &str = "crates/kernel/src/catalog.rs";

const RULE: &str = "event-catalog";

/// The kernel enums whose wire names are record subtypes.
const WIRE_ENUMS: &[&str] = &["DeclarationSubtype", "ClaimSubtype", "ActSubtype"];

/// One row of the event type table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Event {
    pub(crate) name: String,
    pub(crate) item: String,
    pub(crate) data: String,
    pub(crate) sources: Vec<String>,
}

/// The string literals of `text`, in order; escapes are not expected in the tables.
pub(crate) fn literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let after = rest.get(start.saturating_add(1)..).unwrap_or_default();
        let Some(end) = after.find('"') else {
            break;
        };
        out.push(after.get(..end).unwrap_or_default().to_owned());
        rest = after.get(end.saturating_add(1)..).unwrap_or_default();
    }
    out
}

fn path_word(text: &str, prefix: &str) -> Option<String> {
    let at = text.find(prefix)?;
    let word: String = text
        .get(at.saturating_add(prefix.len())..)?
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    (!word.is_empty()).then_some(word)
}

/// The text of the constant `name` up to its closing `];`.
fn constant<'a>(src: &'a str, name: &str) -> Result<&'a str, String> {
    let start = src
        .find(&format!("pub const {name}"))
        .ok_or_else(|| format!("{name} not found"))?;
    let body = src.get(start..).unwrap_or_default();
    let end = body
        .find("];")
        .ok_or_else(|| format!("{name} has no closing `];`"))?;
    Ok(body.get(..end).unwrap_or_default())
}

/// The event type table.
pub(crate) fn events(src: &str) -> Result<Vec<Event>, String> {
    let table = constant(src, "CATALOG")?;
    let mut out = Vec::new();
    for row in table.split("event(").skip(1) {
        let mut strings = literals(row).into_iter();
        let name = strings
            .next()
            .ok_or_else(|| format!("an event row has no name: {row}"))?;
        let item = path_word(row, "Item::").ok_or_else(|| format!("{name}: no Item"))?;
        let data = path_word(row, "Data::").ok_or_else(|| format!("{name}: no Data"))?;
        out.push(Event {
            name,
            item,
            data,
            sources: strings.collect(),
        });
    }
    if out.is_empty() {
        return Err("CATALOG has no event rows".to_owned());
    }
    Ok(out)
}

/// The wire names listed as waiting for an event type.
pub(crate) fn uncatalogued(src: &str) -> Result<Vec<String>, String> {
    Ok(literals(constant(src, "UNCATALOGUED")?))
}

/// The qualified action names, `work:<name>`, outside the test module.
pub(crate) fn actions(src: &str) -> BTreeSet<String> {
    let code = src.split("#[cfg(test)]").next().unwrap_or_default();
    literals(code)
        .into_iter()
        .filter(|s| {
            s.strip_prefix("work:").is_some_and(|n| {
                !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            })
        })
        .collect()
}

/// The wire names of the kernel's record subtype enums.
pub(crate) fn kernel_wires(src: &str) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    for name in WIRE_ENUMS {
        let open = format!("    {name} {{");
        let start = src
            .find(&open)
            .ok_or_else(|| format!("{name} not found in the kernel catalog"))?;
        let body = src
            .get(start.saturating_add(open.len())..)
            .unwrap_or_default();
        let end = body
            .find("\n    }")
            .ok_or_else(|| format!("{name} has no closing brace"))?;
        for line in body.get(..end).unwrap_or_default().lines() {
            if let Some((_, wire)) = line.split_once("=>") {
                out.extend(literals(wire));
            }
        }
    }
    Ok(out)
}

/// Problems of the event table against the kernel wire names.
pub(crate) fn catalog_problems(
    events: &[Event],
    waiting: &[String],
    wires: &BTreeSet<String>,
) -> Vec<String> {
    let typed: BTreeSet<&str> = events
        .iter()
        .flat_map(|e| e.sources.iter().map(String::as_str))
        .collect();
    let mut out = Vec::new();
    for wire in wires {
        let listed = waiting.contains(wire);
        match (typed.contains(wire.as_str()), listed) {
            (false, false) => out.push(format!(
                "kernel wire name `{wire}` has no event type; add one to CATALOG or, until the catalog approval, to UNCATALOGUED (T-98 item 5)"
            )),
            (true, true) => out.push(format!(
                "`{wire}` has an event type and is also UNCATALOGUED; remove it from UNCATALOGUED"
            )),
            _ => {}
        }
    }
    for source in typed.iter().filter(|s| !wires.contains(**s)) {
        out.push(format!("event source `{source}` is not a kernel wire name"));
    }
    for wire in waiting.iter().filter(|w| !wires.contains(*w)) {
        out.push(format!("UNCATALOGUED `{wire}` is not a kernel wire name"));
    }
    let mut seen = BTreeSet::new();
    for event in events {
        if !seen.insert(event.name.as_str()) {
            out.push(format!("event type `{}` repeats", event.name));
        }
        if event.name.split_once('.').map(|(item, _)| item)
            != Some(event.item.to_lowercase().as_str())
        {
            out.push(format!(
                "event type `{}` does not start with its item `{}` (T-98 item 4)",
                event.name, event.item
            ));
        }
    }
    out
}

/// `event-catalog` (T-98 item 5).
pub(crate) fn check_event_catalog(root: &Path) -> Result<Vec<Violation>, String> {
    let read =
        |rel: &str| std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: {e}"));
    let src = read(EVENTS_RS)?;
    let problems = catalog_problems(
        &events(&src)?,
        &uncatalogued(&src)?,
        &kernel_wires(&read(KERNEL_CATALOG_RS)?)?,
    );
    Ok(problems
        .into_iter()
        .map(|m| violation(RULE, EVENTS_RS, m))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENTS: &str = r#"
const fn event(name: &'static str) {}
pub const CATALOG: &[EventType] = &[
    event("work.opened", Item::Work, Data::Thin, &[]),
    event(
        "commitment.revoked",
        Item::Commitment,
        Data::Revoked,
        &["revoke_request", "revoke_promise"],
    ),
    event("gate.decided", Item::Gate, Data::Thin, &["gate_decision"]),
];

pub const UNCATALOGUED: &[&str] = &["allow"];
"#;

    const KERNEL: &str = r#"
wire_enum! {
    /// Docs.
    DeclarationSubtype {
        /// `revoke_request`.
        RevokeRequest => "revoke_request",
        RevokePromise => "revoke_promise",
        GateDecision => "gate_decision",
        Allow => "allow",
    }
}

wire_enum! {
    ClaimSubtype {
        Observation => "observation",
    }
}

wire_enum! {
    ActSubtype {
        Action => "action",
    }
}
"#;

    // T-98
    #[test]
    fn t_98_the_event_table_is_read_from_the_proto_source() {
        let events = events(EVENTS).unwrap();
        let names: Vec<&str> = events.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["work.opened", "commitment.revoked", "gate.decided"]);
        assert_eq!(events[1].item, "Commitment");
        assert_eq!(events[1].data, "Revoked");
        assert_eq!(events[1].sources, ["revoke_request", "revoke_promise"]);
        assert_eq!(uncatalogued(EVENTS).unwrap(), ["allow"]);
        let wires = kernel_wires(KERNEL).unwrap();
        assert_eq!(wires.len(), 6);
        assert!(wires.contains("observation") && wires.contains("action"));
    }

    // T-98
    #[test]
    fn t_98_a_wire_name_without_an_event_type_is_refused() {
        let events = events(EVENTS).unwrap();
        let wires = kernel_wires(KERNEL).unwrap();
        let problems = catalog_problems(&events, &["allow".to_owned()], &wires);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("`observation`")));
        assert!(problems.iter().any(|p| p.contains("`action`")));
        let problems = catalog_problems(&events, &[], &wires);
        assert!(problems.iter().any(|p| p.contains("`allow`")));
        let problems = catalog_problems(&events, &["allow".into(), "gate_decision".into()], &wires);
        assert!(problems.iter().any(|p| p.contains("also UNCATALOGUED")));
        let mut wrong = events.clone();
        wrong[0].item = "Ledger".to_owned();
        assert!(
            catalog_problems(&wrong, &["allow".into()], &wires)
                .iter()
                .any(|p| p.contains("does not start with its item"))
        );
    }

    // T-98
    #[test]
    fn t_98_the_committed_tables_agree() {
        let root = crate::workspace_root();
        assert!(check_event_catalog(&root).unwrap().is_empty());
        let actions = actions(&std::fs::read_to_string(root.join(ACTIONS_RS)).unwrap());
        assert_eq!(actions.len(), 23);
        assert!(actions.contains("work:version_activate"));
    }
}
