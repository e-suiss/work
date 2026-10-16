//! Periodic review list of WATCH rows (F-25, OQ-24, MKT-2…MKT-12, P-63, P-64).

use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use crate::rules::files::read;

const DECISIONS: &str = "conformance/catalog/decisions.toml";

#[derive(Debug, Deserialize)]
struct Decisions {
    rule: Vec<Row>,
}

#[derive(Debug, Deserialize)]
struct Row {
    id: String,
    status: String,
    #[serde(default)]
    title: String,
}

/// Markdown checklist of every WATCH row, for the scheduled review issue.
pub(crate) fn report(root: &Path) -> Result<String, String> {
    render(&read(&root.join(DECISIONS))?)
}

fn render(text: &str) -> Result<String, String> {
    let decisions: Decisions = toml::from_str(text).map_err(|e| format!("{DECISIONS}: {e}"))?;
    let mut out = String::from(
        "Review each WATCH row against current evidence. A counterexample drops a differentiation claim; it does not change the thesis. Record any change as a new decision ID.\n\n",
    );
    let mut count = 0_usize;
    for row in decisions.rule.iter().filter(|r| r.status == "watch") {
        let _ = writeln!(out, "- [ ] **{}** {}", row.id, row.title);
        count = count.saturating_add(1);
    }
    if count == 0 {
        return Err("no WATCH rows in the catalog".to_owned());
    }
    out.push_str("- [ ] Platform and standards churn (§4.5 table): vendor objects stay in adapters and References\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // F-25
    #[test]
    fn f_25_watch_rows_are_listed_for_review() {
        let text = "[[rule]]\nid = \"MKT-2\"\nfamily = \"MKT\"\nstatus = \"watch\"\ntitle = \"Durable identity\"\ntests = []\n\n[[rule]]\nid = \"T-1\"\nfamily = \"T\"\nstatus = \"central-decision\"\ntitle = \"Rust\"\ntests = []\n";
        let out = render(text).unwrap();
        assert!(out.contains("- [ ] **MKT-2** Durable identity"));
        assert!(!out.contains("T-1"));
    }

    #[test]
    fn f_25_a_catalog_without_watch_rows_is_an_error() {
        let text = "[[rule]]\nid = \"T-1\"\nfamily = \"T\"\nstatus = \"central-decision\"\ntitle = \"Rust\"\ntests = []\n";
        assert!(render(text).is_err());
    }
}
