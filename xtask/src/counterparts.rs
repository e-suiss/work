//! `cargo xtask spec-counterparts` (T-50, E-40): digests every Access and Relay
//! clause the E-40 table names and compares them with the local record
//! `docs/spec/.counterparts.toml`; changed, removed, missing and unrecorded
//! clauses are listed. The specs are local and untracked, so this runs where
//! they are, not in CI.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::sha256::hex_digest;

const WORK_FILE: &str = "docs/spec/07-ecosystem-boundaries.md";
const RECORD_FILE: &str = "docs/spec/.counterparts.toml";
const SECTION: &str = "7.10";

/// A counterpart clause: product and reference (`E7`, `MD-2`, `§7.9.5.3`).
pub(crate) type Clause = (String, String);

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    #[serde(default)]
    clause: Vec<RecordRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordRow {
    product: String,
    #[serde(rename = "ref")]
    reference: String,
    sha256: String,
}

/// The comparison result.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) changed: Vec<Clause>,
    pub(crate) removed: Vec<Clause>,
    pub(crate) missing: Vec<Clause>,
    pub(crate) unrecorded: Vec<Clause>,
    pub(crate) stale: Vec<Clause>,
    pub(crate) digests: BTreeMap<Clause, String>,
}

impl Report {
    fn clean(&self) -> bool {
        self.changed.is_empty()
            && self.removed.is_empty()
            && self.missing.is_empty()
            && self.unrecorded.is_empty()
            && self.stale.is_empty()
    }
}

fn heading(line: &str) -> Option<(usize, &str)> {
    let level = line.chars().take_while(|c| *c == '#').count();
    if level == 0 {
        return None;
    }
    let rest = line.get(level..)?.strip_prefix(' ')?;
    Some((level, rest.trim()))
}

fn cells(line: &str) -> Vec<String> {
    let t = line.trim();
    if !t.starts_with('|') {
        return Vec::new();
    }
    t.trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(|c| c.trim().to_owned())
        .collect()
}

/// The counterpart clauses of the E-40 table in Work §7.10.
pub(crate) fn e40_clauses(work_md: &str) -> Vec<Clause> {
    let mut inside = false;
    let mut out: Vec<Clause> = Vec::new();
    for line in work_md.lines() {
        if let Some((level, title)) = heading(line) {
            if inside && level <= 3 {
                break;
            }
            inside = title.split_whitespace().next() == Some(SECTION);
            continue;
        }
        if !inside {
            continue;
        }
        let row = cells(line);
        let Some(first) = row.first() else { continue };
        if first.starts_with("---") || first.starts_with("Karşı") {
            continue;
        }
        let mut product = String::new();
        for part in first.split(',') {
            let words: Vec<&str> = part.split_whitespace().collect();
            let reference = match words.as_slice() {
                [p, r] if matches!(*p, "Access" | "Relay") => {
                    (*p).clone_into(&mut product);
                    *r
                }
                [r] if !product.is_empty() => *r,
                _ => continue,
            };
            let clause = (product.clone(), reference.to_owned());
            if !out.contains(&clause) {
                out.push(clause);
            }
        }
    }
    out
}

fn defines(line: &str, id: &str) -> bool {
    let t = line.trim_start();
    let body = t.strip_prefix("- **").or_else(|| t.strip_prefix("**"));
    body.is_some_and(|b| {
        b.strip_prefix(id).is_some_and(|rest| {
            rest.chars()
                .next()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
        })
    })
}

fn row_defines(line: &str, id: &str) -> bool {
    cells(line)
        .first()
        .is_some_and(|c| c.trim_matches('*').trim() == id)
}

fn block_end(line: &str) -> bool {
    let t = line.trim_start();
    t.is_empty()
        || t.starts_with('#')
        || t.starts_with("- ")
        || t.starts_with('|')
        || t.starts_with("**")
}

/// The clause text for `reference` in one spec directory's files, or `None`.
pub(crate) fn clause_text(files: &[(String, String)], reference: &str) -> Option<String> {
    let mut pieces: Vec<String> = Vec::new();
    if let Some(number) = reference.strip_prefix('§') {
        for (_, text) in files {
            let lines: Vec<&str> = text.lines().collect();
            let Some(start) = lines.iter().position(|l| {
                heading(l).is_some_and(|(_, title)| {
                    title
                        .split_whitespace()
                        .next()
                        .map(|n| n.trim_end_matches('.'))
                        == Some(number)
                })
            }) else {
                continue;
            };
            let level = lines
                .get(start)
                .and_then(|l| heading(l))
                .map_or(0, |(lv, _)| lv);
            let mut block = Vec::new();
            for l in lines.iter().skip(start) {
                if !block.is_empty() && heading(l).is_some_and(|(lv, _)| lv <= level) {
                    break;
                }
                block.push(l.trim_end());
            }
            pieces.push(block.join("\n"));
        }
    } else {
        for (_, text) in files {
            let lines: Vec<&str> = text.lines().collect();
            let mut k = 0;
            while let Some(line) = lines.get(k) {
                if row_defines(line, reference) {
                    pieces.push(line.trim_end().to_owned());
                } else if defines(line, reference) {
                    let mut block = vec![line.trim_end()];
                    for next in lines.iter().skip(k.saturating_add(1)) {
                        if block_end(next) {
                            break;
                        }
                        block.push(next.trim_end());
                    }
                    k = k.saturating_add(block.len().saturating_sub(1));
                    pieces.push(block.join("\n"));
                }
                k = k.saturating_add(1);
            }
        }
    }
    (!pieces.is_empty()).then(|| pieces.join("\n"))
}

fn spec_files(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            std::fs::read_to_string(dir.join(&n))
                .map(|t| (n.clone(), t))
                .map_err(|e| format!("{n}: {e}"))
        })
        .collect()
}

/// Compares the E-40 clauses with the recorded digests.
pub(crate) fn compare(
    clauses: &[Clause],
    specs: &BTreeMap<String, Vec<(String, String)>>,
    recorded: &BTreeMap<Clause, String>,
) -> Report {
    let mut report = Report::default();
    for clause in clauses {
        let text = specs
            .get(&clause.0)
            .and_then(|files| clause_text(files, &clause.1));
        match (text, recorded.get(clause)) {
            (Some(t), old) => {
                let digest = hex_digest(t.as_bytes());
                match old {
                    Some(o) if *o != digest => report.changed.push(clause.clone()),
                    None => report.unrecorded.push(clause.clone()),
                    Some(_) => {}
                }
                report.digests.insert(clause.clone(), digest);
            }
            (None, Some(_)) => report.removed.push(clause.clone()),
            (None, None) => report.missing.push(clause.clone()),
        }
    }
    report.stale = recorded
        .keys()
        .filter(|k| !clauses.contains(k))
        .cloned()
        .collect();
    report
}

fn render_record(digests: &BTreeMap<Clause, String>) -> String {
    let mut out = String::new();
    for ((product, reference), digest) in digests {
        let _ = write!(
            out,
            "[[clause]]\nproduct = \"{product}\"\nref = \"{reference}\"\nsha256 = \"{digest}\"\n\n"
        );
    }
    out
}

fn load_record(path: &Path) -> Result<BTreeMap<Clause, String>, String> {
    let record: Record = match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Record::default(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    Ok(record
        .clause
        .into_iter()
        .map(|r| ((r.product, r.reference), r.sha256))
        .collect())
}

fn print_list(title: &str, items: &[Clause]) {
    if items.is_empty() {
        return;
    }
    println!("{title}:");
    for (product, reference) in items {
        println!("  {product} {reference}");
    }
}

/// Runs the comparison from the workspace root; `update` rewrites the record.
pub(crate) fn run(root: &Path, update: bool) -> Result<(), String> {
    let work = root.join(WORK_FILE);
    let parent = root
        .parent()
        .map_or_else(|| PathBuf::from(".."), Path::to_path_buf);
    let dirs = [
        ("Access", parent.join("access/docs/spec")),
        ("Relay", parent.join("relay/docs/spec")),
    ];
    if !work.is_file() || dirs.iter().any(|(_, d)| !d.is_dir()) {
        return Err(format!(
            "needs the local specs: {} and {} and {}; the specs are untracked, so this check runs on the machine that has them (T-50), not in CI",
            work.display(),
            dirs[0].1.display(),
            dirs[1].1.display()
        ));
    }
    let clauses =
        e40_clauses(&std::fs::read_to_string(&work).map_err(|e| format!("{WORK_FILE}: {e}"))?);
    let mut specs = BTreeMap::new();
    for (product, dir) in &dirs {
        specs.insert((*product).to_owned(), spec_files(dir)?);
    }
    let record_path = root.join(RECORD_FILE);
    let recorded = load_record(&record_path)?;
    let report = compare(&clauses, &specs, &recorded);
    println!("spec-counterparts: {} clauses in E-40", clauses.len());
    print_list(
        "changed (review the Work counterpart, then --update)",
        &report.changed,
    );
    print_list("removed from the counterpart spec", &report.removed);
    print_list("not found in the counterpart spec", &report.missing);
    print_list("not recorded yet", &report.unrecorded);
    print_list("recorded but no longer in E-40", &report.stale);
    if update {
        std::fs::write(&record_path, render_record(&report.digests))
            .map_err(|e| format!("{}: {e}", record_path.display()))?;
        println!(
            "spec-counterparts: recorded {} digests in {RECORD_FILE}",
            report.digests.len()
        );
        return Ok(());
    }
    if report.clean() {
        println!("spec-counterparts: all counterparts unchanged");
        Ok(())
    } else {
        Err("counterpart clauses differ from the record".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::files::TempDir;

    const WORK: &str = "### 7.10 Karşılıklar (E-40)\n\n| Karşı taraftaki madde | Rol | Work |\n|---|---|---|\n| Access E7, Access §7.9.5.3 | x | E-9 |\n| Relay MD-2 | y | E-18 |\n| Relay MD-3, Relay C-72 | z | E-20 |\n\n### 7.11 Register\n| Access E99 | not in E-40 | x |\n";

    const ACCESS: &str = "## 7 Ecosystem\n- **E7** Approval: one mechanism, two facts.\n- **E8** Work handoff.\n\n##### 7.9.5.3 Flow A\nGate then approval.\n##### 7.9.5.4 Flow B\nOther.\n";

    const RELAY: &str = "**MD-2 — Relay is not an approval source.**\n1. Delivery is not authority.\n\n**MD-20 — Replay guards.**\n| MD-2 | Relay is not an approval source | MK |\n| C-72 | Wait point | FÜ |\n";

    fn specs(access: &str, relay: &str) -> BTreeMap<String, Vec<(String, String)>> {
        let dir = TempDir::new("counterparts");
        dir.write("access/07.md", access);
        dir.write("relay/01.md", relay);
        BTreeMap::from([
            (
                "Access".to_owned(),
                spec_files(&dir.0.join("access")).unwrap(),
            ),
            (
                "Relay".to_owned(),
                spec_files(&dir.0.join("relay")).unwrap(),
            ),
        ])
    }

    // E-40 T-50
    #[test]
    fn t_50_e40_table_lists_every_counterpart_clause() {
        let clauses = e40_clauses(WORK);
        let refs: Vec<String> = clauses.iter().map(|(p, r)| format!("{p} {r}")).collect();
        assert_eq!(
            refs,
            [
                "Access E7",
                "Access §7.9.5.3",
                "Relay MD-2",
                "Relay MD-3",
                "Relay C-72"
            ]
        );
    }

    // E-40 T-50
    #[test]
    fn t_50_clause_text_covers_definitions_rows_and_sections() {
        let s = specs(ACCESS, RELAY);
        let relay = s.get("Relay").unwrap();
        let md2 = clause_text(relay, "MD-2").unwrap();
        assert!(md2.contains("Delivery is not authority"));
        assert!(md2.contains("| MD-2 |"));
        assert!(!md2.contains("Replay guards"));
        let access = s.get("Access").unwrap();
        let section = clause_text(access, "§7.9.5.3").unwrap();
        assert!(section.contains("Gate then approval"));
        assert!(!section.contains("Other"));
        assert_eq!(
            clause_text(access, "E7").unwrap(),
            "- **E7** Approval: one mechanism, two facts."
        );
        assert!(clause_text(relay, "MD-3").is_none());
    }

    // E-40 T-50
    #[test]
    fn t_50_changed_counterpart_is_reported() {
        let clauses = e40_clauses(WORK);
        let first = compare(&clauses, &specs(ACCESS, RELAY), &BTreeMap::new());
        assert_eq!(first.missing, [("Relay".to_owned(), "MD-3".to_owned())]);
        assert_eq!(first.unrecorded.len(), 4);
        let recorded = first.digests.clone();
        let same = compare(&clauses, &specs(ACCESS, RELAY), &recorded);
        assert!(same.changed.is_empty() && same.unrecorded.is_empty());
        let edited = ACCESS.replace("two facts", "three facts");
        let changed = compare(&clauses, &specs(&edited, RELAY), &recorded);
        assert_eq!(changed.changed, [("Access".to_owned(), "E7".to_owned())]);
        let dropped = RELAY.replace("| C-72 | Wait point | FÜ |\n", "");
        let removed = compare(&clauses, &specs(ACCESS, &dropped), &recorded);
        assert_eq!(removed.removed, [("Relay".to_owned(), "C-72".to_owned())]);
        let mut extra = recorded;
        extra.insert(("Access".to_owned(), "E99".to_owned()), "00".to_owned());
        let stale = compare(&clauses, &specs(ACCESS, RELAY), &extra);
        assert_eq!(stale.stale, [("Access".to_owned(), "E99".to_owned())]);
    }

    // T-50
    #[test]
    fn t_50_record_round_trips() {
        let digests = BTreeMap::from([(("Access".to_owned(), "E7".to_owned()), "ab".to_owned())]);
        let dir = TempDir::new("record");
        dir.write("r.toml", &render_record(&digests));
        assert_eq!(load_record(&dir.0.join("r.toml")).unwrap(), digests);
    }
}
