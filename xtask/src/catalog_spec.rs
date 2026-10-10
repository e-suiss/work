//! Reads the local, untracked Work spec (`docs/spec/*.md`) for `cargo xtask
//! catalog` (T-46): register rows, acceptance and guarantee cells, Ek B stage
//! boundaries and the sizes of the must-never list, guarantee matrix and threat
//! table.

use std::collections::BTreeMap;
use std::path::Path;

use crate::catalog::ids::{family, ids_in, work_ids_expanded};

/// One register row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecRule {
    pub(crate) id: String,
    pub(crate) status: String,
    pub(crate) class: Option<String>,
    pub(crate) acceptance: Option<String>,
    pub(crate) pd: Option<String>,
}

/// Everything `cargo xtask catalog` takes from the spec.
#[derive(Debug, Default)]
pub(crate) struct Spec {
    pub(crate) rules: Vec<SpecRule>,
    pub(crate) stages: BTreeMap<String, u8>,
    pub(crate) must_never: usize,
    /// (rule, classes per item) for SEC-31, SEC-32 and SEC-33.
    pub(crate) guarantees: Vec<(String, Vec<String>)>,
    pub(crate) threats: usize,
    /// Stage boundary IDs that have no register row.
    pub(crate) unknown_stage_ids: Vec<String>,
}

/// Table cells of a `| a | b |` row, trimmed; empty for other lines.
pub(crate) fn cells(text: &str) -> Vec<String> {
    let t = text.trim();
    if !t.starts_with('|') {
        return Vec::new();
    }
    t.trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(|c| c.trim().to_owned())
        .collect()
}

fn is_separator(row: &[String]) -> bool {
    row.iter()
        .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

/// Maps a register status to its slug, with the PD/EA qualifier text.
pub(crate) fn status_slug(cell: &str) -> Option<(&'static str, Vec<String>)> {
    let mut parts = cell.split('·').map(str::trim);
    let main = parts.next()?;
    let slug = match main {
        "KANONİK DEĞİŞMEZ" => "canonical-invariant",
        "MERKEZİ KARAR" => "central-decision",
        "FROZEN (ürün)" => "frozen-product",
        "FROZEN (teknik)" => "frozen-technical",
        "FROZEN (protokol)" => "frozen-protocol",
        "POLICY DEFAULT" => "policy-default",
        "ENGINEERING ASSUMPTION" => "engineering-assumption",
        "WATCH" => "watch",
        "KAPSAM DIŞI" => "out-of-scope",
        _ => return None,
    };
    Some((slug, parts.map(str::to_owned).collect()))
}

const UNSET_MARKERS: &[&str] = &["ölçümle", "özellik yapılırken"];

fn unset(text: &str) -> bool {
    UNSET_MARKERS.iter().any(|m| text.contains(m))
}

/// The PD/EA value state of a row: `set`, `unset`, or none when the row has no value.
pub(crate) fn pd_state(slug: &str, qualifiers: &[String], decision: &str) -> Option<String> {
    let valued = qualifiers
        .iter()
        .find(|q| q.starts_with("PD") || q.starts_with("POLICY DEFAULT") || q.starts_with("EA"));
    let state = match (slug, valued) {
        (_, Some(q)) => unset(q),
        ("policy-default" | "engineering-assumption", None) => unset(decision),
        _ => return None,
    };
    Some(if state { "unset" } else { "set" }.to_owned())
}

/// True when F-21 asks the row for an acceptance test.
pub(crate) fn needs_acceptance(id: &str, slug: &str) -> bool {
    matches!(slug, "frozen-technical" | "frozen-protocol")
        || (family(id) == Some("MKT") && slug != "watch")
}

#[derive(Default)]
struct Cells {
    filled: BTreeMap<String, bool>,
    class: BTreeMap<String, String>,
}

/// Acceptance-test and guarantee-class cells from every table that has them.
fn field_cells(md: &str, cells_out: &mut Cells) {
    let mut accept_col: Option<usize> = None;
    let mut class_col: Option<usize> = None;
    for line in md.lines() {
        let row = cells(line);
        if row.is_empty() {
            accept_col = None;
            class_col = None;
            continue;
        }
        if row.first().is_some_and(|c| c == "ID") {
            accept_col = row.iter().position(|c| c == "Kabul testi");
            class_col = row.iter().position(|c| c == "Garanti");
            continue;
        }
        if is_separator(&row) {
            continue;
        }
        let ids: Vec<String> = row
            .first()
            .map(|c| {
                ids_in(c)
                    .into_iter()
                    .filter(|t| !t.foreign)
                    .map(|t| t.text)
                    .collect()
            })
            .unwrap_or_default();
        if let Some(cell) = accept_col.and_then(|c| row.get(c)) {
            let filled = !cell.contains("doldurulacak");
            for id in &ids {
                let e = cells_out.filled.entry(id.clone()).or_insert(false);
                *e = *e || filled;
            }
        }
        if let Some(cell) = class_col.and_then(|c| row.get(c))
            && matches!(cell.as_str(), "BS" | "UDC" | "NG" | "PU")
        {
            for id in &ids {
                cells_out.class.insert(id.clone(), cell.clone());
            }
        }
    }
}

/// Register rows (`| ID | Karar | Statü | … |` tables) in one file.
fn register_rows(md: &str, out: &mut Vec<(String, String, String, String)>) -> Result<(), String> {
    let mut in_register = false;
    for line in md.lines() {
        let row = cells(line);
        if row.is_empty() {
            in_register = false;
            continue;
        }
        if row.first().is_some_and(|c| c == "ID") {
            in_register = row.get(1).is_some_and(|c| c == "Karar")
                && row.get(2).is_some_and(|c| c == "Statü");
            continue;
        }
        if !in_register || is_separator(&row) {
            continue;
        }
        let id = row
            .first()
            .map(|c| c.trim_matches('*').trim().to_owned())
            .unwrap_or_default();
        if family(&id).is_none() {
            return Err(format!("register row `{id}` is not a Work ID"));
        }
        out.push((
            id,
            row.get(2).cloned().unwrap_or_default(),
            row.get(1).cloned().unwrap_or_default(),
            row.get(3).cloned().unwrap_or_default(),
        ));
    }
    Ok(())
}

/// Earliest Ek B stage citing each ID in a "Doğrulanacak sınırlar" bullet.
pub(crate) fn stages(md: &str) -> BTreeMap<String, u8> {
    let mut stage: Option<u8> = None;
    let mut boundaries = false;
    let mut out: BTreeMap<String, u8> = BTreeMap::new();
    for line in md.lines() {
        if let Some(h) = line.strip_prefix("### Aşama ") {
            stage = h.split_whitespace().next().and_then(|n| n.parse().ok());
            boundaries = false;
            continue;
        }
        if line.starts_with('#') {
            boundaries = line.trim_start_matches('#').trim() == "Doğrulanacak sınırlar";
            continue;
        }
        let (Some(s), true) = (stage, boundaries) else {
            continue;
        };
        let Some(rest) = line.trim_start().strip_prefix("- **") else {
            continue;
        };
        let bold = rest.split("**").next().unwrap_or_default();
        for id in work_ids_expanded(bold) {
            out.entry(id).and_modify(|v| *v = (*v).min(s)).or_insert(s);
        }
    }
    out
}

/// Data rows of the table under the heading whose number is `section`.
pub(crate) fn section_rows(md: &str, section: &str) -> Vec<Vec<String>> {
    let mut inside = false;
    let mut header_seen = false;
    let mut out = Vec::new();
    for line in md.lines() {
        if line.starts_with('#') {
            let title = line.trim_start_matches('#').trim();
            inside = title.split_whitespace().next() == Some(section);
            header_seen = false;
            continue;
        }
        if !inside {
            continue;
        }
        let row = cells(line);
        if row.is_empty() {
            if header_seen && !out.is_empty() {
                inside = false;
            }
            continue;
        }
        if !header_seen {
            header_seen = true;
            continue;
        }
        if !is_separator(&row) {
            out.push(row);
        }
    }
    out
}

fn read(dir: &Path, name: &str) -> Result<String, String> {
    std::fs::read_to_string(dir.join(name)).map_err(|e| format!("{name}: {e}"))
}

/// Parses the spec directory.
pub(crate) fn parse(dir: &Path) -> Result<Spec, String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        })
        .filter(|n| n != "19-decision-register.md" && n != "README.md")
        .collect();
    names.sort();
    let mut rows = Vec::new();
    let mut field = Cells::default();
    for name in &names {
        let text = read(dir, name)?;
        register_rows(&text, &mut rows).map_err(|e| format!("{name}: {e}"))?;
        field_cells(&text, &mut field);
    }
    let mut spec = Spec::default();
    let mut seen = std::collections::BTreeSet::new();
    for (id, status, decision, source) in rows {
        if !seen.insert(id.clone()) {
            continue;
        }
        let (slug, qualifiers) =
            status_slug(&status).ok_or_else(|| format!("{id}: unknown status `{status}`"))?;
        let acceptance = needs_acceptance(&id, slug).then(|| {
            let filled =
                field.filled.get(&id).copied().unwrap_or(false) && !source.contains("doldurulacak");
            if filled { "filled" } else { "to-fill" }.to_owned()
        });
        spec.rules.push(SpecRule {
            pd: pd_state(slug, &qualifiers, &decision),
            class: field.class.get(&id).cloned(),
            acceptance,
            status: slug.to_owned(),
            id,
        });
    }
    spec.stages = stages(&read(dir, "appendix-b-feature-inventory.md")?);
    spec.unknown_stage_ids = spec
        .stages
        .keys()
        .filter(|id| !seen.contains(*id))
        .cloned()
        .collect();
    spec.must_never = section_rows(&read(dir, "02-product-thesis.md")?, "2.10").len();
    let security = read(dir, "14-security.md")?;
    for (rule, section, fixed) in [
        ("SEC-31", "14.7.1", Some("BS")),
        ("SEC-32", "14.7.2", Some("UDC")),
        ("SEC-33", "14.7.3", None),
    ] {
        let classes = section_rows(&security, section)
            .iter()
            .map(|r| fixed.map_or_else(|| r.last().cloned().unwrap_or_default(), str::to_owned))
            .collect();
        spec.guarantees.push((rule.to_owned(), classes));
    }
    spec.threats = section_rows(&security, "14.2").len();
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-46
    #[test]
    fn t_46_status_slugs_and_qualifiers_are_read() {
        assert_eq!(
            status_slug("FROZEN (teknik) · PD (eşik, bekleme)").map(|s| s.0),
            Some("frozen-technical")
        );
        assert_eq!(
            status_slug("MERKEZİ KARAR · DAY-1").map(|s| s.0),
            Some("central-decision")
        );
        assert_eq!(status_slug("Belki"), None);
    }

    // F-27 OP-26
    #[test]
    fn f_27_op_26_values_to_be_measured_are_unset() {
        let q = |s: &str| vec![s.to_owned()];
        assert_eq!(
            pd_state(
                "frozen-technical",
                &q("PD (tarama aralığı, değer ölçümle)"),
                ""
            ),
            Some("unset".into())
        );
        assert_eq!(
            pd_state("frozen-technical", &q("PD (eşik, bekleme)"), ""),
            Some("set".into())
        );
        assert_eq!(
            pd_state("engineering-assumption", &[], "bütün değerler ölçümle"),
            Some("unset".into())
        );
        assert_eq!(
            pd_state("policy-default", &[], "Dört göz varsayılan açık"),
            Some("set".into())
        );
        assert_eq!(pd_state("central-decision", &q("DAY-1"), ""), None);
    }

    // F-21
    #[test]
    fn f_21_acceptance_cells_mark_rows_filled_or_to_fill() {
        let md = "| ID | Gerekçe | Kabul testi | Garanti |\n|---|---|---|---|\n| T-46 | x | `cargo xtask check catalog-format` | UDC |\n| T-50 | x | doldurulacak (test) | — |\n\n| ID | Kabul testi | Karşı örnek |\n|---|---|---|\n| T-50 | `t_50_changed_counterpart_is_reported` | x |\n| P-2, T-3 | `license` | x |\n";
        let mut c = Cells::default();
        field_cells(md, &mut c);
        assert_eq!(c.filled.get("T-46"), Some(&true));
        assert_eq!(c.filled.get("T-50"), Some(&true));
        assert_eq!(c.filled.get("T-3"), Some(&true));
        assert_eq!(c.class.get("T-46").map(String::as_str), Some("UDC"));
        assert!(!c.class.contains_key("T-50"));
        assert!(needs_acceptance("T-46", "frozen-technical"));
        assert!(needs_acceptance("MKT-1", "frozen-product"));
        assert!(!needs_acceptance("MKT-2", "watch"));
        assert!(!needs_acceptance("INV-2", "canonical-invariant"));
    }

    // T-46
    #[test]
    fn t_46_register_rows_come_only_from_register_tables() {
        let md = "| ID | Karar | Statü | Gerekçe/kaynak |\n|---|---|---|---|\n| T-1 | Rust | MERKEZİ KARAR | x |\n\n| ID | Bölüm | Karar | Statü |\n|---|---|---|---|\n| T-2 | §17 | y | WATCH |\n";
        let mut rows = Vec::new();
        register_rows(md, &mut rows).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "T-1");
    }

    // T-46 T-37
    #[test]
    fn t_46_stages_come_from_boundary_bullets() {
        let md = "### Aşama 0 — Temel\n#### Tedarik\n- [ ] **Item** — T-99 note\n#### Doğrulanacak sınırlar\n- **MD-15, F-9 #15, P-2** — lisans; T-98\n- **T-31 (madde 4), T-8** — yön\n### Aşama 1 — Kernel\n#### Doğrulanacak sınırlar\n- **INV-1…INV-3, T-31** — x\n";
        let s = stages(md);
        assert_eq!(s.get("MD-15"), Some(&0));
        assert_eq!(s.get("F-9"), Some(&0));
        assert_eq!(s.get("T-31"), Some(&0));
        assert_eq!(s.get("INV-2"), Some(&1));
        assert_eq!(s.get("T-99"), None);
        assert_eq!(s.get("T-98"), None);
    }

    // SEC-33 T-49
    #[test]
    fn sec_33_section_tables_are_counted() {
        let md = "#### 14.7.3 İddia edilmez\n\nText.\n\n| # | Work | Sınıf |\n|---|---|---|\n| 1 | a | PU |\n| 2 | b | NG |\n\n#### 14.7.4 Dil\n| x | y |\n|---|---|\n| 1 | 2 |\n";
        let rows = section_rows(md, "14.7.3");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].last().map(String::as_str), Some("NG"));
    }
}
