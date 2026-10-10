//! Finds the rule IDs Rust tests cite (T-47): the leading ID run of a test name
//! and bare ID comment lines directly above the test.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::catalog::ids::{ids_in, is_bare_id_line, name_ids};
use crate::rules::lex::lex;

/// Citations found in tests.
#[derive(Debug, Default)]
pub(crate) struct Scan {
    /// Known ID → `path::function` locations.
    pub(crate) found: BTreeMap<String, BTreeSet<String>>,
    /// (`path::function`, ID) pairs naming IDs that are not in the catalog.
    pub(crate) unknown: Vec<(String, String)>,
}

/// A function declared in the code view: name and 1-based declaration line.
fn functions(code: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let mut from = 0;
        while let Some(pos) = line.get(from..).and_then(|s| s.find("fn ")) {
            let at = from.saturating_add(pos);
            from = at.saturating_add(3);
            let boundary = at == 0
                || line
                    .as_bytes()
                    .get(at.saturating_sub(1))
                    .is_some_and(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
            if !boundary {
                continue;
            }
            let name: String = line
                .get(at.saturating_add(3)..)
                .unwrap_or_default()
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.push((name, n.saturating_add(1)));
            }
        }
    }
    out
}

fn is_test_attribute(line: &str) -> bool {
    let squeezed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    squeezed.starts_with("#[test")
        || squeezed.contains("::test]")
        || squeezed.contains("::test(")
        || squeezed.starts_with("#[rstest")
}

/// Citations in one Rust file.
pub(crate) fn scan_source(path: &str, src: &str, known: &BTreeSet<String>, scan: &mut Scan) {
    let lexed = lex(src);
    let raw: Vec<&str> = src.lines().collect();
    for (name, decl) in functions(&lexed.code) {
        let mut ids: Vec<String> = name_ids(&name);
        let mut is_test = false;
        let mut k = decl.saturating_sub(1);
        while k >= 1 {
            let line = raw.get(k.saturating_sub(1)).map_or("", |l| l.trim());
            if line.is_empty() || line.ends_with(';') || line.ends_with('{') || line.ends_with('}')
            {
                break;
            }
            if is_test_attribute(line) {
                is_test = true;
            }
            if let Some(body) = line.strip_prefix("//")
                && !body.starts_with('/')
                && !body.starts_with('!')
                && is_bare_id_line(body.trim())
            {
                ids.extend(
                    ids_in(body)
                        .into_iter()
                        .filter(|t| !t.foreign)
                        .map(|t| t.text),
                );
            }
            k = k.saturating_sub(1);
        }
        let header = raw.get(decl.saturating_sub(1)).copied().unwrap_or_default();
        if !is_test && !is_test_attribute(header) {
            continue;
        }
        let location = format!("{path}::{name}");
        for id in ids {
            if known.contains(&id) {
                scan.found.entry(id).or_default().insert(location.clone());
            } else if !scan.unknown.contains(&(location.clone(), id.clone())) {
                scan.unknown.push((location.clone(), id));
            }
        }
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == "node_modules" || name.to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Citations across all Rust files under `roots`.
pub(crate) fn scan(root: &Path, roots: &[String], known: &BTreeSet<String>) -> Scan {
    let mut files = Vec::new();
    for r in roots {
        walk(&root.join(r), &mut files);
    }
    files.sort();
    let mut result = Scan::default();
    for file in files {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        let rel = crate::rules::files::rel(root, &file);
        scan_source(&rel, &src, known, &mut result);
    }
    result
}

/// Whether a catalog test link (`path::function`) resolves.
pub(crate) fn link_exists(root: &Path, link: &str) -> bool {
    let (path, func) = link
        .split_once("::")
        .map_or((link, None), |(p, f)| (p, Some(f)));
    let Ok(src) = std::fs::read_to_string(root.join(path)) else {
        return false;
    };
    func.is_none_or(|f| functions(&lex(&src).code).iter().any(|(n, _)| n == f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    const SRC: &str = r##"
//! Module docs mention INV-1 outside a test.
fn helper() { let _ = "T-31 in a string"; }

#[cfg(test)]
mod tests {
    // T-36 OP-12
    #[test]
    fn delete_is_rejected() {
        let s = r#"fn t_99_in_a_string() {}"#;
    }

    #[test]
    fn t_47_unknown_rule_id_in_test_is_rejected_sample() {}

    // T-99
    #[test]
    fn t_31_cites_an_unknown_id_above() {}

    // Access OP-73
    #[test]
    fn foreign_ids_are_not_work_ids() {}

    fn t_31_helper_is_not_a_test() {}
}
"##;

    // T-47
    #[test]
    fn t_47_test_names_and_bare_id_lines_cite_rules() {
        let mut s = Scan::default();
        scan_source(
            "a.rs",
            SRC,
            &known(&["T-36", "OP-12", "T-47", "T-31", "INV-1"]),
            &mut s,
        );
        let at = |id: &str| {
            s.found
                .get(id)
                .map(|l| l.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        assert_eq!(at("T-36"), ["a.rs::delete_is_rejected"]);
        assert_eq!(at("OP-12"), ["a.rs::delete_is_rejected"]);
        assert_eq!(
            at("T-47"),
            ["a.rs::t_47_unknown_rule_id_in_test_is_rejected_sample"]
        );
        assert_eq!(at("T-31"), ["a.rs::t_31_cites_an_unknown_id_above"]);
        assert!(at("INV-1").is_empty());
    }

    // T-47
    #[test]
    fn t_47_unknown_rule_id_in_test_is_rejected() {
        let mut s = Scan::default();
        scan_source(
            "a.rs",
            SRC,
            &known(&["T-36", "OP-12", "T-47", "T-31"]),
            &mut s,
        );
        assert_eq!(
            s.unknown,
            [(
                "a.rs::t_31_cites_an_unknown_id_above".to_owned(),
                "T-99".to_owned()
            )]
        );
    }
}
