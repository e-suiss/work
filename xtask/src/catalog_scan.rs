//! Finds the rule IDs tests cite (T-47): the leading ID run of a test name and
//! bare ID comment lines directly above the test, in Rust tests that are part of
//! a crate's module tree and not ignored, TypeScript `*.test.*` and `*.spec.*`
//! files and Swift test harnesses. With `XTASK_NEXTEST=1`, Rust citations also
//! need a non-ignored test in `cargo nextest list`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::catalog::ids::{ids_in, is_bare_id_line, name_ids};
use crate::rules::files::{extension, rel};
use crate::rules::lex::{Lexed, SWIFT, TS, find_token, lex, lex_with, line_at};

/// Citations found in tests.
#[derive(Debug, Default)]
pub(crate) struct Scan {
    /// Known ID → `path::function` locations.
    pub(crate) found: BTreeMap<String, BTreeSet<String>>,
    /// (`path::function`, ID) pairs naming IDs that are not in the catalog.
    pub(crate) unknown: Vec<(String, String)>,
}

impl Scan {
    fn cite(&mut self, location: &str, ids: Vec<String>, known: &BTreeSet<String>) {
        for id in ids {
            if known.contains(&id) {
                self.found
                    .entry(id)
                    .or_default()
                    .insert(location.to_owned());
            } else if !self.unknown.iter().any(|(l, i)| l == location && *i == id) {
                self.unknown.push((location.to_owned(), id));
            }
        }
    }
}

/// A function declared in the code view: name and 1-based declaration line.
fn functions(code: &str, keyword: &str) -> Vec<(String, usize)> {
    let needle = format!("{keyword} ");
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let mut from = 0;
        while let Some(pos) = line.get(from..).and_then(|s| s.find(&needle)) {
            let at = from.saturating_add(pos);
            from = at.saturating_add(needle.len());
            let boundary = at == 0
                || line
                    .as_bytes()
                    .get(at.saturating_sub(1))
                    .is_some_and(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
            if !boundary {
                continue;
            }
            let name: String = line
                .get(from..)
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

fn is_ignore_attribute(line: &str) -> bool {
    let squeezed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    squeezed.starts_with("#[ignore")
}

/// Work IDs in the bare ID comment lines directly above line `decl`, walking up
/// over comments and attributes; with `attrs`, the attribute lines seen.
fn ids_above(raw: &[&str], decl: usize, attrs: &mut Vec<String>) -> Vec<String> {
    let mut ids = Vec::new();
    let mut k = decl.saturating_sub(1);
    while k >= 1 {
        let line = raw.get(k.saturating_sub(1)).map_or("", |l| l.trim());
        if line.is_empty() || line.ends_with(';') || line.ends_with('{') || line.ends_with('}') {
            break;
        }
        if let Some(body) = line.strip_prefix("//")
            && !body.starts_with('/')
            && !body.starts_with('!')
        {
            if is_bare_id_line(body.trim()) {
                ids.extend(
                    ids_in(body)
                        .into_iter()
                        .filter(|t| !t.foreign)
                        .map(|t| t.text),
                );
            }
        } else {
            attrs.push(line.to_owned());
        }
        k = k.saturating_sub(1);
    }
    ids
}

/// Citations in one Rust file; ignored tests do not count.
pub(crate) fn scan_source(path: &str, src: &str, known: &BTreeSet<String>, scan: &mut Scan) {
    let lexed = lex(src);
    let raw: Vec<&str> = src.lines().collect();
    for (name, decl) in functions(&lexed.code, "fn") {
        let mut attrs = Vec::new();
        let mut ids = name_ids(&name);
        ids.extend(ids_above(&raw, decl, &mut attrs));
        let header = raw.get(decl.saturating_sub(1)).copied().unwrap_or_default();
        let is_test = attrs.iter().any(|a| is_test_attribute(a)) || is_test_attribute(header);
        let ignored = attrs.iter().any(|a| is_ignore_attribute(a));
        if is_test && !ignored {
            scan.cite(&format!("{path}::{name}"), ids, known);
        }
    }
}

/// A TypeScript test call: its name, line and whether it is skipped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScriptTest {
    pub(crate) name: String,
    pub(crate) line: usize,
    pub(crate) skipped: bool,
}

const SCRIPT_CALLS: &[&str] = &["it", "test", "describe"];
const SKIPPED: &[&str] = &["skip", "todo", "fixme"];

/// Test calls (`it`, `test`, `describe`, with member chains such as `.each(…)`)
/// in a lexed TypeScript file and the string literal naming each.
pub(crate) fn script_tests(lexed: &Lexed) -> Vec<ScriptTest> {
    let code = &lexed.code;
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    for call in SCRIPT_CALLS {
        for at in find_token(code, call) {
            if at > 0 && bytes.get(at.saturating_sub(1)) == Some(&b'.') {
                continue;
            }
            let mut i = at.saturating_add(call.len());
            let mut skipped = false;
            loop {
                while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                    i = i.saturating_add(1);
                }
                match bytes.get(i) {
                    Some(b'.') => {
                        let member: String = code
                            .get(i.saturating_add(1)..)
                            .unwrap_or_default()
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        skipped |= SKIPPED.contains(&member.as_str());
                        i = i.saturating_add(1).saturating_add(member.len());
                    }
                    Some(b'(') => {
                        let first = lexed.strings.iter().find(|l| l.at > i).filter(|l| {
                            code.get(i.saturating_add(1)..l.at)
                                .is_some_and(|between| between.trim().is_empty())
                        });
                        if let Some(lit) = first {
                            out.push(ScriptTest {
                                name: lit.text.clone(),
                                line: line_at(code, at),
                                skipped,
                            });
                            break;
                        }
                        let mut depth = 0_usize;
                        while let Some(&b) = bytes.get(i) {
                            match b {
                                b'(' => depth = depth.saturating_add(1),
                                b')' => {
                                    depth = depth.saturating_sub(1);
                                    if depth == 0 {
                                        break;
                                    }
                                }
                                _ => {}
                            }
                            i = i.saturating_add(1);
                        }
                        i = i.saturating_add(1);
                    }
                    _ => break,
                }
            }
        }
    }
    out.sort_by_key(|t| t.line);
    out
}

/// True for TypeScript and JavaScript test files the scan reads.
pub(crate) fn is_script_test_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let script = [".ts", ".tsx", ".mts", ".js", ".mjs"]
        .iter()
        .any(|e| name.ends_with(e));
    script && (name.contains(".test.") || name.contains(".spec."))
}

/// True for Swift files in a `tests` directory.
pub(crate) fn is_swift_test_file(path: &str) -> bool {
    extension(path) == "swift" && path.split('/').any(|p| p == "tests")
}

/// Citations in one TypeScript test file; skipped tests do not count.
pub(crate) fn scan_script(path: &str, src: &str, known: &BTreeSet<String>, scan: &mut Scan) {
    let lexed = lex_with(src, &TS);
    let raw: Vec<&str> = src.lines().collect();
    for t in script_tests(&lexed) {
        if t.skipped {
            continue;
        }
        let first = t.name.split_whitespace().next().unwrap_or_default();
        let mut ids = name_ids(first);
        ids.extend(ids_above(&raw, t.line, &mut Vec::new()));
        scan.cite(&format!("{path}::{}", t.name), ids, known);
    }
}

/// Citations in one Swift test harness: every `func` the harness runs.
pub(crate) fn scan_swift(path: &str, src: &str, known: &BTreeSet<String>, scan: &mut Scan) {
    let lexed = lex_with(src, &SWIFT);
    let raw: Vec<&str> = src.lines().collect();
    for (name, decl) in functions(&lexed.code, "func") {
        let mut ids = name_ids(&name);
        ids.extend(ids_above(&raw, decl, &mut Vec::new()));
        scan.cite(&format!("{path}::{name}"), ids, known);
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
        } else {
            out.push(path);
        }
    }
}

/// The `#[path = "…"]` value attached to the `mod` at byte offset `at`.
fn path_attribute(lexed: &Lexed, at: usize) -> Option<String> {
    let before = lexed.code.get(..at)?;
    let start = before
        .rfind([';', '{', '}'])
        .map_or(0, |p| p.saturating_add(1));
    let attrs = before.get(start..)?;
    let rel_at = attrs.find("#[path")?;
    let attr_at = start.saturating_add(rel_at);
    lexed
        .strings
        .iter()
        .find(|l| l.at > attr_at && l.at < at)
        .map(|l| l.text.clone())
}

/// The files of a module tree: the crate root files and every file a `mod x;`
/// declaration reaches, following `#[path]` attributes and inline modules.
pub(crate) fn module_tree(roots: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<(PathBuf, PathBuf)> = roots
        .iter()
        .map(|r| {
            (
                r.clone(),
                r.parent().map(Path::to_path_buf).unwrap_or_default(),
            )
        })
        .collect();
    while let Some((file, child_dir)) = stack.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        let lexed = lex(&src);
        let file_dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let code = lexed.code.as_str();
        let mut inline: Vec<(usize, usize, String)> = Vec::new();
        for at in find_token(code, "mod") {
            let rest = code.get(at.saturating_add(3)..).unwrap_or_default();
            let name: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let after = rest
                .trim_start()
                .get(name.len()..)
                .unwrap_or_default()
                .trim_start();
            let prefix: PathBuf = inline
                .iter()
                .filter(|(s, e, _)| *s < at && at < *e)
                .map(|(_, _, n)| n.clone())
                .collect();
            if after.starts_with('{') {
                let open = code.len().saturating_sub(after.len());
                let mut depth = 0_usize;
                let mut end = code.len();
                for (k, c) in code.get(open..).unwrap_or_default().char_indices() {
                    match c {
                        '{' => depth = depth.saturating_add(1),
                        '}' => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                end = open.saturating_add(k);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                inline.push((open, end, name));
                continue;
            }
            if !after.starts_with(';') {
                continue;
            }
            if let Some(p) = path_attribute(&lexed, at) {
                let base = if prefix.as_os_str().is_empty() {
                    file_dir.clone()
                } else {
                    child_dir.join(&prefix)
                };
                let target = base.join(p);
                let dir = target.parent().map(Path::to_path_buf).unwrap_or_default();
                stack.push((target, dir));
                continue;
            }
            let dir = child_dir.join(&prefix);
            let flat = dir.join(format!("{name}.rs"));
            let nested = dir.join(&name).join("mod.rs");
            if nested.is_file() {
                stack.push((nested, dir.join(&name)));
            } else {
                stack.push((flat, dir.join(&name)));
            }
        }
    }
    seen
}

/// Non-ignored test names per package directory from `cargo nextest list`.
fn nextest_tests(root: &Path) -> Result<Vec<(PathBuf, BTreeSet<String>)>, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "nextest",
            "list",
            "--workspace",
            "--locked",
            "--message-format",
            "json",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo nextest list: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo nextest list failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_nextest(&String::from_utf8_lossy(&output.stdout))
}

/// Parses `cargo nextest list --message-format json`.
pub(crate) fn parse_nextest(json: &str) -> Result<Vec<(PathBuf, BTreeSet<String>)>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("cargo nextest list: {e}"))?;
    let mut out = Vec::new();
    for suite in v
        .get("rust-suites")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|m| m.values())
    {
        let cwd = suite
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let names: BTreeSet<String> = suite
            .get("testcases")
            .and_then(serde_json::Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(_, case)| {
                case.get("ignored").and_then(serde_json::Value::as_bool) != Some(true)
            })
            .map(|(name, _)| name.rsplit("::").next().unwrap_or(name).to_owned())
            .collect();
        out.push((PathBuf::from(cwd), names));
    }
    Ok(out)
}

/// Drops Rust locations that no non-ignored nextest test backs.
pub(crate) fn retain_listed(root: &Path, scan: &mut Scan, listed: &[(PathBuf, BTreeSet<String>)]) {
    let backed = |location: &str| {
        let Some((path, func)) = location.split_once("::") else {
            return true;
        };
        if extension(path) != "rs" {
            return true;
        }
        listed.iter().any(|(dir, names)| {
            let dir = rel(root, dir);
            (dir.is_empty() || path.starts_with(&format!("{dir}/"))) && names.contains(func)
        })
    };
    for locations in scan.found.values_mut() {
        locations.retain(|l| backed(l));
    }
    scan.found.retain(|_, l| !l.is_empty());
    scan.unknown.retain(|(l, _)| backed(l));
}

/// Citations across the tests under `roots`. Rust files outside the module
/// trees of the workspace targets are skipped.
pub(crate) fn scan(
    root: &Path,
    roots: &[String],
    known: &BTreeSet<String>,
) -> Result<Scan, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    let target_roots: Vec<PathBuf> = md
        .members()
        .flat_map(|p| p.target_roots.iter().cloned())
        .collect();
    let tree = module_tree(&target_roots);
    let mut files = Vec::new();
    for r in roots {
        walk(&root.join(r), &mut files);
    }
    files.sort();
    let mut result = Scan::default();
    for file in files {
        let rel_path = rel(root, &file);
        let rust = extension(&rel_path) == "rs" && tree.contains(&file);
        let script = is_script_test_file(&rel_path);
        let swift = is_swift_test_file(&rel_path);
        if !(rust || script || swift) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        if rust {
            scan_source(&rel_path, &src, known, &mut result);
        } else if script {
            scan_script(&rel_path, &src, known, &mut result);
        } else {
            scan_swift(&rel_path, &src, known, &mut result);
        }
    }
    if std::env::var("XTASK_NEXTEST").is_ok_and(|v| v == "1") {
        retain_listed(root, &mut result, &nextest_tests(root)?);
    }
    Ok(result)
}

/// Whether a catalog test link (`path::function` or `path::test name`) resolves.
pub(crate) fn link_exists(root: &Path, link: &str) -> bool {
    let (path, func) = link
        .split_once("::")
        .map_or((link, None), |(p, f)| (p, Some(f)));
    let Ok(src) = std::fs::read_to_string(root.join(path)) else {
        return false;
    };
    let Some(f) = func else { return true };
    if is_script_test_file(path) {
        script_tests(&lex_with(&src, &TS))
            .iter()
            .any(|t| t.name == f)
    } else if extension(path) == "swift" {
        functions(&lex_with(&src, &SWIFT).code, "func")
            .iter()
            .any(|(n, _)| n == f)
    } else {
        functions(&lex(&src).code, "fn").iter().any(|(n, _)| n == f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::files::TempDir;

    fn known(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    fn at(s: &Scan, id: &str) -> Vec<String> {
        s.found
            .get(id)
            .map(|l| l.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
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

    // T-37
    #[test]
    #[ignore = "slow"]
    fn t_37_ignored_tests_do_not_count() {}
}
"##;

    // T-47
    #[test]
    fn t_47_test_names_and_bare_id_lines_cite_rules() {
        let mut s = Scan::default();
        scan_source(
            "a.rs",
            SRC,
            &known(&["T-36", "OP-12", "T-47", "T-31", "INV-1", "T-37"]),
            &mut s,
        );
        assert_eq!(at(&s, "T-36"), ["a.rs::delete_is_rejected"]);
        assert_eq!(at(&s, "OP-12"), ["a.rs::delete_is_rejected"]);
        assert_eq!(
            at(&s, "T-47"),
            ["a.rs::t_47_unknown_rule_id_in_test_is_rejected_sample"]
        );
        assert_eq!(at(&s, "T-31"), ["a.rs::t_31_cites_an_unknown_id_above"]);
        assert!(at(&s, "INV-1").is_empty());
        assert!(at(&s, "T-37").is_empty());
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

    // T-47 T-37
    #[test]
    fn t_47_typescript_and_swift_tests_cite_rules() {
        let ts = "// T-5\ndescribe(\"t_5_t_37 kernel\", () => {\n  // T-34\n  it(\"rejects values\", async () => {});\n  it.each(cases)(\"t_44 $id\", (c) => {});\n  it.skip(\"t_31 skipped\", () => {});\n  test.describe(\"t_36 nested\", () => {});\n  const s = \"t_99 not a test\";\n});\n";
        let mut s = Scan::default();
        scan_script(
            "packages/k/src/a.test.ts",
            ts,
            &known(&["T-5", "T-37", "T-34", "T-44", "T-31", "T-36"]),
            &mut s,
        );
        assert_eq!(at(&s, "T-5"), ["packages/k/src/a.test.ts::t_5_t_37 kernel"]);
        assert_eq!(at(&s, "T-34"), ["packages/k/src/a.test.ts::rejects values"]);
        assert_eq!(at(&s, "T-44"), ["packages/k/src/a.test.ts::t_44 $id"]);
        assert_eq!(at(&s, "T-36"), ["packages/k/src/a.test.ts::t_36 nested"]);
        assert!(at(&s, "T-31").is_empty());
        let swift =
            "// T-5 T-37\nfunc t_5_t_37_swift_api(_ dir: URL) throws {}\nfunc helper() {}\n";
        let mut w = Scan::default();
        scan_swift(
            "sdks/b/tests/swift/main.swift",
            swift,
            &known(&["T-5", "T-37"]),
            &mut w,
        );
        assert_eq!(
            at(&w, "T-37"),
            ["sdks/b/tests/swift/main.swift::t_5_t_37_swift_api"]
        );
        assert!(is_script_test_file("packages/k/e2e/kernel.spec.ts"));
        assert!(!is_script_test_file("packages/k/src/index.ts"));
        assert!(is_swift_test_file("sdks/b/tests/swift/main.swift"));
    }

    // T-47 T-37
    #[test]
    fn t_47_orphan_files_outside_the_module_tree_are_not_scanned() {
        let dir = TempDir::new("modtree");
        dir.write(
            "src/lib.rs",
            "mod a;\n#[path = \"other_name.rs\"]\npub(crate) mod b;\nmod inline { mod deep; }\n",
        );
        dir.write("src/a.rs", "mod c;\n");
        dir.write("src/a/c.rs", "");
        dir.write("src/other_name.rs", "");
        dir.write("src/inline/deep.rs", "");
        dir.write("src/orphan.rs", "#[test] fn t_31_orphan() {}\n");
        dir.write("tests/it.rs", "mod support;\n");
        dir.write("tests/support/mod.rs", "");
        let tree = module_tree(&[dir.0.join("src/lib.rs"), dir.0.join("tests/it.rs")]);
        let mut names: Vec<String> = tree.iter().map(|p| rel(&dir.0, p)).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "src/a.rs",
                "src/a/c.rs",
                "src/inline/deep.rs",
                "src/lib.rs",
                "src/other_name.rs",
                "tests/it.rs",
                "tests/support/mod.rs"
            ]
        );
    }

    // T-47 T-37
    #[test]
    fn t_47_nextest_listing_drops_ignored_and_unlisted_rust_tests() {
        let json = r#"{"rust-suites":{"k::records":{"cwd":"/ws/crates/kernel","testcases":{"t_31_a":{"ignored":false},"mod_x::t_31_b":{"ignored":true}}}}}"#;
        let listed = parse_nextest(json).unwrap();
        let mut s = Scan::default();
        s.cite(
            "crates/kernel/tests/records.rs::t_31_a",
            vec!["T-31".to_owned()],
            &known(&["T-31"]),
        );
        s.cite(
            "crates/kernel/tests/records.rs::t_31_b",
            vec!["T-31".to_owned()],
            &known(&["T-31"]),
        );
        s.cite(
            "packages/k/src/a.test.ts::t_31 c",
            vec!["T-31".to_owned()],
            &known(&["T-31"]),
        );
        retain_listed(Path::new("/ws"), &mut s, &listed);
        assert_eq!(
            at(&s, "T-31"),
            [
                "crates/kernel/tests/records.rs::t_31_a",
                "packages/k/src/a.test.ts::t_31 c"
            ]
        );
    }
}
