//! Source-level rules: kernel and domain purity (T-4, T-31 rule 5, T-32 rule 1),
//! SQL only in `store` (T-36 rule 2), no physical delete (T-36 rule 4, OP-12),
//! tracked TODOs (T-33 rule 8, T-53) and the `unsafe` allowlist (T-33 rule 3).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::comments::hash_comment;
use crate::rules::files::{is_test_file, read, read_optional, rel, walk};
use crate::rules::lex::{Lexed, find_token, in_regions, lex, line_at, test_regions};
use crate::supply_chain::metadata::{DepKind, Metadata};

fn violation(rule: &'static str, path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{path}:{line}")),
        message,
    }
}

fn rust_files(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    Ok(walk(root)?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| (rel(root, &p), p))
        .collect())
}

/// Files whose pattern tables and tests spell out the text they forbid.
const RULE_DEFINITION_FILES: &[&str] = &[
    "xtask/src/rules_source.rs",
    "xtask/src/rules_switches.rs",
    "xtask/src/rules_comments.rs",
];

/// True for rule definitions: the files above and Semgrep rule test fixtures.
pub(crate) fn is_rule_definition(rel_path: &str) -> bool {
    RULE_DEFINITION_FILES.contains(&rel_path) || rel_path.starts_with(".semgrep/")
}

const PURITY: &str = "kernel-purity";

/// Pure code: the kernel and the `domain` layer of every crate; `*` is one segment.
pub(crate) const PURE_PATHS: &[&str] = &[
    "crates/kernel/src/",
    "crates/*/src/domain/",
    "crates/*/src/domain.rs",
];

const IMPURE_PATTERNS: &[&str] = &[
    "async fn",
    "async move",
    ".await",
    "tokio::",
    "sqlx::",
    "reqwest::",
    "hyper::",
    "mio::",
    "std::fs",
    "std::net",
    "std::io",
    "std::env",
    "std::process",
    "std::thread",
    "std::time",
    "SystemTime",
    "Instant::now",
    "rand::",
    "getrandom",
    "extern crate std",
];

const KERNEL_ONLY_PATTERNS: &[&str] = &["std::", "no_mangle", "#[link"];

const IMPURE_CRATES: &[&str] = &[
    "tokio",
    "async-std",
    "sqlx",
    "tokio-postgres",
    "postgres",
    "reqwest",
    "hyper",
    "mio",
    "socket2",
    "rand",
    "rand_core",
    "getrandom",
];

/// True if `rel_path` is pure code.
pub(crate) fn is_pure_path(rel_path: &str) -> bool {
    PURE_PATHS
        .iter()
        .any(|pattern| glob_prefix(pattern, rel_path))
}

fn glob_prefix(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    let dir_pattern = pattern.ends_with('/');
    if segs.len() < pat.len() || (!dir_pattern && segs.len() != pat.len()) {
        return false;
    }
    pat.iter().zip(&segs).all(|(p, s)| *p == "*" || p == s)
}

/// Purity violations in one file's non-test code.
pub(crate) fn purity_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let kernel = rel_path.starts_with("crates/kernel/");
    let raw_externs: Vec<usize> = find_token(&lexed.code, "extern")
        .into_iter()
        .filter(|&at| {
            let rest = lexed.code.get(at.saturating_add(6)..).unwrap_or_default();
            let next = rest.trim_start();
            !next.starts_with("crate") || next.starts_with("crate std")
        })
        .collect();
    let mut out = Vec::new();
    let mut push = |at: usize, what: &str| {
        let line = line_at(&lexed.code, at);
        if !in_regions(&tests, line) {
            out.push(violation(
                PURITY,
                rel_path,
                line,
                format!("`{what}` in pure code; clock, RNG, I/O and FFI are ports (T-4, T-32)"),
            ));
        }
    };
    for pattern in IMPURE_PATTERNS {
        for at in find_token(&lexed.code, pattern) {
            push(at, pattern);
        }
    }
    if kernel {
        for pattern in KERNEL_ONLY_PATTERNS {
            for at in find_token(&lexed.code, pattern) {
                if *pattern == "std::"
                    && IMPURE_PATTERNS.iter().any(|p| {
                        p.starts_with("std::")
                            && lexed.code.get(at..).is_some_and(|s| s.starts_with(p))
                    })
                {
                    continue;
                }
                push(at, pattern);
            }
        }
        for at in raw_externs {
            push(at, "extern");
        }
    }
    out
}

/// The kernel root declares `no_std` and forbids `unsafe` (T-4).
pub(crate) fn kernel_root_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let code: String = lex(src).code.split_whitespace().collect();
    ["#![no_std]", "#![forbid(unsafe_code)]"]
        .iter()
        .filter(|attr| !code.contains(*attr))
        .map(|attr| {
            violation(
                PURITY,
                rel_path,
                1,
                format!("the kernel root must declare `{attr}` (T-4)"),
            )
        })
        .collect()
}

fn purity_deps(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        if rel(root, pkg.dir()) != "crates/kernel" {
            continue;
        }
        for dep in pkg.deps.iter().filter(|d| d.kind == DepKind::Normal) {
            if IMPURE_CRATES.contains(&dep.name.as_str()) {
                out.push(Violation {
                    rule: PURITY,
                    path: PathBuf::from("crates/kernel/Cargo.toml"),
                    message: format!("the kernel must not depend on `{}` (T-4)", dep.name),
                });
            }
        }
    }
    out
}

pub(crate) fn check_purity(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for (rel_path, path) in rust_files(root)? {
        if is_pure_path(&rel_path) && !is_test_file(&rel_path) {
            out.extend(purity_violations(&rel_path, &read(&path)?));
        }
    }
    match read_optional(&root.join("crates/kernel/src/lib.rs"))? {
        Some(text) => out.extend(kernel_root_violations("crates/kernel/src/lib.rs", &text)),
        None => out.push(violation(
            PURITY,
            "crates/kernel/src/lib.rs",
            0,
            "the kernel root is missing".to_owned(),
        )),
    }
    out.extend(purity_deps(
        root,
        &*crate::supply_chain::metadata::load(root)?,
    ));
    Ok(out)
}

const SQL: &str = "sql-only-in-store";

const STORE_DIR: &str = "crates/store/";

const SQL_TOKENS: &[&str] = &[
    "sqlx::",
    "tokio_postgres",
    "deadpool_postgres",
    "postgres::",
    "query!",
    "query_as!",
    "query_scalar!",
    "query_file!",
    "query_file_as!",
    "query_unchecked!",
];

const SQL_CRATES: &[&str] = &[
    "sqlx",
    "tokio-postgres",
    "postgres",
    "deadpool-postgres",
    "diesel",
    "sea-orm",
];

/// True if a string literal looks like an upper-case SQL statement.
pub(crate) fn looks_like_sql(s: &str) -> bool {
    let words: Vec<&str> = s
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    let has = |w: &str| words.contains(&w);
    let pair = |a: &str, b: &str| words.windows(2).any(|p| p == [a, b]);
    (has("SELECT") && has("FROM"))
        || pair("INSERT", "INTO")
        || (has("UPDATE") && has("SET"))
        || pair("DELETE", "FROM")
        || pair("CREATE", "TABLE")
        || pair("ALTER", "TABLE")
        || pair("DROP", "TABLE")
        || has("TRUNCATE")
}

/// SQL violations in one Rust file outside `store`.
pub(crate) fn sql_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let mut out = Vec::new();
    for token in SQL_TOKENS {
        for at in find_token(&lexed.code, token) {
            out.push(violation(
                SQL,
                rel_path,
                line_at(&lexed.code, at),
                format!("`{token}` outside crates/store (T-36 rule 2)"),
            ));
        }
    }
    for lit in lexed.strings.iter().filter(|l| looks_like_sql(&l.text)) {
        out.push(violation(
            SQL,
            rel_path,
            lit.line,
            "SQL statement outside crates/store (T-36 rule 2)".to_owned(),
        ));
    }
    out
}

pub(crate) fn check_sql(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if rel_path.starts_with(STORE_DIR) || is_rule_definition(&rel_path) {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("rs") => out.extend(sql_violations(&rel_path, &read(&path)?)),
            Some("sql") => out.push(violation(
                SQL,
                &rel_path,
                1,
                "SQL file outside crates/store (T-36 rule 2)".to_owned(),
            )),
            _ => {}
        }
    }
    let md = crate::supply_chain::metadata::load(root)?;
    out.extend(sql_crate_violations(root, &md));
    Ok(out)
}

fn sql_crate_violations(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        if rel(root, pkg.dir()) == STORE_DIR.trim_end_matches('/') {
            continue;
        }
        for dep in pkg.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            if SQL_CRATES.contains(&dep.name.as_str()) {
                out.push(Violation {
                    rule: SQL,
                    path: pkg
                        .manifest_path
                        .strip_prefix(root)
                        .unwrap_or(&pkg.manifest_path)
                        .to_path_buf(),
                    message: format!(
                        "only crates/store may depend on `{}` (T-36 rule 2)",
                        dep.name
                    ),
                });
            }
        }
    }
    out
}

const DELETE: &str = "no-physical-delete";

/// Reviewed tables that may be cleaned with `DELETE FROM` (job queue exception).
pub(crate) const DELETE_ALLOWLIST_FILE: &str = "xtask/physical-delete-allowlist.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteAllowlist {
    #[serde(default)]
    table: Vec<AllowedTable>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowedTable {
    name: String,
    reason: String,
}

/// Parses the allowlist; every entry needs a reason.
pub(crate) fn parse_allowlist(text: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let list: DeleteAllowlist =
        toml::from_str(text).map_err(|e| format!("{DELETE_ALLOWLIST_FILE}: {e}"))?;
    let mut names = Vec::new();
    let mut problems = Vec::new();
    for t in list.table {
        if t.reason.trim().is_empty() {
            problems.push(format!("`{}` has no reason", t.name));
        }
        names.push(t.name);
    }
    Ok((names, problems))
}

/// Physical-delete statements in SQL text, as (byte offset, message).
pub(crate) fn delete_findings(sql: &str, allow: &[String]) -> Vec<(usize, String)> {
    let upper = sql.to_ascii_uppercase();
    let mut words: Vec<(usize, &str)> = Vec::new();
    let mut start = None;
    for (i, c) in upper.char_indices() {
        let word_char = c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '"';
        match (word_char, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                words.push((s, upper.get(s..i).unwrap_or_default()));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        words.push((s, upper.get(s..).unwrap_or_default()));
    }
    let mut out = Vec::new();
    for (k, &(at, w)) in words.iter().enumerate() {
        let next = words.get(k.saturating_add(1)).map(|&(_, n)| n);
        match (w, next) {
            ("DELETE", Some("FROM")) => {
                let mut t = k.saturating_add(2);
                if words.get(t).is_some_and(|&(_, x)| x == "ONLY") {
                    t = t.saturating_add(1);
                }
                let table = words.get(t).map_or("", |&(_, x)| x);
                let bare = table.rsplit('.').next().unwrap_or(table).trim_matches('"');
                if !allow.iter().any(|a| a.eq_ignore_ascii_case(bare)) {
                    out.push((
                        at,
                        format!(
                            "`DELETE FROM {bare}`: rows are never deleted; use soft delete (T-36 rule 4, OP-12)"
                        ),
                    ));
                }
            }
            ("TRUNCATE", _) => out.push((
                at,
                "`TRUNCATE` is forbidden (T-36 rule 4, OP-12)".to_owned(),
            )),
            ("DROP", Some("TABLE")) => out.push((
                at,
                "`DROP TABLE` is forbidden; archive instead (T-36 rule 4, OP-12)".to_owned(),
            )),
            _ => {}
        }
    }
    out
}

fn strip_sql_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('-', Some('-')) => {
                for d in chars.by_ref() {
                    if d == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                let mut prev = ' ';
                for d in chars.by_ref() {
                    if d == '\n' {
                        out.push('\n');
                    }
                    if prev == '*' && d == '/' {
                        break;
                    }
                    prev = d;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn check_delete(root: &Path) -> Result<Vec<Violation>, String> {
    let (allow, problems) = match read_optional(&root.join(DELETE_ALLOWLIST_FILE))? {
        Some(text) => parse_allowlist(&text)?,
        None => (Vec::new(), Vec::new()),
    };
    let mut out: Vec<Violation> = problems
        .into_iter()
        .map(|m| violation(DELETE, DELETE_ALLOWLIST_FILE, 1, m))
        .collect();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        match path.extension().and_then(|e| e.to_str()) {
            Some("sql") => {
                let sql = strip_sql_comments(&read(&path)?);
                for (at, msg) in delete_findings(&sql, &allow) {
                    out.push(violation(DELETE, &rel_path, line_at(&sql, at), msg));
                }
            }
            Some("rs") if !is_test_file(&rel_path) && !is_rule_definition(&rel_path) => {
                let lexed = lex(&read(&path)?);
                let tests = test_regions(&lexed.code);
                for lit in lexed.strings.iter().filter(|l| !in_regions(&tests, l.line)) {
                    for (_, msg) in delete_findings(&lit.text, &allow) {
                        out.push(violation(DELETE, &rel_path, lit.line, msg));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

const TODO: &str = "todo-has-issue";

/// True if a comment's to-do has the `TODO(#n): text` form.
pub(crate) fn todo_is_tracked(comment: &str) -> bool {
    let body = comment
        .trim_start_matches(['/', '!', '*', '#'])
        .trim_start();
    let Some(rest) = body.strip_prefix("TODO(#") else {
        return false;
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let after = rest.get(digits.len()..).unwrap_or_default();
    !digits.is_empty()
        && after
            .strip_prefix("): ")
            .is_some_and(|text| !text.trim().is_empty())
}

/// Lines of to-do comments without the tracked form.
pub(crate) fn untracked_todos(comments: &[(usize, String)]) -> Vec<usize> {
    comments
        .iter()
        .filter(|(_, text)| !find_token(text, "TODO").is_empty() && !todo_is_tracked(text))
        .map(|(line, _)| *line)
        .collect()
}

fn hash_comments(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(i, l)| hash_comment(l).map(|(_, c)| (i.saturating_add(1), c.to_owned())))
        .collect()
}

pub(crate) fn check_todo(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if is_rule_definition(&rel_path) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let comments: Vec<(usize, String)> = match ext {
            "rs" => {
                let Lexed { comments, .. } = lex(&read(&path)?);
                comments.into_iter().map(|c| (c.line, c.text)).collect()
            }
            "toml" | "yml" | "yaml" | "sh" | "py" => hash_comments(&read(&path)?),
            _ if name == "justfile" || name.starts_with("Dockerfile") => {
                hash_comments(&read(&path)?)
            }
            _ => continue,
        };
        for line in untracked_todos(&comments) {
            out.push(violation(
                TODO,
                &rel_path,
                line,
                "TODO must read `TODO(#n): short text` (T-33 rule 8, T-53)".to_owned(),
            ));
        }
    }
    Ok(out)
}

const UNSAFE: &str = "unsafe-allowlist";

/// The only place `unsafe` may appear: generated FFI scaffolding (T-33 rule 3).
pub(crate) const UNSAFE_ALLOWED: &[&str] = &["sdks/bindings"];

/// An `unsafe` use: its line and whether a `// SAFETY:` comment justifies it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnsafeUse {
    pub(crate) line: usize,
    pub(crate) justified: bool,
}

/// Every `unsafe` keyword in a file and whether `// SAFETY:` (or a `# Safety` doc
/// section) is on its line or in the comment and attribute lines directly above.
pub(crate) fn unsafe_uses(src: &str) -> Vec<UnsafeUse> {
    let lexed = lex(src);
    let src_lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for at in find_token(&lexed.code, "unsafe") {
        let line = line_at(&lexed.code, at);
        let justified_line = |n: usize| {
            src_lines
                .get(n.saturating_sub(1))
                .is_some_and(|l| l.contains("SAFETY:") || l.contains("# Safety"))
        };
        let mut justified = justified_line(line);
        let mut n = line.saturating_sub(1);
        while !justified && n >= 1 {
            let trimmed = src_lines
                .get(n.saturating_sub(1))
                .map_or("", |l| l.trim_start());
            let continues = ["//", "#[", "#!", "*", "/*"]
                .iter()
                .any(|p| trimmed.starts_with(p));
            if !continues {
                break;
            }
            justified = justified_line(n);
            n = n.saturating_sub(1);
        }
        out.push(UnsafeUse { line, justified });
    }
    out
}

fn inherits_workspace_lints(manifest: &str) -> bool {
    manifest
        .parse::<toml::Table>()
        .ok()
        .and_then(|t| t.get("lints")?.get("workspace")?.as_bool())
        .unwrap_or(false)
}

fn workspace_forbids_unsafe(root_manifest: &str) -> bool {
    root_manifest
        .parse::<toml::Table>()
        .ok()
        .and_then(|t| {
            let v = t
                .get("workspace")?
                .get("lints")?
                .get("rust")?
                .get("unsafe_code")?;
            v.as_str()
                .or_else(|| v.get("level").and_then(toml::Value::as_str))
                .map(|s| s == "forbid")
        })
        .unwrap_or(false)
}

fn in_allowlist(rel_path: &str) -> bool {
    UNSAFE_ALLOWED
        .iter()
        .any(|d| rel_path == *d || rel_path.starts_with(&format!("{d}/")))
}

/// `unsafe` findings in one Rust file.
pub(crate) fn unsafe_file_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let allowed = in_allowlist(rel_path);
    let mut out = Vec::new();
    for u in unsafe_uses(src) {
        if !allowed {
            out.push(violation(
                UNSAFE,
                rel_path,
                u.line,
                "`unsafe` outside sdks/bindings (T-33 rule 3)".to_owned(),
            ));
        } else if !u.justified {
            out.push(violation(
                UNSAFE,
                rel_path,
                u.line,
                "`unsafe` without a preceding `// SAFETY:` comment (T-33 rule 3, T-53)".to_owned(),
            ));
        }
    }
    out
}

pub(crate) fn check_unsafe(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let ws_forbids = workspace_forbids_unsafe(&read(&root.join("Cargo.toml"))?);
    if !ws_forbids {
        out.push(violation(
            UNSAFE,
            "Cargo.toml",
            1,
            "[workspace.lints.rust] must set unsafe_code = \"forbid\" (T-33 rule 3)".to_owned(),
        ));
    }
    let md = crate::supply_chain::metadata::load(root)?;
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        if in_allowlist(&dir) {
            continue;
        }
        let manifest_ok = ws_forbids && inherits_workspace_lints(&read(&pkg.manifest_path)?);
        let mut roots_ok = !pkg.crate_roots.is_empty();
        for root_file in &pkg.crate_roots {
            let code: String = lex(&read(root_file)?).code.split_whitespace().collect();
            roots_ok &= code.contains("#![forbid(unsafe_code)]");
        }
        if !manifest_ok && !roots_ok {
            out.push(violation(
                UNSAFE,
                &format!("{dir}/Cargo.toml"),
                1,
                "crate must forbid unsafe: `[lints] workspace = true` or `#![forbid(unsafe_code)]` (T-33 rule 3)".to_owned(),
            ));
        }
    }
    for (rel_path, path) in rust_files(root)? {
        if is_rule_definition(&rel_path) {
            continue;
        }
        out.extend(unsafe_file_violations(&rel_path, &read(&path)?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-32 T-4
    #[test]
    fn t_32_kernel_and_domain_layers_are_pure_paths() {
        assert!(is_pure_path("crates/kernel/src/lib.rs"));
        assert!(is_pure_path("crates/reconciler/src/domain/diff.rs"));
        assert!(is_pure_path("crates/timers/src/domain.rs"));
        assert!(!is_pure_path("crates/timers/src/adapters/pg.rs"));
        assert!(!is_pure_path("crates/timers/src/app/domain.rs"));
    }

    // T-4 T-31
    #[test]
    fn t_4_clock_in_kernel_is_rejected() {
        let v = purity_violations(
            "crates/kernel/src/a.rs",
            "fn now() { let t = std::time::SystemTime::now(); }",
        );
        assert_eq!(v.len(), 2, "{v:?}");
    }

    // T-4 T-31
    #[test]
    fn t_4_std_and_ffi_in_kernel_are_rejected_but_alloc_is_not() {
        let v = purity_violations(
            "crates/kernel/src/a.rs",
            "extern crate alloc;\nuse std::collections::BTreeMap;\nextern \"C\" { fn f(); }\n#[unsafe(no_mangle)] fn g() {}\n",
        );
        assert_eq!(v.len(), 3, "{v:?}");
        let domain = purity_violations(
            "crates/views/src/domain.rs",
            "use std::collections::BTreeMap;\n",
        );
        assert!(domain.is_empty(), "{domain:?}");
    }

    // T-32
    #[test]
    fn t_32_async_and_tokio_in_domain_layer_are_rejected() {
        let v = purity_violations(
            "crates/query/src/domain/x.rs",
            "async fn f() { tokio::spawn(g()).await; }",
        );
        assert_eq!(v.len(), 3);
    }

    // T-32
    #[test]
    fn t_32_impure_words_in_comments_strings_and_tests_are_ignored() {
        let src = "// no std::fs here\nconst S: &str = \"rand::\";\n#[cfg(test)]\nmod tests { fn t() { std::fs::read(\"x\"); } }\n";
        assert!(purity_violations("crates/kernel/src/a.rs", src).is_empty());
    }

    // T-4
    #[test]
    fn t_4_kernel_root_without_no_std_is_rejected() {
        let v = kernel_root_violations("lib.rs", "#![forbid(unsafe_code)]\n");
        assert_eq!(v.len(), 1);
        assert!(
            kernel_root_violations("lib.rs", "#![no_std]\n#![forbid(unsafe_code)]\n").is_empty()
        );
    }

    // T-36
    #[test]
    fn t_36_sqlx_macro_outside_store_is_rejected() {
        let v = sql_violations(
            "crates/views/src/a.rs",
            "fn f() { sqlx::query!(\"SELECT 1 FROM t\"); }",
        );
        assert_eq!(v.len(), 3);
    }

    // T-36
    #[test]
    fn t_36_english_text_is_not_mistaken_for_sql() {
        assert!(!looks_like_sql("select a value from the list"));
        assert!(!looks_like_sql("update the settings"));
        assert!(looks_like_sql("UPDATE commitments SET state = $1"));
    }

    // T-36 OP-12
    #[test]
    fn t_36_physical_delete_statements_are_rejected() {
        let f = delete_findings(
            "DELETE FROM records WHERE id = 1; truncate x; drop table y;",
            &[],
        );
        assert_eq!(f.len(), 3);
    }

    // T-36 OP-12
    #[test]
    fn t_36_allowlisted_job_queue_table_needs_a_reason() {
        let (allow, problems) = parse_allowlist(
            "[[table]]\nname = \"jobs\"\nreason = \"identity-only job queue, result is in the ledger\"\n",
        )
        .unwrap();
        assert!(problems.is_empty());
        assert_eq!(
            delete_findings("DELETE FROM public.\"jobs\" WHERE done", &allow),
            vec![]
        );
        assert_eq!(delete_findings("DELETE FROM records", &allow).len(), 1);
        let (_, missing) = parse_allowlist("[[table]]\nname = \"jobs\"\nreason = \" \"\n").unwrap();
        assert_eq!(missing.len(), 1);
    }

    // T-36 OP-12
    #[test]
    fn t_36_sql_comments_do_not_count() {
        let sql = strip_sql_comments("-- DELETE FROM a\n/* TRUNCATE b */ SELECT 1;");
        assert_eq!(delete_findings(&sql, &[]), vec![]);
    }

    // T-33 T-53
    #[test]
    fn t_33_todo_without_issue_number_is_rejected() {
        let comments = vec![
            (1, "// TODO: fix later".to_owned()),
            (2, "// TODO(#42): fix later".to_owned()),
            (
                3,
                "// TODO see https://github.com/e-suiss/work/issues/7".to_owned(),
            ),
            (4, "# TODO(#7): pin the image".to_owned()),
            (5, "// TODO(#7)".to_owned()),
            (6, "// TODOS are not TODO-tagged words".to_owned()),
        ];
        assert_eq!(untracked_todos(&comments), vec![1, 3, 5, 6]);
    }

    // T-33
    #[test]
    fn t_33_unsafe_outside_bindings_is_rejected() {
        let src = "fn f() {\n    // SAFETY: g has no preconditions.\n    unsafe { g() };\n}\n";
        assert_eq!(
            unsafe_file_violations("crates/store/src/a.rs", src).len(),
            1
        );
        assert!(unsafe_file_violations("sdks/bindings/uniffi/src/a.rs", src).is_empty());
    }

    // T-33 T-53
    #[test]
    fn t_33_unsafe_in_bindings_needs_a_safety_comment() {
        let src = "fn f() {\n    let x = unsafe { g() };\n}\n";
        assert_eq!(
            unsafe_uses(src),
            vec![UnsafeUse {
                line: 2,
                justified: false
            }]
        );
        assert_eq!(
            unsafe_file_violations("sdks/bindings/wasm/src/a.rs", src).len(),
            1
        );
    }

    // T-33
    #[test]
    fn t_33_forbid_unsafe_attribute_is_not_an_unsafe_use() {
        assert_eq!(unsafe_uses("#![forbid(unsafe_code)]\n"), vec![]);
        assert!(inherits_workspace_lints("[lints]\nworkspace = true\n"));
        assert!(!inherits_workspace_lints(
            "[lints.rust]\nunsafe_code = \"allow\"\n"
        ));
        assert!(workspace_forbids_unsafe(
            "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n"
        ));
    }
}
