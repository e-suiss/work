//! Source-level rules: kernel and domain purity (T-4, T-31 rule 5, T-32 rule 1),
//! SQL only in `store` (T-36 rule 2), no physical delete (T-36 rule 4, OP-12),
//! tracked TODOs (T-33 rule 8, T-53) and the `unsafe` allowlist (T-33 rule 3).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::comments::{comments_of, scanned_files};
use crate::rules::files::{is_test_file, read, read_optional, rel, walk};
use crate::rules::lex::{
    decoded, find_token, in_regions, lex, line_at, macro_literals, test_regions,
};
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
    "xtask/src/rules_derived.rs",
    "xtask/src/rules_migrations.rs",
    "xtask/src/rules_switches.rs",
    "xtask/src/rules_comments.rs",
    "xtask/src/policy_terms.rs",
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

/// Types whose iteration order depends on a random seed (T-4, T-6).
const UNORDERED: &[&str] = &["HashMap", "HashSet", "RandomState", "hashbrown"];

fn split_top(inner: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0;
    for (i, c) in inner.char_indices() {
        match c {
            '{' => depth = depth.saturating_add(1),
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(inner.get(start..i).unwrap_or_default());
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    parts.push(inner.get(start..).unwrap_or_default());
    parts.into_iter().filter(|p| !p.trim().is_empty()).collect()
}

/// Every path a `use` tree names: `std::{fs, io::{Read}}` → `std::fs`, `std::io::Read`.
pub(crate) fn expand_use(tree: &str) -> Vec<String> {
    let t: String = tree.split_whitespace().collect::<Vec<_>>().join(" ");
    let t = t.trim().trim_start_matches("::").trim();
    let Some(open) = t.find('{') else {
        return vec![t.to_owned()];
    };
    let prefix = t.get(..open).unwrap_or_default().trim();
    let inner = t
        .get(open.saturating_add(1)..)
        .unwrap_or_default()
        .trim_end()
        .strip_suffix('}')
        .unwrap_or_default();
    split_top(inner)
        .into_iter()
        .flat_map(expand_use)
        .map(|rest| format!("{prefix}{rest}"))
        .collect()
}

/// The `use` declarations of a code view: (byte offset, expanded paths).
fn use_paths(code: &str) -> Vec<(usize, Vec<String>)> {
    find_token(code, "use")
        .into_iter()
        .filter_map(|at| {
            let rest = code.get(at.saturating_add(3)..)?;
            let end = rest.find(';')?;
            Some((at, expand_use(rest.get(..end)?)))
        })
        .collect()
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
    let mut seen: Vec<(usize, String)> = Vec::new();
    let mut push = |at: usize, what: &str, why: &str| {
        let line = line_at(&lexed.code, at);
        let key = (line, what.to_owned());
        if !in_regions(&tests, line) && !seen.contains(&key) {
            seen.push(key);
            out.push(violation(
                PURITY,
                rel_path,
                line,
                format!("`{what}` in pure code; {why} (T-4, T-32)"),
            ));
        }
    };
    let ports = "clock, RNG, I/O and FFI are ports";
    for pattern in IMPURE_PATTERNS {
        for at in find_token(&lexed.code, pattern) {
            push(at, pattern, ports);
        }
    }
    for (at, paths) in use_paths(&lexed.code) {
        for path in paths {
            let impure = IMPURE_PATTERNS.iter().find(|p| {
                p.starts_with("std::") && (path == **p || path.starts_with(&format!("{p}::")))
            });
            if let Some(p) = impure {
                push(at, p, ports);
            }
            if path == "std" || path.starts_with("std as ") {
                push(
                    at,
                    "use std",
                    "std is not renamed or imported whole in pure code",
                );
            }
        }
    }
    for pattern in UNORDERED {
        for at in find_token(&lexed.code, pattern) {
            push(
                at,
                pattern,
                "iteration order must not depend on a random seed; use BTreeMap or BTreeSet",
            );
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
                push(at, pattern, ports);
            }
        }
        for at in raw_externs {
            push(at, "extern", ports);
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

const SQL_STARTS: &[&str] = &[
    "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "TRUNCATE", "WITH", "MERGE",
];

fn sql_shape(words: &[String]) -> bool {
    let has = |w: &str| words.iter().any(|x| x == w);
    let pair = |a: &str, b: &str| {
        words
            .windows(2)
            .any(|p| matches!(p, [x, y] if x == a && y == b))
    };
    (has("SELECT") && has("FROM"))
        || pair("INSERT", "INTO")
        || (has("UPDATE") && has("SET"))
        || pair("DELETE", "FROM")
        || pair("CREATE", "TABLE")
        || pair("ALTER", "TABLE")
        || pair("DROP", "TABLE")
        || pair("DROP", "SCHEMA")
        || has("TRUNCATE")
}

/// True if a string looks like a SQL statement: upper-case keywords anywhere, or
/// a statement of any case that starts with a SQL keyword.
pub(crate) fn looks_like_sql(s: &str) -> bool {
    let raw: Vec<&str> = s
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    let exact: Vec<String> = raw.iter().map(|w| (*w).to_owned()).collect();
    if sql_shape(&exact) {
        return true;
    }
    let upper: Vec<String> = raw.iter().map(|w| w.to_ascii_uppercase()).collect();
    let prose = upper.windows(2).any(|p| {
        matches!(p, [x, y] if matches!(x.as_str(), "FROM" | "INTO" | "TABLE" | "UPDATE")
            && DETERMINERS.contains(&y.as_str()))
    });
    !prose
        && upper
            .first()
            .is_some_and(|first| SQL_STARTS.contains(&first.as_str()))
        && sql_shape(&upper)
}

/// English words that follow `from` or `into` in prose, never a table name.
const DETERMINERS: &[&str] = &[
    "THE", "A", "AN", "THIS", "THAT", "THESE", "THOSE", "YOUR", "OUR", "MY", "ITS", "THEIR",
    "EACH", "EVERY", "ALL", "SOME", "ANY",
];

/// Macros whose string arguments are joined before the SQL and delete checks.
const JOINING_MACROS: &[&str] = &["concat!", "format!", "format_args!", "write!", "writeln!"];

/// Decoded string literals of a lexed file and the joined arguments of string
/// building macros, as (line, text).
fn literal_texts(lexed: &crate::rules::lex::Lexed) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> =
        lexed.strings.iter().map(|l| (l.line, decoded(l))).collect();
    out.extend(macro_literals(lexed, JOINING_MACROS));
    out
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
    let mut lines = Vec::new();
    for (line, text) in literal_texts(&lexed) {
        if looks_like_sql(&text) && !lines.contains(&line) {
            lines.push(line);
            out.push(violation(
                SQL,
                rel_path,
                line,
                "SQL statement outside crates/store (T-36 rule 2)".to_owned(),
            ));
        }
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
    #[serde(default)]
    drop: Vec<AllowedDrop>,
}

/// A reviewed SQL function whose body may run `DROP TABLE` (archive path, OP-12 rule 4).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AllowedDrop {
    pub(crate) file: String,
    pub(crate) function: String,
    pub(crate) id: String,
    pub(crate) reason: String,
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

/// Parses the reviewed `DROP TABLE` functions; every entry needs a spec ID and a reason.
pub(crate) fn parse_drops(text: &str) -> Result<(Vec<AllowedDrop>, Vec<String>), String> {
    let list: DeleteAllowlist =
        toml::from_str(text).map_err(|e| format!("{DELETE_ALLOWLIST_FILE}: {e}"))?;
    let problems = list
        .drop
        .iter()
        .filter(|d| d.reason.trim().is_empty() || d.id.trim().is_empty())
        .map(|d| format!("`{}` needs an id and a reason", d.function))
        .collect();
    Ok((list.drop, problems))
}

/// Byte ranges of the `$$` bodies of `functions` in comment-free SQL.
pub(crate) fn function_bodies(sql: &str, functions: &[&str]) -> Vec<(usize, usize)> {
    let upper = sql.to_ascii_uppercase();
    let mut out = Vec::new();
    for f in functions {
        let needle = format!("FUNCTION {}(", f.to_ascii_uppercase());
        let mut from = 0;
        while let Some(pos) = upper.get(from..).and_then(|s| s.find(&needle)) {
            let at = from.saturating_add(pos);
            from = at.saturating_add(needle.len());
            let Some(open) = upper.get(from..).and_then(|s| s.find("$$")) else {
                break;
            };
            let start = from.saturating_add(open).saturating_add(2);
            let Some(close) = upper.get(start..).and_then(|s| s.find("$$")) else {
                break;
            };
            let end = start.saturating_add(close);
            out.push((start, end));
            from = end;
        }
    }
    out
}

/// Privilege names that may precede `TRUNCATE` in a `GRANT` or `REVOKE` list.
const PRIVILEGES: &[&str] = &[
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
    "MAINTAIN",
];

/// True if the word at `k` is a trigger event (`BEFORE TRUNCATE`, `UPDATE OR TRUNCATE`)
/// or a privilege in a `GRANT`/`REVOKE` list, not a statement.
fn truncate_is_not_a_statement(words: &[(usize, &str, usize)], k: usize) -> bool {
    let stmt = words.get(k).map(|&(_, _, s)| s);
    let word = |i: usize| {
        words
            .get(i)
            .filter(|&&(_, _, s)| Some(s) == stmt)
            .map(|&(_, w, _)| w)
    };
    let Some(prev) = k.checked_sub(1) else {
        return false;
    };
    if matches!(word(prev), Some("BEFORE" | "AFTER" | "OR")) {
        return true;
    }
    let mut i = prev;
    loop {
        match word(i) {
            Some("GRANT" | "REVOKE") => return true,
            Some(w) if PRIVILEGES.contains(&w) => {}
            _ => return false,
        }
        let Some(next) = i.checked_sub(1) else {
            return false;
        };
        i = next;
    }
}

/// `ALTER TABLE … DROP x` forms that do not remove a column.
const ALTER_DROP_KEEPS_DATA: &[&str] = &["CONSTRAINT", "DEFAULT", "NOT", "IDENTITY", "EXPRESSION"];

/// Physical-delete statements in SQL text, as (byte offset, message).
pub(crate) fn delete_findings(sql: &str, allow: &[String]) -> Vec<(usize, String)> {
    let upper = sql.to_ascii_uppercase();
    let mut words: Vec<(usize, &str, usize)> = Vec::new();
    let mut start = None;
    let mut statement = 0_usize;
    for (i, c) in upper.char_indices() {
        let word_char = c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '"';
        match (word_char, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                words.push((s, upper.get(s..i).unwrap_or_default(), statement));
                start = None;
            }
            _ => {}
        }
        if c == ';' {
            statement = statement.saturating_add(1);
        }
    }
    if let Some(s) = start {
        words.push((s, upper.get(s..).unwrap_or_default(), statement));
    }
    let mut out = Vec::new();
    let mut alter_statement: Option<usize> = None;
    for (k, &(at, w, stmt)) in words.iter().enumerate() {
        let next = words.get(k.saturating_add(1)).map(|&(_, n, _)| n);
        if (w, next) == ("ALTER", Some("TABLE")) {
            alter_statement = Some(stmt);
        }
        match (w, next) {
            ("DELETE", Some("FROM")) => {
                let mut t = k.saturating_add(2);
                if words.get(t).is_some_and(|&(_, x, _)| x == "ONLY") {
                    t = t.saturating_add(1);
                }
                let table = words.get(t).map_or("", |&(_, x, _)| x);
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
            ("TRUNCATE", _) if truncate_is_not_a_statement(&words, k) => {}
            ("TRUNCATE", _) => out.push((
                at,
                "`TRUNCATE` is forbidden (T-36 rule 4, OP-12)".to_owned(),
            )),
            ("DROP", Some(object @ ("TABLE" | "SCHEMA" | "DATABASE"))) => out.push((
                at,
                format!("`DROP {object}` is forbidden; archive instead (T-36 rule 4, OP-12)"),
            )),
            ("DROP", Some(object))
                if alter_statement == Some(stmt) && !ALTER_DROP_KEEPS_DATA.contains(&object) =>
            {
                out.push((
                    at,
                    "`ALTER TABLE … DROP COLUMN` is forbidden; columns are deprecated, not dropped (T-36 rule 4, OP-12)"
                        .to_owned(),
                ));
            }
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

/// Findings in a SQL file, with `DROP TABLE` allowed only inside the bodies of the
/// reviewed `functions` (OP-12 rule 4).
pub(crate) fn sql_delete_findings(
    sql: &str,
    allow: &[String],
    functions: &[&str],
) -> Vec<(usize, String)> {
    let bodies = function_bodies(sql, functions);
    delete_findings(sql, allow)
        .into_iter()
        .filter(|(at, msg)| {
            !(msg.starts_with("`DROP TABLE`") && bodies.iter().any(|&(s, e)| *at >= s && *at < e))
        })
        .collect()
}

pub(crate) fn check_delete(root: &Path) -> Result<Vec<Violation>, String> {
    let (allow, problems) = match read_optional(&root.join(DELETE_ALLOWLIST_FILE))? {
        Some(text) => parse_allowlist(&text)?,
        None => (Vec::new(), Vec::new()),
    };
    let (drops, drop_problems) = match read_optional(&root.join(DELETE_ALLOWLIST_FILE))? {
        Some(text) => parse_drops(&text)?,
        None => (Vec::new(), Vec::new()),
    };
    let mut out: Vec<Violation> = problems
        .into_iter()
        .chain(drop_problems)
        .map(|m| violation(DELETE, DELETE_ALLOWLIST_FILE, 1, m))
        .collect();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        match path.extension().and_then(|e| e.to_str()) {
            Some("sql") => {
                let sql = strip_sql_comments(&read(&path)?);
                let functions: Vec<&str> = drops
                    .iter()
                    .filter(|d| d.file == rel_path)
                    .map(|d| d.function.as_str())
                    .collect();
                for (at, msg) in sql_delete_findings(&sql, &allow, &functions) {
                    out.push(violation(DELETE, &rel_path, line_at(&sql, at), msg));
                }
            }
            Some("rs") if !is_test_file(&rel_path) && !is_rule_definition(&rel_path) => {
                let lexed = lex(&read(&path)?);
                let tests = test_regions(&lexed.code);
                let mut seen: Vec<(usize, String)> = Vec::new();
                for (line, text) in literal_texts(&lexed) {
                    if in_regions(&tests, line) {
                        continue;
                    }
                    for (_, msg) in delete_findings(&text, &allow) {
                        if !seen.contains(&(line, msg.clone())) {
                            seen.push((line, msg.clone()));
                            out.push(violation(DELETE, &rel_path, line, msg));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

const TODO: &str = "todo-has-issue";

/// True if a comment's to-do names an issue number above zero and a short text.
pub(crate) fn todo_is_tracked(comment: &str) -> bool {
    let body = comment
        .trim_start_matches(['/', '!', '*', '#', '-', ';', '<'])
        .trim_start();
    let Some(rest) = body.strip_prefix("TODO(#") else {
        return false;
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let after = rest.get(digits.len()..).unwrap_or_default();
    !digits.is_empty()
        && !digits.starts_with('0')
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

pub(crate) fn check_todo(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for rel_path in scanned_files(root)? {
        let text = read(&root.join(&rel_path))?;
        let Some(comments) = comments_of(&rel_path, &text) else {
            continue;
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

/// Header lines that mark a file as generated FFI scaffolding.
const GENERATED_MARKERS: &[&str] = &[
    "@generated",
    "This file was autogenerated by some hot garbage in the `uniffi` crate.",
];

/// True when one of the first lines of `src` carries a generator marker.
pub(crate) fn is_generated(src: &str) -> bool {
    src.lines()
        .take(5)
        .any(|l| GENERATED_MARKERS.iter().any(|m| l.contains(m)))
}

/// An `unsafe` use: its line and whether a `// SAFETY:` comment justifies it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnsafeUse {
    pub(crate) line: usize,
    pub(crate) justified: bool,
}

/// Every `unsafe` keyword in a file and whether a `// SAFETY:` comment (or a
/// `# Safety` doc section) is on its line or in the comment and attribute lines
/// directly above; text in string literals does not count.
pub(crate) fn unsafe_uses(src: &str) -> Vec<UnsafeUse> {
    let lexed = lex(src);
    let src_lines: Vec<&str> = src.lines().collect();
    let code_lines: Vec<&str> = lexed.code.lines().collect();
    let safety_lines: Vec<usize> = lexed
        .comments
        .iter()
        .filter(|c| c.text.contains("SAFETY:") || c.text.contains("# Safety"))
        .flat_map(|c| {
            let n = c.text.matches('\n').count();
            c.line..=c.line.saturating_add(n)
        })
        .collect();
    let mut out = Vec::new();
    for at in find_token(&lexed.code, "unsafe") {
        let line = line_at(&lexed.code, at);
        let mut justified = safety_lines.contains(&line);
        let mut n = line.saturating_sub(1);
        while !justified && n >= 1 {
            let trimmed = src_lines
                .get(n.saturating_sub(1))
                .map_or("", |l| l.trim_start());
            let code = code_lines.get(n.saturating_sub(1)).map_or("", |l| l.trim());
            let continues = code.is_empty() && !trimmed.is_empty()
                || ["#[", "#!"].iter().any(|p| code.starts_with(p));
            if !continues {
                break;
            }
            justified = safety_lines.contains(&n);
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
    let allowed = in_allowlist(rel_path) && is_generated(src);
    let mut out = Vec::new();
    for u in unsafe_uses(src) {
        if !allowed {
            out.push(violation(
                UNSAFE,
                rel_path,
                u.line,
                "`unsafe` outside generated FFI scaffolding in sdks/bindings (T-33 rule 3)"
                    .to_owned(),
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

    // T-32 T-4
    #[test]
    fn t_32_grouped_std_imports_in_domain_layers_are_expanded() {
        assert_eq!(
            expand_use(" std::{fs, io::{Read, Write}, collections::BTreeMap} "),
            [
                "std::fs",
                "std::io::Read",
                "std::io::Write",
                "std::collections::BTreeMap"
            ]
        );
        let v = purity_violations(
            "crates/views/src/domain/a.rs",
            "use std::{\n    collections::BTreeMap,\n    fs,\n    time::{Duration},\n};\nuse ::std::net::TcpStream;\nuse std as s;\n",
        );
        let what: Vec<String> = v.iter().map(|x| x.message.clone()).collect();
        assert_eq!(v.len(), 4, "{what:?}");
        let ok = purity_violations(
            "crates/views/src/domain/a.rs",
            "use std::{collections::BTreeMap, fmt};\n",
        );
        assert!(ok.is_empty(), "{ok:?}");
    }

    // T-32 T-4
    #[test]
    fn t_32_hash_maps_and_sets_in_domain_layers_are_rejected() {
        let v = purity_violations(
            "crates/views/src/domain.rs",
            "use std::collections::{HashMap, HashSet};\nstruct S { m: HashMap<u8, u8>, b: std::collections::BTreeMap<u8, u8> }\n",
        );
        assert_eq!(v.len(), 3, "{v:?}");
        assert!(
            purity_violations("crates/views/src/domain.rs", "struct FxHashMapLike;\n").is_empty()
        );
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
    fn t_36_lower_case_escaped_and_concatenated_sql_outside_store_is_rejected() {
        let src = "fn f() {\n    let a = \"select id from commitments\";\n    let b = \"\\x53ELECT id FROM t\";\n    let c = concat!(\"SELE\", \"CT id \", \"FROM t\");\n    let d = format!(\"{}{}\", \"insert \", \"into t values (1)\");\n    let e = \"Select a value from the list\";\n}\n";
        let mut lines: Vec<String> = sql_violations("crates/views/src/a.rs", src)
            .iter()
            .map(|v| v.path.display().to_string())
            .collect();
        lines.sort();
        assert_eq!(
            lines,
            [
                "crates/views/src/a.rs:2",
                "crates/views/src/a.rs:3",
                "crates/views/src/a.rs:4",
                "crates/views/src/a.rs:5"
            ]
        );
    }

    // T-36 OP-12
    #[test]
    fn t_36_drop_schema_and_drop_column_are_rejected() {
        let f = delete_findings(
            "DROP SCHEMA work CASCADE; ALTER TABLE records DROP COLUMN body; ALTER TABLE x DROP IF EXISTS y; ALTER TABLE t ALTER COLUMN c DROP DEFAULT; ALTER TABLE t DROP CONSTRAINT k; DROP INDEX i;",
            &[],
        );
        assert_eq!(f.len(), 3, "{f:?}");
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

    // T-36 OP-12 OP-17
    #[test]
    fn t_36_truncate_trigger_events_and_privileges_are_not_statements() {
        let sql = "CREATE TRIGGER t BEFORE TRUNCATE ON a FOR EACH STATEMENT EXECUTE FUNCTION f();\n\
                   CREATE TRIGGER u AFTER UPDATE OR TRUNCATE ON a EXECUTE FUNCTION f();\n\
                   EXECUTE format('REVOKE DELETE, TRUNCATE ON %s FROM %I', t, o);\n\
                   GRANT TRUNCATE ON a TO b;";
        assert_eq!(delete_findings(sql, &[]), vec![]);
        assert_eq!(delete_findings("TRUNCATE a;", &[]).len(), 1);
        assert_eq!(delete_findings("BEGIN; TRUNCATE TABLE a;", &[]).len(), 1);
        assert_eq!(delete_findings("SELECT 1; TRUNCATE a, b;", &[]).len(), 1);
        assert_eq!(delete_findings("DELETE FROM x; TRUNCATE y;", &[]).len(), 2);
        assert_eq!(
            delete_findings("GRANT SELECT ON a TO b; TRUNCATE a;", &[]).len(),
            1
        );
        assert_eq!(
            delete_findings("ALTER TABLE a OWNER TO u; TRUNCATE a;", &[]).len(),
            1
        );
    }

    // T-36 OP-12
    #[test]
    fn t_36_drop_table_is_allowed_only_in_a_reviewed_function_body() {
        let sql = "CREATE FUNCTION work.drop_archived(p regclass) RETURNS void AS $$\n\
                   BEGIN EXECUTE format('DROP TABLE %s', p); END $$;\n\
                   CREATE FUNCTION work.other() RETURNS void AS $$ BEGIN DROP TABLE x; END $$;\n\
                   DROP TABLE y;";
        assert_eq!(
            sql_delete_findings(sql, &[], &["work.drop_archived"]).len(),
            2
        );
        assert_eq!(sql_delete_findings(sql, &[], &[]).len(), 3);
        let (drops, problems) = parse_drops(
            "[[drop]]\nfile = \"a.sql\"\nfunction = \"work.f\"\nid = \"OP-12\"\nreason = \"r\"\n\
             [[drop]]\nfile = \"a.sql\"\nfunction = \"work.g\"\nid = \"\"\nreason = \"r\"\n",
        )
        .unwrap();
        assert_eq!(drops.len(), 2);
        assert_eq!(problems.len(), 1);
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
            (7, "// TODO(#0): no issue zero".to_owned()),
            (8, "-- TODO(#9): tracked SQL to-do".to_owned()),
            (9, "<!-- TODO: untracked HTML to-do -->".to_owned()),
            (10, "; TODO(#07): leading zero".to_owned()),
        ];
        assert_eq!(untracked_todos(&comments), vec![1, 3, 5, 6, 7, 9, 10]);
    }

    // T-33
    #[test]
    fn t_33_unsafe_outside_generated_bindings_scaffolding_is_rejected() {
        let src = "fn f() {\n    // SAFETY: g has no preconditions.\n    unsafe { g() };\n}\n";
        let generated = format!("// @generated\n{src}");
        assert_eq!(
            unsafe_file_violations("crates/store/src/a.rs", &generated).len(),
            1
        );
        assert_eq!(
            unsafe_file_violations("sdks/bindings/uniffi/src/a.rs", src).len(),
            1
        );
        assert!(unsafe_file_violations("sdks/bindings/uniffi/src/a.rs", &generated).is_empty());
    }

    // T-33 T-53
    #[test]
    fn t_33_unsafe_in_bindings_needs_a_safety_comment() {
        let src = "// @generated\nfn f() {\n    let x = unsafe { g() };\n}\n";
        assert_eq!(
            unsafe_uses(src),
            vec![UnsafeUse {
                line: 3,
                justified: false
            }]
        );
        assert_eq!(
            unsafe_file_violations("sdks/bindings/wasm/src/a.rs", src).len(),
            1
        );
        let in_string =
            "// @generated\nfn f() {\n    let s = \"SAFETY: not a comment\"; unsafe { g() };\n}\n";
        assert_eq!(
            unsafe_file_violations("sdks/bindings/wasm/src/a.rs", in_string).len(),
            1
        );
        let attr = "// @generated\n// SAFETY: exported symbol.\n#[unsafe(no_mangle)]\nfn f() {}\n";
        assert!(unsafe_file_violations("sdks/bindings/wasm/src/a.rs", attr).is_empty());
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
