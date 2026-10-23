//! Canonical terminology (C-42) in code names, identifier-like string literals
//! and serde renames of Rust and TypeScript, Rust enum variants, SQL and CDDL
//! identifiers, and `OpenAPI` and `AsyncAPI` documents wherever they live.

use std::path::Path;

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{
    extension, is_api_document, is_test_file, read, read_optional, repo_files,
};
use crate::rules::lex::{CDDL, Lexed, SQL, TS, in_regions, lex, lex_with, line_at, test_regions};
use crate::rules::switches::is_script_test;

const TERMS: &str = "conformance/catalog/terms.toml";

#[derive(Debug, Deserialize)]
struct Terms {
    #[serde(default)]
    term: Vec<Term>,
    #[serde(default)]
    allow: Vec<Allow>,
}

#[derive(Debug, Deserialize)]
struct Term {
    canonical: String,
    not: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Allow {
    path: String,
    name: String,
    reason: String,
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    check_files(root, &repo_files(root)?)
}

fn check_files(root: &Path, files: &[String]) -> Result<Vec<Violation>, String> {
    let Some(text) = read_optional(&root.join(TERMS))? else {
        return Ok(vec![violation(
            TERMS,
            0,
            "the C-42 term list is missing".to_owned(),
        )]);
    };
    let terms: Terms = toml::from_str(&text).map_err(|e| format!("{TERMS}: {e}"))?;
    let mut out = Vec::new();
    for allow in &terms.allow {
        if allow.reason.trim().is_empty() {
            out.push(violation(
                TERMS,
                0,
                format!("allow entry `{}` has no reason", allow.name),
            ));
        }
    }
    for file in files {
        let Some(names) = names_of(file, || read(&root.join(file)))? else {
            continue;
        };
        for (line, name) in names {
            if terms
                .allow
                .iter()
                .any(|a| &a.path == file && a.name == name)
            {
                continue;
            }
            if let Some((word, canonical)) = offending(&terms.term, &name) {
                out.push(violation(
                    file,
                    line,
                    format!("`{name}` uses `{word}`; the canonical term is `{canonical}` (C-42)"),
                ));
            }
        }
    }
    Ok(out)
}

fn violation(path: &str, line: usize, message: String) -> Violation {
    let path = if line == 0 {
        path.to_owned()
    } else {
        format!("{path}:{line}")
    };
    Violation {
        rule: "C-42",
        path: path.into(),
        message,
    }
}

fn in_code_roots(file: &str) -> bool {
    ["crates/", "bins/", "sdks/", "packages/"]
        .iter()
        .any(|r| file.starts_with(r))
}

const SCRIPT_EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];

/// The names a file contributes, or `None` when the rule does not read it.
fn names_of(
    file: &str,
    read_file: impl FnOnce() -> Result<String, String>,
) -> Result<Option<Vec<(usize, String)>>, String> {
    let ext = extension(file);
    let names = match ext.as_str() {
        "rs" if in_code_roots(file) && !is_test_file(file) => rust_names(&read_file()?),
        e if SCRIPT_EXTENSIONS.contains(&e) && in_code_roots(file) && !is_script_test(file) => {
            script_names(&read_file()?)
        }
        "sql" => all_identifiers(&lex_with(&read_file()?, &SQL)),
        "cddl" => all_identifiers(&lex_with(&read_file()?, &CDDL)),
        "json" | "yaml" | "yml" => {
            let text = read_file()?;
            if !is_api_document(file, &text) {
                return Ok(None);
            }
            schema_keys(&text)
        }
        _ => return Ok(None),
    };
    Ok(Some(names))
}

fn offending<'a>(terms: &'a [Term], name: &str) -> Option<(String, &'a str)> {
    let snake: String = to_snake(name)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    for term in terms {
        for not in &term.not {
            let hit = if not.contains('_') {
                format!("_{snake}_").contains(&format!("_{not}_"))
            } else {
                snake.split('_').any(|w| w == not)
            };
            if hit {
                return Some((not.clone(), term.canonical.as_str()));
            }
        }
    }
    None
}

fn to_snake(name: &str) -> String {
    let mut out = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            if prev_lower {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            prev_lower = false;
        } else {
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
            out.push(c);
        }
    }
    out
}

const DECL_KEYWORDS: &[&str] = &[
    "fn", "struct", "enum", "trait", "type", "mod", "const", "static", "let", "mut",
];

const SCRIPT_KEYWORDS: &[&str] = &[
    "const",
    "let",
    "var",
    "function",
    "class",
    "interface",
    "type",
    "enum",
    "namespace",
];

/// Declared names and `name:` fields of a code view, outside `skip` line ranges.
fn declared_names(code: &str, keywords: &[&str], skip: &[(usize, usize)]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0;
    let mut prev_word = String::new();
    while let Some(&c) = chars.get(i) {
        if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while chars
                .get(i)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            {
                i = i.saturating_add(1);
            }
            let word: String = chars.get(start..i).unwrap_or_default().iter().collect();
            let rest: String = chars.get(i..).unwrap_or_default().iter().take(3).collect();
            let declared = keywords.contains(&prev_word.as_str());
            let rest = rest.trim_start().trim_start_matches('?');
            let field = rest.starts_with(':') && !rest.starts_with("::");
            if (declared || field) && !keywords.contains(&word.as_str()) {
                let at = code.char_indices().nth(start).map_or(0, |(b, _)| b);
                let line = line_at(code, at);
                if !in_regions(skip, line) {
                    out.push((line, word.clone()));
                }
            }
            prev_word = word;
        } else {
            if !c.is_whitespace() {
                prev_word.clear();
            }
            i = i.saturating_add(1);
        }
    }
    out
}

/// The variants of every Rust `enum` in a code view.
fn enum_variants(code: &str, skip: &[(usize, usize)]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for at in crate::rules::lex::find_token(code, "enum") {
        let rest = code.get(at..).unwrap_or_default();
        let Some(open) = rest.find('{') else { continue };
        if rest.get(..open).is_some_and(|h| h.contains(';')) {
            continue;
        }
        let body_start = at.saturating_add(open).saturating_add(1);
        let mut depth = 1_usize;
        let mut expect = true;
        let mut word = String::new();
        let mut word_at = 0;
        let mut attr = 0_usize;
        for (k, c) in code.get(body_start..).unwrap_or_default().char_indices() {
            let pos = body_start.saturating_add(k);
            if depth == 1 && attr == 0 && expect && (c.is_ascii_alphanumeric() || c == '_') {
                if word.is_empty() {
                    word_at = pos;
                }
                word.push(c);
                continue;
            }
            if !word.is_empty() {
                let line = line_at(code, word_at);
                if !in_regions(skip, line) {
                    out.push((line, std::mem::take(&mut word)));
                }
                word.clear();
                expect = false;
            }
            match c {
                '#' if depth == 1 => attr = attr.max(1),
                '[' if attr > 0 => attr = attr.saturating_add(1),
                ']' if attr > 1 => {
                    attr = attr.saturating_sub(1);
                    if attr == 1 {
                        attr = 0;
                    }
                }
                '{' | '(' | '<' => depth = depth.saturating_add(1),
                '}' | ')' | '>' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                ',' if depth == 1 => expect = true,
                _ => {}
            }
        }
    }
    out
}

/// A string literal that reads as one identifier or wire value (`"assignee"`,
/// `"task-list"`), not prose.
fn identifier_like(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

fn literal_names(lexed: &Lexed, skip: &[(usize, usize)]) -> Vec<(usize, String)> {
    lexed
        .strings
        .iter()
        .filter(|l| identifier_like(&l.text) && !in_regions(skip, l.line))
        .map(|l| (l.line, l.text.clone()))
        .collect()
}

fn rust_names(src: &str) -> Vec<(usize, String)> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = declared_names(&lexed.code, DECL_KEYWORDS, &tests);
    out.extend(enum_variants(&lexed.code, &tests));
    out.extend(literal_names(&lexed, &tests));
    out
}

fn script_names(src: &str) -> Vec<(usize, String)> {
    let lexed = lex_with(src, &TS);
    let mut out = declared_names(&lexed.code, SCRIPT_KEYWORDS, &[]);
    out.extend(literal_names(&lexed, &[]));
    out
}

/// Every identifier of a SQL or CDDL file and its identifier-like strings.
fn all_identifiers(lexed: &Lexed) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in lexed.code.lines().enumerate() {
        for word in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
            let word = word.trim_matches('-');
            if word
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            {
                out.push((n.saturating_add(1), word.to_owned()));
            }
        }
    }
    out.extend(literal_names(lexed, &[]));
    out
}

/// Keys of a YAML or JSON API document and identifier-like list values (enums).
fn schema_keys(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let item = line.trim_start().strip_prefix("- ").map(|v| {
            crate::yaml::strip_comment(v)
                .trim()
                .trim_matches(['"', '\''])
                .to_owned()
        });
        if let Some(value) = item.filter(|v| identifier_like(v)) {
            out.push((n.saturating_add(1), value));
        }
        let trimmed = line.trim_start().trim_start_matches("- ");
        let key: String = trimmed
            .trim_start_matches('"')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = trimmed
            .trim_start_matches('"')
            .get(key.len()..)
            .unwrap_or_default();
        if !key.is_empty() && after.trim_start_matches('"').trim_start().starts_with(':') {
            out.push((n.saturating_add(1), key));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::files::TempDir;

    fn terms() -> Vec<Term> {
        toml::from_str::<Terms>(include_str!("../../conformance/catalog/terms.toml"))
            .unwrap()
            .term
    }

    // C-42
    #[test]
    fn c_42_task_and_assignee_names_are_rejected() {
        let src =
            "pub struct TaskList { assignee: PartyId }\nfn open_ticket() {}\nlet user_id = 1;\n";
        let hits: Vec<String> = rust_names(src)
            .into_iter()
            .filter(|(_, n)| offending(&terms(), n).is_some())
            .map(|(_, n)| n)
            .collect();
        assert_eq!(hits, ["TaskList", "assignee", "open_ticket", "user_id"]);
    }

    // C-42
    #[test]
    fn c_42_canonical_names_and_external_paths_pass() {
        let src = "pub struct Commitment { debtor: PartyId }\nfn spawn() { tokio::task::spawn(run()); let tasker_free = 1; }\n// a task\nconst S: &str = \"a task\";\n";
        assert!(
            rust_names(src)
                .into_iter()
                .all(|(_, n)| offending(&terms(), &n).is_none())
        );
    }

    // C-42
    #[test]
    fn c_42_api_schema_keys_are_checked() {
        let yaml = "properties:\n  work_id:\n    type: string\n  assignee:\n    type: string\n";
        let keys: Vec<String> = schema_keys(yaml).into_iter().map(|(_, k)| k).collect();
        assert!(keys.contains(&"assignee".to_owned()));
        assert!(offending(&terms(), "assignee").is_some());
        assert!(offending(&terms(), "work_id").is_none());
    }

    // C-42
    #[test]
    fn c_42_variants_strings_serde_renames_and_other_languages_are_scanned() {
        let hits = |names: Vec<(usize, String)>| -> Vec<String> {
            names
                .into_iter()
                .filter(|(_, n)| offending(&terms(), n).is_some())
                .map(|(_, n)| n)
                .collect()
        };
        let rs = "pub enum Kind {\n    #[serde(rename = \"assignee\")]\n    Debtor,\n    Ticket { id: u8 },\n    Card(u8),\n}\nconst M: &str = \"Assign a task to the debtor\";\nconst W: &str = \"subtask-list\";\n#[cfg(test)]\nmod tests { const T: &str = \"task\"; }\n";
        assert_eq!(
            hits(rust_names(rs)),
            ["Ticket", "Card", "assignee", "subtask-list"]
        );
        let ts = "export interface Work { assignee?: string; title: string }\nexport const kind = \"ticket\";\nconst message = \"open a ticket\";\n";
        assert_eq!(hits(script_names(ts)), ["assignee", "ticket"]);
        let sql = "-- tasks are not here\nCREATE TABLE commitments (id uuid, assignee uuid);\nSELECT 'task' FROM t;\n";
        assert_eq!(
            hits(all_identifiers(&lex_with(sql, &SQL))),
            ["assignee", "task"]
        );
        let cddl = "; task\nrecord = { assignee: party, ? \"user_id\": tstr }\n";
        assert_eq!(
            hits(all_identifiers(&lex_with(cddl, &CDDL))),
            ["assignee", "user_id"]
        );
        let api = "openapi: 3.1.0\ncomponents:\n  schemas:\n    Kind:\n      enum:\n        - debtor\n        - assignee\n";
        let names = names_of("deploy/api/work.yaml", || Ok(api.to_owned()))
            .unwrap()
            .unwrap();
        assert_eq!(hits(names), ["assignee"]);
        assert!(
            names_of("deploy/x.yaml", || Ok("a: 1\n".to_owned()))
                .unwrap()
                .is_none()
        );
    }

    // C-42
    #[test]
    fn c_42_allow_entries_need_a_reason() {
        let dir = TempDir::new("terms");
        dir.write(
            TERMS,
            "[[term]]\ncanonical = \"work\"\nnot = [\"task\"]\n\n[[allow]]\npath = \"crates/x/src/lib.rs\"\nname = \"task\"\nreason = \"\"\n",
        );
        let found = check_files(&dir.0, &[]).unwrap();
        assert!(found.iter().any(|v| v.message.contains("no reason")));
    }
}
