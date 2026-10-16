//! Canonical terminology in code names and API schemas (C-42).

use std::path::Path;

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{extension, is_test_file, read, read_optional, repo_files};
use crate::rules::lex::{lex, line_at};

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
        let names = if is_scanned_rust(file) {
            rust_names(&read(&root.join(file))?)
        } else if is_api_schema(file) {
            schema_keys(&read(&root.join(file))?)
        } else {
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

fn is_scanned_rust(file: &str) -> bool {
    extension(file) == "rs"
        && (file.starts_with("crates/") || file.starts_with("bins/") || file.starts_with("sdks/"))
        && !is_test_file(file)
}

fn is_api_schema(file: &str) -> bool {
    (file.starts_with("sdks/openapi/") || file.starts_with("sdks/asyncapi/"))
        && matches!(extension(file).as_str(), "json" | "yaml" | "yml")
}

fn offending<'a>(terms: &'a [Term], name: &str) -> Option<(String, &'a str)> {
    let snake = to_snake(name);
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

fn rust_names(src: &str) -> Vec<(usize, String)> {
    let code = lex(src).code;
    let mut out = Vec::new();
    let bytes: Vec<char> = code.chars().collect();
    let mut i = 0;
    let mut prev_word = String::new();
    while let Some(&c) = bytes.get(i) {
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while bytes
                .get(i)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                i = i.saturating_add(1);
            }
            let word: String = bytes.get(start..i).unwrap_or_default().iter().collect();
            let rest: String = bytes.get(i..).unwrap_or_default().iter().take(3).collect();
            let declared = DECL_KEYWORDS.contains(&prev_word.as_str());
            let field = rest.trim_start().starts_with(':') && !rest.trim_start().starts_with("::");
            if (declared || field) && !DECL_KEYWORDS.contains(&word.as_str()) {
                let at = code.char_indices().nth(start).map_or(0, |(b, _)| b);
                out.push((line_at(&code, at), word.clone()));
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

fn schema_keys(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
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

    #[test]
    fn c_42_canonical_names_and_external_paths_pass() {
        let src = "pub struct Commitment { debtor: PartyId }\nfn spawn() { tokio::task::spawn(run()); let tasker_free = 1; }\n// a task\nconst S: &str = \"task\";\n";
        assert!(
            rust_names(src)
                .into_iter()
                .all(|(_, n)| offending(&terms(), &n).is_none())
        );
    }

    #[test]
    fn c_42_api_schema_keys_are_checked() {
        let yaml = "properties:\n  work_id:\n    type: string\n  assignee:\n    type: string\n";
        let keys: Vec<String> = schema_keys(yaml).into_iter().map(|(_, k)| k).collect();
        assert!(keys.contains(&"assignee".to_owned()));
        assert!(offending(&terms(), "assignee").is_some());
        assert!(offending(&terms(), "work_id").is_none());
    }

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
