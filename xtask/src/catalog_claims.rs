//! `forbidden-claims` (T-48, F-24, INV-34, SEC-33, SEC-34, MKT-1, T-42): tracked
//! documents, rustdoc, API description files and message catalogs never use a
//! forbidden claim outside its reasoned exceptions; Markdown never links to the
//! local-only `docs/`; a `COMPARISON.md` carries its set, date and counterexample.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::catalog::DIR;
use crate::catalog::ids::family;
use crate::rules::files::{extension, repo_files};
use crate::rules::lex::lex;

const FILE: &str = "forbidden-claims.toml";

/// Which files the scan reads.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scan {
    pub(crate) include: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) extensions: Vec<String>,
}

/// The public comparison text (MKT-1, T-49).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Comparison {
    pub(crate) file: String,
    pub(crate) sections: Vec<String>,
}

/// A context in which a phrase is allowed, with its reason.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Allow {
    pub(crate) context: String,
    pub(crate) reason: String,
}

/// A file where a claim may appear, with its reason.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Exception {
    pub(crate) path: String,
    pub(crate) reason: String,
}

/// One forbidden claim.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claim {
    pub(crate) id: String,
    pub(crate) rules: Vec<String>,
    pub(crate) phrases: Vec<String>,
    pub(crate) replacement: String,
    #[serde(default)]
    pub(crate) negation: bool,
    #[serde(default)]
    pub(crate) allow: Vec<Allow>,
    #[serde(default)]
    pub(crate) exception: Vec<Exception>,
}

/// `forbidden-claims.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimsFile {
    pub(crate) scan: Scan,
    pub(crate) comparison: Comparison,
    #[serde(default)]
    pub(crate) claim: Vec<Claim>,
}

pub(crate) fn load(root: &Path) -> Result<ClaimsFile, String> {
    let path = root.join(DIR).join(FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Minimal glob: `**` spans directories, `*` stays in one segment; a pattern
/// without `/` matches the file name at any depth.
pub(crate) fn glob(pattern: &str, path: &str) -> bool {
    fn seg(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                let rest = p.get(1..).unwrap_or_default();
                seg(rest, s) || (!s.is_empty() && seg(p, s.get(1..).unwrap_or_default()))
            }
            (Some(a), Some(b)) if a == b => seg(
                p.get(1..).unwrap_or_default(),
                s.get(1..).unwrap_or_default(),
            ),
            _ => false,
        }
    }
    fn parts(p: &[&str], s: &[&str]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(&"**"), _) => {
                let rest = p.get(1..).unwrap_or_default();
                parts(rest, s) || (!s.is_empty() && parts(p, s.get(1..).unwrap_or_default()))
            }
            (Some(a), Some(b)) if seg(a.as_bytes(), b.as_bytes()) => parts(
                p.get(1..).unwrap_or_default(),
                s.get(1..).unwrap_or_default(),
            ),
            _ => false,
        }
    }
    if !pattern.contains('/') {
        let name = path.rsplit('/').next().unwrap_or(path);
        return seg(pattern.as_bytes(), name.as_bytes());
    }
    let p: Vec<&str> = pattern.split('/').collect();
    let s: Vec<&str> = path.split('/').collect();
    parts(&p, &s)
}

/// Files to scan.
pub(crate) fn targets(files: &[String], scan: &Scan) -> Vec<String> {
    files
        .iter()
        .filter(|f| !scan.exclude.iter().any(|g| glob(g, f)))
        .filter(|f| scan.extensions.iter().any(|e| *e == extension(f)))
        .filter(|f| scan.include.iter().any(|g| glob(g, f)))
        .cloned()
        .collect()
}

fn split_camel(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_lower = false;
    for c in s.chars() {
        if c.is_uppercase() && prev_lower {
            out.push(' ');
        }
        prev_lower = c.is_lowercase();
        out.push(c);
    }
    out
}

/// Lower-cases and folds typography so phrases match across quotes, dashes,
/// emphasis and identifier separators.
pub(crate) fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\u{2018}' | '\u{2019}' => out.push('\''),
            '\u{201C}' | '\u{201D}' => out.push('"'),
            '\u{2010}'..='\u{2015}' => out.push('-'),
            '*' | '`' => {}
            c if c.is_whitespace() || c == '_' => {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// Paragraphs (blank-line separated) with their first line number.
fn paragraphs(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start = 0;
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            if !current.trim().is_empty() {
                out.push((start, std::mem::take(&mut current)));
            }
            current.clear();
            continue;
        }
        if current.is_empty() {
            start = n.saturating_add(1);
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.trim().is_empty() {
        out.push((start, current));
    }
    out
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric()
}

fn find_all(text: &str, phrase: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = text.get(from..).and_then(|t| t.find(phrase)) {
        let at = from.saturating_add(pos);
        let end = at.saturating_add(phrase.len());
        let before = text.get(..at).and_then(|t| t.chars().next_back());
        let after = text.get(end..).and_then(|t| t.chars().next());
        let starts_word = phrase.chars().next().is_some_and(is_word);
        let ends_word = phrase.chars().next_back().is_some_and(is_word);
        if !((starts_word && before.is_some_and(is_word))
            || (ends_word && after.is_some_and(is_word)))
        {
            out.push(at);
        }
        from = at.saturating_add(phrase.chars().next().map_or(1, char::len_utf8));
    }
    out
}

const NEGATIONS: &[&str] = &[
    "not", "never", "no", "don't", "doesn't", "isn't", "aren't", "cannot", "can't", "won't",
    "without", "nor", "neither", "nothing", "none",
];

fn negated(text: &str, at: usize) -> bool {
    text.get(..at)
        .unwrap_or_default()
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .filter(|w| !w.is_empty())
        .rev()
        .take(5)
        .any(|w| NEGATIONS.contains(&w))
}

/// A paragraph normalized line by line, with the offset where each line starts.
fn normalize_lines(para: &str) -> (String, Vec<usize>) {
    let mut norm = String::new();
    let mut starts = Vec::new();
    for line in para.lines() {
        if !norm.is_empty() {
            norm.push(' ');
        }
        starts.push(norm.len());
        norm.push_str(normalize(line.trim()).trim());
    }
    (norm, starts)
}

/// Claims found in one text: (line, claim id, phrase).
pub(crate) fn find_claims(
    path: &str,
    text: &str,
    claims: &[Claim],
) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (start, para) in paragraphs(text) {
        let (norm, starts) = normalize_lines(&para);
        for claim in claims {
            if claim.exception.iter().any(|e| glob(&e.path, path))
                || claim
                    .allow
                    .iter()
                    .any(|a| norm.contains(&normalize(&a.context)))
            {
                continue;
            }
            for phrase in &claim.phrases {
                for at in find_all(&norm, &normalize(phrase)) {
                    if claim.negation && negated(&norm, at) {
                        continue;
                    }
                    let offset = starts
                        .iter()
                        .filter(|s| **s <= at)
                        .count()
                        .saturating_sub(1);
                    let line = start.saturating_add(offset);
                    if !out.iter().any(|(l, id, _)| *l == line && *id == claim.id) {
                        out.push((line, claim.id.clone(), phrase.clone()));
                    }
                }
            }
        }
    }
    out
}

/// The text a file contributes: rustdoc for Rust, camelCase split for API and
/// message files, the file itself otherwise.
pub(crate) fn scanned_text(path: &str, text: &str) -> String {
    match extension(path).as_str() {
        "rs" => {
            let lexed = lex(text);
            let mut lines = vec![String::new(); text.lines().count()];
            for c in &lexed.comments {
                let doc = c
                    .text
                    .strip_prefix("///")
                    .or_else(|| c.text.strip_prefix("//!"));
                if let (Some(body), Some(slot)) = (doc, lines.get_mut(c.line.saturating_sub(1))) {
                    body.clone_into(slot);
                }
            }
            lines.join("\n")
        }
        "json" | "yml" | "yaml" => split_camel(text),
        _ => text.to_owned(),
    }
}

/// Markdown links into the local-only `docs/` (T-42).
pub(crate) fn docs_links(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            [
                "](docs/",
                "](./docs/",
                "]: docs/",
                "]: ./docs/",
                "href=\"docs/",
                "href=\"./docs/",
            ]
            .iter()
            .any(|p| l.contains(p))
        })
        .map(|(n, _)| n.saturating_add(1))
        .collect()
}

/// Missing sections of the comparison text (MKT-1).
pub(crate) fn missing_sections(text: &str, sections: &[String]) -> Vec<String> {
    let headings: Vec<String> = text
        .lines()
        .filter(|l| l.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect();
    sections
        .iter()
        .filter(|s| !headings.iter().any(|h| h.contains(&s.to_ascii_lowercase())))
        .cloned()
        .collect()
}

fn violation(rule: &'static str, path: String, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

/// Dictionary problems.
pub(crate) fn validate(file: &ClaimsFile, catalog_ids: &BTreeSet<String>) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut ids = BTreeSet::new();
    let path = format!("{DIR}/{FILE}");
    for c in &file.claim {
        let mut bad = |m: &str| {
            out.push(violation(
                "forbidden-claims",
                path.clone(),
                format!("{}: {m}", c.id),
            ));
        };
        if !ids.insert(c.id.clone()) {
            bad("duplicate claim id");
        }
        if c.phrases.is_empty() || c.phrases.iter().any(|p| p.trim().is_empty()) {
            bad("needs non-empty phrases");
        }
        if c.replacement.trim().is_empty() {
            bad("needs an allowed replacement");
        }
        if c.rules.is_empty() {
            bad("needs rule IDs");
        }
        for r in &c.rules {
            if family(r).is_none() || (!catalog_ids.is_empty() && !catalog_ids.contains(r)) {
                bad(&format!("rule `{r}` is not in the catalog"));
            }
        }
        if c.allow
            .iter()
            .any(|a| a.context.trim().is_empty() || a.reason.trim().is_empty())
            || c.exception
                .iter()
                .any(|e| e.path.trim().is_empty() || e.reason.trim().is_empty())
        {
            bad("every allowed context and exception needs a reason");
        }
    }
    out
}

/// All findings over in-memory files: (path, text).
pub(crate) fn findings(file: &ClaimsFile, files: &[(String, String)]) -> Vec<Violation> {
    let mut out = Vec::new();
    for (path, text) in files {
        for (line, id, phrase) in find_claims(path, &scanned_text(path, text), &file.claim) {
            let replacement = file
                .claim
                .iter()
                .find(|c| c.id == id)
                .map_or("", |c| c.replacement.as_str());
            out.push(violation(
                "forbidden-claims",
                format!("{path}:{line}"),
                format!("forbidden claim `{id}` (\"{phrase}\"); say instead: {replacement} (T-48)"),
            ));
        }
        if extension(path) == "md" {
            for line in docs_links(text) {
                out.push(violation(
                    "forbidden-claims",
                    format!("{path}:{line}"),
                    "links to docs/, which is local-only and untracked (T-42)".to_owned(),
                ));
            }
        }
        if *path == file.comparison.file {
            for s in missing_sections(text, &file.comparison.sections) {
                out.push(violation(
                    "forbidden-claims",
                    path.clone(),
                    format!("the comparison text needs a `{s}` section (MKT-1, T-49)"),
                ));
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let file = load(root)?;
    let catalog = crate::catalog::load(root)?;
    let mut out = validate(&file, &catalog.ids());
    let all = repo_files(root)?;
    let mut texts = Vec::new();
    for path in targets(&all, &file.scan) {
        if let Ok(text) = std::fs::read_to_string(root.join(&path)) {
            texts.push((path, text));
        }
    }
    out.extend(findings(&file, &texts));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(id: &str, phrases: &[&str], negation: bool) -> Claim {
        Claim {
            id: id.to_owned(),
            rules: vec!["SEC-34".to_owned()],
            phrases: phrases.iter().map(|s| (*s).to_owned()).collect(),
            replacement: "x".to_owned(),
            negation,
            ..Claim::default()
        }
    }

    fn dictionary() -> ClaimsFile {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        load(root).unwrap()
    }

    // F-24 INV-34 SEC-33 SEC-34
    #[test]
    fn f_24_inv_34_sec_33_sec_34_every_forbidden_phrase_is_caught() {
        let file = dictionary();
        assert!(!file.claim.is_empty());
        for c in &file.claim {
            for phrase in &c.phrases {
                let text = format!("Work output is {phrase} today.");
                let found = find_claims("README.md", &text, std::slice::from_ref(c));
                let allowed_by_context = c
                    .allow
                    .iter()
                    .any(|a| normalize(&text).contains(&normalize(&a.context)));
                if !allowed_by_context {
                    assert_eq!(found.len(), 1, "{} / {phrase}", c.id);
                }
            }
        }
    }

    // T-48 F-24
    #[test]
    fn t_48_reasoned_exceptions_pass() {
        let file = dictionary();
        for c in &file.claim {
            let Some(phrase) = c.phrases.first() else {
                continue;
            };
            for a in &c.allow {
                let text = format!("It is {phrase} with {}.", a.context);
                assert!(
                    find_claims("README.md", &text, std::slice::from_ref(c)).is_empty(),
                    "{}",
                    c.id
                );
            }
            for e in &c.exception {
                let text = format!("It is {phrase}.");
                assert!(
                    find_claims(&e.path, &text, std::slice::from_ref(c)).is_empty(),
                    "{}",
                    c.id
                );
            }
        }
    }

    // T-48 SEC-33
    #[test]
    fn t_48_claims_match_across_wrapped_lines_and_skip_negations() {
        let claims = [claim(
            "exactly-once",
            &["exactly-once", "exactly once"],
            true,
        )];
        let found = find_claims(
            "a.md",
            "Intro.\n\nDelivery is **Exactly\nonce**.\n",
            &claims,
        );
        assert_eq!(
            found,
            [(3, "exactly-once".to_owned(), "exactly once".to_owned())]
        );
        assert!(find_claims("a.md", "Delivery is not exactly once.", &claims).is_empty());
        assert!(find_claims("a.md", "The exactlyonce flag.", &claims).is_empty());
    }

    // SEC-34
    #[test]
    fn sec_34_api_field_names_and_rustdoc_are_scanned() {
        let claims = [claim("permanently-deleted", &["permanently deleted"], true)];
        let api =
            "properties:\n  permanently_deleted:\n    type: boolean\n  wasPermanentlyDeleted: {}\n";
        assert_eq!(
            find_claims(
                "sdks/openapi/work.yaml",
                &scanned_text("sdks/openapi/work.yaml", api),
                &claims
            )
            .len(),
            2
        );
        let rs =
            "/// The body is permanently deleted.\nfn f() { let s = \"permanently deleted\"; }\n";
        assert_eq!(
            find_claims(
                "crates/a/src/lib.rs",
                &scanned_text("crates/a/src/lib.rs", rs),
                &claims
            )
            .len(),
            1
        );
    }

    // T-42 MKT-1
    #[test]
    fn t_42_mkt_1_docs_links_and_incomplete_comparison_are_rejected() {
        assert_eq!(
            docs_links("See [spec](docs/spec/README.md).\n[ok](CONTRIBUTING.md)\n"),
            [1]
        );
        let sections = vec![
            "set".to_owned(),
            "date".to_owned(),
            "counterexample".to_owned(),
        ];
        assert_eq!(
            missing_sections("# Comparison\n## Comparison set\n## Date\n", &sections),
            ["counterexample"]
        );
        assert!(missing_sections("## Set\n## Date\n## Counterexample\n", &sections).is_empty());
    }

    // MKT-1 T-49
    #[test]
    fn mkt_1_comparison_claims_only_in_the_comparison_text() {
        let file = dictionary();
        let readme = vec![(
            "README.md".to_owned(),
            "Work is better than task boards.\n".to_owned(),
        )];
        assert_eq!(findings(&file, &readme).len(), 1);
        let comparison = vec![(
            "COMPARISON.md".to_owned(),
            "## Comparison set\nA\n\n## Date\n2026-10-10\n\n## Counterexample\nB\n\nWork is better than A at waits.\n".to_owned(),
        )];
        assert!(findings(&file, &comparison).is_empty());
    }

    // T-48
    #[test]
    fn t_48_globs_match_names_anywhere_and_paths_by_segment() {
        assert!(glob("*.md", "crates/kernel/README.md"));
        assert!(glob("docs/**", "docs/spec/a.md"));
        assert!(glob("packages/i18n/**", "packages/i18n/en.json"));
        assert!(!glob("docs/**", "xdocs/a.md"));
    }

    // T-48 T-46
    #[test]
    fn t_48_dictionary_entries_need_rules_replacements_and_reasons() {
        let mut c = claim("x", &["y"], false);
        c.rules = vec!["Q-1".to_owned()];
        c.allow = vec![Allow {
            context: "z".to_owned(),
            reason: String::new(),
        }];
        let file = ClaimsFile {
            claim: vec![c],
            ..ClaimsFile::default()
        };
        assert_eq!(validate(&file, &BTreeSet::new()).len(), 2);
    }
}
