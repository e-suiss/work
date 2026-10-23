//! `forbidden-claims` (T-48, F-24, INV-34, SEC-33, SEC-34, MKT-1, T-42): tracked
//! documents, Rust and TypeScript docs and string literals, `OpenAPI` and
//! `AsyncAPI` documents and message catalogs never use a forbidden claim outside
//! its reasoned exceptions, whose context must sit in the same sentence; Markdown
//! never links to the local-only spec, relatively or through a GitHub URL; a
//! `COMPARISON.md` carries its set, date and counterexample.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::catalog::DIR;
use crate::catalog::ids::family;
use crate::rules::files::{extension, is_api_document, is_test_file, repo_files};
use crate::rules::lex::{Lexed, TS, decoded, in_regions, lex, lex_with, test_regions};
use crate::rules::switches::is_script_test;

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

/// Files to scan by the configured globs, and the candidates for `OpenAPI` and
/// `AsyncAPI` documents found by content: every other JSON and YAML file.
pub(crate) fn targets(files: &[String], scan: &Scan) -> (Vec<String>, Vec<String>) {
    let kept = files
        .iter()
        .filter(|f| !scan.exclude.iter().any(|g| glob(g, f)));
    let (listed, rest): (Vec<&String>, Vec<&String>) = kept.partition(|f| {
        scan.extensions.iter().any(|e| *e == extension(f))
            && scan.include.iter().any(|g| glob(g, f))
    });
    let api = rest
        .into_iter()
        .filter(|f| matches!(extension(f).as_str(), "json" | "yaml" | "yml"))
        .cloned()
        .collect();
    (listed.into_iter().cloned().collect(), api)
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

/// The sentence of normalized `text` around byte offset `at`.
fn sentence(text: &str, at: usize) -> &str {
    let ends = |i: usize| {
        text.get(i..i.saturating_add(1))
            .is_some_and(|c| matches!(c, "." | "!" | "?" | ";"))
            && text
                .get(i.saturating_add(1)..)
                .is_none_or(|r| r.is_empty() || r.starts_with(' '))
    };
    let start = (0..at)
        .rev()
        .find(|&i| ends(i))
        .map_or(0, |i| i.saturating_add(1));
    let end = (at..text.len()).find(|&i| ends(i)).unwrap_or(text.len());
    text.get(start..end).unwrap_or(text)
}

/// True when an allowed context stands, as whole words, in the sentence of the
/// match at `at`.
pub(crate) fn context_allows(claim: &Claim, norm: &str, at: usize) -> bool {
    let s = sentence(norm, at);
    claim
        .allow
        .iter()
        .any(|a| !find_all(s, normalize(&a.context).trim()).is_empty())
}

/// Claims found in text fragments `(first line, text)`: (line, claim id, phrase).
pub(crate) fn claims_in(
    path: &str,
    fragments: &[(usize, String)],
    claims: &[Claim],
) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (start, para) in fragments {
        let (norm, starts) = normalize_lines(para);
        for claim in claims {
            if claim.exception.iter().any(|e| glob(&e.path, path)) {
                continue;
            }
            for phrase in &claim.phrases {
                for at in find_all(&norm, &normalize(phrase)) {
                    if (claim.negation && negated(&norm, at)) || context_allows(claim, &norm, at) {
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

/// Claims found in plain text, paragraph by paragraph.
#[cfg(test)]
pub(crate) fn find_claims(
    path: &str,
    text: &str,
    claims: &[Claim],
) -> Vec<(usize, String, String)> {
    claims_in(path, &paragraphs(text), claims)
}

/// Doc comment runs (`///`, `//!`, `/** */`, `/*! */`) of a lexed Rust file.
fn rust_docs(lexed: &Lexed) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut last_line = 0_usize;
    for c in &lexed.comments {
        let line_doc = c
            .text
            .strip_prefix("///")
            .or_else(|| c.text.strip_prefix("//!"));
        let block_doc = c
            .text
            .strip_prefix("/**")
            .or_else(|| c.text.strip_prefix("/*!"))
            .map(|b| b.trim_end_matches("*/"));
        if let Some(body) = line_doc {
            let continues = c.line == last_line.saturating_add(1) && !body.trim().is_empty();
            match out.last_mut() {
                Some((_, text)) if continues => {
                    text.push('\n');
                    text.push_str(body);
                }
                _ if body.trim().is_empty() => {}
                _ => out.push((c.line, body.to_owned())),
            }
            last_line = c.line;
        } else if let Some(body) = block_doc {
            out.push((c.line, block_text(body)));
        }
    }
    out
}

fn block_text(body: &str) -> String {
    body.lines()
        .map(|l| l.trim_start().trim_start_matches('*'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The text fragments a file contributes: Rust docs and non-test string literals
/// (`#[doc = "…"]` included), TypeScript `/** */` docs and string literals,
/// camelCase-split API and message files, and paragraphs of everything else.
pub(crate) fn fragments(path: &str, text: &str) -> Vec<(usize, String)> {
    match extension(path).as_str() {
        "rs" => {
            let lexed = lex(text);
            let tests = test_regions(&lexed.code);
            let mut out = rust_docs(&lexed);
            if !is_test_file(path) {
                out.extend(
                    lexed
                        .strings
                        .iter()
                        .filter(|l| !in_regions(&tests, l.line))
                        .map(|l| (l.line, decoded(l))),
                );
            }
            out
        }
        "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs" => {
            let lexed = lex_with(text, &TS);
            let mut out: Vec<(usize, String)> = lexed
                .comments
                .iter()
                .filter_map(|c| {
                    c.text
                        .strip_prefix("/**")
                        .map(|b| (c.line, block_text(b.trim_end_matches("*/"))))
                })
                .collect();
            if !is_script_test(path) {
                out.extend(lexed.strings.iter().map(|l| (l.line, l.text.clone())));
            }
            out
        }
        "json" | "yml" | "yaml" => paragraphs(&split_camel(text)),
        _ => paragraphs(text),
    }
}

/// Link targets in a Markdown line: `](target)`, `]: target` and `href="target"`.
fn link_targets(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for (open, close) in [("](", ")"), ("href=\"", "\""), ("href='", "'")] {
        let mut rest = line;
        while let Some(at) = rest.find(open) {
            let after = rest
                .get(at.saturating_add(open.len())..)
                .unwrap_or_default();
            let end = after.find(close).unwrap_or(after.len());
            out.push(after.get(..end).unwrap_or_default().trim());
            rest = after.get(end..).unwrap_or_default();
        }
    }
    let t = line.trim_start();
    if t.starts_with('[')
        && let Some(at) = t.find("]: ")
    {
        out.push(t.get(at.saturating_add(3)..).unwrap_or_default().trim());
    }
    out
}

const GITHUB_HOSTS: &[(&str, usize)] = &[
    ("https://github.com/", 4),
    ("http://github.com/", 4),
    ("https://raw.githubusercontent.com/", 3),
];

/// The repository path a link target points to from `file`: a local path, or the
/// path inside a GitHub `blob`/`tree`/`raw` URL.
fn link_path(file: &str, target: &str) -> Option<String> {
    let target = target
        .split(['#', '?', ' '])
        .next()
        .unwrap_or_default()
        .trim_matches(['<', '>']);
    for (host, skip) in GITHUB_HOSTS {
        if let Some(rest) = target.strip_prefix(host) {
            let parts: Vec<&str> = rest.split('/').collect();
            let raw = *skip == 3;
            let blob = raw || matches!(parts.get(2), Some(&("blob" | "tree" | "raw")));
            return blob.then(|| parts.get(*skip..).unwrap_or_default().join("/"));
        }
    }
    if target.contains("://") || target.starts_with("mailto:") || target.is_empty() {
        return None;
    }
    let rooted = target.starts_with('/');
    let mut parts: Vec<&str> = if rooted {
        Vec::new()
    } else {
        let mut dir: Vec<&str> = file.split('/').collect();
        dir.pop();
        dir
    };
    for seg in target.trim_start_matches('/').split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// Lines of Markdown links into the local-only `docs/` (T-42): relative links,
/// root links and GitHub URLs.
pub(crate) fn docs_links(file: &str, text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            link_targets(l)
                .into_iter()
                .any(|t| link_path(file, t).is_some_and(|p| p == "docs" || p.starts_with("docs/")))
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
        for (line, id, phrase) in claims_in(path, &fragments(path, text), &file.claim) {
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
        if matches!(extension(path).as_str(), "md" | "mdx") {
            for line in docs_links(path, text) {
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
    let (listed, api) = targets(&all, &file.scan);
    for path in listed {
        if let Ok(text) = std::fs::read_to_string(root.join(&path)) {
            texts.push((path, text));
        }
    }
    for path in api {
        if let Ok(text) = std::fs::read_to_string(root.join(&path))
            && is_api_document(&path, &text)
        {
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
                let norm = normalize(&text);
                let allowed_by_context = find_all(&norm, &normalize(phrase))
                    .first()
                    .is_some_and(|at| context_allows(c, &norm, *at));
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
            claims_in(
                "sdks/openapi/work.yaml",
                &fragments("sdks/openapi/work.yaml", api),
                &claims
            )
            .len(),
            2
        );
        let rs = "/// The body is permanently deleted.\nfn f() { let s = \"permanently deleted\"; }\n#[cfg(test)]\nmod tests { const S: &str = \"permanently deleted\"; }\n";
        assert_eq!(
            claims_in(
                "crates/a/src/lib.rs",
                &fragments("crates/a/src/lib.rs", rs),
                &claims
            )
            .len(),
            2
        );
    }

    // SEC-34 T-48
    #[test]
    fn sec_34_string_literals_doc_attributes_tsdoc_and_api_documents_are_scanned() {
        let claims = [claim("exactly-once", &["exactly once"], true)];
        let rs = "#[doc = \"Delivery is exactly once.\"]\npub struct D;\n/** Delivered\n * exactly once. */\npub struct E;\nconst M: &str = \"sent exactly once\";\n";
        let found = claims_in(
            "crates/a/src/lib.rs",
            &fragments("crates/a/src/lib.rs", rs),
            &claims,
        );
        let lines: Vec<usize> = found.iter().map(|(l, _, _)| *l).collect();
        assert_eq!(lines, [4, 1, 6], "{found:?}");
        let ts = "/** Delivery is exactly once. */\nexport const m = \"exactly once\";\n// exactly once in a comment\n";
        assert_eq!(
            claims_in(
                "packages/a/src/i.ts",
                &fragments("packages/a/src/i.ts", ts),
                &claims
            )
            .len(),
            2
        );
        let test = "it(\"is exactly once\", () => {});\n";
        assert!(
            claims_in(
                "packages/a/src/i.test.ts",
                &fragments("packages/a/src/i.test.ts", test),
                &claims
            )
            .is_empty()
        );
        let scan = Scan {
            include: vec!["*.md".to_owned()],
            exclude: vec!["docs/**".to_owned()],
            extensions: vec!["md".to_owned()],
        };
        let files = vec![
            "README.md".to_owned(),
            "deploy/api/work.yaml".to_owned(),
            "docs/api.yaml".to_owned(),
        ];
        let (listed, api) = targets(&files, &scan);
        assert_eq!(listed, ["README.md"]);
        assert_eq!(api, ["deploy/api/work.yaml"]);
    }

    // T-48
    #[test]
    fn t_48_allowed_context_counts_only_in_the_same_sentence_as_whole_words() {
        let mut c = claim("exactly-once", &["exactly once"], true);
        c.allow = vec![Allow {
            context: "idempotency key".to_owned(),
            reason: "x".to_owned(),
        }];
        let claims = [c];
        assert!(
            find_claims(
                "a.md",
                "Delivered exactly once with an idempotency key.",
                &claims
            )
            .is_empty()
        );
        assert_eq!(
            find_claims(
                "a.md",
                "Delivered exactly once. Retries carry an idempotency key.",
                &claims
            )
            .len(),
            1
        );
        assert_eq!(
            find_claims(
                "a.md",
                "Delivered exactly once with idempotency keystore.",
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
            docs_links(
                "README.md",
                "See [spec](docs/spec/README.md).\n[ok](CONTRIBUTING.md)\n"
            ),
            [1]
        );
        let nested = "[a](../../docs/spec/x.md)\n[b](../docs/x.md)\n[c](https://github.com/e-suiss/work/blob/main/docs/spec/README.md)\n[d]: /docs/decision-log.md\n<a href=\"./docs/x\">e</a>\n[f](https://github.com/e-suiss/work/issues/1)\n[g](https://example.com/docs/x)\n";
        assert_eq!(docs_links("crates/kernel/README.md", nested), [1, 3, 4]);
        assert_eq!(docs_links("README.md", "<a href=\"./docs/x\">e</a>\n"), [1]);
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
