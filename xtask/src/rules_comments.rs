//! `comments` (T-53): code and configuration carry no explanatory comments; only
//! `// SAFETY:`, `///` docs and a one-paragraph `//!` per module in Rust, `/** */`
//! docs on TypeScript exports, bare spec ID lines, to-dos with an issue, shebangs and
//! the tool directives of each file type, and version notes on pinned references.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::catalog::ids::is_bare_id_line;
use crate::rules::files::{extension, file_name, read, repo_files};
use crate::rules::lex::{Lexed, Syntax, lex, lex_with, syntax_of};

const RULE: &str = "comments";

const RUST_DIRECTIVES: &[&str] = &[
    "@generated",
    "nosemgrep",
    "rustfmt::",
    "cspell:",
    "spellchecker:",
    "codespell:",
    "language=",
];

const SEMGREP_DIRECTIVES: &[&str] = &["ruleid:", "ok:", "todoruleid:", "todook:"];

const COMMON_DIRECTIVES: &[&str] = &["@generated", "nosemgrep", "cspell:", "codespell:"];

const TS_DIRECTIVES: &[&str] = &[
    "eslint-disable",
    "eslint-enable",
    "prettier-ignore",
    "@ts-expect-error",
    "@vitest-environment",
    "c8 ignore",
];

const SWIFT_DIRECTIVES: &[&str] = &["swiftlint:", "swift-format-ignore"];

const KOTLIN_DIRECTIVES: &[&str] = &[
    "ktlint-disable",
    "ktlint-enable",
    "@formatter:",
    "noinspection",
];

const PROTO_DIRECTIVES: &[&str] = &["buf:lint:ignore"];

const SQL_DIRECTIVES: &[&str] = &["squawk-ignore", "sqlfluff:"];

const HTML_DIRECTIVES: &[&str] = &["prettier-ignore"];

const HASH_DIRECTIVES: &[&str] = &[
    "!/",
    "nosemgrep",
    "-*-",
    "vim:",
    "renovate:",
    "prettier-ignore",
    "codespell:",
    "cspell:",
    "@generated",
];

const PYTHON_DIRECTIVES: &[&str] = &["noqa", "type:", "pylint:", "fmt:"];
const SHELL_DIRECTIVES: &[&str] = &["shellcheck "];
const DOCKER_DIRECTIVES: &[&str] = &["syntax=", "check=", "escape=", "hadolint "];
const YAML_DIRECTIVES: &[&str] = &[
    "yaml-language-server:",
    "yamllint ",
    "actionlint",
    "zizmor:",
];
const TOML_DIRECTIVES: &[&str] = &["taplo:", "tombi:"];

/// How a scanned file writes comments.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    Rust,
    Generic(&'static Syntax),
    Hash,
}

fn is_container_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("dockerfile")
        || lower.starts_with("containerfile")
        || lower.ends_with(".dockerfile")
        || lower.ends_with(".containerfile")
}

/// True for Dockerfiles and Containerfiles, by name, case-insensitively.
pub(crate) fn is_dockerfile(rel_path: &str) -> bool {
    is_container_file(file_name(rel_path))
}

/// Which comment syntax a repository file uses, if it is scanned.
pub(crate) fn kind(rel_path: &str) -> Option<Kind> {
    let name = file_name(rel_path);
    let ext = extension(rel_path);
    if ext == "rs" {
        return Some(Kind::Rust);
    }
    if let Some(syn) = syntax_of(rel_path) {
        return Some(Kind::Generic(syn));
    }
    let hook = rel_path.starts_with(".githooks/") && !name.contains('.');
    let hash_ext = matches!(
        ext.as_str(),
        "toml" | "yml" | "yaml" | "sh" | "bash" | "py" | "conf"
    );
    (hash_ext || hook || name == "justfile" || is_container_file(name)).then_some(Kind::Hash)
}

fn hash_directives(rel_path: &str) -> Vec<&'static str> {
    let name = file_name(rel_path);
    let mut out = HASH_DIRECTIVES.to_vec();
    let extra: &[&str] = match extension(rel_path).as_str() {
        "py" => PYTHON_DIRECTIVES,
        "sh" | "bash" => SHELL_DIRECTIVES,
        "yml" | "yaml" => YAML_DIRECTIVES,
        "toml" => TOML_DIRECTIVES,
        _ if is_container_file(name) => DOCKER_DIRECTIVES,
        _ if name == "justfile" || rel_path.starts_with(".githooks/") => SHELL_DIRECTIVES,
        _ => &[],
    };
    out.extend_from_slice(extra);
    if rel_path.starts_with(".semgrep/") {
        out.extend_from_slice(SEMGREP_DIRECTIVES);
    }
    out
}

fn generic_directives(rel_path: &str, syn: &Syntax) -> Vec<&'static str> {
    let mut out = COMMON_DIRECTIVES.to_vec();
    let extra: &[&str] = match syn.name {
        "ts" => TS_DIRECTIVES,
        "swift" => SWIFT_DIRECTIVES,
        "kotlin" => KOTLIN_DIRECTIVES,
        "proto" => PROTO_DIRECTIVES,
        "sql" => SQL_DIRECTIVES,
        "html" => HTML_DIRECTIVES,
        _ => &[],
    };
    out.extend_from_slice(extra);
    if rel_path.starts_with(".semgrep/") {
        out.extend_from_slice(SEMGREP_DIRECTIVES);
    }
    out
}

/// The `#` comment on a line: its byte offset and text, when `#` starts the line
/// or follows whitespace outside quotes and is not a Rust attribute (`#[`).
pub(crate) fn hash_comment(line: &str) -> Option<(usize, &str)> {
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#'
                && prev_space
                && !line.get(i..).is_some_and(|t| t.starts_with("#[")) =>
            {
                return line.get(i..).map(|t| (i, t));
            }
            _ => {}
        }
        prev_space = c.is_whitespace();
    }
    None
}

fn is_version_note(body: &str, code: &str) -> bool {
    let t = body.trim();
    let token = !t.is_empty()
        && !t.contains(char::is_whitespace)
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'));
    let digits = t.strip_prefix('v').unwrap_or(t);
    let versioned = digits.chars().next().is_some_and(|c| c.is_ascii_digit());
    let image_note = code.contains("@sha256:") && t.chars().any(|c| c.is_ascii_digit());
    token && has_pin(code) && (versioned || image_note)
}

fn has_pin(code: &str) -> bool {
    code.contains("@sha256:")
        || code.match_indices('@').any(|(at, _)| {
            let rest = code.get(at.saturating_add(1)..).unwrap_or_default();
            let hex: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            hex.len() == 40
        })
}

fn allowed_body(body: &str, directives: &[&str]) -> bool {
    let t = body.trim();
    t.starts_with("SAFETY:")
        || t.starts_with("TODO")
        || is_bare_id_line(t)
        || directives.iter().any(|d| t.starts_with(d))
}

fn v(path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(format!("{path}:{line}")),
        message,
    }
}

fn explanatory(rel_path: &str, line: usize, text: &str) -> Violation {
    v(
        rel_path,
        line,
        format!(
            "explanatory comment `{}`: only SAFETY, docs, bare spec IDs, TODO(#n), directives and version notes (T-53)",
            text.trim().chars().take(60).collect::<String>()
        ),
    )
}

fn rust_directives(rel_path: &str) -> Vec<&'static str> {
    let mut out = RUST_DIRECTIVES.to_vec();
    if rel_path.starts_with(".semgrep/") {
        out.extend_from_slice(SEMGREP_DIRECTIVES);
    }
    out
}

/// Comment violations in a Rust file.
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let lexed = lex(src);
    let directives = rust_directives(rel_path);
    let mut module_doc: Vec<(usize, bool)> = Vec::new();
    let flush = |block: &mut Vec<(usize, bool)>, out: &mut Vec<Violation>| {
        let first_text = block.iter().position(|(_, empty)| !empty);
        let last_text = block.iter().rposition(|(_, empty)| !empty);
        if let (Some(a), Some(b)) = (first_text, last_text)
            && block
                .get(a..=b)
                .is_some_and(|inner| inner.iter().any(|(_, empty)| *empty))
        {
            let line = block.first().map_or(0, |(l, _)| *l);
            out.push(v(
                rel_path,
                line,
                "module docs (`//!`) are one paragraph (T-53)".to_owned(),
            ));
        }
        block.clear();
    };
    let mut last_doc_line = 0_usize;
    for c in &lexed.comments {
        let text = c.text.as_str();
        if let Some(body) = text.strip_prefix("//!") {
            if !module_doc.is_empty() && c.line != last_doc_line.saturating_add(1) {
                flush(&mut module_doc, &mut out);
            }
            module_doc.push((c.line, body.trim().is_empty()));
            last_doc_line = c.line;
            continue;
        }
        if text.starts_with("///") || text.starts_with("/**") || text.starts_with("/*!") {
            continue;
        }
        let body = if let Some(b) = text.strip_prefix("//") {
            b
        } else {
            text.trim_start_matches("/*").trim_end_matches("*/")
        };
        if !allowed_body(body, &directives) {
            out.push(explanatory(rel_path, c.line, text));
        }
    }
    flush(&mut module_doc, &mut out);
    out
}

/// The first non-blank line of the code view after `line` (1-based), trimmed.
fn next_code_line(lexed: &Lexed, line: usize) -> &str {
    lexed
        .code
        .lines()
        .skip(line)
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default()
}

/// The text of a comment without its markers.
fn comment_body<'a>(text: &'a str, syn: &Syntax) -> &'a str {
    if let Some(p) = syn.line.iter().find(|p| text.starts_with(*p)) {
        return text.get(p.len()..).unwrap_or_default();
    }
    match syn.block {
        Some((open, close)) => text
            .strip_prefix(open)
            .unwrap_or(text)
            .strip_suffix(close)
            .unwrap_or(text),
        None => text,
    }
}

/// Comment violations in a C-family, SQL, CDDL or HTML file.
pub(crate) fn generic_violations(rel_path: &str, src: &str, syn: &Syntax) -> Vec<Violation> {
    let lexed = lex_with(src, syn);
    let directives = generic_directives(rel_path, syn);
    let mut out = Vec::new();
    for c in &lexed.comments {
        let text = c.text.as_str();
        if syn.name == "ts" && text.starts_with("/**") {
            let end = c.line.saturating_add(text.matches('\n').count());
            if next_code_line(&lexed, end).starts_with("export ") {
                continue;
            }
            out.push(v(
                rel_path,
                c.line,
                "`/** */` docs belong on exported declarations (T-53)".to_owned(),
            ));
            continue;
        }
        if syn.name == "ts" && text.starts_with("/// <reference ") {
            continue;
        }
        let body = comment_body(text, syn);
        if body.lines().count() > 1 || !allowed_body(body, &directives) {
            out.push(explanatory(rel_path, c.line, text));
        }
    }
    out
}

/// The TOML multi-line string delimiter open after `line`, given the one open before it.
fn toml_string_state<'a>(line: &str, open: Option<&'a str>) -> Option<&'a str> {
    let mut state = open;
    let mut rest = line;
    loop {
        if let Some(delim) = state {
            let Some(at) = rest.find(delim) else {
                return state;
            };
            rest = rest.get(at.saturating_add(3)..).unwrap_or_default();
            state = None;
        } else {
            let code = hash_comment(rest).map_or(rest, |(at, _)| rest.get(..at).unwrap_or(rest));
            let (at, delim) = [DOUBLE_QUOTES, SINGLE_QUOTES]
                .into_iter()
                .filter_map(|d| code.find(d).map(|at| (at, d)))
                .min_by_key(|(at, _)| *at)?;
            rest = rest.get(at.saturating_add(3)..).unwrap_or_default();
            state = Some(delim);
        }
    }
}

const DOUBLE_QUOTES: &str = "\"\"\"";
const SINGLE_QUOTES: &str = "'''";

fn is_recipe_header(line: &str) -> bool {
    let first = line.chars().next();
    first.is_some_and(|c| c.is_ascii_alphanumeric() || c == '@' || c == '_')
        && line.contains(':')
        && !line.contains(":=")
}

/// A `#` comment: 1-based line, byte offset, the comment text and the line.
struct HashComment<'a> {
    line: usize,
    at: usize,
    text: &'a str,
    source: &'a str,
}

/// The `#` comments of a file, skipping TOML multi-line strings and the shebang.
fn hash_comments_of<'a>(rel_path: &str, text: &'a str) -> Vec<HashComment<'a>> {
    let toml = extension(rel_path) == "toml";
    let mut in_string: Option<&str> = None;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if toml {
            let was_inside = in_string.is_some();
            in_string = toml_string_state(line, in_string);
            if was_inside {
                continue;
            }
        }
        let Some((at, comment)) = hash_comment(line) else {
            continue;
        };
        if i == 0 && comment.starts_with("#!") && at == 0 {
            continue;
        }
        out.push(HashComment {
            line: i.saturating_add(1),
            at,
            text: comment,
            source: line,
        });
    }
    out
}

/// Comment violations in a `#`-comment file (TOML, YAML, shell, Python, justfile,
/// Dockerfile, Git hook, `.conf`).
pub(crate) fn hash_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    let lines: Vec<&str> = text.lines().collect();
    let justfile = file_name(rel_path) == "justfile";
    let directives = hash_directives(rel_path);
    let mut out = Vec::new();
    for c in hash_comments_of(rel_path, text) {
        let body = c.text.trim_start_matches('#');
        if allowed_body(body, &directives) {
            continue;
        }
        let code = c.source.get(..c.at).unwrap_or_default();
        if is_version_note(body, code) {
            continue;
        }
        if justfile && c.at == 0 {
            let next = lines
                .iter()
                .skip(c.line)
                .find(|l| !l.trim_start().starts_with('#'));
            if next.is_some_and(|l| is_recipe_header(l)) {
                continue;
            }
        }
        out.push(explanatory(rel_path, c.line, c.text));
    }
    out
}

/// Every comment of a scanned file as (line, text with its markers); `None` for
/// files the comment rules do not read.
pub(crate) fn comments_of(rel_path: &str, text: &str) -> Option<Vec<(usize, String)>> {
    let comments = match kind(rel_path)? {
        Kind::Rust => lex(text)
            .comments
            .into_iter()
            .map(|c| (c.line, c.text))
            .collect(),
        Kind::Generic(syn) => lex_with(text, syn)
            .comments
            .into_iter()
            .map(|c| (c.line, c.text))
            .collect(),
        Kind::Hash => hash_comments_of(rel_path, text)
            .into_iter()
            .map(|c| (c.line, c.text.to_owned()))
            .collect(),
    };
    Some(comments)
}

/// Files written and regenerated by tools (`cargo vet`).
const TOOL_WRITTEN: &[&str] = &[
    "supply-chain/audits.toml",
    "supply-chain/config.toml",
    "supply-chain/imports.lock",
];

/// The files both comment rules read: tracked and unignored files with a known
/// comment syntax, without tool-written files.
pub(crate) fn scanned_files(root: &Path) -> Result<Vec<String>, String> {
    Ok(repo_files(root)?
        .into_iter()
        .filter(|f| !TOOL_WRITTEN.contains(&f.as_str()) && kind(f).is_some())
        .collect())
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in scanned_files(root)? {
        let text = read(&root.join(&file))?;
        match kind(&file) {
            Some(Kind::Rust) => out.extend(rust_violations(&file, &text)),
            Some(Kind::Generic(syn)) => out.extend(generic_violations(&file, &text, syn)),
            Some(Kind::Hash) => out.extend(hash_violations(&file, &text)),
            None => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-53
    #[test]
    fn t_53_explanatory_rust_comments_are_rejected() {
        let src = "//! Module docs in one paragraph.\n\n/// Item docs.\nfn f() {\n    // T-31\n    // T-36 OP-12\n    // SAFETY: no preconditions.\n    // TODO(#12): short text\n    // this explains why we loop\n    /* a block note */\n    let x = 1; // rustfmt::skip\n}\n";
        let v = rust_violations("a.rs", src);
        let lines: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(lines, ["a.rs:9", "a.rs:10"]);
    }

    // T-53
    #[test]
    fn t_53_module_docs_with_two_paragraphs_are_rejected() {
        let src = "//! First paragraph.\n//!\n//! Second paragraph.\nfn f() {}\n";
        assert_eq!(rust_violations("a.rs", src).len(), 1);
        let one = "//! One paragraph\n//! over two lines.\n//!\nfn f() {}\n";
        assert!(rust_violations("a.rs", one).is_empty());
    }

    // T-53
    #[test]
    fn t_53_comments_inside_strings_are_not_comments() {
        let src = "const S: &str = \"// not a comment\";\nconst R: &str = r#\"# nor this\"#;\n";
        assert!(rust_violations("a.rs", src).is_empty());
    }

    // T-53 T-60
    #[test]
    fn t_53_hash_comments_allow_ids_directives_and_version_notes() {
        let yaml = "# T-41\n# yaml-language-server: $schema=x\nname: ci # T-40\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0\n      - run: echo \"#not\" # explain this step\n    services:\n      pg:\n        image: postgres@sha256:abc # 18.6-trixie\n";
        let v = hash_violations(".github/workflows/ci.yml", yaml);
        let lines: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(lines, [".github/workflows/ci.yml:8"]);
    }

    // T-53
    #[test]
    fn t_53_shebang_and_dockerfile_directives_pass_but_prose_fails() {
        let sh = "#!/usr/bin/env bash\n# shellcheck disable=SC2086\n# T-56\nset -eu\n# create the token\n";
        assert_eq!(hash_violations("deploy/a.sh", sh).len(), 1);
        let docker = "# syntax=docker/dockerfile:1\nFROM debian@sha256:abc # 13.1\n";
        assert!(hash_violations("deploy/Dockerfile", docker).is_empty());
        let toml = "# A product whose image is not published yet stays in a profile.\n[access]\n";
        assert_eq!(hash_violations("compat.toml", toml).len(), 1);
    }

    // T-53
    #[test]
    fn t_53_toml_strings_attributes_and_tool_annotations_are_not_comments() {
        let toml =
            "# T-40\nheader = \"\"\"\n# Changelog\n\"\"\"\nbody = '''\n## x\n''' # T-40\n# stray\n";
        let v = hash_violations("cliff.toml", toml);
        let lines: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(lines, ["cliff.toml:8"]);
        let yaml = "rules:\n  - pattern: |\n      #[derive(..., Debug, ...)]\n";
        assert!(hash_violations(".semgrep/rules.yml", yaml).is_empty());
        let rs = "// ruleid: sql-outside-store\nfn f() {}\n// ok: sql-outside-store\nfn g() {}\n";
        assert!(rust_violations(".semgrep/rules.rs", rs).is_empty());
        assert_eq!(rust_violations("crates/store/src/a.rs", rs).len(), 2);
        assert_eq!(
            hash_violations("deploy/a.yml", "# ruleid: x\nname: a\n").len(),
            1
        );
        let just = "x:\n    #!/usr/bin/env bash\n    set -eu\n";
        assert!(hash_violations("justfile", just).is_empty());
    }

    // T-53
    #[test]
    fn t_53_version_note_needs_a_pinned_reference() {
        let v = hash_violations("a.yml", "- uses: actions/checkout@v5 # v5.0.0\n");
        assert_eq!(v.len(), 1);
    }

    // T-53 T-41
    #[test]
    fn t_53_justfile_recipe_docs_are_tool_docs() {
        let just = "# T-41\n\n# Start the local environment\ndev:\n    docker compose up\n\n# stray note\nx := \"1\"\n";
        let v = hash_violations("justfile", just);
        let lines: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(lines, ["justfile:7"]);
    }

    // T-53
    #[test]
    fn t_53_typescript_comments_allow_ids_directives_and_export_docs_only() {
        let ts = "// T-5 T-34\n/** A record. */\nexport type R = string;\n/** Not exported. */\nconst x = 1;\n// eslint-disable-next-line no-console\nconst s = \"// not a comment\";\nconst t = `/* nor ${x} this */`;\n// load the module once\n/* a block note */\n/// <reference types=\"vite/client\" />\n";
        let v = generic_violations("packages/kernel/src/a.ts", ts, &crate::rules::lex::TS);
        let lines: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(
            lines,
            [
                "packages/kernel/src/a.ts:4",
                "packages/kernel/src/a.ts:9",
                "packages/kernel/src/a.ts:10"
            ]
        );
        assert!(kind("packages/kernel/eslint.config.mjs").is_some());
    }

    // T-53
    #[test]
    fn t_53_swift_kotlin_proto_sql_cddl_and_html_comments_are_scanned() {
        let cases = [
            (
                "sdks/a/main.swift",
                "// T-5\nlet s = \"\"\"\n// in a string\n\"\"\"\n// check the vectors\n",
            ),
            ("sdks/a/Main.kt", "// T-5\n/* explain */\nval x = 1\n"),
            (
                "proto/work.proto",
                "// buf:lint:ignore FIELD_LOWER_SNAKE_CASE\n// the work message\n",
            ),
            (
                "crates/store/migrations/1.sql",
                "-- T-36\nSELECT '-- not a comment';\n-- create the table\n",
            ),
            (
                "conformance/cddl/a.cddl",
                "; P-5\nrecord = { \"a;b\": int }\n; explain the map\n",
            ),
            (
                "packages/a/index.html",
                "<!-- T-5 -->\n<p>x</p>\n<!-- the app root -->\n",
            ),
        ];
        for (path, src) in cases {
            let Some(Kind::Generic(syn)) = kind(path) else {
                panic!("{path} is not scanned");
            };
            let v = generic_violations(path, src, syn);
            assert_eq!(v.len(), 1, "{path}: {v:?}");
        }
    }

    // T-53
    #[test]
    fn t_53_git_hooks_conf_files_and_containerfiles_use_hash_comments() {
        for path in [
            ".githooks/pre-commit",
            "deploy/compose/nats/nats.conf",
            "deploy/app.Dockerfile",
            "deploy/Containerfile",
        ] {
            assert!(matches!(kind(path), Some(Kind::Hash)), "{path}");
            let text = "#!/bin/sh\n# T-41\n# explain the hook\n";
            assert_eq!(hash_violations(path, text).len(), 1, "{path}");
        }
        assert!(kind(".githooks/README.md").is_none());
    }

    // T-53
    #[test]
    fn t_53_directives_are_allowed_only_for_their_file_type() {
        assert_eq!(
            hash_violations("deploy/a.yml", "# shellcheck disable=SC2086\n").len(),
            1
        );
        assert!(hash_violations("deploy/a.sh", "# shellcheck disable=SC2086\n").is_empty());
        assert_eq!(
            hash_violations("deploy/a.toml", "# hadolint ignore=DL3008\n").len(),
            1
        );
        assert!(hash_violations("deploy/Dockerfile", "# hadolint ignore=DL3008\n").is_empty());
        assert_eq!(
            rust_violations("crates/a/src/lib.rs", "// eslint-disable-next-line\n").len(),
            1
        );
    }

    // T-53 T-60
    #[test]
    fn t_53_image_version_notes_follow_digest_pins() {
        let yaml = "image: postgres@sha256:abc # 18.6-trixie\nimage: x@sha256:abc # trixie-20251020\nimage: postgres:18 # 18.6-trixie\nimage: x@sha256:abc # pinned for now\n";
        let v = hash_violations("deploy/compose/compose.yaml", yaml);
        let lines: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(
            lines,
            [
                "deploy/compose/compose.yaml:3",
                "deploy/compose/compose.yaml:4"
            ]
        );
    }
}
