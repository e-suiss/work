//! `comments` (T-53): code and configuration carry no explanatory comments; only
//! `// SAFETY:`, `///` docs and a one-paragraph `//!` per module, bare spec ID
//! lines, `TODO(#n): text`, shebangs and tool directives, and version notes on
//! pinned references.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::catalog::ids::is_bare_id_line;
use crate::rules::files::{extension, file_name, read, repo_files};
use crate::rules::lex::lex;

const RULE: &str = "comments";

const RUST_DIRECTIVES: &[&str] = &[
    "@generated",
    "ruleid:",
    "ok:",
    "todoruleid:",
    "todook:",
    "nosemgrep",
    "rustfmt::",
    "cspell:",
    "spellchecker:",
    "codespell:",
    "noqa",
    "prettier-ignore",
    "eslint-disable",
    "language=",
];

const HASH_DIRECTIVES: &[&str] = &[
    "!/",
    "ruleid:",
    "ok:",
    "syntax=",
    "check=",
    "escape=",
    "shellcheck ",
    "yaml-language-server:",
    "yamllint ",
    "hadolint ",
    "nosemgrep",
    "noqa",
    "type:",
    "pylint:",
    "fmt:",
    "-*-",
    "vim:",
    "renovate:",
    "actionlint",
    "zizmor:",
    "prettier-ignore",
    "codespell:",
    "cspell:",
    "taplo:",
    "tombi:",
    "@generated",
];

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

fn is_version_note(body: &str) -> bool {
    let t = body.trim();
    let digits = t.strip_prefix('v').unwrap_or(t);
    !t.contains(char::is_whitespace)
        && digits.chars().next().is_some_and(|c| c.is_ascii_digit())
        && digits
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
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

/// Comment violations in a Rust file.
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let lexed = lex(src);
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
        if !allowed_body(body, RUST_DIRECTIVES) {
            out.push(v(
                rel_path,
                c.line,
                format!(
                    "explanatory comment `{}`: only SAFETY, docs, bare spec IDs, TODO(#n) and tool directives (T-53)",
                    text.trim().chars().take(60).collect::<String>()
                ),
            ));
        }
    }
    flush(&mut module_doc, &mut out);
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

/// Comment violations in a `#`-comment file (TOML, YAML, shell, Python, justfile,
/// Dockerfile).
pub(crate) fn hash_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    let lines: Vec<&str> = text.lines().collect();
    let justfile = file_name(rel_path) == "justfile";
    let toml = extension(rel_path) == "toml";
    let mut in_string: Option<&str> = None;
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
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
        let body = comment.trim_start_matches('#');
        if allowed_body(body, HASH_DIRECTIVES) {
            continue;
        }
        let code = line.get(..at).unwrap_or_default();
        if has_pin(code) && is_version_note(body) {
            continue;
        }
        if justfile && at == 0 {
            let next = lines
                .iter()
                .skip(i.saturating_add(1))
                .find(|l| !l.trim_start().starts_with('#'));
            if next.is_some_and(|l| is_recipe_header(l)) {
                continue;
            }
        }
        out.push(v(
            rel_path,
            i.saturating_add(1),
            format!(
                "explanatory comment `{}`: only bare spec IDs, TODO(#n), shebangs, directives and version notes (T-53)",
                comment.trim().chars().take(60).collect::<String>()
            ),
        ));
    }
    out
}

/// Which comment syntax a repository file uses, if it is scanned.
fn syntax(rel_path: &str) -> Option<bool> {
    let name = file_name(rel_path);
    match extension(rel_path).as_str() {
        "rs" => Some(true),
        "toml" | "yml" | "yaml" | "sh" | "bash" | "py" => Some(false),
        _ if name == "justfile"
            || name.starts_with("Dockerfile")
            || name.ends_with(".dockerfile") =>
        {
            Some(false)
        }
        _ => None,
    }
}

/// Files written and regenerated by tools (`cargo vet`).
const TOOL_WRITTEN: &[&str] = &[
    "supply-chain/audits.toml",
    "supply-chain/config.toml",
    "supply-chain/imports.lock",
];

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)?
        .into_iter()
        .filter(|f| !TOOL_WRITTEN.contains(&f.as_str()))
    {
        let Some(is_rust) = syntax(&file) else {
            continue;
        };
        let text = read(&root.join(&file))?;
        if is_rust {
            out.extend(rust_violations(&file, &text));
        } else {
            out.extend(hash_violations(&file, &text));
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
}
