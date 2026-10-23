//! `disallowed-suppression` (T-32, T-52): the Clippy `disallowed-methods` and
//! `disallowed-types` lints that keep clock and randomness behind ports are
//! allowed or expected only in the reviewed Clock and Rng adapters, never through
//! a lint table or rustflags.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{extension, file_name, read, repo_files};
use crate::rules::lex::{find_token, lex, line_at};

const RULE: &str = "disallowed-suppression";

const LINTS: &[&str] = &["disallowed_methods", "disallowed_types"];

/// Clock and Rng adapters that may suppress the lints: (path, reason).
pub(crate) const ADAPTERS: &[(&str, &str)] = &[(
    "xtask/src/supply_cooldown.rs",
    "the developer tool is its own clock adapter for dependency ages",
)];

fn v(path: String, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    }
}

/// Lint suppressions in one Rust file: `allow`/`expect` attributes, directly or
/// through `cfg_attr`, naming a disallowed-methods or disallowed-types lint.
pub(crate) fn source_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    if ADAPTERS.iter().any(|(p, _)| *p == rel_path) {
        return Vec::new();
    }
    let code = lex(src).code;
    let mut out = Vec::new();
    for lint in LINTS {
        for at in find_token(&code, lint) {
            let before = code.get(..at).unwrap_or_default();
            let Some(open) = before.rfind("#[").max(before.rfind("#![")) else {
                continue;
            };
            let attr: String = before
                .get(open..)
                .unwrap_or_default()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let closed = attr.matches('[').count() <= attr.matches(']').count();
            if !closed && (attr.contains("allow(") || attr.contains("expect(")) {
                out.push(v(
                    format!("{rel_path}:{}", line_at(&code, at)),
                    format!(
                        "`clippy::{lint}` is suppressed outside the reviewed Clock and Rng adapters (T-32)"
                    ),
                ));
            }
        }
    }
    out
}

/// Lint-level overrides in a manifest or Cargo config: a `[lints.clippy]` or
/// `[workspace.lints.clippy]` entry below `warn`, or `-A`/`--allow` in rustflags.
pub(crate) fn config_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let squeezed: String = line
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .collect();
        for lint in LINTS {
            let dashed = lint.replace('_', "-");
            let level_off = [*lint, dashed.as_str()].iter().any(|k| {
                squeezed.starts_with(&format!("{k}=allow"))
                    || squeezed.starts_with(&format!("{k}={{level=allow"))
            });
            let flag_off = ["-A", "--allow", "-Aclippy", "--cap-lints"]
                .iter()
                .any(|f| squeezed.contains(f))
                && squeezed.contains(&format!("clippy::{lint}"));
            if level_off || flag_off {
                out.push(v(
                    format!("{rel_path}:{}", n.saturating_add(1)),
                    format!(
                        "`clippy::{lint}` is turned off; time and randomness come from ports (T-32)"
                    ),
                ));
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let name = file_name(&file);
        if extension(&file) == "rs" {
            out.extend(source_violations(&file, &read(&root.join(&file))?));
        } else if name == "Cargo.toml" || file.starts_with(".cargo/config") {
            out.extend(config_violations(&file, &read(&root.join(&file))?));
        }
    }
    for (path, _) in ADAPTERS {
        if !root.join(path).is_file() {
            out.push(v(
                (*path).to_owned(),
                "allowlisted adapter no longer exists; remove it from xtask/src/rules_clippy.rs"
                    .to_owned(),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-32 T-52
    #[test]
    fn t_32_disallowed_lint_suppressed_outside_adapters_is_rejected() {
        let src = "#[allow(clippy::disallowed_methods)]\nfn now() {}\n#[cfg_attr(test, expect(\n    clippy::disallowed_types,\n    reason = \"x\"\n))]\nfn rng() {}\n#![deny(clippy::disallowed_methods)]\n// allow(clippy::disallowed_methods)\nconst S: &str = \"#[allow(clippy::disallowed_methods)]\";\n";
        let v = source_violations("crates/timers/src/adapters/clock.rs", src);
        let lines: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(
            lines,
            [
                "crates/timers/src/adapters/clock.rs:1",
                "crates/timers/src/adapters/clock.rs:4"
            ]
        );
        assert!(source_violations("xtask/src/supply_cooldown.rs", src).is_empty());
    }

    // T-32 T-52
    #[test]
    fn t_32_lint_tables_and_rustflags_cannot_turn_the_lints_off() {
        let manifest = "[lints.clippy]\ndisallowed_methods = \"allow\"\ndisallowed-types = { level = \"allow\", priority = 1 }\npedantic = \"warn\"\n";
        assert_eq!(config_violations("crates/a/Cargo.toml", manifest).len(), 2);
        let config = "[build]\nrustflags = [\"-A\", \"clippy::disallowed_methods\"]\n";
        assert_eq!(config_violations(".cargo/config.toml", config).len(), 1);
        assert!(config_violations("Cargo.toml", "disallowed_methods = \"deny\"\n").is_empty());
    }
}
