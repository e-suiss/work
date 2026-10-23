//! `panic-profile` (T-33 rule 4): release builds keep overflow checks and no
//! profile, rustflag or `CARGO_PROFILE_*` variable aborts on panic or turns
//! overflow checks off, so a panic fails one request, not the process.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::comments::is_dockerfile;
use crate::rules::files::{extension, read, repo_files};

const RULE: &str = "panic-profile";

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    }
}

/// Checks the `[profile.*]` tables of a manifest or Cargo config.
pub(crate) fn profile_violations(
    path: &str,
    text: &str,
    require_release: bool,
) -> Result<Vec<Violation>, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("{path}: {e}"))?;
    let mut out = Vec::new();
    let profiles = table.get("profile").and_then(toml::Value::as_table);
    if require_release {
        let overflow = profiles
            .and_then(|p| p.get("release"))
            .and_then(|r| r.get("overflow-checks"))
            .and_then(toml::Value::as_bool);
        if overflow != Some(true) {
            out.push(v(
                path,
                "[profile.release] must set overflow-checks = true (T-33 rule 4)".to_owned(),
            ));
        }
    }
    for (name, profile) in profiles.into_iter().flatten() {
        if profile
            .get("overflow-checks")
            .and_then(toml::Value::as_bool)
            == Some(false)
        {
            out.push(v(
                path,
                format!("[profile.{name}] disables overflow checks (T-33 rule 4)"),
            ));
        }
        if profile.get("panic").and_then(toml::Value::as_str) == Some("abort") {
            out.push(v(
                path,
                format!(
                    "[profile.{name}] sets panic = \"abort\"; network processes unwind (T-33 rule 4)"
                ),
            ));
        }
    }
    Ok(out)
}

const OFF: &[&str] = &["off", "no", "n", "false", "0"];

fn is_off(value: &str) -> bool {
    let v: String = value
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    OFF.contains(&v.as_str())
}

/// The setting after `key` followed by `=` or `:`, when `key` occurs in `line`.
fn settings<'a>(line: &'a str, key: &str) -> Vec<&'a str> {
    line.match_indices(key)
        .filter_map(|(at, _)| {
            let rest = line.get(at.saturating_add(key.len())..)?;
            rest.strip_prefix('=').or_else(|| rest.strip_prefix(':'))
        })
        .collect()
}

/// Rejects `panic=abort` and disabled overflow checks passed through rustflags
/// or `CARGO_PROFILE_<NAME>_PANIC` / `_OVERFLOW_CHECKS` in a Cargo config,
/// justfile, Dockerfile or workflow.
pub(crate) fn rustflag_violations(path: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let squeezed: String = line
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .collect::<String>()
            .to_ascii_lowercase();
        let at = format!("{path}:{}", n.saturating_add(1));
        let profile_panic = squeezed.contains("cargo_profile_")
            && settings(&squeezed, "_panic")
                .iter()
                .any(|v| v.starts_with("abort"));
        if squeezed.contains("panic=abort") || profile_panic {
            out.push(v(
                &at,
                "panic=abort through rustflags or CARGO_PROFILE_*; network processes unwind (T-33 rule 4)"
                    .to_owned(),
            ));
        }
        let flag_off = ["overflow-checks", "overflow_checks"]
            .iter()
            .any(|k| settings(&squeezed, k).iter().any(|v| is_off(v)));
        if flag_off {
            out.push(v(
                &at,
                "overflow checks turned off through rustflags or CARGO_PROFILE_*; they stay on (T-33 rule 4)"
                    .to_owned(),
            ));
        }
    }
    out
}

/// True for the files that can pass rustflags or `CARGO_PROFILE_*` to a build.
pub(crate) fn passes_build_flags(rel_path: &str) -> bool {
    let workflow = (rel_path.starts_with(".github/workflows/")
        || rel_path.starts_with(".github/actions/"))
        && matches!(extension(rel_path).as_str(), "yml" | "yaml");
    let cargo_config = rel_path.starts_with(".cargo/config");
    workflow || cargo_config || rel_path == "justfile" || is_dockerfile(rel_path)
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = profile_violations("Cargo.toml", &read(&root.join("Cargo.toml"))?, true)?;
    for config in [".cargo/config.toml", ".cargo/config"] {
        let path = root.join(config);
        if path.exists() {
            out.extend(profile_violations(config, &read(&path)?, false)?);
        }
    }
    for file in repo_files(root)?
        .into_iter()
        .filter(|f| passes_build_flags(f))
    {
        out.extend(rustflag_violations(&file, &read(&root.join(&file))?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-33
    #[test]
    fn t_33_release_without_overflow_checks_is_rejected() {
        let v = profile_violations("Cargo.toml", "[profile.release]\nlto = true\n", true).unwrap();
        assert_eq!(v.len(), 1);
    }

    // T-33
    #[test]
    fn t_33_panic_abort_in_any_profile_is_rejected() {
        let text = "[profile.release]\noverflow-checks = true\npanic = \"abort\"\n[profile.signer]\npanic = \"abort\"\n";
        assert_eq!(
            profile_violations("Cargo.toml", text, true).unwrap().len(),
            2
        );
    }

    // T-33
    #[test]
    fn t_33_unwinding_release_with_overflow_checks_is_accepted() {
        let text = "[profile.release]\noverflow-checks = true\npanic = \"unwind\"\n";
        assert!(
            profile_violations("Cargo.toml", text, true)
                .unwrap()
                .is_empty()
        );
    }

    // T-33
    #[test]
    fn t_33_panic_abort_rustflag_is_rejected() {
        assert_eq!(
            rustflag_violations("c", "rustflags = [\"-C\", \"panic=abort\"]").len(),
            1
        );
        assert!(rustflag_violations("c", "rustflags = [\"-D\", \"warnings\"]").is_empty());
    }

    // T-33
    #[test]
    fn t_33_env_profiles_and_rustflags_in_build_files_are_rejected() {
        let wf = "env:\n  CARGO_PROFILE_RELEASE_PANIC: abort\n  RUSTFLAGS: -C overflow-checks=off\n  CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS: \"false\"\n  CARGO_PROFILE_RELEASE_LTO: \"true\"\n";
        let v = rustflag_violations(".github/workflows/ci.yml", wf);
        let lines: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(
            lines,
            [
                ".github/workflows/ci.yml:2",
                ".github/workflows/ci.yml:3",
                ".github/workflows/ci.yml:4"
            ]
        );
        let just = "build:\n    RUSTFLAGS=\"-Cpanic=abort\" cargo build\n";
        assert_eq!(rustflag_violations("justfile", just).len(), 1);
        let docker = "ENV CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=no\n";
        assert_eq!(
            rustflag_violations("deploy/docker/Dockerfile", docker).len(),
            1
        );
        assert!(
            rustflag_violations("justfile", "x:\n    cargo build -C overflow-checks=on\n")
                .is_empty()
        );
        assert!(passes_build_flags("deploy/app.Dockerfile"));
        assert!(passes_build_flags(".github/workflows/ci.yml"));
        assert!(!passes_build_flags("README.md"));
    }
}
