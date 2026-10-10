//! Repository configuration scans: no automatic test retries (T-37 rule 10),
//! sensitive paths in `CODEOWNERS` (T-43), the benchmark runner boundary (T-62,
//! T-44) and generated files (T-41 rule 4).

use std::path::{Path, PathBuf};

use crate::rules::files::{extension, file_name, read, read_optional, repo_files};
use crate::yaml::{self, Node};
use crate::{Check, Violation};

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "no-flaky-retries",
            run: no_flaky_retries,
        },
        Check {
            name: "codeowners",
            run: codeowners,
        },
        Check {
            name: "bench-runner",
            run: bench_runner,
        },
        Check {
            name: "generated",
            run: generated,
        },
    ]
}

fn violation(rule: &'static str, file: &str, line: usize, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{file}:{}", line.saturating_add(1))),
        message,
    }
}

fn is_config(file: &str) -> bool {
    let name = file_name(file).to_ascii_lowercase();
    name.starts_with("dockerfile")
        || name == "justfile"
        || matches!(
            extension(file).as_str(),
            "toml" | "yml" | "yaml" | "sh" | "json"
        )
}

/// Lines that retry failing tests until they pass.
pub(crate) fn retry_findings(file: &str, text: &str) -> Vec<usize> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let lower = compact.to_ascii_lowercase();
        let nonzero_setting = lower
            .strip_prefix("retries=")
            .is_some_and(|value| !value.trim_start_matches(['"', '{']).starts_with('0'));
        let nonzero_flag = lower
            .split("--retries")
            .nth(1)
            .is_some_and(|value| !value.trim_start_matches('=').starts_with('0'));
        let retry_action =
            file.starts_with(".github/") && lower.contains("uses:") && lower.contains("retry");
        if nonzero_setting || nonzero_flag || retry_action {
            found.push(n);
        }
    }
    found
}

fn no_flaky_retries(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)?.iter().filter(|f| is_config(f)) {
        for n in retry_findings(file, &read(&root.join(file))?) {
            out.push(violation(
                "no-flaky-retries",
                file,
                n,
                "flaky tests are quarantined, never retried until green (T-37 rule 10)".to_owned(),
            ));
        }
    }
    Ok(out)
}

const CODEOWNERS_FILE: &str = ".github/CODEOWNERS";

/// Paths that must be owned for review (T-43; shared crate versions live in the
/// manifest, the lockfile and `compat.toml`).
pub(crate) const SENSITIVE_PATHS: &[&str] = &[
    "/crates/kernel/",
    "/crates/store/",
    "/crates/ledger/",
    "/crates/federation/",
    "/bins/work-signer/",
    "/sdks/bindings/",
    "/Cargo.toml",
    "/Cargo.lock",
    "/compat.toml",
];

/// Sensitive paths without an owner line.
pub(crate) fn missing_owners(text: &str) -> Vec<&'static str> {
    let owned: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let path = parts.next()?;
            parts
                .next()
                .is_some_and(|o| o.starts_with('@') || o.contains('@'))
                .then_some(path)
        })
        .collect();
    SENSITIVE_PATHS
        .iter()
        .copied()
        .filter(|p| !owned.contains(p))
        .collect()
}

fn codeowners(root: &Path) -> Result<Vec<Violation>, String> {
    let text = read_optional(&root.join(CODEOWNERS_FILE))?.unwrap_or_default();
    Ok(missing_owners(&text)
        .into_iter()
        .map(|p| Violation {
            rule: "codeowners",
            path: PathBuf::from(CODEOWNERS_FILE),
            message: format!("sensitive path `{p}` has no owner (T-43)"),
        })
        .collect())
}

const ALLOWED_BENCH_TRIGGERS: &[&str] = &["schedule", "workflow_dispatch"];

/// Benchmark-runner problems in one workflow (T-62).
pub(crate) fn bench_findings(text: &str) -> Vec<String> {
    let doc = yaml::parse(text);
    let triggers: Vec<String> = doc
        .get("on")
        .or_else(|| doc.get("true"))
        .map(|n| n.names().into_iter().map(str::to_owned).collect())
        .unwrap_or_default();
    let mut out = Vec::new();
    for (job, body) in doc.get("jobs").map(Node::entries).unwrap_or_default() {
        let runs_on = body.get("runs-on").map(Node::scalars).unwrap_or_default();
        if !runs_on.iter().any(|r| r.contains("bench")) {
            continue;
        }
        for t in triggers
            .iter()
            .filter(|t| !ALLOWED_BENCH_TRIGGERS.contains(&t.as_str()))
        {
            out.push(format!(
                "job `{job}` runs on the bench runner but the workflow triggers on `{t}`; only schedule and workflow_dispatch (T-62)"
            ));
        }
        if triggers.is_empty() {
            out.push(format!(
                "job `{job}` runs on the bench runner in a workflow without triggers (T-62)"
            ));
        }
        let guard = body.get("if").and_then(Node::as_str).unwrap_or_default();
        if !guard.contains("refs/heads/main") {
            out.push(format!(
                "job `{job}` runs on the bench runner without `if: github.ref == 'refs/heads/main'` (T-62)"
            ));
        }
    }
    out
}

fn bench_runner(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let workflow = file.starts_with(".github/workflows/")
            && matches!(extension(&file).as_str(), "yml" | "yaml");
        if !workflow {
            continue;
        }
        for message in bench_findings(&read(&root.join(&file))?) {
            out.push(Violation {
                rule: "bench-runner",
                path: PathBuf::from(&file),
                message,
            });
        }
    }
    Ok(out)
}

/// A generator whose committed output CI regenerates and compares (T-41 rule 4).
pub(crate) struct Generator {
    pub(crate) name: &'static str,
    pub(crate) check: fn(&Path) -> Result<Vec<Violation>, String>,
}

/// Registered generators; the `OpenAPI` and `AsyncAPI` documents and the sqlx
/// metadata register here when they exist.
pub(crate) const GENERATORS: &[Generator] = &[];

/// Runs every generator check.
pub(crate) fn run_generators(
    root: &Path,
    generators: &[Generator],
) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for g in generators {
        out.extend((g.check)(root).map_err(|e| format!("{}: {e}", g.name))?);
    }
    Ok(out)
}

fn generated(root: &Path) -> Result<Vec<Violation>, String> {
    if GENERATORS.is_empty() {
        println!("      generated: no generators registered yet");
    }
    run_generators(root, GENERATORS)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-37
    #[test]
    fn t_37_nonzero_retries_are_rejected() {
        assert_eq!(
            retry_findings(".config/nextest.toml", "retries = 2").len(),
            1
        );
        assert_eq!(
            retry_findings(".config/nextest.toml", "retries = 0").len(),
            0
        );
        assert_eq!(
            retry_findings("justfile", "cargo nextest run --retries 3").len(),
            1
        );
        assert_eq!(
            retry_findings(".github/workflows/ci.yml", "uses: nick-fields/retry@abc").len(),
            1
        );
    }

    // T-43
    #[test]
    fn t_43_sensitive_path_without_owner_is_reported() {
        let full = SENSITIVE_PATHS
            .iter()
            .fold(String::new(), |acc, p| acc + p + " @ademceper\n");
        assert!(missing_owners(&full).is_empty());
        let partial = full.replace("/compat.toml @ademceper\n", "# /compat.toml @ademceper\n");
        assert_eq!(missing_owners(&partial), ["/compat.toml"]);
        assert_eq!(
            missing_owners("/crates/kernel/\n").len(),
            SENSITIVE_PATHS.len()
        );
    }

    // T-62 T-44
    #[test]
    fn t_62_bench_job_with_pull_request_trigger_is_rejected() {
        let ok = "on:\n  schedule:\n    - cron: \"0 2 * * *\"\n  workflow_dispatch:\njobs:\n  bench:\n    runs-on: [self-hosted, bench]\n    if: github.ref == 'refs/heads/main'\n";
        assert!(bench_findings(ok).is_empty());
        let pr = ok.replace("  workflow_dispatch:\n", "  pull_request:\n");
        assert_eq!(bench_findings(&pr).len(), 1);
        let unguarded = ok.replace("    if: github.ref == 'refs/heads/main'\n", "");
        assert_eq!(bench_findings(&unguarded).len(), 1);
        let other = "on: [pull_request]\njobs:\n  test:\n    runs-on: ubuntu-24.04\n";
        assert!(bench_findings(other).is_empty());
    }

    // T-41
    #[test]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "generator checks share the `Generator::check` signature"
    )]
    fn t_41_generator_differences_are_reported() {
        fn stale(_: &Path) -> Result<Vec<Violation>, String> {
            Ok(vec![Violation {
                rule: "generated",
                path: PathBuf::from("sdks/openapi/work.json"),
                message: "differs from the regenerated output".to_owned(),
            }])
        }
        fn fresh(_: &Path) -> Result<Vec<Violation>, String> {
            Ok(Vec::new())
        }
        let gens = [
            Generator {
                name: "openapi",
                check: stale,
            },
            Generator {
                name: "asyncapi",
                check: fresh,
            },
        ];
        assert_eq!(run_generators(Path::new("."), &gens).unwrap().len(), 1);
        assert!(
            run_generators(Path::new("."), GENERATORS)
                .unwrap()
                .is_empty()
        );
    }
}
