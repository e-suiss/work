//! Repository configuration scans: no automatic test retries (T-37 rule 10),
//! sensitive paths in `CODEOWNERS` (T-43), the benchmark runner boundary (T-62,
//! T-44) and generated files (T-41 rule 4).

use std::path::{Path, PathBuf};

use crate::rules::comments::is_dockerfile;
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

const SCRIPT_EXTENSIONS: &[&str] = &["ts", "mts", "cts", "js", "mjs", "cjs"];

fn is_script_config(file: &str) -> bool {
    SCRIPT_EXTENSIONS.contains(&extension(file).as_str()) && file_name(file).contains(".config.")
}

fn is_config(file: &str) -> bool {
    is_dockerfile(file)
        || file_name(file) == "justfile"
        || is_script_config(file)
        || matches!(
            extension(file).as_str(),
            "toml" | "yml" | "yaml" | "sh" | "json"
        )
}

fn nonzero(value: &str) -> bool {
    let end = value.find([',', '}', ';']).unwrap_or(value.len());
    value
        .get(..end)
        .unwrap_or_default()
        .chars()
        .any(|c| matches!(c, '1'..='9'))
}

/// Lines that retry failing tests until they pass: nextest `retries`, the
/// `--retries` flag, `NEXTEST_RETRIES`, Playwright and Vitest `retries`, and
/// retry actions in workflows.
pub(crate) fn retry_findings(file: &str, text: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let script = is_script_config(file);
    for (n, line) in text.lines().enumerate() {
        let compact: String = line
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .collect();
        let lower = compact.to_ascii_lowercase();
        let nonzero_setting = lower
            .strip_prefix("retries=")
            .or_else(|| script.then(|| lower.strip_prefix("retries:")).flatten())
            .is_some_and(|value| nonzero(value.trim_start_matches('{')));
        let nonzero_flag = lower.split("--retries").skip(1).any(|value| {
            nonzero(
                value
                    .trim_start_matches('=')
                    .split(' ')
                    .next()
                    .unwrap_or_default(),
            )
        });
        let nonzero_env = lower.split("nextest_retries").skip(1).any(|value| {
            value
                .strip_prefix('=')
                .or_else(|| value.strip_prefix(':'))
                .is_some_and(nonzero)
        });
        let retry_action =
            file.starts_with(".github/") && lower.contains("uses:") && lower.contains("retry");
        if nonzero_setting || nonzero_flag || nonzero_env || retry_action {
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

fn segment_match(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            segment_match(p.get(1..).unwrap_or_default(), s)
                || (!s.is_empty() && segment_match(p, s.get(1..).unwrap_or_default()))
        }
        (Some(b'?'), Some(_)) => segment_match(
            p.get(1..).unwrap_or_default(),
            s.get(1..).unwrap_or_default(),
        ),
        (Some(a), Some(b)) if a == b => segment_match(
            p.get(1..).unwrap_or_default(),
            s.get(1..).unwrap_or_default(),
        ),
        _ => false,
    }
}

fn parts_match(p: &[&str], s: &[&str]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(&"**"), _) => {
            parts_match(p.get(1..).unwrap_or_default(), s)
                || (!s.is_empty() && parts_match(p, s.get(1..).unwrap_or_default()))
        }
        (Some(a), Some(b)) if segment_match(a.as_bytes(), b.as_bytes()) => parts_match(
            p.get(1..).unwrap_or_default(),
            s.get(1..).unwrap_or_default(),
        ),
        _ => false,
    }
}

/// Whether a `CODEOWNERS` pattern covers `file` (relative, no leading `/`):
/// gitignore rules, so a pattern without an inner `/` matches at any depth and
/// one ending in `/` covers everything below a directory.
pub(crate) fn owner_pattern_matches(pattern: &str, file: &str) -> bool {
    let dir_only = pattern.ends_with('/');
    let trimmed = pattern.trim_end_matches('/');
    let anchored = trimmed.starts_with('/') || trimmed.contains('/');
    let pat: Vec<&str> = trimmed.trim_start_matches('/').split('/').collect();
    let segs: Vec<&str> = file.split('/').collect();
    (1..=segs.len()).any(|len| {
        let is_file = len == segs.len();
        if dir_only && is_file {
            return false;
        }
        let candidate = segs.get(..len).unwrap_or_default();
        if anchored {
            parts_match(&pat, candidate)
        } else {
            candidate.last().is_some_and(|last| {
                pat.first()
                    .is_some_and(|p| segment_match(p.as_bytes(), last.as_bytes()))
            })
        }
    })
}

fn is_owner(token: &str) -> bool {
    let Some(name) = token.strip_prefix('@') else {
        return false;
    };
    let ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    };
    match name.split_once('/') {
        Some((org, team)) => ok(org) && ok(team),
        None => ok(name),
    }
}

/// A file inside each sensitive path, for evaluating patterns against it.
fn sample(sensitive: &str) -> String {
    let rel_path = sensitive.trim_start_matches('/');
    if rel_path.ends_with('/') {
        format!("{rel_path}x")
    } else {
        rel_path.to_owned()
    }
}

/// Sensitive paths whose last matching line has no valid `@user` or `@org/team`
/// owner (the last match wins in `CODEOWNERS`).
pub(crate) fn missing_owners(text: &str) -> Vec<&'static str> {
    let rules: Vec<(&str, Vec<&str>)> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let path = parts.next()?;
            Some((path, parts.take_while(|t| !t.starts_with('#')).collect()))
        })
        .collect();
    SENSITIVE_PATHS
        .iter()
        .copied()
        .filter(|p| {
            let file = sample(p);
            let last = rules
                .iter()
                .rev()
                .find(|(pattern, _)| owner_pattern_matches(pattern, &file));
            !last
                .is_some_and(|(_, owners)| !owners.is_empty() && owners.iter().all(|o| is_owner(o)))
        })
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

const MAIN_GUARD: &str = "github.ref == 'refs/heads/main'";

/// The values a `runs-on` expression can take: matrix values for
/// `${{ matrix.x }}`, `None` for any other expression.
fn runs_on_values(job: &Node) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for label in job.get("runs-on").map(Node::scalars).unwrap_or_default() {
        let Some(start) = label.find("${{") else {
            out.push(label.to_owned());
            continue;
        };
        let inner = label
            .get(start.saturating_add(3)..)
            .and_then(|r| r.split("}}").next())
            .unwrap_or_default()
            .trim();
        let key = inner.strip_prefix("matrix.")?;
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }
        let matrix = job.get("strategy").and_then(|s| s.get("matrix"))?;
        let mut values: Vec<String> = matrix
            .get(key)
            .map(|n| n.scalars().into_iter().map(str::to_owned).collect())
            .unwrap_or_default();
        for extra in ["include", "exclude"] {
            if let Some(Node::Seq(items)) = matrix.get(extra) {
                values.extend(
                    items
                        .iter()
                        .filter_map(|i| i.get(key))
                        .flat_map(Node::scalars)
                        .map(str::to_owned),
                );
            }
        }
        if values.is_empty() {
            return None;
        }
        out.extend(values);
    }
    Some(out)
}

/// True when a job guard is exactly the main-branch condition, alone or joined
/// with `&&`, and has no `||`.
fn guarded_to_main(guard: &str) -> bool {
    let g = guard.trim();
    let g = g
        .strip_prefix("${{")
        .and_then(|r| r.strip_suffix("}}"))
        .unwrap_or(g);
    let normal: String = g.split_whitespace().collect::<Vec<_>>().join(" ");
    !normal.contains("||")
        && normal
            .split("&&")
            .any(|part| part.trim().replace('"', "'") == MAIN_GUARD)
}

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
        let Some(labels) = runs_on_values(body) else {
            out.push(format!(
                "job `{job}` chooses its runner through an expression that is not a literal matrix value; the bench runner boundary cannot be checked (T-62)"
            ));
            continue;
        };
        if !labels
            .iter()
            .any(|r| r.to_ascii_lowercase().contains("bench"))
        {
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
        if !guarded_to_main(guard) {
            out.push(format!(
                "job `{job}` runs on the bench runner without `if: {MAIN_GUARD}` (T-62)"
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
pub(crate) const GENERATORS: &[Generator] = &[Generator {
    name: "record-vectors",
    check: record_vectors,
}];

const RECORD_VECTORS: &str = "conformance/vectors/records";
const RECORD_VECTORS_KEEP: &[&str] = &["README.md", "gen"];

/// Files of `dir` (names only, sorted), or none when it does not exist.
fn file_names(dir: &Path) -> Result<Vec<String>, String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        out.push(entry.file_name().to_string_lossy().into_owned());
    }
    out.sort();
    Ok(out)
}

/// Committed files that differ from a fresh generator run in `fresh` (P-11, P-72).
pub(crate) fn directory_drift(
    committed: &Path,
    fresh: &Path,
    rel_dir: &str,
    keep: &[&str],
) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let stale = |name: &str, message: &str| Violation {
        rule: "generated",
        path: PathBuf::from(format!("{rel_dir}/{name}")),
        message: message.to_owned(),
    };
    let generated = file_names(fresh)?;
    for name in &generated {
        let want = std::fs::read(fresh.join(name)).map_err(|e| format!("{name}: {e}"))?;
        match std::fs::read(committed.join(name)) {
            Ok(have) if have == want => {}
            Ok(_) => out.push(stale(
                name,
                "differs from the regenerated output; regenerate and commit it (T-41 rule 4)",
            )),
            Err(_) => out.push(stale(name, "is generated but not committed (T-41 rule 4)")),
        }
    }
    for name in file_names(committed)? {
        if !generated.contains(&name) && !keep.contains(&name.as_str()) {
            out.push(stale(
                &name,
                "is committed but no longer generated (T-41 rule 4)",
            ));
        }
    }
    Ok(out)
}

fn record_vectors(root: &Path) -> Result<Vec<Violation>, String> {
    let fresh = root.join("target/xtask-generated/records");
    if fresh.exists() {
        std::fs::remove_dir_all(&fresh).map_err(|e| format!("{}: {e}", fresh.display()))?;
    }
    let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_owned());
    let script = root.join(RECORD_VECTORS).join("gen/gen.py");
    let output = std::process::Command::new(&python)
        .arg(&script)
        .arg(&fresh)
        .current_dir(root)
        .output()
        .map_err(|e| format!("{python} {}: {e}", script.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{}: {}",
            script.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    directory_drift(
        &root.join(RECORD_VECTORS),
        &fresh,
        RECORD_VECTORS,
        RECORD_VECTORS_KEEP,
    )
}

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
    run_generators(root, GENERATORS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::files::TempDir;

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
        assert!(GENERATORS.iter().any(|g| g.name == "record-vectors"));
    }

    // T-41 P-11 P-72
    #[test]
    fn t_41_stale_missing_and_orphan_generated_files_are_reported() {
        let committed = TempDir::new("gen-committed");
        let fresh = TempDir::new("gen-fresh");
        committed.write("same.json", "{}");
        fresh.write("same.json", "{}");
        committed.write("changed.json", "{\"a\":1}");
        fresh.write("changed.json", "{\"a\":2}");
        fresh.write("new.json", "[]");
        committed.write("orphan.json", "[]");
        committed.write("README.md", "x");
        let found: Vec<String> = directory_drift(&committed.0, &fresh.0, "v", &["README.md"])
            .unwrap()
            .iter()
            .map(|v| v.path.display().to_string())
            .collect();
        assert_eq!(found, ["v/changed.json", "v/new.json", "v/orphan.json"]);
    }

    // T-37
    #[test]
    fn t_37_playwright_and_nextest_env_retries_are_rejected() {
        let pw = "export default defineConfig({\n  retries: process.env.CI ? 2 : 0,\n  workers: 4,\n});\n";
        assert_eq!(
            retry_findings("packages/kernel/playwright.config.ts", pw),
            [1]
        );
        assert!(
            retry_findings("packages/kernel/playwright.config.ts", "  retries: 0,\n").is_empty()
        );
        let wf =
            "env:\n  NEXTEST_RETRIES: 2\n  OTHER: 1\nrun: NEXTEST_RETRIES=0 cargo nextest run\n";
        assert_eq!(retry_findings(".github/workflows/ci.yml", wf), [1]);
        assert!(retry_findings("deploy/compose/compose.yaml", "    retries: 30\n").is_empty());
        assert!(is_config("packages/kernel/vitest.config.mjs"));
    }

    // T-43
    #[test]
    fn t_43_last_matching_codeowners_line_decides_and_owners_are_handles() {
        let full = SENSITIVE_PATHS
            .iter()
            .fold(String::new(), |acc, p| acc + p + " @ademceper\n");
        let overridden = format!("{full}/crates/\n");
        assert_eq!(
            missing_owners(&overridden),
            [
                "/crates/kernel/",
                "/crates/store/",
                "/crates/ledger/",
                "/crates/federation/"
            ]
        );
        let star = format!("{full}*.lock nobody\n");
        assert_eq!(missing_owners(&star), ["/Cargo.lock"]);
        let team = "* @e-suiss/maintainers\n";
        assert!(missing_owners(team).is_empty());
        let email = "* adem@example.com\n";
        assert_eq!(missing_owners(email).len(), SENSITIVE_PATHS.len());
        assert!(owner_pattern_matches(
            "crates/**/Cargo.toml",
            "crates/kernel/Cargo.toml"
        ));
        assert!(!owner_pattern_matches(
            "/Cargo.toml",
            "crates/kernel/Cargo.toml"
        ));
        assert!(owner_pattern_matches(
            "Cargo.toml",
            "crates/kernel/Cargo.toml"
        ));
    }

    // T-62 T-44
    #[test]
    fn t_62_bench_labels_matrix_runners_and_exact_main_guard() {
        let base = "on:\n  workflow_dispatch:\njobs:\n  bench:\n    runs-on: [self-hosted, Bench]\n    if: github.ref == 'refs/heads/main'\n";
        assert!(bench_findings(base).is_empty());
        let pr = base.replace("  workflow_dispatch:\n", "  pull_request:\n");
        assert_eq!(bench_findings(&pr).len(), 1);
        let loose = base.replace(
            "if: github.ref == 'refs/heads/main'",
            "if: github.ref == 'refs/heads/main' || github.event_name == 'pull_request'",
        );
        assert_eq!(bench_findings(&loose).len(), 1);
        let near = base.replace(
            "if: github.ref == 'refs/heads/main'",
            "if: contains(github.ref, 'refs/heads/main')",
        );
        assert_eq!(bench_findings(&near).len(), 1);
        let matrix = "on: [pull_request]\njobs:\n  b:\n    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        include:\n          - { arch: amd64, runner: ubuntu-24.04 }\n          - { arch: arm64, runner: bench-arm }\n";
        assert_eq!(bench_findings(matrix).len(), 2);
        let release = matrix.replace("bench-arm", "ubuntu-24.04-arm");
        assert!(bench_findings(&release).is_empty());
        let opaque = "on: [pull_request]\njobs:\n  b:\n    runs-on: ${{ inputs.runner }}\n";
        assert_eq!(bench_findings(opaque).len(), 1);
    }
}
