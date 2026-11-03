//! The npm publish boundary (T-38 rule 2, T-63): a workflow job that runs `npm publish` triggers only on a pushed `v*` tag, guards itself to that tag, waits for the release gate, runs in the `npm` environment with only `contents: read` and an OIDC token, and publishes with provenance; no workflow hands npm a token.

use std::path::{Path, PathBuf};

use crate::rules::files::{extension, read, repo_files};
use crate::yaml::{self, Node};
use crate::{Check, Violation};

const TAG_GUARD: &str = "github.ref_type == 'tag'";
const GATE_JOB: &str = "gate";
const ENVIRONMENT: &str = "npm";
const PERMISSIONS: &[(&str, &str)] = &[("contents", "read"), ("id-token", "write")];
const TOKENS: &[&str] = &["NPM_TOKEN", "NODE_AUTH_TOKEN", "npm_config__authToken"];

pub(crate) fn checks() -> Vec<Check> {
    vec![Check {
        name: "npm-publish",
        run: npm_publish,
    }]
}

fn tag_only(on: Option<&Node>) -> bool {
    let Some(Node::Map(triggers)) = on else {
        return false;
    };
    let [(event, push)] = triggers.as_slice() else {
        return false;
    };
    let Some(Node::Map(filters)) = (event == "push").then_some(push) else {
        return false;
    };
    let [(filter, tags)] = filters.as_slice() else {
        return false;
    };
    let patterns = tags.scalars();
    filter == "tags" && !patterns.is_empty() && patterns.iter().all(|p| p.starts_with('v'))
}

fn guarded_to_tag(guard: &str) -> bool {
    let g = guard.trim();
    let g = g
        .strip_prefix("${{")
        .and_then(|r| r.strip_suffix("}}"))
        .unwrap_or(g);
    let normal: String = g.split_whitespace().collect::<Vec<_>>().join(" ");
    !normal.contains("||")
        && normal
            .split("&&")
            .any(|part| part.trim().replace('"', "'") == TAG_GUARD)
}

fn runs(job: &Node) -> Vec<&str> {
    match job.get("steps") {
        Some(Node::Seq(steps)) => steps
            .iter()
            .filter_map(|s| s.get("run").and_then(Node::as_str))
            .collect(),
        _ => Vec::new(),
    }
}

fn environment(job: &Node) -> Option<&str> {
    let env = job.get("environment")?;
    env.get("name").unwrap_or(env).as_str()
}

fn permissions(job: &Node) -> Vec<(&str, &str)> {
    job.get("permissions")
        .map(Node::entries)
        .unwrap_or_default()
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str().unwrap_or_default()))
        .collect()
}

/// npm publish problems in one workflow (T-38 rule 2, T-63).
pub(crate) fn npm_publish_findings(text: &str) -> Vec<String> {
    let doc = yaml::parse(text);
    let on = doc.get("on").or_else(|| doc.get("true"));
    let mut out = Vec::new();
    for token in TOKENS.iter().filter(|t| text.contains(**t)) {
        out.push(format!(
            "the workflow passes `{token}`; npm publishes only through trusted publishing (T-38)"
        ));
    }
    for (job, body) in doc.get("jobs").map(Node::entries).unwrap_or_default() {
        let commands: Vec<&str> = runs(body)
            .into_iter()
            .filter(|r| r.contains("npm publish"))
            .collect();
        if commands.is_empty() {
            continue;
        }
        if !tag_only(on) {
            out.push(format!(
                "job `{job}` publishes to npm in a workflow that does not trigger on pushed `v*` tags only (T-63)"
            ));
        }
        let guard = body.get("if").and_then(Node::as_str).unwrap_or_default();
        if !guarded_to_tag(guard) {
            out.push(format!(
                "job `{job}` publishes to npm without `if: {TAG_GUARD}` (T-63)"
            ));
        }
        let needs = body.get("needs").map(Node::names).unwrap_or_default();
        if !needs.contains(&GATE_JOB) {
            out.push(format!(
                "job `{job}` publishes to npm without needing the `{GATE_JOB}` job (T-63)"
            ));
        }
        if environment(body) != Some(ENVIRONMENT) {
            out.push(format!(
                "job `{job}` publishes to npm outside the `{ENVIRONMENT}` environment (T-38)"
            ));
        }
        let mut granted = permissions(body);
        granted.sort_unstable();
        if granted != PERMISSIONS {
            out.push(format!(
                "job `{job}` publishes to npm with permissions other than `contents: read` and `id-token: write` (T-38)"
            ));
        }
        if commands.iter().any(|c| !c.contains("--provenance")) {
            out.push(format!(
                "job `{job}` publishes to npm without `--provenance` (T-38)"
            ));
        }
    }
    out
}

fn npm_publish(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let workflow = file.starts_with(".github/workflows/")
            && matches!(extension(&file).as_str(), "yml" | "yaml");
        if !workflow {
            continue;
        }
        for message in npm_publish_findings(&read(&root.join(&file))?) {
            out.push(Violation {
                rule: "npm-publish",
                path: PathBuf::from(&file),
                message,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATED: &str = "on:\n  push:\n    tags: [\"v*\"]\njobs:\n  gate:\n    runs-on: ubuntu-24.04\n  publish-npm:\n    needs: [gate]\n    if: github.event_name == 'push' && github.ref_type == 'tag'\n    environment:\n      name: npm\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: npm publish --provenance --access public\n";

    // T-38 T-63
    #[test]
    fn t_38_npm_publishes_only_from_a_gated_tag_job_with_provenance() {
        assert!(npm_publish_findings(GATED).is_empty());
        let changes = [
            ("    tags: [\"v*\"]\n", "    branches: [main]\n"),
            ("  push:\n    tags: [\"v*\"]\n", "  workflow_dispatch:\n"),
            (" && github.ref_type == 'tag'", ""),
            (
                "github.event_name == 'push' &&",
                "github.event_name == 'push' ||",
            ),
            ("    needs: [gate]\n", ""),
            ("      name: npm\n", "      name: release\n"),
            ("      contents: read\n", "      contents: write\n"),
            (" --provenance", ""),
            (
                "    steps:\n",
                "    env:\n      NODE_AUTH_TOKEN: x\n    steps:\n",
            ),
        ];
        for (from, to) in changes {
            let case = GATED.replace(from, to);
            assert_eq!(npm_publish_findings(&case).len(), 1, "{case}");
        }
        let other = "on: [pull_request]\njobs:\n  test:\n    steps:\n      - run: npm test\n";
        assert!(npm_publish_findings(other).is_empty());
    }

    // T-38 T-63 T-5
    #[test]
    fn t_38_the_release_workflow_publishes_the_kernel_package_only_on_a_tag() {
        let release = include_str!("../../.github/workflows/release.yml");
        assert!(npm_publish_findings(release).is_empty());
        assert!(release.contains("npm publish --provenance"));
        let ci = include_str!("../../.github/workflows/ci.yml");
        assert!(!ci.contains("npm publish"));
    }
}
