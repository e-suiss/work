//! Pinning part of `supply-cooldown` (T-60 rules 2 and 3): every action is pinned
//! to a commit SHA, every container image to a digest, and Renovate waits seven
//! days before proposing a release.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{extension, file_name, read, read_optional, repo_files};
use crate::yaml::{self, Node};

const RULE: &str = "supply-cooldown";

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    }
}

fn is_sha(r: &str) -> bool {
    r.len() == 40
        && r.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// `uses:` lines not pinned to a commit SHA with a version note; local `./` actions pass.
pub(crate) fn unpinned_uses(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start().trim_start_matches("- ").trim_start();
        let Some(rest) = trimmed.strip_prefix("uses:") else {
            continue;
        };
        let (value, comment) = rest
            .split_once(" #")
            .map_or((rest, ""), |(a, b)| (a, b.trim()));
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if value.starts_with("./") {
            continue;
        }
        let at = format!("{rel_path}:{}", i.saturating_add(1));
        let pinned = value.rsplit_once('@').is_some_and(|(_, r)| is_sha(r));
        let docker_pinned = value.starts_with("docker://") && value.contains("@sha256:");
        if !(pinned || docker_pinned) {
            out.push(v(
                &at,
                format!("`{value}` must be pinned to a full commit SHA (T-60 rule 3)"),
            ));
        } else if comment.is_empty() {
            out.push(v(
                &at,
                format!("`{value}` needs a `# vX.Y.Z` version note (T-60 rule 3)"),
            ));
        }
    }
    out
}

/// Image references that may stay unpinned: unpublished Suiss products while
/// `compat.toml` marks them so (T-51).
pub(crate) fn unpublished_images(compat: &str) -> Vec<String> {
    let Ok(table) = compat.parse::<toml::Table>() else {
        return Vec::new();
    };
    ["access", "relay"]
        .iter()
        .filter_map(|p| table.get(*p))
        .filter(|row| row.get("status").and_then(toml::Value::as_str) == Some("unpublished"))
        .filter_map(|row| row.get("image").and_then(toml::Value::as_str))
        .map(|image| format!("{image}:unpublished"))
        .collect()
}

fn image_problem(reference: &str, allowed: &[String]) -> Option<String> {
    let r = reference.trim();
    if r.is_empty()
        || r.starts_with('$')
        || allowed.iter().any(|a| a == r)
        || r.contains("@sha256:")
    {
        return None;
    }
    Some(format!("image `{r}` is not pinned by digest (T-60 rule 3)"))
}

/// Unpinned images in a compose file; services built locally (`build:`) pass.
pub(crate) fn compose_images(rel_path: &str, text: &str, allowed: &[String]) -> Vec<Violation> {
    let doc = yaml::parse(text);
    let mut out = Vec::new();
    for (name, service) in doc.get("services").map(Node::entries).unwrap_or_default() {
        if service.get("build").is_some() {
            continue;
        }
        let image = service
            .get("image")
            .and_then(Node::as_str)
            .unwrap_or_default();
        if let Some(problem) = image_problem(image, allowed) {
            out.push(v(rel_path, format!("service `{name}`: {problem}")));
        }
    }
    out
}

/// Unpinned `image:` lines in deployment YAML and in workflow `services`/`container`.
pub(crate) fn yaml_images(rel_path: &str, text: &str, allowed: &[String]) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let content = crate::yaml::strip_comment(line).trim_start();
        let content = content.trim_start_matches("- ").trim_start();
        let Some(rest) = content.strip_prefix("image:") else {
            continue;
        };
        let reference = rest.trim().trim_matches(|c| c == '"' || c == '\'');
        if let Some(problem) = image_problem(reference, allowed) {
            out.push(v(&format!("{rel_path}:{}", i.saturating_add(1)), problem));
        }
    }
    out
}

/// Unpinned `FROM` lines in a Dockerfile; build stages and `scratch` pass.
pub(crate) fn dockerfile_images(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut stages: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed
            .strip_prefix("FROM ")
            .or_else(|| trimmed.strip_prefix("from "))
        else {
            continue;
        };
        let parts: Vec<&str> = rest
            .split_whitespace()
            .filter(|p| !p.starts_with("--"))
            .collect();
        let Some(reference) = parts.first() else {
            continue;
        };
        let lower = reference.to_ascii_lowercase();
        let local = lower == "scratch" || stages.contains(&lower);
        if let Some(alias) = parts
            .iter()
            .position(|p| p.eq_ignore_ascii_case("as"))
            .and_then(|k| parts.get(k.saturating_add(1)))
        {
            stages.push(alias.to_ascii_lowercase());
        }
        if local {
            continue;
        }
        if let Some(problem) = image_problem(reference, &[]) {
            out.push(v(&format!("{rel_path}:{}", i.saturating_add(1)), problem));
        }
    }
    out
}

fn days(value: &str) -> Option<u32> {
    let mut parts = value.split_whitespace();
    let n: u32 = parts.next()?.parse().ok()?;
    match parts.next()? {
        "day" | "days" => Some(n),
        "week" | "weeks" => n.checked_mul(7),
        _ => None,
    }
}

/// Renovate waits at least seven days; the top level sets exactly `"7 days"`.
pub(crate) fn renovate_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    let json: serde_json::Value = match serde_json::from_str(text) {
        Ok(j) => j,
        Err(e) => return vec![v(rel_path, format!("not JSON: {e}"))],
    };
    let mut out = Vec::new();
    if json
        .get("minimumReleaseAge")
        .and_then(serde_json::Value::as_str)
        != Some("7 days")
    {
        out.push(v(
            rel_path,
            "`minimumReleaseAge` must be \"7 days\" (T-60 rule 2)".to_owned(),
        ));
    }
    for rule in json
        .get("packageRules")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(age) = rule.get("minimumReleaseAge") {
            let ok = age.as_str().and_then(days).is_some_and(|d| d >= 7);
            if !ok {
                out.push(v(
                    rel_path,
                    format!("a package rule lowers `minimumReleaseAge` to {age} (T-60 rule 2)"),
                ));
            }
        }
    }
    out
}

const RENOVATE_FILES: &[&str] = &["renovate.json", ".github/renovate.json"];

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let allowed =
        unpublished_images(&read_optional(&root.join("compat.toml"))?.unwrap_or_default());
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let yaml_file = matches!(extension(&file).as_str(), "yml" | "yaml");
        let name = file_name(&file);
        if file.starts_with(".github/workflows/") || file.starts_with(".github/actions/") {
            if yaml_file {
                let text = read(&root.join(&file))?;
                out.extend(unpinned_uses(&file, &text));
                out.extend(yaml_images(&file, &text, &allowed));
            }
        } else if file.starts_with("deploy/") && yaml_file {
            let text = read(&root.join(&file))?;
            if name.starts_with("compose") {
                out.extend(compose_images(&file, &text, &allowed));
            } else {
                out.extend(yaml_images(&file, &text, &allowed));
            }
        }
        if name.starts_with("Dockerfile") || name.ends_with(".dockerfile") {
            out.extend(dockerfile_images(&file, &read(&root.join(&file))?));
        }
    }
    let mut found = false;
    for file in RENOVATE_FILES {
        if let Some(text) = read_optional(&root.join(file))? {
            found = true;
            out.extend(renovate_violations(file, &text));
        }
    }
    if !found {
        out.push(v(
            "renovate.json",
            "renovate.json is missing (T-38 rule 6, T-60 rule 2)".to_owned(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "08c6903cd8c0fde910a37f88322edcfb5dd907a8";

    // T-60 T-38
    #[test]
    fn t_60_action_pinned_to_tag_is_rejected() {
        let wf = format!(
            "steps:\n  - uses: actions/checkout@v5\n  - uses: actions/checkout@{SHA} # v5.0.0\n  - uses: ./.github/actions/setup\n"
        );
        let found = unpinned_uses("ci.yml", &wf);
        assert_eq!(found.len(), 1);
        assert!(found[0].path.ends_with("ci.yml:2"));
        let bare = format!("- uses: actions/checkout@{SHA}\n");
        assert_eq!(unpinned_uses("ci.yml", &bare).len(), 1);
    }

    // T-60 T-51
    #[test]
    fn t_60_images_need_a_digest_except_unpublished_suiss_products() {
        let compat = "[access]\nstatus = \"unpublished\"\nimage = \"ghcr.io/e-suiss/access\"\n[relay]\nstatus = \"published\"\nimage = \"ghcr.io/e-suiss/relay\"\n";
        let allowed = unpublished_images(compat);
        assert_eq!(allowed, ["ghcr.io/e-suiss/access:unpublished"]);
        let compose = "services:\n  access:\n    image: ghcr.io/e-suiss/access:unpublished\n  relay:\n    image: ghcr.io/e-suiss/relay:unpublished\n  pg:\n    image: postgres:18\n  nats:\n    image: nats@sha256:ac # 2.15.0\n  softhsm:\n    build: ./softhsm\n    image: work-dev/softhsm:local\n";
        let found = compose_images("deploy/compose/compose.yaml", compose, &allowed);
        assert_eq!(found.len(), 2, "{found:?}");
        let wf = "jobs:\n  t:\n    services:\n      pg:\n        image: postgres:18\n    container:\n      image: rust@sha256:aa\n";
        assert_eq!(yaml_images("ci.yml", wf, &allowed).len(), 1);
    }

    // T-60
    #[test]
    fn t_60_dockerfile_base_images_need_a_digest() {
        let docker =
            "FROM rust@sha256:aa AS build\nFROM build AS chef\nFROM debian:13-slim\nFROM scratch\n";
        let found = dockerfile_images("deploy/Dockerfile", docker);
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("debian"));
    }

    // T-60 T-38
    #[test]
    fn t_60_renovate_must_wait_seven_days() {
        assert!(
            renovate_violations("renovate.json", "{\"minimumReleaseAge\": \"7 days\"}").is_empty()
        );
        assert_eq!(
            renovate_violations("renovate.json", "{\"minimumReleaseAge\": \"3 days\"}").len(),
            1
        );
        assert_eq!(renovate_violations("renovate.json", "{}").len(), 1);
        let lowered = "{\"minimumReleaseAge\": \"7 days\", \"packageRules\": [{\"minimumReleaseAge\": \"1 day\"}, {\"minimumReleaseAge\": \"2 weeks\"}]}";
        assert_eq!(renovate_violations("renovate.json", lowered).len(), 1);
    }
}
