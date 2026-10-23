//! Pinning part of `supply-cooldown` (T-60 rules 2 and 3): every action is pinned
//! to a commit SHA, every container image to a digest (after resolving Dockerfile
//! `ARG` defaults and compose `${VAR:-default}`, and in workflow `docker run` and
//! `docker pull` steps), and Renovate waits seven days before proposing a release.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::comments::is_dockerfile;
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
    if r.is_empty() || allowed.iter().any(|a| a == r) {
        return None;
    }
    if r.contains('$') {
        return Some(format!(
            "image `{r}` comes from a variable without a pinned default; pin it by digest (T-60 rule 3)"
        ));
    }
    if r.contains("@sha256:") {
        return None;
    }
    Some(format!("image `{r}` is not pinned by digest (T-60 rule 3)"))
}

/// Replaces `${VAR}`, `${VAR:-default}`, `${VAR-default}` and `$VAR` with the
/// value `lookup` gives or the inline default; unresolved references stay.
pub(crate) fn substitute(reference: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = reference;
    while let Some(at) = rest.find('$') {
        out.push_str(rest.get(..at).unwrap_or_default());
        let after = rest.get(at.saturating_add(1)..).unwrap_or_default();
        if let Some(body) = after.strip_prefix('{').filter(|b| !b.starts_with('{')) {
            let Some(end) = body.find('}') else {
                out.push_str(rest.get(at..).unwrap_or_default());
                return out;
            };
            let inner = body.get(..end).unwrap_or_default();
            let (name, default) = inner
                .split_once(":-")
                .or_else(|| inner.split_once('-'))
                .map_or((inner, None), |(n, d)| (n, Some(d)));
            match lookup(name).or_else(|| default.map(str::to_owned)) {
                Some(value) => out.push_str(&value),
                None => out.push_str(
                    rest.get(at..at.saturating_add(end).saturating_add(3))
                        .unwrap_or_default(),
                ),
            }
            rest = body.get(end.saturating_add(1)..).unwrap_or_default();
        } else {
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if let Some(value) = lookup(&name).filter(|_| !name.is_empty()) {
                out.push_str(&value);
            } else {
                out.push('$');
                out.push_str(&name);
            }
            rest = after.get(name.len()..).unwrap_or_default();
        }
    }
    out.push_str(rest);
    out
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
        let image = substitute(image, &|_| None);
        if let Some(problem) = image_problem(&image, allowed) {
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

/// Unpinned `FROM` lines in a Dockerfile; build stages and `scratch` pass, and
/// `ARG` defaults declared before the `FROM` resolve `${NAME}` references.
pub(crate) fn dockerfile_images(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut stages: Vec<String> = Vec::new();
    let mut args: Vec<(String, String)> = Vec::new();
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let keyword: String = trimmed
            .chars()
            .take_while(char::is_ascii_alphabetic)
            .collect::<String>()
            .to_ascii_uppercase();
        let rest = trimmed.get(keyword.len()..).unwrap_or_default();
        if keyword == "ARG" {
            for decl in rest.split_whitespace() {
                if let Some((name, value)) = decl.split_once('=') {
                    let value = value.trim_matches(|c| c == '"' || c == '\'');
                    args.retain(|(n, _)| n != name);
                    args.push((name.to_owned(), value.to_owned()));
                }
            }
            continue;
        }
        if keyword != "FROM" || !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let parts: Vec<&str> = rest
            .split_whitespace()
            .filter(|p| !p.starts_with("--"))
            .collect();
        let Some(raw) = parts.first() else {
            continue;
        };
        let lookup = |name: &str| {
            args.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty())
        };
        let reference = substitute(raw, &lookup);
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
        if let Some(problem) = image_problem(&reference, &[]) {
            out.push(v(&format!("{rel_path}:{}", i.saturating_add(1)), problem));
        }
    }
    out
}

const DOCKER_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--env",
    "-v",
    "--volume",
    "--name",
    "-p",
    "--publish",
    "--network",
    "--net",
    "--entrypoint",
    "-w",
    "--workdir",
    "-u",
    "--user",
    "--mount",
    "--platform",
    "-l",
    "--label",
    "--env-file",
    "--add-host",
    "--cap-add",
    "--cap-drop",
    "--cpus",
    "-m",
    "--memory",
    "--user",
    "--hostname",
    "-h",
    "--tmpfs",
    "--security-opt",
    "--ulimit",
    "--pull",
    "--restart",
    "--log-driver",
    "--log-opt",
    "--device",
    "--gpus",
    "--shm-size",
    "--stop-signal",
];

/// Shell words of a command line, with quotes removed.
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c.is_whitespace() || c == ';' || c == '|' || c == '&' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            Some(_) | None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Images that `docker run`, `docker create` and `docker pull` (or `podman`) use
/// in shell text, and tags that `docker build` gives local images.
pub(crate) fn shell_images(text: &str) -> (Vec<(usize, String)>, Vec<String>) {
    let mut used = Vec::new();
    let mut built = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let w = words(line);
        for (k, word) in w.iter().enumerate() {
            if word != "docker" && word != "podman" {
                continue;
            }
            let mut j = k.saturating_add(1);
            if w.get(j)
                .is_some_and(|x| x == "container" || x == "image" || x == "buildx")
            {
                j = j.saturating_add(1);
            }
            let Some(sub) = w.get(j) else { continue };
            if sub == "build" {
                let mut t = j.saturating_add(1);
                while let Some(x) = w.get(t) {
                    if x == "-t" || x == "--tag" {
                        if let Some(tag) = w.get(t.saturating_add(1)) {
                            built.push(tag.clone());
                        }
                    } else if let Some(tag) = x.strip_prefix("--tag=") {
                        built.push(tag.to_owned());
                    }
                    t = t.saturating_add(1);
                }
                continue;
            }
            if !matches!(sub.as_str(), "run" | "create" | "pull") {
                continue;
            }
            let mut t = j.saturating_add(1);
            while let Some(x) = w.get(t) {
                if !x.starts_with('-') {
                    used.push((n, x.clone()));
                    break;
                }
                let takes_value = DOCKER_VALUE_FLAGS.contains(&x.as_str());
                t = t.saturating_add(if takes_value { 2 } else { 1 });
            }
        }
    }
    (used, built)
}

/// Unpinned images in the `run:` steps of a workflow or composite action.
pub(crate) fn run_step_images(rel_path: &str, text: &str, allowed: &[String]) -> Vec<Violation> {
    let doc = yaml::parse(text);
    let mut runs: Vec<String> = Vec::new();
    let mut steps: Vec<&Node> = Vec::new();
    for (_, job) in doc.get("jobs").map(Node::entries).unwrap_or_default() {
        if let Some(Node::Seq(items)) = job.get("steps") {
            steps.extend(items);
        }
    }
    if let Some(Node::Seq(items)) = doc.get("runs").and_then(|r| r.get("steps")) {
        steps.extend(items);
    }
    for step in steps {
        if let Some(run) = step.get("run").and_then(Node::as_str) {
            runs.push(run.to_owned());
        }
    }
    let script = runs.join("\n");
    let (used, built) = shell_images(&script);
    let mut out = Vec::new();
    for (_, image) in used {
        if built.contains(&image) {
            continue;
        }
        if let Some(problem) = image_problem(&image, allowed) {
            let line = text
                .lines()
                .position(|l| l.contains(&image))
                .map_or(0, |n| n.saturating_add(1));
            out.push(v(&format!("{rel_path}:{line}"), problem));
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
                out.extend(run_step_images(&file, &text, &allowed));
            }
        } else if file.starts_with("deploy/") && yaml_file {
            let text = read(&root.join(&file))?;
            if name.starts_with("compose") {
                out.extend(compose_images(&file, &text, &allowed));
            } else {
                out.extend(yaml_images(&file, &text, &allowed));
            }
        }
        if is_dockerfile(&file) {
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

    // T-60
    #[test]
    fn t_60_dockerfile_arg_defaults_resolve_and_must_be_pinned() {
        let docker = "ARG RUST_IMAGE=rust@sha256:aa\nARG RUNTIME=debian:13-slim\nARG FREE\nFROM ${RUST_IMAGE} AS build\nFROM $RUNTIME\nFROM ${FREE}\nFROM ${MISSING:-alpine@sha256:bb}\nfrom build\n";
        let found = dockerfile_images("deploy/app.Dockerfile", docker);
        let lines: Vec<String> = found.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(
            lines,
            ["deploy/app.Dockerfile:5", "deploy/app.Dockerfile:6"],
            "{found:?}"
        );
        assert!(found[0].message.contains("debian:13-slim"));
        assert!(is_dockerfile("deploy/App.DOCKERFILE"));
        assert!(is_dockerfile("deploy/Containerfile"));
    }

    // T-60
    #[test]
    fn t_60_compose_variable_defaults_must_be_pinned() {
        let compose = "services:\n  a:\n    image: ${A_IMAGE:-postgres:18}\n  b:\n    image: ${B_IMAGE:-nats@sha256:aa}\n  c:\n    image: ${C_IMAGE}\n";
        let found = compose_images("deploy/compose/compose.yaml", compose, &[]);
        assert_eq!(found.len(), 2, "{found:?}");
    }

    // T-60
    #[test]
    fn t_60_docker_run_and_pull_in_workflow_steps_need_a_digest() {
        let wf = "jobs:\n  t:\n    steps:\n      - run: docker pull postgres:18\n      - run: |\n          docker build -t work:ci .\n          docker run --rm -e A=1 --network host work:ci\n          docker run --rm -v \"$PWD:/w\" grafana/k6@sha256:aa run x.js\n          docker compose -f c.yaml run --rm migrate\n          docker container run -it alpine:3 sh\n";
        let found = run_step_images(".github/workflows/ci.yml", wf, &[]);
        let msgs: Vec<String> = found.iter().map(|x| x.message.clone()).collect();
        assert_eq!(found.len(), 2, "{msgs:?}");
        assert!(msgs[0].contains("postgres:18"));
        assert!(msgs[1].contains("alpine:3"));
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
