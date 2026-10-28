//! `Bench-Accepted` commit trailers (T-77, T-44 rule 2): a deliberate
//! instruction-count regression is accepted by a `Bench-Accepted: <spec IDs>
//! <reason>` trailer on a commit between the gate's base and `HEAD`. The check
//! rejects malformed trailers; `cargo xtask bench-accepted` prints the valid ones
//! so the gate can pass a regression while still reporting it. The range is
//! `$BENCH_BASE..HEAD` when `BENCH_BASE` names a commit, else the unpushed
//! commits (`@{upstream}..HEAD`), else `HEAD` alone.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Violation;
use crate::catalog::ids::family;

const RULE: &str = "bench-accepted";

/// The trailer key.
pub(crate) const KEY: &str = "Bench-Accepted";

const BASE_ENV: &str = "BENCH_BASE";

/// One accepted regression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Accepted {
    pub(crate) commit: String,
    pub(crate) ids: Vec<String>,
    pub(crate) reason: String,
}

/// One commit of the range: its hash, full message and the values git reads as
/// `Bench-Accepted` trailers.
#[derive(Debug, Clone, Default)]
pub(crate) struct Commit {
    pub(crate) hash: String,
    pub(crate) message: String,
    pub(crate) trailers: Vec<String>,
}

fn id_shaped(token: &str) -> bool {
    token.split_once('-').is_some_and(|(prefix, n)| {
        !prefix.is_empty()
            && prefix.bytes().all(|b| b.is_ascii_uppercase())
            && !n.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
    })
}

/// Splits a trailer value into its spec IDs and reason; every ID must be a Work
/// ID in the rule catalog and the reason must not be empty.
pub(crate) fn parse_value(
    value: &str,
    known: &BTreeSet<String>,
) -> Result<(Vec<String>, String), String> {
    let mut ids = Vec::new();
    let mut words = value.split_whitespace().peekable();
    while let Some(id) = words
        .peek()
        .map(|w| w.trim_end_matches(','))
        .filter(|w| id_shaped(w))
    {
        if family(id).is_none() || !known.contains(id) {
            return Err(format!("`{id}` is not a spec ID in the rule catalog"));
        }
        ids.push(id.to_owned());
        words.next();
    }
    if ids.is_empty() {
        return Err("names no spec ID; the form is `Bench-Accepted: <spec IDs> <reason>`".into());
    }
    let reason = words.collect::<Vec<_>>().join(" ");
    if reason.is_empty() {
        return Err("has no reason after the spec IDs".into());
    }
    Ok((ids, reason))
}

fn short(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

fn key_value(line: &str) -> Option<&str> {
    let (key, value) = line.split_once(':')?;
    key.trim().eq_ignore_ascii_case(KEY).then_some(value.trim())
}

/// The accepted regressions of `commits` and the malformed trailers, as
/// messages naming the commit.
pub(crate) fn evaluate(
    commits: &[Commit],
    known: &BTreeSet<String>,
) -> (Vec<Accepted>, Vec<String>) {
    let mut accepted = Vec::new();
    let mut problems = Vec::new();
    for c in commits {
        for value in c.message.lines().filter_map(key_value) {
            match parse_value(value, known) {
                Ok((ids, reason)) if c.trailers.iter().any(|t| t.trim() == value) => {
                    accepted.push(Accepted {
                        commit: c.hash.clone(),
                        ids,
                        reason,
                    });
                }
                Ok(_) => problems.push(format!(
                    "commit {}: `{KEY}: {value}` is not in the trailer block, so the gate does not read it (T-77)",
                    short(&c.hash)
                )),
                Err(e) => problems.push(format!(
                    "commit {}: `{KEY}: {value}` {e} (T-77 rule 2)",
                    short(&c.hash)
                )),
            }
        }
    }
    (accepted, problems)
}

/// Parses `git log` output in the [`LOG_FORMAT`] layout.
pub(crate) fn parse_log(text: &str) -> Vec<Commit> {
    text.split('\u{1e}')
        .filter_map(|record| {
            let mut fields = record.trim_start_matches('\n').split('\u{1f}');
            let hash = fields.next()?.trim();
            if hash.is_empty() {
                return None;
            }
            let message = fields.next().unwrap_or_default().to_owned();
            let trailers = fields
                .next()
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect();
            Some(Commit {
                hash: hash.to_owned(),
                message,
                trailers,
            })
        })
        .collect()
}

/// `git log` format: hash, message and `Bench-Accepted` trailer values.
pub(crate) const LOG_FORMAT: &str =
    "--format=%H%x1f%B%x1f%(trailers:key=Bench-Accepted,valueonly,unfold)%x1e";

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn is_commit(root: &Path, rev: &str) -> bool {
    !rev.is_empty()
        && !rev.bytes().all(|b| b == b'0')
        && git(
            root,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("{rev}^{{commit}}"),
            ],
        )
        .is_ok()
}

/// The `git log` revision arguments of the range the trailers are read from.
fn range(root: &Path) -> Vec<String> {
    let base = std::env::var(BASE_ENV).unwrap_or_default();
    if is_commit(root, base.trim()) {
        return vec![format!("{}..HEAD", base.trim())];
    }
    if is_commit(root, "@{upstream}") {
        return vec!["@{upstream}..HEAD".to_owned()];
    }
    vec!["-1".to_owned(), "HEAD".to_owned()]
}

fn commits(root: &Path) -> Result<Vec<Commit>, String> {
    let mut args = vec!["log", "--no-color", LOG_FORMAT];
    let revs = range(root);
    args.extend(revs.iter().map(String::as_str));
    Ok(parse_log(&git(root, &args)?))
}

fn read(root: &Path) -> Result<(Vec<Accepted>, Vec<String>), String> {
    let known = crate::catalog::load(root)?.ids();
    Ok(evaluate(&commits(root)?, &known))
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let (_, problems) = read(root)?;
    Ok(problems
        .into_iter()
        .map(|message| Violation {
            rule: RULE,
            path: PathBuf::from("git log"),
            message,
        })
        .collect())
}

/// Prints the accepted regressions of the range, one per line; fails on a
/// malformed trailer.
pub(crate) fn report(root: &Path) -> Result<String, String> {
    let (accepted, problems) = read(root)?;
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    let mut out = String::new();
    for a in &accepted {
        let _ = writeln!(
            out,
            "{} {KEY}: {} {}",
            short(&a.commit),
            a.ids.join(" "),
            a.reason
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> BTreeSet<String> {
        ["T-44", "T-77", "SEC-32"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn commit(message: &str, trailers: &[&str]) -> Commit {
        Commit {
            hash: "0123456789abcdef0123".into(),
            message: message.into(),
            trailers: trailers.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    // T-77 T-44
    #[test]
    fn t_77_valid_trailer_accepts_the_regression_and_is_reported() {
        let value = "T-44, SEC-32 witness check adds one hash per commit";
        let c = commit(&format!("feat: x\n\nBody.\n\n{KEY}: {value}\n"), &[value]);
        let (accepted, problems) = evaluate(&[c], &known());
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(
            accepted,
            [Accepted {
                commit: "0123456789abcdef0123".into(),
                ids: vec!["T-44".into(), "SEC-32".into()],
                reason: "witness check adds one hash per commit".into(),
            }]
        );
    }

    // T-77
    #[test]
    fn t_77_trailer_without_spec_id_or_reason_fails() {
        let k = known();
        assert!(parse_value("adds a verification step", &k).is_err());
        assert!(parse_value("T-44", &k).is_err());
        assert!(parse_value("T-44 T-77", &k).is_err());
        assert!(parse_value("T-9999 reason", &k).is_err());
        assert!(parse_value("ZZ-1 reason", &k).is_err());
        assert!(parse_value("", &k).is_err());
        let bad = commit(
            &format!("fix: y\n\n{KEY}: T-44\nbench-accepted: slower\n"),
            &["T-44", "slower"],
        );
        let (accepted, problems) = evaluate(&[bad], &k);
        assert!(accepted.is_empty());
        assert_eq!(problems.len(), 2, "{problems:?}");
    }

    // T-77
    #[test]
    fn t_77_trailer_outside_the_trailer_block_fails() {
        let c = commit(&format!("fix: z\n\n{KEY}: T-44 slower\n\nmore text\n"), &[]);
        let (accepted, problems) = evaluate(&[c], &known());
        assert!(accepted.is_empty());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("not in the trailer block"));
    }

    // T-77
    #[test]
    fn t_77_commits_without_trailers_accept_nothing() {
        let (accepted, problems) = evaluate(&[commit("chore: a\n", &[])], &known());
        assert!(accepted.is_empty() && problems.is_empty());
    }

    // T-77
    #[test]
    fn t_77_git_log_records_split_into_commits() {
        let text = "aaa\u{1f}feat: a\n\nBench-Accepted: T-44 why\n\u{1f}T-44 why\n\u{1e}\nbbb\u{1f}fix: b\n\u{1f}\u{1e}\n";
        let commits = parse_log(text);
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].hash, "aaa");
        assert_eq!(commits[0].trailers, ["T-44 why"]);
        assert_eq!(commits[1].hash, "bbb");
        assert!(commits[1].trailers.is_empty());
    }
}
