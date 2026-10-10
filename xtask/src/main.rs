//! Repository rule checks and development automation (T-46, T-52).

#![cfg_attr(
    test,
    allow(
        clippy::assert_is_empty,
        reason = "tests assert empty findings; a failure prints the findings through the test name and context"
    )
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "xtask is a developer CLI; it reports to the terminal"
)]

mod catalog;
mod counterparts;
mod policy;
mod rules;
mod sha256;
mod supply_chain;
mod yaml;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// One rule violation, reported as `path: [rule] message`.
#[derive(Debug)]
pub(crate) struct Violation {
    pub(crate) rule: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) message: String,
}

/// A named check over the repository.
pub(crate) struct Check {
    pub(crate) name: &'static str,
    pub(crate) run: fn(&Path) -> Result<Vec<Violation>, String>,
}

fn checks() -> Vec<Check> {
    let mut all = Vec::new();
    all.extend(rules::checks());
    all.extend(policy::checks());
    all.extend(supply_chain::checks());
    all.extend(catalog::checks());
    all
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Names Access CI uses for checks that carry another name here.
const ALIASES: &[(&str, &str)] = &[("cooldown", "supply-cooldown")];

fn run_checks(root: &Path, only: Option<&str>) -> ExitCode {
    let only = only.map(|name| {
        ALIASES
            .iter()
            .find(|(alias, _)| *alias == name)
            .map_or(name, |(_, target)| *target)
    });
    if let Some(name) = only
        && !checks().iter().any(|check| check.name == name)
    {
        eprintln!("unknown check `{name}`; see `cargo xtask list`");
        return ExitCode::FAILURE;
    }
    let mut failed = false;
    for check in checks() {
        if only.is_some_and(|name| name != check.name) {
            continue;
        }
        match (check.run)(root) {
            Ok(violations) if violations.is_empty() => println!("ok    {}", check.name),
            Ok(violations) => {
                failed = true;
                println!("FAIL  {} ({} violations)", check.name, violations.len());
                for v in violations {
                    println!("      {}: [{}] {}", v.path.display(), v.rule, v.message);
                }
            }
            Err(error) => {
                failed = true;
                println!("ERROR {}: {error}", check.name);
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: cargo xtask <command>");
    eprintln!("  check [NAME]                 run all rule checks, or only NAME");
    eprintln!("  list                         list check names");
    eprintln!(
        "  catalog [--links-only]       regenerate the rule catalog from the local spec (T-46)"
    );
    eprintln!(
        "  spec-counterparts [--update] compare E-40 counterpart clauses with recorded digests (T-50)"
    );
    ExitCode::FAILURE
}

fn report(name: &str, result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{name}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = workspace_root();
    let flag = |f: &str| args.iter().skip(1).any(|a| a == f);
    match args.first().map(String::as_str) {
        Some("check") => run_checks(&root, args.get(1).map(String::as_str)),
        Some("list") => {
            for check in checks() {
                println!("{}", check.name);
            }
            ExitCode::SUCCESS
        }
        Some("catalog") => report("catalog", catalog::generate(&root, flag("--links-only"))),
        Some("spec-counterparts") => report(
            "spec-counterparts",
            counterparts::run(&root, flag("--update")),
        ),
        _ => usage(),
    }
}
