//! Supply-chain checks (T-38, T-58, T-60; Access F-1…F-3 through T-29).

#[path = "supply_cooldown.rs"]
pub(crate) mod cooldown;
#[path = "supply_metadata.rs"]
pub(crate) mod metadata;
#[path = "supply_pinning.rs"]
mod pinning;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::rules::files::{read, read_optional, rel, walk};
use crate::{Check, Violation};
use cooldown::parse_lock;

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "supply-cooldown",
            run: supply_cooldown,
        },
        Check {
            name: "lockfiles",
            run: check_lockfiles,
        },
        Check {
            name: "build-rs-allowlist",
            run: check_build_rs,
        },
        Check {
            name: "vendored-ide-files",
            run: check_vendored_ide_files,
        },
        Check {
            name: "no-backtracking-regex",
            run: check_backtracking_regex,
        },
        Check {
            name: "no-io-uring",
            run: check_io_uring,
        },
        Check {
            name: "serde-json-depth",
            run: check_serde_json_depth,
        },
    ]
}

fn v(rule: &'static str, path: &str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

fn supply_cooldown(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = cooldown::check(root)?;
    out.extend(pinning::check(root)?);
    Ok(out)
}

const BACKTRACKING_REGEX: &[&str] = &["fancy-regex", "pcre2", "pcre2-sys", "onig", "onig_sys"];

const IO_URING: &[&str] = &["io-uring", "tokio-uring", "rio", "glommio", "monoio"];

/// Locked packages whose name is in `banned`.
pub(crate) fn banned_in_lock(
    lock: &str,
    banned: &[&str],
    rule: &'static str,
    why: &str,
) -> Result<Vec<Violation>, String> {
    Ok(parse_lock(lock)?
        .into_iter()
        .filter(|p| banned.contains(&p.name.as_str()))
        .map(|p| {
            v(
                rule,
                "Cargo.lock",
                format!("`{}` {} is banned: {why}", p.name, p.version),
            )
        })
        .collect())
}

fn check_backtracking_regex(root: &Path) -> Result<Vec<Violation>, String> {
    banned_in_lock(
        &read(&root.join("Cargo.lock"))?,
        BACKTRACKING_REGEX,
        "no-backtracking-regex",
        "only linear-time regex engines (T-33, Access OP-5)",
    )
}

fn check_io_uring(root: &Path) -> Result<Vec<Violation>, String> {
    banned_in_lock(
        &read(&root.join("Cargo.lock"))?,
        IO_URING,
        "no-io-uring",
        "io_uring escapes seccomp filtering (T-33, Access OP-4)",
    )
}

/// JSON nesting stays bounded; `unbounded_depth` turns the limit off (P-7, P-33).
pub(crate) fn serde_json_depth(md: &metadata::Metadata) -> Vec<Violation> {
    md.packages
        .iter()
        .filter(|p| p.name == "serde_json")
        .filter(|p| {
            md.features
                .get(&p.id)
                .is_some_and(|f| f.iter().any(|x| x == "unbounded_depth"))
        })
        .map(|p| {
            v(
                "serde-json-depth",
                "Cargo.lock",
                format!(
                    "serde_json {} has `unbounded_depth` enabled (P-7, P-33)",
                    p.version
                ),
            )
        })
        .collect()
}

fn check_serde_json_depth(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(serde_json_depth(&*metadata::load(root)?))
}

const BUILD_RS_ALLOWLIST: &str = "supply-chain/build-rs-allowlist.txt";
const PROC_MACRO_ALLOWLIST: &str = "supply-chain/proc-macro-allowlist.txt";

fn listed(allowlist: &str) -> BTreeSet<String> {
    allowlist
        .lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim())
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Compares the reviewed list with the actual set: new and stale entries both fail.
pub(crate) fn allowlist_diff(
    actual: &BTreeSet<String>,
    allowlist: &str,
    file: &str,
    what: &str,
) -> Vec<Violation> {
    let listed = listed(allowlist);
    let new = actual.difference(&listed).map(|n| {
        v(
            "build-rs-allowlist",
            file,
            format!("`{n}` has a {what} that was not reviewed (T-38 rule 1); review it and add it"),
        )
    });
    let stale = listed.difference(actual).map(|n| {
        v(
            "build-rs-allowlist",
            file,
            format!("`{n}` no longer has a {what}; remove it"),
        )
    });
    new.chain(stale).collect()
}

/// Build-script and proc-macro packages, excluding workspace members.
pub(crate) fn reviewed_sets(md: &metadata::Metadata) -> (BTreeSet<String>, BTreeSet<String>) {
    let external = || {
        md.packages
            .iter()
            .filter(|p| !md.workspace_members.contains(&p.id))
    };
    (
        external()
            .filter(|p| p.has_build_script)
            .map(|p| p.name.clone())
            .collect(),
        external()
            .filter(|p| p.is_proc_macro)
            .map(|p| p.name.clone())
            .collect(),
    )
}

fn check_build_rs(root: &Path) -> Result<Vec<Violation>, String> {
    let md = metadata::load(root)?;
    let (build, macros) = reviewed_sets(&md);
    let mut out = Vec::new();
    for (actual, file, what) in [
        (&build, BUILD_RS_ALLOWLIST, "build script"),
        (&macros, PROC_MACRO_ALLOWLIST, "proc-macro"),
    ] {
        let text = read_optional(&root.join(file))?.unwrap_or_default();
        out.extend(allowlist_diff(actual, &text, file, what));
    }
    Ok(out)
}

const IDE_DIRS: &[&str] = &[".vscode", ".devcontainer", ".githooks", ".idea"];

fn find_ide_dirs(dir: &Path, root: &Path, out: &mut Vec<Violation>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if IDE_DIRS.contains(&name.as_str()) {
                out.push(v(
                    "vendored-ide-files",
                    &rel(root, &path),
                    "IDE or hook directory in vendored sources (T-38, Access F-2)".to_owned(),
                ));
            }
            find_ide_dirs(&path, root, out)?;
        }
    }
    Ok(())
}

pub(crate) fn check_vendored_ide_files(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let vendor = root.join("vendor");
    if vendor.is_dir() {
        find_ide_dirs(&vendor, root, &mut out)?;
    }
    Ok(out)
}

fn parent_dir(file: &str) -> &str {
    file.rsplit_once('/').map_or("", |(d, _)| d)
}

fn sibling(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// `Cargo.lock` is committed; every npm package is its own project with its own
/// `package-lock.json` and `.npmrc`; the root holds no JS files (T-58).
pub(crate) fn lockfile_violations(
    files: &[String],
    read_file: &dyn Fn(&str) -> String,
) -> Vec<Violation> {
    let mut out = Vec::new();
    if !files.iter().any(|f| f == "Cargo.lock") {
        out.push(v(
            "lockfiles",
            "Cargo.lock",
            "Cargo.lock is missing (T-38)".to_owned(),
        ));
    }
    for root_file in ["package.json", "package-lock.json", ".npmrc"] {
        if files.iter().any(|f| f == root_file) {
            out.push(v(
                "lockfiles",
                root_file,
                "no JS files at the repository root; every package is independent (T-58)"
                    .to_owned(),
            ));
        }
    }
    for pkg in files
        .iter()
        .filter(|f| f.rsplit('/').next() == Some("package.json"))
    {
        let dir = parent_dir(pkg);
        if dir.is_empty() {
            continue;
        }
        if !files.contains(&sibling(dir, "package-lock.json")) {
            out.push(v(
                "lockfiles",
                pkg,
                "package.json without its own package-lock.json (T-58)".to_owned(),
            ));
        }
        let npmrc = sibling(dir, ".npmrc");
        if files.contains(&npmrc) {
            let text = read_file(&npmrc);
            let lines: Vec<String> = text
                .lines()
                .map(|l| l.chars().filter(|c| !c.is_whitespace()).collect())
                .collect();
            for want in ["ignore-scripts=true", "min-release-age=7"] {
                if !lines.iter().any(|l| l == want) {
                    out.push(v(
                        "lockfiles",
                        &npmrc,
                        format!("`.npmrc` must set `{want}` (T-58, T-60)"),
                    ));
                }
            }
        } else {
            out.push(v(
                "lockfiles",
                pkg,
                "package.json without its own .npmrc (T-58)".to_owned(),
            ));
        }
    }
    out
}

fn check_lockfiles(root: &Path) -> Result<Vec<Violation>, String> {
    let files: Vec<String> = walk(root)?.iter().map(|p| rel(root, p)).collect();
    let read_file = |f: &str| std::fs::read_to_string(root.join(f)).unwrap_or_default();
    Ok(lockfile_violations(&files, &read_file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use metadata::fixture::{external, member, metadata as md_json};
    use metadata::parse;

    // T-33
    #[test]
    fn t_33_backtracking_regex_and_io_uring_in_lockfile_are_rejected() {
        let lock = "[[package]]\nname = \"fancy-regex\"\nversion = \"0.14.0\"\n[[package]]\nname = \"regex\"\nversion = \"1.0.0\"\n[[package]]\nname = \"tokio-uring\"\nversion = \"0.5.0\"\n";
        assert_eq!(
            banned_in_lock(lock, BACKTRACKING_REGEX, "r", "x")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(banned_in_lock(lock, IO_URING, "r", "x").unwrap().len(), 1);
    }

    // T-33 P-7
    #[test]
    fn t_33_serde_json_with_unbounded_depth_is_rejected() {
        let pkg = external("serde_json", "1.0.0", false);
        let id = "registry+https://github.com/rust-lang/crates.io-index#serde_json@1.0.0";
        let md = parse(&md_json(
            std::slice::from_ref(&pkg),
            &[(id, &["std", "unbounded_depth"])],
        ))
        .unwrap();
        assert_eq!(serde_json_depth(&md).len(), 1);
        let md = parse(&md_json(&[pkg], &[(id, &["std"])])).unwrap();
        assert!(serde_json_depth(&md).is_empty());
    }

    // T-38
    #[test]
    fn t_38_new_build_script_and_stale_entry_are_both_reported() {
        let mut macro_pkg = external("serde_derive", "1.0.0", false);
        macro_pkg["targets"] =
            serde_json::json!([{"kind": ["proc-macro"], "src_path": "/reg/lib.rs"}]);
        let md = parse(&md_json(
            &[
                external("libc", "0.2.0", true),
                external("serde", "1.0.0", false),
                macro_pkg,
                member("crates/kernel", &[]),
            ],
            &[],
        ))
        .unwrap();
        let (build, macros) = reviewed_sets(&md);
        assert_eq!(
            allowlist_diff(&build, "# reviewed\nproc-macro2\n", "f", "build script").len(),
            2
        );
        assert!(allowlist_diff(&build, "libc\n", "f", "build script").is_empty());
        assert_eq!(macros.into_iter().collect::<Vec<_>>(), ["serde_derive"]);
    }

    // T-58 T-38
    #[test]
    fn t_58_npm_package_needs_its_own_lockfile_and_npmrc() {
        let files = vec!["Cargo.lock".to_owned(), "web/package.json".to_owned()];
        assert_eq!(lockfile_violations(&files, &|_| String::new()).len(), 2);
        let mut complete = files.clone();
        complete.push("web/package-lock.json".to_owned());
        complete.push("web/.npmrc".to_owned());
        let good = |_: &str| "ignore-scripts=true\nmin-release-age=7\n".to_owned();
        assert!(lockfile_violations(&complete, &good).is_empty());
        let weak = |_: &str| "ignore-scripts=false\n".to_owned();
        assert_eq!(lockfile_violations(&complete, &weak).len(), 2);
        let mut rooted = complete;
        rooted.push("package.json".to_owned());
        assert_eq!(lockfile_violations(&rooted, &good).len(), 1);
        assert_eq!(lockfile_violations(&[], &good).len(), 1);
    }
}
