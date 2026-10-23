//! Cooldown part of `supply-cooldown` (T-60 rule 2, T-38 rule 1, T-58): every
//! crates.io package in every `Cargo.lock` and every npm package in every
//! `package-lock.json` was published at least seven days ago; registry and git
//! sources stay closed (T-31 rule 2); npm packages pin exact versions and lock
//! every package with a registry URL and an integrity hash. Offline the check
//! judges what the local cache knows; `XTASK_ONLINE=1` queries crates.io and the
//! npm registry, and in CI (`CI=true`) or online a version without a verdict fails.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

use crate::Violation;
use crate::rules::files::{file_name, read, read_optional, repo_files};

const RULE: &str = "supply-cooldown";

/// Minimum age of a dependency version in days (T-60 rule 2).
pub(crate) const COOLDOWN_DAYS: i64 = 7;

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const NPM_REGISTRY: &str = "https://registry.npmjs.org/";
const CACHE_FILE: &str = "target/xtask-cooldown-cache.json";
const EXCEPTIONS_FILE: &str = "supply-chain/cooldown-exceptions.toml";
const USER_AGENT: &str = "work-xtask cooldown check (https://github.com/e-suiss/work)";

/// A locked package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Locked {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: Option<String>,
}

/// Parses `Cargo.lock`.
pub(crate) fn parse_lock(text: &str) -> Result<Vec<Locked>, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("Cargo.lock: {e}"))?;
    let packages = table
        .get("package")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let field =
        |p: &toml::Value, k: &str| p.get(k).and_then(toml::Value::as_str).map(str::to_owned);
    Ok(packages
        .iter()
        .map(|p| Locked {
            name: field(p, "name").unwrap_or_default(),
            version: field(p, "version").unwrap_or_default(),
            source: field(p, "source"),
        })
        .collect())
}

/// A reviewed security exception: a fix that may not wait (T-60 rule 2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Exception {
    #[serde(rename = "crate")]
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) advisory: String,
    pub(crate) reason: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exceptions {
    #[serde(default)]
    exception: Vec<Exception>,
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y.checked_div_euclid(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = m.checked_add(if m > 2 { -3 } else { 9 })?;
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// Parses an RFC 3339 UTC timestamp into Unix seconds.
pub(crate) fn parse_timestamp(ts: &str) -> Option<i64> {
    let num = |range: std::ops::Range<usize>| ts.get(range)?.parse::<i64>().ok();
    let days = days_from_civil(num(0..4)?, num(5..7)?, num(8..10)?)?;
    let secs = num(11..13)?
        .checked_mul(3600)?
        .checked_add(num(14..16)?.checked_mul(60)?)?
        .checked_add(num(17..19)?)?;
    days.checked_mul(86_400)?.checked_add(secs)
}

/// Whether a version published at `published` is younger than the cooldown at
/// `now`, counted in whole UTC calendar days.
pub(crate) fn too_new(published: i64, now: i64) -> bool {
    now.div_euclid(86_400)
        .saturating_sub(published.div_euclid(86_400))
        < COOLDOWN_DAYS
}

/// Now in Unix seconds; xtask is its own clock adapter.
#[expect(
    clippy::disallowed_methods,
    reason = "the developer tool reads the wall clock once to age dependency versions"
)]
pub(crate) fn now_unix() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())
        .and_then(|d| i64::try_from(d.as_secs()).map_err(|e| e.to_string()))
}

fn load_cache(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<BTreeMap<String, String>>(&s).ok())
        .unwrap_or_default()
}

fn save_cache(path: &Path, cache: &BTreeMap<String, String>) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let json = serde_json::to_string_pretty(cache).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
}

fn get_json(url: &str) -> Result<Value, String> {
    let output = Command::new("curl")
        .args([
            "-sSf",
            "--compressed",
            "--max-time",
            "60",
            "-A",
            USER_AGENT,
            url,
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("{url}: {e}"))
}

fn fetch_crate(name: &str, version: &str) -> Result<String, String> {
    let url = format!("https://crates.io/api/v1/crates/{name}/{version}");
    get_json(&url)?
        .get("version")
        .and_then(|x| x.get("created_at"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{url}: no created_at"))
}

fn fetch_npm(name: &str, version: &str) -> Result<String, String> {
    let url = format!("{NPM_REGISTRY}{}", name.replace('/', "%2f"));
    get_json(&url)?
        .get("time")
        .and_then(|t| t.get(version))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{url}: no publication time for {version}"))
}

/// True when online checks are enabled (`XTASK_ONLINE=1`).
pub(crate) fn online() -> bool {
    std::env::var("XTASK_ONLINE").is_ok_and(|v| v == "1")
}

/// True when every version needs a verdict: in CI (`CI=true`) or online.
pub(crate) fn strict() -> bool {
    online() || std::env::var("CI").is_ok_and(|v| v == "true" || v == "1")
}

fn v(message: String) -> Violation {
    at("Cargo.lock", message)
}

fn at(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    }
}

/// Sources other than crates.io and the workspace (T-31 rule 2: no git dependencies).
pub(crate) fn source_violations(locked: &[Locked]) -> Vec<Violation> {
    locked
        .iter()
        .filter(|p| p.source.as_deref().is_some_and(|s| s != CRATES_IO))
        .map(|p| {
            v(format!(
                "{}@{} comes from `{}`; only crates.io is allowed (T-31 rule 2, T-38)",
                p.name,
                p.version,
                p.source.as_deref().unwrap_or_default()
            ))
        })
        .collect()
}

/// An npm package locked in a `package-lock.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmLocked {
    pub(crate) name: String,
    pub(crate) version: String,
}

/// True for an exact semantic version (`1.2.3`, `1.2.3-rc.1`), never a range.
pub(crate) fn is_exact_version(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

const DEP_FIELDS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

/// Ranges and non-registry specifiers in a `package.json` (T-38: exact versions).
pub(crate) fn package_json_violations(path: &str, text: &str) -> Vec<Violation> {
    let json: Value = match serde_json::from_str(text) {
        Ok(j) => j,
        Err(e) => return vec![at(path, format!("not JSON: {e}"))],
    };
    let mut out = Vec::new();
    for field in DEP_FIELDS {
        for (name, spec) in json
            .get(*field)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let spec = spec.as_str().unwrap_or_default();
            if !is_exact_version(spec) {
                out.push(at(
                    path,
                    format!(
                        "{field} `{name}` is `{spec}`; dependencies pin an exact version (T-38)"
                    ),
                ));
            }
        }
    }
    out
}

/// The locked packages of a `package-lock.json` and its structural problems: an
/// empty or old lockfile, entries without a registry URL or integrity hash, and a
/// root entry that disagrees with `package.json`.
pub(crate) fn parse_npm_lock(
    path: &str,
    lock: &str,
    manifest: Option<&str>,
) -> (Vec<NpmLocked>, Vec<Violation>) {
    let mut out = Vec::new();
    let json: Value = match serde_json::from_str(lock) {
        Ok(j) => j,
        Err(e) => return (Vec::new(), vec![at(path, format!("not JSON: {e}"))]),
    };
    if json
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        < 3
    {
        out.push(at(path, "lockfileVersion must be 3 (T-58)".to_owned()));
    }
    let Some(packages) = json.get("packages").and_then(Value::as_object) else {
        out.push(at(
            path,
            "the lockfile locks no packages (T-38, T-58)".to_owned(),
        ));
        return (Vec::new(), out);
    };
    let mut locked = Vec::new();
    for (key, entry) in packages {
        if key.is_empty() || entry.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let name = entry.get("name").and_then(Value::as_str).map_or_else(
            || {
                key.rsplit_once("node_modules/")
                    .map_or(key.as_str(), |(_, n)| n)
                    .to_owned()
            },
            str::to_owned,
        );
        let field = |k: &str| entry.get(k).and_then(Value::as_str).unwrap_or_default();
        let version = field("version").to_owned();
        if !is_exact_version(&version) {
            out.push(at(path, format!("`{key}` has no exact version (T-38)")));
        }
        if !field("resolved").starts_with(NPM_REGISTRY) {
            out.push(at(
                path,
                format!("`{key}` does not resolve from {NPM_REGISTRY} (T-31 rule 2, T-38)"),
            ));
        }
        if !field("integrity").starts_with("sha512-") {
            out.push(at(
                path,
                format!("`{key}` has no sha512 integrity hash (T-38)"),
            ));
        }
        locked.push(NpmLocked { name, version });
    }
    let root = packages.get("");
    if root.is_none() {
        out.push(at(
            path,
            "the lockfile has no root package entry (T-58)".to_owned(),
        ));
    }
    if let (Some(root), Some(manifest)) = (
        root,
        manifest.and_then(|m| serde_json::from_str::<Value>(m).ok()),
    ) {
        for field in DEP_FIELDS {
            if root.get(*field) != manifest.get(*field) {
                out.push(at(
                    path,
                    format!("root `{field}` differ from package.json; run `npm install` (T-58)"),
                ));
            }
        }
    }
    (locked, out)
}

/// Cooldown verdicts from known publication dates.
fn cooldown_in(
    locked: &[Locked],
    lock_path: &str,
    published: &BTreeMap<String, String>,
    exceptions: &[Exception],
    now: i64,
) -> Vec<Violation> {
    let mut out = Vec::new();
    for e in exceptions {
        if e.advisory.trim().is_empty() || e.reason.trim().is_empty() {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(EXCEPTIONS_FILE),
                message: format!(
                    "{}@{}: an exception needs an advisory and a reason (T-60 rule 2)",
                    e.name, e.version
                ),
            });
        }
    }
    for pkg in locked
        .iter()
        .filter(|p| p.source.as_deref() == Some(CRATES_IO))
    {
        let key = format!("{}@{}", pkg.name, pkg.version);
        let excepted = exceptions
            .iter()
            .any(|e| e.name == pkg.name && e.version == pkg.version && !e.reason.trim().is_empty());
        if let Some((ts, t)) = published
            .get(&key)
            .and_then(|ts| parse_timestamp(ts).map(|t| (ts, t)))
            && too_new(t, now)
            && !excepted
        {
            out.push(at(
                lock_path,
                format!(
                    "{key} was published {ts}, less than {COOLDOWN_DAYS} days ago (T-60 rule 2)"
                ),
            ));
        }
    }
    out
}

/// Cooldown verdicts for npm packages; cache keys carry an `npm:` prefix.
pub(crate) fn npm_cooldown_violations(
    lock_path: &str,
    locked: &[NpmLocked],
    published: &BTreeMap<String, String>,
    now: i64,
) -> Vec<Violation> {
    locked
        .iter()
        .filter_map(|p| {
            let key = npm_key(p);
            let ts = published.get(&key)?;
            let t = parse_timestamp(ts)?;
            too_new(t, now).then(|| {
                at(
                    lock_path,
                    format!(
                        "{}@{} was published {ts}, less than {COOLDOWN_DAYS} days ago (T-60 rule 2)",
                        p.name, p.version
                    ),
                )
            })
        })
        .collect()
}

fn npm_key(p: &NpmLocked) -> String {
    format!("npm:{}@{}", p.name, p.version)
}

/// The verdict state of one version after the cache and any online lookup.
pub(crate) fn unjudged_violation(lock_path: &str, key: &str, strict: bool) -> Option<Violation> {
    strict.then(|| {
        at(
            lock_path,
            format!(
                "{key}: publication date unknown; in CI and online every version needs a verdict (T-60 rule 2)"
            ),
        )
    })
}

/// Looks up `key` in the cache, fetching it online when missing; returns whether
/// a verdict is possible.
fn judge(
    cache: &mut BTreeMap<String, String>,
    key: &str,
    online: bool,
    fetch: impl FnOnce() -> Result<String, String>,
    errors: &mut Vec<String>,
) -> bool {
    if !cache.contains_key(key) && online {
        match fetch() {
            Ok(ts) => {
                cache.insert(key.to_owned(), ts);
            }
            Err(error) => errors.push(format!("{key}: {error}")),
        }
    }
    cache.contains_key(key)
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let exceptions: Exceptions = match read_optional(&root.join(EXCEPTIONS_FILE))? {
        Some(text) => toml::from_str(&text).map_err(|e| format!("{EXCEPTIONS_FILE}: {e}"))?,
        None => Exceptions::default(),
    };
    let cache_path = root.join(CACHE_FILE);
    let mut cache = load_cache(&cache_path);
    let now = now_unix()?;
    let (online, strict) = (online(), strict());
    let files = repo_files(root)?;
    let mut out = Vec::new();
    let mut fetched_any = false;
    let mut unjudged = 0_usize;
    let mut errors = Vec::new();
    for lock_path in files.iter().filter(|f| file_name(f) == "Cargo.lock") {
        let locked = parse_lock(&read(&root.join(lock_path))?)?;
        out.extend(source_violations(&locked).into_iter().map(|mut x| {
            x.path = PathBuf::from(lock_path);
            x
        }));
        for pkg in locked
            .iter()
            .filter(|p| p.source.as_deref() == Some(CRATES_IO))
        {
            let key = format!("{}@{}", pkg.name, pkg.version);
            let was_cached = cache.contains_key(&key);
            if !was_cached && online {
                if fetched_any {
                    std::thread::sleep(Duration::from_secs(1));
                }
                fetched_any = true;
            }
            let fetch = || fetch_crate(&pkg.name, &pkg.version);
            if !judge(&mut cache, &key, online, fetch, &mut errors) {
                unjudged = unjudged.saturating_add(1);
                out.extend(unjudged_violation(lock_path, &key, strict));
            }
        }
        out.extend(cooldown_in(
            &locked,
            lock_path,
            &cache,
            &exceptions.exception,
            now,
        ));
    }
    for lock_path in files.iter().filter(|f| file_name(f) == "package-lock.json") {
        let dir = lock_path.rsplit_once('/').map_or("", |(d, _)| d);
        let manifest_path = if dir.is_empty() {
            "package.json".to_owned()
        } else {
            format!("{dir}/package.json")
        };
        let manifest = read_optional(&root.join(&manifest_path))?;
        if let Some(m) = &manifest {
            out.extend(package_json_violations(&manifest_path, m));
        }
        let (locked, problems) = parse_npm_lock(
            lock_path,
            &read(&root.join(lock_path))?,
            manifest.as_deref(),
        );
        out.extend(problems);
        for pkg in &locked {
            let key = npm_key(pkg);
            fetched_any |= online && !cache.contains_key(&key);
            let fetch = || fetch_npm(&pkg.name, &pkg.version);
            if !judge(&mut cache, &key, online, fetch, &mut errors) {
                unjudged = unjudged.saturating_add(1);
                out.extend(unjudged_violation(lock_path, &key, strict));
            }
        }
        out.extend(npm_cooldown_violations(lock_path, &locked, &cache, now));
    }
    if fetched_any {
        save_cache(&cache_path, &cache)?;
    }
    for error in errors {
        println!("      supply-cooldown: {error}");
    }
    if unjudged > 0 && !strict {
        println!(
            "      supply-cooldown: {unjudged} versions not in the local cache were not judged; run with XTASK_ONLINE=1"
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    // T-60 T-38
    #[test]
    fn t_60_crates_io_timestamps_parse_to_unix_seconds() {
        assert_eq!(parse_timestamp("1970-01-02T00:00:01.5Z"), Some(86_401));
        assert_eq!(parse_timestamp("2026-10-09T00:00:00Z"), Some(1_791_504_000));
    }

    // T-60 T-38
    #[test]
    fn t_60_version_published_six_days_ago_is_too_new() {
        let now = 8_643_600;
        assert!(too_new(8_125_200, now));
        assert!(!too_new(8_038_800, now));
        assert!(!too_new(8_115_200, now));
    }

    // T-60 T-38
    #[test]
    fn t_60_new_version_fails_unless_a_reasoned_exception_covers_it() {
        let locked = parse_lock("version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n[[package]]\nname = \"ws\"\nversion = \"0.0.0\"\n").unwrap();
        let published = BTreeMap::from([("a@1.0.0".to_owned(), "2026-10-08T00:00:00Z".to_owned())]);
        let now = parse_timestamp("2026-10-10T00:00:00Z").unwrap();
        assert_eq!(
            cooldown_in(&locked, "Cargo.lock", &published, &[], now).len(),
            1
        );
        let fix = Exception {
            name: "a".into(),
            version: "1.0.0".into(),
            advisory: "RUSTSEC-2026-0001".into(),
            reason: "fixes a known vulnerability".into(),
        };
        assert!(cooldown_in(&locked, "Cargo.lock", &published, &[fix], now).is_empty());
        let later = now.saturating_add(DAY.saturating_mul(6));
        assert!(cooldown_in(&locked, "Cargo.lock", &published, &[], later).is_empty());
    }

    // T-60 T-38
    #[test]
    fn t_60_unjudged_versions_fail_in_ci_and_online() {
        assert!(unjudged_violation("fuzz/Cargo.lock", "a@1.0.0", true).is_some());
        assert!(unjudged_violation("fuzz/Cargo.lock", "a@1.0.0", false).is_none());
        let mut cache = BTreeMap::new();
        let mut errors = Vec::new();
        let offline = judge(
            &mut cache,
            "a@1.0.0",
            false,
            || panic!("offline"),
            &mut errors,
        );
        assert!(!offline);
        let failed = judge(
            &mut cache,
            "a@1.0.0",
            true,
            || Err("timeout".to_owned()),
            &mut errors,
        );
        assert!(!failed);
        assert_eq!(errors.len(), 1);
        let found = judge(
            &mut cache,
            "a@1.0.0",
            true,
            || Ok("2026-01-01T00:00:00Z".to_owned()),
            &mut errors,
        );
        assert!(found);
    }

    // T-60 T-38 T-58
    #[test]
    fn t_60_new_npm_versions_are_too_new() {
        let lock = r#"{"lockfileVersion":3,"packages":{"":{"name":"@esuiss/work-kernel","devDependencies":{"vite":"8.3.2"}},"node_modules/vite":{"version":"8.3.2","resolved":"https://registry.npmjs.org/vite/-/vite-8.3.2.tgz","integrity":"sha512-aa"},"node_modules/@scope/x/node_modules/y":{"version":"1.0.0","resolved":"https://registry.npmjs.org/y/-/y-1.0.0.tgz","integrity":"sha512-bb"}}}"#;
        let manifest = r#"{"devDependencies":{"vite":"8.3.2"}}"#;
        let (locked, problems) =
            parse_npm_lock("packages/kernel/package-lock.json", lock, Some(manifest));
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(locked.len(), 2);
        assert!(locked.iter().any(|p| p.name == "y"));
        let published = BTreeMap::from([(
            "npm:vite@8.3.2".to_owned(),
            "2026-10-12T00:00:00Z".to_owned(),
        )]);
        let now = parse_timestamp("2026-10-16T00:00:00Z").unwrap();
        assert_eq!(
            npm_cooldown_violations("l", &locked, &published, now).len(),
            1
        );
    }

    // T-38 T-58
    #[test]
    fn t_38_empty_lockfiles_and_version_ranges_are_rejected() {
        let (_, empty) = parse_npm_lock("p/package-lock.json", "{}", None);
        assert_eq!(empty.len(), 2, "{empty:?}");
        let loose = r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0","resolved":"git+https://x/a.git","integrity":"sha1-aa"}}}"#;
        let (_, problems) = parse_npm_lock(
            "p/package-lock.json",
            loose,
            Some(r#"{"dependencies":{"a":"1.0.0"}}"#),
        );
        assert_eq!(problems.len(), 3, "{problems:?}");
        let manifest = r#"{"dependencies":{"a":"^1.0.0","b":"~2.1.0","c":"1.2.3","d":"latest","e":"file:../e"},"devDependencies":{"f":"1.0.0-rc.1"}}"#;
        assert_eq!(package_json_violations("p/package.json", manifest).len(), 4);
    }

    // T-31 T-38
    #[test]
    fn t_31_git_sources_in_the_lockfile_are_rejected() {
        let locked = parse_lock("[[package]]\nname = \"esuiss-crypto\"\nversion = \"0.1.0\"\nsource = \"git+https://github.com/e-suiss/access#abc\"\n").unwrap();
        assert_eq!(source_violations(&locked).len(), 1);
    }
}
