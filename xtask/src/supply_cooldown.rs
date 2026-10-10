//! Cooldown part of `supply-cooldown` (T-60 rule 2, T-38 rule 1): every crates.io
//! package in `Cargo.lock` was published at least seven days ago; registry and
//! git sources stay closed (T-31 rule 2). Offline the check judges what the local
//! cache knows; `XTASK_ONLINE=1` queries crates.io.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

use crate::Violation;
use crate::rules::files::{read, read_optional};

const RULE: &str = "supply-cooldown";

/// Minimum age of a dependency version in days (T-60 rule 2).
pub(crate) const COOLDOWN_DAYS: i64 = 7;

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
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

fn fetch(name: &str, version: &str) -> Result<String, String> {
    let url = format!("https://crates.io/api/v1/crates/{name}/{version}");
    let output = Command::new("curl")
        .args(["-sSf", "--max-time", "20", "-A", USER_AGENT, &url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let v: Value = serde_json::from_slice(&output.stdout).map_err(|e| format!("{url}: {e}"))?;
    v.get("version")
        .and_then(|x| x.get("created_at"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{url}: no created_at"))
}

/// True when online checks are enabled (`XTASK_ONLINE=1`).
pub(crate) fn online() -> bool {
    std::env::var("XTASK_ONLINE").is_ok_and(|v| v == "1")
}

fn v(message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from("Cargo.lock"),
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

/// Cooldown verdicts from known publication dates.
pub(crate) fn cooldown_violations(
    locked: &[Locked],
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
            out.push(v(format!(
                "{key} was published {ts}, less than {COOLDOWN_DAYS} days ago (T-60 rule 2)"
            )));
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let locked = parse_lock(&read(&root.join("Cargo.lock"))?)?;
    let exceptions: Exceptions = match read_optional(&root.join(EXCEPTIONS_FILE))? {
        Some(text) => toml::from_str(&text).map_err(|e| format!("{EXCEPTIONS_FILE}: {e}"))?,
        None => Exceptions::default(),
    };
    let cache_path = root.join(CACHE_FILE);
    let mut cache = load_cache(&cache_path);
    let now = now_unix()?;
    let online = online();
    let mut out = source_violations(&locked);
    let mut fetched_any = false;
    let mut unchecked = 0_usize;
    for pkg in locked
        .iter()
        .filter(|p| p.source.as_deref() == Some(CRATES_IO))
    {
        let key = format!("{}@{}", pkg.name, pkg.version);
        if !cache.contains_key(&key) && online {
            if fetched_any {
                std::thread::sleep(Duration::from_secs(1));
            }
            fetched_any = true;
            match fetch(&pkg.name, &pkg.version) {
                Ok(ts) => {
                    cache.insert(key.clone(), ts);
                }
                Err(error) => out.push(v(format!("{key}: publication date unknown: {error}"))),
            }
        }
        if !cache.contains_key(&key) {
            unchecked = unchecked.saturating_add(1);
        }
    }
    if fetched_any {
        save_cache(&cache_path, &cache)?;
    }
    out.extend(cooldown_violations(
        &locked,
        &cache,
        &exceptions.exception,
        now,
    ));
    if unchecked > 0 && !online {
        println!(
            "      supply-cooldown: {unchecked} versions not in the local cache were not judged; run with XTASK_ONLINE=1"
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
        assert_eq!(cooldown_violations(&locked, &published, &[], now).len(), 1);
        let fix = Exception {
            name: "a".into(),
            version: "1.0.0".into(),
            advisory: "RUSTSEC-2026-0001".into(),
            reason: "fixes a known vulnerability".into(),
        };
        assert!(cooldown_violations(&locked, &published, &[fix], now).is_empty());
        let later = now.saturating_add(DAY.saturating_mul(6));
        assert!(cooldown_violations(&locked, &published, &[], later).is_empty());
    }

    // T-31 T-38
    #[test]
    fn t_31_git_sources_in_the_lockfile_are_rejected() {
        let locked = parse_lock("[[package]]\nname = \"esuiss-crypto\"\nversion = \"0.1.0\"\nsource = \"git+https://github.com/e-suiss/access#abc\"\n").unwrap();
        assert_eq!(source_violations(&locked).len(), 1);
    }
}
