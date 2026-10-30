//! Cooldown part of `supply-cooldown` (T-60 rule 2, T-38 rule 1, T-58): every
//! crates.io package in every `Cargo.lock` and every npm package in every
//! `package-lock.json` was published at least seven days ago; registry and git
//! sources stay closed (T-31 rule 2); npm packages pin exact versions and lock
//! every package with a registry URL and an integrity hash. A Suiss shared crate
//! (`esuiss-*`) pinned exactly everywhere is exempt from the cooldown when its
//! crates.io trusted publishing record names the commit of a verified, signed
//! Access tag (T-86). Offline the check judges what the local cache knows;
//! `XTASK_ONLINE=1` queries crates.io, the npm registry and GitHub, and in CI
//! (`CI=true`) or online a version without a verdict fails.

use std::collections::{BTreeMap, BTreeSet};
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
const SHARED_PREFIX: &str = "esuiss-";
const ACCESS_REPOSITORY: &str = "e-suiss/access";
const GITHUB_API: &str = "https://api.github.com/repos";
const VERIFIED: &str = "verified:";
const REJECTED: &str = "rejected:";
const DEPENDENCY_TABLES: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

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

fn fetch_provenance(name: &str, version: &str) -> Result<Provenance, String> {
    let crate_json = get_json(&format!("https://crates.io/api/v1/crates/{name}/{version}"))?;
    let access = format!("{GITHUB_API}/{ACCESS_REPOSITORY}/git");
    verify_provenance(
        &crate_json,
        || get_json(&format!("{access}/ref/tags/v{version}")),
        |sha| get_json(&format!("{access}/tags/{sha}")),
    )
}

/// Refreshes the provenance verdict of a version online unless it is already
/// verified; a lookup without a verdict leaves the cache unchanged.
fn judge_provenance(
    cache: &mut BTreeMap<String, String>,
    key: &str,
    online: bool,
    fetch: impl FnOnce() -> Result<Provenance, String>,
    errors: &mut Vec<String>,
) -> bool {
    let verified =
        |c: &BTreeMap<String, String>| c.get(key).is_some_and(|v| v.starts_with(VERIFIED));
    if !verified(cache) && online {
        match fetch() {
            Ok(verdict) => {
                if let Provenance::Rejected(reason) = &verdict {
                    errors.push(format!("{key}: {reason} (T-86)"));
                }
                cache.insert(key.to_owned(), verdict.cache_value());
            }
            Err(error) => errors.push(format!("{key}: {error} (T-86)")),
        }
    }
    verified(cache)
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

/// True for a Suiss shared crate published from the Access repo (T-86 rule 1).
pub(crate) fn is_shared(name: &str) -> bool {
    name.starts_with(SHARED_PREFIX)
}

/// Adds every dependency declaration of a `Cargo.toml` to `into`, keyed by the
/// depended-on package name (renames resolved) with its version requirement;
/// an entry without a version records an empty requirement and inherited
/// `workspace = true` entries are covered by the workspace declaration.
pub(crate) fn collect_declarations(
    manifest: &str,
    into: &mut BTreeMap<String, Vec<String>>,
) -> Result<(), String> {
    let table: toml::Table = manifest
        .parse()
        .map_err(|e: toml::de::Error| e.to_string())?;
    let parents = std::iter::once(&table)
        .chain(table.get("workspace").and_then(toml::Value::as_table))
        .chain(
            table
                .get("target")
                .and_then(toml::Value::as_table)
                .into_iter()
                .flat_map(toml::Table::values)
                .filter_map(toml::Value::as_table),
        );
    let tables = parents.flat_map(|parent| {
        DEPENDENCY_TABLES
            .iter()
            .filter_map(|k| parent.get(*k).and_then(toml::Value::as_table))
    });
    for (key, dep) in tables.flatten() {
        let (package, requirement) = match dep {
            toml::Value::String(req) => (key.as_str(), req.as_str()),
            toml::Value::Table(t) => {
                if t.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                    continue;
                }
                let field = |k: &str| t.get(k).and_then(toml::Value::as_str);
                (
                    field("package").unwrap_or(key),
                    field("version").unwrap_or_default(),
                )
            }
            _ => (key.as_str(), ""),
        };
        into.entry(package.to_owned())
            .or_default()
            .push(requirement.to_owned());
    }
    Ok(())
}

/// True when every declaration of `name` pins exactly `=version` (T-86 rule 2).
pub(crate) fn exactly_pinned(
    declarations: &BTreeMap<String, Vec<String>>,
    name: &str,
    version: &str,
) -> bool {
    let want = format!("={version}");
    declarations
        .get(name)
        .is_some_and(|reqs| !reqs.is_empty() && reqs.iter().all(|r| r.trim() == want))
}

/// The outcome of a provenance lookup that reached a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Provenance {
    /// The commit both the trusted publishing record and the signed tag name.
    Verified(String),
    /// Why the version does not qualify.
    Rejected(String),
}

impl Provenance {
    /// The cache value: `verified:<commit>` or `rejected:<reason>`.
    pub(crate) fn cache_value(&self) -> String {
        match self {
            Self::Verified(sha) => format!("{VERIFIED}{sha}"),
            Self::Rejected(reason) => format!("{REJECTED}{reason}"),
        }
    }
}

fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn path_str<'a>(json: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(json, |v, k| v.get(*k))
        .and_then(Value::as_str)
}

/// Judges a version from its crates.io record, the Access tag ref and, for an
/// annotated tag, the tag object fetched by `fetch_tag`; `Err` means no verdict
/// was possible (T-86 rule 2).
pub(crate) fn verify_provenance(
    crate_json: &Value,
    tag_ref: impl FnOnce() -> Result<Value, String>,
    fetch_tag: impl FnOnce(&str) -> Result<Value, String>,
) -> Result<Provenance, String> {
    let reject = |r: &str| Ok(Provenance::Rejected(r.to_owned()));
    let Some(trustpub) = crate_json
        .get("version")
        .and_then(|v| v.get("trustpub_data"))
        .filter(|t| !t.is_null())
    else {
        return reject("no trusted publishing record");
    };
    if path_str(trustpub, &["provider"]) != Some("github") {
        return reject("trusted publishing provider is not github");
    }
    if path_str(trustpub, &["repository"]) != Some(ACCESS_REPOSITORY) {
        return reject("trusted publishing repository is not e-suiss/access");
    }
    let Some(published) = path_str(trustpub, &["sha"]).filter(|s| is_commit_sha(s)) else {
        return reject("trusted publishing record has no commit sha");
    };
    let reference = tag_ref()?;
    if path_str(&reference, &["object", "type"]) != Some("tag") {
        return reject("the Access tag is not an annotated tag");
    }
    let Some(tag_sha) = path_str(&reference, &["object", "sha"]).filter(|s| is_commit_sha(s))
    else {
        return reject("the Access tag ref has no object sha");
    };
    let tag = fetch_tag(tag_sha)?;
    if path_str(&tag, &["object", "type"]) != Some("commit") {
        return reject("the Access tag does not point to a commit");
    }
    if tag
        .get("verification")
        .and_then(|v| v.get("verified"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return reject("GitHub did not verify the Access tag signature");
    }
    let commit = path_str(&tag, &["object", "sha"]).unwrap_or_default();
    if commit != published {
        return reject("the published commit differs from the Access tag commit");
    }
    Ok(Provenance::Verified(commit.to_owned()))
}

fn provenance_key(name: &str, version: &str) -> String {
    format!("provenance:{name}@{version}")
}

/// Versions exempt from the cooldown: shared crates pinned exactly everywhere
/// whose cached provenance verdict is verified (T-86).
pub(crate) fn provenance_exempt(
    locked: &[Locked],
    declarations: &BTreeMap<String, Vec<String>>,
    cache: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    locked
        .iter()
        .filter(|p| p.source.as_deref() == Some(CRATES_IO) && is_shared(&p.name))
        .filter(|p| exactly_pinned(declarations, &p.name, &p.version))
        .filter(|p| {
            cache
                .get(&provenance_key(&p.name, &p.version))
                .is_some_and(|v| v.starts_with(VERIFIED))
        })
        .map(|p| format!("{}@{}", p.name, p.version))
        .collect()
}

/// Cooldown verdicts from known publication dates.
fn cooldown_in(
    locked: &[Locked],
    lock_path: &str,
    published: &BTreeMap<String, String>,
    exceptions: &[Exception],
    exempt: &BTreeSet<String>,
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
            && !exempt.contains(&key)
        {
            let note = if is_shared(&pkg.name) {
                "; provenance not verified (T-86)"
            } else {
                ""
            };
            out.push(at(
                lock_path,
                format!(
                    "{key} was published {ts}, less than {COOLDOWN_DAYS} days ago (T-60 rule 2){note}"
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

fn workspace_declarations(
    root: &Path,
    files: &[String],
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut declarations = BTreeMap::new();
    for manifest in files.iter().filter(|f| file_name(f) == "Cargo.toml") {
        collect_declarations(&read(&root.join(manifest))?, &mut declarations)
            .map_err(|e| format!("{manifest}: {e}"))?;
    }
    Ok(declarations)
}

/// Looks up the provenance of every exactly pinned shared crate still inside
/// the cooldown (T-86 rule 3).
fn refresh_provenance(
    locked: &[Locked],
    declarations: &BTreeMap<String, Vec<String>>,
    cache: &mut BTreeMap<String, String>,
    now: i64,
    online: bool,
    fetched_any: &mut bool,
    errors: &mut Vec<String>,
) {
    let pending: Vec<&Locked> = locked
        .iter()
        .filter(|p| {
            p.source.as_deref() == Some(CRATES_IO)
                && is_shared(&p.name)
                && exactly_pinned(declarations, &p.name, &p.version)
                && cache
                    .get(&format!("{}@{}", p.name, p.version))
                    .and_then(|ts| parse_timestamp(ts))
                    .is_some_and(|t| too_new(t, now))
        })
        .collect();
    for pkg in pending {
        let key = provenance_key(&pkg.name, &pkg.version);
        if online && cache.get(&key).is_none_or(|v| !v.starts_with(VERIFIED)) {
            if *fetched_any {
                std::thread::sleep(Duration::from_secs(1));
            }
            *fetched_any = true;
        }
        let fetch = || fetch_provenance(&pkg.name, &pkg.version);
        judge_provenance(cache, &key, online, fetch, errors);
    }
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
    let declarations = workspace_declarations(root, &files)?;
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
        refresh_provenance(
            &locked,
            &declarations,
            &mut cache,
            now,
            online,
            &mut fetched_any,
            &mut errors,
        );
        let exempt = provenance_exempt(&locked, &declarations, &cache);
        out.extend(cooldown_in(
            &locked,
            lock_path,
            &cache,
            &exceptions.exception,
            &exempt,
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
            cooldown_in(
                &locked,
                "Cargo.lock",
                &published,
                &[],
                &BTreeSet::new(),
                now
            )
            .len(),
            1
        );
        let fix = Exception {
            name: "a".into(),
            version: "1.0.0".into(),
            advisory: "RUSTSEC-2026-0001".into(),
            reason: "fixes a known vulnerability".into(),
        };
        assert!(
            cooldown_in(
                &locked,
                "Cargo.lock",
                &published,
                &[fix],
                &BTreeSet::new(),
                now
            )
            .is_empty()
        );
        let later = now.saturating_add(DAY.saturating_mul(6));
        assert!(
            cooldown_in(
                &locked,
                "Cargo.lock",
                &published,
                &[],
                &BTreeSet::new(),
                later
            )
            .is_empty()
        );
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
    const COMMIT: &str = "595e1e8b6df222c035a0c669fe509829a64c8f1a";
    const TAG: &str = "7407143fa3db5407b89e8e7526be37d7e9d17d1d";
    const ROOT_MANIFEST: &str = "[workspace.dependencies]\nsuiss-ledger = { package = \"esuiss-ledger\", version = \"=0.2.2\", default-features = false }\n";

    fn crate_record(repository: &str, sha: &str) -> Value {
        serde_json::json!({"version": {"created_at": "2026-10-28T00:00:00Z", "trustpub_data": {"provider": "github", "repository": repository, "run_id": 1, "sha": sha}}})
    }

    fn tag_ref(kind: &str) -> Value {
        serde_json::json!({"ref": "refs/tags/v0.2.2", "object": {"type": kind, "sha": TAG}})
    }

    fn tag_object(commit: &str, verified: bool) -> Value {
        serde_json::json!({"sha": TAG, "object": {"type": "commit", "sha": commit}, "verification": {"verified": verified, "reason": "valid"}})
    }

    fn verdict(record: &Value, reference: Value, tag: Value) -> Provenance {
        verify_provenance(
            record,
            || Ok(reference),
            |sha| {
                assert_eq!(sha, TAG);
                Ok(tag)
            },
        )
        .unwrap()
    }

    fn cooldown_with(name: &str, manifest: &str, provenance: &Provenance) -> Vec<Violation> {
        let locked = vec![Locked {
            name: name.to_owned(),
            version: "0.2.2".to_owned(),
            source: Some(CRATES_IO.to_owned()),
        }];
        let mut declarations = BTreeMap::new();
        collect_declarations(manifest, &mut declarations).unwrap();
        let cache = BTreeMap::from([
            (format!("{name}@0.2.2"), "2026-10-28T00:00:00Z".to_owned()),
            (provenance_key(name, "0.2.2"), provenance.cache_value()),
        ]);
        let exempt = provenance_exempt(&locked, &declarations, &cache);
        let now = parse_timestamp("2026-10-30T00:00:00Z").unwrap();
        cooldown_in(&locked, "Cargo.lock", &cache, &[], &exempt, now)
    }

    // T-86 T-60
    #[test]
    fn t_86_verified_provenance_lifts_the_cooldown_for_an_exactly_pinned_shared_crate() {
        let p = verdict(
            &crate_record("e-suiss/access", COMMIT),
            tag_ref("tag"),
            tag_object(COMMIT, true),
        );
        assert_eq!(p, Provenance::Verified(COMMIT.to_owned()));
        assert!(cooldown_with("esuiss-ledger", ROOT_MANIFEST, &p).is_empty());
    }

    // T-86 T-60
    #[test]
    fn t_86_trusted_publishing_from_another_repository_keeps_the_cooldown() {
        let p = verdict(
            &crate_record("e-suiss/fork", COMMIT),
            tag_ref("tag"),
            tag_object(COMMIT, true),
        );
        assert!(matches!(p, Provenance::Rejected(_)));
        assert_eq!(cooldown_with("esuiss-ledger", ROOT_MANIFEST, &p).len(), 1);
        let missing = verify_provenance(
            &serde_json::json!({"version": {"trustpub_data": null}}),
            || panic!("no tag lookup"),
            |_| panic!("no tag lookup"),
        );
        assert!(matches!(missing, Ok(Provenance::Rejected(_))));
    }

    // T-86 T-60
    #[test]
    fn t_86_published_commit_other_than_the_tag_commit_keeps_the_cooldown() {
        let other = "0000000000000000000000000000000000000001";
        let p = verdict(
            &crate_record("e-suiss/access", other),
            tag_ref("tag"),
            tag_object(COMMIT, true),
        );
        assert!(matches!(p, Provenance::Rejected(_)));
        assert_eq!(cooldown_with("esuiss-ledger", ROOT_MANIFEST, &p).len(), 1);
    }

    // T-86 T-60
    #[test]
    fn t_86_unverified_tag_signature_keeps_the_cooldown() {
        let p = verdict(
            &crate_record("e-suiss/access", COMMIT),
            tag_ref("tag"),
            tag_object(COMMIT, false),
        );
        assert!(matches!(p, Provenance::Rejected(_)));
        assert_eq!(cooldown_with("esuiss-ledger", ROOT_MANIFEST, &p).len(), 1);
    }

    // T-86 T-60
    #[test]
    fn t_86_lightweight_tag_keeps_the_cooldown() {
        let p = verify_provenance(
            &crate_record("e-suiss/access", COMMIT),
            || Ok(tag_ref("commit")),
            |_| panic!("a lightweight tag has no tag object"),
        )
        .unwrap();
        assert!(matches!(p, Provenance::Rejected(_)));
        assert_eq!(cooldown_with("esuiss-ledger", ROOT_MANIFEST, &p).len(), 1);
    }

    // T-86 T-60
    #[test]
    fn t_86_range_declarations_keep_the_cooldown() {
        let p = verdict(
            &crate_record("e-suiss/access", COMMIT),
            tag_ref("tag"),
            tag_object(COMMIT, true),
        );
        for req in ["0.2.2", "^0.2.2", "~0.2.2", ">=0.2.2"] {
            let manifest = format!(
                "[workspace.dependencies]\nsuiss-ledger = {{ package = \"esuiss-ledger\", version = \"{req}\" }}\n"
            );
            assert_eq!(
                cooldown_with("esuiss-ledger", &manifest, &p).len(),
                1,
                "{req}"
            );
        }
        let split = format!(
            "{ROOT_MANIFEST}[dev-dependencies]\nesuiss-ledger = \"^0.2.2\"\n[dependencies]\nsuiss-ledger = {{ workspace = true }}\n"
        );
        assert_eq!(cooldown_with("esuiss-ledger", &split, &p).len(), 1);
        assert_eq!(
            cooldown_with("esuiss-ledger", "[dependencies]\n", &p).len(),
            1
        );
    }

    // T-86 T-60
    #[test]
    fn t_86_third_party_crates_get_no_provenance_exemption() {
        let p = Provenance::Verified(COMMIT.to_owned());
        let manifest = "[workspace.dependencies]\nsuiss-ledger = { package = \"suiss-ledger\", version = \"=0.2.2\" }\n";
        assert_eq!(cooldown_with("suiss-ledger", manifest, &p).len(), 1);
    }

    // T-86 T-60
    #[test]
    fn t_86_failed_lookups_are_never_cached_as_verified() {
        let key = provenance_key("esuiss-ledger", "0.2.2");
        let mut cache = BTreeMap::new();
        let mut errors = Vec::new();
        assert!(!judge_provenance(
            &mut cache,
            &key,
            false,
            || panic!("offline"),
            &mut errors
        ));
        assert!(!judge_provenance(
            &mut cache,
            &key,
            true,
            || Err("timeout".to_owned()),
            &mut errors
        ));
        assert!(cache.is_empty());
        let rejected = Provenance::Rejected("unsigned".to_owned());
        assert!(!judge_provenance(
            &mut cache,
            &key,
            true,
            || Ok(rejected),
            &mut errors
        ));
        assert_eq!(
            cache.get(&key).map(String::as_str),
            Some("rejected:unsigned")
        );
        let verified = Provenance::Verified(COMMIT.to_owned());
        assert!(judge_provenance(
            &mut cache,
            &key,
            true,
            || Ok(verified),
            &mut errors
        ));
        assert!(judge_provenance(
            &mut cache,
            &key,
            true,
            || panic!("cached"),
            &mut errors
        ));
        assert_eq!(errors.len(), 2);
    }
}
