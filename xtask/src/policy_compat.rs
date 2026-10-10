//! `compat` (T-40, T-51, T-56, T-57, MD-14): `compat.toml` is well formed, the
//! local compose environment pulls Access and Relay only as `compat.toml` pins
//! them, runs the required infrastructure and observability services, and has no
//! KMS emulator and no single-image observability bundle.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{read, read_optional};
use crate::supply_chain::cooldown::parse_lock;
use crate::yaml::{self, Node};

const RULE: &str = "compat";
pub(crate) const COMPAT_FILE: &str = "compat.toml";
pub(crate) const COMPOSE_FILE: &str = "deploy/compose/compose.yaml";

/// Services every local environment runs (MD-14, T-41, T-56, T-57).
const REQUIRED_SERVICES: &[&str] = &[
    "postgres",
    "nats",
    "softhsm",
    "otel-collector",
    "jaeger",
    "prometheus",
    "grafana",
];

const KMS_MARKERS: &[&str] = &["kms", "localstack", "moto"];
const BUNDLE_MARKERS: &[&str] = &["otel-lgtm", "grafana/otel-lgtm"];
const SHARED_CRATES: &[&str] = &["esuiss-crypto", "esuiss-ledger", "esuiss-restriction"];

/// `compat.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Compat {
    pub(crate) work: WorkRow,
    pub(crate) access: Product,
    pub(crate) relay: Product,
    #[serde(rename = "shared-crates")]
    pub(crate) shared_crates: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkRow {
    pub(crate) version: String,
}

/// One product row.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Product {
    pub(crate) status: String,
    pub(crate) version: String,
    pub(crate) image: String,
    pub(crate) digest: String,
}

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    }
}

fn is_semver(s: &str) -> bool {
    let core = s.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn is_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// Format problems of `compat.toml` itself.
pub(crate) fn format_violations(c: &Compat) -> Vec<Violation> {
    let mut out = Vec::new();
    if !is_semver(&c.work.version) {
        out.push(v(
            COMPAT_FILE,
            format!("[work] version `{}` is not SemVer (T-40)", c.work.version),
        ));
    }
    for (name, p) in [("access", &c.access), ("relay", &c.relay)] {
        if p.image.trim().is_empty() || p.image.contains('@') || p.image.contains(' ') {
            out.push(v(
                COMPAT_FILE,
                format!("[{name}] image must be a repository without tag or digest"),
            ));
        }
        match p.status.as_str() {
            "published" => {
                if !is_semver(&p.version) {
                    out.push(v(
                        COMPAT_FILE,
                        format!(
                            "[{name}] published version `{}` is not SemVer (T-51)",
                            p.version
                        ),
                    ));
                }
                if !is_digest(&p.digest) {
                    out.push(v(
                        COMPAT_FILE,
                        format!("[{name}] published digest must be `sha256:<64 hex>` (T-51)"),
                    ));
                }
            }
            "unpublished" => {
                if !p.version.is_empty() || !p.digest.is_empty() {
                    out.push(v(
                        COMPAT_FILE,
                        format!("[{name}] is unpublished; version and digest stay empty (T-51)"),
                    ));
                }
            }
            other => out.push(v(
                COMPAT_FILE,
                format!("[{name}] status `{other}` is not `published` or `unpublished` (T-51)"),
            )),
        }
    }
    for name in SHARED_CRATES {
        if !c.shared_crates.contains_key(*name) {
            out.push(v(
                COMPAT_FILE,
                format!("[shared-crates] has no `{name}` row (T-51)"),
            ));
        }
    }
    for (name, value) in &c.shared_crates {
        if !SHARED_CRATES.contains(&name.as_str()) {
            out.push(v(
                COMPAT_FILE,
                format!("[shared-crates] `{name}` is not a shared crate (T-54)"),
            ));
        }
        if value != "unpublished" && !is_semver(value) {
            out.push(v(COMPAT_FILE, format!("[shared-crates] `{name}` = `{value}` is neither `unpublished` nor a version (T-51)")));
        }
    }
    out
}

/// Shared-crate rows agree with the root manifest and the lockfile (T-31 rule 2).
pub(crate) fn shared_crate_violations(
    c: &Compat,
    manifest: &str,
    lock: &str,
) -> Result<Vec<Violation>, String> {
    let table: toml::Table = manifest.parse().map_err(|e| format!("Cargo.toml: {e}"))?;
    let deps = table
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    let locked = parse_lock(lock)?;
    let mut out = Vec::new();
    for (name, value) in &c.shared_crates {
        let declared = deps
            .values()
            .find(|d| d.get("package").and_then(toml::Value::as_str) == Some(name.as_str()))
            .and_then(|d| {
                d.get("version")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
            });
        let in_lock: Vec<&str> = locked
            .iter()
            .filter(|p| p.name == *name)
            .map(|p| p.version.as_str())
            .collect();
        if value == "unpublished" {
            if declared.is_some() || !in_lock.is_empty() {
                out.push(v(
                    "Cargo.toml",
                    format!("`{name}` is unpublished in compat.toml but is a dependency (T-51)"),
                ));
            }
        } else {
            if declared.as_deref() != Some(&format!("={value}")) {
                out.push(v("Cargo.toml", format!("`{name}` must be bound as `version = \"={value}\"` to match compat.toml (T-31 rule 2, T-51)")));
            }
            if !in_lock.is_empty() && in_lock.iter().any(|l| *l != value) {
                out.push(v(
                    "Cargo.lock",
                    format!("`{name}` is locked at {in_lock:?}, compat.toml says {value} (T-51)"),
                ));
            }
        }
    }
    Ok(out)
}

fn service_image(service: &Node) -> String {
    service
        .get("image")
        .and_then(Node::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Compose problems against `compat.toml`.
pub(crate) fn compose_violations(c: &Compat, compose: &str) -> Vec<Violation> {
    let doc = yaml::parse(compose);
    let services = doc
        .get("services")
        .cloned()
        .unwrap_or(Node::Map(Vec::new()));
    let mut out = Vec::new();
    for (name, p) in [("access", &c.access), ("relay", &c.relay)] {
        let Some(service) = services.get(name) else {
            out.push(v(
                COMPOSE_FILE,
                format!("service `{name}` is missing (T-41 rule 1, T-51)"),
            ));
            continue;
        };
        let image = service_image(service);
        let profiles = service
            .get("profiles")
            .map(Node::scalars)
            .unwrap_or_default();
        if p.status == "published" {
            let want = format!("{}@{}", p.image, p.digest);
            if image != want {
                out.push(v(
                    COMPOSE_FILE,
                    format!(
                        "service `{name}` image `{image}` must be `{want}` from compat.toml (T-51)"
                    ),
                ));
            }
            if !profiles.is_empty() {
                out.push(v(COMPOSE_FILE, format!("service `{name}` is published; it runs by default, without a profile (T-41 rule 1)")));
            }
        } else {
            let want = format!("{}:unpublished", p.image);
            if image != want {
                out.push(v(
                    COMPOSE_FILE,
                    format!(
                        "service `{name}` image `{image}` must be `{want}` while unpublished (T-51)"
                    ),
                ));
            }
            if profiles.is_empty() {
                out.push(v(COMPOSE_FILE, format!("unpublished service `{name}` stays in a profile that is off by default (T-51)")));
            }
        }
    }
    for required in REQUIRED_SERVICES {
        if services.get(required).is_none() {
            out.push(v(
                COMPOSE_FILE,
                format!("service `{required}` is missing (MD-14, T-41, T-56, T-57)"),
            ));
        }
    }
    for (name, service) in services.entries() {
        let image = service_image(service).to_ascii_lowercase();
        let lower = name.to_ascii_lowercase();
        let kms = |s: &str| {
            s.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| KMS_MARKERS.contains(&w))
        };
        if kms(&lower) || kms(&image) {
            out.push(v(COMPOSE_FILE, format!("service `{name}` looks like a KMS emulator; keys go through PKCS#11 and SoftHSM (T-56)")));
        }
        if BUNDLE_MARKERS
            .iter()
            .any(|m| image.contains(m) || lower.contains(m))
        {
            out.push(v(COMPOSE_FILE, format!("service `{name}` is a single-image observability bundle; use the separate images (T-57)")));
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let text = read(&root.join(COMPAT_FILE))?;
    let compat: Compat = toml::from_str(&text).map_err(|e| format!("{COMPAT_FILE}: {e}"))?;
    let mut out = format_violations(&compat);
    out.extend(shared_crate_violations(
        &compat,
        &read(&root.join("Cargo.toml"))?,
        &read(&root.join("Cargo.lock"))?,
    )?);
    match read_optional(&root.join(COMPOSE_FILE))? {
        Some(compose) => out.extend(compose_violations(&compat, &compose)),
        None => out.push(v(
            COMPOSE_FILE,
            "the local compose environment is missing (T-51)".to_owned(),
        )),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    const UNPUBLISHED: &str = "[work]\nversion = \"0.0.0\"\n[access]\nstatus = \"unpublished\"\nversion = \"\"\nimage = \"ghcr.io/e-suiss/access\"\ndigest = \"\"\n[relay]\nstatus = \"unpublished\"\nversion = \"\"\nimage = \"ghcr.io/e-suiss/relay\"\ndigest = \"\"\n[shared-crates]\nesuiss-crypto = \"unpublished\"\nesuiss-ledger = \"unpublished\"\nesuiss-restriction = \"unpublished\"\n";

    const DIGEST: &str = "sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336";

    fn compose(access: &str, extra: &str) -> String {
        let mut s = String::from("services:\n");
        for name in REQUIRED_SERVICES {
            let _ = write!(s, "  {name}:\n    image: x/{name}@{DIGEST}\n");
        }
        s.push_str(access);
        s.push_str(
            "  relay:\n    image: ghcr.io/e-suiss/relay:unpublished\n    profiles: [relay]\n",
        );
        s.push_str(extra);
        s
    }

    fn compat(text: &str) -> Compat {
        toml::from_str(text).unwrap()
    }

    // T-51 T-40
    #[test]
    fn t_51_unpublished_products_stay_in_a_profile() {
        let c = compat(UNPUBLISHED);
        assert!(format_violations(&c).is_empty());
        let ok = compose(
            "  access:\n    image: ghcr.io/e-suiss/access:unpublished\n    profiles: [access]\n",
            "",
        );
        assert!(
            compose_violations(&c, &ok).is_empty(),
            "{:?}",
            compose_violations(&c, &ok)
        );
        let no_profile = compose(
            "  access:\n    image: ghcr.io/e-suiss/access:unpublished\n",
            "",
        );
        assert_eq!(compose_violations(&c, &no_profile).len(), 1);
    }

    // T-51 T-40
    #[test]
    fn t_51_published_access_image_must_match_the_compat_digest() {
        let text = UNPUBLISHED
            .replacen(
                "status = \"unpublished\"\nversion = \"\"",
                "status = \"published\"\nversion = \"1.2.0\"",
                1,
            )
            .replacen("digest = \"\"", &format!("digest = \"{DIGEST}\""), 1);
        let c = compat(&text);
        assert!(
            format_violations(&c).is_empty(),
            "{:?}",
            format_violations(&c)
        );
        let pinned = compose(
            &format!("  access:\n    image: ghcr.io/e-suiss/access@{DIGEST}\n"),
            "",
        );
        assert!(compose_violations(&c, &pinned).is_empty());
        let tagged = compose("  access:\n    image: ghcr.io/e-suiss/access:1.2.0\n", "");
        assert_eq!(compose_violations(&c, &tagged).len(), 1);
    }

    // T-40 T-51
    #[test]
    fn t_40_malformed_compat_rows_are_rejected() {
        let bad = UNPUBLISHED
            .replacen("status = \"unpublished\"", "status = \"beta\"", 1)
            .replace(
                "esuiss-restriction = \"unpublished\"",
                "esuiss-restriction = \"latest\"",
            );
        assert_eq!(format_violations(&compat(&bad)).len(), 2);
    }

    // T-56 T-57 MD-14
    #[test]
    fn t_56_kms_emulator_bundle_and_missing_services_are_rejected() {
        let c = compat(UNPUBLISHED);
        let access =
            "  access:\n    image: ghcr.io/e-suiss/access:unpublished\n    profiles: [access]\n";
        let kms = compose(
            access,
            "  local-kms:\n    image: nsmithuk/local-kms@sha256:aa\n  lgtm:\n    image: grafana/otel-lgtm@sha256:bb\n",
        );
        assert_eq!(compose_violations(&c, &kms).len(), 2);
        let missing = "services:\n  access:\n    image: ghcr.io/e-suiss/access:unpublished\n    profiles: [access]\n  relay:\n    image: ghcr.io/e-suiss/relay:unpublished\n    profiles: [relay]\n";
        assert_eq!(
            compose_violations(&c, missing).len(),
            REQUIRED_SERVICES.len()
        );
    }

    // T-51 T-31
    #[test]
    fn t_51_shared_crate_versions_match_manifest_and_lockfile() {
        let c = compat(&UNPUBLISHED.replace(
            "esuiss-crypto = \"unpublished\"",
            "esuiss-crypto = \"0.3.1\"",
        ));
        let manifest = "[workspace.dependencies]\nsuiss-crypto = { package = \"esuiss-crypto\", version = \"=0.3.1\" }\n";
        let lock = "version = 4\n[[package]]\nname = \"esuiss-crypto\"\nversion = \"0.3.1\"\n";
        assert!(
            shared_crate_violations(&c, manifest, lock)
                .unwrap()
                .is_empty()
        );
        let loose = manifest.replace("=0.3.1", "0.3");
        assert_eq!(shared_crate_violations(&c, &loose, lock).unwrap().len(), 1);
        let unpublished = compat(UNPUBLISHED);
        assert_eq!(
            shared_crate_violations(&unpublished, manifest, lock)
                .unwrap()
                .len(),
            1
        );
    }
}
