//! Project policy checks: open source and the business-model boundary (T-3,
//! P-2, MD-15), package names (T-54), the decision record (T-42) and component
//! layers (T-32 rule 1).

use std::path::{Path, PathBuf};

use crate::rules::deps::COMPONENTS;
use crate::rules::files::{read, rel, repo_files, walk};
use crate::supply_chain::metadata::{self, Metadata};
use crate::{Check, Violation};

#[path = "policy_compat.rs"]
mod compat;
#[path = "policy_scan.rs"]
mod scan;

pub(crate) fn checks() -> Vec<Check> {
    let mut all = vec![
        Check {
            name: "no-paid-features",
            run: no_paid_features,
        },
        Check {
            name: "license",
            run: license,
        },
        Check {
            name: "package-names",
            run: package_names,
        },
        Check {
            name: "no-adr-folder",
            run: no_adr_folder,
        },
        Check {
            name: "component-layers",
            run: component_layers,
        },
        Check {
            name: "compat",
            run: compat::check,
        },
    ];
    all.extend(scan::checks());
    all
}

const PAID_MARKERS: &[&str] = &[
    "enterprise",
    "premium",
    "paid",
    "commercial",
    "license_key",
    "licence_key",
    "pro_only",
    "paywall",
    "cloud_only",
    "saas_only",
    "hosted_only",
];

/// The paid-tier marker contained in `name`, if any.
pub(crate) fn paid_marker(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase().replace('-', "_");
    PAID_MARKERS.iter().copied().find(|marker| {
        lower
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| {
                word == *marker
                    || word.starts_with(&format!("{marker}_"))
                    || word.ends_with(&format!("_{marker}"))
                    || word.contains(&format!("_{marker}_"))
            })
    })
}

fn manifest(root: &Path, pkg: &metadata::Package) -> PathBuf {
    pkg.manifest_path
        .strip_prefix(root)
        .unwrap_or(&pkg.manifest_path)
        .to_path_buf()
}

fn paid_violation(path: &Path, what: &str, marker: &str) -> Violation {
    Violation {
        rule: "no-paid-features",
        path: path.to_path_buf(),
        message: format!(
            "{what} contains `{marker}`: no licence flag, paid tier or cloud-only path (T-3, P-2, MD-15)"
        ),
    }
}

pub(crate) fn paid_violations(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        let path = manifest(root, pkg);
        if let Some(marker) = paid_marker(&pkg.name) {
            out.push(paid_violation(
                &path,
                &format!("package `{}`", pkg.name),
                marker,
            ));
        }
        for feature in &pkg.feature_names {
            if let Some(marker) = paid_marker(feature) {
                out.push(paid_violation(
                    &path,
                    &format!("feature `{feature}`"),
                    marker,
                ));
            }
        }
    }
    out
}

/// Every `package.json` outside `node_modules` (T-58: each is its own project).
fn npm_manifests(root: &Path) -> Result<Vec<(String, serde_json::Value)>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if path.file_name().is_some_and(|n| n == "package.json") {
            let text = read(&path)?;
            let json: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("{rel_path}: {e}"))?;
            out.push((rel_path, json));
        }
    }
    Ok(out)
}

/// Paid markers and licences of npm packages.
pub(crate) fn npm_violations(manifests: &[(String, serde_json::Value)]) -> Vec<Violation> {
    let mut out = Vec::new();
    for (path, json) in manifests {
        let name = json
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if let Some(marker) = paid_marker(name) {
            out.push(paid_violation(
                Path::new(path),
                &format!("npm package `{name}`"),
                marker,
            ));
        }
        let license = json
            .get("license")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if license != "Apache-2.0" {
            out.push(Violation {
                rule: "license",
                path: PathBuf::from(path),
                message: format!("npm package `{name}` has license `{license}`; every package is Apache-2.0 (T-3)"),
            });
        }
    }
    out
}

fn no_paid_features(root: &Path) -> Result<Vec<Violation>, String> {
    let md = metadata::load(root)?;
    let mut out = paid_violations(root, &md);
    out.extend(
        npm_violations(&npm_manifests(root)?)
            .into_iter()
            .filter(|v| v.rule == "no-paid-features"),
    );
    Ok(out)
}

pub(crate) fn license_violations(root: &Path, md: &Metadata, license_file: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        if pkg.license != "Apache-2.0" {
            out.push(Violation {
                rule: "license",
                path: manifest(root, pkg),
                message: format!(
                    "package `{}` has license `{}`; every package is Apache-2.0 (T-3, MD-15)",
                    pkg.name, pkg.license
                ),
            });
        }
    }
    if !license_file.contains("Apache License") || !license_file.contains("Version 2.0") {
        out.push(Violation {
            rule: "license",
            path: PathBuf::from("LICENSE"),
            message: "LICENSE must be the Apache License 2.0 (T-3)".to_owned(),
        });
    }
    out
}

fn license(root: &Path) -> Result<Vec<Violation>, String> {
    let md = metadata::load(root)?;
    let text = std::fs::read_to_string(root.join("LICENSE")).unwrap_or_default();
    let mut out = license_violations(root, &md, &text);
    out.extend(
        npm_violations(&npm_manifests(root)?)
            .into_iter()
            .filter(|v| v.rule == "license"),
    );
    Ok(out)
}

const SHARED: &[(&str, &str)] = &[
    ("esuiss-crypto", "suiss-crypto"),
    ("esuiss-ledger", "suiss-ledger"),
    ("esuiss-restriction", "suiss-restriction"),
];

/// Package-name rule violations (T-54).
pub(crate) fn package_name_violations(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut bad = |pkg: &metadata::Package, message: String| {
        out.push(Violation {
            rule: "package-names",
            path: manifest(root, pkg),
            message,
        });
    };
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        let named_published = pkg.name.starts_with("esuiss-work-");
        if pkg.publishable && !named_published {
            bad(
                pkg,
                format!(
                    "`{}` is publishable; published crates are named `esuiss-work-*` (T-54)",
                    pkg.name
                ),
            );
        }
        if pkg.name.starts_with("esuiss-") && !named_published {
            bad(
                pkg,
                format!(
                    "`{}`: Work packages use the `esuiss-work-` prefix (T-54)",
                    pkg.name
                ),
            );
        }
        let internal_ok = pkg.name.starts_with("work-") || named_published || dir == "xtask";
        if !pkg.publishable && !internal_ok {
            bad(
                pkg,
                format!(
                    "`{}`: internal crates are named `work-*` (T-31 rule 3, T-54)",
                    pkg.name
                ),
            );
        }
        for dep in &pkg.deps {
            if let Some((_, lib)) = SHARED.iter().find(|(published, _)| *published == dep.name) {
                if dep.rename.as_deref() != Some(lib) {
                    bad(
                        pkg,
                        format!(
                            "`{}` must be bound as `{lib} = {{ package = \"{}\", … }}` (T-54)",
                            dep.name, dep.name
                        ),
                    );
                }
            } else if let Some((published, _)) = SHARED.iter().find(|(_, lib)| *lib == dep.name) {
                bad(
                    pkg,
                    format!(
                        "`{}` is published as `{published}`; bind it with `package = \"{published}\"` (T-54)",
                        dep.name
                    ),
                );
            }
        }
    }
    out
}

fn package_names(root: &Path) -> Result<Vec<Violation>, String> {
    let md = metadata::load(root)?;
    Ok(package_name_violations(root, &md))
}

fn no_adr_folder(root: &Path) -> Result<Vec<Violation>, String> {
    let files = repo_files(root)?;
    Ok(adr_paths(files.iter().map(String::as_str))
        .into_iter()
        .map(|path| Violation {
            rule: "no-adr-folder",
            path,
            message: "no ADR folder: the spec registers are the decision record (T-42)".to_owned(),
        })
        .collect())
}

pub(crate) fn adr_paths<'a>(files: impl Iterator<Item = &'a str>) -> Vec<PathBuf> {
    files
        .filter(|file| {
            Path::new(file).components().any(|c| {
                let part = c.as_os_str().to_string_lossy().to_ascii_lowercase();
                part == "adr" || part == "adrs" || part == "decisions"
            })
        })
        .map(PathBuf::from)
        .collect()
}

const LAYERS: &[&str] = &["domain", "ports", "app", "adapters"];

pub(crate) fn missing_layers(src: &Path) -> Vec<&'static str> {
    LAYERS
        .iter()
        .copied()
        .filter(|layer| !src.join(format!("{layer}.rs")).is_file() && !src.join(layer).is_dir())
        .collect()
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "every check shares the `Check::run` signature"
)]
fn component_layers(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for name in COMPONENTS {
        let src = root.join("crates").join(name).join("src");
        if !src.is_dir() {
            out.push(Violation {
                rule: "component-layers",
                path: PathBuf::from(format!("crates/{name}")),
                message: format!("component crate `{name}` is missing (T-31 rule 3)"),
            });
            continue;
        }
        for layer in missing_layers(&src) {
            out.push(Violation {
                rule: "component-layers",
                path: PathBuf::from(format!("crates/{name}/src")),
                message: format!("component crate `{name}` has no `{layer}` layer (T-32 rule 1)"),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::files::TempDir;
    use crate::supply_chain::metadata::fixture::{member, metadata, with_registry_dep};
    use crate::supply_chain::metadata::parse;

    // MD-15 F-9 P-2
    #[test]
    fn md_15_f_9_p_2_paid_or_cloud_only_names_are_rejected() {
        assert_eq!(paid_marker("enterprise"), Some("enterprise"));
        assert_eq!(paid_marker("enterprise-sso"), Some("enterprise"));
        assert_eq!(paid_marker("sso_premium"), Some("premium"));
        assert_eq!(paid_marker("license-key"), Some("license_key"));
        assert_eq!(paid_marker("export-cloud-only"), Some("cloud_only"));
        for name in [
            "std",
            "verify",
            "work-server",
            "prepaid_budget_view",
            "sso",
            "export",
        ] {
            assert_eq!(paid_marker(name), None, "{name}");
        }
        let mut pkg = member("crates/export", &[]);
        pkg["features"] = serde_json::json!({"saas-only-replay": []});
        let md = parse(&metadata(&[pkg], &[])).unwrap();
        assert_eq!(paid_violations(Path::new("/ws"), &md).len(), 1);
    }

    // T-3 MD-15
    #[test]
    fn t_3_non_apache_package_or_licence_file_is_rejected() {
        let mut pkg = member("crates/store", &[]);
        pkg["license"] = "MIT".into();
        let md = parse(&metadata(&[pkg, member("crates/proto", &[])], &[])).unwrap();
        let v = license_violations(Path::new("/ws"), &md, "Apache License\nVersion 2.0\n");
        assert_eq!(v.len(), 1);
        let ok = parse(&metadata(&[member("crates/proto", &[])], &[])).unwrap();
        assert_eq!(
            license_violations(Path::new("/ws"), &ok, "MIT License").len(),
            1
        );
        let npm = vec![(
            "web/package.json".to_owned(),
            serde_json::json!({"name": "@esuiss/work-premium", "license": "MIT"}),
        )];
        assert_eq!(npm_violations(&npm).len(), 2);
    }

    // T-54
    #[test]
    fn t_54_published_crates_carry_the_esuiss_work_prefix() {
        let mut published = member("crates/proto", &[]);
        published["publish"] = serde_json::Value::Null;
        let mut kernel = member("crates/kernel", &[]);
        kernel["name"] = "esuiss-work-kernel".into();
        kernel["publish"] = serde_json::Value::Null;
        let md = parse(&metadata(&[published, kernel, member("xtask", &[])], &[])).unwrap();
        let v = package_name_violations(Path::new("/ws"), &md);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].message.contains("work-proto") || v[0].message.contains("proto"));
    }

    // T-54
    #[test]
    fn t_54_shared_crates_are_bound_by_package_with_the_library_name() {
        let mut ledger = member("crates/ledger", &[]);
        ledger["name"] = "work-ledger".into();
        let mut store = member("crates/store", &[]);
        store["name"] = "work-store".into();
        let ok = with_registry_dep(ledger.clone(), "esuiss-ledger", Some("suiss-ledger"), true);
        let md = parse(&metadata(&[ok], &[])).unwrap();
        assert!(package_name_violations(Path::new("/ws"), &md).is_empty());
        let unrenamed = with_registry_dep(ledger, "esuiss-ledger", None, true);
        let old_name = with_registry_dep(store, "suiss-ledger", None, true);
        let md = parse(&metadata(&[unrenamed, old_name], &[])).unwrap();
        assert_eq!(package_name_violations(Path::new("/ws"), &md).len(), 2);
    }

    // T-42
    #[test]
    fn t_42_adr_directory_is_rejected() {
        let found = adr_paths(
            [
                "README.md",
                "docs/adr/0001-x.md",
                "crates/kernel/src/lib.rs",
                "Decisions/x.md",
            ]
            .into_iter(),
        );
        assert_eq!(
            found,
            vec![
                PathBuf::from("docs/adr/0001-x.md"),
                PathBuf::from("Decisions/x.md")
            ]
        );
    }

    // T-32
    #[test]
    fn t_32_component_crate_without_layers_is_reported() {
        let dir = TempDir::new("layers");
        dir.write("src/domain.rs", "");
        dir.write("src/app/mod.rs", "");
        assert_eq!(
            missing_layers(&dir.0.join("src")),
            vec!["ports", "adapters"]
        );
    }
}
