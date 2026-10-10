//! `cargo metadata` loading shared by the dependency and supply-chain checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};

use serde_json::Value;

/// How a dependency is used; dev-dependencies never reach a shipped artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepKind {
    Normal,
    Dev,
    Build,
}

/// One declared dependency of a package.
#[derive(Debug, Clone)]
pub(crate) struct Dep {
    /// The depended-on package name, not the rename.
    pub(crate) name: String,
    /// The local name when the dependency is renamed (`suiss-crypto = { package = … }`).
    pub(crate) rename: Option<String>,
    pub(crate) kind: DepKind,
    /// Set for path dependencies.
    pub(crate) path: Option<PathBuf>,
    pub(crate) uses_default_features: bool,
}

/// One package in the resolved graph.
#[derive(Debug, Clone, Default)]
pub(crate) struct Package {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) license: String,
    pub(crate) manifest_path: PathBuf,
    pub(crate) deps: Vec<Dep>,
    pub(crate) has_build_script: bool,
    pub(crate) is_proc_macro: bool,
    /// False when the manifest sets `publish = false`.
    pub(crate) publishable: bool,
    pub(crate) feature_names: Vec<String>,
    /// Source files of the lib and bin targets.
    pub(crate) crate_roots: Vec<PathBuf>,
}

impl Package {
    /// The directory holding `Cargo.toml`.
    pub(crate) fn dir(&self) -> &Path {
        self.manifest_path.parent().unwrap_or(&self.manifest_path)
    }
}

/// The parts of `cargo metadata` the checks use.
#[derive(Debug, Default)]
pub(crate) struct Metadata {
    pub(crate) packages: Vec<Package>,
    pub(crate) workspace_members: Vec<String>,
    /// Enabled features per package id.
    pub(crate) features: BTreeMap<String, Vec<String>>,
    /// Resolved dependency edges per package id: (dependency id, kinds).
    pub(crate) edges: BTreeMap<String, Vec<(String, Vec<DepKind>)>>,
}

impl Metadata {
    /// Workspace member packages.
    pub(crate) fn members(&self) -> impl Iterator<Item = &Package> {
        self.packages
            .iter()
            .filter(|p| self.workspace_members.contains(&p.id))
    }

    /// Ids reachable from `start` over normal and build edges (dev edges skipped).
    pub(crate) fn shipped_closure(&self, start: &[String]) -> BTreeSet<String> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut stack: Vec<String> = start.to_vec();
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            for (dep, kinds) in self.edges.get(&id).into_iter().flatten() {
                if kinds.iter().any(|k| *k != DepKind::Dev) {
                    stack.push(dep.clone());
                }
            }
        }
        seen
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn kind_of(v: Option<&Value>) -> DepKind {
    match v.and_then(Value::as_str) {
        Some("dev") => DepKind::Dev,
        Some("build") => DepKind::Build,
        _ => DepKind::Normal,
    }
}

fn target_kinds(t: &Value) -> Vec<String> {
    t.get("kind")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn parse_package(p: &Value) -> Package {
    let deps = p
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|d| Dep {
            name: str_field(d, "name"),
            rename: d.get("rename").and_then(Value::as_str).map(str::to_owned),
            kind: kind_of(d.get("kind")),
            path: d.get("path").and_then(Value::as_str).map(PathBuf::from),
            uses_default_features: d
                .get("uses_default_features")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        })
        .collect();
    let targets: Vec<&Value> = p
        .get("targets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let has = |kind: &str| {
        targets
            .iter()
            .any(|t| target_kinds(t).iter().any(|k| k == kind))
    };
    let crate_roots = targets
        .iter()
        .filter(|t| {
            target_kinds(t).iter().any(|k| {
                matches!(
                    k.as_str(),
                    "lib" | "bin" | "rlib" | "cdylib" | "staticlib" | "proc-macro"
                )
            })
        })
        .map(|t| PathBuf::from(str_field(t, "src_path")))
        .collect();
    let publishable = !p
        .get("publish")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    Package {
        id: str_field(p, "id"),
        name: str_field(p, "name"),
        version: str_field(p, "version"),
        license: str_field(p, "license"),
        manifest_path: PathBuf::from(str_field(p, "manifest_path")),
        deps,
        has_build_script: has("custom-build"),
        is_proc_macro: has("proc-macro"),
        publishable,
        feature_names: p
            .get("features")
            .and_then(Value::as_object)
            .map(|f| f.keys().cloned().collect())
            .unwrap_or_default(),
        crate_roots,
    }
}

/// Parses `cargo metadata --format-version 1` output.
pub(crate) fn parse(json: &str) -> Result<Metadata, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("cargo metadata: {e}"))?;
    let mut md = Metadata::default();
    for p in v
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        md.packages.push(parse_package(p));
    }
    md.workspace_members = v
        .get("workspace_members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let nodes = v
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(Value::as_array);
    for node in nodes.into_iter().flatten() {
        let id = str_field(node, "id");
        let features = node
            .get("features")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        md.features.insert(id.clone(), features);
        let edges = node
            .get("deps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|d| {
                let kinds = d
                    .get("dep_kinds")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|k| kind_of(k.get("kind")))
                    .collect::<Vec<_>>();
                let kinds = if kinds.is_empty() {
                    vec![DepKind::Normal]
                } else {
                    kinds
                };
                (str_field(d, "pkg"), kinds)
            })
            .collect();
        md.edges.insert(id, edges);
    }
    Ok(md)
}

static CACHE: OnceLock<Result<Arc<Metadata>, String>> = OnceLock::new();

/// Runs `cargo metadata` once per process (offline, locked) and caches it.
pub(crate) fn load(root: &Path) -> Result<Arc<Metadata>, String> {
    CACHE
        .get_or_init(|| {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
            let output = Command::new(cargo)
                .args(["metadata", "--format-version", "1", "--locked", "--offline"])
                .current_dir(root)
                .output()
                .map_err(|e| format!("cargo metadata: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "cargo metadata failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            let json =
                String::from_utf8(output.stdout).map_err(|e| format!("cargo metadata: {e}"))?;
            parse(&json).map(Arc::new)
        })
        .clone()
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Builds `cargo metadata` JSON for the unit tests.

    use serde_json::{Value, json};

    /// A workspace member at `/ws/<dir>` with path dependencies on other members.
    pub(crate) fn member(dir: &str, deps: &[(&str, Option<&str>)]) -> Value {
        let name = dir.rsplit('/').next().unwrap_or(dir);
        let deps: Vec<Value> = deps
            .iter()
            .map(|(dep_dir, kind)| {
                json!({
                    "name": dep_dir.rsplit('/').next().unwrap_or(dep_dir),
                    "kind": kind,
                    "path": format!("/ws/{dep_dir}"),
                })
            })
            .collect();
        json!({
            "id": format!("path+file:///ws/{dir}#{name}@0.0.0"),
            "name": name,
            "version": "0.0.0",
            "license": "Apache-2.0",
            "source": null,
            "publish": [],
            "manifest_path": format!("/ws/{dir}/Cargo.toml"),
            "dependencies": deps,
            "targets": [{"kind": ["lib"], "src_path": format!("/ws/{dir}/src/lib.rs")}],
            "features": {},
        })
    }

    /// Adds a registry dependency (by package name, optionally renamed) to a member.
    pub(crate) fn with_registry_dep(
        mut pkg: Value,
        name: &str,
        rename: Option<&str>,
        default_features: bool,
    ) -> Value {
        if let Some(deps) = pkg.get_mut("dependencies").and_then(Value::as_array_mut) {
            deps.push(json!({
                "name": name,
                "rename": rename,
                "kind": null,
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "uses_default_features": default_features,
            }));
        }
        pkg
    }

    /// A registry package depended on by name.
    pub(crate) fn external(name: &str, version: &str, build_rs: bool) -> Value {
        let mut targets = vec![json!({"kind": ["lib"], "src_path": "/reg/src/lib.rs"})];
        if build_rs {
            targets.push(json!({"kind": ["custom-build"], "src_path": "/reg/build.rs"}));
        }
        json!({
            "id": format!("registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"),
            "name": name,
            "version": version,
            "license": "MIT",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "publish": null,
            "manifest_path": format!("/reg/{name}/Cargo.toml"),
            "dependencies": [],
            "targets": targets,
            "features": {},
        })
    }

    /// A metadata document; every package without a source is a workspace member.
    /// `edges` are (from id, to id, kind) resolve edges.
    pub(crate) fn metadata(packages: &[Value], features: &[(&str, &[&str])]) -> String {
        metadata_with_edges(packages, features, &[])
    }

    /// Like [`metadata`], with resolve edges.
    pub(crate) fn metadata_with_edges(
        packages: &[Value],
        features: &[(&str, &[&str])],
        edges: &[(&str, &str, Option<&str>)],
    ) -> String {
        let members: Vec<Value> = packages
            .iter()
            .filter(|p| p.get("source").is_some_and(Value::is_null))
            .filter_map(|p| p.get("id").cloned())
            .collect();
        let mut ids: Vec<String> = packages
            .iter()
            .filter_map(|p| p.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        ids.sort();
        let nodes: Vec<Value> = ids
            .iter()
            .map(|id| {
                let f: Vec<&str> = features
                    .iter()
                    .find(|(fid, _)| fid == id)
                    .map(|(_, f)| f.to_vec())
                    .unwrap_or_default();
                let deps: Vec<Value> = edges
                    .iter()
                    .filter(|(from, _, _)| from == id)
                    .map(|(_, to, kind)| json!({"pkg": to, "dep_kinds": [{"kind": kind}]}))
                    .collect();
                json!({"id": id, "features": f, "deps": deps})
            })
            .collect();
        json!({
            "packages": packages,
            "workspace_members": members,
            "resolve": {"nodes": nodes},
        })
        .to_string()
    }
}
