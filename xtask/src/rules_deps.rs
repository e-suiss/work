//! `dependency-direction` (T-31 rule 4, T-8, T-22, P-1): every crate depends
//! only on the internal and shared crates the T-31 table allows; Access internal
//! crates, Relay code and unmeasured accelerators never enter the shipped tree.

use std::path::Path;

use crate::Violation;
use crate::rules::files::rel;
use crate::supply_chain::metadata::{DepKind, Metadata};

const RULE: &str = "dependency-direction";

/// The nine component crates (T-31 rule 4).
pub(crate) const COMPONENTS: &[&str] = &[
    "reconciler",
    "timers",
    "views",
    "query",
    "dispatch",
    "federation",
    "agents",
    "live",
    "export",
];

/// The T-31 crate classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Kernel,
    Proto,
    Parse,
    Store,
    Ledger,
    Client,
    Component,
    Http,
    Rpc,
    Telemetry,
    Testkit,
    Bin,
    Bindings,
    Tooling,
    SuissCrypto,
    SuissLedger,
    SuissRestriction,
    AccessPublic,
    Forbidden,
}

/// Classifies a workspace crate by its directory relative to the root.
pub(crate) fn classify_dir(dir: &str) -> Option<Class> {
    let (group, name) = dir.split_once('/').unwrap_or((dir, ""));
    let class = match (group, name) {
        ("crates", "kernel") => Class::Kernel,
        ("crates", "proto") => Class::Proto,
        ("crates", "parse") => Class::Parse,
        ("crates", "store") => Class::Store,
        ("crates", "ledger") => Class::Ledger,
        ("crates", "access-client" | "relay-client") => Class::Client,
        ("crates", "http") => Class::Http,
        ("crates", "rpc") => Class::Rpc,
        ("crates", "telemetry") => Class::Telemetry,
        ("crates", "testkit") => Class::Testkit,
        ("crates", n) if COMPONENTS.contains(&n) => Class::Component,
        ("bins", n) if !n.is_empty() && !n.contains('/') => Class::Bin,
        ("sdks", n) if n == "bindings" || n.starts_with("bindings/") => Class::Bindings,
        ("xtask", "") => Class::Tooling,
        _ => return None,
    };
    Some(class)
}

/// Classifies a registry dependency by package name; `None` for third-party crates.
pub(crate) fn classify_name(name: &str) -> Option<Class> {
    let class = match name {
        "esuiss-crypto" | "suiss-crypto" => Class::SuissCrypto,
        "esuiss-ledger" | "suiss-ledger" => Class::SuissLedger,
        "esuiss-restriction" | "suiss-restriction" => Class::SuissRestriction,
        "esuiss-access-kernel" | "esuiss-access-verify" => Class::AccessPublic,
        n if n.starts_with("esuiss-access-")
            || n.starts_with("access-")
            || n.starts_with("authority-")
            || n.starts_with("identity-")
            || n.starts_with("esuiss-relay")
            || n.starts_with("relay-") =>
        {
            Class::Forbidden
        }
        _ => return None,
    };
    Some(class)
}

/// The T-31 rule 4 table: what a crate of class `from` may depend on; `None` means
/// every internal and shared class.
fn allowed_targets(from: Class) -> Option<&'static [Class]> {
    use Class::{
        AccessPublic, Client, Component, Kernel, Ledger, Parse, Proto, Rpc, Store, SuissCrypto,
        SuissLedger, SuissRestriction, Telemetry,
    };
    let targets: &'static [Class] = match from {
        Class::Bin | Class::Testkit => return None,
        // T-4 T-23
        Kernel => &[SuissCrypto],
        Proto => &[Kernel],
        Parse => &[Kernel, Proto],
        Store => &[Kernel, Proto, SuissLedger],
        Ledger => &[Kernel, Proto, Store, SuissLedger, SuissCrypto],
        Client => &[Proto, Telemetry, AccessPublic],
        Component => &[
            Kernel,
            Proto,
            Parse,
            Store,
            Ledger,
            Rpc,
            Client,
            Telemetry,
            SuissCrypto,
            SuissLedger,
            SuissRestriction,
        ],
        Class::Http => &[Component, Kernel, Proto, Telemetry],
        Rpc => &[Proto],
        Class::Bindings => &[Kernel, Proto, SuissRestriction],
        Telemetry
        | Class::Tooling
        | SuissCrypto
        | SuissLedger
        | SuissRestriction
        | AccessPublic
        | Class::Forbidden => &[],
    };
    Some(targets)
}

/// May a crate of class `from` depend on a crate of class `to`?
pub(crate) fn allowed(from: Class, to: Class) -> bool {
    if matches!(to, Class::Testkit | Class::Forbidden) {
        return false;
    }
    allowed_targets(from).is_none_or(|targets| targets.contains(&to))
}

/// Client crates of optional accelerators, search engines and second queues (T-22).
pub(crate) const ACCELERATORS: &[&str] = &[
    "redis",
    "redis-async",
    "fred",
    "deadpool-redis",
    "bb8-redis",
    "mobc-redis",
    "valkey",
    "valkey-glide",
    "elasticsearch",
    "opensearch",
    "meilisearch-sdk",
    "typesense",
    "rdkafka",
    "kafka",
    "rskafka",
    "lapin",
    "amiquip",
    "amqprs",
    "rabbitmq-stream-client",
];

fn manifest(root: &Path, pkg: &crate::supply_chain::metadata::Package) -> std::path::PathBuf {
    pkg.manifest_path
        .strip_prefix(root)
        .unwrap_or(&pkg.manifest_path)
        .to_path_buf()
}

/// Checks every workspace crate's dependencies against the table.
pub(crate) fn check_metadata(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        let path = manifest(root, pkg);
        let Some(from) = classify_dir(&dir) else {
            out.push(Violation {
                rule: RULE,
                path,
                message: format!(
                    "crate `{}` in `{dir}` has no T-31 class; add its directory to xtask/src/rules_deps.rs",
                    pkg.name
                ),
            });
            continue;
        };
        for dep in pkg.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            let to = if let Some(dep_path) = &dep.path {
                let dep_dir = rel(root, dep_path);
                let Some(class) = classify_dir(&dep_dir) else {
                    out.push(Violation {
                        rule: RULE,
                        path: path.clone(),
                        message: format!(
                            "path dependency `{}` in `{dep_dir}` has no T-31 class (T-31 rule 2: no path dependencies outside the workspace)",
                            dep.name
                        ),
                    });
                    continue;
                };
                class
            } else {
                let Some(class) = classify_name(&dep.name) else {
                    continue;
                };
                class
            };
            if !allowed(from, to) {
                let why = if to == Class::Forbidden {
                    "Access internal crates and Relay code are forbidden; use the public API (T-8)"
                } else if to == Class::Testkit {
                    "testkit is a dev-dependency only"
                } else {
                    "not allowed by the T-31 rule 4 table"
                };
                out.push(Violation {
                    rule: RULE,
                    path: path.clone(),
                    message: format!(
                        "`{}` ({from:?}) must not depend on `{}` ({to:?}): {why}",
                        pkg.name, dep.name
                    ),
                });
            }
        }
    }
    out.extend(accelerators(md));
    out
}

/// Accelerator clients in the default shipped tree (T-22).
pub(crate) fn accelerators(md: &Metadata) -> Vec<Violation> {
    let closure = md.shipped_closure(&md.workspace_members);
    md.packages
        .iter()
        .filter(|p| closure.contains(&p.id) && ACCELERATORS.contains(&p.name.as_str()))
        .map(|p| Violation {
            rule: RULE,
            path: std::path::PathBuf::from("Cargo.lock"),
            message: format!(
                "`{}` {} is in the default dependency tree; accelerators and second queues are optional adapters behind a Cargo feature (T-22)",
                p.name, p.version
            ),
        })
        .collect()
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    Ok(check_metadata(root, &md))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::metadata::fixture::{
        external, member, metadata, metadata_with_edges, with_registry_dep,
    };
    use crate::supply_chain::metadata::parse;

    fn run(packages: &[serde_json::Value]) -> Vec<Violation> {
        let md = parse(&metadata(packages, &[])).unwrap();
        check_metadata(Path::new("/ws"), &md)
    }

    // T-31 T-8
    #[test]
    fn t_31_component_crates_must_not_depend_on_each_other() {
        let v = run(&[
            member("crates/timers", &[]),
            member("crates/reconciler", &[("crates/timers", None)]),
        ]);
        assert_eq!(v.len(), 1);
        let ok = run(&[
            member("crates/kernel", &[]),
            member("crates/store", &[]),
            member(
                "crates/reconciler",
                &[("crates/kernel", None), ("crates/store", None)],
            ),
        ]);
        assert!(ok.is_empty(), "{ok:?}");
    }

    // T-31 T-4
    #[test]
    fn t_31_kernel_depends_only_on_suiss_crypto() {
        let bad = run(&[
            member("crates/proto", &[]),
            member("crates/kernel", &[("crates/proto", None)]),
        ]);
        assert_eq!(bad.len(), 1);
        let ledger = run(&[with_registry_dep(
            member("crates/kernel", &[]),
            "esuiss-ledger",
            Some("suiss-ledger"),
            false,
        )]);
        assert_eq!(ledger.len(), 1);
        let ok = run(&[with_registry_dep(
            member("crates/kernel", &[]),
            "esuiss-crypto",
            Some("suiss-crypto"),
            false,
        )]);
        assert!(ok.is_empty(), "{ok:?}");
    }

    // P-1
    #[test]
    fn p_1_protocol_crates_do_not_depend_on_transport_crates() {
        for from in ["crates/proto", "crates/parse", "crates/kernel"] {
            for to in ["crates/http", "crates/rpc"] {
                let v = run(&[member(to, &[]), member(from, &[(to, None)])]);
                assert_eq!(v.len(), 1, "{from} -> {to}");
            }
        }
    }

    // T-8 T-31
    #[test]
    fn t_8_access_internal_crates_and_relay_code_are_forbidden() {
        for name in [
            "esuiss-access-store",
            "authority-core",
            "identity-session",
            "access-internal-api",
            "relay-core",
        ] {
            let v = run(&[with_registry_dep(
                member("bins/work-server", &[]),
                name,
                None,
                true,
            )]);
            assert_eq!(v.len(), 1, "{name}");
            assert!(v[0].message.contains("T-8"), "{name}");
        }
        let ok = run(&[with_registry_dep(
            member("crates/access-client", &[]),
            "esuiss-access-verify",
            None,
            true,
        )]);
        assert!(ok.is_empty(), "{ok:?}");
    }

    // T-31
    #[test]
    fn t_31_http_uses_component_app_interfaces_and_clients_stay_thin() {
        let ok = run(&[
            member("crates/query", &[]),
            member("crates/http", &[("crates/query", None)]),
        ]);
        assert!(ok.is_empty(), "{ok:?}");
        let bad = run(&[
            member("crates/store", &[]),
            member("crates/access-client", &[("crates/store", None)]),
        ]);
        assert_eq!(bad.len(), 1);
        let rpc = run(&[
            member("crates/kernel", &[]),
            member("crates/rpc", &[("crates/kernel", None)]),
        ]);
        assert_eq!(rpc.len(), 1);
    }

    // T-31
    #[test]
    fn t_31_testkit_is_a_dev_dependency_only() {
        let bad = run(&[
            member("crates/testkit", &[]),
            member("bins/work-server", &[("crates/testkit", None)]),
        ]);
        assert_eq!(bad.len(), 1);
        let dev = run(&[
            member("crates/testkit", &[]),
            member("crates/views", &[("crates/testkit", Some("dev"))]),
        ]);
        assert!(dev.is_empty(), "{dev:?}");
    }

    // T-31
    #[test]
    fn t_31_bins_may_depend_on_every_crate_and_xtask_on_none() {
        let ok = run(&[
            member("crates/views", &[]),
            member("crates/federation", &[]),
            member(
                "bins/work-server",
                &[("crates/views", None), ("crates/federation", None)],
            ),
        ]);
        assert!(ok.is_empty(), "{ok:?}");
        let bad = run(&[
            member("crates/kernel", &[]),
            member("xtask", &[("crates/kernel", None)]),
        ]);
        assert_eq!(bad.len(), 1);
    }

    // T-31
    #[test]
    fn t_31_crate_in_unknown_directory_fails_closed() {
        let v = run(&[member("crates/mystery", &[])]);
        assert_eq!(v.len(), 1);
        assert!(v[0].message.contains("no T-31 class"));
        let outside = run(&[member("crates/store", &[("../access/crates/kernel", None)])]);
        assert_eq!(outside.len(), 1);
    }

    // T-22 MD-14
    #[test]
    fn t_22_accelerator_clients_in_the_default_tree_are_rejected() {
        let server = member("bins/work-server", &[]);
        let redis = external("redis", "0.32.0", false);
        let server_id = "path+file:///ws/bins/work-server#work-server@0.0.0";
        let redis_id = "registry+https://github.com/rust-lang/crates.io-index#redis@0.32.0";
        let shipped = parse(&metadata_with_edges(
            &[server.clone(), redis.clone()],
            &[],
            &[(server_id, redis_id, None)],
        ))
        .unwrap();
        assert_eq!(accelerators(&shipped).len(), 1);
        let dev_only = parse(&metadata_with_edges(
            &[server, redis],
            &[],
            &[(server_id, redis_id, Some("dev"))],
        ))
        .unwrap();
        assert!(accelerators(&dev_only).is_empty());
    }
}
