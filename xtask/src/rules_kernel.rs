//! `kernel` (T-4, T-31 rule 5, T-32 rule 3, T-87): the dependency tree of `work-kernel`, resolved
//! for each distribution target, holds only the `no_std` verification part of `suiss-crypto`; no
//! std runtime, I/O, async, FFI, signer or other shared crate.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::rel;
use crate::supply_chain::metadata::{DepKind, Metadata, Package};

const RULE: &str = "kernel";

/// The kernel's published package name (T-54).
pub(crate) const KERNEL_PACKAGE: &str = "esuiss-work-kernel";

/// Crates that bring std, I/O, async, FFI or key storage into the kernel tree.
const FORBIDDEN_IN_TREE: &[&str] = &[
    "tokio",
    "async-std",
    "smol",
    "futures",
    "futures-util",
    "futures-executor",
    "futures-channel",
    "futures-io",
    "tokio-util",
    "tokio-stream",
    "async-nats",
    "async-channel",
    "flume",
    "crossbeam-channel",
    "mio",
    "socket2",
    "libc",
    "windows-sys",
    "windows",
    "nix",
    "rustix",
    "reqwest",
    "hyper",
    "hyper-util",
    "h2",
    "tonic",
    "tower",
    "sqlx",
    "rand",
    "getrandom",
    "cc",
    "bindgen",
    "cxx",
    "cryptoki",
    "pkcs11",
    "aws-lc-rs",
    "aws-lc-sys",
    "esuiss-ledger",
    "esuiss-restriction",
    "suiss-ledger",
    "suiss-restriction",
];

const SHARED_CRYPTO: &[&str] = &["esuiss-crypto", "suiss-crypto"];

/// The targets the kernel ships to, whose trees the rule evaluates (T-87): a host-only edge such
/// as `cpufeatures` → `libc` on aarch64 never reaches them.
pub(crate) const DISTRIBUTION_TARGETS: &[&str] =
    &["wasm32-unknown-unknown", "thumbv7em-none-eabihf"];

fn v(message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from("crates/kernel/Cargo.toml"),
        message,
    }
}

fn kernel_package<'a>(root: &Path, md: &'a Metadata) -> Option<&'a Package> {
    md.members().find(|p| rel(root, p.dir()) == "crates/kernel")
}

/// Kernel manifest violations: the published name and the one shared-crate dependency.
pub(crate) fn kernel_violations(root: &Path, md: &Metadata) -> Vec<Violation> {
    let Some(kernel) = kernel_package(root, md) else {
        return vec![v("crates/kernel is not a workspace member".to_owned())];
    };
    let mut out = Vec::new();
    if kernel.name != KERNEL_PACKAGE {
        out.push(v(format!(
            "the kernel package is `{}`; it is published as `{KERNEL_PACKAGE}` (T-54)",
            kernel.name
        )));
    }
    for dep in kernel.deps.iter().filter(|d| d.kind != DepKind::Dev) {
        if !SHARED_CRYPTO.contains(&dep.name.as_str()) {
            out.push(v(format!(
                "the kernel may depend only on suiss-crypto; found `{}` (T-31 rule 4)",
                dep.name
            )));
        } else if dep.uses_default_features {
            out.push(v(format!(
                "`{}` must be bound with default-features = false so only the no_std verification part enters (T-31 rule 4)",
                dep.name
            )));
        }
    }
    out
}

/// Kernel tree violations over metadata resolved for `target` (T-87).
pub(crate) fn tree_violations(root: &Path, md: &Metadata, target: &str) -> Vec<Violation> {
    let Some(kernel) = kernel_package(root, md) else {
        return vec![v("crates/kernel is not a workspace member".to_owned())];
    };
    let closure = md.shipped_closure(std::slice::from_ref(&kernel.id));
    let mut out = Vec::new();
    for pkg in md.packages.iter().filter(|p| closure.contains(&p.id)) {
        if FORBIDDEN_IN_TREE.contains(&pkg.name.as_str()) {
            out.push(v(format!(
                "`{}` {} is in the kernel dependency tree for {target}; std, I/O, async and FFI stay out (T-4, T-31 rule 5)",
                pkg.name, pkg.version
            )));
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    let mut out = kernel_violations(root, &md);
    for target in DISTRIBUTION_TARGETS {
        let filtered = crate::supply_chain::metadata::load_for_target(root, target)?;
        out.extend(tree_violations(root, &filtered, target));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::metadata::fixture::{
        external, member, metadata_with_edges, with_registry_dep,
    };
    use crate::supply_chain::metadata::{args, parse};

    const KERNEL_ID: &str = "path+file:///ws/crates/kernel#esuiss-work-kernel@0.0.0";

    fn kernel() -> serde_json::Value {
        let mut k = member("crates/kernel", &[]);
        k["name"] = KERNEL_PACKAGE.into();
        k["id"] = KERNEL_ID.into();
        k
    }

    // T-31 T-4
    #[test]
    fn t_31_std_pulling_crate_in_kernel_tree_is_rejected() {
        let crypto = external("esuiss-crypto", "0.1.0", false);
        let libc = external("libc", "0.2.0", false);
        let crypto_id = "registry+https://github.com/rust-lang/crates.io-index#esuiss-crypto@0.1.0";
        let libc_id = "registry+https://github.com/rust-lang/crates.io-index#libc@0.2.0";
        let k = with_registry_dep(kernel(), "esuiss-crypto", Some("suiss-crypto"), false);
        let bad = parse(&metadata_with_edges(
            &[k.clone(), crypto.clone(), libc.clone()],
            &[],
            &[(KERNEL_ID, crypto_id, None), (crypto_id, libc_id, None)],
        ))
        .unwrap();
        assert!(kernel_violations(Path::new("/ws"), &bad).is_empty());
        let found = tree_violations(Path::new("/ws"), &bad, DISTRIBUTION_TARGETS[0]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].message.contains("libc"));
        let ok = parse(&metadata_with_edges(
            &[k, crypto, libc],
            &[],
            &[
                (KERNEL_ID, crypto_id, None),
                (KERNEL_ID, libc_id, Some("dev")),
            ],
        ))
        .unwrap();
        let found = tree_violations(Path::new("/ws"), &ok, DISTRIBUTION_TARGETS[0]);
        assert!(found.is_empty(), "{found:?}");
    }

    // T-32 T-4
    #[test]
    fn t_32_nats_client_in_kernel_tree_is_rejected() {
        let crypto = external("esuiss-crypto", "0.1.0", false);
        let nats = external("async-nats", "0.50.0", false);
        let crypto_id = "registry+https://github.com/rust-lang/crates.io-index#esuiss-crypto@0.1.0";
        let nats_id = "registry+https://github.com/rust-lang/crates.io-index#async-nats@0.50.0";
        let k = with_registry_dep(kernel(), "esuiss-crypto", Some("suiss-crypto"), false);
        let md = parse(&metadata_with_edges(
            &[k, crypto, nats],
            &[],
            &[(KERNEL_ID, crypto_id, None), (crypto_id, nats_id, None)],
        ))
        .unwrap();
        let found = tree_violations(Path::new("/ws"), &md, DISTRIBUTION_TARGETS[1]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].message.contains("async-nats"));
    }

    // T-31 T-4
    #[test]
    fn t_31_kernel_binds_suiss_crypto_without_default_features() {
        let k = with_registry_dep(kernel(), "esuiss-crypto", Some("suiss-crypto"), true);
        let md = parse(&metadata_with_edges(&[k], &[], &[])).unwrap();
        let found = kernel_violations(Path::new("/ws"), &md);
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("default-features"));
    }

    // T-54
    #[test]
    fn t_54_kernel_package_carries_the_published_name() {
        let md = parse(&metadata_with_edges(
            &[member("crates/kernel", &[])],
            &[],
            &[],
        ))
        .unwrap();
        assert_eq!(kernel_violations(Path::new("/ws"), &md).len(), 1);
    }

    // T-87 T-31 T-4
    #[test]
    fn t_87_the_tree_is_resolved_for_each_distribution_target() {
        assert_eq!(
            DISTRIBUTION_TARGETS,
            ["wasm32-unknown-unknown", "thumbv7em-none-eabihf"]
        );
        for target in DISTRIBUTION_TARGETS {
            let with = args(Some(*target));
            assert!(with.ends_with(&["--filter-platform", *target]), "{with:?}");
            assert!(with.contains(&"--locked") && with.contains(&"--offline"));
        }
        assert!(!args(None).contains(&"--filter-platform"));
    }

    // T-87 T-31 T-4
    #[test]
    fn t_87_a_host_only_libc_edge_passes_and_a_target_edge_names_the_target() {
        let crypto = external("esuiss-crypto", "0.2.2", false);
        let cpufeatures = external("cpufeatures", "0.2.17", false);
        let libc = external("libc", "0.2.177", false);
        let crypto_id = "registry+https://github.com/rust-lang/crates.io-index#esuiss-crypto@0.2.2";
        let cpu_id = "registry+https://github.com/rust-lang/crates.io-index#cpufeatures@0.2.17";
        let libc_id = "registry+https://github.com/rust-lang/crates.io-index#libc@0.2.177";
        let k = with_registry_dep(kernel(), "esuiss-crypto", Some("suiss-crypto"), false);
        let packages = [k, crypto, cpufeatures, libc];
        let distribution = parse(&metadata_with_edges(
            &packages,
            &[],
            &[(KERNEL_ID, crypto_id, None), (crypto_id, cpu_id, None)],
        ))
        .unwrap();
        for target in DISTRIBUTION_TARGETS {
            let found = tree_violations(Path::new("/ws"), &distribution, target);
            assert!(found.is_empty(), "{target}: {found:?}");
        }
        let host = parse(&metadata_with_edges(
            &packages,
            &[],
            &[
                (KERNEL_ID, crypto_id, None),
                (crypto_id, cpu_id, None),
                (cpu_id, libc_id, None),
            ],
        ))
        .unwrap();
        let found = tree_violations(Path::new("/ws"), &host, "thumbv7em-none-eabihf");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].message.contains("libc"));
        assert!(found[0].message.contains("for thumbv7em-none-eabihf"));
    }
}
