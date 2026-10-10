//! `kernel` (T-4, T-31 rule 5): the dependency tree of `work-kernel` holds only
//! the `no_std` verification part of `suiss-crypto`; no std runtime, I/O, async,
//! FFI, signer or other shared crate.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::rel;
use crate::supply_chain::metadata::{DepKind, Metadata};

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
    "mio",
    "socket2",
    "libc",
    "windows-sys",
    "windows",
    "nix",
    "rustix",
    "reqwest",
    "hyper",
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

fn v(message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from("crates/kernel/Cargo.toml"),
        message,
    }
}

/// Kernel gate violations over the resolved metadata.
pub(crate) fn kernel_violations(root: &Path, md: &Metadata) -> Vec<Violation> {
    let Some(kernel) = md.members().find(|p| rel(root, p.dir()) == "crates/kernel") else {
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
    let closure = md.shipped_closure(std::slice::from_ref(&kernel.id));
    for pkg in md.packages.iter().filter(|p| closure.contains(&p.id)) {
        if FORBIDDEN_IN_TREE.contains(&pkg.name.as_str()) {
            out.push(v(format!(
                "`{}` {} is in the kernel dependency tree; std, I/O, async and FFI stay out (T-4, T-31 rule 5)",
                pkg.name, pkg.version
            )));
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    Ok(kernel_violations(root, &md))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::metadata::fixture::{
        external, member, metadata_with_edges, with_registry_dep,
    };
    use crate::supply_chain::metadata::parse;

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
        let found = kernel_violations(Path::new("/ws"), &bad);
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
        assert!(kernel_violations(Path::new("/ws"), &ok).is_empty());
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
}
