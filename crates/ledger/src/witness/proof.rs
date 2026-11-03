//! RFC 9162 consistency proofs (section 2.1.4.1) over a ledger's leaf hashes, from the size a
//! witness holds to the checkpoint sent to it (C2SP `tlog-witness`, OP-33). Every subtree hash
//! is the shared engine's frontier root over that subtree's leaves, so no second Merkle hash is
//! computed here; the shared crates verify proofs but do not build them.

use suiss_ledger::merkle::Frontier;

/// An old size above the tree, or a tree the engine cannot hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no consistency proof from this size")]
pub(crate) struct ProofSizeError;

fn subtree_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], ProofSizeError> {
    let mut frontier = Frontier::default();
    for leaf in leaves {
        frontier.push(*leaf).map_err(|_| ProofSizeError)?;
    }
    Ok(frontier.root())
}

fn split(n: usize) -> usize {
    let mut k = 1_usize;
    while let Some(next) = k.checked_mul(2) {
        if next >= n {
            break;
        }
        k = next;
    }
    k
}

fn subproof(
    m: usize,
    leaves: &[[u8; 32]],
    complete: bool,
    out: &mut Vec<[u8; 32]>,
) -> Result<(), ProofSizeError> {
    if m == leaves.len() {
        if !complete {
            out.push(subtree_root(leaves)?);
        }
        return Ok(());
    }
    let k = split(leaves.len());
    let (left, right) = leaves.split_at_checked(k).ok_or(ProofSizeError)?;
    if m <= k {
        subproof(m, left, complete, out)?;
        out.push(subtree_root(right)?);
    } else {
        let rest = m.checked_sub(k).ok_or(ProofSizeError)?;
        subproof(rest, right, false, out)?;
        out.push(subtree_root(left)?);
    }
    Ok(())
}

/// The proof that the tree of the first `old` of `leaves` is a prefix of the tree of all of
/// them, in RFC 9162 order; empty when `old` is 0 or the whole tree.
///
/// # Errors
/// [`ProofSizeError`] when `old` is above the number of leaves.
pub(crate) fn consistency_proof(
    leaves: &[[u8; 32]],
    old: u64,
) -> Result<Vec<[u8; 32]>, ProofSizeError> {
    let m = usize::try_from(old).map_err(|_| ProofSizeError)?;
    if m > leaves.len() {
        return Err(ProofSizeError);
    }
    let mut out = Vec::new();
    if m > 0 {
        subproof(m, leaves, true, &mut out)?;
    }
    Ok(out)
}

/// The RFC 9162 root of the tree of `leaves`.
///
/// # Errors
/// [`ProofSizeError`] for a tree the engine cannot hold.
pub(crate) fn tree_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], ProofSizeError> {
    subtree_root(leaves)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use suiss_crypto::digest::{leaf_hash, node_hash, root};
    use work_kernel::id::Digest;
    use work_kernel::proof::verify_consistency;

    use super::*;

    fn data(n: u8) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i, 0x5a, i]).collect()
    }

    // OP-33 T-31 OP-48
    #[test]
    fn op_33_every_consistency_proof_verifies_under_the_shared_verifier() {
        let all = data(19);
        let leaves: Vec<[u8; 32]> = all.iter().map(|d| leaf_hash(d.as_slice())).collect();
        for n in 1..=all.len() {
            let size = u64::try_from(n).unwrap();
            let slices: Vec<&[u8]> = all[..n].iter().map(Vec::as_slice).collect();
            let new_root = Digest::sha256(root(&slices));
            assert_eq!(tree_root(&leaves[..n]).unwrap(), *new_root.as_bytes());
            assert_eq!(
                consistency_proof(&leaves[..n], 0).unwrap(),
                Vec::<[u8; 32]>::new()
            );
            assert_eq!(
                consistency_proof(&leaves[..n], size).unwrap(),
                Vec::<[u8; 32]>::new()
            );
            for m in 1..n {
                let old = u64::try_from(m).unwrap();
                let path = consistency_proof(&leaves[..n], old).unwrap();
                let proof: Vec<Digest> = path.into_iter().map(Digest::sha256).collect();
                let old_root = Digest::sha256(root(&slices[..m]));
                assert_eq!(
                    verify_consistency(old, size, &old_root, &new_root, &proof),
                    Ok(()),
                    "{old} -> {size}"
                );
                if let Some((_, rest)) = proof.split_first() {
                    assert!(verify_consistency(old, size, &old_root, &new_root, rest).is_err());
                }
            }
        }
    }

    // OP-33 OP-48
    #[test]
    fn op_33_the_proof_from_3_to_4_is_c_d_ab_and_no_proof_starts_above_the_tree() {
        let all = data(4);
        let leaves: Vec<[u8; 32]> = all.iter().map(|d| leaf_hash(d.as_slice())).collect();
        assert_eq!(
            consistency_proof(&leaves, 3).unwrap(),
            vec![leaves[2], leaves[3], node_hash(&leaves[0], &leaves[1])]
        );
        assert_eq!(consistency_proof(&leaves, 5), Err(ProofSizeError));
    }
}
