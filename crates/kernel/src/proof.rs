//! Ledger proofs through the shared crate with its pure backend (T-4, T-7, T-64, P-11, P-20, P-101, OP-33): RFC 9162 inclusion and consistency proofs over the envelope leaf hashes, where the genesis is leaf 0 and the record at `pos` is leaf `pos`, and C2SP signed-note checkpoints with Ed25519 `tlog-cosignature/v1` witness cosignatures; a proof states presence and order in the ledger, never truth or authorisation (SEC-5), and the kernel holds no second Merkle or note implementation.

use alloc::vec::Vec;

use suiss_crypto::digest::{self, Hash};
use suiss_crypto::note;
use suiss_crypto::sig::PureBackend;

pub use suiss_crypto::digest::ProofError;
pub use suiss_crypto::note::{Accepted, Checkpoint, NoteError, Verifier};

use crate::id::Digest;

/// The RFC 9162 interior node hash `SHA-256(0x01 ‖ left ‖ right)` (P-101).
#[must_use]
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    Digest::sha256(digest::node_hash(left.as_bytes(), right.as_bytes()))
}

/// The RFC 9162 tree hash over envelope bytes in ledger order, the genesis first; the empty tree is `SHA-256("")` (P-100, P-101).
#[must_use]
pub fn root(envelopes: &[&[u8]]) -> Digest {
    Digest::sha256(digest::root(envelopes))
}

fn hashes(path: &[Digest]) -> Vec<Hash> {
    path.iter().map(|d| *d.as_bytes()).collect()
}

/// Verifies that the envelope with leaf hash `leaf` is at `position` in the tree of `size` with `root` (RFC 9162 section 2.1.3.2).
///
/// # Errors
///
/// `proof-range` for a position outside the tree, `proof-length` for a path of the wrong length, `proof-mismatch` when the recomputed root differs.
pub fn verify_inclusion(
    position: u64,
    size: u64,
    leaf: &Digest,
    path: &[Digest],
    root: &Digest,
) -> Result<(), ProofError> {
    digest::verify_inclusion(
        position,
        size,
        leaf.as_bytes(),
        &hashes(path),
        root.as_bytes(),
    )
}

/// Verifies that the tree of `first` with `first_root` is a prefix of the tree of `second` with `second_root` (RFC 9162 section 2.1.4.2).
///
/// # Errors
///
/// `proof-range` when `first` is above `second`, `proof-length` for a path of the wrong length, `proof-mismatch` when a recomputed root differs.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Digest,
    second_root: &Digest,
    path: &[Digest],
) -> Result<(), ProofError> {
    digest::verify_consistency(
        first,
        second,
        first_root.as_bytes(),
        second_root.as_bytes(),
        &hashes(path),
    )
}

/// A checkpoint whose log signature verified, with the witness cosignatures that verified (P-20, OP-33).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    /// The `tlog-checkpoint` body.
    pub checkpoint: Checkpoint,
    /// The verified witness cosignatures, each with its timestamp; never the log's own signature.
    pub cosignatures: Vec<Accepted>,
}

/// Verifies a C2SP signed note as a checkpoint of `origin`: the log's own signature must verify, every signature line from a known witness must verify, and lines from unknown keys are ignored (T-4, T-64, OP-33).
///
/// # Errors
///
/// The shared crate's [`NoteError`]: `signature-*` when a known key's signature fails, `note-unverified` without the log's signature, `checkpoint-malformed` for another origin or a body that is not a checkpoint, or a note syntax code.
pub fn verify_checkpoint(
    signed_note: &str,
    origin: &str,
    log: &Verifier,
    witnesses: &[Verifier],
) -> Result<SignedCheckpoint, NoteError> {
    let (checkpoint, accepted) =
        note::verify_checkpoint(&PureBackend, signed_note, origin, log, witnesses)?;
    Ok(SignedCheckpoint {
        checkpoint,
        cosignatures: accepted
            .into_iter()
            .filter(|a| a.timestamp.is_some())
            .collect(),
    })
}

impl SignedCheckpoint {
    /// The tree size.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.checkpoint.size
    }

    /// The RFC 9162 root at this size.
    #[must_use]
    pub const fn root(&self) -> Digest {
        Digest::sha256(self.checkpoint.root)
    }

    /// Verifies that the envelope with leaf hash `leaf` at `position` is in this checkpoint's tree.
    ///
    /// # Errors
    ///
    /// A [`verify_inclusion`] error.
    pub fn includes(
        &self,
        position: u64,
        leaf: &Digest,
        path: &[Digest],
    ) -> Result<(), ProofError> {
        verify_inclusion(position, self.size(), leaf, path, &self.root())
    }

    /// Verifies that this checkpoint's tree is a prefix of the tree of `newer`, a checkpoint of the same origin.
    ///
    /// # Errors
    ///
    /// `proof-mismatch` for another origin, or a [`verify_consistency`] error.
    pub fn extends_to(&self, newer: &Self, path: &[Digest]) -> Result<(), ProofError> {
        if self.checkpoint.origin != newer.checkpoint.origin {
            return Err(ProofError::Mismatch);
        }
        let (older_root, newer_root) = (self.root(), newer.root());
        verify_consistency(self.size(), newer.size(), &older_root, &newer_root, path)
    }
}
