//! Ledger proofs through the shared crate with its pure backend (T-4, T-7, T-64, P-11, P-20, P-101, OP-33, OP-46): RFC 9162 inclusion and consistency proofs over the envelope leaf hashes, where the genesis is leaf 0 and the record at `pos` is leaf `pos`, and C2SP signed-note checkpoints with Ed25519 `tlog-cosignature/v1` witness cosignatures, whose body carries exactly the three profile lines `durability`, `time_sources` and `witness` after the root; a proof states presence and order in the ledger, never truth or authorisation (SEC-5), and the kernel holds no second Merkle or note implementation.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::num::NonZeroU8;

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

/// The `durability` profile line: how a commit is made durable (OP-20, OP-27 item 4, OP-46).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DurabilityProfile {
    /// `durability quorum`: a synchronous standby quorum.
    Quorum,
    /// `durability single-node`: durable on one node.
    SingleNode,
}

/// The `time_sources` profile line (OP-32, OP-46).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeSources {
    /// `time_sources independent`: at least two NTS sources run by different organisations.
    Independent,
    /// `time_sources dependent`: the sources are not independent, as locally and in CI.
    Dependent,
}

/// The `witness` profile line (OP-33, OP-46).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WitnessProfile {
    /// `witness independent k`: k independent witnesses are declared.
    Independent(NonZeroU8),
    /// `witness local-dependent`: the dependent witness of a local or single-node installation.
    LocalDependent,
    /// `witness none`: no witness is declared.
    Undeclared,
}

/// The profile a Work checkpoint declares in its three extension lines, in this order and each once (OP-46 item 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Profile {
    /// The `durability` line.
    pub durability: DurabilityProfile,
    /// The `time_sources` line.
    pub time_sources: TimeSources,
    /// The `witness` line.
    pub witness: WitnessProfile,
}

fn witness_count(k: &str) -> Option<NonZeroU8> {
    let bytes = k.as_bytes();
    let canonical = (1..=3).contains(&bytes.len())
        && bytes.iter().all(u8::is_ascii_digit)
        && bytes.first().is_some_and(|b| *b != b'0');
    if !canonical {
        return None;
    }
    let mut value: u8 = 0;
    for b in bytes {
        value = value.checked_mul(10)?.checked_add(b.checked_sub(b'0')?)?;
    }
    NonZeroU8::new(value)
}

impl Profile {
    /// Reads the extension lines of a Work checkpoint body.
    ///
    /// # Errors
    ///
    /// `checkpoint-malformed` when a line is missing, extra, out of order, repeated or carries an unknown value.
    pub fn from_extensions(lines: &[String]) -> Result<Self, NoteError> {
        let [durability, time_sources, witness] = lines else {
            return Err(NoteError::Checkpoint);
        };
        let durability = match durability.as_str() {
            "durability quorum" => DurabilityProfile::Quorum,
            "durability single-node" => DurabilityProfile::SingleNode,
            _ => return Err(NoteError::Checkpoint),
        };
        let time_sources = match time_sources.as_str() {
            "time_sources independent" => TimeSources::Independent,
            "time_sources dependent" => TimeSources::Dependent,
            _ => return Err(NoteError::Checkpoint),
        };
        let witness = match witness.as_str() {
            "witness local-dependent" => WitnessProfile::LocalDependent,
            "witness none" => WitnessProfile::Undeclared,
            other => other
                .strip_prefix("witness independent ")
                .and_then(witness_count)
                .map(WitnessProfile::Independent)
                .ok_or(NoteError::Checkpoint)?,
        };
        Ok(Self {
            durability,
            time_sources,
            witness,
        })
    }

    /// The three extension lines, in order.
    #[must_use]
    pub fn to_extensions(&self) -> Vec<String> {
        let durability = match self.durability {
            DurabilityProfile::Quorum => "durability quorum",
            DurabilityProfile::SingleNode => "durability single-node",
        };
        let time_sources = match self.time_sources {
            TimeSources::Independent => "time_sources independent",
            TimeSources::Dependent => "time_sources dependent",
        };
        let witness = match self.witness {
            WitnessProfile::Independent(k) => {
                let mut line = String::from("witness independent ");
                line.push_str(&k.get().to_string());
                line
            }
            WitnessProfile::LocalDependent => String::from("witness local-dependent"),
            WitnessProfile::Undeclared => String::from("witness none"),
        };
        alloc::vec![
            String::from(durability),
            String::from(time_sources),
            witness,
        ]
    }
}

/// A checkpoint whose log signature verified, with the witness cosignatures that verified (P-20, OP-33).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    /// The `tlog-checkpoint` body.
    pub checkpoint: Checkpoint,
    /// The profile its extension lines declare (OP-46).
    pub profile: Profile,
    /// The verified witness cosignatures, each with its timestamp; never the log's own signature.
    pub cosignatures: Vec<Accepted>,
}

/// Verifies a C2SP signed note as a checkpoint of `origin`: the log's own signature must verify, every signature line from a known witness must verify, lines from unknown keys are ignored, and the body must carry the three profile lines (T-4, T-64, OP-33, OP-46).
///
/// # Errors
///
/// The shared crate's [`NoteError`]: `signature-*` when a known key's signature fails, `note-unverified` without the log's signature, `checkpoint-malformed` for another origin, a body that is not a checkpoint or profile lines that are missing, extra, out of order or of unknown value, or a note syntax code.
pub fn verify_checkpoint(
    signed_note: &str,
    origin: &str,
    log: &Verifier,
    witnesses: &[Verifier],
) -> Result<SignedCheckpoint, NoteError> {
    let (checkpoint, accepted) =
        note::verify_checkpoint(&PureBackend, signed_note, origin, log, witnesses)?;
    let profile = Profile::from_extensions(&checkpoint.extensions)?;
    Ok(SignedCheckpoint {
        checkpoint,
        profile,
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const QUORUM: &str = "durability quorum";
    const SINGLE: &str = "durability single-node";
    const INDEPENDENT: &str = "time_sources independent";
    const DEPENDENT: &str = "time_sources dependent";

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| String::from(*l)).collect()
    }

    fn profile(durability: DurabilityProfile, time: TimeSources, w: WitnessProfile) -> Profile {
        Profile {
            durability,
            time_sources: time,
            witness: w,
        }
    }

    // OP-46 T-88
    #[test]
    fn op_46_profile_lines_are_three_known_values_in_order() {
        let (two, max) = (NonZeroU8::MIN.saturating_add(1), NonZeroU8::MAX);
        let cases = [
            (
                [QUORUM, INDEPENDENT, "witness independent 2"],
                profile(
                    DurabilityProfile::Quorum,
                    TimeSources::Independent,
                    WitnessProfile::Independent(two),
                ),
            ),
            (
                [SINGLE, DEPENDENT, "witness local-dependent"],
                profile(
                    DurabilityProfile::SingleNode,
                    TimeSources::Dependent,
                    WitnessProfile::LocalDependent,
                ),
            ),
            (
                [SINGLE, INDEPENDENT, "witness none"],
                profile(
                    DurabilityProfile::SingleNode,
                    TimeSources::Independent,
                    WitnessProfile::Undeclared,
                ),
            ),
            (
                [QUORUM, DEPENDENT, "witness independent 255"],
                profile(
                    DurabilityProfile::Quorum,
                    TimeSources::Dependent,
                    WitnessProfile::Independent(max),
                ),
            ),
        ];
        for (text, want) in cases {
            assert_eq!(Profile::from_extensions(&lines(&text)), Ok(want));
            assert_eq!(want.to_extensions(), lines(&text));
        }
        let witness = "witness independent 1";
        for bad in [
            vec![QUORUM, INDEPENDENT],
            vec![QUORUM, INDEPENDENT, witness, witness],
            vec![INDEPENDENT, QUORUM, witness],
            vec![QUORUM, QUORUM, witness],
            vec![QUORUM, INDEPENDENT, witness, "extra"],
            vec!["durability eventual", INDEPENDENT, witness],
            vec![QUORUM, "time_sources none", witness],
            vec![QUORUM, INDEPENDENT, "witness independent 0"],
            vec![QUORUM, INDEPENDENT, "witness independent 01"],
            vec![QUORUM, INDEPENDENT, "witness independent 256"],
            vec![QUORUM, INDEPENDENT, "witness independent +1"],
            vec![QUORUM, INDEPENDENT, "witness independent"],
            vec![QUORUM, INDEPENDENT, "witness  independent 1"],
            vec![QUORUM, INDEPENDENT, "witness independent 1 "],
            vec![],
        ] {
            assert_eq!(
                Profile::from_extensions(&lines(&bad)),
                Err(NoteError::Checkpoint),
                "{bad:?}"
            );
        }
    }
}
