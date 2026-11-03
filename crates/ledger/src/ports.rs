//! Ports of the ledger binding (T-32 rule 2): `Rng`, the only source of random bytes, which a test
//! runs on a fixed seed; `Signer`, the process that holds the log key and signs checkpoint bodies
//! (T-56, T-92); and `Store`, the canonical log a leader appends each batch to in one transaction
//! behind the head compare-and-set and the epoch fence (§18 OP-5). The ledger time port is
//! [`crate::Clock`].

use std::future::Future;

use suiss_ledger::port::LogStore;
use work_kernel::proof::Verifier;
use work_store::{LedgerId, StoreError};

use crate::{CheckpointError, SealedRecord};

/// The random source gave no bytes; nothing random is used then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no randomness")]
pub struct RngError;

/// Random bytes (T-32 rule 2): salts, nonces and every other value Work draws come from here.
pub trait Rng: Send + Sync + std::fmt::Debug {
    /// Fills `out` with random bytes.
    ///
    /// # Errors
    /// [`RngError`] when the source has no randomness.
    fn fill(&self, out: &mut [u8]) -> Result<(), RngError>;
}

/// 32 fresh bytes from `rng`.
///
/// # Errors
/// [`RngError`].
pub fn bytes32(rng: &(impl Rng + ?Sized)) -> Result<[u8; 32], RngError> {
    let mut out = [0_u8; 32];
    rng.fill(&mut out)?;
    Ok(out)
}

/// The process holding the log key (T-92): it reports the key and signs checkpoint bodies; the
/// key never leaves its PKCS#11 token (T-56).
pub trait Signer: Send + Sync {
    /// The log key as a note verifier.
    ///
    /// # Errors
    /// [`CheckpointError`] when the signer cannot be reached or refuses.
    fn log_key(&self) -> impl Future<Output = Result<Verifier, CheckpointError>> + Send;

    /// The note signature line over a checkpoint body.
    ///
    /// # Errors
    /// [`CheckpointError`] when the signer cannot be reached or refuses.
    fn sign_checkpoint(
        &self,
        body: &str,
    ) -> impl Future<Output = Result<String, CheckpointError>> + Send;
}

/// The canonical log of one ledger (§18 OP-5, T-74): an append writes a batch in one transaction
/// that succeeds only if the stored head is still where the batch starts under its epoch.
pub trait Store: LogStore<SealedRecord, Error = StoreError> + Send + Sync {
    /// The ledger the log belongs to.
    fn ledger(&self) -> &LedgerId;
}
