//! Ports this component depends on (T-32): [`Source`], the canonical rows of one ledger an export reads, and nothing derived from them (T-10).

use std::future::Future;

use work_store::{LedgerId, StoreError};

use crate::domain::{BundleCheckpoint, BundleEntry};

/// The canonical rows of a ledger.
pub trait Source: Send + Sync {
    /// Up to `limit` entries of `ledger` from position `from` on, in position order.
    fn entries(
        &self,
        ledger: &LedgerId,
        from: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<BundleEntry>, StoreError>> + Send;

    /// Every signed checkpoint of `ledger` in size order, with its witness cosignatures.
    fn checkpoints(
        &self,
        ledger: &LedgerId,
    ) -> impl Future<Output = Result<Vec<BundleCheckpoint>, StoreError>> + Send;
}
