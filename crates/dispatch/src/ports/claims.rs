//! Ports of the `commitment_active` Claim delivery (E-8, E-12, T-32 rule 2): [`ClaimQueue`], the delivery rows of the canonical store, and [`ClaimSink`], the Access the Claims go to, with the clock their times are read on.

use std::future::Future;

use work_access_client::domain::AccessError;
use work_access_client::domain::commitments::{Ended, Verdict};
use work_store::{ClaimAnswer, ClaimDelivery, ClaimKey, LedgerId, StoreError};

/// The delivery rows of the canonical store.
pub trait ClaimQueue: Send + Sync {
    /// Up to `limit` ledgers with deliveries due at `now_ms` above `after`, in ascending byte
    /// order (T-83).
    fn ledgers(
        &self,
        after: Option<&LedgerId>,
        now_ms: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<LedgerId>, StoreError>> + Send;

    /// Up to `limit` deliveries of `ledger` due at `now_ms`, the longest due first.
    fn due(
        &self,
        ledger: &LedgerId,
        now_ms: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ClaimDelivery>, StoreError>> + Send;

    /// Marks `key` of `ledger` delivered; whether it was still pending.
    fn delivered(
        &self,
        ledger: &LedgerId,
        key: &ClaimKey,
        answer: &ClaimAnswer,
        replayed: bool,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Marks `key` of `ledger` held by Access for `reason`; whether it was still pending.
    fn quarantined(
        &self,
        ledger: &LedgerId,
        key: &ClaimKey,
        answer: &ClaimAnswer,
        reason: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Counts a failed attempt of `key` of `ledger` under `error` and moves it to
    /// `next_attempt_ms`; whether it was still pending.
    fn retry(
        &self,
        ledger: &LedgerId,
        key: &ClaimKey,
        error: &str,
        next_attempt_ms: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// The Access the Claims go to.
pub trait ClaimSink: Send + Sync {
    /// Now on the clock Access's answers are read on, Unix milliseconds.
    fn now_ms(&self) -> u64;

    /// Hands Access the Claim of `ended`.
    fn deliver(&self, ended: &Ended) -> impl Future<Output = Result<Verdict, AccessError>> + Send;
}
