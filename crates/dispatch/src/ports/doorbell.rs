//! Ports of the executor doorbell (E-39, T-105, T-32 rule 2): [`DoorbellQueue`], the delivery rows of the canonical store, and [`Ring`], the webhooks the doorbells go to, with the clock their times are read on.

use std::future::Future;

use work_store::{ExecutorDelivery, LedgerId, StoreError};

use crate::domain::doorbell::RingError;

/// The delivery rows of the canonical store.
pub trait DoorbellQueue: Send + Sync {
    /// Up to `limit` ledgers with doorbells due at `now_ms` above `after`, in ascending byte
    /// order (T-83).
    fn ledgers(
        &self,
        after: Option<&LedgerId>,
        now_ms: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<LedgerId>, StoreError>> + Send;

    /// Up to `limit` deliveries of `ledger` whose doorbell is due at `now_ms`, the longest due
    /// first.
    fn due(
        &self,
        ledger: &LedgerId,
        now_ms: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ExecutorDelivery>, StoreError>> + Send;

    /// Settles the doorbell of delivery `seq` of `ledger` as rung, or as unrouted when no
    /// webhook is configured for its addressee; whether it was still pending.
    fn settled(
        &self,
        ledger: &LedgerId,
        seq: u64,
        rung: bool,
        at_ms: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Counts a failed doorbell of delivery `seq` of `ledger` under `error` and moves it to
    /// `next_attempt_ms`; whether it was still pending.
    fn retry(
        &self,
        ledger: &LedgerId,
        seq: u64,
        error: &str,
        next_attempt_ms: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// The webhooks the doorbells go to.
pub trait Ring: Send + Sync {
    /// Now, Unix milliseconds.
    fn now_ms(&self) -> u64;

    /// POSTs `body` as `application/json` to `url`.
    fn ring(&self, url: &str, body: &str) -> impl Future<Output = Result<(), RingError>> + Send;
}
