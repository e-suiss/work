//! Adapters of the `commitment_active` Claim delivery (E-8, E-12): [`PgClaims`], the delivery rows of the canonical store over a pool logged in as `work_publisher`, each call in a transaction of its own (T-32 rule 4); and [`AccessClaims`], Work's Access client over its PEP certificate, every call under a timeout (T-32 rule 7).

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use work_access_client::app::Client;
use work_access_client::domain::AccessError;
use work_access_client::domain::commitments::{Ended, Verdict};
use work_access_client::ports::{Clock, Transport};
use work_store::{ClaimAnswer, ClaimDelivery, ClaimKey, LedgerId, PublisherPool, StoreError};

use crate::ports::{ClaimQueue, ClaimSink};

/// The delivery rows over a pool logged in as `work_publisher`.
#[derive(Debug, Clone)]
pub struct PgClaims {
    pool: PublisherPool,
}

impl PgClaims {
    /// Over `pool`.
    #[must_use]
    pub const fn new(pool: PublisherPool) -> Self {
        Self { pool }
    }
}

impl ClaimQueue for PgClaims {
    async fn ledgers(
        &self,
        after: Option<&LedgerId>,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<LedgerId>, StoreError> {
        self.pool.claim_ledgers(after, now_ms, limit).await
    }

    async fn due(
        &self,
        ledger: &LedgerId,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<ClaimDelivery>, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let rows = tx.claims_due(now_ms, limit).await?;
        tx.commit().await?;
        Ok(rows)
    }

    async fn delivered(
        &self,
        ledger: &LedgerId,
        key: &ClaimKey,
        answer: &ClaimAnswer,
        replayed: bool,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let done = tx.claim_delivered(key, answer, replayed).await?;
        tx.commit().await?;
        Ok(done)
    }

    async fn quarantined(
        &self,
        ledger: &LedgerId,
        key: &ClaimKey,
        answer: &ClaimAnswer,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let done = tx.claim_quarantined(key, answer, reason).await?;
        tx.commit().await?;
        Ok(done)
    }

    async fn retry(
        &self,
        ledger: &LedgerId,
        key: &ClaimKey,
        error: &str,
        next_attempt_ms: u64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let done = tx.claim_retry(key, error, next_attempt_ms).await?;
        tx.commit().await?;
        Ok(done)
    }
}

/// Work's Access client, each Claim handed over under `call_timeout`.
pub struct AccessClaims<T, C> {
    access: Arc<Client<T, C>>,
    call_timeout: Duration,
}

impl<T, C> std::fmt::Debug for AccessClaims<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessClaims")
            .field("call_timeout", &self.call_timeout)
            .finish_non_exhaustive()
    }
}

impl<T, C> AccessClaims<T, C> {
    /// Over `access`.
    #[must_use]
    pub const fn new(access: Arc<Client<T, C>>, call_timeout: Duration) -> Self {
        Self {
            access,
            call_timeout,
        }
    }
}

impl<T: Transport, C: Clock> ClaimSink for AccessClaims<T, C> {
    fn now_ms(&self) -> u64 {
        self.access.now_ms()
    }

    async fn deliver(&self, ended: &Ended) -> Result<Verdict, AccessError> {
        timeout(self.call_timeout, self.access.commitment_ended(ended))
            .await
            .map_err(|_| AccessError::Timeout)?
    }
}
