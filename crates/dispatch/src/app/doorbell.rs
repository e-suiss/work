//! The executor doorbell (E-39, T-105): the sequencer writes a delivery row for each commitment or request a record delivers to the executor assigned to the work, and this worker rings the addressee's webhook outside any transaction (T-32 rule 4) with a content-free body naming the ledger and the cursor; the executor then pulls the delivery. A 2xx answer settles the doorbell as rung, an addressee with no webhook configured settles it as unrouted, since it pulls on its own; any other answer or failure keeps it pending under the code of what failed and moves its next attempt by an exponential, bounded and jittered wait (T-21).

use std::future::Future;

use tokio::time::{sleep, timeout};
use work_store::{ExecutorDelivery, LedgerId, StoreError};

use crate::domain::doorbell::{DoorbellConfig, RingError, doorbell_body, ring_again_at};
use crate::domain::{Backoff, ConfigError};
use crate::ports::{DoorbellQueue, Ring};

/// Why one doorbell pass stopped; the doorbells not yet settled stay pending.
#[derive(Debug, thiserror::Error)]
pub enum DoorbellError {
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A store call did not finish within the call timeout.
    #[error("store call timed out")]
    StoreTimedOut,
}

/// Counts of one [`Doorbells::ring_ledger`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rung {
    /// Doorbells a webhook answered.
    pub rung: u64,
    /// Doorbells of addressees without a webhook.
    pub unrouted: u64,
    /// Doorbells that failed and wait for their next attempt.
    pub retried: u64,
}

/// Rings the due executor doorbells.
#[derive(Debug)]
pub struct Doorbells<Q, R> {
    queue: Q,
    ring: R,
    config: DoorbellConfig,
}

impl<Q: DoorbellQueue, R: Ring> Doorbells<Q, R> {
    /// A worker over `queue` and `ring`.
    ///
    /// # Errors
    /// [`ConfigError`] if `config` does not validate.
    pub fn new(queue: Q, ring: R, config: DoorbellConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            queue,
            ring,
            config,
        })
    }

    async fn store<V>(
        &self,
        call: impl Future<Output = Result<V, StoreError>>,
    ) -> Result<V, DoorbellError> {
        Ok(timeout(self.config.call_timeout, call)
            .await
            .map_err(|_| DoorbellError::StoreTimedOut)??)
    }

    async fn settle(
        &self,
        ledger: &LedgerId,
        row: &ExecutorDelivery,
        counts: &mut Rung,
    ) -> Result<(), DoorbellError> {
        let now_ms = self.ring.now_ms();
        let Some(url) = self.config.webhooks.get(&row.row.addressee) else {
            self.store(self.queue.settled(ledger, row.seq, false, now_ms))
                .await?;
            counts.unrouted = counts.unrouted.saturating_add(1);
            return Ok(());
        };
        let body = doorbell_body(ledger, row.seq);
        let rang = timeout(self.config.call_timeout, self.ring.ring(url, &body))
            .await
            .unwrap_or(Err(RingError::Timeout));
        match rang {
            Ok(()) => {
                self.store(self.queue.settled(ledger, row.seq, true, now_ms))
                    .await?;
                counts.rung = counts.rung.saturating_add(1);
            }
            Err(error) => {
                let code = error.code();
                let next = ring_again_at(
                    now_ms,
                    row.attempts,
                    (ledger, row.seq),
                    self.config.retry_min,
                    self.config.retry_max,
                );
                self.store(self.queue.retry(ledger, row.seq, &code, next))
                    .await?;
                counts.retried = counts.retried.saturating_add(1);
                tracing::warn!(
                    event = "executor.doorbell_unrung",
                    error = code.as_str(),
                    attempts = row.attempts.saturating_add(1),
                    next_attempt_ms = next,
                    "an executor doorbell did not ring"
                );
            }
        }
        Ok(())
    }

    /// Rings every due doorbell of `ledger`, batch by batch, until none is due or a store call
    /// fails. A doorbell that failed is not due again in the same pass.
    ///
    /// # Errors
    /// The first [`DoorbellError`]; doorbells not yet settled stay pending.
    pub async fn ring_ledger(&self, ledger: &LedgerId) -> Result<Rung, DoorbellError> {
        let mut counts = Rung::default();
        loop {
            let now_ms = self.ring.now_ms();
            let batch = self
                .store(self.queue.due(ledger, now_ms, self.config.batch_size))
                .await?;
            for row in &batch {
                self.settle(ledger, row, &mut counts).await?;
            }
            if batch.len() < usize::try_from(self.config.batch_size).unwrap_or(usize::MAX) {
                return Ok(counts);
            }
        }
    }

    /// Rings the due doorbells of every ledger until `shutdown` resolves, paging through the
    /// ledgers like the Claim delivery (T-83); after a store failure it waits the exponential
    /// backoff (T-21).
    pub async fn run(&self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut backoff = Backoff::new(self.config.retry_min, self.config.retry_max);
        let mut after: Option<LedgerId> = None;
        loop {
            let mut failed = false;
            let mut full = false;
            let now_ms = self.ring.now_ms();
            match self
                .store(
                    self.queue
                        .ledgers(after.as_ref(), now_ms, self.config.ledgers_per_poll),
                )
                .await
            {
                Ok(ledgers) => {
                    full = ledgers.len()
                        >= usize::try_from(self.config.ledgers_per_poll).unwrap_or(usize::MAX);
                    after = if full { ledgers.last().copied() } else { None };
                    for ledger in &ledgers {
                        if let Err(e) = self.ring_ledger(ledger).await {
                            tracing::warn!(
                                event = "executor.doorbell_pass_stopped",
                                error = %e,
                                "an executor doorbell pass stopped"
                            );
                            failed = true;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        event = "executor.doorbell_discovery_failed",
                        error = %e,
                        "the ledgers with executor doorbells due are not discovered"
                    );
                    failed = true;
                }
            }
            let wait = if failed {
                backoff.fail()
            } else {
                backoff.reset();
                if full {
                    std::time::Duration::ZERO
                } else {
                    self.config.poll_interval
                }
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = sleep(wait) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use work_store::{DeliveryKind, Doorbell, ExecutorDeliveryRow};

    use super::*;

    const NOW: u64 = 1_792_749_600_000;

    fn ledger() -> LedgerId {
        LedgerId::from_bytes([0xab; 32])
    }

    fn row(seq: u64, addressee: &str) -> ExecutorDelivery {
        ExecutorDelivery {
            seq,
            pos: seq,
            record: [1; 32],
            row: ExecutorDeliveryRow {
                addressee: addressee.to_owned(),
                kind: DeliveryKind::Request,
                commitment: [2; 32],
                body: vec![0xa0],
            },
            issued_at_ms: NOW,
            attempts: 0,
            doorbell: Doorbell::Pending {
                next_attempt_ms: NOW,
                last_error: None,
            },
        }
    }

    #[derive(Default)]
    struct MemQueue {
        rows: Mutex<BTreeMap<u64, ExecutorDelivery>>,
    }

    impl DoorbellQueue for MemQueue {
        fn ledgers(
            &self,
            _: Option<&LedgerId>,
            _: u64,
            _: u32,
        ) -> impl Future<Output = Result<Vec<LedgerId>, StoreError>> + Send {
            std::future::ready(Ok(vec![ledger()]))
        }

        fn due(
            &self,
            _: &LedgerId,
            now_ms: u64,
            limit: u32,
        ) -> impl Future<Output = Result<Vec<ExecutorDelivery>, StoreError>> + Send {
            let rows = self.rows.lock().unwrap();
            let due: Vec<ExecutorDelivery> = rows
                .values()
                .filter(|r| {
                    matches!(r.doorbell, Doorbell::Pending { next_attempt_ms, .. } if next_attempt_ms <= now_ms)
                })
                .take(usize::try_from(limit).unwrap())
                .cloned()
                .collect();
            std::future::ready(Ok(due))
        }

        fn settled(
            &self,
            _: &LedgerId,
            seq: u64,
            rung: bool,
            at_ms: u64,
        ) -> impl Future<Output = Result<bool, StoreError>> + Send {
            let mut rows = self.rows.lock().unwrap();
            let r = rows.get_mut(&seq).unwrap();
            r.attempts = r.attempts.checked_add(1).unwrap();
            r.doorbell = if rung {
                Doorbell::Rung { at_ms }
            } else {
                Doorbell::Unrouted { at_ms }
            };
            std::future::ready(Ok(true))
        }

        fn retry(
            &self,
            _: &LedgerId,
            seq: u64,
            error: &str,
            next_attempt_ms: u64,
        ) -> impl Future<Output = Result<bool, StoreError>> + Send {
            let mut rows = self.rows.lock().unwrap();
            let r = rows.get_mut(&seq).unwrap();
            r.attempts = r.attempts.checked_add(1).unwrap();
            r.doorbell = Doorbell::Pending {
                next_attempt_ms,
                last_error: Some(error.to_owned()),
            };
            std::future::ready(Ok(true))
        }
    }

    struct Hooks {
        answer: Result<(), RingError>,
        rung: Mutex<Vec<(String, String)>>,
    }

    impl Ring for Hooks {
        fn now_ms(&self) -> u64 {
            NOW
        }

        fn ring(
            &self,
            url: &str,
            body: &str,
        ) -> impl Future<Output = Result<(), RingError>> + Send {
            self.rung
                .lock()
                .unwrap()
                .push((url.to_owned(), body.to_owned()));
            std::future::ready(self.answer.clone())
        }
    }

    fn worker(answer: Result<(), RingError>) -> Doorbells<MemQueue, Hooks> {
        let queue = MemQueue::default();
        {
            let mut rows = queue.rows.lock().unwrap();
            rows.insert(1, row(1, "party:acme:agent"));
            rows.insert(2, row(2, "party:acme:robot"));
        }
        let mut webhooks = BTreeMap::new();
        webhooks.insert(
            "party:acme:agent".to_owned(),
            "https://agent.example/doorbell".to_owned(),
        );
        let config = DoorbellConfig {
            webhooks,
            ..DoorbellConfig::default()
        };
        let hooks = Hooks {
            answer,
            rung: Mutex::new(Vec::new()),
        };
        Doorbells::new(queue, hooks, config).unwrap()
    }

    // E-39 T-105
    #[tokio::test]
    async fn e_39_a_doorbell_rings_the_addressee_s_webhook_and_an_unrouted_one_is_settled() {
        let w = worker(Ok(()));
        let counts = w.ring_ledger(&ledger()).await.unwrap();
        assert_eq!(
            counts,
            Rung {
                rung: 1,
                unrouted: 1,
                retried: 0
            }
        );
        let rung = w.ring.rung.lock().unwrap().clone();
        assert_eq!(rung.len(), 1);
        assert_eq!(rung[0].0, "https://agent.example/doorbell");
        assert_eq!(rung[0].1, doorbell_body(&ledger(), 1));
        let rows = w.queue.rows.lock().unwrap();
        assert_eq!(rows[&1].doorbell, Doorbell::Rung { at_ms: NOW });
        assert_eq!(rows[&2].doorbell, Doorbell::Unrouted { at_ms: NOW });
    }

    // T-105 T-21
    #[tokio::test]
    async fn t_105_a_failed_doorbell_keeps_its_attempts_and_waits_its_backoff() {
        let w = worker(Err(RingError::Status(503)));
        let counts = w.ring_ledger(&ledger()).await.unwrap();
        assert_eq!(counts.retried, 1);
        let rows = w.queue.rows.lock().unwrap();
        let failed = &rows[&1];
        assert_eq!(failed.attempts, 1);
        match &failed.doorbell {
            Doorbell::Pending {
                next_attempt_ms,
                last_error,
            } => {
                assert_eq!(last_error.as_deref(), Some("webhook_status:503"));
                assert!(*next_attempt_ms >= NOW.checked_add(500).unwrap());
                assert!(*next_attempt_ms <= NOW.checked_add(1000).unwrap());
            }
            other => panic!("{other:?}"),
        }
    }
}
