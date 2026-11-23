//! The `commitment_active` Claim delivery (E-8, E-12, WD-146 item 5): the sequencer writes a delivery row for each end of `commitment.active` with the record that gave it, and this worker hands each due row's Claim to Access outside any transaction (T-32 rule 4). An admission, a replay among them, settles the row as delivered; a quarantine settles it as held with Access's reason, since the same Claim handed over again is answered with the same quarantine; any other answer or failure keeps the row pending under the code of what failed and moves its next attempt by an exponential, bounded and jittered wait (T-21). The Claim is the same on every attempt, issued at the ledger time of the record, so Access answers a repeat as a replay.

use std::future::Future;

use tokio::time::{sleep, timeout};
use work_access_client::domain::commitments::Verdict;
use work_store::{ClaimAnswer, ClaimDelivery, LedgerId, StoreError};

use crate::domain::claims::{ClaimConfig, ended, error_code, retry_at};
use crate::domain::{Backoff, ConfigError};
use crate::ports::{ClaimQueue, ClaimSink};

/// Why one delivery pass stopped; the rows not yet settled stay pending.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A store call did not finish within the call timeout.
    #[error("store call timed out")]
    StoreTimedOut,
}

/// Counts of one [`ClaimDeliverer::deliver_ledger`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Delivered {
    /// Claims Access admitted.
    pub admitted: u64,
    /// Of those, answered as a replay of an earlier hand-over.
    pub replayed: u64,
    /// Claims Access holds.
    pub quarantined: u64,
    /// Claims that did not reach Access and wait for their next attempt.
    pub retried: u64,
}

/// Hands the due `commitment_active` Claims to Access.
#[derive(Debug)]
pub struct ClaimDeliverer<Q, S> {
    queue: Q,
    sink: S,
    config: ClaimConfig,
}

impl<Q: ClaimQueue, S: ClaimSink> ClaimDeliverer<Q, S> {
    /// A worker over `queue` and `sink`.
    ///
    /// # Errors
    /// [`ConfigError`] if `config` does not validate.
    pub fn new(queue: Q, sink: S, config: ClaimConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            queue,
            sink,
            config,
        })
    }

    async fn store<V>(
        &self,
        call: impl Future<Output = Result<V, StoreError>>,
    ) -> Result<V, ClaimError> {
        Ok(timeout(self.config.call_timeout, call)
            .await
            .map_err(|_| ClaimError::StoreTimedOut)??)
    }

    async fn settle(
        &self,
        ledger: &LedgerId,
        row: &ClaimDelivery,
        counts: &mut Delivered,
    ) -> Result<(), ClaimError> {
        let now_ms = self.sink.now_ms();
        let answer = timeout(self.config.call_timeout, self.sink.deliver(&ended(row))).await;
        match answer {
            Ok(Ok(Verdict::Admitted {
                claim,
                position,
                replayed,
            })) => {
                let answer = ClaimAnswer {
                    claim,
                    position,
                    at_ms: now_ms,
                };
                self.store(self.queue.delivered(ledger, &row.key, &answer, replayed))
                    .await?;
                counts.admitted = counts.admitted.saturating_add(1);
                if replayed {
                    counts.replayed = counts.replayed.saturating_add(1);
                }
                tracing::info!(
                    event = "commitment.active_ended",
                    replayed,
                    attempts = row.attempts.saturating_add(1),
                    "Access admitted the commitment.active = false Claim"
                );
            }
            Ok(Ok(Verdict::Quarantined {
                claim,
                position,
                reason,
            })) => {
                let answer = ClaimAnswer {
                    claim,
                    position,
                    at_ms: now_ms,
                };
                self.store(self.queue.quarantined(ledger, &row.key, &answer, &reason))
                    .await?;
                counts.quarantined = counts.quarantined.saturating_add(1);
                tracing::warn!(
                    event = "commitment.active_end_held",
                    reason = reason.as_str(),
                    "Access holds the commitment.active = false Claim"
                );
            }
            failed => {
                let code = match &failed {
                    Ok(Err(error)) => error_code(error),
                    _ => "access_timeout",
                };
                let next = retry_at(
                    now_ms,
                    row.attempts,
                    &row.key,
                    self.config.retry_min,
                    self.config.retry_max,
                );
                self.store(self.queue.retry(ledger, &row.key, code, next))
                    .await?;
                counts.retried = counts.retried.saturating_add(1);
                tracing::warn!(
                    event = "commitment.active_end_unsent",
                    error = code,
                    attempts = row.attempts.saturating_add(1),
                    next_attempt_ms = next,
                    "the commitment.active = false Claim did not reach Access"
                );
            }
        }
        Ok(())
    }

    /// Hands Access every due Claim of `ledger`, batch by batch, until none is due or a store
    /// call fails. A Claim that did not reach Access is not due again in the same pass.
    ///
    /// # Errors
    /// The first [`ClaimError`]; rows not yet settled stay pending.
    pub async fn deliver_ledger(&self, ledger: &LedgerId) -> Result<Delivered, ClaimError> {
        let mut counts = Delivered::default();
        loop {
            let now_ms = self.sink.now_ms();
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

    /// Delivers the due Claims of every ledger until `shutdown` resolves. Each poll discovers
    /// up to `ledgers_per_poll` ledgers with Claims due above the last one discovered and
    /// delivers them in turn; a shorter page starts the next poll from the lowest id again
    /// (T-83). After a full page without failure the next poll starts at once, otherwise it
    /// waits `poll_interval`, and after a store failure the exponential backoff (T-21).
    pub async fn run(&self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut backoff = Backoff::new(self.config.retry_min, self.config.retry_max);
        let mut after: Option<LedgerId> = None;
        loop {
            let mut failed = false;
            let mut full = false;
            let now_ms = self.sink.now_ms();
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
                        if let Err(e) = self.deliver_ledger(ledger).await {
                            tracing::warn!(
                                event = "commitment.active_end_pass_stopped",
                                error = %e,
                                "a commitment_active Claim delivery pass stopped"
                            );
                            failed = true;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        event = "commitment.active_end_discovery_failed",
                        error = %e,
                        "the ledgers with commitment_active Claims due are not discovered"
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
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use work_access_client::domain::AccessError;
    use work_access_client::domain::commitments::Ended;
    use work_store::{ClaimKey, ClaimRow, Delivery};

    use super::*;

    const L: [u8; 32] = [0xab; 32];
    const NOW: u64 = 1_792_749_600_000;

    fn ledger() -> LedgerId {
        LedgerId::from_bytes(L)
    }

    fn row(n: u8) -> ClaimDelivery {
        ClaimDelivery {
            key: ClaimKey {
                record: [n; 32],
                subject: [n; 16],
            },
            pos: u64::from(n),
            claim: ClaimRow {
                subject: [n; 16],
                commitment: [0xc0; 32],
                issuer: [0x11; 16],
                domain: [0x22; 32],
                pep: [0x33; 32],
            },
            issued_at_ms: NOW,
            attempts: 0,
            delivery: Delivery::Pending {
                next_attempt_ms: NOW,
                last_error: None,
            },
        }
    }

    #[derive(Default)]
    struct MemQueue {
        rows: Mutex<BTreeMap<ClaimKey, ClaimDelivery>>,
    }

    impl MemQueue {
        fn with(rows: &[ClaimDelivery]) -> Self {
            Self {
                rows: Mutex::new(rows.iter().map(|r| (r.key, r.clone())).collect()),
            }
        }

        fn get(&self, key: &ClaimKey) -> ClaimDelivery {
            self.rows.lock().unwrap()[key].clone()
        }

        fn settle(&self, key: &ClaimKey, delivery: Delivery) -> bool {
            let mut rows = self.rows.lock().unwrap();
            let r = rows.get_mut(key).unwrap();
            if !matches!(r.delivery, Delivery::Pending { .. }) {
                return false;
            }
            r.attempts = r.attempts.checked_add(1).unwrap();
            r.delivery = delivery;
            true
        }
    }

    impl ClaimQueue for MemQueue {
        fn ledgers(
            &self,
            _: Option<&LedgerId>,
            now_ms: u64,
            _: u32,
        ) -> impl Future<Output = Result<Vec<LedgerId>, StoreError>> + Send {
            std::future::ready({
                let rows = self.rows.lock().unwrap();
                let due = rows.values().any(|r| {
                    matches!(r.delivery, Delivery::Pending { next_attempt_ms, .. } if next_attempt_ms <= now_ms)
                });
                Ok(if due { vec![ledger()] } else { vec![] })
            })
        }

        fn due(
            &self,
            _: &LedgerId,
            now_ms: u64,
            limit: u32,
        ) -> impl Future<Output = Result<Vec<ClaimDelivery>, StoreError>> + Send {
            std::future::ready({
                let rows = self.rows.lock().unwrap();
                Ok(rows
                    .values()
                    .filter(|r| {
                        matches!(r.delivery, Delivery::Pending { next_attempt_ms, .. } if next_attempt_ms <= now_ms)
                    })
                    .take(usize::try_from(limit).unwrap())
                    .cloned()
                    .collect())
            })
        }

        fn delivered(
            &self,
            _: &LedgerId,
            key: &ClaimKey,
            answer: &ClaimAnswer,
            replayed: bool,
        ) -> impl Future<Output = Result<bool, StoreError>> + Send {
            std::future::ready({
                Ok(self.settle(
                    key,
                    Delivery::Delivered {
                        claim: answer.claim,
                        position: answer.position,
                        replayed,
                        at_ms: answer.at_ms,
                    },
                ))
            })
        }

        fn quarantined(
            &self,
            _: &LedgerId,
            key: &ClaimKey,
            answer: &ClaimAnswer,
            reason: &str,
        ) -> impl Future<Output = Result<bool, StoreError>> + Send {
            std::future::ready({
                Ok(self.settle(
                    key,
                    Delivery::Quarantined {
                        claim: answer.claim,
                        position: answer.position,
                        reason: reason.to_owned(),
                        at_ms: answer.at_ms,
                    },
                ))
            })
        }

        fn retry(
            &self,
            _: &LedgerId,
            key: &ClaimKey,
            error: &str,
            next_attempt_ms: u64,
        ) -> impl Future<Output = Result<bool, StoreError>> + Send {
            std::future::ready({
                Ok(self.settle(
                    key,
                    Delivery::Pending {
                        next_attempt_ms,
                        last_error: Some(error.to_owned()),
                    },
                ))
            })
        }
    }

    enum Answer {
        Admit,
        Hold,
        Down,
    }

    struct MemAccess {
        now: Mutex<u64>,
        answer: Mutex<Answer>,
        seen: Mutex<Vec<Ended>>,
        admitted: Mutex<BTreeMap<[u8; 16], [u8; 16]>>,
    }

    impl MemAccess {
        fn new(answer: Answer) -> Self {
            Self {
                now: Mutex::new(NOW),
                answer: Mutex::new(answer),
                seen: Mutex::new(Vec::new()),
                admitted: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl ClaimSink for MemAccess {
        fn now_ms(&self) -> u64 {
            *self.now.lock().unwrap()
        }

        fn deliver(&self, e: &Ended) -> impl Future<Output = Result<Verdict, AccessError>> + Send {
            std::future::ready({
                self.seen.lock().unwrap().push(*e);
                let claim = [e.subject.0[0]; 16];
                match *self.answer.lock().unwrap() {
                    Answer::Admit => {
                        let mut admitted = self.admitted.lock().unwrap();
                        let replayed = admitted.insert(e.subject.0, claim).is_some();
                        Ok(Verdict::Admitted {
                            claim,
                            position: 9,
                            replayed,
                        })
                    }
                    Answer::Hold => Ok(Verdict::Quarantined {
                        claim,
                        position: 9,
                        reason: "source-not-accepted".to_owned(),
                    }),
                    Answer::Down => Err(AccessError::Transport("reset".to_owned())),
                }
            })
        }
    }

    fn config() -> ClaimConfig {
        ClaimConfig {
            batch_size: 2,
            ..ClaimConfig::default()
        }
    }

    // E-12 E-8
    #[tokio::test]
    async fn e_12_a_claim_that_does_not_reach_access_stays_pending_and_is_sent_again_the_same() {
        let queue = MemQueue::with(&[row(1), row(2), row(3)]);
        let access = MemAccess::new(Answer::Down);
        let worker = ClaimDeliverer::new(queue, access, config()).unwrap();
        let first = worker.deliver_ledger(&ledger()).await.unwrap();
        assert_eq!(first.retried, 3);
        assert_eq!(first.admitted, 0);
        let held = worker.queue.get(&row(1).key);
        assert_eq!(held.attempts, 1);
        let Delivery::Pending {
            next_attempt_ms,
            last_error,
        } = held.delivery
        else {
            panic!("pending");
        };
        assert_eq!(last_error.as_deref(), Some("access_unreachable"));
        assert!(next_attempt_ms > NOW);
        assert_eq!(
            worker.deliver_ledger(&ledger()).await.unwrap(),
            Delivered::default()
        );
        *worker.sink.now.lock().unwrap() = next_attempt_ms.checked_add(3_600_000).unwrap();
        *worker.sink.answer.lock().unwrap() = Answer::Admit;
        let second = worker.deliver_ledger(&ledger()).await.unwrap();
        assert_eq!(second.admitted, 3);
        let seen = worker.sink.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 6);
        assert_eq!(seen[0], seen[3]);
        assert_eq!(seen[0].issued_at_ms, NOW);
        assert_eq!(seen[0].commitment, [0xc0; 32]);
        let done = worker.queue.get(&row(1).key);
        assert_eq!(done.attempts, 2);
        assert!(matches!(
            done.delivery,
            Delivery::Delivered {
                replayed: false,
                ..
            }
        ));
    }

    // E-12 E-8
    #[tokio::test]
    async fn e_12_an_admitted_or_replayed_claim_is_delivered_and_a_held_one_keeps_its_reason() {
        let queue = MemQueue::with(&[row(1)]);
        let access = MemAccess::new(Answer::Admit);
        access.admitted.lock().unwrap().insert([1; 16], [1; 16]);
        let worker = ClaimDeliverer::new(queue, access, config()).unwrap();
        let counts = worker.deliver_ledger(&ledger()).await.unwrap();
        assert_eq!(counts.admitted, 1);
        assert_eq!(counts.replayed, 1);
        assert!(matches!(
            worker.queue.get(&row(1).key).delivery,
            Delivery::Delivered { replayed: true, claim, position: 9, at_ms: NOW } if claim == [1; 16]
        ));
        assert_eq!(
            worker.deliver_ledger(&ledger()).await.unwrap(),
            Delivered::default()
        );

        let queue = MemQueue::with(&[row(4)]);
        let worker = ClaimDeliverer::new(queue, MemAccess::new(Answer::Hold), config()).unwrap();
        let counts = worker.deliver_ledger(&ledger()).await.unwrap();
        assert_eq!(counts.quarantined, 1);
        let held = worker.queue.get(&row(4).key);
        assert!(matches!(
            held.delivery,
            Delivery::Quarantined { ref reason, .. } if reason == "source-not-accepted"
        ));
        assert_eq!(
            worker.deliver_ledger(&ledger()).await.unwrap(),
            Delivered::default()
        );
        assert_eq!(worker.sink.seen.lock().unwrap().len(), 1);
    }
}
