use std::future::Future;
use std::time::Duration;

use suiss_ledger::sequencer::MAX_BATCH;
use tokio::sync::{mpsc, oneshot};
use work_store::StoreError;

use crate::{Leader, LedgerError, PendingRecord};

/// Ledger time (T-32 rule 2, §18 OP-6): no code reads the wall clock directly.
pub trait Clock: Send {
    /// Trusted time in Unix milliseconds; an error means no commit (OP-6).
    fn now(&mut self) -> impl Future<Output = Result<u64, ClockError>> + Send;
}

/// Trusted time is not available, so nothing is committed (OP-6, OP-32 item 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("trusted time unavailable: {0}")]
pub struct ClockError(pub String);

/// Group commit values (OP-31 item 2, OP-41; POLICY DEFAULT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupConfig {
    max_records: usize,
    max_bytes: usize,
    queue: usize,
    retry_after: Duration,
}

/// Most records in one batch (OP-31 item 2).
pub const DEFAULT_MAX_RECORDS: usize = MAX_BATCH;
/// Most record bytes in one batch, 1 MiB (OP-31 item 2).
pub const DEFAULT_MAX_BYTES: usize = 1 << 20;
/// Pending requests per ledger, four batches (OP-41 item 1).
pub const DEFAULT_QUEUE: usize = 1024;
/// `Retry-After` of a request refused on a full queue (OP-41 item 2).
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(1);

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            max_records: DEFAULT_MAX_RECORDS,
            max_bytes: DEFAULT_MAX_BYTES,
            queue: DEFAULT_QUEUE,
            retry_after: DEFAULT_RETRY_AFTER,
        }
    }
}

/// A group commit value outside its range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("group commit value out of range: {0}")]
pub struct GroupConfigError(&'static str);

impl GroupConfig {
    /// The values; `max_records` is 1 to the engine ceiling, the others at least 1.
    ///
    /// # Errors
    /// [`GroupConfigError`] naming the value.
    pub fn new(
        max_records: usize,
        max_bytes: usize,
        queue: usize,
        retry_after: Duration,
    ) -> Result<Self, GroupConfigError> {
        if max_records == 0 || max_records > MAX_BATCH {
            return Err(GroupConfigError("max_records"));
        }
        if max_bytes == 0 {
            return Err(GroupConfigError("max_bytes"));
        }
        if queue == 0 {
            return Err(GroupConfigError("queue"));
        }
        if retry_after.is_zero() {
            return Err(GroupConfigError("retry_after"));
        }
        Ok(Self {
            max_records,
            max_bytes,
            queue,
            retry_after,
        })
    }

    /// Most records in one batch.
    #[must_use]
    pub const fn max_records(&self) -> usize {
        self.max_records
    }
}

/// Where a submitted record landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    /// Its log position.
    pub pos: u64,
    /// Its ledger time.
    pub recorded_at_ms: u64,
}

/// Why a submitted record was not committed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubmitError {
    /// The queue is full; nothing was written and the caller retries with the same
    /// idempotency key after `retry_after` (OP-41 item 2).
    #[error("ledger busy")]
    Busy {
        /// The `Retry-After` value.
        retry_after: Duration,
    },
    /// The record was refused before anything was written: an item head conflict or a reused
    /// idempotency key (P-29, OP-8).
    #[error("refused: {0}")]
    Refused(StoreError),
    /// Trusted time was unavailable; nothing was written (OP-6).
    #[error(transparent)]
    Clock(ClockError),
    /// The commit failed or its outcome is unknown; the result is read back through the
    /// idempotency key (OP-8, §17.12).
    #[error("commit failed")]
    Failed,
    /// The writer has stopped.
    #[error("writer stopped")]
    Closed,
}

struct Request {
    record: PendingRecord,
    reply: oneshot::Sender<Result<Committed, SubmitError>>,
}

/// The submitting side of a ledger's single writer (OP-31, OP-41).
#[derive(Debug, Clone)]
pub struct GroupCommit {
    tx: mpsc::Sender<Request>,
    retry_after: Duration,
}

impl GroupCommit {
    /// Starts the writer of `leader`'s ledger. It runs until every [`GroupCommit`] is dropped,
    /// or until a failed commit steps the leader down, when it returns that error.
    #[must_use]
    pub fn spawn<C: Clock + 'static>(
        leader: Leader,
        clock: C,
        config: GroupConfig,
    ) -> (Self, tokio::task::JoinHandle<Result<(), LedgerError>>) {
        let (tx, rx) = mpsc::channel(config.queue);
        let writer = tokio::spawn(run(leader, clock, config, rx));
        (
            Self {
                tx,
                retry_after: config.retry_after,
            },
            writer,
        )
    }

    /// Queues `record` and waits until its batch is durable (OP-3). A full queue answers
    /// [`SubmitError::Busy`] at once. Dropping the future before the record joins a batch
    /// withdraws it; after that it is committed or failed as a whole (OP-41 item 3).
    ///
    /// # Errors
    /// [`SubmitError`].
    pub async fn submit(&self, record: PendingRecord) -> Result<Committed, SubmitError> {
        let (reply, answer) = oneshot::channel();
        self.tx
            .try_send(Request { record, reply })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => SubmitError::Busy {
                    retry_after: self.retry_after,
                },
                mpsc::error::TrySendError::Closed(_) => SubmitError::Closed,
            })?;
        answer.await.unwrap_or(Err(SubmitError::Closed))
    }
}

fn size(r: &PendingRecord) -> usize {
    r.record_bytes.len()
}

/// Takes the next batch: waits for one request, then drains what queued during the previous
/// flush up to the limits, with no added wait (OP-31 item 1).
async fn next_batch(
    rx: &mut mpsc::Receiver<Request>,
    config: &GroupConfig,
) -> Option<Vec<Request>> {
    let first = rx.recv().await?;
    let mut bytes = size(&first.record);
    let mut batch = vec![first];
    while batch.len() < config.max_records && bytes < config.max_bytes {
        let Ok(next) = rx.try_recv() else { break };
        bytes = bytes.saturating_add(size(&next.record));
        batch.push(next);
    }
    batch.retain(|r| !r.reply.is_closed());
    Some(batch)
}

fn answer(requests: Vec<Request>, outcome: impl Fn(usize) -> Result<Committed, SubmitError>) {
    for (i, r) in requests.into_iter().enumerate() {
        let _sent = r.reply.send(outcome(i));
    }
}

async fn run<C: Clock>(
    mut leader: Leader,
    mut clock: C,
    config: GroupConfig,
    mut rx: mpsc::Receiver<Request>,
) -> Result<(), LedgerError> {
    while let Some(batch) = next_batch(&mut rx, &config).await {
        if batch.is_empty() {
            continue;
        }
        let now = match clock.now().await {
            Ok(now) => now,
            Err(e) => {
                answer(batch, |_| Err(SubmitError::Clock(e.clone())));
                continue;
            }
        };
        let records: Vec<PendingRecord> = batch.iter().map(|r| r.record.clone()).collect();
        match leader.commit(now, &records).await {
            Ok(last) => {
                let at = leader.head().recorded_at;
                let first = last
                    .checked_sub(u64::try_from(records.len()).unwrap_or(u64::MAX))
                    .ok_or(LedgerError::Head)?;
                answer(batch, |i| {
                    let pos = u64::try_from(i)
                        .ok()
                        .and_then(|i| first.checked_add(i))
                        .and_then(|p| p.checked_add(1))
                        .ok_or(SubmitError::Failed)?;
                    Ok(Committed {
                        pos,
                        recorded_at_ms: at,
                    })
                });
            }
            Err(LedgerError::Refused(_)) => one_by_one(&mut leader, now, batch).await?,
            Err(e) => {
                answer(batch, |_| Err(SubmitError::Failed));
                return Err(e);
            }
        }
    }
    Ok(())
}

/// A refused batch is retried record by record, so only the record that conflicts is refused
/// and the others are committed (§17.1.1 step 9).
async fn one_by_one(leader: &mut Leader, now: u64, batch: Vec<Request>) -> Result<(), LedgerError> {
    let mut rest = batch.into_iter();
    while let Some(r) = rest.next() {
        match leader.commit(now, core::slice::from_ref(&r.record)).await {
            Ok(pos) => {
                let _sent = r.reply.send(Ok(Committed {
                    pos,
                    recorded_at_ms: leader.head().recorded_at,
                }));
            }
            Err(LedgerError::Refused(e)) => {
                let _sent = r.reply.send(Err(SubmitError::Refused(e)));
            }
            Err(e) => {
                let _sent = r.reply.send(Err(SubmitError::Failed));
                answer(rest.collect(), |_| Err(SubmitError::Failed));
                return Err(e);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-31 OP-41
    #[test]
    fn op_41_defaults_are_the_policy_defaults() {
        let d = GroupConfig::default();
        assert_eq!(d.max_records, 256);
        assert_eq!(d.max_bytes, 1_048_576);
        assert_eq!(d.queue, 1024);
        assert_eq!(d.retry_after, Duration::from_secs(1));
    }

    // OP-31 OP-41
    #[test]
    fn op_41_values_outside_their_range_are_refused() {
        let s = Duration::from_secs(1);
        assert_eq!(
            GroupConfig::new(0, 1, 1, s),
            Err(GroupConfigError("max_records"))
        );
        assert_eq!(
            GroupConfig::new(257, 1, 1, s),
            Err(GroupConfigError("max_records"))
        );
        assert_eq!(
            GroupConfig::new(1, 0, 1, s),
            Err(GroupConfigError("max_bytes"))
        );
        assert_eq!(GroupConfig::new(1, 1, 0, s), Err(GroupConfigError("queue")));
        assert_eq!(
            GroupConfig::new(1, 1, 1, Duration::ZERO),
            Err(GroupConfigError("retry_after"))
        );
        assert!(GroupConfig::new(256, 1, 1, s).is_ok());
    }
}
