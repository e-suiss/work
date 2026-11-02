//! The ledgers this process leads and the checkpoints they are owed (§18 OP-4 item 3, OP-5,
//! OP-31, OP-33, T-85 item 4): [`Ledgers`] takes a ledger under a new epoch on first use and runs
//! its group commit writer on the ledger time [`Clock`], counting the records it commits, and
//! [`run_checkpoints`] checkpoints each led ledger through `work-signer` once its [`Cadence`] is
//! due, 60 s of ledger time or 1,000 records by default, whichever comes first, then mirrors it
//! to the replica, which a witness cosignature waits for. Until the signer has answered its log
//! key nothing is checkpointed and the connection is tried again on the next tick.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use work_store::{CheckpointerPool, LedgerId, SequencerPool};

use crate::{
    Checkpointer, Clock, Committed, DirectoryReplica, GroupCommit, GroupConfig, Leader,
    LedgerError, PendingRecord, SignerClient, SubmitError,
};

/// Ledger time between checkpoints of a ledger with new records (OP-33 item 4; POLICY DEFAULT,
/// as Access T16).
pub const DEFAULT_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(60);

/// New records after which a checkpoint is due at once (OP-33 item 4; POLICY DEFAULT, as Access
/// T16).
pub const DEFAULT_CHECKPOINT_RECORDS: u64 = 1000;

/// How often the checkpointer looks at the led ledgers.
pub const CHECKPOINT_TICK: Duration = Duration::from_secs(1);

/// When a checkpoint is due: after `records` new records or `interval` of ledger time since the
/// last one, whichever comes first (OP-33 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    interval_ms: u64,
    records: u64,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            interval_ms: 60_000,
            records: DEFAULT_CHECKPOINT_RECORDS,
        }
    }
}

/// A cadence value outside its range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("checkpoint cadence value out of range: {0}")]
pub struct CadenceError(&'static str);

impl Cadence {
    /// The cadence; both values at least 1, the interval in whole milliseconds.
    ///
    /// # Errors
    /// [`CadenceError`] naming the value.
    pub fn new(interval: Duration, records: u64) -> Result<Self, CadenceError> {
        let interval_ms = u64::try_from(interval.as_millis())
            .ok()
            .filter(|ms| *ms > 0)
            .ok_or(CadenceError("interval"))?;
        if records == 0 {
            return Err(CadenceError("records"));
        }
        Ok(Self {
            interval_ms,
            records,
        })
    }

    /// Whether a ledger with `pending` records committed since its last checkpoint, which was
    /// `elapsed_ms` of ledger time ago, is owed one now.
    #[must_use]
    pub const fn due(&self, pending: u64, elapsed_ms: u64) -> bool {
        pending >= self.records || (pending > 0 && elapsed_ms >= self.interval_ms)
    }
}

struct Led {
    commit: GroupCommit,
    writer: JoinHandle<Result<(), LedgerError>>,
    pending: AtomicU64,
    checkpointed_at: AtomicU64,
    mirror: AtomicBool,
}

/// The ledgers this process leads, each behind its own group commit writer.
pub struct Ledgers<C> {
    pool: SequencerPool,
    clock: C,
    config: GroupConfig,
    led: Mutex<BTreeMap<LedgerId, Arc<Led>>>,
}

impl<C> std::fmt::Debug for Ledgers<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledgers")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<C: Clock + Clone + Sync + 'static> Ledgers<C> {
    /// No ledger led yet; each is acquired from `pool` on first use and written on `clock`.
    #[must_use]
    pub fn new(pool: SequencerPool, clock: C, config: GroupConfig) -> Self {
        Self {
            pool,
            clock,
            config,
            led: Mutex::new(BTreeMap::new()),
        }
    }

    async fn entry(&self, ledger: &LedgerId) -> Result<Arc<Led>, LedgerError> {
        let mut led = self.led.lock().await;
        if let Some(entry) = led.get(ledger).filter(|e| !e.writer.is_finished()) {
            return Ok(Arc::clone(entry));
        }
        let leader = Leader::acquire(self.pool.clone(), *ledger).await?;
        let (commit, writer) = GroupCommit::spawn(leader, self.clock.clone(), self.config);
        let entry = Arc::new(Led {
            commit,
            writer,
            pending: AtomicU64::new(1),
            checkpointed_at: AtomicU64::new(0),
            mirror: AtomicBool::new(true),
        });
        led.insert(*ledger, Arc::clone(&entry));
        Ok(entry)
    }

    /// Leads `ledger`, taking it under a new epoch unless this process already leads it, and
    /// returns its writer. A writer that stepped down is replaced (T-85 item 4).
    ///
    /// # Errors
    /// [`LedgerError`] from [`Leader::acquire`].
    pub async fn lead(&self, ledger: &LedgerId) -> Result<GroupCommit, LedgerError> {
        Ok(self.entry(ledger).await?.commit.clone())
    }

    /// Commits `record` to `ledger` through its writer and counts it towards the next
    /// checkpoint.
    ///
    /// # Errors
    /// [`SubmitError`]; [`SubmitError::Lead`] when the ledger cannot be led here.
    pub async fn submit(
        &self,
        ledger: &LedgerId,
        record: PendingRecord,
    ) -> Result<Committed, SubmitError> {
        let entry = self.entry(ledger).await.map_err(SubmitError::Lead)?;
        let committed = entry.commit.submit(record).await?;
        bump(&entry.pending);
        Ok(committed)
    }

    /// The ledgers led now, in id order.
    pub async fn led(&self) -> Vec<LedgerId> {
        self.led.lock().await.keys().copied().collect()
    }

    async fn snapshot(&self) -> Vec<(LedgerId, Arc<Led>)> {
        self.led
            .lock()
            .await
            .iter()
            .map(|(l, e)| (*l, Arc::clone(e)))
            .collect()
    }
}

/// Counts of the checkpointer since start, for the metrics endpoint; no identity in them.
#[derive(Debug, Default)]
pub struct CheckpointStats {
    signer: AtomicBool,
    stored: AtomicU64,
    failed: AtomicU64,
    mirrored: AtomicU64,
    mirror_failed: AtomicU64,
}

fn bump(n: &AtomicU64) {
    let _bumped = n.update(Ordering::AcqRel, Ordering::Acquire, |v| v.saturating_add(1));
}

fn settle(n: &AtomicU64, by: u64) {
    let _settled = n.update(Ordering::AcqRel, Ordering::Acquire, |v| v.saturating_sub(by));
}

impl CheckpointStats {
    /// Whether the signer has answered its log key.
    #[must_use]
    pub fn signer_connected(&self) -> bool {
        self.signer.load(Ordering::Acquire)
    }

    /// Checkpoints stored.
    #[must_use]
    pub fn stored(&self) -> u64 {
        self.stored.load(Ordering::Acquire)
    }

    /// Checkpoint attempts that stored nothing because of an error.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Acquire)
    }

    /// Mirror passes that brought the replica up to the largest checkpoint.
    #[must_use]
    pub fn mirrored(&self) -> u64 {
        self.mirrored.load(Ordering::Acquire)
    }

    /// Mirror passes that failed; the replica's progress did not move.
    #[must_use]
    pub fn mirror_failed(&self) -> u64 {
        self.mirror_failed.load(Ordering::Acquire)
    }
}

/// What the checkpointer works with.
#[derive(Debug, Clone)]
pub struct CheckpointSetup {
    /// The `work_checkpointer` pool.
    pub pool: CheckpointerPool,
    /// The signer's socket.
    pub signer: SignerClient,
    /// The checkpoint origin of a ledger is this prefix and the ledger id in hex.
    pub origin_prefix: String,
    /// The replica every checkpoint is mirrored to before a witness is asked (OP-4 item 3).
    pub replica: DirectoryReplica,
    /// When a checkpoint is due.
    pub cadence: Cadence,
}

async fn connect(setup: &CheckpointSetup, stats: &CheckpointStats) -> Option<Checkpointer> {
    match Checkpointer::connect(
        setup.pool.clone(),
        setup.signer.clone(),
        &setup.origin_prefix,
    )
    .await
    {
        Ok(checkpointer) => {
            stats.signer.store(true, Ordering::Release);
            tracing::info!(
                event = "checkpointer.connected",
                "the signer answered its log key"
            );
            Some(checkpointer)
        }
        Err(error) => {
            tracing::warn!(event = "checkpointer.signer_unreachable", %error, "no checkpoint until the signer answers");
            None
        }
    }
}

async fn checkpoint_one(
    checkpointer: &Checkpointer,
    setup: &CheckpointSetup,
    ledger: &LedgerId,
    led: &Led,
    now: u64,
    stats: &CheckpointStats,
) {
    let pending = led.pending.load(Ordering::Acquire);
    let elapsed = now.saturating_sub(led.checkpointed_at.load(Ordering::Acquire));
    if setup.cadence.due(pending, elapsed) {
        match checkpointer.checkpoint(ledger, now).await {
            Ok(stored) => {
                settle(&led.pending, pending);
                led.checkpointed_at.store(now, Ordering::Release);
                if let Some(row) = stored {
                    bump(&stats.stored);
                    led.mirror.store(true, Ordering::Release);
                    tracing::info!(
                        event = "checkpoint.stored",
                        size = row.size,
                        "checkpoint signed and stored"
                    );
                }
            }
            Err(error) => {
                bump(&stats.failed);
                tracing::warn!(event = "checkpoint.failed", %error, "checkpoint not stored");
            }
        }
    }
    if led.mirror.load(Ordering::Acquire) {
        match checkpointer.mirror(ledger, &setup.replica).await {
            Ok(size) => {
                led.mirror.store(false, Ordering::Release);
                bump(&stats.mirrored);
                tracing::debug!(
                    event = "replica.mirrored",
                    size,
                    "replica holds the checkpoint"
                );
            }
            Err(error) => {
                bump(&stats.mirror_failed);
                tracing::warn!(event = "replica.mirror_failed", %error, "replica did not advance");
            }
        }
    }
}

/// Checkpoints and mirrors the ledgers `ledgers` leads, every [`CHECKPOINT_TICK`], until the
/// task is dropped. A tick without trusted time checkpoints nothing (OP-6).
pub async fn run_checkpoints<C: Clock + Clone + Sync + 'static>(
    ledgers: Arc<Ledgers<C>>,
    setup: CheckpointSetup,
    stats: Arc<CheckpointStats>,
) {
    let mut clock = ledgers.clock.clone();
    let mut checkpointer: Option<Checkpointer> = None;
    let mut ticks = tokio::time::interval(CHECKPOINT_TICK);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        if checkpointer.is_none() {
            checkpointer = connect(&setup, &stats).await;
        }
        let Some(current) = checkpointer.as_ref() else {
            continue;
        };
        let led = ledgers.snapshot().await;
        if led.is_empty() {
            continue;
        }
        let now = match clock.now().await {
            Ok(now) => now,
            Err(error) => {
                tracing::warn!(event = "checkpoint.no_time", %error, "no checkpoint without trusted time");
                continue;
            }
        };
        for (ledger, entry) in &led {
            checkpoint_one(current, &setup, ledger, entry, now, &stats).await;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-33
    #[test]
    fn op_33_a_checkpoint_is_due_after_60_s_or_1000_records_whichever_comes_first() {
        let c = Cadence::default();
        assert_eq!(
            c,
            Cadence::new(DEFAULT_CHECKPOINT_INTERVAL, DEFAULT_CHECKPOINT_RECORDS).unwrap()
        );
        assert!(c.due(1000, 0));
        assert!(c.due(1, 60_000));
        assert!(!c.due(999, 59_999));
        assert!(!c.due(0, u64::MAX));
        assert!(c.due(u64::MAX, 0));
    }

    // OP-33
    #[test]
    fn op_33_cadence_values_outside_their_range_are_refused() {
        assert_eq!(
            Cadence::new(Duration::ZERO, 1),
            Err(CadenceError("interval"))
        );
        assert_eq!(
            Cadence::new(Duration::from_micros(999), 1),
            Err(CadenceError("interval"))
        );
        assert_eq!(
            Cadence::new(Duration::from_secs(1), 0),
            Err(CadenceError("records"))
        );
        let one = Cadence::new(Duration::from_millis(1), 1).unwrap();
        assert!(one.due(1, 0));
    }
}
