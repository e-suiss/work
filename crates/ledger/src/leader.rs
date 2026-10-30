use suiss_ledger::fence::Fence;
use suiss_ledger::merkle::Frontier;
use suiss_ledger::port::{CommitError, commit};
use suiss_ledger::sequencer::{Head, PlanError, Sequencer};
use work_store::{Genesis, LedgerId, SequencerPool, StoredHead};

use crate::envelope::Bound;
use crate::{LedgerError, PendingRecord, PgLog};

/// The single writer of one ledger under one epoch (T-85 item 4, §18 OP-5, OP-10): every
/// committed batch advances the head and the durability fence; a failed commit steps it down.
#[derive(Debug)]
pub struct Leader {
    log: PgLog,
    seq: Sequencer,
    fence: Fence,
}

fn head_of(stored: StoredHead) -> Result<Head, LedgerError> {
    let size = stored.pos.checked_add(1).ok_or(LedgerError::Head)?;
    Ok(Head {
        pos: stored.pos,
        leaf: stored.leaf,
        recorded_at: stored.recorded_at_ms,
        frontier: Frontier::from_parts(size, stored.frontier).map_err(|_| LedgerError::Head)?,
    })
}

impl Leader {
    /// Opens a ledger with its genesis in one transaction (P-100, T-85 item 3).
    ///
    /// # Errors
    /// [`LedgerError::Store`]; `AlreadyOpened` for a second genesis of the same ledger.
    pub async fn open(pool: &SequencerPool, genesis: &Genesis) -> Result<(), LedgerError> {
        Ok(pool.open_ledger(genesis).await?)
    }

    /// Takes `ledger` under a new epoch, which fences every earlier leader, and leads it from
    /// the stored head (T-85 item 4).
    ///
    /// # Errors
    /// [`LedgerError::Store`] (`NotOpened`, `Diverged`), or [`LedgerError::Head`].
    pub async fn acquire(pool: SequencerPool, ledger: LedgerId) -> Result<Self, LedgerError> {
        let stored = pool.acquire(&ledger).await?;
        let epoch = stored.epoch;
        let head = head_of(stored)?;
        let fence = Fence::at(head.pos);
        Ok(Self {
            log: PgLog::new(pool, ledger),
            seq: Sequencer::lead(epoch, head),
            fence,
        })
    }

    /// The last committed head.
    #[must_use]
    pub const fn head(&self) -> &Head {
        self.seq.head()
    }

    /// The fencing epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.seq.epoch()
    }

    /// The durability fence: nothing derived from a record leaves before it (OP-3).
    #[must_use]
    pub const fn fence(&self) -> &Fence {
        &self.fence
    }

    /// The ledger.
    #[must_use]
    pub const fn ledger(&self) -> &LedgerId {
        self.log.ledger()
    }

    /// Appends `records` as one batch at trusted time `now_ms` and returns the last position;
    /// it returns only after the batch is durable (OP-3, §17.1.1 steps 10–12).
    ///
    /// # Errors
    /// [`LedgerError::Refused`] leaves the leader in place; [`LedgerError::Failed`],
    /// [`LedgerError::Outcome`] and [`LedgerError::SteppedDown`] mean it must be acquired again.
    pub async fn commit(
        &mut self,
        now_ms: u64,
        records: &[PendingRecord],
    ) -> Result<u64, LedgerError> {
        let ledger = *self.log.ledger();
        let entries: Vec<Bound<'_>> = records
            .iter()
            .map(|record| Bound {
                ledger: &ledger,
                record,
            })
            .collect();
        commit(&mut self.seq, &mut self.fence, &self.log, now_ms, &entries)
            .await
            .map_err(|e| match e {
                CommitError::Plan(PlanError::SteppedDown | PlanError::InFlight) => {
                    LedgerError::SteppedDown
                }
                CommitError::Plan(PlanError::Size) => LedgerError::BatchSize,
                CommitError::Plan(PlanError::Overflow) => LedgerError::Head,
                CommitError::Plan(PlanError::Seal(e)) => LedgerError::Encode(e),
                CommitError::Refused(e) => LedgerError::Refused(e),
                CommitError::Failed(e) => LedgerError::Failed(e),
                CommitError::Outcome(_) | _ => LedgerError::Outcome,
            })
    }
}
