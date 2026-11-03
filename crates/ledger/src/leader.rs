use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use suiss_crypto::dcbor::EncodeError;
use suiss_ledger::fence::Fence;
use suiss_ledger::merkle::Frontier;
use suiss_ledger::port::{CommitError, commit};
use suiss_ledger::sequencer::{Entry, Head, PlanError, Sequencer};
use work_kernel::activation::Activation;
use work_kernel::id::Digest;
use work_kernel::record::ProtocolVersion;
use work_kernel::rules::RuleSet;
use work_store::{CellId, Genesis, LedgerId, SequencerPool, StoreError, StoredHead};

use crate::envelope::{Activating, ActivationRequest, Bound, SealedRecord};
use crate::ports::Store;
use crate::{LedgerError, Node, PendingRecord, PgLog};

/// The single writer of one ledger under one epoch (T-85 item 4, §18 OP-5, OP-10): every
/// committed batch advances the head and the durability fence; a failed commit steps it down,
/// and so does a lost sequencer lease, after which it commits nothing (§17.12). Batches go to
/// the `Store` port. It knows the protocol versions its node supports and the ledger's
/// activations, and writes a version activation only as a batch of its own (P-110).
#[derive(Debug)]
pub struct Leader<S = PgLog> {
    log: S,
    seq: Sequencer,
    fence: Fence,
    held: Arc<AtomicBool>,
    protocols: Vec<ProtocolVersion>,
    activations: Vec<Activation>,
}

fn commit_error(e: CommitError<EncodeError, StoreError>) -> LedgerError {
    match e {
        CommitError::Plan(PlanError::SteppedDown | PlanError::InFlight) => LedgerError::SteppedDown,
        CommitError::Plan(PlanError::Size) => LedgerError::BatchSize,
        CommitError::Plan(PlanError::Overflow) => LedgerError::Head,
        CommitError::Plan(PlanError::Seal(e)) => LedgerError::Encode(e),
        CommitError::Refused(e) => LedgerError::Refused(e),
        CommitError::Failed(e) => LedgerError::Failed(e),
        CommitError::Outcome(_) | _ => LedgerError::Outcome,
    }
}

/// The genesis activation a leader that never read its ledger's log assumes: protocol 1.0
/// with its own schema digest at position 0 (P-110 item 1).
fn opening_activation() -> Vec<Activation> {
    let set = RuleSet::V1_0;
    vec![Activation {
        position: 0,
        protocol: set.protocol(),
        schema: set.schema(),
    }]
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
    /// Opens a ledger with its genesis in one transaction, led in `cell` and placed there in
    /// the placement directory (P-100, T-85 item 3, OP-9).
    ///
    /// # Errors
    /// [`LedgerError::Store`]; `AlreadyOpened` for a second genesis of the same ledger.
    pub async fn open(
        pool: &SequencerPool,
        genesis: &Genesis,
        cell: &CellId,
    ) -> Result<(), LedgerError> {
        Ok(pool.open_ledger(genesis, cell).await?)
    }

    /// Takes `ledger` for `node` under a new epoch, which fences every earlier leader, and
    /// leads it from the stored head (T-85 item 4): only in the ledger's own cell, only when
    /// `node` supports the versions its log has activated and only while no other node holds
    /// a live sequencer lease on it (OP-9 item 5, OP-28 item 3, §17.12). A refusal leaves the
    /// epoch and the current leader as they were.
    ///
    /// # Errors
    /// [`LedgerError::Store`] (`NotOpened`, `Misrouted`, `Unsupported`, `LeaseHeld`,
    /// `Diverged`), or [`LedgerError::Head`].
    pub async fn acquire(
        pool: SequencerPool,
        ledger: LedgerId,
        node: &Node,
    ) -> Result<Self, LedgerError> {
        let mut found = Vec::new();
        let supports = |entries: &[Vec<u8>]| match node.activations(entries) {
            Some(list) => {
                found = list;
                true
            }
            None => false,
        };
        let stored = pool.acquire(&ledger, node.seat(), supports).await?;
        let epoch = stored.epoch;
        let head = head_of(stored)?;
        let mut leader = Self::lead(PgLog::new(pool, ledger), epoch, head);
        leader.protocols = node.protocols().to_vec();
        leader.activations = found;
        Ok(leader)
    }
}

impl<S: Store> Leader<S> {
    /// Leads the ledger of `log` under `epoch` from `head`, supporting the protocol versions
    /// this kernel carries rule sets for and assuming the ledger's only activation is a
    /// protocol 1.0 genesis.
    pub(crate) fn lead(log: S, epoch: u64, head: Head) -> Self {
        let fence = Fence::at(head.pos);
        Self {
            log,
            seq: Sequencer::lead(epoch, head),
            fence,
            held: Arc::new(AtomicBool::new(true)),
            protocols: RuleSet::ALL.iter().map(|r| r.protocol()).collect(),
            activations: opening_activation(),
        }
    }

    /// The ledger's activations in log order, the genesis first (P-110).
    #[must_use]
    pub fn activations(&self) -> &[Activation] {
        &self.activations
    }

    /// Activates `request` at trusted time `now_ms` as a batch of its own and returns its
    /// position (P-110 items 5, 6, OP-28 items 2, 3): the leader must still hold the ledger,
    /// its node must carry the version's rule set, the version must be above the active one,
    /// major then minor, and the schema must be the digest the kernel carries for it. Any
    /// refusal writes nothing and keeps the epoch; batches committed after it are evaluated
    /// under the new version.
    ///
    /// # Errors
    /// [`LedgerError::SteppedDown`], [`LedgerError::Store`] with [`StoreError::Unsupported`],
    /// [`LedgerError::ActivationNotNewer`], [`LedgerError::ActivationSchemaMismatch`], or an
    /// error of [`Leader::commit`].
    pub async fn activate(
        &mut self,
        now_ms: u64,
        request: &ActivationRequest,
    ) -> Result<u64, LedgerError> {
        if !self.held.load(Ordering::Acquire) {
            return Err(LedgerError::SteppedDown);
        }
        let set = RuleSet::for_version(request.protocol);
        if !self.protocols.contains(&request.protocol) || set.is_none() {
            return Err(LedgerError::Store(StoreError::Unsupported));
        }
        let newer = self
            .activations
            .last()
            .is_some_and(|a| request.protocol > a.protocol);
        if !newer {
            return Err(LedgerError::ActivationNotNewer);
        }
        let schema = Digest::sha256(request.schema);
        if set.is_none_or(|s| s.schema() != schema) {
            return Err(LedgerError::ActivationSchemaMismatch);
        }
        let ledger = *self.log.ledger();
        let entry = Activating {
            ledger: &ledger,
            request,
        };
        let pos = self.write(now_ms, &[entry]).await?;
        self.activations.push(Activation {
            position: pos,
            protocol: request.protocol,
            schema,
        });
        Ok(pos)
    }

    async fn write<E>(&mut self, now_ms: u64, entries: &[E]) -> Result<u64, LedgerError>
    where
        E: Entry<Sealed = SealedRecord, Error = EncodeError>,
    {
        commit(&mut self.seq, &mut self.fence, &self.log, now_ms, entries)
            .await
            .map_err(commit_error)
    }

    /// The flag that stays set while the leader may commit; clearing it steps the leader down
    /// before its next batch (§17.12).
    pub(crate) fn held(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.held)
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
    pub fn ledger(&self) -> &LedgerId {
        self.log.ledger()
    }

    /// Appends `records` as one batch at trusted time `now_ms` and returns the last position;
    /// it returns only after the batch is durable (OP-3, §17.1.1 steps 10–12).
    ///
    /// # Errors
    /// [`LedgerError::Refused`] leaves the leader in place; [`LedgerError::Failed`],
    /// [`LedgerError::Outcome`] and [`LedgerError::SteppedDown`] mean it must be acquired again.
    /// A leader whose lease was lost answers [`LedgerError::SteppedDown`] and writes nothing.
    pub async fn commit(
        &mut self,
        now_ms: u64,
        records: &[PendingRecord],
    ) -> Result<u64, LedgerError> {
        if !self.held.load(Ordering::Acquire) {
            return Err(LedgerError::SteppedDown);
        }
        let ledger = *self.log.ledger();
        let entries: Vec<Bound<'_>> = records
            .iter()
            .map(|record| Bound {
                ledger: &ledger,
                record,
            })
            .collect();
        self.write(now_ms, &entries).await
    }
}

impl<S> Drop for Leader<S> {
    fn drop(&mut self) {
        self.held.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use std::sync::Mutex;

    use suiss_crypto::dcbor::Value;
    use suiss_ledger::port::{AppendError, LogStore};
    use suiss_ledger::sequencer::Batch;
    use work_store::{Expect, ItemHeadRow, ItemRef};

    use super::*;
    use crate::ItemTouch;
    use crate::log::rows;

    #[derive(Debug)]
    struct Memory {
        ledger: LedgerId,
        refuse: bool,
        appended: Mutex<Vec<(u64, u64)>>,
        items: Mutex<Vec<ItemHeadRow>>,
        activations: Mutex<Vec<bool>>,
    }

    impl LogStore<SealedRecord> for Memory {
        type Error = StoreError;

        fn append(
            &self,
            batch: &Batch<SealedRecord>,
        ) -> impl Future<Output = Result<(), AppendError<StoreError>>> + Send {
            let answer = if self.refuse {
                Err(AppendError::Refused(StoreError::RecordExists))
            } else {
                self.appended
                    .lock()
                    .unwrap()
                    .push((batch.epoch, batch.head.pos));
                let written = rows(batch);
                let flags = written.records.iter().map(|r| r.activation);
                self.activations.lock().unwrap().extend(flags);
                self.items.lock().unwrap().extend(written.items);
                Ok(())
            };
            std::future::ready(answer)
        }
    }

    impl Store for Memory {
        fn ledger(&self) -> &LedgerId {
            &self.ledger
        }
    }

    fn memory(refuse: bool) -> Memory {
        Memory {
            ledger: LedgerId::from_bytes([3; 32]),
            refuse,
            appended: Mutex::new(Vec::new()),
            items: Mutex::new(Vec::new()),
            activations: Mutex::new(Vec::new()),
        }
    }

    fn genesis_head() -> Head {
        Head {
            pos: 0,
            leaf: [1; 32],
            recorded_at: 10,
            frontier: Frontier::from_parts(1, vec![[1; 32]]).unwrap(),
        }
    }

    fn record() -> PendingRecord {
        PendingRecord {
            record_bytes: b"record".to_vec(),
            actor_type: Value::Map(Vec::new()),
            proof_commit: None,
            auth_context: None,
            ingest: Value::text("admitted"),
            received: Vec::new(),
            skeleton: None,
            body: Vec::new(),
            items: Vec::new(),
            outbox: Vec::new(),
            idempotency: None,
            inbound: None,
            effective_at: None,
        }
    }

    // T-32 OP-5 OP-10
    #[tokio::test]
    async fn t_32_the_leader_commits_each_batch_through_the_store_port() {
        let mut leader = Leader::lead(memory(false), 4, genesis_head());
        assert_eq!(leader.ledger(), &LedgerId::from_bytes([3; 32]));
        assert_eq!(leader.commit(20, &[record(), record()]).await.unwrap(), 2);
        assert_eq!(leader.commit(30, &[record()]).await.unwrap(), 3);
        assert_eq!(leader.head().pos, 3);
        assert_eq!(*leader.log.appended.lock().unwrap(), [(4, 2), (4, 3)]);

        let mut refused = Leader::lead(memory(true), 4, genesis_head());
        assert!(matches!(
            refused.commit(20, &[record()]).await,
            Err(LedgerError::Refused(StoreError::RecordExists))
        ));
        assert_eq!(refused.head().pos, 0);
    }

    fn request(protocol: ProtocolVersion, schema: Digest) -> ActivationRequest {
        ActivationRequest {
            protocol,
            schema: *schema.as_bytes(),
            auth_context: [0x0c; 32],
            assurance: "aal3".to_owned(),
            step_up: true,
        }
    }

    // P-110 OP-28 T-85
    #[tokio::test]
    async fn p_110_an_activation_is_written_alone_only_when_newer_supported_and_of_its_schema() {
        let v0_9 = ProtocolVersion { major: 0, minor: 9 };
        let v1_0 = ProtocolVersion { major: 1, minor: 0 };
        let v1_1 = ProtocolVersion { major: 1, minor: 1 };
        let right = RuleSet::V1_0.schema();
        let wrong = Digest::sha256([0x0d; 32]);
        let mut leader = Leader::lead(memory(false), 4, genesis_head());
        assert!(matches!(
            leader.activate(20, &request(v1_0, right)).await,
            Err(LedgerError::ActivationNotNewer)
        ));
        leader.protocols.push(v1_1);
        assert!(matches!(
            leader.activate(20, &request(v1_1, wrong)).await,
            Err(LedgerError::Store(StoreError::Unsupported))
        ));
        leader.protocols = vec![v0_9, v1_0];
        leader.activations = vec![Activation {
            position: 0,
            protocol: v0_9,
            schema: wrong,
        }];
        assert!(matches!(
            leader.activate(20, &request(v1_0, wrong)).await,
            Err(LedgerError::ActivationSchemaMismatch)
        ));
        assert!(leader.log.appended.lock().unwrap().is_empty());
        assert_eq!(leader.head().pos, 0);
        assert_eq!(
            leader.activate(20, &request(v1_0, right)).await.unwrap(),
            1
        );
        assert_eq!(leader.activations().len(), 2);
        assert_eq!(leader.activations()[1].position, 1);
        assert!(matches!(
            leader.activate(30, &request(v1_0, right)).await,
            Err(LedgerError::ActivationNotNewer)
        ));
        assert_eq!(leader.commit(30, &[record()]).await.unwrap(), 2);
        assert_eq!(*leader.log.appended.lock().unwrap(), [(4, 1), (4, 2)]);
        assert_eq!(*leader.log.activations.lock().unwrap(), [true, false]);
        leader.held().store(false, Ordering::Release);
        assert!(matches!(
            leader.activate(40, &request(v1_1, wrong)).await,
            Err(LedgerError::SteppedDown)
        ));
        assert_eq!(leader.epoch(), 4);
    }

    // T-28 T-85 OP-10
    #[tokio::test]
    async fn t_28_a_leader_whose_lease_is_lost_commits_nothing() {
        let mut leader = Leader::lead(memory(false), 4, genesis_head());
        assert_eq!(leader.commit(20, &[record()]).await.unwrap(), 1);
        let held = leader.held();
        held.store(false, Ordering::Release);
        assert!(matches!(
            leader.commit(30, &[record()]).await,
            Err(LedgerError::SteppedDown)
        ));
        assert_eq!(leader.head().pos, 1);
        assert_eq!(*leader.log.appended.lock().unwrap(), [(4, 1)]);

        let other = Leader::lead(memory(false), 5, genesis_head());
        let flag = other.held();
        assert!(flag.load(Ordering::Acquire));
        drop(other);
        assert!(!flag.load(Ordering::Acquire));
    }

    // OP-7 T-89 T-81
    #[tokio::test]
    async fn op_7_each_touch_reaches_the_store_with_its_expectation_and_no_version() {
        let mut leader = Leader::lead(memory(false), 4, genesis_head());
        let work = ItemRef::Work([7; 16]);
        let commitment = ItemRef::Commitment([8; 32]);
        let mut touching = record();
        touching.record_bytes = b"touching".to_vec();
        touching.items = vec![
            ItemTouch {
                item: work,
                expect: Expect::Next,
                heads: None,
            },
            ItemTouch {
                item: commitment,
                expect: Expect::Version(3),
                heads: Some(vec![[9; 32]]),
            },
        ];
        assert_eq!(leader.commit(20, &[record(), touching]).await.unwrap(), 2);
        assert_eq!(
            *leader.log.items.lock().unwrap(),
            [
                ItemHeadRow {
                    item: work,
                    expect: Expect::Next,
                    last_pos: 2,
                    heads: None,
                },
                ItemHeadRow {
                    item: commitment,
                    expect: Expect::Version(3),
                    last_pos: 2,
                    heads: Some(vec![[9; 32]]),
                },
            ]
        );
    }
}
