//! The reads scoped to their caller (P-56, T-13, P-57, T-26, P-20, T-97 item 6): each runs in one read-only snapshot of one ledger's canonical rows, scoped by the caller's Party, so nothing is answered from a session, a cache or a connection; the item head it reads is sync-derived, written in the record's own transaction, so a read is never behind a write it follows and a `Work-Min-Position` is only checked against the head, never waited for. Every answer carries the head it reflects as its `Work-Position`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use work_access_client::ports::Clock;
use work_kernel::commitment_time::DEFINITION_PART;
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, WorkId};
use work_kernel::proof::verify_inclusion;
use work_kernel::validate::ActorType;
use work_ledger::{BodyError, PartRead};
use work_proto::id::{Cursor, PositionToken};
use work_proto::position::Positions;
use work_store::{LedgerTx, Pool, StoreError};

use crate::adapters::{OpenError, PositionKeys};
use crate::app::writes::log_of;
use crate::domain::caller::{Caller, CallerKind};
use crate::domain::commitments::{self, CommitmentRead, Evaluation, Folded, fold};
use crate::domain::reads::{
    Attestation, Change, Changes, CheckpointRef, CursorAt, DELIVERY_PAGE, Deliveries, Delivery,
    Evidence, Inclusion, MAX_CHANGES, MAX_DELIVERY_WAIT_S, MAX_PROOF_LEAVES, Opened, ReadRefusal,
    WorkView, audit_path, compromise_marks,
};
use crate::domain::responsibility::{self, QueueRead, WorkloadRead};
use crate::domain::writes::header_kid;
use crate::domain::{PositionRefusal, check_heads};
use crate::ports::{Bodies, Pending, WorkReads};

/// How often a delivery read that waits reads again (T-105).
pub const DELIVERY_POLL: Duration = Duration::from_millis(500);

/// The reads over the canonical database, as `work_app`, with the read position keys and the
/// body store.
pub struct Reads {
    pool: Pool,
    keys: Arc<PositionKeys>,
    bodies: Arc<dyn Bodies>,
    clock: Option<Arc<dyn Clock>>,
}

impl std::fmt::Debug for Reads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reads").finish_non_exhaustive()
    }
}

impl From<StoreError> for ReadRefusal {
    fn from(_: StoreError) -> Self {
        Self::Unavailable
    }
}

fn store_ledger(ledger: &LedgerId) -> work_store::LedgerId {
    work_store::LedgerId::from_bytes(*ledger.0.as_bytes())
}

impl Reads {
    /// Reads over `pool`, logged in as `work_app`, sealing positions and cursors with `keys`
    /// and opening body parts through `bodies` (OP-45).
    #[must_use]
    pub const fn new(pool: Pool, keys: Arc<PositionKeys>, bodies: Arc<dyn Bodies>) -> Self {
        Self {
            pool,
            keys,
            bodies,
            clock: None,
        }
    }

    /// The same reads evaluating the clocks, periodic updates and budgets of a commitment at
    /// `clock`'s now on ledger time; without one they are evaluated at the head's ledger time
    /// (CM-51).
    #[must_use]
    pub fn with_clock(self, clock: Arc<dyn Clock>) -> Self {
        Self {
            clock: Some(clock),
            ..self
        }
    }

    /// The opened `definition` part of every time Condition the read of `root` needs; a part
    /// that is unreadable or redacted is left out, and its Condition reads as undefined (CM-48,
    /// CM-50, CM-53).
    async fn definitions(
        &self,
        ledger: &LedgerId,
        folded: &Folded,
        root: &RecordId,
    ) -> Result<BTreeMap<RecordId, Vec<u8>>, ReadRefusal> {
        let positions = folded
            .definition_positions(root)
            .map_err(|_| ReadRefusal::Unavailable)?;
        self.open(ledger, positions).await
    }

    /// The opened `definition` part of each of `positions`; a part that is unreadable or
    /// redacted is left out.
    async fn open(
        &self,
        ledger: &LedgerId,
        positions: Vec<(RecordId, u64)>,
    ) -> Result<BTreeMap<RecordId, Vec<u8>>, ReadRefusal> {
        let mut out = BTreeMap::new();
        let now_ms = self.clock.as_ref().map_or(0, |c| c.now_ms());
        for (record, pos) in positions {
            let parts = self
                .parts(ledger, pos, now_ms)
                .await
                .map_err(|_| ReadRefusal::Unavailable)?;
            let opened = parts.into_iter().find_map(|(name, read)| match read {
                PartRead::Readable(o) if name == DEFINITION_PART => Some(o.content),
                PartRead::Readable(_) | PartRead::Unreadable => None,
            });
            if let Some(content) = opened {
                out.insert(record, content);
            }
        }
        Ok(out)
    }

    /// The body parts of the record at `pos` of `ledger` in part order at ledger time `now_ms`,
    /// each readable with its checked content or unreadable once its keys are gone (OP-45
    /// item 5, OP-13, OP-12 item 3); no caller scope applies, so the read and fold paths open
    /// only parts of records the caller may already read.
    ///
    /// # Errors
    /// [`BodyError`] for a part that does not open to its commitment or a store that failed.
    pub async fn parts(
        &self,
        ledger: &LedgerId,
        pos: u64,
        now_ms: u64,
    ) -> Result<Vec<(String, PartRead)>, BodyError> {
        self.bodies.parts(&store_ledger(ledger), pos, now_ms).await
    }

    async fn snapshot(&self, ledger: &LedgerId) -> Result<(LedgerTx<'static>, u64), ReadRefusal> {
        let mut tx = LedgerTx::begin_snapshot(&self.pool, &store_ledger(ledger)).await?;
        let head = tx.head().await?;
        let Some(head) = head else {
            let _closed = tx.rollback().await;
            return Err(ReadRefusal::NotFound);
        };
        Ok((tx, head.pos.unwrap_or_default()))
    }

    fn position(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        head: u64,
    ) -> Result<PositionToken, ReadRefusal> {
        let at = Positions::new([(*ledger, head)]).map_err(|_| ReadRefusal::Unavailable)?;
        self.keys
            .seal(&caller.tenant, &at)
            .map_err(|_| ReadRefusal::Unavailable)
    }

    fn check_min(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        head: u64,
        min: Option<&PositionToken>,
    ) -> Result<(), ReadRefusal> {
        let Some(token) = min else {
            return Ok(());
        };
        let wanted = self
            .keys
            .open_token(&caller.tenant, token)
            .map_err(|e| match e {
                OpenError::Refused(_) => ReadRefusal::PositionInvalid,
                OpenError::Key(_) => ReadRefusal::Unavailable,
            })?;
        check_heads(&wanted, &BTreeMap::from([(*ledger, Some(head))])).map_err(|r| match r {
            PositionRefusal::Invalid => ReadRefusal::PositionInvalid,
            PositionRefusal::Ahead => ReadRefusal::PositionAhead,
        })
    }

    /// `work` of `ledger` as `caller` may read it (P-56, T-13).
    ///
    /// # Errors
    /// [`ReadRefusal`].
    pub async fn read_work(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        work: &WorkId,
        min: Option<&PositionToken>,
    ) -> Result<WorkView, ReadRefusal> {
        let party = caller.party().map_err(|_| ReadRefusal::NotFound)?;
        let (mut tx, head) = self.snapshot(ledger).await?;
        let row = tx
            .visible_work(work.as_bytes(), party.reference.as_str())
            .await
            .map_err(ReadRefusal::from);
        let _closed = tx.rollback().await;
        self.check_min(caller, ledger, head, min)?;
        let row = row?.ok_or(ReadRefusal::NotFound)?;
        Ok(WorkView {
            ledger: *ledger,
            work: *work,
            version: row.version,
            first_pos: row.first_pos,
            last_pos: row.last_pos,
            opened_at_ms: row.opened_at_ms,
            updated_at_ms: row.updated_at_ms,
            position: self.position(caller, ledger, head)?,
        })
    }

    /// The commitment of `ledger` its `request` `root` opened, as `caller` may read it: derived
    /// by the kernel from the records in one snapshot, with the transitions the caller may make
    /// now and who holds the next move (CM-2, CM-19, P-55, P-56, CM-58).
    ///
    /// # Errors
    /// [`ReadRefusal`].
    pub async fn read_commitment(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        root: &RecordId,
        min: Option<&PositionToken>,
    ) -> Result<CommitmentRead, ReadRefusal> {
        let party = caller.party().map_err(|_| ReadRefusal::NotFound)?;
        let (mut tx, head) = self.snapshot(ledger).await?;
        let log = log_of(&mut tx).await.map_err(ReadRefusal::from);
        let _closed = tx.rollback().await;
        self.check_min(caller, ledger, head, min)?;
        let folded = fold(ledger, &log?).map_err(|_| ReadRefusal::Unavailable)?;
        let actor = match caller.kind {
            CallerKind::User => ActorType::Human,
            CallerKind::Service => ActorType::Agent,
        };
        let definitions = self.definitions(ledger, &folded, root).await?;
        let wanted = folded
            .control_positions(root, &party.reference)
            .map_err(|_| ReadRefusal::Unavailable)?;
        let control = self.open(ledger, wanted).await?;
        commitments::read(
            &folded,
            root,
            &party.reference,
            actor,
            self.position(caller, ledger, head)?,
            Evaluation {
                definitions: &definitions,
                control: &control,
                now_ms: self.clock.as_ref().map_or(0, |c| c.now_ms()),
            },
        )
    }

    async fn folded(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        min: Option<&PositionToken>,
    ) -> Result<(Folded, u64), ReadRefusal> {
        let (mut tx, head) = self.snapshot(ledger).await?;
        let log = log_of(&mut tx).await.map_err(ReadRefusal::from);
        let _closed = tx.rollback().await;
        self.check_min(caller, ledger, head, min)?;
        let folded = fold(ledger, &log?).map_err(|_| ReadRefusal::Unavailable)?;
        Ok((folded, head))
    }

    /// The queue `queue` of `ledger` as `caller` may read it: its definition versions, its open
    /// work with each one's assignment and the candidates over its WIP limit, derived by the
    /// kernel from the records in one snapshot (RC-10…RC-14, RC-24).
    ///
    /// # Errors
    /// [`ReadRefusal`].
    pub async fn read_queue(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        queue: &RecordId,
        min: Option<&PositionToken>,
    ) -> Result<QueueRead, ReadRefusal> {
        let party = caller.party().map_err(|_| ReadRefusal::NotFound)?;
        let (folded, head) = self.folded(caller, ledger, min).await?;
        responsibility::queue(
            &folded,
            queue,
            &party.reference,
            self.position(caller, ledger, head)?,
        )
    }

    /// The open workload of `party` in `ledger` as `caller` may read it (RC-24).
    ///
    /// # Errors
    /// [`ReadRefusal`].
    pub async fn read_workload(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        party: &PartyRef,
        min: Option<&PositionToken>,
    ) -> Result<WorkloadRead, ReadRefusal> {
        let asking = caller.party().map_err(|_| ReadRefusal::NotFound)?;
        let (folded, head) = self.folded(caller, ledger, min).await?;
        responsibility::party_workload(
            &folded,
            party,
            &asking.reference,
            self.position(caller, ledger, head)?,
        )
    }

    /// The Works of `ledger` visible to `caller` changed after `cursor`, at most `limit` (P-57,
    /// T-26): a cursor whose key was retired, or whose position is past the head, answers
    /// `resync` with no change, so the client reads every Work again and nothing is missed.
    ///
    /// # Errors
    /// [`ReadRefusal`].
    pub async fn read_changes(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        cursor: Option<&Cursor>,
        limit: u32,
    ) -> Result<Changes, ReadRefusal> {
        let party = caller
            .party()
            .map_err(|_| ReadRefusal::NotFound)?
            .reference
            .as_str();
        let ledger_bytes = *ledger.0.as_bytes();
        let opened = cursor
            .map(|c| self.keys.open_cursor(&caller.tenant, party, c))
            .transpose()?;
        let after = match opened {
            Some(Opened::At(at)) if at.ledger != ledger_bytes => {
                return Err(ReadRefusal::CursorInvalid);
            }
            Some(Opened::At(at)) => Some(at),
            Some(Opened::Expired) | None => None,
        };
        let limit = limit.clamp(1, MAX_CHANGES);
        let (mut tx, head) = self.snapshot(ledger).await?;
        let seal = |at: &CursorAt| {
            self.keys
                .seal_cursor(&caller.tenant, party, at)
                .map_err(|_| ReadRefusal::Unavailable)
        };
        let end = CursorAt {
            ledger: ledger_bytes,
            pos: head,
            work: [0xff; 16],
        };
        let expired = matches!(opened, Some(Opened::Expired));
        if expired || after.is_some_and(|at| at.pos > head) {
            let _closed = tx.rollback().await;
            return Ok(Changes {
                changes: Vec::new(),
                next: seal(&CursorAt {
                    pos: 0,
                    work: [0; 16],
                    ..end
                })?,
                more: false,
                resync: true,
                position: self.position(caller, ledger, head)?,
            });
        }
        let rows = tx
            .visible_changes(
                after.map(|at| (at.pos, at.work)),
                limit.saturating_add(1),
                party,
            )
            .await
            .map_err(ReadRefusal::from);
        let _closed = tx.rollback().await;
        let mut rows = rows?;
        let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        let next = match rows.last() {
            Some(last) if more => CursorAt {
                ledger: ledger_bytes,
                pos: last.last_pos,
                work: last.work,
            },
            _ => end,
        };
        Ok(Changes {
            changes: rows
                .into_iter()
                .map(|r| Change {
                    work: WorkId::from_bytes(r.work),
                    version: r.version,
                    pos: r.last_pos,
                })
                .collect(),
            next: seal(&next)?,
            more,
            resync: false,
            position: self.position(caller, ledger, head)?,
        })
    }

    /// The deliveries of `ledger` addressed to `caller` after the sequence number `after`, at
    /// most [`DELIVERY_PAGE`], oldest first (RC-42, T-105, E-39): each pass reads one snapshot;
    /// with none, the read polls every [`DELIVERY_POLL`] until one is committed or `wait_s`
    /// seconds, at most [`MAX_DELIVERY_WAIT_S`], pass. A caller sees only its own deliveries.
    ///
    /// # Errors
    /// [`ReadRefusal::NotFound`] for no such ledger or a caller that names no Party,
    /// [`ReadRefusal::Unavailable`] when the database cannot be read.
    pub async fn read_deliveries(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        after: u64,
        wait_s: u32,
    ) -> Result<Deliveries, ReadRefusal> {
        let party = caller.party().map_err(|_| ReadRefusal::NotFound)?;
        let now = tokio::time::Instant::now;
        let deadline = now()
            .checked_add(Duration::from_secs(u64::from(
                wait_s.min(MAX_DELIVERY_WAIT_S),
            )))
            .unwrap_or_else(now);
        loop {
            let (mut tx, _) = self.snapshot(ledger).await?;
            let read = tx
                .executor_deliveries(party.reference.as_str(), after, DELIVERY_PAGE)
                .await;
            let _closed = tx.rollback().await;
            let deliveries: Vec<Delivery> = read?
                .into_iter()
                .map(|d| Delivery {
                    seq: d.seq,
                    kind: d.row.kind.as_str(),
                    commitment: RecordId(Digest::sha256(d.row.commitment)),
                    record: RecordId(Digest::sha256(d.record)),
                    body: d.row.body,
                    at_ms: d.issued_at_ms,
                })
                .collect();
            if !deliveries.is_empty() || now() >= deadline {
                let cursor = deliveries.last().map_or(after, |d| d.seq);
                return Ok(Deliveries { deliveries, cursor });
            }
            let next = now().checked_add(DELIVERY_POLL).unwrap_or(deadline);
            tokio::time::sleep_until(deadline.min(next)).await;
        }
    }

    /// The evidence of `record` of `ledger`, each kind apart (P-20): the author signature only
    /// when the author signed it, the Access `auth_context` of an unsigned human record apart
    /// from it, the ledger's log entry, the audit path to the first checkpoint that covers it,
    /// checked before it is answered, and that checkpoint's witness cosignatures; and the first action report relying on it (OP-4).
    ///
    /// # Errors
    /// [`ReadRefusal`].
    pub async fn read_evidence(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        record: &RecordId,
    ) -> Result<Evidence, ReadRefusal> {
        let party = caller.party().map_err(|_| ReadRefusal::NotFound)?;
        let (mut tx, head) = self.snapshot(ledger).await?;
        let read = async {
            let Some(row) = tx
                .visible_record(record.0.as_bytes(), party.reference.as_str())
                .await?
            else {
                return Ok(None);
            };
            let notices = tx.notices_at(row.recorded_at_ms).await?;
            let checkpoint = tx.covering_checkpoint(row.pos).await?;
            let leaves = match &checkpoint {
                Some(c) if c.size <= MAX_PROOF_LEAVES => Some(tx.leaf_hashes(c.size).await?),
                _ => None,
            };
            let acted = tx.acted_upon(record.0.as_bytes()).await?;
            Ok::<_, StoreError>(Some((row, notices, checkpoint, leaves, acted)))
        }
        .await;
        let _closed = tx.rollback().await;
        let Some((row, notices, checkpoint, leaves, acted)) = read? else {
            return Err(ReadRefusal::NotFound);
        };
        let leaf_hash = Digest::sha256(row.leaf_hash);
        let (inclusion, witnesses) = match checkpoint {
            None => (Inclusion::Pending, Vec::new()),
            Some(c) => {
                let checkpoint = CheckpointRef {
                    size: c.size,
                    root: Digest::sha256(c.root),
                    signed_note: String::from_utf8(c.signed_note)
                        .map_err(|_| ReadRefusal::Unavailable)?,
                    issued_at_ms: c.issued_at_ms,
                };
                let inclusion = match leaves {
                    Some(leaves) => {
                        let leaves: Vec<Digest> = leaves.into_iter().map(Digest::sha256).collect();
                        let index =
                            usize::try_from(row.pos).map_err(|_| ReadRefusal::Unavailable)?;
                        let path = audit_path(index, &leaves).ok_or(ReadRefusal::Unavailable)?;
                        verify_inclusion(row.pos, c.size, &leaf_hash, &path, &checkpoint.root)
                            .map_err(|_| ReadRefusal::Unavailable)?;
                        Inclusion::Proven { checkpoint, path }
                    }
                    None => Inclusion::Covered { checkpoint },
                };
                (inclusion, c.cosignatures)
            }
        };
        let kid = row.author_signature.as_deref().and_then(header_kid);
        let compromise_window = compromise_marks(row.recorded_at_ms, kid, &row.author, &notices);
        Ok(Evidence {
            ledger: *ledger,
            record: *record,
            author: row.author,
            author_signature: row.author_signature,
            auth_context: row.auth_context_ref.map(Digest::sha256),
            attestation: Attestation {
                pos: row.pos,
                epoch: row.epoch,
                recorded_at_ms: row.recorded_at_ms,
                leaf_hash,
            },
            inclusion,
            witnesses,
            compromise_window,
            acted_upon: acted.map(|r| RecordId(Digest::sha256(r))),
            position: self.position(caller, ledger, head)?,
        })
    }
}

impl WorkReads for Reads {
    fn work<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        work: &'a WorkId,
        min: Option<&'a PositionToken>,
    ) -> Pending<'a, Result<WorkView, ReadRefusal>> {
        Box::pin(self.read_work(caller, ledger, work, min))
    }

    fn changes<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        cursor: Option<&'a Cursor>,
        limit: u32,
    ) -> Pending<'a, Result<Changes, ReadRefusal>> {
        Box::pin(self.read_changes(caller, ledger, cursor, limit))
    }

    fn evidence<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        record: &'a RecordId,
    ) -> Pending<'a, Result<Evidence, ReadRefusal>> {
        Box::pin(self.read_evidence(caller, ledger, record))
    }

    fn commitment<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        root: &'a RecordId,
        min: Option<&'a PositionToken>,
    ) -> Pending<'a, Result<CommitmentRead, ReadRefusal>> {
        Box::pin(self.read_commitment(caller, ledger, root, min))
    }

    fn deliveries<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        after: u64,
        wait_s: u32,
    ) -> Pending<'a, Result<Deliveries, ReadRefusal>> {
        Box::pin(self.read_deliveries(caller, ledger, after, wait_s))
    }

    fn queue<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        queue: &'a RecordId,
        min: Option<&'a PositionToken>,
    ) -> Pending<'a, Result<QueueRead, ReadRefusal>> {
        Box::pin(self.read_queue(caller, ledger, queue, min))
    }

    fn workload<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        party: &'a PartyRef,
        min: Option<&'a PositionToken>,
    ) -> Pending<'a, Result<WorkloadRead, ReadRefusal>> {
        Box::pin(self.read_workload(caller, ledger, party, min))
    }
}
