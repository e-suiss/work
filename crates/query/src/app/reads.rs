//! The reads scoped to their caller (P-56, T-13, P-57, T-26, P-20, T-97 item 6): each runs in one read-only snapshot of one ledger's canonical rows, scoped by the caller's Party, so nothing is answered from a session, a cache or a connection; the item head it reads is sync-derived, written in the record's own transaction, so a read is never behind a write it follows and a `Work-Min-Position` is only checked against the head, never waited for. Every answer carries the head it reflects as its `Work-Position`.

use std::collections::BTreeMap;
use std::sync::Arc;

use work_access_client::ports::Clock;
use work_kernel::commitment_time::DEFINITION_PART;
use work_kernel::id::{Digest, LedgerId, RecordId, WorkId};
use work_kernel::proof::verify_inclusion;
use work_kernel::validate::ActorType;
use work_ledger::{BodyReader, PartRead};
use work_proto::id::{Cursor, PositionToken};
use work_proto::position::Positions;
use work_store::{LedgerTx, Pool, StoreError};

use crate::adapters::{OpenError, PositionKeys};
use crate::app::writes::log_of;
use crate::domain::caller::{Caller, CallerKind};
use crate::domain::commitments::{self, CommitmentRead, Evaluation, Folded, fold};
use crate::domain::reads::{
    Attestation, Change, Changes, CheckpointRef, CursorAt, Evidence, Inclusion, MAX_CHANGES,
    MAX_PROOF_LEAVES, Opened, ReadRefusal, WorkView, audit_path, compromise_marks,
};
use crate::domain::writes::header_kid;
use crate::domain::{PositionRefusal, check_heads};
use crate::ports::{Pending, WorkReads};

/// The reads over the canonical database, as `work_app`, with the read position keys.
pub struct Reads {
    pool: Pool,
    keys: Arc<PositionKeys>,
    clock: Option<Arc<dyn Clock>>,
    bodies: Option<Arc<BodyReader>>,
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
    /// Reads over `pool`, logged in as `work_app`, sealing positions and cursors with `keys`.
    #[must_use]
    pub const fn new(pool: Pool, keys: Arc<PositionKeys>) -> Self {
        Self {
            pool,
            keys,
            clock: None,
            bodies: None,
        }
    }

    /// The same reads opening the `definition` part of a commitment's clock, periodic and budget
    /// Conditions through `bodies`; without it every such Condition reads as undefined (CM-48,
    /// CM-50, CM-53).
    #[must_use]
    pub fn with_bodies(self, bodies: Arc<BodyReader>) -> Self {
        Self {
            bodies: Some(bodies),
            ..self
        }
    }

    /// The opened `definition` part of every time Condition the read of `root` needs; a part
    /// that is unreadable or redacted is left out, and its Condition reads as undefined.
    async fn definitions(
        &self,
        ledger: &LedgerId,
        folded: &Folded,
        root: &RecordId,
    ) -> Result<BTreeMap<RecordId, Vec<u8>>, ReadRefusal> {
        let mut out = BTreeMap::new();
        let Some(bodies) = &self.bodies else {
            return Ok(out);
        };
        let positions = folded
            .definition_positions(root)
            .map_err(|_| ReadRefusal::Unavailable)?;
        let now_ms = self.clock.as_ref().map_or(0, |c| c.now_ms());
        for (record, pos) in positions {
            let parts = bodies
                .read(&store_ledger(ledger), pos, now_ms)
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
        commitments::read(
            &folded,
            root,
            &party.reference,
            actor,
            self.position(caller, ledger, head)?,
            Evaluation {
                definitions: &definitions,
                now_ms: self.clock.as_ref().map_or(0, |c| c.now_ms()),
            },
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

    /// The evidence of `record` of `ledger`, each kind apart (P-20): the author signature only
    /// when the author signed it, the Access `auth_context` of an unsigned human record apart
    /// from it, the ledger's log entry, the audit path to the first checkpoint that covers it,
    /// checked before it is answered, and that checkpoint's witness cosignatures.
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
            Ok::<_, StoreError>(Some((row, notices, checkpoint, leaves)))
        }
        .await;
        let _closed = tx.rollback().await;
        let Some((row, notices, checkpoint, leaves)) = read? else {
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
}
