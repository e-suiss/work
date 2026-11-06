//! The rebuild of a ledger's rows from its canonical log and the rebuild-diff (§18 OP-1 items 2 and 3, T-10, T-11, T-37 item 3, T-89): every stored entry is read back from the log with the bytes it was received as, the kernel decodes its envelope and record, and the admission path's own mapping turns them into the pending record the live append wrote; a leader appends them into an empty target database through the same store code, so the head, Work roots, skeleton rows and item heads are reconstructed without reading any of them; a version activation is replayed through the leader as a batch of its own, which writes its `ledger.version_activation` row again (P-110 item 4). [`rebuild_diff`] reads the live rows at one state, rebuilds through that state's head and compares; any difference is a sev-1 signal and the log decides. Outbox pointers, idempotency keys and inbound events carry what the request said rather than what the record says, so they are not replayed; the keys and events are checked against the log row they answer, and the pointers, a delivery queue whose rows leave on publication, are not compared. The body store's rows (ciphertexts, part keys, class DEKs, tombstones) are canonical beside the log but are not written in it, so a rebuild writes none of them and the diff does not compare them (OP-2, OP-45).

use suiss_crypto::dcbor::Value;
use suiss_crypto::digest::{leaf_hash, sha256};
use work_kernel::codec::{Decoded, decode_record, record_id};
use work_kernel::envelope::{AuthContextRef, Envelope, EnvelopeIngest, decode_envelope};
use work_kernel::items;
use work_store::{
    CanonicalEntry, CanonicalLog, Durability, Genesis, LedgerId, LedgerTx, Pool, RebuildDiff,
    SequencerPool, StoreError, diff,
};

use crate::admit::{Binding, actor_types, auth_context_value, ingest, skeleton, touch};
use crate::{ActivationRequest, Leader, LedgerError, Node, PendingRecord};

/// Entries read from the log at a time; at most the engine's batch ceiling, since one page's
/// entries of one ledger time are appended as one batch.
pub const REBUILD_PAGE: u32 = 256;

/// Why a rebuild stopped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RebuildError {
    /// A store operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The entry at position 0 is not the genesis of the ledger (P-100).
    #[error("the stored genesis does not open the ledger")]
    Genesis,
    /// The stored entry does not decode to a record of the ledger at its position (P-11).
    #[error("stored entry {0} does not decode to a record of the ledger")]
    Entry(u64),
    /// The log has no entry at the position, or the live head is behind it.
    #[error("the log has no entry at position {0}")]
    Gap(u64),
    /// The target refused or failed the append of the batch starting at `pos`; a target that
    /// already holds the ledger fails at position 0 (T-85).
    #[error("the replay of position {pos} failed: {source}")]
    Replay {
        /// The first position of the batch.
        pos: u64,
        /// What the leader said.
        #[source]
        source: LedgerError,
    },
}

/// The genesis of `ledger` from its stored entry, opened with `durability` (P-100, OP-27).
fn opening(
    ledger: &LedgerId,
    e: &CanonicalEntry,
    durability: Durability,
) -> Result<Genesis, RebuildError> {
    let Ok(Envelope::Genesis(g)) = decode_envelope(&e.record_bytes) else {
        return Err(RebuildError::Genesis);
    };
    if e.pos != 0
        || sha256(&e.record_bytes) != *ledger.as_bytes()
        || e.envelope_bytes != e.record_bytes
        || g.recorded_at.0 != e.recorded_at_ms
    {
        return Err(RebuildError::Genesis);
    }
    Ok(Genesis {
        ledger: *ledger,
        recorded_at_ms: e.recorded_at_ms,
        leaf: leaf_hash(&e.record_bytes),
        bytes: e.record_bytes.clone(),
        durability,
    })
}

/// The envelope `auth_context` value of `a` (P-21).
fn context(a: &AuthContextRef) -> Value {
    auth_context_value(a.reference.as_bytes(), a.step_up, &a.assurance)
}

/// The pending record a stored entry of `ledger` was appended from, built from the stored bytes
/// alone by the kernel and the admission mapping (T-89, T-90, P-11, P-87): the envelope gives
/// the actor types, the author binding and the ingest, the record its skeleton and touched
/// items. It carries no outbox pointer, idempotency key or inbound event.
pub(crate) fn replayed(
    ledger: &LedgerId,
    e: &CanonicalEntry,
) -> Result<PendingRecord, RebuildError> {
    let bad = || RebuildError::Entry(e.pos);
    let Ok(Envelope::Ledger(env)) = decode_envelope(&e.envelope_bytes) else {
        return Err(bad());
    };
    if env.position != e.pos
        || env.ledger.0.as_bytes() != ledger.as_bytes()
        || env.record != record_id(&e.record_bytes)
        || env.recorded_at.0 != e.recorded_at_ms
    {
        return Err(bad());
    }
    let quarantine = match env.ingest {
        EnvelopeIngest::Admitted => None,
        EnvelopeIngest::Quarantined(q) => Some(q.to_string()),
        EnvelopeIngest::Rejected(_) => return Err(bad()),
    };
    let binding = Binding {
        proof_commit: env.proof_commit.map(|d| *d.as_bytes()),
        auth_context_ref: env.auth_context.as_ref().map(|a| *a.reference.as_bytes()),
    };
    let (skeleton, touches, effective_at) = match decode_record(&e.record_bytes) {
        Ok(Decoded::Record(record)) => {
            let touches = items::touched(&record)
                .iter()
                .map(touch)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| bad())?;
            let s = skeleton(&record, &env.actor_types, quarantine.clone(), binding);
            (Some(s), touches, record.effective_at().map(|t| t.0))
        }
        Ok(Decoded::UnknownProtocol(_)) => (None, Vec::new(), None),
        Err(_) => return Err(bad()),
    };
    Ok(PendingRecord {
        record_bytes: e.record_bytes.clone(),
        actor_type: actor_types(&env.actor_types),
        proof_commit: binding.proof_commit,
        auth_context: env.auth_context.as_ref().map(context),
        ingest: ingest(quarantine.as_deref()),
        received: e.received.clone(),
        skeleton,
        body: Vec::new(),
        items: touches,
        outbox: Vec::new(),
        idempotency: None,
        inbound: None,
        effective_at,
        kid: None,
        tenant: None,
    })
}

/// Rebuilds `ledger` through position `through` from `live` into `target`, a canonical
/// database that does not hold the ledger yet (§18 OP-1 item 3): opens it with the stored
/// genesis and `durability` in the cell of `node`, takes it as `node` and appends every stored entry in position
/// order through the store's append, the entries of one page and one ledger time as one batch.
/// It reads nothing but the canonical log and returns the head position reached.
///
/// # Errors
/// [`RebuildError`].
pub async fn rebuild(
    live: &CanonicalLog,
    target: SequencerPool,
    node: &Node,
    ledger: LedgerId,
    durability: Durability,
    through: u64,
) -> Result<u64, RebuildError> {
    let replay = |pos: u64| move |source: LedgerError| RebuildError::Replay { pos, source };
    let first = live.entries(&ledger, 0, 1).await?;
    let opened = opening(
        &ledger,
        first.first().ok_or(RebuildError::Gap(0))?,
        durability,
    )?;
    Leader::open(&target, &opened, node.cell())
        .await
        .map_err(replay(0))?;
    let mut leader = Leader::acquire(target, ledger, node)
        .await
        .map_err(replay(0))?;
    let mut next: u64 = 1;
    while next <= through {
        let page = live.entries(&ledger, next, REBUILD_PAGE).await?;
        if page.is_empty() {
            return Err(RebuildError::Gap(next));
        }
        let page: Vec<CanonicalEntry> = page.into_iter().filter(|e| e.pos <= through).collect();
        for batch in page.chunk_by(|a, b| a.recorded_at_ms == b.recorded_at_ms) {
            let at = batch.first().map_or(0, |e| e.recorded_at_ms);
            let mut start = next;
            let mut records = Vec::with_capacity(batch.len());
            for e in batch {
                if e.pos != next {
                    return Err(RebuildError::Gap(next));
                }
                next = next.checked_add(1).ok_or(RebuildError::Gap(next))?;
                let Some(request) = activation_of(&ledger, e)? else {
                    records.push(replayed(&ledger, e)?);
                    continue;
                };
                if !records.is_empty() {
                    leader.commit(at, &records).await.map_err(replay(start))?;
                    records.clear();
                }
                leader.activate(at, &request).await.map_err(replay(e.pos))?;
                start = next;
            }
            if !records.is_empty() {
                leader.commit(at, &records).await.map_err(replay(start))?;
            }
        }
    }
    Ok(leader.head().pos)
}

/// The activation a stored entry of `ledger` was written from, read from its bytes alone
/// (P-110 items 4, 8); `None` for a record entry.
fn activation_of(
    ledger: &LedgerId,
    e: &CanonicalEntry,
) -> Result<Option<ActivationRequest>, RebuildError> {
    let Ok(Envelope::Activation(a)) = decode_envelope(&e.envelope_bytes) else {
        return Ok(None);
    };
    if a.position != e.pos
        || a.ledger.0.as_bytes() != ledger.as_bytes()
        || a.recorded_at.0 != e.recorded_at_ms
        || e.record_bytes != e.envelope_bytes
        || !e.received.is_empty()
    {
        return Err(RebuildError::Entry(e.pos));
    }
    Ok(Some(ActivationRequest {
        protocol: a.activation.protocol,
        schema: *a.activation.schema.as_bytes(),
        auth_context: *a.auth_context.reference.as_bytes(),
        assurance: a.auth_context.assurance,
        step_up: a.auth_context.step_up,
    }))
}

/// The rebuild-diff of `ledger` (§18 OP-1 item 3, T-37 item 3, T-89): reads the live rows on
/// `live`, a pool logged in as `work_app`, at one state, rebuilds the ledger through that
/// state's head into `target` as `node`, as [`rebuild`] does, and compares the target's rows
/// with the live ones; the idempotency keys and inbound events are checked against the log. A
/// difference is logged as the sev-1 `ledger.rebuild_diff` event and returned; the live rows
/// are then wrong.
///
/// # Errors
/// [`RebuildError`]; [`StoreError::NotOpened`] when the live ledger has no head.
pub async fn rebuild_diff(
    live: &Pool,
    target: &SequencerPool,
    node: &Node,
    ledger: LedgerId,
    durability: Durability,
) -> Result<RebuildDiff, RebuildError> {
    let log = CanonicalLog::new(live.clone()).await?;
    let mut tx = LedgerTx::begin_snapshot(live, &ledger).await?;
    let through = tx
        .head()
        .await?
        .and_then(|h| h.pos)
        .ok_or(StoreError::NotOpened)?;
    let live_rows = tx.snapshot().await?;
    let mismatches = tx.log_mismatches().await?;
    tx.rollback().await?;
    let reached = rebuild(&log, target.clone(), node, ledger, durability, through).await?;
    if reached != through {
        return Err(RebuildError::Gap(reached));
    }
    let mut tx = target.begin(&ledger).await?;
    let rebuilt_rows = tx.snapshot().await?;
    tx.rollback().await?;
    let mut tables = diff(&live_rows, &rebuilt_rows);
    tables.extend(mismatches);
    let outcome = RebuildDiff::new(ledger, through, tables);
    if !outcome.is_clean() {
        let names: Vec<&str> = outcome.tables().iter().map(|t| t.table).collect();
        tracing::error!(
            event = "ledger.rebuild_diff",
            severity = "sev-1",
            ledger = %ledger.to_hex(),
            through,
            tables = %names.join(","),
            rows = outcome.rows(),
            "rebuilt rows differ from the live rows; the log is the arbiter"
        );
    }
    Ok(outcome)
}
