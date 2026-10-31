//! The sequencer's storage (P-100, T-85, T-74, §18 OP-5, OP-10): opening a ledger with its
//! genesis record, taking leadership by bumping the epoch and reading the head with its Merkle
//! frontier, and appending a batch with its item heads and outbox pointers under the head
//! compare-and-set, all as `work_sequencer` in one ledger-scoped transaction each. Values are
//! plain bytes and integers; the ledger crate converts them to and from the engine's types.

use sqlx::PgPool;

use crate::publisher::check_role;
use crate::{
    AppendError, CallerRef, IdempotencyKey, ItemRef, LedgerId, LedgerTx, StoreError, StoredKey,
};

/// The login role a [`SequencerPool`] must have.
pub const SEQUENCER_ROLE: &str = "work_sequencer";

/// The durability profile a ledger is opened with (OP-27).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Durability {
    /// Commit waits for a synchronous standby quorum.
    Quorum,
    /// Commit is durable on one node.
    SingleNode,
}

impl Durability {
    /// The stored `durability_profile`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Quorum => "quorum",
            Self::SingleNode => "single-node",
        }
    }
}

/// The genesis record of a ledger (P-100): position 0, no author and no `prev`; the ledger id
/// is the SHA-256 of `bytes`, and the record id equals it.
#[derive(Clone, PartialEq, Eq)]
pub struct Genesis {
    /// The ledger id, the digest of `bytes`.
    pub ledger: LedgerId,
    /// Ledger time, Unix milliseconds.
    pub recorded_at_ms: u64,
    /// Leaf hash of the genesis envelope.
    pub leaf: [u8; 32],
    /// The genesis deterministic CBOR, stored as both record and envelope bytes.
    pub bytes: Vec<u8>,
    /// Durability profile of the ledger.
    pub durability: Durability,
}

impl std::fmt::Debug for Genesis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Genesis")
            .field("ledger", &self.ledger)
            .field("recorded_at_ms", &self.recorded_at_ms)
            .field("bytes", &self.bytes.len())
            .field("durability", &self.durability)
            .finish_non_exhaustive()
    }
}

/// The head a new leader starts from (T-85 m.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHead {
    /// The epoch just taken.
    pub epoch: u64,
    /// Position of the last record.
    pub pos: u64,
    /// Its leaf hash.
    pub leaf: [u8; 32],
    /// Its ledger time, Unix milliseconds.
    pub recorded_at_ms: u64,
    /// Merkle frontier over positions `0..=pos`: right-edge subtree roots, largest first.
    pub frontier: Vec<[u8; 32]>,
}

/// One record of a batch; never the genesis, so `prev` is always present.
#[derive(Clone, PartialEq, Eq)]
pub struct LogRow {
    /// Log position.
    pub pos: u64,
    /// Record digest.
    pub record_id: [u8; 32],
    /// Ledger time, Unix milliseconds.
    pub recorded_at_ms: u64,
    /// Leaf hash of the previous record.
    pub prev: [u8; 32],
    /// Leaf hash of this record.
    pub leaf: [u8; 32],
    /// Canonical record bytes (deterministic CBOR).
    pub record_bytes: Vec<u8>,
    /// Ledger envelope bytes.
    pub envelope_bytes: Vec<u8>,
}

impl std::fmt::Debug for LogRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogRow")
            .field("pos", &self.pos)
            .field("recorded_at_ms", &self.recorded_at_ms)
            .field("record_bytes", &self.record_bytes.len())
            .field("envelope_bytes", &self.envelope_bytes.len())
            .finish_non_exhaustive()
    }
}

/// An outbox pointer written with its record (T-17, T-81).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// Log position of the record.
    pub pos: u64,
    /// CloudEvents `id` (§15 P-35).
    pub event_id: String,
    /// Catalogued event type (§15 P-38).
    pub event_type: String,
    /// W3C trace context of the committing request (§15 P-42).
    pub traceparent: String,
    /// The work item the event is about.
    pub item: ItemRef,
    /// The item's version after the record.
    pub version: u64,
}

/// An idempotency key written with the record it first produced (OP-8, OP-36 item 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    /// The caller the key belongs to.
    pub caller: CallerRef,
    /// The key.
    pub key: IdempotencyKey,
    /// The request digest and its first result.
    pub stored: StoredKey,
}

/// The new head of one work item (P-29): inserted at version 1, otherwise the stored row at
/// `version - 1` is advanced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemHeadRow {
    /// The item.
    pub item: ItemRef,
    /// Its version after the batch.
    pub version: u64,
    /// Position of its last record.
    pub last_pos: u64,
    /// Current heads of a Commitment or Condition; `None` for a Work.
    pub heads: Option<Vec<[u8; 32]>>,
}

/// The head after a batch commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewHead {
    /// Position of the last record of the batch.
    pub pos: u64,
    /// Its leaf hash.
    pub leaf: [u8; 32],
    /// Its ledger time, Unix milliseconds.
    pub recorded_at_ms: u64,
    /// Merkle frontier over positions `0..=pos`, largest subtree first.
    pub frontier: Vec<[u8; 32]>,
}

/// One planned batch: it commits only if the stored head is still at `after` under `epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendBatch {
    /// Leader epoch.
    pub epoch: u64,
    /// Head position the batch extends.
    pub after: u64,
    /// The records, in position order.
    pub records: Vec<LogRow>,
    /// Item heads the records advance.
    pub items: Vec<ItemHeadRow>,
    /// Outbox pointers of the records.
    pub outbox: Vec<OutboxRow>,
    /// Idempotency keys of the requests the records answer.
    pub keys: Vec<KeyRow>,
    /// The head after the batch.
    pub head: NewHead,
}

/// The sequencer's pool, logged in as `work_sequencer`. It is not an executor; its statements
/// run only through its methods, each in a [`LedgerTx`], so an unscoped query does not compile:
///
/// ```compile_fail
/// # async fn f(p: &work_store::SequencerPool) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SequencerPool {
    pool: PgPool,
}

type AcquiredRow = (i64, i64, Option<Vec<u8>>, Option<i64>, Vec<u8>);
type LastRow = (i64, Vec<u8>, i64);

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn digest(raw: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(raw).map_err(|_| StoreError::Corrupt)
}

fn frontier_of(raw: &[u8], pos: u64) -> Result<Vec<[u8; 32]>, StoreError> {
    let (nodes, rest) = raw.as_chunks::<32>();
    if !rest.is_empty() {
        return Err(StoreError::Corrupt);
    }
    let nodes = nodes.to_vec();
    let size = pos.checked_add(1).ok_or(StoreError::Corrupt)?;
    if usize::try_from(size.count_ones()).ok() != Some(nodes.len()) {
        return Err(StoreError::Corrupt);
    }
    Ok(nodes)
}

fn db_code(e: &sqlx::Error) -> Option<(String, String, Option<String>)> {
    e.as_database_error().map(|d| {
        (
            d.code()
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_default(),
            d.message().to_owned(),
            d.constraint().map(str::to_owned),
        )
    })
}

fn item_failure(e: sqlx::Error, item: ItemRef) -> AppendError {
    let conflict = db_code(&e).is_some_and(|(code, message, constraint)| {
        (code == "23505" && constraint.as_deref() == Some("item_head_pk"))
            || (code == "23514"
                && matches!(
                    message.as_str(),
                    "item_version_not_monotonic" | "item_position_not_monotonic"
                ))
    });
    if conflict {
        AppendError::Refused(StoreError::ItemConflict(item))
    } else {
        AppendError::Failed(StoreError::Db(e))
    }
}

fn key_failure(e: StoreError) -> AppendError {
    let reused = match &e {
        StoreError::Db(db) => db_code(db).is_some_and(|(code, _, constraint)| {
            code == "23505"
                && constraint
                    .as_deref()
                    .is_some_and(|c| c.starts_with("idempotency_key"))
        }),
        _ => false,
    };
    if reused {
        AppendError::Refused(StoreError::KeyReused)
    } else {
        AppendError::Failed(e)
    }
}

fn failed(e: impl Into<StoreError>) -> AppendError {
    AppendError::Failed(e.into())
}

async fn insert_records(
    tx: &mut LedgerTx<'_>,
    epoch: i64,
    records: &[LogRow],
) -> Result<(), AppendError> {
    let id = *tx.ledger().as_bytes();
    let id = id.as_slice();
    for r in records {
        sqlx::query(
            "INSERT INTO ledger.log \
             (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes, \
              envelope_bytes) \
             VALUES ($1, $2, $3, $4, \
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $5::bigint::double precision, \
             $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(signed(r.pos).map_err(failed)?)
        .bind(epoch)
        .bind(r.record_id.as_slice())
        .bind(signed(r.recorded_at_ms).map_err(failed)?)
        .bind(r.prev.as_slice())
        .bind(r.leaf.as_slice())
        .bind(r.record_bytes.as_slice())
        .bind(r.envelope_bytes.as_slice())
        .execute(tx.conn())
        .await
        .map_err(failed)?;
    }
    Ok(())
}

async fn write_items(tx: &mut LedgerTx<'_>, items: &[ItemHeadRow]) -> Result<(), AppendError> {
    let id = *tx.ledger().as_bytes();
    let id = id.as_slice();
    for i in items {
        let version = signed(i.version).map_err(failed)?;
        let last_pos = signed(i.last_pos).map_err(failed)?;
        let heads: Option<Vec<Vec<u8>>> = i
            .heads
            .as_ref()
            .map(|h| h.iter().map(|d| d.to_vec()).collect());
        if i.version == 1 {
            sqlx::query(
                "INSERT INTO work.item_head \
                 (ledger_id, item_kind, item_id, version, last_pos, heads) \
                 VALUES ($1, $2, $3, $4, $5, $6::bytea[]::ledger.digest32[])",
            )
            .bind(id)
            .bind(i.item.kind())
            .bind(i.item.id())
            .bind(version)
            .bind(last_pos)
            .bind(heads)
            .execute(tx.conn())
            .await
            .map_err(|e| item_failure(e, i.item))?;
        } else {
            let prev = version
                .checked_sub(1)
                .ok_or_else(|| failed(StoreError::Corrupt))?;
            let done = sqlx::query(
                "UPDATE work.item_head \
                 SET version = $4, last_pos = $5, heads = $6::bytea[]::ledger.digest32[] \
                 WHERE ledger_id = $1 AND item_kind = $2 AND item_id = $3 AND version = $7",
            )
            .bind(id)
            .bind(i.item.kind())
            .bind(i.item.id())
            .bind(version)
            .bind(last_pos)
            .bind(heads)
            .bind(prev)
            .execute(tx.conn())
            .await
            .map_err(|e| item_failure(e, i.item))?;
            if done.rows_affected() != 1 {
                return Err(AppendError::Refused(StoreError::ItemConflict(i.item)));
            }
        }
    }
    Ok(())
}

async fn insert_outbox(tx: &mut LedgerTx<'_>, outbox: &[OutboxRow]) -> Result<(), AppendError> {
    if outbox.is_empty() {
        return Ok(());
    }
    let id = *tx.ledger().as_bytes();
    let mut pos = Vec::with_capacity(outbox.len());
    let mut event_ids = Vec::with_capacity(outbox.len());
    let mut event_types = Vec::with_capacity(outbox.len());
    let mut traces = Vec::with_capacity(outbox.len());
    let mut kinds = Vec::with_capacity(outbox.len());
    let mut items = Vec::with_capacity(outbox.len());
    let mut versions = Vec::with_capacity(outbox.len());
    for o in outbox {
        pos.push(signed(o.pos).map_err(failed)?);
        event_ids.push(o.event_id.as_str());
        event_types.push(o.event_type.as_str());
        traces.push(o.traceparent.as_str());
        kinds.push(o.item.kind());
        items.push(o.item.id());
        versions.push(signed(o.version).map_err(failed)?);
    }
    sqlx::query(
        "INSERT INTO ledger.outbox \
         (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version) \
         SELECT $1, u.pos, u.event_id, u.event_type, u.traceparent, u.item_kind, \
                u.item_id, u.version \
         FROM unnest($2::bigint[], $3::text[], $4::text[], $5::text[], $6::text[], \
                     $7::bytea[], $8::bigint[]) \
              AS u(pos, event_id, event_type, traceparent, item_kind, item_id, version)",
    )
    .bind(id.as_slice())
    .bind(pos)
    .bind(event_ids)
    .bind(event_types)
    .bind(traces)
    .bind(kinds)
    .bind(items)
    .bind(versions)
    .execute(tx.conn())
    .await
    .map_err(failed)?;
    Ok(())
}

impl SequencerPool {
    /// Over `pool` after checking that its role is `work_sequencer` or holds its privileges.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        check_role(&pool, SEQUENCER_ROLE).await?;
        Ok(Self { pool })
    }

    /// Opens a transaction scoped to `ledger`.
    ///
    /// # Errors
    /// See [`LedgerTx::begin`].
    pub async fn begin(&self, ledger: &LedgerId) -> Result<LedgerTx<'static>, StoreError> {
        LedgerTx::begin(&self.pool, ledger).await
    }

    /// Opens the ledger of `g` in one transaction (T-85 m.3): the empty head at epoch 0, the
    /// durability profile, the genesis at position 0, then the head at position 0 with the
    /// genesis leaf as its frontier. An empty ledger never commits.
    ///
    /// # Errors
    /// [`StoreError::AlreadyOpened`] if the ledger has a head, [`StoreError::Corrupt`] for a
    /// time beyond `bigint`, otherwise [`StoreError::Db`].
    pub async fn open_ledger(&self, g: &Genesis) -> Result<(), StoreError> {
        let id = g.ledger.as_bytes().as_slice();
        let at = signed(g.recorded_at_ms)?;
        let mut tx = self.begin(&g.ledger).await?;
        let inserted = sqlx::query(
            "INSERT INTO ledger.head (ledger_id, pos, epoch, frontier) VALUES ($1, -1, 0, '\\x')",
        )
        .bind(id)
        .execute(tx.conn())
        .await;
        if let Err(e) = inserted {
            let opened = db_code(&e).is_some_and(|(code, _, constraint)| {
                code == "23505" && constraint.as_deref() == Some("head_pk")
            });
            return Err(if opened {
                StoreError::AlreadyOpened
            } else {
                StoreError::Db(e)
            });
        }
        sqlx::query(
            "INSERT INTO work.ledger_profile (ledger_id, durability_profile) VALUES ($1, $2)",
        )
        .bind(id)
        .bind(g.durability.as_str())
        .execute(tx.conn())
        .await?;
        sqlx::query(
            "INSERT INTO ledger.log \
             (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes, \
              envelope_bytes) \
             VALUES ($1, 0, 0, $1, \
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $2::bigint::double precision, \
             NULL, $3, $4, $4)",
        )
        .bind(id)
        .bind(at)
        .bind(g.leaf.as_slice())
        .bind(g.bytes.as_slice())
        .execute(tx.conn())
        .await?;
        sqlx::query(
            "UPDATE ledger.head SET pos = 0, head_leaf = $2, \
             head_recorded_at = pg_catalog.to_timestamp(0) \
               + interval '1 millisecond' * $3::bigint::double precision, \
             frontier = $2 \
             WHERE ledger_id = $1 AND pos = -1 AND epoch = 0",
        )
        .bind(id)
        .bind(g.leaf.as_slice())
        .bind(at)
        .execute(tx.conn())
        .await?;
        tx.commit().await
    }

    /// Takes leadership of `ledger` (T-85 m.4, OP-10): bumps the epoch, which fences the
    /// previous leader's next compare-and-set, and returns the head under the new epoch once
    /// the last log row matches it. On a mismatch nothing is committed.
    ///
    /// # Errors
    /// [`StoreError::NotOpened`], [`StoreError::Diverged`], [`StoreError::Corrupt`] for an
    /// out-of-range row, otherwise [`StoreError::Db`].
    pub async fn acquire(&self, ledger: &LedgerId) -> Result<StoredHead, StoreError> {
        let id = ledger.as_bytes().as_slice();
        let mut tx = self.begin(ledger).await?;
        let row: Option<AcquiredRow> = sqlx::query_as(
            "UPDATE ledger.head SET epoch = epoch + 1 WHERE ledger_id = $1 \
             RETURNING epoch, pos, head_leaf::bytea, \
             (extract(epoch FROM head_recorded_at) * 1000)::bigint, frontier",
        )
        .bind(id)
        .fetch_optional(tx.conn())
        .await?;
        let Some((epoch, pos, Some(leaf), Some(at), frontier)) = row else {
            tx.rollback().await?;
            return Err(StoreError::NotOpened);
        };
        let pos = unsigned(pos)?;
        let head = StoredHead {
            epoch: unsigned(epoch)?,
            pos,
            leaf: digest(&leaf)?,
            recorded_at_ms: unsigned(at)?,
            frontier: frontier_of(&frontier, pos)?,
        };
        let last: Option<LastRow> = sqlx::query_as(
            "SELECT pos, leaf_hash::bytea, (extract(epoch FROM recorded_at) * 1000)::bigint \
             FROM ledger.log WHERE ledger_id = $1 ORDER BY pos DESC LIMIT 1",
        )
        .bind(id)
        .fetch_optional(tx.conn())
        .await?;
        let matches = match last {
            Some((p, l, t)) => {
                unsigned(p)? == head.pos
                    && digest(&l)? == head.leaf
                    && unsigned(t)? == head.recorded_at_ms
            }
            None => false,
        };
        if !matches {
            tx.rollback().await?;
            return Err(StoreError::Diverged);
        }
        tx.commit().await?;
        Ok(head)
    }

    /// Appends `b` to `ledger` in one transaction (T-74 m.1, OP-5): locks the head and checks
    /// it is at `b.after` under `b.epoch`, inserts the records, the item heads and the outbox
    /// pointers, then moves the head with its frontier by compare-and-set. It returns `Ok` only
    /// after the commit succeeded.
    ///
    /// The outcome maps as follows. [`AppendError::Refused`] carries
    /// [`StoreError::ItemConflict`] and means nothing was written: an item at version 1
    /// already exists (`23505` on `item_head_pk`), an item to advance is not stored at
    /// `version - 1`, or the item guard rejects the step (`23514` with
    /// `item_version_not_monotonic` or `item_position_not_monotonic`); it carries
    /// [`StoreError::KeyReused`] when the caller's idempotency key is already stored in a hot
    /// partition. Since the head row is locked and checked first, none of these is about
    /// leadership. Everything else is
    /// [`AppendError::Failed`]: [`StoreError::NotOpened`], [`StoreError::HeadMoved`] when the
    /// head is not at `b.after` under `b.epoch`, [`StoreError::Corrupt`] for a value beyond
    /// `bigint`, and [`StoreError::Db`] for any other database error, including a failed or
    /// interrupted `COMMIT` whose outcome is unknown.
    ///
    /// # Errors
    /// [`AppendError`], as above.
    pub async fn append(&self, ledger: &LedgerId, b: &AppendBatch) -> Result<(), AppendError> {
        let id = ledger.as_bytes().as_slice();
        let epoch = signed(b.epoch).map_err(failed)?;
        let after = signed(b.after).map_err(failed)?;
        let mut tx = self.begin(ledger).await.map_err(failed)?;
        let locked: Option<(i64, i64)> =
            sqlx::query_as("SELECT pos, epoch FROM ledger.head WHERE ledger_id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(tx.conn())
                .await
                .map_err(failed)?;
        match locked {
            None => return Err(failed(StoreError::NotOpened)),
            Some((p, e)) if p != after || e != epoch => {
                return Err(failed(StoreError::HeadMoved));
            }
            Some(_) => {}
        }
        insert_records(&mut tx, epoch, &b.records).await?;
        write_items(&mut tx, &b.items).await?;
        insert_outbox(&mut tx, &b.outbox).await?;
        for k in &b.keys {
            if tx
                .idempotency_key(&k.caller, &k.key)
                .await
                .map_err(failed)?
                .is_some()
            {
                return Err(AppendError::Refused(StoreError::KeyReused));
            }
            tx.insert_idempotency_key(&k.caller, &k.key, &k.stored)
                .await
                .map_err(key_failure)?;
        }
        let moved = sqlx::query(
            "UPDATE ledger.head SET pos = $2, head_leaf = $3, \
             head_recorded_at = pg_catalog.to_timestamp(0) \
               + interval '1 millisecond' * $4::bigint::double precision, \
             frontier = $5 \
             WHERE ledger_id = $1 AND pos = $6 AND epoch = $7",
        )
        .bind(id)
        .bind(signed(b.head.pos).map_err(failed)?)
        .bind(b.head.leaf.as_slice())
        .bind(signed(b.head.recorded_at_ms).map_err(failed)?)
        .bind(b.head.frontier.concat())
        .bind(after)
        .bind(epoch)
        .execute(tx.conn())
        .await
        .map_err(failed)?;
        if moved.rows_affected() != 1 {
            return Err(failed(StoreError::HeadMoved));
        }
        tx.commit().await.map_err(AppendError::Failed)
    }
}
