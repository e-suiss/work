//! The sequencer's storage (P-100, T-85, T-74, T-89, T-90, §18 OP-5, OP-10): opening a ledger
//! with its genesis record, taking leadership by bumping the epoch and reading the head with its
//! Merkle frontier, and appending a batch with the bytes each record was received as, its
//! skeleton, its item heads, outbox pointers, idempotency keys and inbound events under the head
//! compare-and-set, all as `work_sequencer` in one ledger-scoped transaction each. Values are
//! plain bytes and integers; the ledger crate converts them to and from the engine's types.

use std::collections::BTreeMap;

use sqlx::PgPool;

use crate::publisher::check_role;
use crate::{
    AppendError, BodyPartRow, CallerRef, IdempotencyKey, InboundRow, ItemRef, LedgerId, LedgerTx,
    ReceivedRow, Skeleton, StoreError, StoredKey,
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

/// A cell, the unit a ledger is led in (OP-9 item 4, C-35): 1 to 63 lower-case ASCII letters,
/// digits and hyphens, not starting with a hyphen.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellId(String);

impl CellId {
    /// The cell named `name`; `None` outside the form.
    #[must_use]
    pub fn new(name: &str) -> Option<Self> {
        let bytes = name.as_bytes();
        let first = bytes.first()?;
        let shaped = bytes.len() <= 63
            && *first != b'-'
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        shaped.then(|| Self(name.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The node asking to lead a ledger (T-85 item 4, OP-9 item 4, §17.12): the cell it runs in,
/// the process's lease holder and how long each lease it takes or renews lasts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    /// The cell the node runs in.
    pub cell: CellId,
    /// 16 random bytes drawn once per process.
    pub holder: [u8; 16],
    /// Lease length in milliseconds, at least 1.
    pub lease_ms: u64,
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
    /// The externally signed bytes the record came with, as received (T-90).
    pub received: Vec<ReceivedRow>,
    /// The skeleton of a decoded record; `None` for a record of a protocol version without a
    /// rule set, which is kept as bytes only (P-87).
    pub skeleton: Option<Skeleton>,
    /// The encrypted body parts the record came with (OP-45); none for a rebuild, which reads
    /// only the log.
    pub body: Vec<BodyPartRow>,
    /// Whether the entry is a version activation, whose record bytes are its envelope bytes
    /// and whose position the append also writes to `ledger.version_activation` (P-110 item 4).
    pub activation: bool,
}

impl std::fmt::Debug for LogRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogRow")
            .field("pos", &self.pos)
            .field("recorded_at_ms", &self.recorded_at_ms)
            .field("record_bytes", &self.record_bytes.len())
            .field("envelope_bytes", &self.envelope_bytes.len())
            .field("received", &self.received)
            .field("skeleton", &self.skeleton.is_some())
            .field("body", &self.body.len())
            .field("activation", &self.activation)
            .finish_non_exhaustive()
    }
}

/// An outbox pointer written with its record (T-17, T-81): its version is the one the same
/// batch writes to the item's head at the same position.
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

/// What the append expects of a stored item head (T-89, OP-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expect {
    /// The next version: the stored version plus one, or 1 for a new item; never refused.
    Next,
    /// The stored version, 0 for an item not stored yet; another one refuses the batch with
    /// [`StoreError::ItemConflict`].
    Version(u64),
}

/// The new head of one work item (P-29, T-89): its version is assigned in the append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemHeadRow {
    /// The item.
    pub item: ItemRef,
    /// What the stored head must be.
    pub expect: Expect,
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
    /// Inbound events the records answer.
    pub inbound: Vec<InboundRow>,
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

fn row_failure(e: StoreError) -> AppendError {
    match e {
        StoreError::Constraint(_) => AppendError::Refused(e),
        other => AppendError::Failed(other),
    }
}

fn log_failure(e: sqlx::Error) -> AppendError {
    let exists = db_code(&e).is_some_and(|(code, _, constraint)| {
        code == "23505" && constraint.as_deref() == Some("log_record_uq")
    });
    if exists {
        AppendError::Refused(StoreError::RecordExists)
    } else {
        AppendError::Failed(StoreError::Db(e))
    }
}

async fn insert_records(
    tx: &mut LedgerTx<'_>,
    epoch: i64,
    records: &[LogRow],
) -> Result<(), AppendError> {
    let id = *tx.ledger().as_bytes();
    let id = id.as_slice();
    for r in records {
        sqlx::query!(
            "INSERT INTO ledger.log
             (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes,
              envelope_bytes)
             VALUES ($1, $2, $3, $4,
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $5::bigint::double precision,
             $6, $7, $8, $9)",
            id,
            signed(r.pos).map_err(failed)?,
            epoch,
            r.record_id.as_slice(),
            signed(r.recorded_at_ms).map_err(failed)?,
            r.prev.as_slice(),
            r.leaf.as_slice(),
            r.record_bytes.as_slice(),
            r.envelope_bytes.as_slice()
        )
        .execute(tx.conn())
        .await
        .map_err(log_failure)?;
        if r.activation {
            sqlx::query!(
                "INSERT INTO ledger.version_activation (ledger_id, pos) VALUES ($1, $2)",
                id,
                signed(r.pos).map_err(failed)?
            )
            .execute(tx.conn())
            .await
            .map_err(failed)?;
        }
    }
    Ok(())
}

/// Whether `b` is a version activation written as a batch of its own: one entry whose record
/// bytes are its envelope bytes, with nothing beside its log row (P-110 item 5).
fn lone_activation(b: &AppendBatch) -> bool {
    match b.records.as_slice() {
        [r] => {
            r.record_bytes == r.envelope_bytes
                && r.received.is_empty()
                && r.skeleton.is_none()
                && r.body.is_empty()
                && b.items.is_empty()
                && b.outbox.is_empty()
                && b.keys.is_empty()
                && b.inbound.is_empty()
        }
        _ => false,
    }
}

/// The rows each record writes beside its log row, in the T-90 order: the bytes as received,
/// the skeleton, then the links from the record to its received bytes; then its encrypted body
/// parts and part keys (OP-45).
async fn insert_record_rows(tx: &mut LedgerTx<'_>, records: &[LogRow]) -> Result<(), AppendError> {
    for r in records {
        tx.insert_received(r.pos, &r.received)
            .await
            .map_err(row_failure)?;
    }
    for r in records {
        if let Some(s) = &r.skeleton {
            tx.insert_skeleton(r.pos, s).await.map_err(row_failure)?;
        }
    }
    for r in records {
        tx.link_received(r.pos, &r.received)
            .await
            .map_err(row_failure)?;
    }
    for r in records {
        tx.insert_body(r.pos, &r.body).await.map_err(row_failure)?;
    }
    Ok(())
}

/// The version each `(pos, item)` of the batch has after its record (T-81 item 1, T-89).
type Versions = BTreeMap<(u64, ItemRef), u64>;

/// Writes the item heads in batch order and returns the version each one has after its record:
/// [`Expect::Next`] takes the stored version plus one, or 1, and is never refused (T-89, OP-7);
/// [`Expect::Version`] is a compare-and-set refused with [`StoreError::ItemConflict`].
async fn write_items(
    tx: &mut LedgerTx<'_>,
    items: &[ItemHeadRow],
) -> Result<Versions, AppendError> {
    let id = *tx.ledger().as_bytes();
    let id = id.as_slice();
    let mut versions = Versions::new();
    for i in items {
        let last_pos = signed(i.last_pos).map_err(failed)?;
        let heads: Option<Vec<Vec<u8>>> = i
            .heads
            .as_ref()
            .map(|h| h.iter().map(|d| d.to_vec()).collect());
        let heads = heads.as_deref();
        let written = match i.expect {
            Expect::Next => {
                sqlx::query_scalar!(
                    r#"INSERT INTO work.item_head
                       (ledger_id, item_kind, item_id, version, last_pos, heads)
                       VALUES ($1, $2, $3, 1, $4, $5::bytea[]::ledger.digest32[])
                       ON CONFLICT ON CONSTRAINT item_head_pk DO UPDATE
                       SET version = work.item_head.version + 1, last_pos = EXCLUDED.last_pos,
                           heads = EXCLUDED.heads
                       RETURNING version AS "version!""#,
                    id,
                    i.item.kind(),
                    i.item.id(),
                    last_pos,
                    heads
                )
                .fetch_optional(tx.conn())
                .await
            }
            Expect::Version(0) => {
                sqlx::query_scalar!(
                    r#"INSERT INTO work.item_head
                       (ledger_id, item_kind, item_id, version, last_pos, heads)
                       VALUES ($1, $2, $3, 1, $4, $5::bytea[]::ledger.digest32[])
                       RETURNING version AS "version!""#,
                    id,
                    i.item.kind(),
                    i.item.id(),
                    last_pos,
                    heads
                )
                .fetch_optional(tx.conn())
                .await
            }
            Expect::Version(v) => {
                let stored = signed(v).map_err(failed)?;
                sqlx::query_scalar!(
                    r#"UPDATE work.item_head
                       SET version = version + 1, last_pos = $4,
                           heads = $5::bytea[]::ledger.digest32[]
                       WHERE ledger_id = $1 AND item_kind = $2 AND item_id = $3 AND version = $6
                       RETURNING version AS "version!""#,
                    id,
                    i.item.kind(),
                    i.item.id(),
                    last_pos,
                    heads,
                    stored
                )
                .fetch_optional(tx.conn())
                .await
            }
        }
        .map_err(|e| item_failure(e, i.item))?;
        let Some(version) = written else {
            return Err(AppendError::Refused(StoreError::ItemConflict(i.item)));
        };
        versions.insert((i.last_pos, i.item), unsigned(version).map_err(failed)?);
    }
    Ok(versions)
}

/// Takes the sequencer lease of the transaction's ledger for `seat` under `epoch`, unless
/// another holder's lease is live; whether it was taken (§17.12).
async fn take_lease(
    tx: &mut LedgerTx<'_>,
    seat: &Seat,
    epoch: i64,
    lease_ms: i64,
) -> Result<bool, StoreError> {
    let id = *tx.ledger().as_bytes();
    let leased = sqlx::query_scalar!(
        r#"INSERT INTO ledger.sequencer_lease AS l
               (ledger_id, holder, epoch, acquired_at, expires_at)
               VALUES ($1, $2, $3, pg_catalog.now(),
                       pg_catalog.now() + interval '1 millisecond' * $4::bigint::double precision)
               ON CONFLICT ON CONSTRAINT sequencer_lease_pk DO UPDATE
               SET holder = EXCLUDED.holder, epoch = EXCLUDED.epoch,
                   acquired_at = EXCLUDED.acquired_at, expires_at = EXCLUDED.expires_at,
                   released_at = NULL
               WHERE l.expires_at < pg_catalog.now() OR l.released_at IS NOT NULL
                  OR l.holder = EXCLUDED.holder
               RETURNING epoch AS "epoch!""#,
        id.as_slice(),
        seat.holder.as_slice(),
        epoch,
        lease_ms
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(leased.is_some())
}

async fn insert_outbox(
    tx: &mut LedgerTx<'_>,
    outbox: &[OutboxRow],
    written: &Versions,
) -> Result<(), AppendError> {
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
        event_ids.push(o.event_id.clone());
        event_types.push(o.event_type.clone());
        traces.push(o.traceparent.clone());
        kinds.push(o.item.kind().to_owned());
        items.push(o.item.id().to_vec());
        let version = written
            .get(&(o.pos, o.item))
            .ok_or(AppendError::Refused(StoreError::OutboxItem(o.item)))?;
        versions.push(signed(*version).map_err(failed)?);
    }
    sqlx::query!(
        "INSERT INTO ledger.outbox
         (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version)
         SELECT $1::bytea, u.pos, u.event_id, u.event_type, u.traceparent, u.item_kind,
                u.item_id, u.version
         FROM unnest($2::bigint[], $3::text[], $4::text[], $5::text[], $6::text[],
                     $7::bytea[], $8::bigint[])
              AS u(pos, event_id, event_type, traceparent, item_kind, item_id, version)",
        id.as_slice(),
        pos.as_slice(),
        event_ids.as_slice(),
        event_types.as_slice(),
        traces.as_slice(),
        kinds.as_slice(),
        items.as_slice(),
        versions.as_slice()
    )
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

    /// Opens the ledger of `g` in `cell` in one transaction (T-85 m.3, OP-9): the empty head at
    /// epoch 0, the cell that leads it, its placement directory entry, the durability profile,
    /// the genesis at position 0 as the ledger's first version activation (P-110 item 4), then
    /// the head at position 0 with the genesis leaf as its frontier. An empty ledger never
    /// commits.
    ///
    /// # Errors
    /// [`StoreError::AlreadyOpened`] if the ledger has a head, [`StoreError::Corrupt`] for a
    /// time beyond `bigint`, otherwise [`StoreError::Db`].
    pub async fn open_ledger(&self, g: &Genesis, cell: &CellId) -> Result<(), StoreError> {
        let id = g.ledger.as_bytes().as_slice();
        let at = signed(g.recorded_at_ms)?;
        let mut tx = self.begin(&g.ledger).await?;
        let inserted = sqlx::query!(
            "INSERT INTO ledger.head (ledger_id, pos, epoch, frontier) VALUES ($1, -1, 0, '\\x')",
            id
        )
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
        sqlx::query!(
            "INSERT INTO ledger.ledger_cell (ledger_id, cell) VALUES ($1, $2)",
            id,
            cell.as_str()
        )
        .execute(tx.conn())
        .await?;
        sqlx::query!(
            "INSERT INTO work.placement (ledger_id, cell) VALUES ($1, $2)",
            id,
            cell.as_str()
        )
        .execute(tx.conn())
        .await?;
        sqlx::query!(
            "INSERT INTO work.ledger_profile (ledger_id, durability_profile) VALUES ($1, $2)",
            id,
            g.durability.as_str()
        )
        .execute(tx.conn())
        .await?;
        sqlx::query!(
            "INSERT INTO ledger.log
             (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes,
              envelope_bytes)
             VALUES ($1::bytea, 0, 0, $1::bytea,
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $2::bigint::double precision,
             NULL, $3, $4::bytea, $4::bytea)",
            id,
            at,
            g.leaf.as_slice(),
            g.bytes.as_slice()
        )
        .execute(tx.conn())
        .await?;
        sqlx::query!(
            "INSERT INTO ledger.version_activation (ledger_id, pos) VALUES ($1, 0)",
            id
        )
        .execute(tx.conn())
        .await?;
        sqlx::query!(
            "UPDATE ledger.head SET pos = 0, head_leaf = $2::bytea,
             head_recorded_at = pg_catalog.to_timestamp(0)
               + interval '1 millisecond' * $3::bigint::double precision,
             frontier = $2::bytea
             WHERE ledger_id = $1 AND pos = -1 AND epoch = 0",
            id,
            g.leaf.as_slice(),
            at
        )
        .execute(tx.conn())
        .await?;
        tx.commit().await
    }

    /// Takes leadership of `ledger` for `seat` (T-85 m.4, OP-10, OP-9, OP-28 item 3, §17.12)
    /// in one transaction: locks the head, refuses a ledger led in another cell and a node that
    /// does not support the ledger's activation entries, the log bytes at the positions of
    /// `ledger.version_activation`, which `supports` is given in log order, the genesis first
    /// (P-110 item 7); takes the sequencer lease unless another holder's is live;
    /// then bumps the epoch, which fences the previous leader's next compare-and-set, and
    /// returns the head under the new epoch once the last log row matches it. On any refusal
    /// nothing is committed and the epoch stays.
    ///
    /// # Errors
    /// [`StoreError::NotOpened`], [`StoreError::Misrouted`], [`StoreError::Unsupported`],
    /// [`StoreError::LeaseHeld`], [`StoreError::Diverged`], [`StoreError::Corrupt`] for an
    /// out-of-range row, otherwise [`StoreError::Db`].
    pub async fn acquire(
        &self,
        ledger: &LedgerId,
        seat: &Seat,
        supports: impl FnOnce(&[Vec<u8>]) -> bool + Send,
    ) -> Result<StoredHead, StoreError> {
        let id = ledger.as_bytes().as_slice();
        let lease_ms = signed(seat.lease_ms)?;
        let mut tx = self.begin(ledger).await?;
        let locked = sqlx::query_scalar!(
            r#"SELECT epoch AS "epoch!" FROM ledger.head WHERE ledger_id = $1 FOR UPDATE"#,
            id
        )
        .fetch_optional(tx.conn())
        .await?;
        let Some(stored_epoch) = locked else {
            tx.rollback().await?;
            return Err(StoreError::NotOpened);
        };
        let cell = sqlx::query_scalar!(
            "SELECT cell FROM ledger.ledger_cell WHERE ledger_id = $1",
            id
        )
        .fetch_optional(tx.conn())
        .await?;
        if cell.as_deref() != Some(seat.cell.as_str()) {
            tx.rollback().await?;
            return Err(StoreError::Misrouted);
        }
        let activations = sqlx::query_scalar!(
            "SELECT l.record_bytes FROM ledger.version_activation v
             JOIN ledger.log l ON l.ledger_id = v.ledger_id AND l.pos = v.pos
             WHERE v.ledger_id = $1 ORDER BY v.pos",
            id
        )
        .fetch_all(tx.conn())
        .await?;
        if activations.is_empty() || !supports(&activations) {
            tx.rollback().await?;
            return Err(StoreError::Unsupported);
        }
        let epoch = stored_epoch.checked_add(1).ok_or(StoreError::Corrupt)?;
        let leased = take_lease(&mut tx, seat, epoch, lease_ms).await?;
        if !leased {
            tx.rollback().await?;
            return Err(StoreError::LeaseHeld);
        }
        let row = sqlx::query!(
            r#"UPDATE ledger.head SET epoch = $2 WHERE ledger_id = $1
               RETURNING epoch AS "epoch!", pos AS "pos!", head_leaf::bytea AS "leaf?",
                         (extract(epoch FROM head_recorded_at) * 1000)::bigint AS "at?",
                         frontier AS "frontier!""#,
            id,
            epoch
        )
        .fetch_optional(tx.conn())
        .await?;
        let Some((epoch, pos, Some(leaf), Some(at), frontier)) =
            row.map(|r| (r.epoch, r.pos, r.leaf, r.at, r.frontier))
        else {
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
        let last = sqlx::query!(
            r#"SELECT pos AS "pos!", leaf_hash::bytea AS "leaf!",
                      (extract(epoch FROM recorded_at) * 1000)::bigint AS "at!"
               FROM ledger.log WHERE ledger_id = $1 ORDER BY pos DESC LIMIT 1"#,
            id
        )
        .fetch_optional(tx.conn())
        .await?;
        let matches = match last {
            Some(l) => {
                unsigned(l.pos)? == head.pos
                    && digest(&l.leaf)? == head.leaf
                    && unsigned(l.at)? == head.recorded_at_ms
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

    /// Extends the lease `seat` holds on `ledger` under `epoch` by its lease length (§17.12).
    ///
    /// # Errors
    /// [`StoreError::LeaseLost`] when the lease expired, was released or was taken under a
    /// later epoch, otherwise [`StoreError::Db`].
    pub async fn renew(
        &self,
        ledger: &LedgerId,
        seat: &Seat,
        epoch: u64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin(ledger).await?;
        let renewed = sqlx::query!(
            "UPDATE ledger.sequencer_lease
             SET expires_at = pg_catalog.now()
               + interval '1 millisecond' * $4::bigint::double precision
             WHERE ledger_id = $1 AND holder = $2 AND epoch = $3 AND released_at IS NULL
               AND expires_at >= pg_catalog.now()",
            ledger.as_bytes().as_slice(),
            seat.holder.as_slice(),
            signed(epoch)?,
            signed(seat.lease_ms)?
        )
        .execute(tx.conn())
        .await?;
        if renewed.rows_affected() != 1 {
            tx.rollback().await?;
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await
    }

    /// Releases the lease `seat` holds on `ledger` under `epoch`, so the next node need not wait
    /// for it to expire (§17.12).
    ///
    /// # Errors
    /// [`StoreError::LeaseLost`] when the lease is no longer this one, otherwise
    /// [`StoreError::Db`].
    pub async fn release(
        &self,
        ledger: &LedgerId,
        seat: &Seat,
        epoch: u64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin(ledger).await?;
        let released = sqlx::query!(
            "UPDATE ledger.sequencer_lease SET released_at = pg_catalog.now()
             WHERE ledger_id = $1 AND holder = $2 AND epoch = $3 AND released_at IS NULL",
            ledger.as_bytes().as_slice(),
            seat.holder.as_slice(),
            signed(epoch)?
        )
        .execute(tx.conn())
        .await?;
        if released.rows_affected() != 1 {
            tx.rollback().await?;
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await
    }

    /// Appends `b` to `ledger` in one transaction (T-74 m.1, OP-5, T-90): locks the head and
    /// checks it is at `b.after` under `b.epoch`, inserts the log rows, the bytes each record was
    /// received as, the skeletons and the links to the received bytes, then the item heads, the
    /// outbox pointers with the versions those heads took, the idempotency keys and the inbound
    /// events, then moves the head with its frontier by compare-and-set. A version activation is
    /// a batch of its own, one log row and its `ledger.version_activation` position and nothing
    /// else (P-110 items 4, 5). It returns `Ok` only after the commit succeeded.
    ///
    /// The outcome maps as follows. [`AppendError::Refused`] means nothing was written and
    /// carries [`StoreError::ItemConflict`] when an [`Expect::Version`] head is not stored at
    /// that version (`23505` on `item_head_pk` for version 0) or the item guard rejects the
    /// step (`23514` with `item_version_not_monotonic` or `item_position_not_monotonic`);
    /// [`StoreError::KeyReused`] when the caller's idempotency key is already stored in a hot
    /// partition; [`StoreError::RecordExists`] for a record id already in the ledger;
    /// [`StoreError::InboundSeen`] for an inbound event already seen in a hot partition;
    /// [`StoreError::OutboxItem`] for a pointer whose item its record does not touch; and
    /// [`StoreError::Constraint`] for a received, skeleton or inbound row that breaks a
    /// constraint, such as a `proof_commit` without its received bytes, or `activation_alone`
    /// for an activation that is not the only entry of its batch. Since the head row is
    /// locked and checked first, none of these is about leadership. Everything else is
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
        if b.records.iter().any(|r| r.activation) && !lone_activation(b) {
            let refused = StoreError::Constraint("activation_alone".to_owned());
            return Err(AppendError::Refused(refused));
        }
        let mut tx = self.begin(ledger).await.map_err(failed)?;
        let locked = sqlx::query!(
            r#"SELECT pos AS "pos!", epoch AS "epoch!" FROM ledger.head
               WHERE ledger_id = $1 FOR UPDATE"#,
            id
        )
        .fetch_optional(tx.conn())
        .await
        .map_err(failed)?;
        match locked {
            None => return Err(failed(StoreError::NotOpened)),
            Some(h) if h.pos != after || h.epoch != epoch => {
                return Err(failed(StoreError::HeadMoved));
            }
            Some(_) => {}
        }
        insert_records(&mut tx, epoch, &b.records).await?;
        insert_record_rows(&mut tx, &b.records).await?;
        let versions = write_items(&mut tx, &b.items).await?;
        insert_outbox(&mut tx, &b.outbox, &versions).await?;
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
        for i in &b.inbound {
            if tx.inbound_seen(i).await.map_err(failed)? {
                return Err(AppendError::Refused(StoreError::InboundSeen));
            }
            tx.insert_inbound(i).await.map_err(row_failure)?;
        }
        let frontier = b.head.frontier.concat();
        let moved = sqlx::query!(
            "UPDATE ledger.head SET pos = $2, head_leaf = $3,
             head_recorded_at = pg_catalog.to_timestamp(0)
               + interval '1 millisecond' * $4::bigint::double precision,
             frontier = $5
             WHERE ledger_id = $1 AND pos = $6 AND epoch = $7",
            id,
            signed(b.head.pos).map_err(failed)?,
            b.head.leaf.as_slice(),
            signed(b.head.recorded_at_ms).map_err(failed)?,
            frontier.as_slice(),
            after,
            epoch
        )
        .execute(tx.conn())
        .await
        .map_err(failed)?;
        if moved.rows_affected() != 1 {
            return Err(failed(StoreError::HeadMoved));
        }
        tx.commit().await.map_err(AppendError::Failed)
    }
}
