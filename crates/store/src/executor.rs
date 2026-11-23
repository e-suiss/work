//! The executor coordination rows (RC-41, RC-42, RC-43, T-105, E-39, SEC-15, OP-4, OP-47): the sequencer writes one `work.executor_delivery` row for each commitment or request a record delivers to the executor assigned to the work, numbered by a sequence that only grows per ledger, and one `work.single_use` row for each action report, binding its authority context to its idempotency key, both in the same transaction as the record. The executor pulls its deliveries in sequence order; the doorbell worker, as `work_publisher`, discovers the ledgers with doorbells due through the `SECURITY DEFINER` function `work.executor_delivery_ledgers` and settles each row's doorbell as rung or unrouted, or moves its next attempt. Rows are never removed.

use crate::skeleton::refused;
use crate::{DiscoveryPool, LedgerId, LedgerTx, PublisherRole, StoreError};

/// What a delivery carries (RC-42).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryKind {
    /// A `commitment-delivery` body: the commitment is bound to the executor.
    Commitment,
    /// A `request` body: a stop, a control change, a resume or a change.
    Request,
}

impl DeliveryKind {
    /// The stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Commitment => "commitment",
            Self::Request => "request",
        }
    }

    /// The kind of a stored name.
    #[must_use]
    pub fn from_stored(name: &str) -> Option<Self> {
        match name {
            "commitment" => Some(Self::Commitment),
            "request" => Some(Self::Request),
            _ => None,
        }
    }
}

/// One delivery the sequencer writes beside its record (RC-42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorDeliveryRow {
    /// The executor Party it is addressed to, its `PartyRef`.
    pub addressee: String,
    /// What it carries.
    pub kind: DeliveryKind,
    /// The commitment, by the digest of its `request`.
    pub commitment: [u8; 32],
    /// The `work/control/1` body, deterministic CBOR.
    pub body: Vec<u8>,
}

/// The binding an action report writes beside its record (SEC-15, OP-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleUseRow {
    /// The digest of the single-use authority context.
    pub authority: [u8; 32],
    /// The idempotency key it binds.
    pub key: String,
    /// The records the report relies on, ascending.
    pub relies_on: Vec<[u8; 32]>,
}

/// A stored binding of an authority context to an idempotency key (SEC-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedRow {
    /// The digest of the authority context.
    pub authority: [u8; 32],
    /// The idempotency key.
    pub key: String,
    /// The position of the action report that bound them.
    pub pos: u64,
    /// Its record id.
    pub record: [u8; 32],
}

/// Where a delivery's doorbell stands (E-39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Doorbell {
    /// Not yet rung; tried again at `next_attempt_ms`.
    Pending {
        /// When it is next due, Unix milliseconds.
        next_attempt_ms: u64,
        /// The code of the last failed attempt.
        last_error: Option<String>,
    },
    /// The addressee's webhook answered.
    Rung {
        /// When, Unix milliseconds.
        at_ms: u64,
    },
    /// No webhook is configured for the addressee; it pulls.
    Unrouted {
        /// When, Unix milliseconds.
        at_ms: u64,
    },
}

/// A stored delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorDelivery {
    /// Its sequence number in the ledger.
    pub seq: u64,
    /// The log position of the record that caused it.
    pub pos: u64,
    /// That record's id.
    pub record: [u8; 32],
    /// What it carries, to whom, for which commitment.
    pub row: ExecutorDeliveryRow,
    /// The record's ledger time, Unix milliseconds.
    pub issued_at_ms: u64,
    /// The doorbell attempts made.
    pub attempts: u64,
    /// Where its doorbell stands.
    pub doorbell: Doorbell,
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn fixed<const N: usize>(raw: &[u8]) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(raw).map_err(|_| StoreError::Corrupt)
}

struct Raw {
    seq: i64,
    pos: i64,
    record_id: Vec<u8>,
    addressee: String,
    kind: String,
    commitment: Vec<u8>,
    body: Vec<u8>,
    issued_at_ms: i64,
    doorbell: String,
    attempts: i64,
    next_attempt_ms: i64,
    last_error: Option<String>,
    settled_ms: Option<i64>,
}

impl TryFrom<Raw> for ExecutorDelivery {
    type Error = StoreError;

    fn try_from(r: Raw) -> Result<Self, StoreError> {
        let settled = || unsigned(r.settled_ms.ok_or(StoreError::Corrupt)?);
        let doorbell = match r.doorbell.as_str() {
            "pending" => Doorbell::Pending {
                next_attempt_ms: unsigned(r.next_attempt_ms)?,
                last_error: r.last_error,
            },
            "rung" => Doorbell::Rung { at_ms: settled()? },
            "unrouted" => Doorbell::Unrouted { at_ms: settled()? },
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Self {
            seq: unsigned(r.seq)?,
            pos: unsigned(r.pos)?,
            record: fixed(&r.record_id)?,
            row: ExecutorDeliveryRow {
                addressee: r.addressee,
                kind: DeliveryKind::from_stored(&r.kind).ok_or(StoreError::Corrupt)?,
                commitment: fixed(&r.commitment)?,
                body: r.body,
            },
            issued_at_ms: unsigned(r.issued_at_ms)?,
            attempts: unsigned(r.attempts)?,
            doorbell,
        })
    }
}

impl LedgerTx<'_> {
    /// Writes the deliveries and the binding of the record at `pos`, issued at its ledger time
    /// `recorded_at_ms`, each delivery numbered after the last one of the ledger and its
    /// doorbell due at once (RC-42, SEC-15).
    pub(crate) async fn insert_executor(
        &mut self,
        pos: u64,
        record_id: &[u8; 32],
        recorded_at_ms: u64,
        deliveries: &[ExecutorDeliveryRow],
        single_use: Option<&SingleUseRow>,
    ) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        for d in deliveries {
            sqlx::query!(
                "INSERT INTO work.executor_delivery
                 (ledger_id, seq, pos, record_id, addressee, kind, commitment, body, issued_at,
                  doorbell, attempts, next_attempt_at)
                 SELECT $1, COALESCE(MAX(e.seq), 0) + 1, $2, $3, $4, $5, $6, $7,
                  pg_catalog.to_timestamp(0) + interval '1 millisecond' * $8::bigint::double precision,
                  'pending', 0,
                  pg_catalog.to_timestamp(0) + interval '1 millisecond' * $8::bigint::double precision
                 FROM work.executor_delivery e WHERE e.ledger_id = $1",
                ledger.as_slice(),
                signed(pos)?,
                record_id.as_slice(),
                d.addressee.as_str(),
                d.kind.as_str(),
                d.commitment.as_slice(),
                d.body.as_slice(),
                signed(recorded_at_ms)?
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        if let Some(u) = single_use {
            let relies: Vec<Vec<u8>> = u.relies_on.iter().map(|d| d.to_vec()).collect();
            sqlx::query!(
                "INSERT INTO work.single_use
                 (ledger_id, authority_digest, idem_key, pos, record_id, relies_on)
                 VALUES ($1, $2, $3, $4, $5, $6::bytea[]::ledger.digest32[])",
                ledger.as_slice(),
                u.authority.as_slice(),
                u.key.as_str(),
                signed(pos)?,
                record_id.as_slice(),
                relies.as_slice()
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        Ok(())
    }

    /// Up to `limit` deliveries of the scoped ledger addressed to `addressee` with a sequence
    /// number above `after`, oldest first (RC-42, T-105).
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not read them, or [`StoreError::Corrupt`] for
    /// a malformed row or a number beyond `bigint`.
    pub async fn executor_deliveries(
        &mut self,
        addressee: &str,
        after: u64,
        limit: u32,
    ) -> Result<Vec<ExecutorDelivery>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query_as!(
            Raw,
            r#"SELECT seq, pos AS "pos!", record_id::bytea AS "record_id!", addressee, kind,
                      commitment::bytea AS "commitment!", body,
                      (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at_ms!",
                      doorbell, attempts,
                      (extract(epoch FROM next_attempt_at) * 1000)::bigint AS "next_attempt_ms!",
                      last_error,
                      (extract(epoch FROM settled_at) * 1000)::bigint AS settled_ms
               FROM work.executor_delivery
               WHERE ledger_id = $1 AND addressee = $2 AND seq > $3
               ORDER BY seq
               LIMIT $4"#,
            ledger.as_slice(),
            addressee,
            signed(after)?,
            i64::from(limit)
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter().map(ExecutorDelivery::try_from).collect()
    }

    /// Up to `limit` deliveries of the scoped ledger whose doorbell is due at `now_ms`, the
    /// longest due first (E-39).
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not read them, or [`StoreError::Corrupt`] for
    /// a malformed row or a time beyond `bigint`.
    pub async fn doorbells_due(
        &mut self,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<ExecutorDelivery>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query_as!(
            Raw,
            r#"SELECT seq, pos AS "pos!", record_id::bytea AS "record_id!", addressee, kind,
                      commitment::bytea AS "commitment!", body,
                      (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at_ms!",
                      doorbell, attempts,
                      (extract(epoch FROM next_attempt_at) * 1000)::bigint AS "next_attempt_ms!",
                      last_error,
                      (extract(epoch FROM settled_at) * 1000)::bigint AS settled_ms
               FROM work.executor_delivery
               WHERE ledger_id = $1 AND doorbell = 'pending'
                 AND next_attempt_at <= pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $2::bigint::double precision
               ORDER BY next_attempt_at, seq
               LIMIT $3"#,
            ledger.as_slice(),
            signed(now_ms)?,
            i64::from(limit)
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter().map(ExecutorDelivery::try_from).collect()
    }

    /// Settles the pending doorbell of delivery `seq` as `rung` or, with no webhook for its
    /// addressee, `unrouted`, at `at_ms`, counting the attempt; whether it was pending.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not update it, or [`StoreError::Corrupt`] for
    /// a value beyond `bigint`.
    pub async fn doorbell_settled(
        &mut self,
        seq: u64,
        rung: bool,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let state = if rung { "rung" } else { "unrouted" };
        let done = sqlx::query!(
            "UPDATE work.executor_delivery
             SET doorbell = $3, attempts = attempts + 1,
                 settled_at = pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $4::bigint::double precision
             WHERE ledger_id = $1 AND seq = $2 AND doorbell = 'pending'",
            ledger.as_slice(),
            signed(seq)?,
            state,
            signed(at_ms)?
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(done.rows_affected() == 1)
    }

    /// Counts a failed doorbell of delivery `seq` with the code `error` and moves its next
    /// attempt to `next_attempt_ms`; whether it was pending.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not update it, [`StoreError::Corrupt`] for a
    /// time beyond `bigint`, or [`StoreError::Constraint`] for a code that is not a lower-case
    /// identifier of at most 64 bytes.
    pub async fn doorbell_retry(
        &mut self,
        seq: u64,
        error: &str,
        next_attempt_ms: u64,
    ) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let done = sqlx::query!(
            "UPDATE work.executor_delivery
             SET attempts = attempts + 1, last_error = $3,
                 next_attempt_at = pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $4::bigint::double precision
             WHERE ledger_id = $1 AND seq = $2 AND doorbell = 'pending'",
            ledger.as_slice(),
            signed(seq)?,
            error,
            signed(next_attempt_ms)?
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(done.rows_affected() == 1)
    }

    /// The bindings of the scoped ledger that use the authority context `authority` or the
    /// idempotency key `key` (SEC-15).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn single_uses(
        &mut self,
        authority: &[u8; 32],
        key: &str,
    ) -> Result<Vec<UsedRow>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query!(
            r#"SELECT authority_digest::bytea AS "authority!", idem_key, pos AS "pos!",
                      record_id::bytea AS "record_id!"
               FROM work.single_use
               WHERE ledger_id = $1 AND (authority_digest = $2 OR idem_key = $3)
               ORDER BY pos"#,
            ledger.as_slice(),
            authority.as_slice(),
            key
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(UsedRow {
                    authority: fixed(&r.authority)?,
                    key: r.idem_key,
                    pos: unsigned(r.pos)?,
                    record: fixed(&r.record_id)?,
                })
            })
            .collect()
    }

    /// The record id of the first action report of the scoped ledger relying on `record`, which
    /// makes it `acted upon` (OP-4).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn acted_upon(&mut self, record: &[u8; 32]) -> Result<Option<[u8; 32]>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let found = sqlx::query_scalar!(
            r#"SELECT record_id::bytea AS "record_id!"
               FROM work.single_use
               WHERE ledger_id = $1 AND $2::bytea = ANY (relies_on::bytea[])
               ORDER BY pos
               LIMIT 1"#,
            ledger.as_slice(),
            record.as_slice()
        )
        .fetch_optional(self.conn())
        .await?;
        found.map(|raw| fixed(&raw)).transpose()
    }
}

impl DiscoveryPool<PublisherRole> {
    /// Up to `limit` ids of ledgers with doorbells due at `now_ms`, in ascending byte order,
    /// all above `after` (from the lowest for `None`); a page shorter than `limit` is the last
    /// (T-83).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed id or a time beyond
    /// `bigint`.
    pub async fn doorbell_ledgers(
        &self,
        after: Option<&LedgerId>,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<LedgerId>, StoreError> {
        let rows = sqlx::query_scalar!(
            r#"SELECT l::bytea AS "l!"
               FROM work.executor_delivery_ledgers($1::bytea::ledger.digest32, $2, $3) AS t(l)"#,
            after.map(|l| l.as_bytes().as_slice()),
            signed(now_ms)?,
            i64::from(limit)
        )
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|raw| fixed::<32>(raw).map(LedgerId::from_bytes))
            .collect()
    }
}
