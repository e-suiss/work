//! The durable delivery of the `commitment_active` Claims Work hands Access (E-8, E-12, T-17, OP-34): the sequencer writes one `work.claim_delivery` row for each end of `commitment.active` a record gives, in the same transaction as the record, issued at the record's ledger time so every attempt sends the same Claim; the delivery worker, as `work_publisher`, discovers the ledgers with rows due through the `SECURITY DEFINER` function `work.claim_delivery_ledgers`, reads their due rows in a [`LedgerTx`], and settles each row as delivered or quarantined, or moves its next attempt. Rows are never removed: a settled row keeps Access's answer.

use crate::skeleton::refused;
use crate::{DiscoveryPool, LedgerId, LedgerTx, PublisherRole, StoreError};

/// One end of `commitment.active` the sequencer writes beside its record (E-8, E-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRow {
    /// The obligor whose commitment ended, its Access `PartyID`.
    pub subject: [u8; 16],
    /// The commitment, by the digest of its `request`.
    pub commitment: [u8; 32],
    /// Work's service Party in the governing domain, the Claim's issuer.
    pub issuer: [u8; 16],
    /// The governing domain of the tenant's realm.
    pub domain: [u8; 32],
    /// The `x5t#S256` of Work's PEP certificate, the channel the Claim comes over.
    pub pep: [u8; 32],
}

/// The key of a delivery inside its ledger: the record that ended the commitment and the
/// obligor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimKey {
    /// The record that ended it.
    pub record: [u8; 32],
    /// The obligor.
    pub subject: [u8; 16],
}

/// Where a delivery stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Not yet answered by Access; tried again at `next_attempt_ms`.
    Pending {
        /// When it is next due, Unix milliseconds.
        next_attempt_ms: u64,
        /// The code of the last failed attempt.
        last_error: Option<String>,
    },
    /// Admitted by Access.
    Delivered {
        /// Access's `ClaimID`.
        claim: [u8; 16],
        /// The domain log position.
        position: u64,
        /// Whether Access answered it as a Claim admitted before.
        replayed: bool,
        /// When, Unix milliseconds.
        at_ms: u64,
    },
    /// Held by Access.
    Quarantined {
        /// Access's `ClaimID`.
        claim: [u8; 16],
        /// The domain log position.
        position: u64,
        /// Access's reason.
        reason: String,
        /// When, Unix milliseconds.
        at_ms: u64,
    },
}

/// A stored delivery with the Claim it sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimDelivery {
    /// Its key.
    pub key: ClaimKey,
    /// The log position of the record that ended the commitment.
    pub pos: u64,
    /// The Claim.
    pub claim: ClaimRow,
    /// The Claim's `issued_at`, the record's ledger time, Unix milliseconds.
    pub issued_at_ms: u64,
    /// The attempts made.
    pub attempts: u64,
    /// Where it stands.
    pub delivery: Delivery,
}

/// Access's answer to a delivered or held Claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimAnswer {
    /// Access's `ClaimID`.
    pub claim: [u8; 16],
    /// The domain log position.
    pub position: u64,
    /// When the answer was taken, Unix milliseconds.
    pub at_ms: u64,
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
    record_id: Vec<u8>,
    subject: Vec<u8>,
    pos: i64,
    commitment: Vec<u8>,
    issuer: Vec<u8>,
    domain_id: Vec<u8>,
    pep: Vec<u8>,
    issued_at_ms: i64,
    delivery: String,
    attempts: i64,
    next_attempt_ms: i64,
    last_error: Option<String>,
    access_claim: Option<Vec<u8>>,
    access_pos: Option<i64>,
    replayed: Option<bool>,
    held_reason: Option<String>,
    settled_ms: Option<i64>,
}

impl TryFrom<Raw> for ClaimDelivery {
    type Error = StoreError;

    fn try_from(r: Raw) -> Result<Self, StoreError> {
        let answered = |claim: Option<Vec<u8>>, pos: Option<i64>, at: Option<i64>| {
            Ok::<_, StoreError>((
                fixed::<16>(&claim.ok_or(StoreError::Corrupt)?)?,
                unsigned(pos.ok_or(StoreError::Corrupt)?)?,
                unsigned(at.ok_or(StoreError::Corrupt)?)?,
            ))
        };
        let delivery = match r.delivery.as_str() {
            "pending" => Delivery::Pending {
                next_attempt_ms: unsigned(r.next_attempt_ms)?,
                last_error: r.last_error,
            },
            "delivered" => {
                let (claim, position, at_ms) =
                    answered(r.access_claim, r.access_pos, r.settled_ms)?;
                Delivery::Delivered {
                    claim,
                    position,
                    replayed: r.replayed.ok_or(StoreError::Corrupt)?,
                    at_ms,
                }
            }
            "quarantined" => {
                let (claim, position, at_ms) =
                    answered(r.access_claim, r.access_pos, r.settled_ms)?;
                Delivery::Quarantined {
                    claim,
                    position,
                    reason: r.held_reason.ok_or(StoreError::Corrupt)?,
                    at_ms,
                }
            }
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Self {
            key: ClaimKey {
                record: fixed(&r.record_id)?,
                subject: fixed(&r.subject)?,
            },
            pos: unsigned(r.pos)?,
            claim: ClaimRow {
                subject: fixed(&r.subject)?,
                commitment: fixed(&r.commitment)?,
                issuer: fixed(&r.issuer)?,
                domain: fixed(&r.domain_id)?,
                pep: fixed(&r.pep)?,
            },
            issued_at_ms: unsigned(r.issued_at_ms)?,
            attempts: unsigned(r.attempts)?,
            delivery,
        })
    }
}

impl LedgerTx<'_> {
    /// Writes the Claims of the record at `pos`, issued at its ledger time `recorded_at_ms` and
    /// due at once (E-8, E-12).
    pub(crate) async fn insert_claims(
        &mut self,
        pos: u64,
        record_id: &[u8; 32],
        recorded_at_ms: u64,
        claims: &[ClaimRow],
    ) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        for c in claims {
            sqlx::query!(
                "INSERT INTO work.claim_delivery
                 (ledger_id, record_id, subject, pos, commitment, issuer, domain_id, pep,
                  issued_at, delivery, attempts, next_attempt_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                  pg_catalog.to_timestamp(0) + interval '1 millisecond' * $9::bigint::double precision,
                  'pending', 0,
                  pg_catalog.to_timestamp(0) + interval '1 millisecond' * $9::bigint::double precision)",
                ledger.as_slice(),
                record_id.as_slice(),
                c.subject.as_slice(),
                signed(pos)?,
                c.commitment.as_slice(),
                c.issuer.as_slice(),
                c.domain.as_slice(),
                c.pep.as_slice(),
                signed(recorded_at_ms)?
            )
            .execute(self.conn())
            .await
            .map_err(refused)?;
        }
        Ok(())
    }

    /// The deliveries of the scoped ledger for the record `record`, by subject.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not read them, or [`StoreError::Corrupt`] for
    /// a malformed row.
    pub async fn claim_deliveries(
        &mut self,
        record: &[u8; 32],
    ) -> Result<Vec<ClaimDelivery>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query_as!(
            Raw,
            r#"SELECT record_id::bytea AS "record_id!", subject, pos AS "pos!",
                      commitment::bytea AS "commitment!", issuer, domain_id::bytea AS "domain_id!",
                      pep::bytea AS "pep!",
                      (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at_ms!",
                      delivery, attempts,
                      (extract(epoch FROM next_attempt_at) * 1000)::bigint AS "next_attempt_ms!",
                      last_error, access_claim, access_pos, replayed, held_reason,
                      (extract(epoch FROM settled_at) * 1000)::bigint AS settled_ms
               FROM work.claim_delivery
               WHERE ledger_id = $1 AND record_id = $2
               ORDER BY subject"#,
            ledger.as_slice(),
            record.as_slice()
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter().map(ClaimDelivery::try_from).collect()
    }

    /// Up to `limit` pending deliveries of the scoped ledger due at `now_ms`, the longest due
    /// first.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not read them, or [`StoreError::Corrupt`] for
    /// a malformed row or a time beyond `bigint`.
    pub async fn claims_due(
        &mut self,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<ClaimDelivery>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query_as!(
            Raw,
            r#"SELECT record_id::bytea AS "record_id!", subject, pos AS "pos!",
                      commitment::bytea AS "commitment!", issuer, domain_id::bytea AS "domain_id!",
                      pep::bytea AS "pep!",
                      (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at_ms!",
                      delivery, attempts,
                      (extract(epoch FROM next_attempt_at) * 1000)::bigint AS "next_attempt_ms!",
                      last_error, access_claim, access_pos, replayed, held_reason,
                      (extract(epoch FROM settled_at) * 1000)::bigint AS settled_ms
               FROM work.claim_delivery
               WHERE ledger_id = $1 AND delivery = 'pending'
                 AND next_attempt_at <= pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $2::bigint::double precision
               ORDER BY next_attempt_at, pos, subject
               LIMIT $3"#,
            ledger.as_slice(),
            signed(now_ms)?,
            i64::from(limit)
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter().map(ClaimDelivery::try_from).collect()
    }

    /// Marks the pending delivery `key` delivered with Access's `answer`; whether it was
    /// pending.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not update it, [`StoreError::Corrupt`] for a
    /// value beyond `bigint`, or [`StoreError::Constraint`] for an answer the table refuses.
    pub async fn claim_delivered(
        &mut self,
        key: &ClaimKey,
        answer: &ClaimAnswer,
        replayed: bool,
    ) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let done = sqlx::query!(
            "UPDATE work.claim_delivery
             SET delivery = 'delivered', attempts = attempts + 1, access_claim = $3,
                 access_pos = $4, replayed = $5,
                 settled_at = pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $6::bigint::double precision
             WHERE ledger_id = $1 AND record_id = $2 AND subject = $7 AND delivery = 'pending'",
            ledger.as_slice(),
            key.record.as_slice(),
            answer.claim.as_slice(),
            signed(answer.position)?,
            replayed,
            signed(answer.at_ms)?,
            key.subject.as_slice()
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(done.rows_affected() == 1)
    }

    /// Marks the pending delivery `key` held by Access for `reason` with its `answer`; whether
    /// it was pending.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not update it, [`StoreError::Corrupt`] for a
    /// value beyond `bigint`, or [`StoreError::Constraint`] for a reason outside printable
    /// ASCII or above 128 bytes.
    pub async fn claim_quarantined(
        &mut self,
        key: &ClaimKey,
        answer: &ClaimAnswer,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let done = sqlx::query!(
            "UPDATE work.claim_delivery
             SET delivery = 'quarantined', attempts = attempts + 1, access_claim = $3,
                 access_pos = $4, held_reason = $5,
                 settled_at = pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $6::bigint::double precision
             WHERE ledger_id = $1 AND record_id = $2 AND subject = $7 AND delivery = 'pending'",
            ledger.as_slice(),
            key.record.as_slice(),
            answer.claim.as_slice(),
            signed(answer.position)?,
            reason,
            signed(answer.at_ms)?,
            key.subject.as_slice()
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(done.rows_affected() == 1)
    }

    /// Counts a failed attempt of the pending delivery `key` with the code `error` and moves
    /// its next attempt to `next_attempt_ms`; whether it was pending.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not update it, [`StoreError::Corrupt`] for a
    /// time beyond `bigint`, or [`StoreError::Constraint`] for a code that is not a lower-case
    /// identifier of at most 64 bytes.
    pub async fn claim_retry(
        &mut self,
        key: &ClaimKey,
        error: &str,
        next_attempt_ms: u64,
    ) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let done = sqlx::query!(
            "UPDATE work.claim_delivery
             SET attempts = attempts + 1, last_error = $3,
                 next_attempt_at = pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $4::bigint::double precision
             WHERE ledger_id = $1 AND record_id = $2 AND subject = $5 AND delivery = 'pending'",
            ledger.as_slice(),
            key.record.as_slice(),
            error,
            signed(next_attempt_ms)?,
            key.subject.as_slice()
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(done.rows_affected() == 1)
    }
}

impl DiscoveryPool<PublisherRole> {
    /// Up to `limit` ids of ledgers with deliveries due at `now_ms`, in ascending byte order,
    /// all above `after` (from the lowest for `None`); a page shorter than `limit` is the last
    /// (T-83).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed id or a time beyond
    /// `bigint`.
    pub async fn claim_ledgers(
        &self,
        after: Option<&LedgerId>,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<LedgerId>, StoreError> {
        let rows = sqlx::query_scalar!(
            r#"SELECT l::bytea AS "l!"
               FROM work.claim_delivery_ledgers($1::bytea::ledger.digest32, $2, $3) AS t(l)"#,
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
