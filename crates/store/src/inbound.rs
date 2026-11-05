//! Inbound events that answer no record (P-35 item 4, T-12 item 6, T-100 item 5, OP-38 item 5): only their deduplication row in `work.inbound_seen` is written, without a result position, in the scope of the ledger that stands for the tenant the event came for, so `(tenant, source, id)` is seen once across the record path and this one.

use crate::skeleton::refused;
use crate::{LedgerTx, StoreError};

/// An inbound event that produces no record (T-100 item 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundEvent {
    /// The CloudEvents `source`.
    pub source: String,
    /// The CloudEvents `id`.
    pub source_id: String,
    /// The digest of what arrived.
    pub content_digest: [u8; 32],
    /// Ledger time of the arrival, Unix milliseconds; it selects the monthly partition.
    pub seen_at_ms: u64,
}

/// Whether an inbound event is new to the scoped ledger's tenant (P-35 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum InboundSeen {
    /// Not seen in a hot partition; its deduplication row is written.
    First,
    /// Already seen, with or without a record; nothing is written.
    Repeat,
}

impl LedgerTx<'_> {
    /// Writes the deduplication row of `event` unless its `(source, source_id)` is already in a
    /// hot partition of the scoped ledger (OP-38 item 5). A transaction advisory lock on the
    /// pair serializes concurrent arrivals of the same event, so exactly one of them sees
    /// [`InboundSeen::First`]; the row is visible to the others once this transaction commits.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not write the table, [`StoreError::Corrupt`]
    /// for a time beyond `bigint`, or [`StoreError::Constraint`] for a source or id outside
    /// printable ASCII or above 1024 bytes, or a month without a partition (OP-37).
    pub async fn note_inbound(&mut self, event: &InboundEvent) -> Result<InboundSeen, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let seen_at = i64::try_from(event.seen_at_ms).map_err(|_| StoreError::Corrupt)?;
        let lock = format!(
            "work.inbound_seen\n{}\n{}\n{}",
            self.ledger().to_hex(),
            event.source,
            event.source_id
        );
        sqlx::query_scalar!(
            r#"SELECT pg_catalog.pg_advisory_xact_lock(
                   pg_catalog.hashtextextended($1::text, 0))::text AS "locked!""#,
            lock.as_str()
        )
        .fetch_one(self.conn())
        .await?;
        let written = sqlx::query!(
            "INSERT INTO work.inbound_seen
             (ledger_id, source, source_id, content_digest, result_pos, seen_at)
             SELECT $1::bytea, $2::text, $3::text, $4::bytea, NULL::bigint,
                    pg_catalog.to_timestamp(0)
                    + interval '1 millisecond' * $5::bigint::double precision
             WHERE NOT EXISTS (SELECT 1 FROM work.inbound_seen
                               WHERE ledger_id = $1 AND source = $2 AND source_id = $3)",
            ledger.as_slice(),
            event.source.as_str(),
            event.source_id.as_str(),
            event.content_digest.as_slice(),
            seen_at
        )
        .execute(self.conn())
        .await
        .map_err(refused)?;
        Ok(if written.rows_affected() > 0 {
            InboundSeen::First
        } else {
            InboundSeen::Repeat
        })
    }
}
