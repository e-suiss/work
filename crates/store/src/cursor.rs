//! Consumer cursors (§18 OP-39): per consumer group and ledger, the last outbox pointer key whose
//! effect is applied, kept in the derived database as an OPERATIONAL row. `work_deriver` advances
//! it in the same derived transaction as the effect, so the cursor never runs ahead of what is
//! applied; it only moves forward and is updated in place, never deleted. A consumer's fallback
//! scan resumes from it (T-21). Every statement runs in a [`LedgerTx`].

use crate::{LedgerTx, PointerKey, StoreError};

impl LedgerTx<'_> {
    /// The cursor of consumer `group` in the scoped ledger, or `None` before its first advance.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not read cursors, or [`StoreError::Corrupt`]
    /// for an out-of-range position.
    pub async fn consumer_cursor(&mut self, group: &str) -> Result<Option<PointerKey>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT pos, event_id::text FROM derived.consumer_cursor \
             WHERE ledger_id = $1 AND consumer_group = $2",
        )
        .bind(ledger.as_slice())
        .bind(group)
        .fetch_optional(self.conn())
        .await?;
        row.map(|(pos, event_id)| {
            Ok(PointerKey {
                pos: u64::try_from(pos).map_err(|_| StoreError::Corrupt)?,
                event_id,
            })
        })
        .transpose()
    }

    /// Moves the cursor of consumer `group` in the scoped ledger to `to` if `to` follows it (or
    /// there is none yet); returns whether it moved. A key at or behind the cursor leaves it in
    /// place, so a repeated or late event never moves it back.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not write cursors or `group` is not a
    /// `[a-z0-9_]{1,64}` token, or [`StoreError::Corrupt`] for an out-of-range position.
    pub async fn advance_consumer_cursor(
        &mut self,
        group: &str,
        to: &PointerKey,
    ) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let pos = i64::try_from(to.pos).map_err(|_| StoreError::Corrupt)?;
        let done = sqlx::query(
            "INSERT INTO derived.consumer_cursor AS c (ledger_id, consumer_group, pos, event_id) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (ledger_id, consumer_group) DO UPDATE \
             SET pos = excluded.pos, event_id = excluded.event_id \
             WHERE (c.pos, c.event_id::text) < (excluded.pos, excluded.event_id::text)",
        )
        .bind(ledger.as_slice())
        .bind(group)
        .bind(pos)
        .bind(to.event_id.as_str())
        .execute(self.conn())
        .await?;
        Ok(done.rows_affected() > 0)
    }
}
