//! Outbox pointers (T-17, §18 OP-34): a row names an event of a committed log position and
//! carries only its identity, the affected work item and the item's version (T-81); the publisher reads the pending rows of one ledger in `(pos,
//! event_id)` order, builds the event from the committed record, and after the JetStream ack
//! removes the row as `work_publisher`, the only role with `DELETE` on `ledger.outbox` (OP-12
//! rule 6). While NATS is unreachable a consumer scans the pending rows and the log from a
//! `(ledger, pos)` cursor instead (T-21). Every statement runs in a [`LedgerTx`].

use crate::{ItemRef, LedgerTx, StoreError};

/// The key of an outbox row inside its ledger.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PointerKey {
    /// Log position of the record the event reflects.
    pub pos: u64,
    /// CloudEvents `id`, stable across attempts (§15 P-35).
    pub event_id: String,
}

/// A pending outbox row with the log facts the minimal event needs (OP-34 rule 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    /// The row key.
    pub key: PointerKey,
    /// Catalogued event type (§15 P-38).
    pub event_type: String,
    /// W3C trace context of the committing request (§15 P-42).
    pub traceparent: String,
    /// Digest of the record at `key.pos` (§15 P-79).
    pub record_id: [u8; 32],
    /// Ledger time of the record, Unix milliseconds (§15 P-35 rule 2).
    pub recorded_at_ms: i64,
    /// The work item the event is about (T-81).
    pub item: ItemRef,
    /// The item's version after the record, the event's `seq` (§15 P-29, T-81).
    pub version: u64,
}

/// A committed log row (§18 OP-2): what an event body is derived from.
#[derive(Clone, PartialEq, Eq)]
pub struct CommittedRecord {
    /// Log position.
    pub pos: u64,
    /// Record digest.
    pub record_id: [u8; 32],
    /// Ledger time, Unix milliseconds.
    pub recorded_at_ms: i64,
    /// Canonical record bytes (deterministic CBOR).
    pub record_bytes: Vec<u8>,
    /// Ledger envelope bytes.
    pub envelope_bytes: Vec<u8>,
}

impl std::fmt::Debug for CommittedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommittedRecord")
            .field("pos", &self.pos)
            .field("record_bytes", &self.record_bytes.len())
            .field("envelope_bytes", &self.envelope_bytes.len())
            .finish_non_exhaustive()
    }
}

fn pos_of(raw: i64) -> Result<u64, StoreError> {
    u64::try_from(raw).map_err(|_| StoreError::Corrupt)
}

fn digest_of(raw: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(raw).map_err(|_| StoreError::Corrupt)
}

fn pos_param(pos: u64) -> Result<i64, StoreError> {
    i64::try_from(pos).map_err(|_| StoreError::Corrupt)
}

impl LedgerTx<'_> {
    /// Up to `limit` pending outbox rows of the scoped ledger in `(pos, event_id)` order, each
    /// with the record digest and ledger time of its log row.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row.
    pub async fn outbox_pending(&mut self, limit: u32) -> Result<Vec<PendingEvent>, StoreError> {
        self.outbox_pending_after(None, limit).await
    }

    /// Up to `limit` pending outbox rows of the scoped ledger whose key follows `after` (all
    /// rows for `None`), in `(pos, event_id)` order: the cursor scan a consumer falls back to
    /// while NATS is unreachable (§17 T-21, §18 OP-34 rule 2).
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not read the outbox, or
    /// [`StoreError::Corrupt`] for an out-of-range row or position.
    pub async fn outbox_pending_after(
        &mut self,
        after: Option<&PointerKey>,
        limit: u32,
    ) -> Result<Vec<PendingEvent>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let (after_pos, after_id) = match after {
            Some(k) => (pos_param(k.pos)?, k.event_id.as_str()),
            None => (-1, ""),
        };
        let rows = sqlx::query!(
            r#"SELECT o.pos AS "pos!", o.event_id::text AS "event_id!",
                      o.event_type::text AS "event_type!", o.traceparent::text AS "traceparent!",
                      l.record_id::bytea AS "record_id!",
                      (extract(epoch FROM l.recorded_at) * 1000)::bigint AS "recorded_at_ms!",
                      o.item_kind AS "item_kind!", o.item_id AS "item_id!", o.version AS "version!"
               FROM ledger.outbox o
               JOIN ledger.log l ON l.ledger_id = o.ledger_id AND l.pos = o.pos
               WHERE o.ledger_id = $1 AND (o.pos, o.event_id) > ($2::bigint, $3::text)
               ORDER BY o.pos, o.event_id
               LIMIT $4"#,
            ledger.as_slice(),
            after_pos,
            after_id,
            i64::from(limit)
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(PendingEvent {
                    key: PointerKey {
                        pos: pos_of(r.pos)?,
                        event_id: r.event_id,
                    },
                    event_type: r.event_type,
                    traceparent: r.traceparent,
                    record_id: digest_of(&r.record_id)?,
                    recorded_at_ms: r.recorded_at_ms,
                    item: ItemRef::from_parts(&r.item_kind, &r.item_id)
                        .ok_or(StoreError::Corrupt)?,
                    version: pos_of(r.version)?,
                })
            })
            .collect()
    }

    /// The committed log row at `pos`, or `None` if there is none in the scoped ledger.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range row or position.
    pub async fn committed_record(
        &mut self,
        pos: u64,
    ) -> Result<Option<CommittedRecord>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let row = sqlx::query!(
            r#"SELECT pos AS "pos!", record_id::bytea AS "record_id!",
                      (extract(epoch FROM recorded_at) * 1000)::bigint AS "recorded_at_ms!",
                      record_bytes AS "record_bytes!", envelope_bytes AS "envelope_bytes!"
               FROM ledger.log WHERE ledger_id = $1 AND pos = $2"#,
            ledger.as_slice(),
            pos_param(pos)?
        )
        .fetch_optional(self.conn())
        .await?;
        row.map(|r| {
            Ok(CommittedRecord {
                pos: pos_of(r.pos)?,
                record_id: digest_of(&r.record_id)?,
                recorded_at_ms: r.recorded_at_ms,
                record_bytes: r.record_bytes,
                envelope_bytes: r.envelope_bytes,
            })
        })
        .transpose()
    }

    /// Up to `limit` committed log rows of the scoped ledger with a position above `after` (from
    /// position 0 for `None`), in position order: the full scan from the `(ledger, pos)` cursor
    /// (§17 T-17, T-21).
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not read the log, or [`StoreError::Corrupt`]
    /// for an out-of-range row or position.
    pub async fn log_after(
        &mut self,
        after: Option<u64>,
        limit: u32,
    ) -> Result<Vec<CommittedRecord>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let after_pos = after.map_or(Ok(-1), pos_param)?;
        let rows = sqlx::query!(
            r#"SELECT pos AS "pos!", record_id::bytea AS "record_id!",
                      (extract(epoch FROM recorded_at) * 1000)::bigint AS "recorded_at_ms!",
                      record_bytes AS "record_bytes!", envelope_bytes AS "envelope_bytes!"
               FROM ledger.log WHERE ledger_id = $1 AND pos > $2
               ORDER BY pos
               LIMIT $3"#,
            ledger.as_slice(),
            after_pos,
            i64::from(limit)
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(CommittedRecord {
                    pos: pos_of(r.pos)?,
                    record_id: digest_of(&r.record_id)?,
                    recorded_at_ms: r.recorded_at_ms,
                    record_bytes: r.record_bytes,
                    envelope_bytes: r.envelope_bytes,
                })
            })
            .collect()
    }

    /// Removes the acknowledged rows `keys` of the scoped ledger (OP-34 rule 2) and returns how
    /// many were present; removing an absent row is a no-op, so a repeated call is safe.
    ///
    /// # Errors
    /// [`StoreError::Db`], also when the role may not delete (only `work_publisher` may), or
    /// [`StoreError::Corrupt`] for an out-of-range position.
    pub async fn outbox_remove(&mut self, keys: &[PointerKey]) -> Result<u64, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let mut positions = Vec::with_capacity(keys.len());
        let mut ids = Vec::with_capacity(keys.len());
        for k in keys {
            positions.push(pos_param(k.pos)?);
            ids.push(k.event_id.clone());
        }
        let done = sqlx::query!(
            "DELETE FROM ledger.outbox o
             USING unnest($2::bigint[], $3::text[]) AS k(pos, event_id)
             WHERE o.ledger_id = $1 AND o.pos = k.pos AND o.event_id = k.event_id",
            ledger.as_slice(),
            positions.as_slice(),
            ids.as_slice()
        )
        .execute(self.conn())
        .await?;
        Ok(done.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    // P-34 P-35 T-17
    #[test]
    fn p_34_only_the_append_of_a_record_writes_an_outbox_pointer() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let insert = ["INSERT INTO", "ledger.outbox"].join(" ");
        let mut writers = Vec::new();
        for entry in std::fs::read_dir(root.join("src")).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            if text.contains(&insert) {
                writers.push(path.file_name().unwrap().to_string_lossy().into_owned());
            }
        }
        assert_eq!(writers, ["sequencer.rs"]);
        let grant = ["GRANT INSERT ON", "ledger.outbox"].join(" ");
        let mut grants = Vec::new();
        for entry in std::fs::read_dir(root.join("migrations/canonical")).unwrap() {
            let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            for line in text.lines().filter(|l| l.contains(&grant)) {
                grants.push(line.to_owned());
            }
        }
        assert_eq!(grants, ["GRANT INSERT ON ledger.outbox TO work_sequencer;"]);
        let path = root.join("migrations/canonical/20261028100100_ledger_outbox.sql");
        let table = std::fs::read_to_string(path).unwrap();
        let fk = "FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos)";
        assert!(table.contains(fk));
    }
}
