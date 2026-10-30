use suiss_ledger::port::{AppendError, LogStore};
use suiss_ledger::sequencer::Batch;
use work_store::{
    AppendBatch, ItemHeadRow, LedgerId, LogRow, NewHead, OutboxRow, SequencerPool, StoreError,
};

use crate::SealedRecord;

/// One ledger's log in PostgreSQL, written as `work_sequencer` (T-74 item 1).
#[derive(Debug, Clone)]
pub struct PgLog {
    pool: SequencerPool,
    ledger: LedgerId,
}

impl PgLog {
    /// The log of `ledger` on `pool`.
    #[must_use]
    pub const fn new(pool: SequencerPool, ledger: LedgerId) -> Self {
        Self { pool, ledger }
    }

    /// The pool.
    #[must_use]
    pub const fn pool(&self) -> &SequencerPool {
        &self.pool
    }

    /// The ledger.
    #[must_use]
    pub const fn ledger(&self) -> &LedgerId {
        &self.ledger
    }
}

/// The store's batch for an engine batch: log rows in position order, then each record's item
/// heads and outbox pointers at its position (T-81).
pub(crate) fn rows(batch: &Batch<SealedRecord>) -> AppendBatch {
    let mut records = Vec::with_capacity(batch.records.len());
    let mut items = Vec::new();
    let mut outbox = Vec::new();
    for sealed in &batch.records {
        let pos = sealed.slot.pos;
        let r = &sealed.record.record;
        records.push(LogRow {
            pos,
            record_id: r.record_id,
            recorded_at_ms: sealed.slot.recorded_at,
            prev: sealed.slot.prev,
            leaf: sealed.leaf,
            record_bytes: r.record_bytes.clone(),
            envelope_bytes: sealed.record.envelope.clone(),
        });
        items.extend(r.items.iter().map(|c| ItemHeadRow {
            item: c.item,
            version: c.version,
            last_pos: pos,
            heads: c.heads.clone(),
        }));
        outbox.extend(r.outbox.iter().map(|e| OutboxRow {
            pos,
            event_id: e.event_id.clone(),
            event_type: e.event_type.clone(),
            traceparent: e.traceparent.clone(),
            item: e.item,
            version: e.version,
        }));
    }
    AppendBatch {
        epoch: batch.epoch,
        after: batch.after,
        records,
        items,
        outbox,
        head: NewHead {
            pos: batch.head.pos,
            leaf: batch.head.leaf,
            recorded_at_ms: batch.head.recorded_at,
            frontier: batch.head.frontier.nodes().to_vec(),
        },
    }
}

impl LogStore<SealedRecord> for PgLog {
    type Error = StoreError;

    async fn append(&self, batch: &Batch<SealedRecord>) -> Result<(), AppendError<StoreError>> {
        self.pool
            .append(&self.ledger, &rows(batch))
            .await
            .map_err(|e| match e {
                work_store::AppendError::Refused(e) => AppendError::Refused(e),
                work_store::AppendError::Failed(e) => AppendError::Failed(e),
            })
    }
}
