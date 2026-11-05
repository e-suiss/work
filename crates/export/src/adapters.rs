//! Port implementations (T-32): [`StoreSource`], the export's [`Source`] over the store's [`ExportLog`], which reads only canonical tables (T-10).

use work_store::{CanonicalEntry, CosignedCheckpoint, ExportLog, LedgerId, StoreError};

use crate::domain::{BundleCheckpoint, BundleEntry, Cosignature, Received};
use crate::ports::Source;

/// The canonical store, over a pool logged in as `work_app`.
#[derive(Debug, Clone)]
pub struct StoreSource {
    log: ExportLog,
}

impl StoreSource {
    /// Over `log`.
    #[must_use]
    pub const fn new(log: ExportLog) -> Self {
        Self { log }
    }
}

fn entry(e: CanonicalEntry) -> BundleEntry {
    BundleEntry {
        pos: e.pos,
        recorded_at_ms: e.recorded_at_ms,
        record: e.record_bytes,
        envelope: e.envelope_bytes,
        received: e
            .received
            .into_iter()
            .map(|r| Received {
                kind: r.kind.as_str().to_owned(),
                role: r.role.as_str().to_owned(),
                bytes: r.bytes,
            })
            .collect(),
    }
}

fn checkpoint((c, cosigned): CosignedCheckpoint) -> Result<BundleCheckpoint, StoreError> {
    let cosignatures = cosigned
        .into_iter()
        .map(|s| {
            Ok(Cosignature {
                witness_id: s.witness_id,
                cosigned_at_ms: s.cosigned_at_ms,
                line: String::from_utf8(s.signature).map_err(|_| StoreError::Corrupt)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    Ok(BundleCheckpoint {
        size: c.size,
        root: c.root,
        head_leaf: c.head_leaf,
        issued_at_ms: c.issued_at_ms,
        note: String::from_utf8(c.signed_note).map_err(|_| StoreError::Corrupt)?,
        cosignatures,
    })
}

impl Source for StoreSource {
    async fn entries(
        &self,
        ledger: &LedgerId,
        from: u64,
        limit: u32,
    ) -> Result<Vec<BundleEntry>, StoreError> {
        let entries = self.log.entries(ledger, from, limit).await?;
        Ok(entries.into_iter().map(entry).collect())
    }

    async fn checkpoints(&self, ledger: &LedgerId) -> Result<Vec<BundleCheckpoint>, StoreError> {
        let rows = self.log.checkpoints(ledger).await?;
        rows.into_iter().map(checkpoint).collect()
    }
}
