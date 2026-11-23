//! The reads an agent ceiling notice needs (E-23, P-114 item 2): the ledgers a tenant holds records in, from `work.record_signer` over the `work_access` pool, and, inside one ledger's scope, the `SignedRecord` bytes of the record Work sent with a Relay intent, which the notice rests on.

use crate::{AccessPool, LedgerTx, StoreError};

impl AccessPool {
    /// The distinct ledgers `tenant` holds a record in, in ledger order (P-114 item 2).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn tenant_ledgers(&self, tenant: &str) -> Result<Vec<[u8; 32]>, StoreError> {
        let rows = sqlx::query_scalar!(
            r#"SELECT DISTINCT ledger_id::bytea AS "ledger!"
               FROM work.record_signer
               WHERE tenant = $1
               ORDER BY 1"#,
            tenant
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|r| <[u8; 32]>::try_from(r.as_slice()).map_err(|_| StoreError::Corrupt))
            .collect()
    }
}

impl LedgerTx<'_> {
    /// The `SignedRecord` bytes of the ledger's record `record`, when it holds one (P-114 item 2).
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn record_bytes(&mut self, record: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let found = sqlx::query_scalar!(
            r#"SELECT record_bytes AS "record_bytes!"
               FROM ledger.log WHERE ledger_id = $1 AND record_id = $2"#,
            ledger.as_slice(),
            record.as_slice()
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(found)
    }
}
