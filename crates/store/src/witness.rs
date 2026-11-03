//! The gossip comparison rows of the derived database (§18 OP-33, OP-46 item 5, SEC-32 rows 4
//! and 5): each checkpoint a witness or another source was seen holding is an observation of
//! its size and root, stored once as `pending`, and decided once against the ledger's own tree
//! as `consistent` or `inconsistent`; a decided row never changes. `work_deriver` writes them,
//! every statement in a [`LedgerTx`].

use crate::{LedgerTx, StoreError};

/// One observed checkpoint of the scoped ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessObservation {
    /// The witness or source that holds it.
    pub witness_id: String,
    /// The observed tree size.
    pub size: u64,
    /// The observed root.
    pub root: [u8; 32],
}

/// The decision on an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservationVerdict {
    /// The ledger's tree has this root at this size.
    Consistent,
    /// It does not: the log or the source equivocates (SEC-32).
    Inconsistent,
}

impl ObservationVerdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Consistent => "consistent",
            Self::Inconsistent => "inconsistent",
        }
    }
}

impl LedgerTx<'_> {
    /// Stores `observation` as `pending` unless the same one is stored; returns whether it was
    /// new.
    ///
    /// # Errors
    /// [`StoreError::Db`], also for a size below 1 or a witness id that is not a snake name.
    pub async fn observe_checkpoint(
        &mut self,
        observation: &WitnessObservation,
    ) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let size = i64::try_from(observation.size).map_err(|_| StoreError::Corrupt)?;
        let done = sqlx::query!(
            "INSERT INTO derived.witness_comparison_v1
             (ledger_id, witness_id, observed_size, observed_root, verdict)
             VALUES ($1, $2, $3, $4, 'pending') ON CONFLICT DO NOTHING",
            ledger.as_slice(),
            observation.witness_id.as_str(),
            size,
            observation.root.as_slice()
        )
        .execute(self.conn())
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Up to `limit` observations of the scoped ledger still `pending`, oldest first.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an out-of-range row, otherwise [`StoreError::Db`].
    pub async fn pending_observations(
        &mut self,
        limit: u32,
    ) -> Result<Vec<WitnessObservation>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query!(
            r#"SELECT witness_id::text AS "witness_id!", observed_size AS "size!",
                      observed_root::bytea AS "root!"
               FROM derived.witness_comparison_v1
               WHERE ledger_id = $1 AND verdict = 'pending'
               ORDER BY observed_at, witness_id, observed_size LIMIT $2"#,
            ledger.as_slice(),
            i64::from(limit)
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(WitnessObservation {
                    witness_id: r.witness_id,
                    size: u64::try_from(r.size).map_err(|_| StoreError::Corrupt)?,
                    root: <[u8; 32]>::try_from(r.root.as_slice())
                        .map_err(|_| StoreError::Corrupt)?,
                })
            })
            .collect()
    }

    /// Decides a `pending` observation; returns whether it was still pending.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn decide_observation(
        &mut self,
        observation: &WitnessObservation,
        verdict: ObservationVerdict,
    ) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let size = i64::try_from(observation.size).map_err(|_| StoreError::Corrupt)?;
        let done = sqlx::query!(
            "UPDATE derived.witness_comparison_v1
             SET verdict = $5, decided_at = pg_catalog.now()
             WHERE ledger_id = $1 AND witness_id = $2 AND observed_size = $3
             AND observed_root = $4 AND verdict = 'pending'",
            ledger.as_slice(),
            observation.witness_id.as_str(),
            size,
            observation.root.as_slice(),
            verdict.as_str()
        )
        .execute(self.conn())
        .await?;
        Ok(done.rows_affected() == 1)
    }
}
