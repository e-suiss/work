//! The gossip comparison (§18 OP-33, OP-46 item 5, SEC-32 rows 4 and 5): every checkpoint a
//! witness or another source was seen holding is stored as a pending observation in
//! `derived.witness_comparison_v1`, and each pass decides the pending ones against the ledger's
//! own tree, the stored checkpoint of that size or the root of the log's leaves at that size;
//! an observed root the ledger does not have at that size, or a size beyond its head, is
//! `inconsistent`, a security signal logged as an error until the Stage 13 event path exists.

use work_store::{LedgerId, LedgerTx, ObservationVerdict, Pool, StoreError, WitnessObservation};

use super::WitnessError;
use super::proof::tree_root;
use crate::{CheckpointError, Checkpointer};

/// Pending observations decided in one pass over a ledger.
pub(crate) const COMPARISON_PAGE: u32 = 100;

/// What an observation is compared against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expected {
    /// The ledger's root at the observed size.
    Root([u8; 32]),
    /// The observed size is beyond the ledger's head.
    BeyondHead,
}

/// The verdict on an observed root.
pub(crate) fn verdict(observed: &[u8; 32], expected: Expected) -> ObservationVerdict {
    match expected {
        Expected::Root(root) if root == *observed => ObservationVerdict::Consistent,
        Expected::Root(_) | Expected::BeyondHead => ObservationVerdict::Inconsistent,
    }
}

/// The decisions of one comparison pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Comparison {
    /// Observations found consistent.
    pub consistent: usize,
    /// Observations found inconsistent: equivocation (SEC-32).
    pub inconsistent: usize,
}

fn store(e: StoreError) -> WitnessError {
    WitnessError::Checkpoint(CheckpointError::Store(e))
}

/// Stores `observation` of `ledger` as pending in the derived database; returns whether it was
/// new.
///
/// # Errors
/// [`WitnessError::Checkpoint`] when the store refuses.
pub(crate) async fn observe(
    derived: &Pool,
    ledger: &LedgerId,
    observation: &WitnessObservation,
) -> Result<bool, WitnessError> {
    let mut tx = LedgerTx::begin(derived, ledger).await.map_err(store)?;
    let new = tx.observe_checkpoint(observation).await.map_err(store)?;
    tx.commit().await.map_err(store)?;
    Ok(new)
}

async fn pending(
    derived: &Pool,
    ledger: &LedgerId,
) -> Result<Vec<WitnessObservation>, WitnessError> {
    let mut tx = LedgerTx::begin(derived, ledger).await.map_err(store)?;
    let rows = tx
        .pending_observations(COMPARISON_PAGE)
        .await
        .map_err(store)?;
    tx.commit().await.map_err(store)?;
    Ok(rows)
}

async fn decide(
    derived: &Pool,
    ledger: &LedgerId,
    observation: &WitnessObservation,
    verdict: ObservationVerdict,
) -> Result<bool, WitnessError> {
    let mut tx = LedgerTx::begin(derived, ledger).await.map_err(store)?;
    let decided = tx
        .decide_observation(observation, verdict)
        .await
        .map_err(store)?;
    tx.commit().await.map_err(store)?;
    Ok(decided)
}

impl Checkpointer {
    /// Decides the pending observations of `ledger` in `derived` against the ledger's own tree.
    ///
    /// # Errors
    /// [`WitnessError::Checkpoint`] when a store refuses; the undecided rows stay pending.
    pub async fn compare_observations(
        &self,
        ledger: &LedgerId,
        derived: &Pool,
    ) -> Result<Comparison, WitnessError> {
        let mut done = Comparison::default();
        let observations = pending(derived, ledger).await?;
        if observations.is_empty() {
            return Ok(done);
        }
        let pool = self.pool();
        let head = match pool.head(ledger).await {
            Ok(head) => head.pos.saturating_add(1),
            Err(StoreError::NotOpened) => 0,
            Err(e) => return Err(store(e)),
        };
        let mut leaves: Option<Vec<[u8; 32]>> = None;
        for observation in &observations {
            let stored = pool.at(ledger, observation.size).await.map_err(store)?;
            let expected = if let Some(row) = stored {
                Expected::Root(row.root)
            } else if observation.size <= head {
                if leaves.is_none() {
                    leaves = Some(pool.leaf_hashes(ledger, head).await.map_err(store)?);
                }
                let size = usize::try_from(observation.size)
                    .map_err(|_| WitnessError::Unknown(observation.size))?;
                let prefix = leaves
                    .as_deref()
                    .and_then(|l| l.get(..size))
                    .ok_or(WitnessError::Unknown(observation.size))?;
                let root =
                    tree_root(prefix).map_err(|_| WitnessError::Unknown(observation.size))?;
                Expected::Root(root)
            } else {
                Expected::BeyondHead
            };
            let found = verdict(&observation.root, expected);
            if !decide(derived, ledger, observation, found).await? {
                continue;
            }
            match found {
                ObservationVerdict::Consistent => {
                    done.consistent = done.consistent.saturating_add(1);
                }
                ObservationVerdict::Inconsistent => {
                    done.inconsistent = done.inconsistent.saturating_add(1);
                    tracing::error!(
                        event = "witness.comparison_inconsistent",
                        ledger = %ledger.to_hex(),
                        witness = %observation.witness_id,
                        size = observation.size,
                        "a witness holds a checkpoint that is not the ledger's tree"
                    );
                }
            }
        }
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SEC-32 OP-33 OP-46
    #[test]
    fn sec_32_an_observed_root_is_consistent_only_with_the_ledgers_root_at_its_size() {
        let root = [7; 32];
        assert_eq!(
            verdict(&root, Expected::Root(root)),
            ObservationVerdict::Consistent
        );
        assert_eq!(
            verdict(&root, Expected::Root([8; 32])),
            ObservationVerdict::Inconsistent
        );
        assert_eq!(
            verdict(&root, Expected::BeyondHead),
            ObservationVerdict::Inconsistent
        );
    }
}
