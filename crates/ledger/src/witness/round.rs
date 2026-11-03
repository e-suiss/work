//! The witnessing pass (§18 OP-4 item 3, OP-32 item 3, OP-33, OP-46 items 7, 8 and 10, SEC-32):
//! once the replica holds a ledger's latest stored checkpoint, each configured witness that has
//! not cosigned it gets it over C2SP `tlog-witness` with the consistency proof from the size it
//! holds, learnt from its 409 answer; a counted witness's cosignature goes through
//! [`Checkpointer::take_cosignatures`] and its time into the ledger time check, every witness's
//! cosigned checkpoint is an observation for the gossip comparison, a witness that names a
//! larger tree or refuses the proof shows a split view and is logged as a security error, and a
//! witness that refuses or does not answer waits a pause that doubles up to 60 s.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use suiss_ledger::checkpoint::Publication;
use tokio::time::{Instant, MissedTickBehavior};
use work_kernel::proof::{NoteError, verify_checkpoint};
use work_store::{CheckpointRow, CheckpointerPool, LedgerId, Pool, WitnessObservation};

use super::client::{WitnessAnswer, WitnessClient};
use super::gossip::observe;
use super::proof::consistency_proof;
use super::{Witness, WitnessError, cosignatures};
use crate::time::{LedgerTime, Monotonic, WitnessRound, cosign_round};
use crate::{
    AnyReplica, CheckpointError, Checkpointer, Clock, Declaration, Ledgers, Replica, SignerClient,
};

/// How often the led ledgers are looked at.
pub const WITNESS_TICK: Duration = Duration::from_secs(1);

/// The longest pause of a witness that refused or did not answer.
pub const MAX_WITNESS_PAUSE: Duration = Duration::from_secs(60);

/// How often the counted witnesses are asked again while ledger time is ahead of them.
pub const WITNESS_RECHECK: Duration = Duration::from_secs(30);

/// How a configured witness counts (OP-33 item 1, OP-46 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WitnessRole {
    /// Its cosignatures are stored and count towards `witness independent k`.
    Counted,
    /// Gossip and monitoring only, as the witness Suiss runs: its cosigned checkpoints are
    /// observations, never stored cosignatures.
    Gossip,
}

/// A witness the installation sends its checkpoints to.
#[derive(Debug, Clone)]
pub struct WitnessEndpoint {
    /// Its stored identifier and cosigner key.
    pub witness: Witness,
    /// How it counts.
    pub role: WitnessRole,
    /// Its submission prefix.
    pub client: WitnessClient,
}

#[derive(Debug, Default, Clone)]
struct Progress {
    holds: u64,
    cosigned: u64,
    failures: u32,
    paused_until: Option<Instant>,
    asked_at: Option<Instant>,
}

impl Progress {
    fn fail(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.paused_until = now.checked_add(pause(self.failures));
    }
}

/// Per ledger and witness: the size the witness holds, the size it cosigned and its pause.
#[derive(Debug, Default)]
pub struct WitnessStates(BTreeMap<(LedgerId, String), Progress>);

/// The pause after `failures` failures in a row: 1 s, doubling, at most [`MAX_WITNESS_PAUSE`].
pub(crate) fn pause(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(6);
    Duration::from_secs(1_u64.checked_shl(shift).unwrap_or(u64::MAX)).min(MAX_WITNESS_PAUSE)
}

/// What a 409 answer leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AfterConflict {
    /// Send again from the size the witness holds.
    Resend(u64),
    /// The witness holds a larger tree than the ledger's latest checkpoint: a split view.
    SplitView,
}

pub(crate) const fn after_conflict(held: u64, size: u64) -> AfterConflict {
    if held <= size {
        AfterConflict::Resend(held)
    } else {
        AfterConflict::SplitView
    }
}

/// What one pass over a ledger did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WitnessPass {
    /// The size of the checkpoint sent, when the replica held one.
    pub size: Option<u64>,
    /// Its ledger time, Unix milliseconds.
    pub issued_at_ms: u64,
    /// Counted witnesses asked.
    pub asked: usize,
    /// The cosignature times in seconds of the counted witnesses that cosigned.
    pub cosigned_seconds: Vec<u64>,
    /// New cosignatures stored.
    pub stored: usize,
    /// New observations for the gossip comparison.
    pub observed: usize,
}

impl WitnessPass {
    /// The ledger time check the pass gives, when a counted witness was asked (OP-32 item 3).
    #[must_use]
    pub fn time_round(&self) -> Option<WitnessRound> {
        (self.asked > 0).then(|| cosign_round(self.issued_at_ms, &self.cosigned_seconds))
    }
}

fn hex(ledger: &LedgerId) -> String {
    ledger.to_hex()
}

impl Checkpointer {
    async fn ask(
        &self,
        ledger: &LedgerId,
        latest: &CheckpointRow,
        note: &str,
        endpoint: &WitnessEndpoint,
        progress: &mut Progress,
        leaves: &mut Option<Vec<[u8; 32]>>,
    ) -> Result<Option<String>, WitnessError> {
        let id = endpoint.witness.id.as_str();
        let now = Instant::now();
        let mut old = progress.holds.min(latest.size);
        for _ in 0..2 {
            let proof = if old == 0 || old == latest.size {
                Vec::new()
            } else {
                if leaves.is_none() {
                    let read = self.pool().leaf_hashes(ledger, latest.size).await;
                    *leaves = Some(read.map_err(CheckpointError::Store)?);
                }
                let all = leaves.as_deref().unwrap_or_default();
                consistency_proof(all, old).map_err(|_| WitnessError::Unknown(old))?
            };
            let answer = endpoint.client.add_checkpoint(old, &proof, note).await;
            match answer {
                Ok(WitnessAnswer::Cosigned(lines)) => {
                    progress.holds = latest.size;
                    progress.failures = 0;
                    progress.paused_until = None;
                    return Ok(Some(lines));
                }
                Ok(WitnessAnswer::Conflict(held)) => match after_conflict(held, latest.size) {
                    AfterConflict::Resend(size) => {
                        progress.holds = size;
                        old = size;
                    }
                    AfterConflict::SplitView => {
                        tracing::error!(
                            event = "witness.split_view",
                            ledger = %hex(ledger),
                            witness = id,
                            held,
                            size = latest.size,
                            "a witness holds a larger tree than the ledger's latest checkpoint"
                        );
                        progress.fail(now);
                        return Ok(None);
                    }
                },
                Ok(WitnessAnswer::Inconsistent) => {
                    tracing::error!(
                        event = "witness.split_view",
                        ledger = %hex(ledger),
                        witness = id,
                        held = old,
                        size = latest.size,
                        "a witness holds another tree than the ledger's at the size it holds"
                    );
                    progress.fail(now);
                    return Ok(None);
                }
                Ok(refused) => {
                    tracing::warn!(
                        event = "witness.refused",
                        witness = id,
                        answer = ?refused,
                        "the witness refused the checkpoint"
                    );
                    progress.fail(now);
                    return Ok(None);
                }
                Err(error) => {
                    tracing::warn!(
                        event = "witness.unreachable",
                        witness = id,
                        %error,
                        "the witness gave no answer"
                    );
                    progress.fail(now);
                    return Ok(None);
                }
            }
        }
        tracing::warn!(
            event = "witness.refused",
            witness = id,
            "the witness answered a conflict twice"
        );
        progress.fail(now);
        Ok(None)
    }

    /// One witnessing pass over `ledger`: once `replica` holds its latest stored checkpoint,
    /// each of `witnesses` that has not cosigned it is asked; while `recheck` is set, a counted
    /// witness that cosigned it is asked again every [`WITNESS_RECHECK`]. Observations go to
    /// `derived`.
    ///
    /// # Errors
    /// [`WitnessError`] when the stores refuse or the stored checkpoint does not verify; a
    /// witness that refuses or does not answer is no error.
    pub async fn witness_pass(
        &self,
        ledger: &LedgerId,
        replica: &impl Replica,
        derived: &Pool,
        witnesses: &[WitnessEndpoint],
        states: &mut WitnessStates,
        recheck: bool,
    ) -> Result<WitnessPass, WitnessError> {
        let pool = self.pool();
        let Some(latest) = pool.latest(ledger).await.map_err(CheckpointError::Store)? else {
            return Ok(WitnessPass::default());
        };
        let mirrored = pool
            .mirrored(ledger, replica.id())
            .await
            .map_err(CheckpointError::Store)?;
        let mut order = Publication::default();
        order.built(latest.size).map_err(WitnessError::Order)?;
        if order.mirrored(mirrored).is_err() || order.may_witness(latest.size).is_err() {
            return Ok(WitnessPass::default());
        }
        let note = std::str::from_utf8(&latest.signed_note)
            .map_err(|_| WitnessError::Note(NoteError::Malformed))?;
        let own = verify_checkpoint(note, &self.origin(ledger), self.log_key(), &[])
            .map_err(WitnessError::Note)?;
        let mut pass = WitnessPass {
            size: Some(latest.size),
            issued_at_ms: latest.issued_at_ms,
            ..WitnessPass::default()
        };
        let mut leaves = None;
        for endpoint in witnesses {
            let id = endpoint.witness.id.as_str();
            let now = Instant::now();
            let progress = states.0.entry((*ledger, id.to_owned())).or_default();
            if progress.paused_until.is_some_and(|until| now < until) {
                continue;
            }
            let counted = endpoint.role == WitnessRole::Counted;
            let again = progress
                .asked_at
                .is_none_or(|at| now.saturating_duration_since(at) >= WITNESS_RECHECK);
            if progress.cosigned >= latest.size && !(recheck && counted && again) {
                continue;
            }
            progress.asked_at = Some(now);
            if counted {
                pass.asked = pass.asked.saturating_add(1);
            }
            let asked = self
                .ask(ledger, &latest, note, endpoint, progress, &mut leaves)
                .await?;
            let Some(lines) = asked else {
                continue;
            };
            let cosigned = format!("{note}{lines}");
            let one = std::slice::from_ref(&endpoint.witness);
            let rows = match cosignatures(&cosigned, &own.checkpoint, self.log_key(), one) {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::warn!(
                        event = "witness.cosignature_refused",
                        witness = id,
                        %error,
                        "the witness's cosignature does not verify under its configured key"
                    );
                    progress.fail(now);
                    continue;
                }
            };
            progress.cosigned = latest.size;
            let observation = WitnessObservation {
                witness_id: id.to_owned(),
                size: latest.size,
                root: own.checkpoint.root,
            };
            if observe(derived, ledger, &observation).await? {
                pass.observed = pass.observed.saturating_add(1);
            }
            if !counted {
                continue;
            }
            if let Some(row) = rows.first() {
                pass.cosigned_seconds
                    .push(row.cosigned_at_ms.checked_div(1000).unwrap_or_default());
            }
            let new = self
                .take_cosignatures(ledger, latest.size, &cosigned, replica, one)
                .await?;
            pass.stored = pass.stored.saturating_add(new);
        }
        Ok(pass)
    }
}

/// What the witnessing task works with.
#[derive(Debug, Clone)]
pub struct WitnessSetup {
    /// The `work_checkpointer` pool.
    pub pool: CheckpointerPool,
    /// The signer, asked once for the log key.
    pub signer: SignerClient,
    /// The checkpoint origin prefix.
    pub origin_prefix: String,
    /// What the checkpoints declare.
    pub declaration: Declaration,
    /// The replica a checkpoint must be mirrored to before a witness gets it (OP-4 item 3).
    pub replica: AnyReplica,
    /// The derived database as `work_deriver`, for the gossip comparison.
    pub derived: Pool,
    /// The configured witnesses.
    pub witnesses: Vec<WitnessEndpoint>,
}

/// Sends the checkpoints of the ledgers `ledgers` leads to the witnesses every
/// [`WITNESS_TICK`], puts each pass's witness round into `time` and decides the gossip
/// observations, until the task is dropped.
pub async fn run_witnessing<C, M>(
    ledgers: Arc<Ledgers<C>>,
    setup: WitnessSetup,
    time: LedgerTime<M>,
) where
    C: Clock + Clone + Sync + 'static,
    M: Monotonic,
{
    let mut checkpointer: Option<Checkpointer> = None;
    let mut states = WitnessStates::default();
    let mut ticks = tokio::time::interval(WITNESS_TICK);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut tick: u64 = 0;
    loop {
        ticks.tick().await;
        tick = tick.wrapping_add(1);
        if checkpointer.is_none() {
            checkpointer = Checkpointer::connect(
                setup.pool.clone(),
                setup.signer.clone(),
                &setup.origin_prefix,
                setup.declaration,
            )
            .await
            .ok();
        }
        let Some(current) = checkpointer.as_ref() else {
            continue;
        };
        let recheck = time.ahead_of_witness();
        for ledger in ledgers.led().await {
            let mut observed = 0;
            match current
                .witness_pass(
                    &ledger,
                    &setup.replica,
                    &setup.derived,
                    &setup.witnesses,
                    &mut states,
                    recheck,
                )
                .await
            {
                Ok(pass) => {
                    observed = pass.observed;
                    if let Some(round) = pass.time_round() {
                        time.record_witness_round(round);
                    }
                }
                Err(error) => {
                    tracing::warn!(event = "witness.pass_failed", %error, "witnessing pass failed");
                }
            }
            if (observed > 0 || tick.is_multiple_of(60))
                && let Err(error) = current.compare_observations(&ledger, &setup.derived).await
            {
                tracing::warn!(event = "witness.comparison_failed", %error, "gossip comparison failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    // OP-33 T-32 OP-48
    #[test]
    fn op_33_a_witness_that_fails_waits_one_second_doubling_up_to_a_minute() {
        let pauses: Vec<u64> = (1..=9).map(|f| pause(f).as_secs()).collect();
        assert_eq!(pauses, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(pause(0), Duration::from_secs(1));
        assert_eq!(pause(u32::MAX), MAX_WITNESS_PAUSE);
    }

    // OP-33 SEC-32 OP-48
    #[test]
    fn sec_32_a_witness_holding_a_larger_tree_than_the_latest_checkpoint_is_a_split_view() {
        assert_eq!(after_conflict(0, 5), AfterConflict::Resend(0));
        assert_eq!(after_conflict(3, 5), AfterConflict::Resend(3));
        assert_eq!(after_conflict(5, 5), AfterConflict::Resend(5));
        assert_eq!(after_conflict(6, 5), AfterConflict::SplitView);
    }

    // OP-32 OP-33 OP-48
    #[test]
    fn op_32_a_pass_that_asked_a_counted_witness_gives_a_witness_round() {
        let at = 1_793_505_043;
        let mut pass = WitnessPass {
            size: Some(2),
            issued_at_ms: at * 1000,
            ..WitnessPass::default()
        };
        assert_eq!(pass.time_round(), None);
        pass.asked = 1;
        assert_eq!(pass.time_round(), Some(WitnessRound::Unanswered));
        pass.cosigned_seconds.push(at);
        assert_eq!(pass.time_round(), Some(WitnessRound::Agreed(1)));
        pass.cosigned_seconds = vec![at - 60];
        assert_eq!(
            pass.time_round(),
            Some(WitnessRound::Ahead { ahead: 1, of: 1 })
        );
    }
}
