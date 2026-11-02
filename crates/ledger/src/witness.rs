//! Witness cosignatures of the ledger's checkpoints (§18 OP-4 item 3, OP-33, SEC-32, Access
//! T21): a cosigned note is accepted only for a checkpoint the log signed and stored, only once
//! the replica holds its size (mirror before witness, through the shared engine's publication
//! order), and only with the `tlog-cosignature/v1` lines of configured witnesses that verify;
//! a cosigned note that names another tree at a stored size is an equivocation, a security
//! event, and nothing of it is stored.

use suiss_ledger::checkpoint::{OrderError, Publication};
use work_kernel::proof::{Checkpoint, NoteError, Verifier, verify_checkpoint};
use work_store::{CosignatureRow, LedgerId};

use crate::replica::DirectoryReplica;
use crate::{CheckpointError, Checkpointer};

/// A configured witness: the identifier its cosignatures are stored under and its cosigner key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// Stored `witness_id`.
    pub id: String,
    /// Its `tlog-cosignature/v1` key.
    pub key: Verifier,
}

/// Why a cosigned note was not taken.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessError {
    /// The note does not verify under the log key and the witnesses' keys; the shared crate's
    /// code (T-88).
    #[error("cosigned note: {}", .0.code())]
    Note(NoteError),
    /// No checkpoint of this size was signed and stored.
    #[error("no stored checkpoint of size {0}")]
    Unknown(u64),
    /// The cosigned checkpoint is another tree than the stored one of the same size: the log
    /// or a witness equivocates (SEC-32).
    #[error("cosigned checkpoint differs from the stored one of size {0}")]
    Equivocation(u64),
    /// The replica does not hold the size yet (mirror before witness).
    #[error("checkpoint is not mirrored yet: {0}")]
    Order(OrderError),
    /// No configured witness's cosignature verified.
    #[error("no cosignature of a configured witness")]
    Uncosigned,
    /// The checkpointer or the store refused.
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
}

/// The signature lines of `note` that carry the key `key`.
fn line_of<'a>(note: &'a str, key: &Verifier) -> Option<&'a str> {
    let prefix = format!("\u{2014} {} ", key.name());
    let id = key.id().to_be_bytes();
    note.lines().filter(|l| l.starts_with(&prefix)).find(|l| {
        l.get(prefix.len()..)
            .and_then(|b64| suiss_crypto::note::base64_decode(b64).ok())
            .is_some_and(|raw| raw.get(..4) == Some(id.as_slice()))
    })
}

/// The cosignatures of configured witnesses in `note`, a cosigned copy of `stored` (OP-33).
///
/// # Errors
/// [`WitnessError::Note`], [`WitnessError::Equivocation`] or [`WitnessError::Uncosigned`].
pub fn cosignatures(
    note: &str,
    stored: &Checkpoint,
    log: &Verifier,
    witnesses: &[Witness],
) -> Result<Vec<CosignatureRow>, WitnessError> {
    let keys: Vec<Verifier> = witnesses.iter().map(|w| w.key.clone()).collect();
    let signed = verify_checkpoint(note, &stored.origin, log, &keys).map_err(WitnessError::Note)?;
    if signed.checkpoint != *stored {
        return Err(WitnessError::Equivocation(stored.size));
    }
    let mut rows = Vec::new();
    for accepted in &signed.cosignatures {
        let Some(witness) = witnesses
            .iter()
            .find(|w| w.key.name() == accepted.name && w.key.id() == accepted.id)
        else {
            continue;
        };
        let (Some(at), Some(line)) = (accepted.timestamp, line_of(note, &witness.key)) else {
            continue;
        };
        rows.push(CosignatureRow {
            size: stored.size,
            witness_id: witness.id.clone(),
            cosigned_at_ms: at.saturating_mul(1000),
            signature: line.as_bytes().to_vec(),
        });
    }
    if rows.is_empty() {
        Err(WitnessError::Uncosigned)
    } else {
        Ok(rows)
    }
}

impl Checkpointer {
    /// Takes the witness cosignatures in `note`, a cosigned copy of the stored checkpoint of
    /// `size` of `ledger`, once `replica` holds that size; returns how many were new.
    ///
    /// # Errors
    /// [`WitnessError`]; nothing is stored then.
    pub async fn take_cosignatures(
        &self,
        ledger: &LedgerId,
        size: u64,
        note: &str,
        replica: &DirectoryReplica,
        witnesses: &[Witness],
    ) -> Result<usize, WitnessError> {
        let pool = self.pool();
        let stored = pool
            .at(ledger, size)
            .await
            .map_err(CheckpointError::Store)?
            .ok_or(WitnessError::Unknown(size))?;
        let stored_note = std::str::from_utf8(&stored.signed_note)
            .map_err(|_| WitnessError::Note(NoteError::Malformed))?;
        let own = verify_checkpoint(stored_note, &self.origin(ledger), self.log_key(), &[])
            .map_err(WitnessError::Note)?;
        let mirrored = pool
            .mirrored(ledger, replica.id())
            .await
            .map_err(CheckpointError::Store)?;
        let mut order = Publication::default();
        order.built(size).map_err(WitnessError::Order)?;
        order.mirrored(mirrored).map_err(WitnessError::Order)?;
        order.may_witness(size).map_err(WitnessError::Order)?;
        let rows = cosignatures(note, &own.checkpoint, self.log_key(), witnesses)?;
        let mut new = 0_usize;
        for row in &rows {
            if pool
                .insert_cosignature(ledger, row)
                .await
                .map_err(CheckpointError::Store)?
            {
                new = new.saturating_add(1);
            }
        }
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use ed25519_dalek::SigningKey;
    use ed25519_dalek::ed25519::signature::Signer as _;
    use suiss_crypto::note::{base64_encode, cosigned_message};

    use super::*;

    const ORIGIN: &str = "work.example/ledger/ab12";

    fn checkpoint(root: u8) -> Checkpoint {
        Checkpoint {
            origin: ORIGIN.to_owned(),
            size: 3,
            root: [root; 32],
            extensions: Vec::new(),
        }
    }

    fn line(key: &SigningKey, v: &Verifier, message: &[u8], timestamp: Option<u64>) -> String {
        let mut raw = v.id().to_be_bytes().to_vec();
        if let Some(t) = timestamp {
            raw.extend_from_slice(&t.to_be_bytes());
        }
        raw.extend_from_slice(&key.sign(message).to_bytes());
        format!("\u{2014} {} {}\n", v.name(), base64_encode(&raw))
    }

    fn note(log: &SigningKey, witness: &SigningKey, cp: &Checkpoint) -> String {
        let body = cp.to_body().unwrap();
        let log_line = line(log, &log_key(log), body.as_bytes(), None);
        let cosign = line(
            witness,
            &witness_key(witness),
            &cosigned_message(1_792_749_601, &body),
            Some(1_792_749_601),
        );
        format!("{body}\n{log_line}{cosign}")
    }

    fn log_key(key: &SigningKey) -> Verifier {
        Verifier::ed25519("work.example", key.verifying_key().to_bytes()).unwrap()
    }

    fn witness_key(key: &SigningKey) -> Verifier {
        Verifier::cosigner("witness.example", key.verifying_key().to_bytes()).unwrap()
    }

    // OP-33 SEC-32 OP-4
    #[test]
    fn op_33_only_a_configured_witness_cosigning_the_stored_tree_is_taken() {
        let log = SigningKey::from_bytes(&[7; 32]);
        let witness = SigningKey::from_bytes(&[8; 32]);
        let configured = [Witness {
            id: "witness_a".to_owned(),
            key: witness_key(&witness),
        }];
        let stored = checkpoint(9);
        let rows = cosignatures(
            &note(&log, &witness, &stored),
            &stored,
            &log_key(&log),
            &configured,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].witness_id, "witness_a");
        assert_eq!(rows[0].size, 3);
        assert_eq!(rows[0].cosigned_at_ms, 1_792_749_601_000);
        assert!(
            rows[0]
                .signature
                .starts_with("\u{2014} witness.example ".as_bytes())
        );

        assert!(matches!(
            cosignatures(
                &note(&log, &witness, &checkpoint(10)),
                &stored,
                &log_key(&log),
                &configured
            ),
            Err(WitnessError::Equivocation(3))
        ));
        let stranger = SigningKey::from_bytes(&[11; 32]);
        assert!(matches!(
            cosignatures(
                &note(&log, &stranger, &stored),
                &stored,
                &log_key(&log),
                &configured
            ),
            Err(WitnessError::Uncosigned)
        ));
    }

    // OP-4 OP-33
    #[test]
    fn op_4_a_checkpoint_the_replica_does_not_hold_is_not_sent_to_witnesses() {
        let mut order = Publication::default();
        order.built(3).unwrap();
        order.mirrored(2).unwrap();
        assert_eq!(order.may_witness(3), Err(OrderError::NotMirrored));
        order.mirrored(3).unwrap();
        assert_eq!(order.may_witness(3), Ok(()));
    }
}
