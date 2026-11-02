//! The ledger acknowledgement (P-20, T-7, T-88, §18 OP-4, OP-33, OP-46): the checkpointer builds
//! the C2SP `tlog-checkpoint` of a ledger's head with the shared engine, with the ledger's
//! durability profile and the installation's declared time sources and witnesses as its three
//! profile lines, has `work-signer` sign its body over the signer's Unix socket, verifies the
//! signed note with the kernel against the log key the signer reported, and stores it as
//! `work_checkpointer`. A stored checkpoint makes every record below its size `included`; the
//! log key's signature is never an author signature, and the note is not a `COSE_Sign1`, so no
//! record verifier accepts it.

use std::path::PathBuf;
use std::time::Duration;

use suiss_ledger::merkle::Frontier;
use suiss_ledger::sequencer::Head;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::time::timeout;
use work_kernel::proof::{
    Checkpoint, DurabilityProfile, NoteError, Profile, TimeSources, Verifier, WitnessProfile,
    verify_checkpoint,
};
use work_proto::signer::{self as frames, FrameError, Kind, Status};
use work_store::{CheckpointRow, CheckpointerPool, Durability, LedgerId, StoreError};

/// Where the installation runs, which bounds what its checkpoints may declare (OP-33 item 1,
/// OP-46 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Deployment {
    /// The Suiss-operated service.
    Saas,
    /// A self-hosted or local installation.
    SelfHost,
}

/// Why a profile declaration is refused at start-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DeclarationError {
    /// A `SaaS` installation declares fewer than two independent witnesses (OP-33 item 1).
    #[error("a SaaS installation declares at least two independent witnesses")]
    Witnesses,
    /// A `SaaS` installation declares dependent time sources (OP-32 item 5).
    #[error("a SaaS installation declares independent time sources")]
    TimeSources,
}

/// The configured part of a checkpoint's profile: the declared time sources and witnesses; the
/// durability line comes from the ledger's stored profile (OP-46 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Declaration {
    time_sources: TimeSources,
    witness: WitnessProfile,
}

impl Declaration {
    /// A declaration for a `deployment`; `SaaS` takes only `time_sources independent` and
    /// `witness independent k` with k at least 2.
    ///
    /// # Errors
    /// [`DeclarationError`].
    pub fn new(
        deployment: Deployment,
        time_sources: TimeSources,
        witness: WitnessProfile,
    ) -> Result<Self, DeclarationError> {
        if deployment == Deployment::Saas {
            if !matches!(witness, WitnessProfile::Independent(k) if k.get() >= 2) {
                return Err(DeclarationError::Witnesses);
            }
            if time_sources != TimeSources::Independent {
                return Err(DeclarationError::TimeSources);
            }
        }
        Ok(Self {
            time_sources,
            witness,
        })
    }

    /// The declared time sources.
    #[must_use]
    pub const fn time_sources(&self) -> TimeSources {
        self.time_sources
    }

    /// The declared witnesses.
    #[must_use]
    pub const fn witness(&self) -> WitnessProfile {
        self.witness
    }

    /// The profile of a checkpoint of a ledger with `durability`.
    #[must_use]
    pub const fn profile(&self, durability: Durability) -> Profile {
        Profile {
            durability: match durability {
                Durability::Quorum => DurabilityProfile::Quorum,
                Durability::SingleNode => DurabilityProfile::SingleNode,
            },
            time_sources: self.time_sources,
            witness: self.witness,
        }
    }
}

/// Why no checkpoint was stored.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointError {
    /// The signer's socket could not be reached or the exchange broke off.
    #[error("signer unreachable: {0}")]
    Unreachable(std::io::Error),
    /// The signer did not answer within the limit.
    #[error("signer did not answer in time")]
    Timeout,
    /// The signer's answer is not a well-formed frame.
    #[error("signer frame: {0}")]
    Frame(FrameError),
    /// The signer refused, with its reason code.
    #[error("signer refused: {0}")]
    Refused(String),
    /// The checkpoint could not be built, or the signed note does not verify under the log key
    /// as the checkpoint that was asked for; the shared crate's code (T-88).
    #[error("checkpoint: {}", .0.code())]
    Note(NoteError),
    /// The stored head does not fit the engine.
    #[error("stored head does not fit the engine")]
    Head,
    /// The store refused.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A client of `work-signer`'s socket; every exchange runs under one time limit.
#[derive(Debug, Clone)]
pub struct SignerClient {
    socket: PathBuf,
    limit: Duration,
}

impl SignerClient {
    /// A client of the signer listening on `socket`.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>, limit: Duration) -> Self {
        Self {
            socket: socket.into(),
            limit,
        }
    }

    async fn exchange(&self, kind: Kind, payload: &[u8]) -> Result<Vec<u8>, CheckpointError> {
        let request = frames::frame(kind.as_byte(), payload).map_err(CheckpointError::Frame)?;
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .map_err(CheckpointError::Unreachable)?;
        stream
            .write_all(&request)
            .await
            .map_err(CheckpointError::Unreachable)?;
        let mut head = [0_u8; frames::HEADER];
        stream
            .read_exact(&mut head)
            .await
            .map_err(CheckpointError::Unreachable)?;
        let header = frames::header(head).map_err(CheckpointError::Frame)?;
        let mut answer = vec![0_u8; header.len];
        stream
            .read_exact(&mut answer)
            .await
            .map_err(CheckpointError::Unreachable)?;
        match Status::from_byte(header.code) {
            Some(Status::Signed) => Ok(answer),
            Some(Status::Refused) => Err(CheckpointError::Refused(
                String::from_utf8_lossy(&answer).into_owned(),
            )),
            None => Err(CheckpointError::Frame(FrameError::Status)),
        }
    }

    async fn call(&self, kind: Kind, payload: &[u8]) -> Result<Vec<u8>, CheckpointError> {
        timeout(self.limit, self.exchange(kind, payload))
            .await
            .map_err(|_| CheckpointError::Timeout)?
    }

    /// The signer's log key as a note verifier.
    ///
    /// # Errors
    /// [`CheckpointError`].
    pub async fn log_key(&self) -> Result<Verifier, CheckpointError> {
        let answer = self.call(Kind::LogKey, &[]).await?;
        let (public, name) = frames::parse_log_key(&answer).map_err(CheckpointError::Frame)?;
        Verifier::ed25519(&name, public).map_err(CheckpointError::Note)
    }

    /// The signer's note signature line over a checkpoint body.
    ///
    /// # Errors
    /// [`CheckpointError`].
    pub async fn sign_checkpoint(&self, body: &str) -> Result<String, CheckpointError> {
        let answer = self.call(Kind::Checkpoint, body.as_bytes()).await?;
        String::from_utf8(answer).map_err(|_| CheckpointError::Frame(FrameError::Text))
    }
}

/// The signed note of `body` and the signer's `line`, after it verified under `log` as the
/// checkpoint `expected` of `origin` (T-88 item 2).
///
/// # Errors
/// [`NoteError`]: a signature or syntax code, or `checkpoint-malformed` when the note is another
/// checkpoint than the one asked for.
pub fn acknowledgement(
    expected: &Checkpoint,
    line: &str,
    origin: &str,
    log: &Verifier,
) -> Result<String, NoteError> {
    let body = expected.to_body()?;
    let note = format!("{body}\n{line}");
    let signed = verify_checkpoint(&note, origin, log, &[])?;
    if signed.checkpoint == *expected {
        Ok(note)
    } else {
        Err(NoteError::Checkpoint)
    }
}

/// Builds, signs, verifies and stores the checkpoints of the ledgers of one installation.
#[derive(Debug)]
pub struct Checkpointer {
    pool: CheckpointerPool,
    signer: SignerClient,
    log: Verifier,
    origin_prefix: String,
    declaration: Declaration,
}

impl Checkpointer {
    /// A checkpointer for ledgers whose origin is `origin_prefix` followed by the ledger id in
    /// hex, whose checkpoints declare `declaration`; it asks the signer for its log key once.
    ///
    /// # Errors
    /// [`CheckpointError`].
    pub async fn connect(
        pool: CheckpointerPool,
        signer: SignerClient,
        origin_prefix: &str,
        declaration: Declaration,
    ) -> Result<Self, CheckpointError> {
        let log = signer.log_key().await?;
        Ok(Self {
            pool,
            signer,
            log,
            origin_prefix: origin_prefix.to_owned(),
            declaration,
        })
    }

    /// What the checkpoints declare besides the durability profile.
    #[must_use]
    pub const fn declaration(&self) -> &Declaration {
        &self.declaration
    }

    /// The checkpoint origin of `ledger`.
    #[must_use]
    pub fn origin(&self, ledger: &LedgerId) -> String {
        format!("{}{}", self.origin_prefix, ledger.to_hex())
    }

    pub(crate) const fn pool(&self) -> &CheckpointerPool {
        &self.pool
    }

    /// The log key checkpoints verify under.
    #[must_use]
    pub const fn log_key(&self) -> &Verifier {
        &self.log
    }

    /// Checkpoints the head of `ledger` at ledger time `now_ms`, unless the largest stored
    /// checkpoint already covers it; returns the stored checkpoint, or `None` when there was
    /// nothing new.
    ///
    /// # Errors
    /// [`CheckpointError`]; nothing is stored then.
    pub async fn checkpoint(
        &self,
        ledger: &LedgerId,
        now_ms: u64,
    ) -> Result<Option<CheckpointRow>, CheckpointError> {
        let snapshot = self.pool.head(ledger).await?;
        let size = snapshot.pos.checked_add(1).ok_or(CheckpointError::Head)?;
        if self
            .pool
            .latest(ledger)
            .await?
            .is_some_and(|c| c.size >= size)
        {
            return Ok(None);
        }
        let head = Head {
            pos: snapshot.pos,
            leaf: snapshot.leaf,
            recorded_at: snapshot.recorded_at_ms,
            frontier: Frontier::from_parts(size, snapshot.frontier)
                .map_err(|_| CheckpointError::Head)?,
        };
        let profile = self
            .declaration
            .profile(self.pool.durability(ledger).await?);
        let origin = self.origin(ledger);
        let expected = suiss_ledger::checkpoint::of_head(&origin, &head, profile.to_extensions())
            .map_err(CheckpointError::Note)?;
        let body = expected.to_body().map_err(CheckpointError::Note)?;
        let line = self.signer.sign_checkpoint(&body).await?;
        let note =
            acknowledgement(&expected, &line, &origin, &self.log).map_err(CheckpointError::Note)?;
        let row = CheckpointRow {
            size,
            root: expected.root,
            head_leaf: head.leaf,
            issued_at_ms: now_ms.max(head.recorded_at),
            signed_note: note.into_bytes(),
        };
        if self.pool.insert(ledger, &row).await? {
            Ok(Some(row))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use ed25519_dalek::SigningKey;
    use ed25519_dalek::ed25519::signature::Signer as _;
    use suiss_crypto::note::base64_encode;
    use work_kernel::cose::{KeySet, verify_record_signature};

    use super::*;

    const ORIGIN: &str =
        "work.example/ledger/abababababababababababababababababababababababababababababababab";

    fn local() -> Declaration {
        Declaration::new(
            Deployment::SelfHost,
            TimeSources::Dependent,
            WitnessProfile::LocalDependent,
        )
        .unwrap()
    }

    fn checkpoint(size: u64) -> Checkpoint {
        Checkpoint {
            origin: ORIGIN.to_owned(),
            size,
            root: [9; 32],
            extensions: local().profile(Durability::SingleNode).to_extensions(),
        }
    }

    fn line(key: &SigningKey, log: &Verifier, body: &str) -> String {
        let mut raw = log.id().to_be_bytes().to_vec();
        raw.extend_from_slice(&key.sign(body.as_bytes()).to_bytes());
        format!("\u{2014} {} {}\n", log.name(), base64_encode(&raw))
    }

    fn log(key: &SigningKey) -> Verifier {
        Verifier::ed25519("work.example", key.verifying_key().to_bytes()).unwrap()
    }

    // P-20 T-88 OP-4
    #[test]
    fn p_20_the_acknowledgement_is_the_log_signed_checkpoint_asked_for() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let cp = checkpoint(3);
        let signed = line(&key, &log(&key), &cp.to_body().unwrap());
        let note = acknowledgement(&cp, &signed, ORIGIN, &log(&key)).unwrap();
        assert!(note.starts_with(&cp.to_body().unwrap()));

        let other = SigningKey::from_bytes(&[8; 32]);
        assert_eq!(
            acknowledgement(
                &cp,
                &line(&other, &log(&key), &cp.to_body().unwrap()),
                ORIGIN,
                &log(&key)
            )
            .unwrap_err()
            .code(),
            "signature-invalid"
        );
        assert_eq!(
            acknowledgement(
                &checkpoint(4),
                &line(&key, &log(&key), &checkpoint(4).to_body().unwrap()),
                "work.example/ledger/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                &log(&key)
            )
            .unwrap_err(),
            NoteError::Checkpoint
        );
    }

    // P-20
    #[test]
    fn p_20_a_ledger_acknowledgement_never_verifies_as_an_author_signature() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let cp = checkpoint(3);
        let signed = line(&key, &log(&key), &cp.to_body().unwrap());
        let note = acknowledgement(&cp, &signed, ORIGIN, &log(&key)).unwrap();
        assert!(verify_record_signature(note.as_bytes(), &KeySet::default()).is_err());
    }

    // OP-46 P-20 T-88
    #[test]
    fn op_46_the_acknowledgement_declares_the_profile_asked_for() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let cp = checkpoint(3);
        assert_eq!(
            cp.extensions,
            [
                "durability single-node",
                "time_sources dependent",
                "witness local-dependent",
            ]
        );
        let claimed = Checkpoint {
            extensions: vec![
                "durability quorum".to_owned(),
                "time_sources independent".to_owned(),
                "witness independent 2".to_owned(),
            ],
            ..cp.clone()
        };
        let signed = line(&key, &log(&key), &claimed.to_body().unwrap());
        assert_eq!(
            acknowledgement(&cp, &signed, ORIGIN, &log(&key))
                .unwrap_err()
                .code(),
            "signature-invalid"
        );
        let bare = Checkpoint {
            extensions: Vec::new(),
            ..cp
        };
        let signed = line(&key, &log(&key), &bare.to_body().unwrap());
        assert_eq!(
            acknowledgement(&bare, &signed, ORIGIN, &log(&key)).unwrap_err(),
            NoteError::Checkpoint
        );
    }

    // OP-46 OP-33 OP-32
    #[test]
    fn op_46_saas_declares_independent_time_and_at_least_two_witnesses() {
        let k = |n| WitnessProfile::Independent(std::num::NonZeroU8::new(n).unwrap());
        let independent = TimeSources::Independent;
        let local_or_none = [
            k(1),
            WitnessProfile::LocalDependent,
            WitnessProfile::Undeclared,
        ];
        assert!(Declaration::new(Deployment::Saas, independent, k(2)).is_ok());
        assert!(Declaration::new(Deployment::Saas, independent, k(255)).is_ok());
        for witness in local_or_none {
            assert_eq!(
                Declaration::new(Deployment::Saas, independent, witness),
                Err(DeclarationError::Witnesses)
            );
        }
        assert_eq!(
            Declaration::new(Deployment::Saas, TimeSources::Dependent, k(2)),
            Err(DeclarationError::TimeSources)
        );
        for witness in local_or_none {
            let declared = Declaration::new(Deployment::SelfHost, TimeSources::Dependent, witness);
            assert_eq!(declared.map(|d| d.witness()), Ok(witness));
        }
        assert_eq!(
            local().profile(Durability::Quorum).durability,
            DurabilityProfile::Quorum
        );
    }
}
