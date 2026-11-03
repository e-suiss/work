//! The replica mirror (§18 OP-4 item 3, OP-33 item 3, OP-46 item 9, T-90, Access T21): every log
//! entry below the largest signed checkpoint goes to the replica with the signed bytes its record
//! was received as, the replica's own copy is read back and must give exactly that checkpoint's
//! root, and only then is the replica's progress recorded, which is what a witness request waits
//! for (mirror before witness). Each entry, received part, checkpoint and witness cosignature is
//! an object of its own under `<ledger hex>/`, written once and never replaced: in a directory on
//! a single node, or in an S3 bucket with Object Lock that refuses to replace or delete it.

use std::path::PathBuf;

use suiss_crypto::digest::leaf_hash;
use suiss_ledger::replica::{Follower, ReplicaError};
use work_kernel::proof::verify_checkpoint;
use work_store::{CheckpointRow, CosignatureRow, LedgerId, MirrorEntry};

use crate::{CheckpointError, Checkpointer, ClockError};

/// Why the replica did not advance.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MirrorError {
    /// The replica could not be read or written.
    #[error("replica i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The replica's object store refused or did not answer.
    #[error("replica object store: {0}")]
    Object(String),
    /// No trusted time to sign the object store request with (OP-6).
    #[error(transparent)]
    Time(ClockError),
    /// The replica holds other bytes than the log under a key it already wrote.
    #[error("replica holds other bytes at {0}")]
    Diverged(String),
    /// The replica misses an entry it reported as mirrored.
    #[error("replica misses position {0}")]
    Missing(u64),
    /// A log entry's envelope does not hash to its leaf.
    #[error("log entry {0} does not match its leaf hash")]
    Leaf(u64),
    /// The replica's tree does not give the checkpoint (shared engine).
    #[error("replica tree: {0}")]
    Tree(ReplicaError),
    /// The stored checkpoint is not valid UTF-8.
    #[error("stored checkpoint is not a note")]
    Note,
    /// The checkpointer or the store refused.
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
}

/// A replica target: write-once objects by key.
pub trait Replica: Send + Sync {
    /// The `replica_id` its progress is stored under.
    fn id(&self) -> &str;
    /// Makes the target ready to take objects.
    fn prepare(&self) -> impl Future<Output = Result<(), MirrorError>> + Send;
    /// Writes `bytes` under `key` once: a key that holds the same bytes is left as it is.
    fn put_once(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), MirrorError>> + Send;
    /// The bytes under `key`, or `None` when the replica has no such object.
    fn read(&self, key: &str) -> impl Future<Output = Result<Option<Vec<u8>>, MirrorError>> + Send;
}

fn name(n: u64) -> String {
    format!("{n:020}")
}

/// `<ledger hex>/log/<pos>`: the envelope bytes of the entry at `pos`.
#[must_use]
pub fn entry_key(ledger: &LedgerId, pos: u64) -> String {
    format!("{}/log/{}", ledger.to_hex(), name(pos))
}

/// `<ledger hex>/received/<pos>.<role>`: the signed bytes the record at `pos` was received with.
#[must_use]
pub fn received_key(ledger: &LedgerId, pos: u64, role: &str) -> String {
    format!("{}/received/{}.{role}", ledger.to_hex(), name(pos))
}

/// `<ledger hex>/checkpoint/<size>`: the signed note of the checkpoint of `size`.
#[must_use]
pub fn checkpoint_key(ledger: &LedgerId, size: u64) -> String {
    format!("{}/checkpoint/{}", ledger.to_hex(), name(size))
}

/// `<ledger hex>/cosignature/<size>.<witness id>`: a witness's cosignature line of that
/// checkpoint.
#[must_use]
pub fn cosignature_key(ledger: &LedgerId, size: u64, witness_id: &str) -> String {
    format!("{}/cosignature/{}.{witness_id}", ledger.to_hex(), name(size))
}

/// A replica in a directory, one file per key, positions and sizes as 20 decimal digits.
#[derive(Debug, Clone)]
pub struct DirectoryReplica {
    id: String,
    root: PathBuf,
}

impl DirectoryReplica {
    /// The replica `id` (the `replica_id` its progress is stored under) in `root`.
    #[must_use]
    pub fn new(id: &str, root: impl Into<PathBuf>) -> Self {
        Self {
            id: id.to_owned(),
            root: root.into(),
        }
    }

    fn path(&self, key: &str) -> PathBuf {
        key.split('/').fold(self.root.clone(), |p, part| p.join(part))
    }
}

impl Replica for DirectoryReplica {
    fn id(&self) -> &str {
        &self.id
    }

    async fn prepare(&self) -> Result<(), MirrorError> {
        Ok(tokio::fs::create_dir_all(&self.root).await?)
    }

    async fn put_once(&self, key: &str, bytes: &[u8]) -> Result<(), MirrorError> {
        let path = self.path(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let created = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await;
        match created {
            Ok(mut file) => {
                tokio::io::AsyncWriteExt::write_all(&mut file, bytes).await?;
                file.sync_all().await?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if tokio::fs::read(&path).await? == bytes {
                    Ok(())
                } else {
                    Err(MirrorError::Diverged(key.to_owned()))
                }
            }
            Err(e) => Err(MirrorError::Io(e)),
        }
    }

    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, MirrorError> {
        match tokio::fs::read(self.path(key)).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(MirrorError::Io(e)),
        }
    }
}

#[cfg(feature = "s3")]
pub use worm::WormReplica;

#[cfg(feature = "s3")]
mod worm {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{MirrorError, Replica};
    use crate::worm::{WormError, WormStore};
    use crate::{Clock, ClockError};

    type NowFuture = Pin<Box<dyn Future<Output = Result<u64, ClockError>> + Send>>;
    type Now = Arc<dyn Fn() -> NowFuture + Send + Sync>;

    fn object(e: WormError) -> MirrorError {
        match e {
            WormError::Diverged(key) => MirrorError::Diverged(key),
            other => MirrorError::Object(other.to_string()),
        }
    }

    /// A replica in an S3 bucket with Object Lock (§18 OP-33 item 3): each object is written
    /// once with a compliance-mode retention and can be neither replaced nor deleted while it
    /// lasts. Requests are signed at ledger time.
    pub struct WormReplica {
        id: String,
        store: WormStore,
        now: Now,
        prepared: AtomicBool,
    }

    impl std::fmt::Debug for WormReplica {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WormReplica")
                .field("id", &self.id)
                .field("store", &self.store)
                .finish_non_exhaustive()
        }
    }

    impl WormReplica {
        /// The replica `id` in `store`, signing at the time `clock` gives.
        #[must_use]
        pub fn new<C>(id: &str, store: WormStore, clock: C) -> Self
        where
            C: Clock + Clone + Sync + 'static,
        {
            let now: Now = Arc::new(move || -> NowFuture {
                let mut clock = clock.clone();
                Box::pin(async move { clock.now().await })
            });
            Self {
                id: id.to_owned(),
                store,
                now,
                prepared: AtomicBool::new(false),
            }
        }

        async fn time(&self) -> Result<u64, MirrorError> {
            (self.now)().await.map_err(MirrorError::Time)
        }

        async fn ready(&self) -> Result<u64, MirrorError> {
            let now = self.time().await?;
            if !self.prepared.load(Ordering::Acquire) {
                self.store.prepare(now).await.map_err(object)?;
                self.prepared.store(true, Ordering::Release);
            }
            Ok(now)
        }
    }

    impl Replica for WormReplica {
        fn id(&self) -> &str {
            &self.id
        }

        async fn prepare(&self) -> Result<(), MirrorError> {
            self.ready().await.map(|_| ())
        }

        async fn put_once(&self, key: &str, bytes: &[u8]) -> Result<(), MirrorError> {
            let now = self.ready().await?;
            self.store.put_once(key, bytes, now).await.map_err(object)
        }

        async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, MirrorError> {
            let now = self.time().await?;
            self.store.get(key, now).await.map_err(object)
        }
    }
}

/// The replica a process is configured with (§17 T-93 item 6); clones share one target.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnyReplica {
    /// A directory on a single node.
    Directory(DirectoryReplica),
    /// An S3 bucket with Object Lock.
    #[cfg(feature = "s3")]
    Worm(std::sync::Arc<WormReplica>),
}

impl From<DirectoryReplica> for AnyReplica {
    fn from(r: DirectoryReplica) -> Self {
        Self::Directory(r)
    }
}

#[cfg(feature = "s3")]
impl From<WormReplica> for AnyReplica {
    fn from(r: WormReplica) -> Self {
        Self::Worm(std::sync::Arc::new(r))
    }
}

impl Replica for AnyReplica {
    fn id(&self) -> &str {
        match self {
            Self::Directory(r) => r.id(),
            #[cfg(feature = "s3")]
            Self::Worm(r) => r.id(),
        }
    }

    async fn prepare(&self) -> Result<(), MirrorError> {
        match self {
            Self::Directory(r) => r.prepare().await,
            #[cfg(feature = "s3")]
            Self::Worm(r) => r.prepare().await,
        }
    }

    async fn put_once(&self, key: &str, bytes: &[u8]) -> Result<(), MirrorError> {
        match self {
            Self::Directory(r) => r.put_once(key, bytes).await,
            #[cfg(feature = "s3")]
            Self::Worm(r) => r.put_once(key, bytes).await,
        }
    }

    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, MirrorError> {
        match self {
            Self::Directory(r) => r.read(key).await,
            #[cfg(feature = "s3")]
            Self::Worm(r) => r.read(key).await,
        }
    }
}

/// Mirrors one log entry with its received signed bytes, the entry last.
///
/// # Errors
/// [`MirrorError`].
pub async fn put_entry(
    replica: &impl Replica,
    ledger: &LedgerId,
    entry: &MirrorEntry,
) -> Result<(), MirrorError> {
    for (role, bytes) in &entry.received {
        replica
            .put_once(&received_key(ledger, entry.pos, role), bytes)
            .await?;
    }
    replica
        .put_once(&entry_key(ledger, entry.pos), &entry.envelope_bytes)
        .await
}

/// The leaf hash of the envelope the replica holds at `pos`, read back from the replica.
///
/// # Errors
/// [`MirrorError::Missing`] when the replica has no entry there, otherwise [`MirrorError`].
pub async fn leaf(
    replica: &impl Replica,
    ledger: &LedgerId,
    pos: u64,
) -> Result<[u8; 32], MirrorError> {
    replica
        .read(&entry_key(ledger, pos))
        .await?
        .map(|bytes| leaf_hash(&bytes))
        .ok_or(MirrorError::Missing(pos))
}

/// Mirrors a signed checkpoint.
///
/// # Errors
/// [`MirrorError`].
pub async fn put_checkpoint(
    replica: &impl Replica,
    ledger: &LedgerId,
    row: &CheckpointRow,
) -> Result<(), MirrorError> {
    replica
        .put_once(&checkpoint_key(ledger, row.size), &row.signed_note)
        .await
}

/// Archives a witness cosignature line of a stored checkpoint.
///
/// # Errors
/// [`MirrorError`].
pub async fn put_cosignature(
    replica: &impl Replica,
    ledger: &LedgerId,
    row: &CosignatureRow,
) -> Result<(), MirrorError> {
    replica
        .put_once(&cosignature_key(ledger, row.size, &row.witness_id), &row.signature)
        .await
}

impl Checkpointer {
    /// Mirrors `ledger` to `replica` up to its largest signed checkpoint and records the
    /// replica's progress once the replica's own copy gives that checkpoint's root; returns the
    /// mirrored size.
    ///
    /// # Errors
    /// [`MirrorError`]; the stored progress does not move then.
    pub async fn mirror(
        &self,
        ledger: &LedgerId,
        replica: &impl Replica,
    ) -> Result<u64, MirrorError> {
        let pool = self.pool();
        let mirrored = pool
            .mirrored(ledger, replica.id())
            .await
            .map_err(CheckpointError::Store)?;
        let Some(latest) = pool.latest(ledger).await.map_err(CheckpointError::Store)? else {
            return Ok(mirrored);
        };
        if latest.size <= mirrored {
            return Ok(mirrored);
        }
        let origin = self.origin(ledger);
        let note = std::str::from_utf8(&latest.signed_note).map_err(|_| MirrorError::Note)?;
        let signed = verify_checkpoint(note, &origin, self.log_key(), &[])
            .map_err(|e| MirrorError::Checkpoint(CheckpointError::Note(e)))?;
        let mut follower = Follower::new(&origin);
        for pos in 0..mirrored {
            follower
                .append(leaf(replica, ledger, pos).await?)
                .map_err(MirrorError::Tree)?;
        }
        let entries = pool
            .entries(ledger, mirrored, latest.size)
            .await
            .map_err(CheckpointError::Store)?;
        for entry in &entries {
            if leaf_hash(&entry.envelope_bytes) != entry.leaf {
                return Err(MirrorError::Leaf(entry.pos));
            }
            put_entry(replica, ledger, entry).await?;
            follower
                .append(leaf(replica, ledger, entry.pos).await?)
                .map_err(MirrorError::Tree)?;
        }
        follower
            .accept(&signed.checkpoint, &[])
            .map_err(MirrorError::Tree)?;
        put_checkpoint(replica, ledger, &latest).await?;
        pool.record_mirrored(ledger, replica.id(), latest.size)
            .await
            .map_err(CheckpointError::Store)?;
        Ok(latest.size)
    }

    /// Archives in `replica` the stored witness cosignatures of the checkpoint of `size` of
    /// `ledger` (OP-2 checkpoint and witness archive); returns how many there are.
    ///
    /// # Errors
    /// [`MirrorError`].
    pub async fn archive_cosignatures(
        &self,
        ledger: &LedgerId,
        size: u64,
        replica: &impl Replica,
    ) -> Result<usize, MirrorError> {
        let rows = self
            .pool()
            .cosignatures(ledger, size)
            .await
            .map_err(CheckpointError::Store)?;
        for row in &rows {
            put_cosignature(replica, ledger, row).await?;
        }
        Ok(rows.len())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn replica(test: &str) -> DirectoryReplica {
        let root = std::env::temp_dir().join(format!("work-replica-{test}-{}", std::process::id()));
        DirectoryReplica::new("local", root)
    }

    // OP-4 T-90
    #[tokio::test]
    async fn op_4_a_mirrored_entry_and_its_received_bytes_are_written_once() {
        let r = replica("once");
        let ledger = LedgerId::from_bytes([3; 32]);
        let entry = MirrorEntry {
            pos: 5,
            leaf: leaf_hash(b"envelope"),
            envelope_bytes: b"envelope".to_vec(),
            received: vec![("author_signature".to_owned(), b"cose".to_vec())],
        };
        put_entry(&r, &ledger, &entry).await.unwrap();
        put_entry(&r, &ledger, &entry).await.unwrap();
        assert_eq!(leaf(&r, &ledger, 5).await.unwrap(), leaf_hash(b"envelope"));
        let changed = MirrorEntry {
            envelope_bytes: b"another".to_vec(),
            received: Vec::new(),
            ..entry.clone()
        };
        assert!(matches!(
            put_entry(&r, &ledger, &changed).await,
            Err(MirrorError::Diverged(_))
        ));
        let resigned = MirrorEntry {
            received: vec![("author_signature".to_owned(), b"other".to_vec())],
            ..entry
        };
        assert!(matches!(
            put_entry(&r, &ledger, &resigned).await,
            Err(MirrorError::Diverged(_))
        ));
        assert!(matches!(
            leaf(&r, &ledger, 6).await,
            Err(MirrorError::Missing(6))
        ));
    }

    // OP-2 OP-46 SEC-32
    #[tokio::test]
    async fn op_2_a_cosignature_is_archived_once_beside_its_checkpoint() {
        let r = replica("cosign");
        let ledger = LedgerId::from_bytes([4; 32]);
        let row = CosignatureRow {
            size: 2,
            witness_id: "witness_a".to_owned(),
            cosigned_at_ms: 1_000,
            signature: b"\xe2\x80\x94 witness.example AAAA".to_vec(),
        };
        put_cosignature(&r, &ledger, &row).await.unwrap();
        put_cosignature(&r, &ledger, &row).await.unwrap();
        let key = cosignature_key(&ledger, 2, "witness_a");
        assert_eq!(
            key,
            format!("{}/cosignature/00000000000000000002.witness_a", ledger.to_hex())
        );
        assert_eq!(r.read(&key).await.unwrap(), Some(row.signature.clone()));
        let other = CosignatureRow {
            signature: b"another line".to_vec(),
            ..row
        };
        assert!(matches!(
            put_cosignature(&r, &ledger, &other).await,
            Err(MirrorError::Diverged(k)) if k == key
        ));
        assert_eq!(
            entry_key(&ledger, 7),
            format!("{}/log/00000000000000000007", ledger.to_hex())
        );
        assert_eq!(
            received_key(&ledger, 7, "auth_context"),
            format!("{}/received/00000000000000000007.auth_context", ledger.to_hex())
        );
        assert_eq!(
            checkpoint_key(&ledger, 8),
            format!("{}/checkpoint/00000000000000000008", ledger.to_hex())
        );
    }
}
