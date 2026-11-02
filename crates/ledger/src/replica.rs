//! The replica mirror (§18 OP-4 item 3, OP-33, T-90, Access T21): every log entry below the
//! largest signed checkpoint goes to the replica with the signed bytes its record was received
//! as, the replica's own copy is read back and must give exactly that checkpoint's root, and only
//! then is the replica's progress recorded, which is what a witness request waits for (mirror
//! before witness). The directory replica keeps each entry, received part and checkpoint in a
//! file of its own that is written once and never replaced.

use std::path::PathBuf;

use suiss_crypto::digest::leaf_hash;
use suiss_ledger::replica::{Follower, ReplicaError};
use work_kernel::proof::verify_checkpoint;
use work_store::{CheckpointRow, LedgerId, MirrorEntry};

use crate::{CheckpointError, Checkpointer};

/// Why the replica did not advance.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MirrorError {
    /// The replica could not be read or written.
    #[error("replica i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The replica holds other bytes than the log at a path it already wrote.
    #[error("replica holds other bytes at {0}")]
    Diverged(PathBuf),
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

/// A replica in a directory: `<ledger hex>/log/<pos>` holds the envelope bytes,
/// `<ledger hex>/received/<pos>.<role>` the received signed bytes and
/// `<ledger hex>/checkpoint/<size>` the signed note, positions and sizes as 20 decimal digits.
#[derive(Debug, Clone)]
pub struct DirectoryReplica {
    id: String,
    root: PathBuf,
}

fn name(n: u64) -> String {
    format!("{n:020}")
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

    /// The replica id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    fn dir(&self, ledger: &LedgerId, part: &str) -> PathBuf {
        self.root.join(ledger.to_hex()).join(part)
    }

    /// Writes `bytes` to `path` once: an existing file must hold the same bytes.
    ///
    /// # Errors
    /// [`MirrorError::Diverged`] or [`MirrorError::Io`].
    pub async fn put(&self, path: PathBuf, bytes: &[u8]) -> Result<(), MirrorError> {
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
                    Err(MirrorError::Diverged(path))
                }
            }
            Err(e) => Err(MirrorError::Io(e)),
        }
    }

    /// Mirrors one log entry with its received signed bytes.
    ///
    /// # Errors
    /// [`MirrorError`].
    pub async fn put_entry(
        &self,
        ledger: &LedgerId,
        entry: &MirrorEntry,
    ) -> Result<(), MirrorError> {
        for (role, bytes) in &entry.received {
            let path = self
                .dir(ledger, "received")
                .join(format!("{}.{role}", name(entry.pos)));
            self.put(path, bytes).await?;
        }
        let path = self.dir(ledger, "log").join(name(entry.pos));
        self.put(path, &entry.envelope_bytes).await
    }

    /// Mirrors a signed checkpoint.
    ///
    /// # Errors
    /// [`MirrorError`].
    pub async fn put_checkpoint(
        &self,
        ledger: &LedgerId,
        row: &CheckpointRow,
    ) -> Result<(), MirrorError> {
        let path = self.dir(ledger, "checkpoint").join(name(row.size));
        self.put(path, &row.signed_note).await
    }

    /// The leaf hash of the envelope the replica holds at `pos`.
    ///
    /// # Errors
    /// [`MirrorError::Missing`] or [`MirrorError::Io`].
    pub async fn leaf(&self, ledger: &LedgerId, pos: u64) -> Result<[u8; 32], MirrorError> {
        let path = self.dir(ledger, "log").join(name(pos));
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(leaf_hash(&bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(MirrorError::Missing(pos)),
            Err(e) => Err(MirrorError::Io(e)),
        }
    }
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
        replica: &DirectoryReplica,
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
                .append(replica.leaf(ledger, pos).await?)
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
            replica.put_entry(ledger, entry).await?;
            follower
                .append(replica.leaf(ledger, entry.pos).await?)
                .map_err(MirrorError::Tree)?;
        }
        follower
            .accept(&signed.checkpoint, &[])
            .map_err(MirrorError::Tree)?;
        replica.put_checkpoint(ledger, &latest).await?;
        pool.record_mirrored(ledger, replica.id(), latest.size)
            .await
            .map_err(CheckpointError::Store)?;
        Ok(latest.size)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn replica(test: &str) -> DirectoryReplica {
        let root = std::env::temp_dir()
            .join(format!("work-replica-{test}-{}", std::process::id()));
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
        r.put_entry(&ledger, &entry).await.unwrap();
        r.put_entry(&ledger, &entry).await.unwrap();
        assert_eq!(r.leaf(&ledger, 5).await.unwrap(), leaf_hash(b"envelope"));
        let changed = MirrorEntry {
            envelope_bytes: b"another".to_vec(),
            received: Vec::new(),
            ..entry.clone()
        };
        assert!(matches!(
            r.put_entry(&ledger, &changed).await,
            Err(MirrorError::Diverged(_))
        ));
        let resigned = MirrorEntry {
            received: vec![("author_signature".to_owned(), b"other".to_vec())],
            ..entry
        };
        assert!(matches!(
            r.put_entry(&ledger, &resigned).await,
            Err(MirrorError::Diverged(_))
        ));
        assert!(matches!(
            r.leaf(&ledger, 6).await,
            Err(MirrorError::Missing(6))
        ));
    }
}
