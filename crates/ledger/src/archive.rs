//! The cold archive of the monthly partitions (§18 OP-35, OP-34 item 5, OP-36 item 2, OP-37,
//! OP-38 item 4, OP-12 rule 4, Access OP-73 rule 4): each ledger's slice of a cold partition of
//! `work.idempotency_key` or `work.inbound_seen` is copied to a bucket with Object Lock as the
//! row text the database digests, read back, checked against the slice digest and for its
//! compliance-mode retention, and recorded; only when every slice has its record does the archive
//! role drop the partition, and the drop function checks the records and the manifest again.
//! Requests are signed at the database clock, the clock the drop function judges coldness by.

use sha2::{Digest as _, Sha256};
use work_store::{ArchivePool, ArchiveRecord, LedgerId, StoreError};

use crate::body::hex;
use crate::worm::{WormError, WormStore};

/// Why a cold partition was not archived; the partition stays then.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArchiveError {
    /// The database refused or failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The bucket refused or failed.
    #[error("archive bucket: {0}")]
    Worm(#[from] WormError),
    /// The slice's rows do not give the count and digest the database computed.
    #[error("slice of {0} in {1} does not match its digest")]
    Slice(String, String),
    /// The copy read back is not the slice, or it is not under compliance-mode retention.
    #[error("copy {0} did not verify")]
    Unverified(String),
}

/// `archive/<partition>/<ledger hex>`: the key of a ledger's slice of a cold partition.
#[must_use]
pub fn archive_key(part: &str, ledger: &LedgerId) -> String {
    format!("archive/{part}/{}", ledger.to_hex())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The manifest the drop function recomputes: SHA-256 over `<ledger hex>:<rows>:<digest hex>`
/// lines in ledger order, joined by line feeds.
#[must_use]
pub fn archive_manifest(slices: &[(LedgerId, u64, [u8; 32])]) -> [u8; 32] {
    let mut lines: Vec<String> = slices
        .iter()
        .map(|(ledger, n, d)| format!("{}:{n}:{}", ledger.to_hex(), hex(d)))
        .collect();
    lines.sort();
    sha256(lines.join("\n").as_bytes())
}

/// Copies, verifies and records every slice of the cold partition `part` in `store`, then drops
/// the partition; returns the rows dropped.
///
/// # Errors
/// [`ArchiveError`]; the partition is not dropped then.
pub async fn archive_partition(
    pool: &ArchivePool,
    store: &WormStore,
    part: &str,
) -> Result<u64, ArchiveError> {
    let now = pool.now_ms().await?;
    let mut slices = Vec::new();
    for ledger in pool.ledgers(part).await? {
        let slice = pool.slice(part, &ledger).await?;
        let bytes = slice.rows.join("\n").into_bytes();
        let digest = sha256(&bytes);
        let count = u64::try_from(slice.rows.len()).unwrap_or(u64::MAX);
        if digest != slice.digest || count != slice.row_count {
            return Err(ArchiveError::Slice(ledger.to_hex(), part.to_owned()));
        }
        let key = archive_key(part, &ledger);
        store.put_once(&key, &bytes, now).await?;
        let back = store.get(&key, now).await?;
        if back.as_deref().map(sha256) != Some(digest) || !store.locked(&key, now).await? {
            return Err(ArchiveError::Unverified(key));
        }
        let record = ArchiveRecord {
            object_key: key,
            copy_digest: digest,
            row_count: count,
        };
        pool.record(part, &ledger, &record).await?;
        slices.push((ledger, count, digest));
    }
    Ok(pool
        .drop_partition(part, &archive_manifest(&slices))
        .await?)
}

/// Archives every cold partition; returns each dropped partition with its rows.
///
/// # Errors
/// [`ArchiveError`] at the first partition that does not archive; those before it are dropped.
pub async fn archive_cold(
    pool: &ArchivePool,
    store: &WormStore,
) -> Result<Vec<(String, u64)>, ArchiveError> {
    let mut dropped = Vec::new();
    for part in pool.cold_partitions().await? {
        let rows = archive_partition(pool, store, &part).await?;
        dropped.push((part, rows));
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-35 OP-12
    #[test]
    fn op_35_the_manifest_is_the_drop_functions_digest_over_ledger_ordered_lines() {
        let a = LedgerId::from_bytes([0xa1; 32]);
        let b = LedgerId::from_bytes([0x0b; 32]);
        let one = (a, 3, [0x11; 32]);
        let two = (b, 2, [0x22; 32]);
        assert_eq!(archive_manifest(&[one, two]), archive_manifest(&[two, one]));
        let text = format!(
            "{}:2:{}\n{}:3:{}",
            "0b".repeat(32),
            "22".repeat(32),
            "a1".repeat(32),
            "11".repeat(32)
        );
        assert_eq!(archive_manifest(&[one, two]), sha256(text.as_bytes()));
        assert_eq!(
            hex(&archive_manifest(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            archive_key("work.idempotency_key_p202607", &a),
            format!("archive/work.idempotency_key_p202607/{}", "a1".repeat(32))
        );
        assert!(crate::s3::key_ok(&archive_key(
            "work.inbound_seen_p202612",
            &b
        )));
    }
}
