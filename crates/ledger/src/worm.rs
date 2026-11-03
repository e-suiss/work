//! Write-once objects over S3 Object Lock (§18 OP-33 item 3, OP-35, OP-46 item 9): the bucket
//! is created with Object Lock and refused without it; an object is written only while its key
//! is free (`If-None-Match: *`), with its SHA-256 checksum and a compliance-mode retention that
//! lasts the configured number of days from the write; an existing key is never replaced, and a
//! write that finds the key holding other bytes is refused as diverged.

use http::{Method, StatusCode};
use sha2::{Digest as _, Sha256};
use suiss_crypto::note::base64_encode;

use crate::s3::{S3Client, S3Config, S3Error, rfc3339};

/// The Object Lock mode of every write: until it expires no account, the root account included,
/// can shorten the retention or remove the object.
pub const RETENTION_MODE: &str = "COMPLIANCE";

/// Longest retention in days, the S3 bound of 100 years.
pub const MAX_RETENTION_DAYS: u32 = 36_500;

const DAY_MS: u64 = 86_400_000;

/// How long each written object stays locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    days: u32,
}

impl Retention {
    /// A retention of `days`, 1 to [`MAX_RETENTION_DAYS`].
    ///
    /// # Errors
    /// [`WormError::Retention`] outside that range.
    pub fn days(days: u32) -> Result<Self, WormError> {
        if (1..=MAX_RETENTION_DAYS).contains(&days) {
            Ok(Self { days })
        } else {
            Err(WormError::Retention)
        }
    }

    /// The number of days.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.days
    }

    /// The retain-until date of an object written at `now_ms`.
    #[must_use]
    pub fn until(self, now_ms: u64) -> String {
        rfc3339(now_ms.saturating_add(u64::from(self.days).saturating_mul(DAY_MS)))
    }
}

/// Why a write-once store call did not succeed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WormError {
    /// The object store did not answer.
    #[error("object store: {0}")]
    Store(#[from] S3Error),
    /// The bucket does not have Object Lock enabled.
    #[error("bucket has no object lock")]
    Unlocked,
    /// The key already holds other bytes.
    #[error("object {0} holds other bytes")]
    Diverged(String),
    /// The retention is outside its range.
    #[error("retention must be 1 to {MAX_RETENTION_DAYS} days")]
    Retention,
    /// The object store refused with this status.
    #[error("object store answered {0}")]
    Status(u16),
}

/// A bucket with Object Lock that holds each key once.
#[derive(Debug)]
pub struct WormStore {
    client: S3Client,
    retention: Retention,
}

fn contains(body: &[u8], needle: &str) -> bool {
    body.windows(needle.len()).any(|w| w == needle.as_bytes())
}

impl WormStore {
    /// The store `config` names, locking each object for `retention`.
    ///
    /// # Errors
    /// [`WormError::Store`] for a malformed endpoint or bucket, or an `https` endpoint without
    /// TLS settings.
    pub fn new(config: S3Config, retention: Retention) -> Result<Self, WormError> {
        Ok(Self {
            client: S3Client::new(config)?,
            retention,
        })
    }

    /// The retention of each written object.
    #[must_use]
    pub const fn retention(&self) -> Retention {
        self.retention
    }

    /// Creates the bucket with Object Lock and checks that Object Lock is enabled on it.
    ///
    /// # Errors
    /// [`WormError::Unlocked`] for a bucket without Object Lock, otherwise [`WormError::Store`].
    pub async fn prepare(&self, now_ms: u64) -> Result<(), WormError> {
        let lock = [("x-amz-bucket-object-lock-enabled", "true".to_owned())];
        self.client.ensure_bucket(&lock, now_ms).await?;
        let path = self.client.bucket_path();
        let (status, body) = self
            .client
            .call(Method::GET, &path, "object-lock=", &[], Vec::new(), now_ms)
            .await?;
        let enabled = contains(&body, "<ObjectLockEnabled>Enabled</ObjectLockEnabled>");
        if status.is_success() && enabled {
            Ok(())
        } else {
            Err(WormError::Unlocked)
        }
    }

    /// Writes `bytes` under `key` once: a key that already holds the same bytes is left as it is.
    ///
    /// # Errors
    /// [`WormError::Diverged`] when `key` holds other bytes, otherwise [`WormError::Store`] or
    /// [`WormError::Status`].
    pub async fn put_once(&self, key: &str, bytes: &[u8], now_ms: u64) -> Result<(), WormError> {
        let path = self.client.object_path(key)?;
        let extra = [
            ("if-none-match", "*".to_owned()),
            ("x-amz-checksum-sha256", base64_encode(&Sha256::digest(bytes))),
            ("x-amz-object-lock-mode", RETENTION_MODE.to_owned()),
            ("x-amz-object-lock-retain-until-date", self.retention.until(now_ms)),
        ];
        let (status, _) = self
            .client
            .call(Method::PUT, &path, "", &extra, bytes.to_vec(), now_ms)
            .await?;
        if status.is_success() {
            return Ok(());
        }
        match self.get(key, now_ms).await? {
            Some(stored) if stored == bytes => Ok(()),
            Some(_) => Err(WormError::Diverged(key.to_owned())),
            None => Err(WormError::Status(status.as_u16())),
        }
    }

    /// The bytes under `key`, or `None` when the key is free.
    ///
    /// # Errors
    /// [`WormError::Store`] or [`WormError::Status`].
    pub async fn get(&self, key: &str, now_ms: u64) -> Result<Option<Vec<u8>>, WormError> {
        let path = self.client.object_path(key)?;
        let (status, bytes) = self
            .client
            .call(Method::GET, &path, "", &[], Vec::new(), now_ms)
            .await?;
        if status.is_success() {
            Ok(Some(bytes))
        } else if status == StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            Err(WormError::Status(status.as_u16()))
        }
    }

    /// Whether the object under `key` carries a compliance-mode retention.
    ///
    /// # Errors
    /// [`WormError::Store`].
    pub async fn locked(&self, key: &str, now_ms: u64) -> Result<bool, WormError> {
        let path = self.client.object_path(key)?;
        let (status, body) = self
            .client
            .call(Method::GET, &path, "retention=", &[], Vec::new(), now_ms)
            .await?;
        Ok(status.is_success() && contains(&body, "<Mode>COMPLIANCE</Mode>"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-33 OP-35
    #[test]
    fn op_33_objects_are_locked_in_compliance_mode_for_the_configured_days() {
        assert_eq!(RETENTION_MODE, "COMPLIANCE");
        assert_eq!(Retention::days(0), Err(WormError::Retention));
        assert_eq!(Retention::days(36_501), Err(WormError::Retention));
        let year = Retention::days(365).unwrap();
        assert_eq!(year.get(), 365);
        assert_eq!(year.until(1_440_938_160_000), "2016-08-29T12:36:00Z");
        assert_eq!(
            Retention::days(1).unwrap().until(951_696_000_000),
            "2000-02-29T00:00:00Z"
        );
        assert!(contains(b"<a><Mode>COMPLIANCE</Mode></a>", "<Mode>COMPLIANCE</Mode>"));
        assert!(!contains(b"<Mode>GOVERNANCE</Mode>", "<Mode>COMPLIANCE</Mode>"));
    }
}
