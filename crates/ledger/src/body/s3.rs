//! The body store's S3-compatible adapter (§17 T-20, OP-2): `PUT` and `GET` of ciphertexts by
//! their content address through the shared signed client.

use http::Method;

use super::{BodyError, ObjectStore};
use crate::s3::{S3Client, S3Config, S3Error};

impl From<S3Error> for BodyError {
    fn from(e: S3Error) -> Self {
        match e {
            S3Error::Timeout => Self::Timeout,
            S3Error::Failed(m) => Self::Object(m),
        }
    }
}

/// An S3-compatible object store (T-20).
#[derive(Debug)]
pub struct S3Store {
    client: S3Client,
}

impl S3Store {
    /// The store `config` names.
    ///
    /// # Errors
    /// [`BodyError::Object`] for a malformed endpoint or bucket, or an `https` endpoint without
    /// TLS settings.
    pub fn new(config: S3Config) -> Result<Self, BodyError> {
        Ok(Self {
            client: S3Client::new(config)?,
        })
    }

    /// Creates the bucket; an existing bucket of this owner is not an error.
    ///
    /// # Errors
    /// [`BodyError::Object`] for any other answer.
    pub async fn ensure_bucket(&self, now_ms: u64) -> Result<(), BodyError> {
        Ok(self.client.ensure_bucket(&[], now_ms).await?)
    }
}

impl ObjectStore for S3Store {
    async fn put(&self, key: &str, bytes: Vec<u8>, now_ms: u64) -> Result<(), BodyError> {
        let path = self.client.object_path(key)?;
        let (status, _) = self
            .client
            .call(Method::PUT, &path, "", &[], bytes, now_ms)
            .await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(BodyError::Object(format!("put: {status}")))
        }
    }

    async fn get(&self, key: &str, now_ms: u64) -> Result<Vec<u8>, BodyError> {
        let path = self.client.object_path(key)?;
        let (status, bytes) = self
            .client
            .call(Method::GET, &path, "", &[], Vec::new(), now_ms)
            .await?;
        if status.is_success() {
            Ok(bytes)
        } else {
            Err(BodyError::Object(format!("get: {status}")))
        }
    }
}
