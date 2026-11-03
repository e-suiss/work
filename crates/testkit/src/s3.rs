use std::time::Duration;

use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use crate::{TestkitError, compose_image};

const PORT: u16 = 7070;

/// The access key id of the test object store.
pub const S3_KEY_ID: &str = "work-test";

/// The secret access key of the test object store; a test-only value.
pub const S3_SECRET: &str = "local-only-not-a-secret";

/// An S3-compatible object store, versitygw over a container-local POSIX directory (T-20,
/// OP-33 item 5).
pub struct S3 {
    container: ContainerAsync<GenericImage>,
    endpoint: String,
}

impl std::fmt::Debug for S3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3")
            .field("container", &self.container.id())
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl S3 {
    /// Starts the object store and waits until it accepts connections.
    ///
    /// # Errors
    ///
    /// [`TestkitError`] if the image is not pinned or the container does not start.
    pub async fn start() -> Result<Self, TestkitError> {
        let container = compose_image("s3")?
            .generic()
            .with_exposed_port(PORT.tcp())
            .with_env_var("ROOT_ACCESS_KEY", S3_KEY_ID)
            .with_env_var("ROOT_SECRET_KEY", S3_SECRET)
            .with_cmd(["--port", ":7070", "posix", "/tmp"])
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(PORT.tcp()).await?;
        let address = format!("{host}:{port}");
        let mut ready = false;
        for _ in 0..240 {
            let probe = tokio::time::timeout(
                Duration::from_secs(1),
                tokio::net::TcpStream::connect(address.as_str()),
            )
            .await;
            if matches!(probe, Ok(Ok(_))) {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if !ready {
            return Err(TestkitError::NotReady { service: "s3" });
        }
        Ok(Self {
            container,
            endpoint: format!("http://{address}"),
        })
    }

    /// `http://host:port`.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}
