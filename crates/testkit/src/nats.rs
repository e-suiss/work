use std::time::Duration;

use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, Healthcheck, ImageExt};

use crate::{TestkitError, compose_image};

const PORT: u16 = 4222;
const MONITOR: u16 = 8222;

/// A NATS server with JetStream enabled (T-36 rule 7).
pub struct Nats {
    container: ContainerAsync<GenericImage>,
    url: String,
}

impl std::fmt::Debug for Nats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nats")
            .field("container", &self.container.id())
            .field("url", &self.url)
            .finish()
    }
}

impl Nats {
    /// Starts NATS with JetStream on a container-local store.
    ///
    /// # Errors
    ///
    /// [`TestkitError`] if the image is not pinned or the container does not start.
    pub async fn start() -> Result<Self, TestkitError> {
        let container = compose_image("nats")?
            .generic()
            .with_exposed_port(PORT.tcp())
            .with_wait_for(WaitFor::healthcheck())
            .with_cmd(["--jetstream", "--store_dir", "/data", "--http_port", "8222"])
            .with_health_check(
                Healthcheck::cmd([
                    "wget",
                    "-q",
                    "-O-",
                    &format!("http://127.0.0.1:{MONITOR}/healthz?js-enabled-only=true"),
                ])
                .with_interval(Duration::from_millis(250))
                .with_timeout(Duration::from_secs(3))
                .with_retries(240),
            )
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(PORT.tcp()).await?;
        Ok(Self {
            container,
            url: format!("nats://{host}:{port}"),
        })
    }

    /// Client URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// A new client connection.
    ///
    /// # Errors
    ///
    /// [`TestkitError::NatsConnect`] if the server does not answer.
    pub async fn connect(&self) -> Result<async_nats::Client, TestkitError> {
        Ok(async_nats::connect(&self.url).await?)
    }

    /// A JetStream context over a new connection.
    ///
    /// # Errors
    ///
    /// [`TestkitError::NatsConnect`] if the server does not answer.
    pub async fn jetstream(&self) -> Result<async_nats::jetstream::Context, TestkitError> {
        Ok(async_nats::jetstream::new(self.connect().await?))
    }
}
