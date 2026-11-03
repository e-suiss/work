use std::time::Duration;

use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::TestkitError;
use crate::database::exec;

const PORT: u16 = 7380;

/// The image `deploy/compose/witness` builds: litewitness and witnessctl of
/// `filippo.io/torchwood` v0.10.0 (OP-33 item 5, OP-46 item 10).
pub const WITNESS_IMAGE: (&str, &str) = ("work-dev/witness", "local");

/// The witness name its cosignatures carry.
pub const WITNESS_NAME: &str = "witness.localhost";

const VKEY_FILE: &str = "/run/litewitness-public/witness.vkey";

/// A C2SP `tlog-witness` witness, litewitness over a container-local `SQLite` database, that
/// knows the logs it was started with and signs with a key it made when it started.
pub struct LiteWitness {
    container: ContainerAsync<GenericImage>,
    url: String,
    vkey: String,
}

impl std::fmt::Debug for LiteWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiteWitness")
            .field("container", &self.container.id())
            .field("url", &self.url)
            .field("vkey", &self.vkey)
            .finish()
    }
}

async fn answers(address: &str) -> bool {
    let Ok(mut stream) = tokio::net::TcpStream::connect(address).await else {
        return false;
    };
    if stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.is_err() {
        return false;
    }
    let mut head = [0_u8; 5];
    stream.read_exact(&mut head).await.is_ok() && head == *b"HTTP/"
}

impl LiteWitness {
    /// Starts the witness with `logs`, each an origin and the log's verifier key, and waits
    /// until it answers HTTP.
    ///
    /// # Errors
    ///
    /// [`TestkitError`] if the container does not start or does not answer.
    pub async fn start(logs: &[(&str, &str)]) -> Result<Self, TestkitError> {
        let entries: Vec<String> = logs.iter().map(|(o, k)| format!("{o} {k}")).collect();
        let (name, tag) = WITNESS_IMAGE;
        let container = GenericImage::new(name, tag)
            .with_exposed_port(PORT.tcp())
            .with_env_var("WITNESS_NAME", WITNESS_NAME)
            .with_env_var("WITNESS_LOGS", entries.join(";"))
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(PORT.tcp()).await?;
        let address = format!("{host}:{port}");
        let mut ready = false;
        for _ in 0..240 {
            if tokio::time::timeout(Duration::from_secs(1), answers(&address))
                .await
                .is_ok_and(|a| a)
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if !ready {
            return Err(TestkitError::NotReady { service: "witness" });
        }
        let vkey = exec(&container, &["cat", VKEY_FILE], &[])
            .await?
            .trim()
            .to_owned();
        Ok(Self {
            container,
            url: format!("http://{address}"),
            vkey,
        })
    }

    /// `http://host:port`, the submission prefix.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The `tlog-cosignature/v1` verifier key of the key the witness made when it started.
    #[must_use]
    pub fn vkey(&self) -> &str {
        &self.vkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPOSE: &str = include_str!("../../../deploy/compose/compose.yaml");

    // T-36 T-41 OP-33 OP-48
    #[test]
    fn t_41_the_test_witness_is_the_image_the_local_environment_builds() {
        let (name, tag) = WITNESS_IMAGE;
        let service = COMPOSE.split("\n  witness:\n").nth(1).unwrap_or_default();
        let service = service.split("\n  # ").next().unwrap_or_default();
        assert!(service.contains("build: ./witness"), "{service}");
        assert!(
            service.contains(&format!("image: {name}:{tag}")),
            "{service}"
        );
        assert!(
            service.contains(&format!("WITNESS_NAME: {WITNESS_NAME}")),
            "{service}"
        );
    }
}
