use std::path::PathBuf;

/// Failure to start or prepare a test dependency.
#[derive(Debug, thiserror::Error)]
pub enum TestkitError {
    /// The compose file names no digest-pinned image for the service.
    #[error("deploy/compose/compose.yaml pins no image digest for `{service}`")]
    ImageNotPinned {
        /// Compose service name.
        service: &'static str,
    },
    /// Docker refused or failed a container operation.
    #[error("container: {0}")]
    Container(#[from] testcontainers::TestcontainersError),
    /// A command inside a container exited unsuccessfully.
    #[error("`{command}` exited with {code:?}: {stderr}")]
    Exec {
        /// The command line.
        command: String,
        /// Exit code, if the command finished.
        code: Option<i64>,
        /// Captured standard error.
        stderr: String,
    },
    /// The migrations directory could not be read.
    #[error("migrations directory {path}: {source}")]
    Migrations {
        /// The directory.
        path: PathBuf,
        /// The I/O failure.
        source: std::io::Error,
    },
    /// The database copy counter ran out.
    #[error("database name counter overflowed")]
    Exhausted,
    /// Connecting to NATS failed.
    #[error("nats connect: {0}")]
    NatsConnect(#[from] async_nats::ConnectError),
}
