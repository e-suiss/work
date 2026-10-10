//! Structured JSON logging for Work behind a thin facade (T-39, OP-18).

use std::io::Write;

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry, fmt};

/// Error returned when the global subscriber cannot be installed.
#[derive(Debug)]
pub struct InitError(tracing_subscriber::util::TryInitError);

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "telemetry init failed: {}", self.0)
    }
}

impl std::error::Error for InitError {}

/// Installs the process-wide JSON log subscriber.
///
/// `filter` uses `tracing` directive syntax (e.g. `info`, `work_server=debug`).
///
/// # Errors
/// Fails if a global subscriber is already installed.
pub fn init(filter: &str) -> Result<(), InitError> {
    init_with_writer(filter, std::io::stdout)
}

/// Installs the JSON log subscriber with a custom writer (used by tests).
///
/// # Errors
/// Fails if a global subscriber is already installed.
pub fn init_with_writer<W>(filter: &str, writer: W) -> Result<(), InitError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    Registry::default()
        .with(EnvFilter::new(filter))
        .with(
            fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_writer(writer),
        )
        .try_init()
        .map_err(InitError)
}

/// A writer that discards output.
#[derive(Clone, Copy, Debug, Default)]
pub struct Discard;

impl Write for Discard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
