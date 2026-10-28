//! Structured JSON logging for Work behind a thin facade (T-39, OP-18). Telemetry is sampled,
//! lossy and never an audit source (OP-19, P-43): it links to records only by identifier, and the
//! [`ContentGuard`] and the [`RedactingJson`] format keep bodies, secrets and unstable `GenAI`
//! attributes out of every emitted line.

mod guard;
mod json;

use std::io::Write;

use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry, fmt};

pub use guard::{ContentGuard, FieldBan, declares_forbidden_field, forbidden_field};
pub use json::{REDACTED, RedactingFields, RedactingJson};

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
    subscriber(filter, writer).try_init().map_err(InitError)
}

/// The Work subscriber without installing it: the filter, the [`ContentGuard`] and the
/// redacting JSON log layer.
pub fn subscriber<W>(filter: &str, writer: W) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    Registry::default()
        .with(EnvFilter::new(filter))
        .with(ContentGuard)
        .with(log_layer(writer))
}

/// The redacting JSON log layer alone; every other layer goes behind a [`ContentGuard`].
pub fn log_layer<S, W>(writer: W) -> impl Layer<S> + Send + Sync + 'static
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    fmt::layer()
        .fmt_fields(RedactingFields)
        .event_format(RedactingJson)
        .with_writer(writer)
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
