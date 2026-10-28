//! Structured JSON logging and OpenTelemetry traces for Work behind a thin facade (T-39, OP-18).
//! Telemetry is sampled, lossy and never an audit source (OP-19, P-43): it links to records only
//! by identifier, and the [`ContentGuard`], the [`RedactingJson`] format and the
//! [`GuardedExporter`] keep bodies, secrets and unstable `GenAI` attributes out of every emitted
//! line and exported span.

mod guard;
mod json;
mod propagation;
mod trace;

use std::io::Write;

use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry, fmt};

pub use guard::{
    CONTENT_PAIRS, CONTENT_WORDS, ContentGuard, FieldBan, GENAI_PREFIX, declares_forbidden_field,
    forbidden_field,
};
pub use json::{REDACTED, RedactingFields, RedactingJson};
pub use propagation::{
    Extractor, Injector, InvalidTraceParent, SetParentError, TRACEPARENT, TraceParent,
    continue_trace, inject, traceparent,
};
pub use trace::{
    DEFAULT_MAX_QUEUE_SIZE, GuardedExporter, InvalidSampleRatio, SCOPE, SampleRatio, TraceConfig,
    TraceError, guard_span, provider, provider_with_exporter, trace_layer,
};

/// Error returned when telemetry cannot be installed.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// A global subscriber is already installed.
    #[error("telemetry init failed: {0}")]
    Subscriber(#[from] tracing_subscriber::util::TryInitError),
    /// Trace export could not be set up.
    #[error("telemetry init failed: {0}")]
    Trace(#[from] TraceError),
}

/// Installed telemetry; dropping the last handle flushes and stops trace export.
#[derive(Debug)]
pub struct Telemetry {
    provider: SdkTracerProvider,
}

impl Telemetry {
    /// The tracer provider.
    #[must_use]
    pub fn provider(&self) -> &SdkTracerProvider {
        &self.provider
    }
}

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
    subscriber(filter, writer)
        .try_init()
        .map_err(InitError::from)
}

/// Installs the process-wide JSON log subscriber and the trace layer of `config`.
///
/// With an endpoint it must run inside an entered Tokio runtime; export happens on a background
/// thread through a bounded queue and never blocks a request.
///
/// # Errors
/// Fails if trace export cannot be set up or a global subscriber is already installed.
pub fn init_with_traces(filter: &str, config: &TraceConfig) -> Result<Telemetry, InitError> {
    let provider = provider(config)?;
    traced_subscriber(filter, std::io::stdout, &provider).try_init()?;
    Ok(Telemetry { provider })
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

/// [`subscriber`] with the trace layer of `provider` behind the same [`ContentGuard`].
pub fn traced_subscriber<W>(
    filter: &str,
    writer: W,
    provider: &SdkTracerProvider,
) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    Registry::default()
        .with(EnvFilter::new(filter))
        .with(ContentGuard)
        .with(log_layer(writer))
        .with(trace_layer(provider))
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
