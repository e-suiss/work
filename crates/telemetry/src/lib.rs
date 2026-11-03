//! Structured JSON logging and OpenTelemetry traces, metrics and logs for Work behind a thin
//! facade (T-39, OP-18). Telemetry is sampled, lossy and never an audit source (OP-19, P-43): it
//! links to records only by identifier, and the [`ContentGuard`], the [`RedactingJson`] format,
//! the [`OtelLogLayer`] and the [`GuardedExporter`] keep bodies, secrets and unstable `GenAI`
//! attributes out of every emitted line, log record and exported span, while metric labels come
//! only from the bounded [`Label`] set.

mod guard;
mod json;
mod logs;
mod metrics;
mod propagation;
mod trace;

use std::io::Write;

use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
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
pub use logs::{
    EXPORT_TARGETS, LogConfig, OtelLogLayer, logger_provider, logger_provider_with_exporter,
    otel_log_layer,
};
pub use metrics::{
    DEFAULT_METRIC_INTERVAL, IDENTIFIER_WORDS, Label, MetricConfig, Meters, REBUILD_DIFF,
    WorkCounter, WorkGauge, forbidden_label, meter_provider, meter_provider_with_exporter,
};
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
    /// Trace, metric or log export could not be set up.
    #[error("telemetry init failed: {0}")]
    Trace(#[from] TraceError),
}

/// Installed telemetry; dropping the last handle flushes and stops trace, metric and log export.
#[derive(Debug)]
pub struct Telemetry {
    provider: SdkTracerProvider,
    meters: SdkMeterProvider,
    logs: Option<SdkLoggerProvider>,
}

impl Telemetry {
    /// The tracer provider.
    #[must_use]
    pub fn provider(&self) -> &SdkTracerProvider {
        &self.provider
    }

    /// The meter provider.
    #[must_use]
    pub fn meter_provider(&self) -> &SdkMeterProvider {
        &self.meters
    }

    /// The Work instruments.
    #[must_use]
    pub fn meters(&self) -> Meters {
        Meters::new(&self.meters)
    }

    /// The logger provider, when log records are exported.
    #[must_use]
    pub fn logger_provider(&self) -> Option<&SdkLoggerProvider> {
        self.logs.as_ref()
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
    let meters = meter_provider_with_exporter::<opentelemetry_otlp::MetricExporter>(
        &MetricConfig::from(config),
        None,
    );
    traced_subscriber(filter, std::io::stdout, &provider).try_init()?;
    Ok(Telemetry {
        provider,
        meters,
        logs: None,
    })
}

/// Installs the process-wide JSON log subscriber with the trace layer, the OpenTelemetry log
/// layer and the meter provider of `config`, all three exporting to its endpoint.
///
/// With an endpoint it must run inside an entered Tokio runtime; export happens on background
/// threads through bounded queues and never blocks a request.
///
/// # Errors
/// Fails if export cannot be set up or a global subscriber is already installed.
pub fn init_with_otel(filter: &str, config: &TraceConfig) -> Result<Telemetry, InitError> {
    let provider = provider(config)?;
    let meters = meter_provider(&MetricConfig::from(config))?;
    let logs = logger_provider(&LogConfig::from(config))?;
    otel_subscriber(filter, std::io::stdout, &provider, &logs).try_init()?;
    Ok(Telemetry {
        provider,
        meters,
        logs: Some(logs),
    })
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

/// [`traced_subscriber`] with the OpenTelemetry log layer of `logs` behind the same
/// [`ContentGuard`].
pub fn otel_subscriber<W>(
    filter: &str,
    writer: W,
    provider: &SdkTracerProvider,
    logs: &SdkLoggerProvider,
) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    Registry::default()
        .with(EnvFilter::new(filter))
        .with(ContentGuard)
        .with(log_layer(writer))
        .with(trace_layer(provider))
        .with(otel_log_layer(logs))
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
