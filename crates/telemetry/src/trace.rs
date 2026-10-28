//! OpenTelemetry trace export (T-39 rule 1, OP-18 rule 2, OP-19, P-43): traces are sampled, lossy
//! telemetry exported over OTLP/gRPC through a bounded batch queue that drops instead of blocking,
//! with the [`GuardedExporter`] in front of the exporter so a forbidden attribute never leaves the
//! process; with no endpoint there is no exporter and spans still carry a trace context.

use std::fmt;
use std::num::NonZeroUsize;

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider, SpanData, SpanExporter,
};
use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::registry::LookupSpan;

use crate::guard::forbidden_field;

/// The instrumentation scope name of Work spans.
pub const SCOPE: &str = "work";

/// The batch queue bound used unless configured otherwise (the OpenTelemetry SDK default).
pub const DEFAULT_MAX_QUEUE_SIZE: NonZeroUsize = match NonZeroUsize::new(2048) {
    Some(size) => size,
    None => NonZeroUsize::MIN,
};

/// The share of new root traces that are sampled, in `0.0..=1.0` (OP-18 rule 2).
///
/// Sampling applies to telemetry only: a trace context exists for every span whether or not it
/// is sampled, so records always receive a `traceparent` (P-42).
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct SampleRatio(f64);

impl SampleRatio {
    /// Every root trace is sampled.
    pub const ALWAYS: Self = Self(1.0);
    /// No root trace is sampled; continued traces follow the caller's decision.
    pub const NEVER: Self = Self(0.0);
    /// The policy default: one new root trace in ten is sampled (§18 OP-40 rule 2).
    pub const DEFAULT: Self = Self(0.1);

    /// A ratio in `0.0..=1.0`.
    ///
    /// # Errors
    /// Fails for a value outside `0.0..=1.0` or NaN.
    pub fn new(ratio: f64) -> Result<Self, InvalidSampleRatio> {
        if (0.0..=1.0).contains(&ratio) {
            Ok(Self(ratio))
        } else {
            Err(InvalidSampleRatio)
        }
    }

    /// The ratio.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }

    /// The sampler: a continued trace keeps the caller's decision (T-39 rule 2) and a new root
    /// trace is sampled by trace id at this ratio.
    #[must_use]
    pub fn sampler(self) -> Sampler {
        Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(self.0)))
    }
}

/// A sample ratio outside `0.0..=1.0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("trace sample ratio must be within 0.0..=1.0")]
pub struct InvalidSampleRatio;

/// Trace export settings.
#[derive(Clone, Debug, PartialEq)]
pub struct TraceConfig {
    /// The `service.name` resource attribute.
    pub service: String,
    /// The `service.version` resource attribute.
    pub version: String,
    /// The OTLP/gRPC collector endpoint; `None` installs no exporter.
    pub endpoint: Option<String>,
    /// The share of new root traces that are exported.
    pub sample_ratio: SampleRatio,
    /// The batch queue bound; spans beyond it are dropped, never waited for.
    pub max_queue_size: NonZeroUsize,
}

/// Why trace export could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    /// An endpoint is configured but no Tokio runtime is entered.
    #[error("trace export needs an entered Tokio runtime")]
    NoRuntime,
    /// The OTLP exporter rejected its configuration.
    #[error("trace exporter: {0}")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),
}

fn resource(config: &TraceConfig) -> Resource {
    Resource::builder_empty()
        .with_attributes([
            KeyValue::new("service.name", config.service.clone()),
            KeyValue::new("service.version", config.version.clone()),
        ])
        .build()
}

/// The tracer provider with any span exporter behind the [`GuardedExporter`] and a bounded batch
/// queue; used directly by tests with an in-memory exporter.
#[must_use]
pub fn provider_with_exporter<E>(config: &TraceConfig, exporter: Option<E>) -> SdkTracerProvider
where
    E: SpanExporter + 'static,
{
    let builder = SdkTracerProvider::builder()
        .with_sampler(config.sample_ratio.sampler())
        .with_resource(resource(config));
    match exporter {
        Some(exporter) => builder
            .with_span_processor(
                BatchSpanProcessor::builder(GuardedExporter(exporter))
                    .with_batch_config(
                        BatchConfigBuilder::default()
                            .with_max_queue_size(config.max_queue_size.get())
                            .build(),
                    )
                    .build(),
            )
            .build(),
        None => builder.build(),
    }
}

/// The tracer provider for `config`: OTLP/gRPC export when an endpoint is set, none otherwise.
///
/// # Errors
/// Fails when an endpoint is set outside a Tokio runtime or the exporter rejects it.
pub fn provider(config: &TraceConfig) -> Result<SdkTracerProvider, TraceError> {
    let Some(endpoint) = &config.endpoint else {
        return Ok(provider_with_exporter::<opentelemetry_otlp::SpanExporter>(
            config, None,
        ));
    };
    tokio::runtime::Handle::try_current().map_err(|_| TraceError::NoRuntime)?;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()?;
    Ok(provider_with_exporter(config, Some(exporter)))
}

/// The `tracing` layer that turns spans into OpenTelemetry spans of `provider`.
///
/// It goes behind a [`crate::ContentGuard`], which disables spans and events that declare a
/// forbidden field before this layer sees them.
#[must_use]
pub fn trace_layer<S>(provider: &SdkTracerProvider) -> impl Layer<S> + Send + Sync + 'static
where
    S: Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
{
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(SCOPE))
        .with_threads(false)
}

/// A span exporter wrapper that removes every attribute [`forbidden_field`] rejects from spans,
/// span events and links before the inner exporter sees them (OP-19, P-43, SEC-35 rule 4).
pub struct GuardedExporter<E>(pub E);

impl<E: fmt::Debug> fmt::Debug for GuardedExporter<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GuardedExporter").field(&self.0).finish()
    }
}

fn keep(attributes: &mut Vec<KeyValue>) -> u32 {
    let before = attributes.len();
    attributes.retain(|kv| forbidden_field(kv.key.as_str()).is_none());
    u32::try_from(before.saturating_sub(attributes.len())).unwrap_or(u32::MAX)
}

/// The span with forbidden attributes removed and counted as dropped.
#[must_use]
pub fn guard_span(mut span: SpanData) -> SpanData {
    let dropped = keep(&mut span.attributes);
    span.dropped_attributes_count = span.dropped_attributes_count.saturating_add(dropped);
    for event in &mut span.events.events {
        let dropped = keep(&mut event.attributes);
        event.dropped_attributes_count = event.dropped_attributes_count.saturating_add(dropped);
    }
    for link in &mut span.links.links {
        let dropped = keep(&mut link.attributes);
        link.dropped_attributes_count = link.dropped_attributes_count.saturating_add(dropped);
    }
    span
}

impl<E: SpanExporter> SpanExporter for GuardedExporter<E> {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        self.0.export(batch.into_iter().map(guard_span).collect())
    }

    fn shutdown_with_timeout(&self, timeout: std::time::Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.0.set_resource(resource);
    }
}
