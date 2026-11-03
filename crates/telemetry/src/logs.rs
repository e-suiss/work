//! OpenTelemetry logs (T-39 rules 1 and 4, OP-18 items 1 and 5, OP-19): the [`OtelLogLayer`]
//! turns each event into an OpenTelemetry log record with the redaction of the JSON log format,
//! so byte values and fields the content guard forbids are written as [`crate::REDACTED`]; the
//! record carries the level, the target, the message as its body, the remaining fields such as
//! `event` and `outcome` as attributes, and the trace context of the current span; `service`
//! and `version` are resource attributes. Export runs over OTLP/gRPC through a bounded batch
//! queue that drops instead of blocking.

use std::num::NonZeroUsize;

use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::logs::{
    BatchConfigBuilder, BatchLogProcessor, LogExporter, SdkLogger, SdkLoggerProvider,
};
use serde_json::Value;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::trace::{DEFAULT_MAX_QUEUE_SIZE, SCOPE, TraceConfig, TraceError, resource};

/// Targets of the export path itself, whose events never become log records, so exporting a
/// record cannot produce another one.
pub const EXPORT_TARGETS: &[&str] = &["opentelemetry", "tonic", "h2", "hyper", "tower"];

fn export_path(target: &str) -> bool {
    EXPORT_TARGETS.iter().any(|t| {
        target
            .strip_prefix(t)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '_']))
    })
}

/// Log export settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogConfig {
    /// The `service.name` resource attribute.
    pub service: String,
    /// The `service.version` resource attribute.
    pub version: String,
    /// The OTLP/gRPC collector endpoint; `None` installs no exporter.
    pub endpoint: Option<String>,
    /// The batch queue bound; records beyond it are dropped, never waited for.
    pub max_queue_size: NonZeroUsize,
}

impl From<&TraceConfig> for LogConfig {
    fn from(config: &TraceConfig) -> Self {
        Self {
            service: config.service.clone(),
            version: config.version.clone(),
            endpoint: config.endpoint.clone(),
            max_queue_size: config.max_queue_size,
        }
    }
}

impl LogConfig {
    /// Settings for `service` at `version` with no exporter and the default queue bound.
    #[must_use]
    pub fn local(service: &str, version: &str) -> Self {
        Self {
            service: service.to_owned(),
            version: version.to_owned(),
            endpoint: None,
            max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
        }
    }
}

/// The logger provider with any log exporter behind a bounded batch queue; used directly by
/// tests with an in-memory exporter.
#[must_use]
pub fn logger_provider_with_exporter<E>(
    config: &LogConfig,
    exporter: Option<E>,
) -> SdkLoggerProvider
where
    E: LogExporter + 'static,
{
    let builder =
        SdkLoggerProvider::builder().with_resource(resource(&config.service, &config.version));
    match exporter {
        Some(exporter) => builder
            .with_log_processor(
                BatchLogProcessor::builder(exporter)
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

/// The logger provider for `config`: OTLP/gRPC export when an endpoint is set, none otherwise.
///
/// # Errors
/// Fails when an endpoint is set outside a Tokio runtime or the exporter rejects it.
pub fn logger_provider(config: &LogConfig) -> Result<SdkLoggerProvider, TraceError> {
    let Some(endpoint) = &config.endpoint else {
        return Ok(logger_provider_with_exporter::<opentelemetry_otlp::LogExporter>(config, None));
    };
    tokio::runtime::Handle::try_current().map_err(|_| TraceError::NoRuntime)?;
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()?;
    Ok(logger_provider_with_exporter(config, Some(exporter)))
}

/// The layer that writes each event as an OpenTelemetry log record of one logger provider.
///
/// It goes behind a [`crate::ContentGuard`], which disables events that declare a forbidden
/// field before this layer sees them; the values it writes are redacted like the JSON log.
#[derive(Clone, Debug)]
pub struct OtelLogLayer {
    logger: SdkLogger,
}

/// The [`OtelLogLayer`] of `provider`.
#[must_use]
pub fn otel_log_layer(provider: &SdkLoggerProvider) -> OtelLogLayer {
    OtelLogLayer {
        logger: provider.logger(SCOPE),
    }
}

fn severity(level: Level) -> Severity {
    if level == Level::ERROR {
        Severity::Error
    } else if level == Level::WARN {
        Severity::Warn
    } else if level == Level::INFO {
        Severity::Info
    } else if level == Level::DEBUG {
        Severity::Debug
    } else {
        Severity::Trace
    }
}

fn any(value: Value) -> AnyValue {
    match value {
        Value::Bool(b) => AnyValue::Boolean(b),
        Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => AnyValue::Int(i),
            (None, Some(f)) => AnyValue::Double(f),
            (None, None) => AnyValue::String(n.to_string().into()),
        },
        Value::String(s) => AnyValue::String(s.into()),
        other => AnyValue::String(other.to_string().into()),
    }
}

impl<S: Subscriber> Layer<S> for OtelLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if export_path(metadata.target()) {
            return;
        }
        let mut record = self.logger.create_log_record();
        record.set_target(metadata.target());
        record.set_severity_number(severity(*metadata.level()));
        record.set_severity_text(metadata.level().as_str());
        for (name, value) in crate::json::record(event) {
            if name == "message" {
                record.set_body(any(value));
            } else {
                record.add_attribute(name, any(value));
            }
        }
        self.logger.emit(record);
    }
}
