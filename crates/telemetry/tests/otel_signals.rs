//! Metrics and log records leave the process like spans do: metric labels come only from the
//! bounded set and the rebuild-diff counter has none, and a log record carries the redacted
//! fields and the trace context of its span but never a forbidden field (T-39, OP-18, OP-19,
//! OP-47).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use opentelemetry::logs::{AnyValue, Severity};
use opentelemetry::trace::{TraceContextExt as _, TraceId};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogBatch, LogExporter};
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use work_telemetry::{
    DEFAULT_MAX_QUEUE_SIZE, DEFAULT_METRIC_INTERVAL, Discard, Label, LogConfig, Meters,
    MetricConfig, REBUILD_DIFF, REDACTED, SampleRatio, TraceConfig, forbidden_label,
    logger_provider_with_exporter, meter_provider_with_exporter, otel_subscriber, provider,
};

const CANARY: &[u8] = b"CANARY-41f0aa-record-bytes";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Point {
    name: String,
    unit: String,
    value: u64,
    labels: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default)]
struct Points(Arc<Mutex<Vec<Point>>>);

impl Points {
    fn named(&self, name: &str) -> Vec<Point> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|p| p.name == name)
            .cloned()
            .collect()
    }
}

fn labels<'a>(
    attributes: impl Iterator<Item = &'a opentelemetry::KeyValue>,
) -> Vec<(String, String)> {
    attributes
        .map(|kv| (kv.key.as_str().to_owned(), kv.value.as_str().into_owned()))
        .collect()
}

impl PushMetricExporter for Points {
    fn export(
        &self,
        metrics: &ResourceMetrics,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        let mut out = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        for scope in metrics.scope_metrics() {
            for metric in scope.metrics() {
                let points: Vec<(u64, Vec<(String, String)>)> = match metric.data() {
                    AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                        .data_points()
                        .map(|p| (p.value(), labels(p.attributes())))
                        .collect(),
                    AggregatedMetrics::U64(MetricData::Gauge(gauge)) => gauge
                        .data_points()
                        .map(|p| (p.value(), labels(p.attributes())))
                        .collect(),
                    _ => Vec::new(),
                };
                out.extend(points.into_iter().map(|(value, labels)| Point {
                    name: metric.name().to_owned(),
                    unit: metric.unit().to_owned(),
                    value,
                    labels,
                }));
            }
        }
        drop(out);
        std::future::ready(Ok(()))
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        Ok(())
    }

    fn temporality(&self) -> Temporality {
        Temporality::Cumulative
    }
}

fn metric_config() -> MetricConfig {
    MetricConfig {
        service: "work-server".to_owned(),
        version: "0.0.0-test".to_owned(),
        endpoint: None,
        interval: DEFAULT_METRIC_INTERVAL,
    }
}

// T-39 OP-18 T-93
#[test]
fn t_39_exported_metrics_carry_only_bounded_labels() {
    let points = Points::default();
    let provider = meter_provider_with_exporter(&metric_config(), Some(points.clone()));
    Meters::new(&provider)
        .gauge("work.dependency.up", "1", "A dependency answers.")
        .record(0, &[(Label::Dependency, "nats")]);
    provider.force_flush().unwrap();

    let exported = points.named("work.dependency.up");
    assert_eq!(exported.len(), 1, "{exported:?}");
    assert_eq!(
        exported[0].labels,
        [("dependency".to_owned(), "nats".to_owned())]
    );
    for (key, _) in &exported[0].labels {
        assert!(!forbidden_label(key), "{key}");
    }
}

// OP-47 OP-18 T-39
#[test]
fn op_47_a_sev_1_rebuild_diff_is_counted_without_labels() {
    let points = Points::default();
    let provider = meter_provider_with_exporter(&metric_config(), Some(points.clone()));
    Meters::new(&provider).rebuild_diff().add(1, &[]);
    provider.force_flush().unwrap();

    let exported = points.named(REBUILD_DIFF);
    assert_eq!(
        exported,
        [Point {
            name: REBUILD_DIFF.to_owned(),
            unit: "{diff}".to_owned(),
            value: 1,
            labels: Vec::new(),
        }]
    );
}

#[derive(Clone, Debug)]
struct Logged {
    body: Option<AnyValue>,
    attributes: Vec<(String, AnyValue)>,
    severity: Option<Severity>,
    trace: Option<TraceId>,
}

#[derive(Clone, Debug, Default)]
struct Records(Arc<Mutex<Vec<Logged>>>);

impl Records {
    fn all(&self) -> Vec<Logged> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl LogExporter for Records {
    fn export(
        &self,
        batch: LogBatch<'_>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        let mut out = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        for (record, _scope) in batch.iter() {
            out.push(Logged {
                body: record.body().cloned(),
                attributes: record
                    .attributes_iter()
                    .map(|(k, v)| (k.as_str().to_owned(), v.clone()))
                    .collect(),
                severity: record.severity_number(),
                trace: record.trace_context().map(|c| c.trace_id),
            });
        }
        drop(out);
        std::future::ready(Ok(()))
    }
}

fn attribute<'a>(logged: &'a Logged, key: &str) -> Option<&'a AnyValue> {
    logged
        .attributes
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

fn text(value: &str) -> AnyValue {
    AnyValue::String(value.to_owned().into())
}

// T-39 OP-18 OP-19 P-43
#[test]
fn t_39_log_records_carry_redacted_fields_and_the_span_trace() {
    let records = Records::default();
    let logs = logger_provider_with_exporter(
        &LogConfig::local("work-server", "0.0.0-test"),
        Some(records.clone()),
    );
    let traces = provider(&TraceConfig {
        service: "work-server".to_owned(),
        version: "0.0.0-test".to_owned(),
        endpoint: None,
        sample_ratio: SampleRatio::ALWAYS,
        max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
    })
    .unwrap();
    let subscriber = otel_subscriber("trace", || Discard, &traces, &logs);
    let trace = tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("admit", record = "rec_01");
        span.in_scope(|| {
            tracing::info!(
                event = "record.admitted",
                outcome = "accept",
                record = "rec_01",
                digest = CANARY,
                "admitted"
            );
            tracing::warn!(body = "never exported", "content field");
            tracing::Span::current()
                .context()
                .span()
                .span_context()
                .trace_id()
        })
    });
    logs.force_flush().unwrap();

    let all = records.all();
    assert_eq!(all.len(), 1, "{all:?}");
    let logged = &all[0];
    assert_eq!(logged.body, Some(text("admitted")));
    assert_eq!(logged.severity, Some(Severity::Info));
    assert_eq!(attribute(logged, "event"), Some(&text("record.admitted")));
    assert_eq!(attribute(logged, "outcome"), Some(&text("accept")));
    assert_eq!(attribute(logged, "record"), Some(&text("rec_01")));
    assert_eq!(attribute(logged, "digest"), Some(&text(REDACTED)));
    assert_ne!(trace, TraceId::INVALID);
    assert_eq!(logged.trace, Some(trace));
    let canary = String::from_utf8_lossy(CANARY);
    assert!(
        !format!("{all:?}").contains(canary.as_ref()),
        "record bytes leaked into a log record: {all:?}"
    );
}
