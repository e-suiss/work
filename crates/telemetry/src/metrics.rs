//! OpenTelemetry metrics (T-39 rules 1 and 5, OP-18 items 1, 3 and 5): instruments come from
//! [`Meters`], whose label keys are the closed [`Label`] set and whose label values are fixed at
//! compile time, so a tenant, organization, ledger, Work, Party or record identifier can never
//! become a label; export runs over OTLP/gRPC from a periodic reader, and with no endpoint the
//! instruments record into a provider without a reader.

use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, Meter, MeterProvider as _};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

use crate::guard::forbidden_field;
use crate::trace::{SCOPE, TraceConfig, TraceError, resource};

/// How often the periodic reader exports, unless configured otherwise.
pub const DEFAULT_METRIC_INTERVAL: Duration = Duration::from_secs(60);

/// The counter of sev-1 rebuild-diff results (§18 OP-47 item 9, OP-1).
pub const REBUILD_DIFF: &str = "work.ledger.rebuild_diff";

/// Field-name words that name an identifier, which no metric label may carry (OP-18 item 3).
pub const IDENTIFIER_WORDS: &[&str] = &[
    "tenant",
    "tenants",
    "org",
    "orgs",
    "organization",
    "organizations",
    "organisation",
    "organisations",
    "ledger",
    "ledgers",
    "work",
    "works",
    "party",
    "parties",
    "record",
    "records",
    "rec",
    "commitment",
    "commitments",
    "condition",
    "conditions",
    "item",
    "items",
    "correlation",
    "id",
    "ids",
    "uuid",
];

/// A metric label key from the bounded set (T-39 rule 5, T-93 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Label {
    /// The dependency a health gauge reports (T-93 item 3).
    Dependency,
}

impl Label {
    /// Every label key.
    pub const ALL: &[Self] = &[Self::Dependency];

    /// The label key as exported.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Dependency => "dependency",
        }
    }
}

/// True when `key` may not be a metric label: it names an identifier (a tenant, organization,
/// ledger, Work, Party, record or other `*_id`) or content the content guard forbids.
///
/// Names are split into words at `.`, `_` and `-` and compared case-insensitively; a word that
/// starts with an identifier word or ends in `id` counts as one, so `ledgerId` is caught too.
#[must_use]
pub fn forbidden_label(key: &str) -> bool {
    if forbidden_field(key).is_some() {
        return true;
    }
    let lower = key.to_ascii_lowercase();
    lower
        .split(['.', '_', '-'])
        .filter(|w| !w.is_empty())
        .any(|w| {
            w.ends_with("id")
                || w.ends_with("ids")
                || IDENTIFIER_WORDS
                    .iter()
                    .any(|i| w == *i || (i.len() > 3 && w.starts_with(i)))
        })
}

fn attributes(labels: &[(Label, &'static str)]) -> Vec<KeyValue> {
    labels
        .iter()
        .map(|(label, value)| KeyValue::new(label.key(), *value))
        .collect()
}

/// Metric export settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricConfig {
    /// The `service.name` resource attribute.
    pub service: String,
    /// The `service.version` resource attribute.
    pub version: String,
    /// The OTLP/gRPC collector endpoint; `None` installs no reader.
    pub endpoint: Option<String>,
    /// How often the periodic reader exports.
    pub interval: Duration,
}

impl From<&TraceConfig> for MetricConfig {
    fn from(config: &TraceConfig) -> Self {
        Self {
            service: config.service.clone(),
            version: config.version.clone(),
            endpoint: config.endpoint.clone(),
            interval: DEFAULT_METRIC_INTERVAL,
        }
    }
}

/// The meter provider with any push exporter behind a periodic reader; used directly by tests
/// with an in-memory exporter.
#[must_use]
pub fn meter_provider_with_exporter<E>(
    config: &MetricConfig,
    exporter: Option<E>,
) -> SdkMeterProvider
where
    E: PushMetricExporter,
{
    let builder =
        SdkMeterProvider::builder().with_resource(resource(&config.service, &config.version));
    match exporter {
        Some(exporter) => builder
            .with_reader(
                PeriodicReader::builder(exporter)
                    .with_interval(config.interval)
                    .build(),
            )
            .build(),
        None => builder.build(),
    }
}

/// The meter provider for `config`: OTLP/gRPC export when an endpoint is set, none otherwise.
///
/// # Errors
/// Fails when an endpoint is set outside a Tokio runtime or the exporter rejects it.
pub fn meter_provider(config: &MetricConfig) -> Result<SdkMeterProvider, TraceError> {
    let Some(endpoint) = &config.endpoint else {
        return Ok(meter_provider_with_exporter::<opentelemetry_otlp::MetricExporter>(config, None));
    };
    tokio::runtime::Handle::try_current().map_err(|_| TraceError::NoRuntime)?;
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()?;
    Ok(meter_provider_with_exporter(config, Some(exporter)))
}

/// The instruments of Work: every one takes its labels from the bounded [`Label`] set.
#[derive(Clone, Debug)]
pub struct Meters {
    meter: Meter,
}

impl Meters {
    /// The Work meter of `provider`.
    #[must_use]
    pub fn new(provider: &SdkMeterProvider) -> Self {
        Self {
            meter: provider.meter(SCOPE),
        }
    }

    /// A monotonic counter.
    #[must_use]
    pub fn counter(
        &self,
        name: &'static str,
        unit: &'static str,
        description: &'static str,
    ) -> WorkCounter {
        WorkCounter(
            self.meter
                .u64_counter(name)
                .with_unit(unit)
                .with_description(description)
                .build(),
        )
    }

    /// A gauge.
    #[must_use]
    pub fn gauge(
        &self,
        name: &'static str,
        unit: &'static str,
        description: &'static str,
    ) -> WorkGauge {
        WorkGauge(
            self.meter
                .u64_gauge(name)
                .with_unit(unit)
                .with_description(description)
                .build(),
        )
    }

    /// The sev-1 rebuild-diff counter: one per rebuild whose rows differ from the live rows, with
    /// no label, since a ledger may not be one (§18 OP-47 item 9, OP-18 item 3).
    #[must_use]
    pub fn rebuild_diff(&self) -> WorkCounter {
        self.counter(
            REBUILD_DIFF,
            "{diff}",
            "Rebuilds whose rows differ from the live rows; each is sev-1 and the log decides.",
        )
    }
}

/// A counter whose labels come from the bounded set.
#[derive(Clone, Debug)]
pub struct WorkCounter(Counter<u64>);

impl WorkCounter {
    /// Adds `value` under `labels`.
    pub fn add(&self, value: u64, labels: &[(Label, &'static str)]) {
        self.0.add(value, &attributes(labels));
    }
}

/// A gauge whose labels come from the bounded set.
#[derive(Clone, Debug)]
pub struct WorkGauge(Gauge<u64>);

impl WorkGauge {
    /// Records `value` under `labels`.
    pub fn record(&self, value: u64, labels: &[(Label, &'static str)]) {
        self.0.record(value, &attributes(labels));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-39 OP-18 T-93
    #[test]
    fn t_39_every_label_key_is_outside_the_identifier_set() {
        for label in Label::ALL {
            assert!(!forbidden_label(label.key()), "{label:?}");
        }
    }

    // T-39 OP-18
    #[test]
    fn t_39_identifier_and_content_keys_are_never_labels() {
        for key in [
            "tenant",
            "tenant_id",
            "org",
            "organization",
            "organization_id",
            "ledger",
            "ledger_id",
            "ledgerId",
            "work",
            "work_id",
            "workId",
            "party",
            "party_ref",
            "parties",
            "record",
            "record_id",
            "rec",
            "commitment_id",
            "condition",
            "item",
            "correlation",
            "trace_id",
            "span_id",
            "uuid",
            "body",
            "api_key",
        ] {
            assert!(forbidden_label(key), "{key}");
        }
        for key in ["dependency", "outcome", "event", "severity", "status"] {
            assert!(!forbidden_label(key), "{key}");
        }
    }
}
