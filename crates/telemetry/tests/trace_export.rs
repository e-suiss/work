//! Trace export is sampled, bounded and guarded, and the `traceparent` of every span links the
//! outbox row to its trace whether or not the trace is sampled (OP-18, OP-19, P-42, P-43, T-39).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use work_telemetry::{
    DEFAULT_MAX_QUEUE_SIZE, Discard, SampleRatio, TraceConfig, TraceError, TraceParent,
    continue_trace, inject, provider, provider_with_exporter, traced_subscriber, traceparent,
};

const CANARY: &str = "CANARY-7c3b19-record-body";
const INCOMING_SAMPLED: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const INCOMING_UNSAMPLED: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";

#[derive(Clone, Debug, Default)]
struct Memory(Arc<Mutex<Vec<SpanData>>>);

impl Memory {
    fn spans(&self) -> Vec<SpanData> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl SpanExporter for Memory {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(batch);
        std::future::ready(Ok(()))
    }
}

#[derive(Clone, Debug, Default)]
struct Stalled(Arc<Mutex<()>>);

impl SpanExporter for Stalled {
    fn export(
        &self,
        _batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        drop(self.0.lock().unwrap_or_else(PoisonError::into_inner));
        std::future::ready(Ok(()))
    }
}

fn config(ratio: SampleRatio) -> TraceConfig {
    TraceConfig {
        service: "work-server".to_owned(),
        version: "0.0.0-test".to_owned(),
        endpoint: None,
        sample_ratio: ratio,
        max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
    }
}

fn memory_provider(config: &TraceConfig) -> (SdkTracerProvider, Memory) {
    let memory = Memory::default();
    (provider_with_exporter(config, Some(memory.clone())), memory)
}

fn traced<T>(provider: &SdkTracerProvider, f: impl FnOnce() -> T) -> T {
    let out =
        tracing::subscriber::with_default(traced_subscriber("trace", || Discard, provider), f);
    provider.force_flush().unwrap();
    out
}

fn roots(provider: &SdkTracerProvider, n: usize) {
    traced(provider, || {
        for i in 0..n {
            tracing::info_span!("declare", record = i).in_scope(|| {});
        }
    });
}

// OP-18 T-39
#[test]
fn op_18_sample_ratio_must_lie_in_the_unit_interval() {
    for bad in [-0.01, 1.01, f64::NAN, f64::INFINITY] {
        assert!(SampleRatio::new(bad).is_err(), "{bad}");
    }
    for good in [0.0, 0.25, 1.0] {
        assert_eq!(SampleRatio::new(good).unwrap().get(), good);
    }
}

// OP-18 P-43
#[test]
fn op_18_root_traces_are_sampled_at_the_configured_ratio() {
    let (never, never_spans) = memory_provider(&config(SampleRatio::NEVER));
    roots(&never, 50);
    assert_eq!(never_spans.spans().len(), 0);

    let (always, always_spans) = memory_provider(&config(SampleRatio::ALWAYS));
    roots(&always, 50);
    assert_eq!(always_spans.spans().len(), 50);

    let (half, half_spans) = memory_provider(&TraceConfig {
        max_queue_size: std::num::NonZeroUsize::new(4096).unwrap(),
        ..config(SampleRatio::new(0.5).unwrap())
    });
    roots(&half, 1000);
    let n = half_spans.spans().len();
    assert!((350..=650).contains(&n), "{n} of 1000 sampled at 0.5");
}

// P-42 T-39
#[test]
fn p_42_continued_traces_follow_the_caller_sampling_decision() {
    let (never, spans) = memory_provider(&config(SampleRatio::NEVER));
    traced(&never, || {
        let span = tracing::info_span!("request", record = "rec_01");
        continue_trace(&span, &TraceParent::parse(INCOMING_SAMPLED).unwrap()).unwrap();
        span.in_scope(|| {});
    });
    let exported = spans.spans();
    assert_eq!(exported.len(), 1);
    assert_eq!(
        exported[0].span_context.trace_id().to_string(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(exported[0].parent_span_id.to_string(), "00f067aa0ba902b7");

    let (always, spans) = memory_provider(&config(SampleRatio::ALWAYS));
    traced(&always, || {
        let span = tracing::info_span!("request", record = "rec_01");
        continue_trace(&span, &TraceParent::parse(INCOMING_UNSAMPLED).unwrap()).unwrap();
        span.in_scope(|| {});
    });
    assert_eq!(spans.spans().len(), 0);
}

// P-42 OP-18 P-43
#[test]
fn p_42_unsampled_and_unexported_spans_still_give_records_a_traceparent() {
    let (never, _) = memory_provider(&config(SampleRatio::NEVER));
    let unsampled = traced(&never, || traceparent(&tracing::info_span!("append")));
    let unsampled = unsampled.unwrap();
    assert!(!unsampled.sampled());

    let no_exporter = provider(&config(SampleRatio::ALWAYS)).unwrap();
    let local = traced(&no_exporter, || traceparent(&tracing::info_span!("append")));
    assert!(local.unwrap().sampled());
}

// P-42 T-39
#[test]
fn p_42_traceparent_round_trips_through_the_outbox() {
    let (always, spans) = memory_provider(&config(SampleRatio::ALWAYS));
    let (outbox, consumer) = traced(&always, || {
        let request = tracing::info_span!("request", record = "rec_01");
        continue_trace(&request, &TraceParent::parse(INCOMING_SAMPLED).unwrap()).unwrap();
        let outbox = traceparent(&request).unwrap().to_string();

        let row = TraceParent::parse(&outbox).unwrap();
        let publish = tracing::info_span!("publish", record = "rec_01");
        continue_trace(&publish, &row).unwrap();
        let mut headers: HashMap<String, String> = HashMap::new();
        inject(&publish, &mut headers);
        request.in_scope(|| {});
        publish.in_scope(|| {});
        (outbox, headers)
    });

    let outbox = TraceParent::parse(&outbox).unwrap();
    assert_eq!(outbox.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_ne!(outbox.span_id(), "00f067aa0ba902b7");
    assert!(outbox.sampled());

    let header = TraceParent::parse(&consumer["traceparent"]).unwrap();
    assert_eq!(header.trace_id(), outbox.trace_id());

    let exported = spans.spans();
    let request = exported.iter().find(|s| s.name == "request").unwrap();
    let publish = exported.iter().find(|s| s.name == "publish").unwrap();
    assert_eq!(request.span_context.span_id().to_string(), outbox.span_id());
    assert_eq!(publish.parent_span_id.to_string(), outbox.span_id());
    assert_eq!(
        publish.span_context.trace_id(),
        request.span_context.trace_id()
    );
}

// P-42
#[test]
fn p_42_traceparent_accepts_what_the_ledger_domain_accepts() {
    for ok in [
        INCOMING_SAMPLED,
        INCOMING_UNSAMPLED,
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03",
    ] {
        assert_eq!(TraceParent::parse(ok).unwrap().as_str(), ok);
    }
    for bad in [
        "",
        "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-00",
        "00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01",
    ] {
        assert!(TraceParent::parse(bad).is_err(), "{bad}");
    }
}

// OP-19 P-43 SEC-35 T-39
#[test]
fn op_19_forbidden_fields_are_dropped_before_the_exporter() {
    let (always, spans) = memory_provider(&config(SampleRatio::ALWAYS));
    traced(&always, || {
        let span = tracing::info_span!("declare", record = "rec_01", work = "wrk_01");
        span.set_attribute("record_body", CANARY);
        span.set_attribute("gen_ai.request.model", CANARY);
        span.set_attribute("api_key", CANARY);
        span.add_event(
            "parsed",
            vec![
                opentelemetry::KeyValue::new("payload", CANARY),
                opentelemetry::KeyValue::new("outcome", "accepted"),
            ],
        );
        span.in_scope(|| {
            tracing::info!(commitment = "cmt_01", "declared");
            tracing::info!(body = CANARY, "leak attempt");
            tracing::info_span!("store", payload = CANARY).in_scope(|| {});
        });
    });

    let exported = spans.spans();
    assert_eq!(
        exported.len(),
        1,
        "a span declaring `payload` is never exported"
    );
    let span = &exported[0];
    assert!(
        !format!("{exported:?}").contains(CANARY),
        "content reached the exporter"
    );

    let keys: Vec<&str> = span.attributes.iter().map(|kv| kv.key.as_str()).collect();
    assert!(
        keys.contains(&"record") && keys.contains(&"work"),
        "{keys:?}"
    );
    for gone in ["record_body", "gen_ai.request.model", "api_key"] {
        assert!(!keys.contains(&gone), "{gone} exported");
    }
    assert!(span.dropped_attributes_count >= 3);

    let events: Vec<&str> = span.events.iter().map(|e| e.name.as_ref()).collect();
    assert!(
        events.contains(&"declared") && events.contains(&"parsed"),
        "{events:?}"
    );
    assert!(!events.contains(&"leak attempt"), "{events:?}");
    let parsed = span.events.iter().find(|e| e.name == "parsed").unwrap();
    let parsed_keys: Vec<&str> = parsed.attributes.iter().map(|kv| kv.key.as_str()).collect();
    assert_eq!(parsed_keys, ["outcome"]);
}

// T-39 OP-18
#[test]
fn t_39_no_endpoint_installs_no_exporter_and_an_endpoint_needs_a_runtime() {
    assert!(provider(&config(SampleRatio::ALWAYS)).is_ok());

    let remote = TraceConfig {
        endpoint: Some("http://127.0.0.1:4317".to_owned()),
        ..config(SampleRatio::ALWAYS)
    };
    assert!(matches!(provider(&remote), Err(TraceError::NoRuntime)));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let exporting = runtime.block_on(async { provider(&remote) }).unwrap();
    drop(exporting.shutdown_with_timeout(Duration::from_millis(100)));
}

// T-39 OP-18 T-32
#[test]
fn t_39_a_stalled_exporter_never_blocks_span_creation() {
    let stalled = Stalled::default();
    let held = stalled.0.lock().unwrap();
    let small = TraceConfig {
        max_queue_size: std::num::NonZeroUsize::new(8).unwrap(),
        ..config(SampleRatio::ALWAYS)
    };
    let provider = provider_with_exporter(&small, Some(stalled.clone()));
    tracing::subscriber::with_default(traced_subscriber("trace", || Discard, &provider), || {
        for i in 0..5000 {
            tracing::info_span!("declare", record = i).in_scope(|| {});
        }
    });
    drop(held);
    drop(provider.shutdown_with_timeout(Duration::from_secs(1)));
}
