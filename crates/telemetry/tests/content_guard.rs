//! Telemetry links to records only by identifier: bodies, payloads, secrets and unstable `GenAI`
//! attributes never reach an emitted line (P-43, OP-19, OP-18, T-39, SEC-24).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

const CANARY: &str = "CANARY-9f41c7-record-body";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
        .unwrap()
    }

    fn lines(&self) -> Vec<serde_json::Value> {
        self.text()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn with_work_subscriber(f: impl FnOnce()) -> Capture {
    let capture = Capture::default();
    tracing::subscriber::with_default(work_telemetry::subscriber("trace", capture.clone()), f);
    capture
}

fn assert_no_canary(output: &str) {
    assert!(!output.contains(CANARY), "content leaked: {output}");
    let bytes: Vec<String> = CANARY.bytes().take(6).map(|b| b.to_string()).collect();
    assert!(
        !output.contains(&bytes.join(",")) && !output.contains(&bytes.join(", ")),
        "body bytes leaked: {output}"
    );
}

// OP-19 P-43 T-39
#[test]
fn op_19_records_are_linked_by_identifier_only() {
    let capture = with_work_subscriber(|| {
        let span = tracing::info_span!("declare", record = "rec_01", work = "wrk_01");
        span.in_scope(|| {
            tracing::info!(
                commitment = "cmt_01",
                correlation = "ext-42",
                outcome = "accepted",
                "record.accepted"
            );
        });
    });
    let lines = capture.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert_eq!(line["fields"]["commitment"], "cmt_01");
    assert_eq!(line["fields"]["correlation"], "ext-42");
    assert_eq!(line["fields"]["message"], "record.accepted");
    assert_eq!(line["span"]["record"], "rec_01");
    assert_eq!(line["span"]["work"], "wrk_01");
    assert_eq!(line["span"]["name"], "declare");
    assert!(line.get("timestamp").is_some() && line.get("level").is_some());
}

// OP-19 P-43 P-17 T-39
#[test]
fn op_19_record_body_bytes_never_reach_the_output() {
    let body: &[u8] = CANARY.as_bytes();
    let capture = with_work_subscriber(|| {
        tracing::info!(record = "rec_01", bytes = body, "record.received");
        let span = tracing::info_span!("parse", record = "rec_01", bytes = body);
        span.in_scope(|| tracing::info!("parse.finished"));
    });
    let output = capture.text();
    assert_no_canary(&output);
    let lines = capture.lines();
    assert_eq!(lines.len(), 2, "{output}");
    assert_eq!(lines[0]["fields"]["bytes"], work_telemetry::REDACTED);
    assert_eq!(lines[1]["span"]["bytes"], work_telemetry::REDACTED);
}

// P-43 SEC-24 OP-18
#[test]
fn p_43_content_and_secret_fields_are_never_recorded() {
    let capture = with_work_subscriber(|| {
        tracing::info!(body = CANARY, "a");
        tracing::info!(payload = %CANARY, "b");
        tracing::info!(request.body = ?CANARY, "c");
        tracing::warn!(client_secret = CANARY, "d");
        tracing::error!(password = CANARY, "e");
        tracing::debug!(refresh_token = CANARY, "f");
        tracing::trace!(api_key = CANARY, "g");
        tracing::info!(private_key = CANARY, "h");
        tracing::info!(session_cookie = CANARY, "i");
        tracing::info!(card_number = CANARY, "j");
        let span = tracing::info_span!("declare", record = "rec_01", body = tracing::field::Empty);
        span.record("body", CANARY);
        span.in_scope(|| tracing::info!(record = "rec_01", "still.logged"));
    });
    let output = capture.text();
    assert_no_canary(&output);
    let lines = capture.lines();
    assert_eq!(lines.len(), 1, "{output}");
    assert_eq!(lines[0]["fields"]["message"], "still.logged");
    assert!(lines[0].get("span").is_none(), "{output}");
}

// P-43
#[test]
fn p_43_unstable_genai_attributes_are_not_emitted() {
    let capture = with_work_subscriber(|| {
        tracing::info!(gen_ai.request.model = "model-x", "agent.called");
        tracing::info!(record = "rec_01", "agent.reported");
    });
    let output = capture.text();
    assert!(
        !output.contains("gen_ai") && !output.contains("model-x"),
        "{output}"
    );
    assert!(output.contains("agent.reported"), "{output}");
}

// SEC-24 P-17 OP-18
#[test]
fn sec_24_the_log_format_redacts_without_the_guard() {
    let capture = Capture::default();
    let unguarded = tracing_subscriber::registry().with(work_telemetry::log_layer(capture.clone()));
    tracing::subscriber::with_default(unguarded, || {
        tracing::info!(body = CANARY, secret = %CANARY, bytes = CANARY.as_bytes(), "unguarded");
    });
    let output = capture.text();
    assert_no_canary(&output);
    let lines = capture.lines();
    assert_eq!(lines.len(), 1, "{output}");
    for field in ["body", "secret", "bytes"] {
        assert_eq!(
            lines[0]["fields"][field],
            work_telemetry::REDACTED,
            "{field}"
        );
    }
}

// OP-19 P-43
#[test]
fn op_19_the_guard_decides_from_declared_field_names() {
    let capture = Capture::default();
    let guarded = tracing_subscriber::registry()
        .with(work_telemetry::ContentGuard)
        .with(work_telemetry::log_layer(capture.clone()));
    tracing::subscriber::with_default(guarded, || {
        tracing::info!(payload = CANARY, "dropped");
        tracing::info!(pos = 7_u64, "kept");
    });
    let lines = capture.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["fields"]["pos"], 7);
}
