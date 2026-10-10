//! A secret held in a request-like structure never reaches the log output (T-33, T-39, OP-18).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use tracing_subscriber::fmt::MakeWriter;

const CANARY: &str = "CANARY-5d2e81-do-not-log";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

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

struct Token(String);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Debug)]
struct DeclareRequest {
    work_id: &'static str,
    #[allow(dead_code, reason = "carried, never printed")]
    token: Token,
}

// T-39 OP-18
#[test]
fn t_39_json_logs_never_contain_secrets() {
    let capture = Capture::default();
    work_telemetry::init_with_writer("trace", capture.clone()).unwrap();

    let request = DeclareRequest {
        work_id: "wrk_01",
        token: Token(CANARY.to_owned()),
    };
    assert_eq!(request.token.0, CANARY);

    tracing::info!(?request, "declare");
    tracing::info!(request = ?request, work = %request.work_id, "structured fields");
    let span = tracing::info_span!("declare", req = ?request);
    span.in_scope(|| tracing::warn!("inside span"));

    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    for line in output.lines() {
        let event: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(event.get("timestamp").is_some() && event.get("level").is_some());
    }
    assert!(
        output.contains("wrk_01"),
        "log capture did not work: {output}"
    );
    assert!(output.contains("[redacted]"));
    assert!(
        !output.contains(CANARY),
        "secret leaked into logs: {output}"
    );
}
