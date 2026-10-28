//! W3C Trace Context propagation (P-42, T-39 rule 2, OP-18 rule 5): the `traceparent` of a span
//! is injected into HTTP, RPC, NATS and outbox carriers, and an incoming one is continued, so the
//! outbox `traceparent` and the exported trace share one trace id while the record links to the
//! trace by identifier only (P-43).

use std::fmt;
use std::str::FromStr;

use opentelemetry::propagation::TextMapPropagator as _;
pub use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
pub use tracing_opentelemetry::SetParentError;

/// The W3C Trace Context header name.
pub const TRACEPARENT: &str = "traceparent";

/// A W3C `traceparent` value with the same shape the `ledger.traceparent` domain accepts:
/// `version-traceid-spanid-flags` in lowercase hex, version not `ff`, ids not all zero.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TraceParent(String);

/// A string that is not a valid `traceparent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid traceparent")]
pub struct InvalidTraceParent;

fn lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn nonzero(s: &str) -> bool {
    s.bytes().any(|b| b != b'0')
}

impl TraceParent {
    /// Validates a `traceparent` value.
    ///
    /// # Errors
    /// Fails unless `value` is `vv-<32 hex>-<16 hex>-ff` in lowercase hex with a version other
    /// than `ff` and non-zero trace and span ids.
    pub fn parse(value: &str) -> Result<Self, InvalidTraceParent> {
        let mut parts = value.split('-');
        let (Some(version), Some(trace), Some(span), Some(flags), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(InvalidTraceParent);
        };
        let shaped = version.len() == 2
            && trace.len() == 32
            && span.len() == 16
            && flags.len() == 2
            && [version, trace, span, flags].iter().all(|p| lower_hex(p));
        if shaped && version != "ff" && nonzero(trace) && nonzero(span) {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidTraceParent)
        }
    }

    /// The header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 32-hex-digit trace id.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        self.0.get(3..35).unwrap_or_default()
    }

    /// The 16-hex-digit parent span id.
    #[must_use]
    pub fn span_id(&self) -> &str {
        self.0.get(36..52).unwrap_or_default()
    }

    /// True if the caller sampled the trace.
    #[must_use]
    pub fn sampled(&self) -> bool {
        self.0
            .get(53..55)
            .and_then(|f| u8::from_str_radix(f, 16).ok())
            .is_some_and(|f| f & 1 == 1)
    }
}

impl fmt::Display for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TraceParent").field(&self.0).finish()
    }
}

impl FromStr for TraceParent {
    type Err = InvalidTraceParent;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Extractor for TraceParent {
    fn get(&self, key: &str) -> Option<&str> {
        key.eq_ignore_ascii_case(TRACEPARENT)
            .then_some(self.as_str())
    }

    fn keys(&self) -> Vec<&str> {
        vec![TRACEPARENT]
    }
}

#[derive(Default)]
struct Single(Option<String>);

impl Injector for Single {
    fn set(&mut self, key: &str, value: String) {
        if key.eq_ignore_ascii_case(TRACEPARENT) {
            self.0 = Some(value);
        }
    }
}

/// Writes the trace context of `span` (`traceparent` and any `tracestate`) into `carrier`;
/// nothing is written when the span has no trace context.
pub fn inject(span: &tracing::Span, carrier: &mut dyn Injector) {
    TraceContextPropagator::new().inject_context(&span.context(), carrier);
}

/// The `traceparent` of `span`, sampled or not, or `None` when the span has no trace context
/// (the span is disabled or no trace layer is installed).
#[must_use]
pub fn traceparent(span: &tracing::Span) -> Option<TraceParent> {
    let mut single = Single::default();
    inject(span, &mut single);
    single.0.and_then(|v| TraceParent::parse(&v).ok())
}

/// Makes `span` continue the trace carried by `carrier` (an incoming request, NATS message or
/// outbox row); a missing or invalid `traceparent` leaves `span` a new root.
///
/// # Errors
/// Fails if `span` is disabled, already started, or no trace layer is installed.
pub fn continue_trace(span: &tracing::Span, carrier: &dyn Extractor) -> Result<(), SetParentError> {
    span.set_parent(TraceContextPropagator::new().extract(carrier))
}
