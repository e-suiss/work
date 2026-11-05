//! The one layer every API family goes through (P-54, T-35 rule 2, P-42, T-39 item 2): a request continues the caller's W3C `traceparent` or starts a new trace, its `Request-Id` is the trace id and the span id of that context, its body is held to the gateway limits before any handler sees it (P-33), a caller past its quota is answered `429 rate_limited`, every answer carries `Request-Id`, `RateLimit-Policy` and `RateLimit`, and every problem names its request in `instance`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tracing::Instrument as _;
use work_telemetry::{TRACEPARENT, TraceParent, continue_trace, traceparent};

use crate::gateway::Limits;
use crate::problem::{PROBLEM_JSON, Problem, ProblemCode};
use crate::rate::{RATELIMIT, RATELIMIT_POLICY, RateLimiter, RatePolicy};

/// The header naming one request (P-54 item 9, P-42).
pub const REQUEST_ID: HeaderName = HeaderName::from_static("request-id");

/// The largest problem body the layer rewrites to name its request.
const MAX_PROBLEM_BYTES: usize = 65_536;

/// Fresh random bytes for a trace context when the process has no trace layer (T-32: randomness
/// comes from the Rng port).
pub trait TraceIds: Send + Sync {
    /// 16 bytes for a trace id and 8 for a span id; `None` when the source has none.
    fn fresh(&self) -> Option<[u8; 24]>;
}

/// What a handler knows about its request (P-42).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    traceparent: TraceParent,
}

impl RequestContext {
    /// The context of `traceparent`.
    #[must_use]
    pub const fn new(traceparent: TraceParent) -> Self {
        Self { traceparent }
    }

    /// The trace context the request runs in; outbox rows, events and calls to Access and Relay
    /// carry it on.
    #[must_use]
    pub const fn traceparent(&self) -> &TraceParent {
        &self.traceparent
    }

    /// `<trace id>-<span id>`.
    #[must_use]
    pub fn request_id(&self) -> String {
        let (trace, span) = (self.traceparent.trace_id(), self.traceparent.span_id());
        format!("{trace}-{span}")
    }
}

/// The settings and state of the layer, one per process.
pub struct Common {
    limits: Limits,
    rate: RateLimiter,
    ids: Arc<dyn TraceIds>,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            s.extend(DIGITS.get(usize::from(nibble)).map(|&c| char::from(c)));
        }
    }
    s
}

/// The `traceparent` a request sent, if it sent exactly one valid value.
#[must_use]
pub fn incoming(headers: &HeaderMap) -> Option<TraceParent> {
    let mut values = headers.get_all(TRACEPARENT).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    TraceParent::parse(first.to_str().ok()?.trim()).ok()
}

impl Common {
    /// The layer state of `limits` and `rate`, drawing new trace ids from `ids`.
    #[must_use]
    pub fn new(limits: Limits, rate: RatePolicy, ids: Arc<dyn TraceIds>) -> Self {
        Self {
            limits,
            rate: RateLimiter::new(rate),
            ids,
        }
    }

    /// A new unsampled root context from the trace id source.
    #[must_use]
    pub fn new_trace(&self) -> Option<TraceParent> {
        let bytes = self.ids.fresh()?;
        let (trace, span) = (bytes.get(..16)?, bytes.get(16..)?);
        TraceParent::parse(&format!("00-{}-{}-00", hex(trace), hex(span))).ok()
    }

    /// The context a request runs in: the span's own context when a trace layer is installed,
    /// which continues `incoming`, otherwise `incoming` itself or a new trace.
    #[must_use]
    pub fn context(
        &self,
        span: &tracing::Span,
        incoming: Option<TraceParent>,
    ) -> Option<RequestContext> {
        if let Some(parent) = &incoming {
            let _continued = continue_trace(span, parent).is_ok();
        }
        traceparent(span)
            .or(incoming)
            .or_else(|| self.new_trace())
            .map(RequestContext::new)
    }
}

fn caller(request: &Request) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(String::new, |info| info.0.ip().to_string())
}

async fn named(response: Response, request_id: &str) -> Response {
    let problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes() == PROBLEM_JSON.as_bytes());
    if !problem {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_PROBLEM_BYTES).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let instance = Value::String(format!("urn:work:request:{request_id}"));
    let body = match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(mut map)) => {
            map.entry("instance").or_insert(instance);
            serde_json::to_vec(&map).unwrap_or_else(|_| bytes.to_vec())
        }
        _ => bytes.to_vec(),
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(body))
}

/// The layer: `axum::middleware::from_fn_with_state(common, common::layer)`.
pub async fn layer(State(common): State<Arc<Common>>, request: Request, next: Next) -> Response {
    let span = tracing::info_span!("http.request");
    let Some(context) = common.context(&span, incoming(request.headers())) else {
        return Problem::new(ProblemCode::Busy).into_response();
    };
    let request_id = context.request_id();
    let quota = common.rate.take(&caller(&request));
    let response = if quota.allowed {
        match common.limits.hold(request).await {
            Ok(mut request) => {
                request.extensions_mut().insert(context);
                next.run(request).instrument(span).await
            }
            Err(refusal) => refusal.problem().into_response(),
        }
    } else {
        let retry = quota.reset_secs();
        Problem::new(ProblemCode::RateLimited)
            .with_retry_after(retry)
            .into_response()
    };
    let mut response = named(response, &request_id).await;
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        headers.insert(REQUEST_ID, value);
    }
    headers.insert(RATELIMIT_POLICY, common.rate.policy().header());
    headers.insert(RATELIMIT, quota.header());
    response
}
