//! The REST `/v1` family (P-53, P-54 item 1, T-35): every route sits under its major version and goes through the [`common`](crate::common) layer, an unknown route is `404 not_found`, and the generated `OpenAPI` document describes every route; `GET /v1/problems/{code}` describes a problem type and asks for no identity (T-98 item 6), and every other route names its caller from an Access token first (C-9, E-7, [`reads`](crate::reads)).

use std::future::{Ready, ready};
use std::sync::Arc;

use axum::Router;
use axum::extract::Path;
use axum::http::{HeaderValue, header};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::authority;
use crate::common::{self, Common, TraceIds};
use crate::gateway::Limits;
use crate::problem::{Problem, ProblemCode, ProblemType};
use crate::rate::RatePolicy;
use crate::reads::{self, ApiServices};
use crate::writes;

/// The major version every route starts with (P-54 item 1).
pub const MAJOR: &str = "/v1";

/// The settings of the REST family (P-33, P-54 item 9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApiConfig {
    /// The gateway limits.
    pub limits: Limits,
    /// The rate limit policy.
    pub rate: RatePolicy,
}

/// Describes one problem type.
///
/// Every problem `type` is `https://suiss.app/ns/work/problems/<code>`; this route describes the
/// code without asking for an identity.
#[utoipa::path(
    get,
    path = "/v1/problems/{code}",
    operation_id = "get_problem_type",
    tag = "problems",
    params(("code" = ProblemCode, Path, description = "The stable code of the problem type.")),
    responses(
        (status = 200, description = "The problem type.", body = ProblemType, headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 404, description = "No problem type has this code.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 429, description = "The caller has spent its quota.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds until the next window.")
        ))
    ),
    security(())
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub fn problem_type(Path(code): Path<String>) -> Ready<Response> {
    let Some(code) = ProblemCode::parse(&code) else {
        return ready(Problem::new(ProblemCode::NotFound).into_response());
    };
    let body = serde_json::to_vec(&ProblemType::of(code)).unwrap_or_default();
    let json = HeaderValue::from_static("application/json");
    ready(([(header::CONTENT_TYPE, json)], body).into_response())
}

fn not_found() -> Ready<Problem> {
    ready(Problem::new(ProblemCode::NotFound))
}

/// The public REST routes behind the common layer, drawing new trace ids from `ids`.
pub fn router(config: ApiConfig, ids: Arc<dyn TraceIds>) -> Router {
    let state = Arc::new(Common::new(config.limits, config.rate, ids));
    Router::new()
        .route("/v1/problems/{code}", get(problem_type))
        .fallback(not_found)
        .layer(from_fn_with_state(state, common::layer))
}

/// Every REST route behind the common layer: the public ones and those that act for a caller
/// named by `services` (C-9, E-7, P-56).
pub fn router_with(
    config: ApiConfig,
    ids: Arc<dyn TraceIds>,
    services: Arc<ApiServices>,
) -> Router {
    let state = Arc::new(Common::new(config.limits, config.rate, ids));
    let acting = Router::new()
        .route("/v1/ledgers/{ledger}/works/{work}", get(reads::get_work))
        .route("/v1/ledgers/{ledger}/changes", get(reads::list_changes))
        .route(
            "/v1/ledgers/{ledger}/records/{record}/evidence",
            get(reads::get_record_evidence),
        )
        .route(
            "/v1/ledgers/{ledger}/declarations",
            post(writes::create_declaration),
        )
        .route(
            "/v1/authority-requests",
            post(authority::create_authority_request),
        )
        .with_state(services);
    Router::new()
        .route("/v1/problems/{code}", get(problem_type))
        .merge(acting)
        .fallback(not_found)
        .layer(from_fn_with_state(state, common::layer))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;

    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::{HeaderMap, HeaderName, Method, StatusCode};
    use serde_json::Value;
    use tower_service::Service as _;
    use work_telemetry::{
        DEFAULT_MAX_QUEUE_SIZE, Discard, SampleRatio, TraceConfig, provider, traced_subscriber,
    };

    use crate::common::REQUEST_ID;
    use crate::gateway::MAX_REQUEST_BYTES;
    use crate::problem::PROBLEM_JSON;
    use crate::rate::{RATELIMIT, RATELIMIT_POLICY};

    use super::*;

    const BUSY: &str = "/v1/problems/busy";

    const INCOMING: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    const ZERO_TRACE: &str = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";

    #[derive(Default)]
    struct Counter(AtomicU8);

    impl TraceIds for Counter {
        fn fresh(&self) -> Option<[u8; 24]> {
            let n = self.0.fetch_add(1, Ordering::Relaxed);
            Some([n.wrapping_add(1); 24])
        }
    }

    fn api(config: ApiConfig) -> Router {
        router(config, Arc::new(Counter::default()))
    }

    fn get_request(uri: &str, traceparent: Option<&str>) -> Request {
        let mut request = Request::new(Body::empty());
        *request.uri_mut() = uri.parse().unwrap();
        if let Some(value) = traceparent {
            let value = HeaderValue::from_str(value).unwrap();
            request.headers_mut().insert("traceparent", value);
        }
        request
    }

    async fn send(router: &mut Router, request: Request) -> (StatusCode, HeaderMap, Value) {
        let response = router.call(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (parts.status, parts.headers, json)
    }

    fn header_text<'a>(headers: &'a HeaderMap, name: &HeaderName) -> &'a str {
        headers.get(name).unwrap().to_str().unwrap()
    }

    fn generated(n: u8) -> String {
        let byte = format!("{n:02x}");
        format!("{}-{}", byte.repeat(16), byte.repeat(8))
    }

    // T-98 P-53 P-54
    #[tokio::test]
    async fn t_98_a_problem_type_is_described_without_an_identity() {
        let mut router = api(ApiConfig::default());
        let (status, headers, json) = send(&mut router, get_request(BUSY, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["type"], "https://suiss.app/ns/work/problems/busy");
        assert_eq!(json["status"], 503);
        assert_eq!(json["retryable"], true);
        let policy = header_text(&headers, &RATELIMIT_POLICY);
        assert_eq!(policy, r#""default";q=600;w=60"#);
        let left = header_text(&headers, &RATELIMIT);
        assert_eq!(left, r#""default";r=599;t=60"#);
        assert!(headers.contains_key(REQUEST_ID));
        let unknown = get_request("/v1/problems/no_such_code", None);
        let (status, headers, json) = send(&mut router, unknown).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let content_type = header_text(&headers, &header::CONTENT_TYPE);
        assert_eq!(content_type, PROBLEM_JSON);
        let id = header_text(&headers, &REQUEST_ID);
        assert_eq!(json["instance"], format!("urn:work:request:{id}"));
        assert_eq!(json["code"], "not_found");
    }

    // P-53 P-54
    #[tokio::test]
    async fn p_53_every_route_is_versioned_and_an_unknown_one_is_a_problem() {
        let mut router = api(ApiConfig::default());
        for uri in ["/problems/busy", "/v2/problems/busy", "/v1/works"] {
            let (status, headers, json) = send(&mut router, get_request(uri, None)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(json["code"], "not_found", "{uri}");
            assert!(headers.contains_key(RATELIMIT), "{uri}");
        }
        assert_eq!(MAJOR, "/v1");
    }

    // P-42 T-39 P-54
    #[tokio::test]
    async fn p_42_the_request_id_is_bound_to_the_trace_context() {
        let mut router = api(ApiConfig::default());
        let (_, headers, _) = send(&mut router, get_request(BUSY, Some(INCOMING))).await;
        let id = header_text(&headers, &REQUEST_ID);
        assert_eq!(id, "4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7");
        let (_, headers, _) = send(&mut router, get_request(BUSY, None)).await;
        assert_eq!(header_text(&headers, &REQUEST_ID), generated(1));
        let (_, headers, _) = send(&mut router, get_request(BUSY, Some(ZERO_TRACE))).await;
        assert_eq!(header_text(&headers, &REQUEST_ID), generated(2));
    }

    // P-42 T-39
    #[tokio::test]
    async fn p_42_an_incoming_trace_is_continued_by_the_request_span() {
        let config = TraceConfig {
            service: "work-server".to_owned(),
            version: "0.0.0-test".to_owned(),
            endpoint: None,
            sample_ratio: SampleRatio::ALWAYS,
            max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
        };
        let traces = provider(&config).unwrap();
        let subscriber = traced_subscriber("info", || Discard, &traces);
        let _traced = tracing::subscriber::set_default(subscriber);
        let mut router = api(ApiConfig::default());
        let (_, headers, _) = send(&mut router, get_request(BUSY, Some(INCOMING))).await;
        let id = header_text(&headers, &REQUEST_ID);
        let (trace, span) = id.split_once('-').unwrap();
        assert_eq!(trace, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(span, "00f067aa0ba902b7");
        let (_, headers, _) = send(&mut router, get_request(BUSY, None)).await;
        let root = header_text(&headers, &REQUEST_ID);
        assert_ne!(root.split_once('-').unwrap().0, trace);
        assert_ne!(root, generated(1));
    }

    // P-54 P-33
    #[tokio::test(start_paused = true)]
    async fn p_54_a_caller_past_its_quota_is_rate_limited() {
        let rate = RatePolicy::new(1, Duration::from_secs(30)).unwrap();
        let mut router = api(ApiConfig {
            rate,
            ..ApiConfig::default()
        });
        let (status, _, _) = send(&mut router, get_request(BUSY, None)).await;
        assert_eq!(status, StatusCode::OK);
        let (status, headers, json) = send(&mut router, get_request(BUSY, None)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json["code"], "rate_limited");
        assert_eq!(header_text(&headers, &header::RETRY_AFTER), "30");
        let left = header_text(&headers, &RATELIMIT);
        assert_eq!(left, r#""default";r=0;t=30"#);
        tokio::time::advance(Duration::from_secs(30)).await;
        let (status, _, _) = send(&mut router, get_request(BUSY, None)).await;
        assert_eq!(status, StatusCode::OK);
    }

    // P-33 SEC-18 T-10
    #[tokio::test]
    async fn p_33_the_gateway_refuses_a_large_body_before_any_route() {
        let mut router = api(ApiConfig::default());
        let body = vec![b'a'; MAX_REQUEST_BYTES.saturating_add(1)];
        let mut request = Request::new(Body::from(body));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = BUSY.parse().unwrap();
        let (status, headers, json) = send(&mut router, request).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(json["code"], "request_too_large");
        assert!(headers.contains_key(REQUEST_ID));
    }
}
