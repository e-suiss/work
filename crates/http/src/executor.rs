//! The executor coordination family of the REST API (RC-41, RC-42, RC-43, T-105, E-39, SEC-15): `GET /v1/ledgers/{ledger}/executor/deliveries` hands the executor the commitments bound to it and the requests made of it, in the order Work committed them, waiting up to 30 seconds for the next one; a webhook only rings a content-free doorbell. Every element the executor sends back is a typed record write under `/v1/ledgers/{ledger}/commitments/{commitment}/executor/<element>`, taking the record of exactly that element with its `work/control/1` body in the `definition` part, one `Idempotency-Key` and the `If-Match` of the commitment's version; only the executor assigned to the work writes them, and an action report binds its single-use authority context to one idempotency key.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Serialize;
use utoipa::{IntoParams, ToSchema};
use work_kernel::catalog::DeclarationSubtype;
use work_kernel::control::executor::{
    CAPABILITY_EXT_KEY, CONTROL_MODE_EXT_KEY, HEARTBEAT_EXT_KEY, REPORT_EXT_KEY, SESSION_EXT_KEY,
    STATUS_EXT_KEY,
};
use work_kernel::id::LedgerId;
use work_proto::id::{CommitmentId, ExternalId as _};
use work_query::domain::authority::base64url_text;
use work_query::domain::reads::{Deliveries, MAX_DELIVERY_WAIT_S};
use work_query::domain::writes::{Expected, Kind};

use crate::commitments::{CommitmentWritten, written};
use crate::common::RequestContext;
use crate::json::rfc3339_millis;
use crate::problem::{Problem, ProblemCode};
use crate::reads::{ApiServices, caller_of, read_problem};
use crate::writes::{declaration_request, write_problem};

/// One delivery to the executor (RC-42).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct DeliveryAnswer {
    /// Its sequence number in the ledger, a decimal string.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub seq: u64,
    /// `commitment`: the commitment is bound to the executor; `request`: Work asks it to stop,
    /// resume, take over, return control or apply a change.
    pub kind: String,
    /// The commitment, `cmt_…`.
    pub commitment: String,
    /// The record that caused it, `rec_…`.
    pub record: String,
    /// The `work/control/1` `commitment-delivery` or `request` body, unpadded base64url of its
    /// deterministic CBOR.
    pub body: String,
    /// The record's ledger time, RFC 3339 UTC.
    pub at: String,
}

/// The deliveries addressed to the caller (RC-42, T-105).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct DeliveriesAnswer {
    /// At most 100, oldest first.
    pub deliveries: Vec<DeliveryAnswer>,
    /// The sequence number of the last delivery answered, or `after` when none is; the next
    /// read names it as `after`.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub cursor: u64,
}

impl DeliveriesAnswer {
    /// The answer of `read` in `ledger`.
    #[must_use]
    pub fn of(read: &Deliveries) -> Self {
        Self {
            deliveries: read
                .deliveries
                .iter()
                .map(|d| DeliveryAnswer {
                    seq: d.seq,
                    kind: d.kind.to_owned(),
                    commitment: CommitmentId(d.commitment).to_external(),
                    record: d.record.to_external(),
                    body: base64url_text(&d.body),
                    at: rfc3339_millis(i64::try_from(d.at_ms).unwrap_or(i64::MAX))
                        .unwrap_or_default(),
                })
                .collect(),
            cursor: read.cursor,
        }
    }
}

/// The query of a delivery read.
#[derive(Clone, Debug, Default, PartialEq, Eq, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeliveriesQuery {
    /// The `cursor` of the previous answer, a decimal string; `0` without one.
    pub after: Option<String>,
    /// Seconds to wait for a delivery when none is there yet, 0 to 30; 0 without one.
    pub wait: Option<u32>,
}

impl DeliveriesQuery {
    /// The query of `uri`: its `after` and `wait`, other parameters ignored.
    ///
    /// # Errors
    /// `400 invalid_request` for a repeated parameter, an `after` that is not a 64-bit number
    /// or a `wait` above 30.
    pub fn of(uri: &Uri) -> Result<(u64, u32), Box<Problem>> {
        let bad = || Box::new(Problem::new(ProblemCode::InvalidRequest));
        let mut query = Self::default();
        for pair in uri.query().unwrap_or_default().split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            match name {
                "after" if query.after.is_none() => query.after = Some(value.to_owned()),
                "wait" if query.wait.is_none() => {
                    query.wait = Some(value.parse().map_err(|_| bad())?);
                }
                "after" | "wait" => return Err(bad()),
                _ => {}
            }
        }
        let after = match query.after.as_deref() {
            None => 0,
            Some(text) => text.parse().map_err(|_| bad())?,
        };
        let wait = query.wait.unwrap_or(0);
        if wait > MAX_DELIVERY_WAIT_S {
            return Err(bad());
        }
        Ok((after, wait))
    }
}

/// Reads the deliveries addressed to the caller.
///
/// The commitments bound to the caller and the requests made of it as the executor assigned to
/// the work, after `after`, oldest first, at most 100 (RC-42, T-105). With none and a `wait`,
/// the read waits up to that many seconds for the next one. A webhook only rings a doorbell
/// naming the ledger and a cursor (E-39); the executor reads the deliveries here.
#[utoipa::path(
    get,
    path = "/v1/ledgers/{ledger}/executor/deliveries",
    operation_id = "list_executor_deliveries",
    tag = "executor",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        DeliveriesQuery
    ),
    responses(
        (status = 200, description = "The deliveries.", body = DeliveriesAnswer, headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "An identifier, an `after` or a `wait` that does not open.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
            content_type = "application/problem+json", headers(
            ("WWW-Authenticate" = String, description = "The DPoP challenge."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 404, description = "No such ledger.", body = Problem,
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
        )),
        (status = 503, description = "Access or the database cannot be reached.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:read")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn list_executor_deliveries(
    State(services): State<Arc<ApiServices>>,
    Path(ledger): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let Ok(ledger) = LedgerId::parse_external(&ledger) else {
        return Problem::new(ProblemCode::InvalidId).into_response();
    };
    let (after, wait) = match DeliveriesQuery::of(&uri) {
        Ok(query) => query,
        Err(problem) => return problem.into_response(),
    };
    match services
        .reads
        .deliveries(&caller, &ledger, after, wait)
        .await
    {
        Ok(read) => {
            let json = HeaderValue::from_static("application/json");
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, json)],
                serde_json::to_vec(&DeliveriesAnswer::of(&read)).unwrap_or_default(),
            )
                .into_response()
        }
        Err(refused) => read_problem(refused).into_response(),
    }
}

/// Writes one element of the executor contract: the record must be of `kind`, name the
/// commitment, and be written by the executor assigned to it (RC-41, RC-42).
async fn executor_write(
    services: &ApiServices,
    kind: Kind,
    (ledger, commitment): (&str, &str),
    context: &RequestContext,
    (method, uri, headers): (&Method, &Uri, &HeaderMap),
    body: &[u8],
) -> Response {
    let caller = match caller_of(services, method, uri, headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let (Ok(ledger), Ok(commitment)) = (
        LedgerId::parse_external(ledger),
        CommitmentId::parse_external(commitment),
    ) else {
        return Problem::new(ProblemCode::InvalidId).into_response();
    };
    let mut request = match declaration_request(body, headers, context.traceparent().to_string()) {
        Ok(request) => request,
        Err(problem) => return problem.into_response(),
    };
    request.expected = Some(Expected {
        kind,
        commitment: Some(commitment.0),
    });
    request.executor = true;
    match services.writes.declare(&caller, &ledger, &request).await {
        Ok(w) => written(&ledger, &commitment.0, &w),
        Err(refused) => write_problem(refused).into_response(),
    }
}

macro_rules! element {
    ($name:ident, $kind:expr, $path:tt, $id:tt, $action:tt, $doc:tt) => {
        #[doc = $doc]
        #[utoipa::path(
            post,
            path = $path,
            operation_id = $id,
            tag = "executor",
            params(
                ("ledger" = String, Path, description = "The ledger, `led_…`."),
                ("commitment" = String, Path, description = "The commitment, `cmt_…`."),
                ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
                ("If-Match" = String, Header, description = "The strong ETag of the commitment's version.")
            ),
            request_body(content = crate::writes::NewDeclaration, content_type = "application/json"),
            responses(
                (status = 201, description = "The record is in the ledger, or, for an action report whose authority context and idempotency key an earlier report bound, that report with `replayed`.", body = CommitmentWritten, headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 400, description = "A body, identifier or header that does not open, or a record of another element.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("WWW-Authenticate" = String, description = "The DPoP challenge."),
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 403, description = "The Access evidence does not authorise this record.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 404, description = "No such ledger.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 412, description = "The commitment is no longer at the If-Match version.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 413, description = "A body part is above its bound.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 422, description = "The record is refused with its reason, kept under its key: `control`, `not_executor` for a writer that is not the executor assigned to the work; `definition` and the member for a body that does not decode; `control`, `context_reused` or `key_reused` for an authority context or idempotency key another report bound; `control`, `commitment` for a record that names another commitment; or a body part carries a secret.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 428, description = "No If-Match.", body = Problem,
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
                )),
                (status = 503, description = "Access cannot be reached, the ledger is busy, or the outcome is being checked; send the same request again.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota."),
                    ("Retry-After" = String, description = "Seconds to wait when the ledger is busy.")
                ))
            ),
            security(("access_token" = [])),
            extensions(("x-work-action" = json!($action)))
        )]
        #[allow(
            clippy::needless_pass_by_value,
            reason = "axum hands extractors over by value"
        )]
        pub async fn $name(
            State(services): State<Arc<ApiServices>>,
            Path((ledger, commitment)): Path<(String, String)>,
            Extension(context): Extension<RequestContext>,
            method: Method,
            uri: Uri,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            executor_write(
                &services,
                $kind,
                (&ledger, &commitment),
                &context,
                (&method, &uri, &headers),
                &body,
            )
            .await
        }
    };
}

element!(
    capability,
    Kind::Executor(CAPABILITY_EXT_KEY),
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/capability",
    "declare_executor_capability",
    "work:write",
    "Declares the executor's control capability; Work offers only what it declares (RC-39, RC-42, RC-43)."
);
element!(
    status,
    Kind::Executor(STATUS_EXT_KEY),
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/status",
    "report_executor_status",
    "work:write",
    "Reports the execution's status, what was done and what is needed; only this report shows a stop (RC-38, RC-42)."
);
element!(
    control_mode,
    Kind::Executor(CONTROL_MODE_EXT_KEY),
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/control-mode",
    "report_executor_control_mode",
    "work:write",
    "Reports the control mode the executor runs in, with the control lease in force (RC-32, RC-33, RC-42)."
);
element!(
    heartbeat,
    Kind::Executor(HEARTBEAT_EXT_KEY),
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/heartbeat",
    "report_executor_heartbeat",
    "work:write",
    "Reports that the executor is alive, or leaving on purpose (RC-42, ST-4)."
);
element!(
    session,
    Kind::Executor(SESSION_EXT_KEY),
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/session",
    "report_executor_session",
    "work:write",
    "Opens or closes an execution session, one attempt of the commitment, keeping why a failed or abandoned attempt ended (RC-43)."
);
element!(
    report,
    Kind::Executor(REPORT_EXT_KEY),
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/reports",
    "report_executor_progress",
    "work:write",
    "Reports an action as an Act bound to a single-use authority context and one idempotency key, or a question, answer, error, plan update or rationale summary as a Claim (RC-42, RC-43, SEC-15, OP-4)."
);
element!(
    stop_response,
    Kind::Declaration(DeclarationSubtype::StopResponse),
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/responses",
    "respond_executor_stop",
    "work:stop_respond",
    "Answers a stop request with a `stop_response` citing it: accept, finish then stop, or refuse with a reason (RC-36, RC-42)."
);
element!(
    request_response,
    Kind::Claim,
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/request-responses",
    "respond_executor_request",
    "work:write",
    "Answers a takeover, a return of control, a resume, a change or a budget notice with an `observation` Claim carrying a `request-response` body and citing the request (RC-33, RC-40, RC-42)."
);
element!(
    handover,
    Kind::Declaration(DeclarationSubtype::HandoffNote),
    "/v1/ledgers/{ledger}/commitments/{commitment}/executor/handover",
    "hand_over_executor_work",
    "work:control",
    "Hands the work over with a `handoff_note` in the handover schema (RC-34, RC-42, CM-45)."
);

/// The executor routes: the delivery read and one typed write per contract element.
pub fn routes() -> Router<Arc<ApiServices>> {
    let base = "/v1/ledgers/{ledger}/commitments/{commitment}/executor";
    Router::new()
        .route(
            "/v1/ledgers/{ledger}/executor/deliveries",
            get(list_executor_deliveries),
        )
        .route(&format!("{base}/capability"), post(capability))
        .route(&format!("{base}/status"), post(status))
        .route(&format!("{base}/control-mode"), post(control_mode))
        .route(&format!("{base}/heartbeat"), post(heartbeat))
        .route(&format!("{base}/session"), post(session))
        .route(&format!("{base}/reports"), post(report))
        .route(&format!("{base}/responses"), post(stop_response))
        .route(&format!("{base}/request-responses"), post(request_response))
        .route(&format!("{base}/handover"), post(handover))
}

#[cfg(test)]
mod tests;
