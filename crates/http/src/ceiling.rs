//! The agent ceiling decision route (E-23, E-45, T-99 item 9; Relay AG-49): `POST /v1/ledgers/{ledger}/agent-ceiling-decisions` writes the attributable Declaration that decides on an `agent.ceiling_exceeded` event, an `acknowledgement` carrying the `agent-ceiling-decision/1` extension, under the Access action `work:agent_ceiling_decide`; any other record is refused before Access is asked. Work forwards the decision to Relay only through an outbound Relay client offering the ceiling capability; while work-server has none, the written decision is logged as not forwarded and nothing is taken back.

use std::sync::Arc;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::response::{IntoResponse, Response};
use work_kernel::catalog::DeclarationSubtype;
use work_kernel::id::LedgerId;
use work_proto::id::ExternalId as _;
use work_query::domain::kinds::{CeilingDecision, carried_ceiling};
use work_query::domain::writes::{DeclarationRequest, Expected, Kind, WriteRefusal, Written};

use crate::common::RequestContext;
use crate::problem::{Problem, ProblemCode};
use crate::reads::{ApiServices, caller_of};
use crate::writes::{created, declaration_request, write_problem};

/// The reason a record that is no ceiling decision is refused with: `422 record_rejected`,
/// `["ceiling", "not_a_decision"]`.
pub const NOT_A_DECISION: &str = "ceiling:not_a_decision";

/// Why a written decision is not forwarded to Relay: work-server holds no outbound Relay client.
pub const UNFORWARDED: &str = "relay_client_absent";

/// The decision `request` carries, or the refusal of a record that is none (E-23).
///
/// # Errors
/// [`WriteRefusal::Rejected`] with [`NOT_A_DECISION`].
pub fn decision_of(request: &DeclarationRequest) -> Result<CeilingDecision, WriteRefusal> {
    carried_ceiling(&request.record, request.auth_context.is_some())
        .ok_or_else(|| WriteRefusal::Rejected(NOT_A_DECISION.to_owned()))
}

fn unforwarded(ledger: &LedgerId, written: &Written, decision: &CeilingDecision) {
    if written.replayed {
        return;
    }
    tracing::warn!(
        event = "relay.ceiling_decision_unforwarded",
        ledger = ledger.to_external(),
        record = written.record.to_external(),
        agent = decision.agent.as_str(),
        ceiling_event = decision.event.as_str(),
        decision = decision.decision.wire_name(),
        reason = UNFORWARDED,
        "the ceiling decision is written and not forwarded to Relay"
    );
}

/// Decides on an agent's notification ceiling.
///
/// The body carries the `acknowledgement` Declaration whose `agent-ceiling-decision/1`
/// extension names the decision (`send_all`, `cancel` or `stop`), the `agent.ceiling_exceeded`
/// event it answers and the agent, with the Access Exercise of `work:agent_ceiling_decide` it was
/// written under; its `basis` cites the attention the event raised. Any other record is refused
/// before Access is asked. The decision is forwarded to Relay only while Work holds a Relay
/// client offering the ceiling; a decision Relay does not take is never taken back in Work.
#[utoipa::path(
    post,
    path = "/v1/ledgers/{ledger}/agent-ceiling-decisions",
    operation_id = "create_agent_ceiling_decision",
    tag = "records",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
        ("If-Match" = String, Header, description = "The strong ETag of the version of the item the record changes, `\"0\"` before its first record.")
    ),
    request_body(content = crate::writes::NewDeclaration, content_type = "application/json"),
    responses(
        (status = 201, description = "The decision is in the ledger.", body = crate::writes::WrittenAnswer, headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "A body, identifier or header that does not open.", body = Problem,
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
        (status = 412, description = "The item is no longer at the If-Match version.", body = Problem,
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
        (status = 422, description = "The record is no ceiling decision (`ceiling`, `not_a_decision`), the kernel rejected it, its auth_context does not verify, a body part carries a secret, or the key was reused with another body.", body = Problem,
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
        (status = 503, description = "Access cannot be reached, so the authority cannot be verified, the ledger is busy, or the outcome is being checked; send the same request again.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds to wait when the ledger is busy.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:agent_ceiling_decide")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn create_agent_ceiling_decision(
    State(services): State<Arc<ApiServices>>,
    Path(ledger): Path<String>,
    Extension(context): Extension<RequestContext>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let Ok(ledger) = LedgerId::parse_external(&ledger) else {
        return Problem::new(ProblemCode::InvalidId).into_response();
    };
    let mut request = match declaration_request(&body, &headers, context.traceparent().to_string())
    {
        Ok(request) => request,
        Err(problem) => return problem.into_response(),
    };
    let decision = match decision_of(&request) {
        Ok(decision) => decision,
        Err(refused) => return write_problem(refused).into_response(),
    };
    request.expected = Some(Expected {
        kind: Kind::Declaration(DeclarationSubtype::Acknowledgement),
        commitment: None,
    });
    match services.writes.declare(&caller, &ledger, &request).await {
        Ok(written) => {
            unforwarded(&ledger, &written, &decision);
            created(&ledger, &written)
        }
        Err(refused) => write_problem(refused).into_response(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use axum::http::{HeaderValue, header};

    use super::*;
    use crate::conditional::IDEMPOTENCY_KEY;

    // E-23 E-45 T-98
    #[test]
    fn e_23_a_record_that_is_no_ceiling_decision_is_refused_before_access_is_asked() {
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY,
            HeaderValue::from_static("01890a5d-ac96-774b-bcce-b302099a8057"),
        );
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"0\""));
        let raw = serde_json::to_vec(&serde_json::json!({
            "record": "Y29zZQ",
            "authority": {
                "exercise": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                "intent": "aW50ZW50",
            },
            "actor_types": {"author": "human"},
        }))
        .unwrap();
        let request = declaration_request(&raw, &headers, String::new()).unwrap();
        let refused = decision_of(&request).unwrap_err();
        assert_eq!(refused, WriteRefusal::Rejected(NOT_A_DECISION.to_owned()));
        let problem = write_problem(refused);
        assert_eq!(problem.code, ProblemCode::RecordRejected);
        assert_eq!(problem.status, 422);
        assert_eq!(
            problem.reason,
            Some(vec!["ceiling".to_owned(), "not_a_decision".to_owned()])
        );
    }
}
