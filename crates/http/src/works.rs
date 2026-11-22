//! Opening a Work (C-8, PR-9, X-19, E-45, P-54 item 4): `POST /v1/works` names its caller from the Access access token and `DPoP` proof first, takes one `Idempotency-Key` and no required field, and answers a fresh Work identity; nothing is written, since a Work root carries no name, type, owner, state or Practice, and the Work appears in its ledger with the first record that concerns it.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use work_kernel::id::WorkId;
use work_proto::id::ExternalId as _;
use work_query::domain::caller::Caller;
use work_query::domain::works::{opened_work, uuid_v7};

use crate::conditional::idempotency_key;
use crate::problem::{Problem, ProblemCode};
use crate::reads::{ApiServices, caller_of};

/// The body of a Work opening: every field is optional, and there is none yet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewWork {}

/// The opened Work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct OpenedWork {
    /// The Work, `wrk_…`; a record that concerns it opens it in its ledger.
    pub work: String,
}

/// The Work `caller` opens with the request `raw` and `headers`.
///
/// # Errors
/// The `Idempotency-Key` problems, `400 invalid_request` for a body outside the schema and
/// `403 access_denied` for a caller without a Party.
pub fn opening(raw: &[u8], headers: &HeaderMap, caller: &Caller) -> Result<WorkId, Box<Problem>> {
    let key = idempotency_key(headers)?;
    if !uuid_v7(key) {
        return Err(Box::new(Problem::new(ProblemCode::IdempotencyKeyMalformed)));
    }
    if !raw.is_empty() {
        serde_json::from_slice::<NewWork>(raw).map_err(|_| {
            Box::new(Problem::new(ProblemCode::InvalidRequest).with_code_detail("body"))
        })?;
    }
    let party = caller
        .party()
        .map_err(|code| Box::new(Problem::new(ProblemCode::AccessDenied).with_code_detail(code)))?;
    Ok(opened_work(party, key))
}

fn opened(work: &WorkId) -> Response {
    let body = OpenedWork {
        work: work.to_external(),
    };
    let json = HeaderValue::from_static("application/json");
    (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, json)],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

/// Opens a Work.
///
/// A Work is only an identity: no Practice, template, workflow or type is needed and no field is
/// required. The answer is the same Work for the same caller and `Idempotency-Key`; the Work
/// appears in a ledger with the first record whose `concerns` names it.
#[utoipa::path(
    post,
    path = "/v1/works",
    operation_id = "create_work",
    tag = "works",
    params(
        ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key answers the same Work.")
    ),
    request_body(content = NewWork, content_type = "application/json", description = "Optional; an empty body opens the Work."),
    responses(
        (status = 201, description = "The Work is open.", body = OpenedWork, headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "A body or header that does not open.", body = Problem,
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
        (status = 403, description = "The caller is an API client without a Party.", body = Problem,
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
        (status = 503, description = "Access cannot be reached, so the caller cannot be checked.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:write")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn create_work(
    State(services): State<Arc<ApiServices>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    match opening(&body, &headers, &caller) {
        Ok(work) => opened(&work),
        Err(problem) => problem.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderName;
    use work_kernel::id::PartyRef;
    use work_proto::id::TenantId;
    use work_query::domain::caller::{CallerKind, CallerParty};

    use super::*;
    use crate::conditional::IDEMPOTENCY_KEY;

    const UUID7: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

    fn headers(pairs: &[(HeaderName, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(name.clone(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn caller(party: Option<CallerParty>) -> Caller {
        Caller {
            tenant: TenantId::new("tnt_01").unwrap(),
            realm: "realm".to_owned(),
            issuer: "https://acme.suiss.example".to_owned(),
            client_id: "client".to_owned(),
            kind: CallerKind::User,
            party,
        }
    }

    fn alice() -> CallerParty {
        CallerParty {
            reference: PartyRef::new("AwMDAwMDAwMDAwMDAwMDAw").unwrap(),
            id: [3; 16],
        }
    }

    // C-8 PR-9 X-19 MD-18 P-54
    #[test]
    fn c_8_a_work_opens_with_no_required_field() {
        let keyed = headers(&[(IDEMPOTENCY_KEY, UUID7)]);
        let party = caller(Some(alice()));
        let empty = opening(b"", &keyed, &party).unwrap();
        assert_eq!(opening(b"{}", &keyed, &party).unwrap(), empty);
        assert_eq!(empty, opened_work(&alice(), UUID7));
        assert_eq!(opened(&empty).status(), StatusCode::CREATED);
        let code = |raw: &[u8], h: &HeaderMap, c: &Caller| opening(raw, h, c).unwrap_err().code;
        assert_eq!(
            code(br#"{"name":"x"}"#, &keyed, &party),
            ProblemCode::InvalidRequest
        );
        assert_eq!(
            code(br#"{"practice":"x"}"#, &keyed, &party),
            ProblemCode::InvalidRequest
        );
        assert_eq!(
            code(b"", &HeaderMap::new(), &party),
            ProblemCode::IdempotencyKeyMissing
        );
        let loose = headers(&[(IDEMPOTENCY_KEY, "not-a-uuid")]);
        assert_eq!(
            code(b"", &loose, &party),
            ProblemCode::IdempotencyKeyMalformed
        );
        assert_eq!(code(b"", &keyed, &caller(None)), ProblemCode::AccessDenied);
    }
}
