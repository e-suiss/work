//! The authority request route (T-101 item 2 and its note, E-7, E-17, E-45, P-13, P-116 item 6, T-28): a named caller hands Work's PEP the canonical `work:commit` intent, the nonce, the holding basis and the Actor Intent Statement its own device Instance signed, and Work answers what Access decided: the allowed Exercise with its verified decision receipt, which the Declaration write then refers to, or a `REQUIRE_ACTION` with the step-up Access names, the typed authority request and, once the approver's contribution came with it, the Approval Surface URL. The route writes nothing in Work, approves nothing and signs nothing for the caller. `GET /v1/access/approval` is the `redirect_uri` Work registers: it reads the return from the Approval Surface with the caller's token, uses the single-use `state` Work issued, confirms the contribution with Access and hands it back as the proof of the next authority request.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use work_kernel::id::LedgerId;
use work_proto::id::ExternalId as _;
use work_query::domain::authority::{AuthorityAnswer, AuthorityAsk, base64url_text, holding};
use work_query::domain::writes::{ExerciseId, base64url};

use crate::conditional::idempotency_key;
use crate::problem::{Problem, ProblemCode};
use crate::reads::{ApiServices, caller_of};
use crate::writes::write_problem;

/// The answer's `next` when Access asks the caller to authenticate at a higher assurance first.
pub const STEP_UP: &str = "step_up";

/// The answer's `next` when Access asks for an approval on its Approval Surface.
pub const APPROVE: &str = "approve";

/// A holding of the Grant the caller exercises.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HoldingInput {
    /// The Grant, unpadded base64url of 16 bytes.
    pub grant: String,
    /// Its holder, unpadded base64url of 16 bytes.
    pub holder: String,
    /// The position that opened the holding.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub since: u64,
}

/// The basis of the Exercise.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BasisInput {
    /// The caller's holding.
    pub holding: HoldingInput,
}

/// An approval the commit relies on.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofInput {
    /// The contribution `ExerciseID` the Approval Surface returned, unpadded base64url of 32
    /// bytes.
    pub contribution: String,
}

/// One authority request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewAuthorityRequest {
    /// The ledger, `led_…`, the intent's `work.ledger` resource.
    pub ledger: String,
    /// The canonical `work:commit` intent envelope, unpadded base64url.
    pub intent: String,
    /// The Exercise nonce, unpadded base64url of 16 to 64 bytes.
    pub nonce: String,
    /// The basis.
    pub basis: BasisInput,
    /// The Actor Intent Statement, the tagged `COSE_Sign1` the caller's device Instance key
    /// signed over this commit addressed to Work's PEP, unpadded base64url.
    pub ais: String,
    /// The approvals the commit relies on.
    #[serde(default)]
    pub proofs: Vec<ProofInput>,
    /// Why, as the Approval Surface shows it: 1 to 1024 bytes, no control character.
    pub reason: String,
    /// The approver's pre-signed contribution, to push the request with when Access asks for
    /// an approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub contribution: Option<Value>,
}

/// A request pushed to the Approval Surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ApprovalAnswer {
    /// Where the caller's browser goes.
    pub url: String,
    /// The `request_uri` Access gave.
    pub request_uri: String,
    /// When the surface stops showing it, RFC 3339.
    pub expires_at: String,
}

/// What Access decided.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AuthorityDecision {
    /// `allow` or `require_action`.
    pub outcome: String,
    /// The allowed `ExerciseID`, unpadded base64url of 32 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exercise: Option<String>,
    /// The decision receipt `COSE_Sign1` exactly as Access signed it, unpadded base64url; a
    /// record's `authority` digest is its SHA-256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// What the caller does next: `step_up` to authenticate at Access as the `step_up` terms
    /// ask and send a new request, `approve` to have the request approved on the Approval
    /// Surface and send a new request with the contribution as its proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// The unmet terms, as Access shows them to the requester.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<Object>>)]
    pub unmet: Option<Vec<Value>>,
    /// The authentication terms among them, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<Object>>)]
    pub step_up: Option<Vec<Value>>,
    /// The typed authority request (Access `authority-request.schema.json`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub request: Option<Value>,
    /// The pushed request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalAnswer>,
}

/// The answer's `next` once an approval returned: a new authority request with the contribution
/// as its proof.
pub const COMMIT: &str = "commit";

/// What the approval return hands back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ApprovalReturned {
    /// The ledger, `led_…`, the next authority request names.
    pub ledger: String,
    /// The contribution `ExerciseID` Access confirmed, unpadded base64url of 32 bytes; the next
    /// authority request sends it as `proofs[].contribution`.
    pub contribution: String,
    /// The digest of the render the approver approved, unpadded base64url of 32 bytes; the
    /// caller compares it with the render it computes itself.
    pub render_digest: String,
    /// What the caller does next: `commit`, a new authority request with the contribution as
    /// its proof, whose allowed Exercise the Declaration write then refers to.
    pub next: String,
}

/// The answer's body for an approval return.
#[must_use]
pub fn returned(back: &work_query::domain::authority::ApprovalReturned) -> ApprovalReturned {
    ApprovalReturned {
        ledger: back.ledger.to_external(),
        contribution: back.contribution.text(),
        render_digest: base64url_text(&back.render_digest),
        next: COMMIT.to_owned(),
    }
}

fn invalid(code: &str) -> Box<Problem> {
    Box::new(Problem::new(ProblemCode::InvalidRequest).with_code_detail(code))
}

fn bytes(text: &str, code: &'static str) -> Result<Vec<u8>, Box<Problem>> {
    base64url(text).ok_or_else(|| invalid(code))
}

/// The ledger and the request `raw` carries with `headers`.
///
/// # Errors
/// `400 invalid_request` for a body outside the schema, `400 invalid_id` for a ledger that is
/// not `led_…`, and the `Idempotency-Key` problems of [`idempotency_key`].
pub fn authority_request(
    raw: &[u8],
    headers: &HeaderMap,
) -> Result<(LedgerId, AuthorityAsk), Box<Problem>> {
    let idempotency_key = idempotency_key(headers)?.to_owned();
    let body: NewAuthorityRequest = serde_json::from_slice(raw).map_err(|_| invalid("body"))?;
    let ledger = LedgerId::parse_external(&body.ledger)
        .map_err(|_| Box::new(Problem::new(ProblemCode::InvalidId)))?;
    let h = &body.basis.holding;
    let basis = holding(&h.grant, &h.holder, h.since).ok_or_else(|| invalid("basis"))?;
    let contributions = body
        .proofs
        .iter()
        .map(|p| ExerciseId::parse(&p.contribution).map_err(|_| invalid("proofs")))
        .collect::<Result<_, _>>()?;
    Ok((
        ledger,
        AuthorityAsk {
            intent: bytes(&body.intent, "intent")?,
            nonce: bytes(&body.nonce, "nonce")?,
            basis,
            ais: bytes(&body.ais, "ais")?,
            contributions,
            reason: body.reason,
            contribution: body.contribution,
            idempotency_key,
        },
    ))
}

/// The answer's body.
#[must_use]
pub fn decision(answer: AuthorityAnswer) -> AuthorityDecision {
    match answer {
        AuthorityAnswer::Allowed(exercise) => AuthorityDecision {
            outcome: "allow".to_owned(),
            exercise: Some(exercise.exercise.text()),
            receipt: Some(base64url_text(&exercise.receipt)),
            next: None,
            unmet: None,
            step_up: None,
            request: None,
            approval: None,
        },
        AuthorityAnswer::RequireAction {
            unmet,
            step_up,
            request,
            approval,
        } => {
            let next = if step_up.is_empty() {
                request.is_some().then(|| APPROVE.to_owned())
            } else {
                Some(STEP_UP.to_owned())
            };
            AuthorityDecision {
                outcome: "require_action".to_owned(),
                exercise: None,
                receipt: None,
                next,
                unmet: Some(unmet),
                step_up: (!step_up.is_empty()).then_some(step_up),
                request,
                approval: approval.map(|a| ApprovalAnswer {
                    url: a.url,
                    request_uri: a.request_uri,
                    expires_at: a.expires_at,
                }),
            }
        }
    }
}

fn answered(body: &impl Serialize) -> Response {
    let json = HeaderValue::from_static("application/json");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, json)],
        serde_json::to_vec(body).unwrap_or_default(),
    )
        .into_response()
}

/// Asks Access for the authority of a `work:commit`.
///
/// Work's PEP commits the caller's intent at Access's decision point under the Actor Intent
/// Statement the caller's own device signed; Work signs nothing for the caller and approves
/// nothing. The intent must be the `work:commit` of this existing ledger, valid now, and the
/// statement must name exactly this commit, Work's PEP and the domain of the caller's realm. An
/// allowed Exercise is answered only with its decision receipt verified for the intent and
/// addressed to Work's PEP. When Access asks for more, the answer says what: a step-up at
/// Access, verbatim from Access's terms, or an approval on Access's Approval Surface, with the
/// typed request and, given the approver's contribution, the pushed request's URL. A denial is
/// `403`; when Access cannot be asked, nothing is answered as authority.
#[utoipa::path(
    post,
    path = "/v1/authority-requests",
    operation_id = "create_authority_request",
    tag = "authority",
    params(
        ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body asks Access the same question again.")
    ),
    request_body(content = NewAuthorityRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "What Access decided: allow with the Exercise and its receipt, or require_action with what the caller does next.", body = AuthorityDecision, headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "A body, identifier, header or statement that does not open or does not state this commit.", body = Problem,
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
        (status = 403, description = "Access denied the commit, or the intent is not this ledger's work:commit valid now.", body = Problem,
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
        (status = 429, description = "The caller has spent its quota.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds until the next window.")
        )),
        (status = 503, description = "Access cannot be reached or its answer cannot be verified; send the same request again.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:commit")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn create_authority_request(
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
    let (ledger, ask) = match authority_request(&body, &headers) {
        Ok(asked) => asked,
        Err(problem) => return problem.into_response(),
    };
    match services.authorities.request(&caller, &ledger, &ask).await {
        Ok(answer) => answered(&decision(answer)),
        Err(refused) => write_problem(refused).into_response(),
    }
}

/// Reads the return from Access's Approval Surface.
///
/// The `redirect_uri` Work sends to the Approval Surface. Access puts the contribution Exercise,
/// the render digest and Work's `state` on the redirect; the caller's client hands the query to
/// this route with its own token. The `state` must be the one Work issued for this caller's
/// pushed request, unused and unexpired, and is used up by an answer; the contribution must be
/// an Exercise Access allowed in the caller's realm's domain, asked of Access now. The answer is
/// the contribution the caller sends as the proof of its next authority request, whose allowed
/// Exercise the Declaration write refers to. Work approves nothing here.
#[utoipa::path(
    get,
    path = "/v1/access/approval",
    operation_id = "get_approval_return",
    tag = "authority",
    params(
        ("exercise" = String, Query, description = "The contribution `ExerciseID` Access put on the redirect, unpadded base64url of 32 bytes."),
        ("render_digest" = String, Query, description = "The digest of the render the approver approved, unpadded base64url of 32 bytes."),
        ("state" = String, Query, description = "The `state` Work sent with the pushed request.")
    ),
    responses(
        (status = 200, description = "The contribution Access confirmed, for the next authority request.", body = ApprovalReturned, headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "A query without exactly one exercise, render_digest and state.", body = Problem,
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
        (status = 403, description = "A state Work did not issue to this caller, used or expired, or a contribution Access did not allow.", body = Problem,
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
        (status = 503, description = "Access cannot be reached or its answer cannot be verified; send the same request again.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:commit")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn get_approval_return(
    State(services): State<Arc<ApiServices>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let query = uri.query().unwrap_or_default();
    match services.authorities.approval(&caller, query).await {
        Ok(back) => answered(&returned(&back)),
        Err(refused) => write_problem(refused).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use work_query::domain::authority::Approval;
    use work_query::domain::writes::WriteRefusal;

    use super::*;
    use crate::conditional::IDEMPOTENCY_KEY;

    const UUID7: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
    const LEDGER: &str = "led_0101010101010101010101010101010101010101010101010101010101010101";

    fn body() -> Value {
        json!({
            "ledger": LEDGER,
            "intent": "aW50ZW50",
            "nonce": "BQUFBQUFBQUFBQUFBQUFBQ",
            "basis": {"holding": {"grant": "AQEBAQEBAQEBAQEBAQEBAQ", "holder": "AgICAgICAgICAgICAgICAg", "since": "4"}},
            "ais": "YWlz",
            "proofs": [{"contribution": "wcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcE"}],
            "reason": "Commit into the ledger",
        })
    }

    fn headers() -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(IDEMPOTENCY_KEY, HeaderValue::from_static(UUID7));
        map
    }

    // T-101 E-17 P-54
    #[test]
    fn t_101_an_authority_request_carries_one_key_the_intent_and_the_caller_s_own_statement() {
        let raw = serde_json::to_vec(&body()).unwrap();
        let (ledger, ask) = authority_request(&raw, &headers()).unwrap();
        assert_eq!(ledger.to_external(), LEDGER);
        assert_eq!(ask.intent, b"intent");
        assert_eq!(ask.nonce, vec![5; 16]);
        assert_eq!(ask.ais, b"ais");
        assert_eq!(ask.basis.since, 4);
        assert_eq!(ask.contributions, vec![ExerciseId([0xc1; 32])]);
        assert_eq!(ask.reason, "Commit into the ledger");
        assert_eq!(ask.idempotency_key, UUID7);
        assert!(ask.contribution.is_none());
        let code = |h: &HeaderMap, v: &Value| {
            authority_request(&serde_json::to_vec(v).unwrap(), h)
                .unwrap_err()
                .code
        };
        assert_eq!(
            code(&HeaderMap::new(), &body()),
            ProblemCode::IdempotencyKeyMissing
        );
        let mut extra = body();
        extra["capacity"] = json!("own");
        assert_eq!(code(&headers(), &extra), ProblemCode::InvalidRequest);
        let mut number = body();
        number["basis"]["holding"]["since"] = json!(4);
        assert_eq!(code(&headers(), &number), ProblemCode::InvalidRequest);
        let mut short = body();
        short["basis"]["holding"]["grant"] = json!("AQEB");
        assert_eq!(code(&headers(), &short), ProblemCode::InvalidRequest);
        let mut ledger = body();
        ledger["ledger"] = json!("wrk_1");
        assert_eq!(code(&headers(), &ledger), ProblemCode::InvalidId);
    }

    // T-101 P-116 E-17 E-7
    #[test]
    fn p_116_the_answer_says_whether_the_caller_steps_up_at_access_or_has_the_request_approved() {
        let aal2 = json!({"term": {"proof_kind": "authentication", "assurance": {"aal": 2}}});
        let step = decision(AuthorityAnswer::RequireAction {
            unmet: vec![aal2.clone()],
            step_up: vec![aal2.clone()],
            request: None,
            approval: None,
        });
        assert_eq!(step.outcome, "require_action");
        assert_eq!(step.next.as_deref(), Some(STEP_UP));
        assert_eq!(step.step_up, Some(vec![aal2]));
        let approve = decision(AuthorityAnswer::RequireAction {
            unmet: vec![json!({"term": {"proof_kind": "contribution"}})],
            step_up: Vec::new(),
            request: Some(json!({"reason": "r"})),
            approval: Some(Approval {
                url: "https://acme.example/v1/approve?request=x".to_owned(),
                request_uri: "urn:ietf:params:oauth:request_uri:x".to_owned(),
                expires_at: "2026-11-06T12:00:00Z".to_owned(),
            }),
        });
        assert_eq!(approve.next.as_deref(), Some(APPROVE));
        assert!(approve.step_up.is_none());
        let v = serde_json::to_value(&approve).unwrap();
        assert_eq!(
            v["approval"]["request_uri"],
            "urn:ietf:params:oauth:request_uri:x"
        );
        assert!(v.get("exercise").is_none());
        let denied = write_problem(WriteRefusal::Denied("no-covering-authority"));
        assert_eq!(denied.code, ProblemCode::AccessDenied);
        assert_eq!(denied.code_detail.as_deref(), Some("no-covering-authority"));
    }

    // T-101 E-17
    #[test]
    fn e_17_an_approval_return_hands_back_the_contribution_as_the_next_commit_s_proof() {
        let back = work_query::domain::authority::ApprovalReturned {
            ledger: LedgerId::parse_external(LEDGER).unwrap(),
            contribution: ExerciseId([0xc1; 32]),
            render_digest: [7; 32],
        };
        let v = serde_json::to_value(returned(&back)).unwrap();
        assert_eq!(
            v,
            json!({
                "ledger": LEDGER,
                "contribution": "wcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcE",
                "render_digest": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
                "next": COMMIT,
            })
        );
        for code in [
            "state_unknown",
            "state_caller",
            "state_used",
            "state_expired",
        ] {
            let p = write_problem(WriteRefusal::Denied(code));
            assert_eq!(p.code, ProblemCode::AccessDenied);
            assert_eq!(p.code_detail.as_deref(), Some(code));
        }
        assert_eq!(
            write_problem(WriteRefusal::Invalid("state")).code,
            ProblemCode::InvalidRequest
        );
    }
}
