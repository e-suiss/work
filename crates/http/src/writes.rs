//! The consequential writes of the REST family (P-13, P-21, P-54 items 4 and 5, E-45, T-28): a write names its caller from the Access access token and `DPoP` proof first, as every read does, carries one `Idempotency-Key` and one strong `If-Match`, and hands the record as received with the Access evidence it refers to to the write path; the API layer decides nothing about authority and never turns the transport identity into a Party.

use std::sync::Arc;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use work_kernel::codec::plain_digest;
use work_kernel::id::LedgerId;
use work_kernel::validate::ActorType;
use work_proto::id::ExternalId as _;
use work_query::domain::writes::{
    AuthContextGiven, AuthorityGiven, DeclarationRequest, DeclaredTypes, ExerciseId, WriteRefusal,
    Written, base64url,
};

use crate::common::RequestContext;
use crate::conditional::{idempotency_key, idempotency_refusal, if_match};
use crate::problem::{Problem, ProblemCode};
use crate::reads::{ApiServices, caller_of};

/// The Access `auth_context` artifact of an unsigned human record.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthContextInput {
    /// The tagged `COSE_Sign1` as Access issued it, unpadded base64url.
    pub artifact: String,
    /// Access's `digest` of it, unpadded base64url of 32 bytes.
    pub digest: String,
}

/// The Access Exercise the record's `authority` refers to.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityInput {
    /// The `ExerciseID`, unpadded base64url of 32 bytes.
    pub exercise: String,
    /// The canonical intent envelope Access allowed it for, unpadded base64url.
    pub intent: String,
}

/// The actor types the request declares; the envelope writes them only as
/// `declared_unverified`, and Access's bindings win (P-12).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ActorTypesInput {
    /// The author's: `human`, `agent`, `system`, `machine` or `organization`.
    pub author: String,
    /// One per `on_behalf_of` ring, in chain order.
    #[serde(default)]
    pub on_behalf_of: Vec<String>,
    /// One per evidence presenter, in `evidence` order.
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// One commitment Declaration.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewDeclaration {
    /// The tagged `COSE_Sign1` of a signed record, or the `SignedRecord` bytes of an unsigned
    /// human one sent with `auth_context`, unpadded base64url.
    pub record: String,
    /// The `auth_context` artifact of an unsigned human record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<AuthContextInput>,
    /// The Exercise the record's `authority` refers to.
    pub authority: AuthorityInput,
    /// The declared actor types.
    pub actor_types: ActorTypesInput,
}

/// The written record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct WrittenAnswer {
    /// The ledger, `led_…`.
    pub ledger: String,
    /// The record, `rec_…`.
    pub record: String,
    /// Its position.
    #[serde(with = "crate::json::decimal")]
    #[schema(value_type = String)]
    pub pos: u64,
    /// True when the answer is that of the request first sent with this `Idempotency-Key`.
    pub replayed: bool,
}

fn invalid(code: &str) -> Problem {
    Problem::new(ProblemCode::InvalidRequest).with_code_detail(code)
}

/// The problem of a write that wrote nothing (T-98 item 6, T-28).
#[must_use]
pub fn write_problem(refusal: WriteRefusal) -> Problem {
    match refusal {
        WriteRefusal::Invalid(code) => invalid(code),
        WriteRefusal::Idempotency(code) => idempotency_refusal(code),
        WriteRefusal::PreconditionFailed => Problem::new(ProblemCode::PreconditionFailed),
        WriteRefusal::NotFound => Problem::new(ProblemCode::NotFound),
        WriteRefusal::Rejected(reason) => {
            let mut problem = Problem::new(ProblemCode::RecordRejected);
            problem.reason = Some(match reason.split_once(':') {
                Some((code, detail)) => vec![code.to_owned(), detail.to_owned()],
                None => vec![reason],
            });
            problem
        }
        WriteRefusal::AuthContext(code) => {
            Problem::new(ProblemCode::AuthContextInvalid).with_code_detail(code)
        }
        WriteRefusal::Denied(code) => {
            Problem::new(ProblemCode::AccessDenied).with_code_detail(code)
        }
        WriteRefusal::Unverifiable(_) => Problem::new(ProblemCode::AuthorityUnverifiable),
        WriteRefusal::Busy { retry_after_s } => {
            Problem::new(ProblemCode::Busy).with_retry_after(retry_after_s)
        }
        WriteRefusal::NotRecorded => Problem::new(ProblemCode::NotRecorded),
    }
}

fn actor(name: &str) -> Result<ActorType, Box<Problem>> {
    ActorType::from_wire_name(name).ok_or_else(|| Box::new(invalid("actor_types")))
}

fn bytes(text: &str, code: &'static str) -> Result<Vec<u8>, Box<Problem>> {
    base64url(text).ok_or_else(|| Box::new(invalid(code)))
}

/// The write path's request for `body`, received as `raw` with `headers`.
///
/// # Errors
/// `400 invalid_request` for a body outside the schema, the `Idempotency-Key` and `If-Match`
/// problems of [`idempotency_key`] and [`if_match`].
pub fn declaration_request(
    raw: &[u8],
    headers: &HeaderMap,
    traceparent: String,
) -> Result<DeclarationRequest, Box<Problem>> {
    let idempotency_key = idempotency_key(headers)?.to_owned();
    let if_match = if_match(headers)?;
    let body: NewDeclaration =
        serde_json::from_slice(raw).map_err(|_| Box::new(invalid("body")))?;
    let auth_context = body
        .auth_context
        .as_ref()
        .map(|a| -> Result<AuthContextGiven, Box<Problem>> {
            Ok(AuthContextGiven {
                artifact: bytes(&a.artifact, "auth_context")?,
                digest: bytes(&a.digest, "auth_context")?
                    .try_into()
                    .map_err(|_| Box::new(invalid("auth_context")))?,
            })
        })
        .transpose()?;
    let exercise =
        ExerciseId::parse(&body.authority.exercise).map_err(|_| Box::new(invalid("authority")))?;
    let declared = DeclaredTypes {
        author: actor(&body.actor_types.author)?,
        on_behalf_of: body
            .actor_types
            .on_behalf_of
            .iter()
            .map(String::as_str)
            .map(actor)
            .collect::<Result<_, _>>()?,
        evidence: body
            .actor_types
            .evidence
            .iter()
            .map(String::as_str)
            .map(actor)
            .collect::<Result<_, _>>()?,
    };
    Ok(DeclarationRequest {
        record: bytes(&body.record, "record")?,
        auth_context,
        authority: Some(AuthorityGiven {
            exercise,
            intent: bytes(&body.authority.intent, "intent")?,
        }),
        declared,
        digest: *plain_digest(raw).as_bytes(),
        idempotency_key,
        if_match,
        traceparent,
    })
}

fn created(ledger: &LedgerId, written: &Written) -> Response {
    let body = WrittenAnswer {
        ledger: ledger.to_external(),
        record: written.record.to_external(),
        pos: written.pos,
        replayed: written.replayed,
    };
    let json = HeaderValue::from_static("application/json");
    (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, json)],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

/// Writes one commitment Declaration.
///
/// The record is admitted only under the Access Exercise its `authority` refers to: Access is
/// asked for that Exercise on every request, its decision receipt must verify and be exactly the
/// proof the `authority` digest names, the intent must be `work:commit` on this ledger and valid
/// now, and the record's capacity must be the Exercise's. A signed record is checked against the
/// key Access binds at admission; an unsigned one must be the caller's own, with its Access
/// `auth_context`. When Access cannot be asked, nothing is written.
#[utoipa::path(
    post,
    path = "/v1/ledgers/{ledger}/declarations",
    operation_id = "create_declaration",
    tag = "records",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
        ("If-Match" = String, Header, description = "The strong ETag of the version of the item the record changes, `\"0\"` before its first record.")
    ),
    request_body(content = NewDeclaration, content_type = "application/json"),
    responses(
        (status = 201, description = "The record is in the ledger.", body = WrittenAnswer, headers(
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
        (status = 422, description = "The kernel rejected the record, its auth_context does not verify, or the key was reused with another body.", body = Problem,
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
    extensions(("x-work-action" = json!("work:commit")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn create_declaration(
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
    let request = match declaration_request(&body, &headers, context.traceparent().to_string()) {
        Ok(request) => request,
        Err(problem) => return problem.into_response(),
    };
    match services.writes.declare(&caller, &ledger, &request).await {
        Ok(written) => created(&ledger, &written),
        Err(refused) => write_problem(refused).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderName;
    use serde_json::{Value, json};
    use work_kernel::id::{Digest, RecordId};

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

    fn body() -> Value {
        json!({
            "record": "Y29zZQ",
            "authority": {
                "exercise": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                "intent": "aW50ZW50",
            },
            "actor_types": {"author": "agent", "on_behalf_of": ["organization"]},
        })
    }

    // P-54 P-13 E-45 SEC-18
    #[test]
    fn p_54_a_declaration_carries_one_key_one_if_match_and_its_access_evidence() {
        let both = headers(&[(IDEMPOTENCY_KEY, UUID7), (header::IF_MATCH, "\"3\"")]);
        let raw = serde_json::to_vec(&body()).unwrap();
        let request = declaration_request(&raw, &both, "tp".to_owned()).unwrap();
        assert_eq!(request.record, b"cose");
        assert_eq!(request.if_match, 3);
        assert_eq!(request.idempotency_key, UUID7);
        assert_eq!(request.declared.author, ActorType::Agent);
        assert_eq!(request.declared.on_behalf_of, vec![ActorType::Organization]);
        assert!(request.auth_context.is_none());
        let authority = request.authority.unwrap();
        assert_eq!(authority.exercise, ExerciseId([1; 32]));
        assert_eq!(authority.intent, b"intent");
        assert_eq!(request.digest, *plain_digest(&raw).as_bytes());
        let code = |h: &HeaderMap, raw: &[u8]| {
            declaration_request(raw, h, String::new()).unwrap_err().code
        };
        let no_key = headers(&[(header::IF_MATCH, "\"3\"")]);
        assert_eq!(code(&no_key, &raw), ProblemCode::IdempotencyKeyMissing);
        let no_match = headers(&[(IDEMPOTENCY_KEY, UUID7)]);
        assert_eq!(code(&no_match, &raw), ProblemCode::PreconditionRequired);
        let mut extra = body();
        extra["actor_type"] = json!("human");
        let extra = serde_json::to_vec(&extra).unwrap();
        assert_eq!(code(&both, &extra), ProblemCode::InvalidRequest);
        let mut unknown = body();
        unknown["actor_types"]["author"] = json!("robot");
        let unknown = serde_json::to_vec(&unknown).unwrap();
        assert_eq!(code(&both, &unknown), ProblemCode::InvalidRequest);
        let mut no_authority = body();
        no_authority.as_object_mut().unwrap().remove("authority");
        let no_authority = serde_json::to_vec(&no_authority).unwrap();
        assert_eq!(code(&both, &no_authority), ProblemCode::InvalidRequest);
    }

    // T-28 P-13 P-105 E-13 P-93
    #[test]
    fn t_28_a_write_access_cannot_check_is_503_and_one_it_does_not_authorise_403() {
        let problem = write_problem(WriteRefusal::Unverifiable("access_unreachable"));
        assert_eq!(problem.code, ProblemCode::AuthorityUnverifiable);
        assert!(problem.code_detail.is_none());
        let denied = write_problem(WriteRefusal::Denied("capacity_mismatch"));
        assert_eq!(denied.code, ProblemCode::AccessDenied);
        assert_eq!(denied.code_detail.as_deref(), Some("capacity_mismatch"));
        let rejected = write_problem(WriteRefusal::Rejected("signature:kid_unknown".to_owned()));
        assert_eq!(rejected.code, ProblemCode::RecordRejected);
        assert_eq!(
            rejected.reason,
            Some(vec!["signature".to_owned(), "kid_unknown".to_owned()])
        );
        let busy = write_problem(WriteRefusal::Busy { retry_after_s: 2 });
        assert_eq!(busy.retry_after, Some(2));
        assert_eq!(
            write_problem(WriteRefusal::Idempotency("idempotency_key_conflict")).code,
            ProblemCode::IdempotencyKeyConflict
        );
        let answer = created(
            &LedgerId(Digest::sha256([1; 32])),
            &Written {
                record: RecordId(Digest::sha256([2; 32])),
                pos: 7,
                replayed: false,
            },
        );
        assert_eq!(answer.status(), StatusCode::CREATED);
    }
}
