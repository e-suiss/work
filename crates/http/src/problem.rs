//! RFC 9457 problems (T-98 item 6, P-54 item 3): `type` is `https://suiss.app/ns/work/problems/<code>`, `code` is the stable `snake_case` name of the stage 3 list, `instance` names the request, and a rule result is never a problem.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// The namespace of every problem `type` (T-98 item 6).
pub const TYPE_BASE: &str = "https://suiss.app/ns/work/problems/";

/// The problem media type.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// The stable code of a problem (T-98 item 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProblemCode {
    /// A request outside its schema.
    InvalidRequest,
    /// An identifier that does not parse to the expected type (P-112 item 3).
    InvalidId,
    /// A changing request without `Idempotency-Key` (P-99).
    IdempotencyKeyMissing,
    /// An `Idempotency-Key` that is not a `UUIDv7` within the clock bound (P-97).
    IdempotencyKeyMalformed,
    /// An `Idempotency-Key` of an archived month (P-96).
    IdempotencyKeyExpired,
    /// The same key with other content (P-54 item 4).
    IdempotencyKeyConflict,
    /// A changing request without `If-Match` (P-54 item 5).
    PreconditionRequired,
    /// An `If-Match` that is not the item version (P-54 item 5).
    PreconditionFailed,
    /// A read position token that does not open (T-97 item 4).
    ReadPositionInvalid,
    /// A read position past the canonical head (T-97 item 4).
    ReadPositionAhead,
    /// No valid Access token.
    Unauthenticated,
    /// Access answered `DENY`, with its explanation reference.
    AccessDenied,
    /// The object does not exist or the caller cannot see it (P-56).
    NotFound,
    /// A request above its size limit (P-33).
    RequestTooLarge,
    /// The kernel refused the record; `reason` carries the protocol pair (P-93).
    RecordRejected,
    /// A body carries a secret (P-95).
    SecretDetected,
    /// A restriction rule set does not compile (PR-23 item 3).
    RestrictionCompileRefused,
    /// An escalation policy outside Relay's limits (T-99 item 8).
    EscalationPolicyUnsupported,
    /// The Access `auth_context` artifact does not verify or is not bound to the record (P-116
    /// item 4).
    AuthContextInvalid,
    /// Too many requests (P-54 item 9).
    RateLimited,
    /// The server sheds load (OP-41).
    Busy,
    /// A leader change left the outcome unconfirmed; it is being checked (T-28).
    NotRecorded,
    /// Access cannot be reached, so authority cannot be verified (T-28).
    AuthorityUnverifiable,
}

impl ProblemCode {
    /// Every code, in the order of the T-98 list.
    pub const ALL: [Self; 23] = [
        Self::InvalidRequest,
        Self::InvalidId,
        Self::IdempotencyKeyMissing,
        Self::IdempotencyKeyMalformed,
        Self::IdempotencyKeyExpired,
        Self::IdempotencyKeyConflict,
        Self::PreconditionRequired,
        Self::PreconditionFailed,
        Self::ReadPositionInvalid,
        Self::ReadPositionAhead,
        Self::Unauthenticated,
        Self::AccessDenied,
        Self::NotFound,
        Self::RequestTooLarge,
        Self::RecordRejected,
        Self::SecretDetected,
        Self::RestrictionCompileRefused,
        Self::EscalationPolicyUnsupported,
        Self::AuthContextInvalid,
        Self::RateLimited,
        Self::Busy,
        Self::NotRecorded,
        Self::AuthorityUnverifiable,
    ];

    /// The `code` text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidId => "invalid_id",
            Self::IdempotencyKeyMissing => "idempotency_key_missing",
            Self::IdempotencyKeyMalformed => "idempotency_key_malformed",
            Self::IdempotencyKeyExpired => "idempotency_key_expired",
            Self::IdempotencyKeyConflict => "idempotency_key_conflict",
            Self::PreconditionRequired => "precondition_required",
            Self::PreconditionFailed => "precondition_failed",
            Self::ReadPositionInvalid => "read_position_invalid",
            Self::ReadPositionAhead => "read_position_ahead",
            Self::Unauthenticated => "unauthenticated",
            Self::AccessDenied => "access_denied",
            Self::NotFound => "not_found",
            Self::RequestTooLarge => "request_too_large",
            Self::RecordRejected => "record_rejected",
            Self::SecretDetected => "secret_detected",
            Self::RestrictionCompileRefused => "restriction_compile_refused",
            Self::EscalationPolicyUnsupported => "escalation_policy_unsupported",
            Self::AuthContextInvalid => "auth_context_invalid",
            Self::RateLimited => "rate_limited",
            Self::Busy => "busy",
            Self::NotRecorded => "not_recorded",
            Self::AuthorityUnverifiable => "authority_unverifiable",
        }
    }

    /// The code of a `code` text.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == text)
    }

    /// The HTTP status (T-98 item 6).
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest
            | Self::InvalidId
            | Self::IdempotencyKeyMissing
            | Self::IdempotencyKeyMalformed
            | Self::IdempotencyKeyExpired
            | Self::ReadPositionInvalid
            | Self::ReadPositionAhead => StatusCode::BAD_REQUEST,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::AccessDenied => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::IdempotencyKeyConflict
            | Self::RecordRejected
            | Self::SecretDetected
            | Self::RestrictionCompileRefused
            | Self::EscalationPolicyUnsupported
            | Self::AuthContextInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Busy | Self::NotRecorded | Self::AuthorityUnverifiable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }

    /// The short title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid request",
            Self::InvalidId => "Invalid identifier",
            Self::IdempotencyKeyMissing => "Idempotency-Key missing",
            Self::IdempotencyKeyMalformed => "Idempotency-Key malformed",
            Self::IdempotencyKeyExpired => "Idempotency-Key expired",
            Self::IdempotencyKeyConflict => "Idempotency-Key reused with other content",
            Self::PreconditionRequired => "If-Match required",
            Self::PreconditionFailed => "Item version changed",
            Self::ReadPositionInvalid => "Read position invalid",
            Self::ReadPositionAhead => "Read position ahead of the ledger",
            Self::Unauthenticated => "Not authenticated",
            Self::AccessDenied => "Access denied",
            Self::NotFound => "Not found",
            Self::RequestTooLarge => "Request too large",
            Self::RecordRejected => "Record rejected",
            Self::SecretDetected => "Secret detected",
            Self::RestrictionCompileRefused => "Restriction rule refused",
            Self::EscalationPolicyUnsupported => "Escalation policy not supported",
            Self::AuthContextInvalid => "Authentication context invalid",
            Self::RateLimited => "Rate limited",
            Self::Busy => "Busy",
            Self::NotRecorded => "Not confirmed, being checked",
            Self::AuthorityUnverifiable => "Authority cannot be verified",
        }
    }

    /// True for the 429 and 503 problems, whose request may be sent again unchanged.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::Busy | Self::NotRecorded | Self::AuthorityUnverifiable
        )
    }

    /// The `type` URI.
    #[must_use]
    pub fn type_uri(self) -> String {
        format!("{TYPE_BASE}{}", self.as_str())
    }
}

/// A field error with the JSON Pointer of the field (RFC 9457 section 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct FieldError {
    /// JSON Pointer of the field in the request body.
    pub pointer: String,
    /// What is wrong with it.
    pub detail: String,
}

/// An RFC 9457 problem response (T-98 item 6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct Problem {
    /// `https://suiss.app/ns/work/problems/<code>`.
    #[serde(rename = "type")]
    pub type_uri: String,
    /// The short title of the code.
    pub title: String,
    /// The HTTP status.
    pub status: u16,
    /// What happened in this occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// `urn:work:request:<Request-Id>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// The stable code.
    pub code: ProblemCode,
    /// Whether the same request may be sent again.
    pub retryable: bool,
    /// The protocol reason pair `[code, detail]` of a kernel refusal (P-93).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Vec<String>>,
    /// The stable code of the shared crate that refused, such as `policy-cost-too-high`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_detail: Option<String>,
    /// Field errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<FieldError>>,
    /// Seconds after which the request may be sent again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u32>,
}

impl Problem {
    /// The problem of `code` with nothing but its code, title and status.
    #[must_use]
    pub fn new(code: ProblemCode) -> Self {
        Self {
            type_uri: code.type_uri(),
            title: code.title().to_owned(),
            status: code.status().as_u16(),
            detail: None,
            instance: None,
            code,
            retryable: code.retryable(),
            reason: None,
            code_detail: None,
            errors: None,
            retry_after: matches!(code, ProblemCode::Busy).then_some(1),
        }
    }

    /// This problem with a `detail`.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// This problem naming the request `request_id`.
    #[must_use]
    pub fn for_request(mut self, request_id: &str) -> Self {
        self.instance = Some(format!("urn:work:request:{request_id}"));
        self
    }

    /// This problem with the stable code of the shared crate that refused.
    #[must_use]
    pub fn with_code_detail(mut self, code_detail: impl Into<String>) -> Self {
        self.code_detail = Some(code_detail.into());
        self
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = self.code.status();
        let retry_after = self.retry_after;
        let body = serde_json::to_vec(&self).unwrap_or_default();
        let mut response = (status, body).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
        if let Some(seconds) = retry_after {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-98
    #[test]
    fn t_98_every_problem_has_a_stable_code_and_type() {
        let statuses: Vec<(&str, u16)> = ProblemCode::ALL
            .into_iter()
            .map(|code| (code.as_str(), code.status().as_u16()))
            .collect();
        assert_eq!(
            statuses,
            [
                ("invalid_request", 400),
                ("invalid_id", 400),
                ("idempotency_key_missing", 400),
                ("idempotency_key_malformed", 400),
                ("idempotency_key_expired", 400),
                ("idempotency_key_conflict", 422),
                ("precondition_required", 428),
                ("precondition_failed", 412),
                ("read_position_invalid", 400),
                ("read_position_ahead", 400),
                ("unauthenticated", 401),
                ("access_denied", 403),
                ("not_found", 404),
                ("request_too_large", 413),
                ("record_rejected", 422),
                ("secret_detected", 422),
                ("restriction_compile_refused", 422),
                ("escalation_policy_unsupported", 422),
                ("auth_context_invalid", 422),
                ("rate_limited", 429),
                ("busy", 503),
                ("not_recorded", 503),
                ("authority_unverifiable", 503),
            ]
        );
        for code in ProblemCode::ALL {
            assert_eq!(ProblemCode::parse(code.as_str()), Some(code));
            let json = serde_json::to_value(Problem::new(code)).unwrap();
            assert_eq!(json["code"], code.as_str());
            assert_eq!(
                json["type"],
                format!("https://suiss.app/ns/work/problems/{}", code.as_str())
            );
            assert_eq!(json["status"], code.status().as_u16());
            assert!(
                code.as_str()
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_')
            );
        }
        assert_eq!(work_proto::id::INVALID_ID, ProblemCode::InvalidId.as_str());
        assert_eq!(
            work_proto::position::INVALID,
            ProblemCode::ReadPositionInvalid.as_str()
        );
        assert_eq!(
            work_proto::position::AHEAD,
            ProblemCode::ReadPositionAhead.as_str()
        );
    }

    // T-98
    #[test]
    fn t_98_a_problem_is_problem_json_with_its_request_and_retry_after() {
        let problem = Problem::new(ProblemCode::Busy).for_request("req-1");
        assert_eq!(problem.instance.as_deref(), Some("urn:work:request:req-1"));
        let response = problem.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            PROBLEM_JSON
        );
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
        let json = serde_json::to_value(
            Problem::new(ProblemCode::RestrictionCompileRefused)
                .with_detail("rule set refused")
                .with_code_detail("policy-too-many-policies"),
        )
        .unwrap();
        assert_eq!(json["code_detail"], "policy-too-many-policies");
        assert_eq!(json["retryable"], false);
        assert!(json.get("retry_after").is_none());
        assert!(json.get("instance").is_none());
    }
}
