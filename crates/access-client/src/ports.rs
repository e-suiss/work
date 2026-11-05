//! What the client needs from outside (T-32): an HTTPS exchange with Access or Relay under a bound, the time, and Work's tenant map for the reconciliation.

use std::collections::BTreeMap;
use std::future::Future;

use serde_json::Value;
use work_proto::id::TenantId;

use crate::domain::tenants::TenantChange;
use crate::domain::{AccessError, ProblemError};

/// An HTTP method the client uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST` with a JSON body.
    Post,
}

/// One request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Absolute `https` URL.
    pub url: String,
    /// Extra headers, lower-case names.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Request {
    /// A `GET` of `url` with `accept`.
    #[must_use]
    pub fn get(url: String, accept: &str) -> Self {
        Self {
            method: Method::Get,
            url,
            headers: vec![("accept".to_owned(), accept.to_owned())],
            body: Vec::new(),
        }
    }

    /// A JSON `POST` of `body` to `url` with `accept`.
    #[must_use]
    pub fn post(url: String, accept: &str, body: Vec<u8>) -> Self {
        Self {
            method: Method::Post,
            url,
            headers: vec![
                ("accept".to_owned(), accept.to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
            ],
            body,
        }
    }

    /// The request with one more header.
    #[must_use]
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// One answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// Headers, lower-case names.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    /// The first value of header `name`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body of a `200`; a `503` is the peer's outage and any other status its refusal, each
    /// with what its RFC 9457 problem names: `code`, `reason` and `errors`.
    ///
    /// # Errors
    /// [`AccessError::Unavailable`] or [`AccessError::Refused`].
    pub fn ok(&self) -> Result<&[u8], AccessError> {
        if self.status == 200 {
            return Ok(&self.body);
        }
        let problem = serde_json::from_slice::<Value>(&self.body).unwrap_or(Value::Null);
        let text = |v: &Value, name: &str| v.get(name).and_then(Value::as_str).map(str::to_owned);
        let reason = text(&problem, "reason");
        if self.status == 503 {
            return Err(AccessError::Unavailable { reason });
        }
        let errors = problem
            .get("errors")
            .and_then(Value::as_array)
            .map(|all| {
                all.iter()
                    .filter_map(|e| {
                        Some(ProblemError {
                            pointer: text(e, "pointer"),
                            code: text(e, "code")?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Err(AccessError::Refused {
            status: self.status,
            code: text(&problem, "code").unwrap_or_default(),
            reason,
            errors,
        })
    }
}

/// An HTTPS exchange under the adapter's bound (T-32 rule 7).
pub trait Transport: Send + Sync {
    /// Sends `request`.
    fn send(&self, request: Request) -> impl Future<Output = Result<Response, AccessError>> + Send;
}

/// Wall time for cache lifetimes and certificate expiry, Unix milliseconds.
pub trait Clock: Send + Sync {
    /// Now.
    fn now_ms(&self) -> u64;
}

/// Work's tenant map: the Access tenants Work knows with the snapshot version each was last
/// reconciled at.
pub trait TenantMap: Send + Sync {
    /// The known tenants.
    fn known(&self)
    -> impl Future<Output = Result<BTreeMap<TenantId, String>, AccessError>> + Send;

    /// Applies one change.
    fn apply(&self, change: TenantChange) -> impl Future<Output = Result<(), AccessError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![(
                "content-type".to_owned(),
                "application/problem+json".to_owned(),
            )],
            body: body.as_bytes().to_vec(),
        }
    }

    // T-101
    #[test]
    fn t_101_a_refusal_carries_its_problem_code_reason_and_pointers() {
        let refused = answer(
            400,
            r##"{"type":"urn:suiss:access:problem:protocol","title":"Protocol","status":400,"code":"protocol","reason":"r","errors":[{"pointer":"#/set/basis","code":"basis"},{"code":"set"},{"pointer":"#/x"}]}"##,
        )
        .ok()
        .unwrap_err();
        assert_eq!(
            refused,
            AccessError::Refused {
                status: 400,
                code: "protocol".to_owned(),
                reason: Some("r".to_owned()),
                errors: vec![
                    ProblemError {
                        pointer: Some("#/set/basis".to_owned()),
                        code: "basis".to_owned(),
                    },
                    ProblemError {
                        pointer: None,
                        code: "set".to_owned(),
                    },
                ],
            }
        );
        assert!(!refused.is_temporary());
        assert_eq!(refused.code(), "authority_unverifiable");
        let bare = answer(401, "not json").ok().unwrap_err();
        assert_eq!(
            bare,
            AccessError::Refused {
                status: 401,
                code: String::new(),
                reason: None,
                errors: Vec::new(),
            }
        );
        assert_eq!(answer(200, "{}").ok().unwrap(), b"{}");
    }

    // T-101 T-28
    #[test]
    fn t_101_a_signer_without_its_key_is_a_temporary_outage_not_a_refusal() {
        let outage = answer(
            503,
            r#"{"type":"about:blank","title":"Unavailable","status":503,"code":"unavailable","reason":"signer-no-key"}"#,
        )
        .ok()
        .unwrap_err();
        assert_eq!(
            outage,
            AccessError::Unavailable {
                reason: Some("signer-no-key".to_owned()),
            }
        );
        assert!(outage.is_temporary());
        assert_eq!(outage.code(), "authority_unverifiable");
        assert!(!matches!(outage, AccessError::Refused { .. }));
        assert_eq!(
            answer(503, "").ok().unwrap_err(),
            AccessError::Unavailable { reason: None }
        );
        for temporary in [AccessError::Timeout, AccessError::Stale] {
            assert!(temporary.is_temporary(), "{temporary:?}");
        }
        assert!(!AccessError::Expired.is_temporary());
    }
}
