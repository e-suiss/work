//! What the client needs from outside (T-32): an HTTPS exchange with Access or Relay under a bound, the time, randomness, the actor kinds of the Parties a record names without signing it, Work's tenant map for the reconciliation, Work's realm table for the pairing step, and the inbound deduplication row and the effects of an Access event (T-102).

use std::collections::BTreeMap;
use std::future::Future;

use serde_json::Value;
use work_proto::id::TenantId;

use crate::domain::events::Signal;
use crate::domain::keys::{ActorKind, DomainId, KernelId};
use crate::domain::pairing::{RealmChange, StoredRealm};
use crate::domain::streams::StreamStatus;
use crate::domain::tenants::TenantChange;
use crate::domain::{AccessError, ProblemError};

/// The W3C trace context header every call carries (P-42).
pub const TRACEPARENT: &str = "traceparent";

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

    /// The request carrying `traceparent`, the W3C trace context it is sent in (P-42, T-39),
    /// unless it already names one.
    #[must_use]
    pub fn traced(self, traceparent: Option<&str>) -> Self {
        match traceparent {
            Some(value) if !self.headers.iter().any(|(n, _)| n == TRACEPARENT) => {
                self.with(TRACEPARENT, value)
            }
            _ => self,
        }
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

    /// The body of a `200` or `201`; otherwise as [`Response::ok`].
    ///
    /// # Errors
    /// [`AccessError::Unavailable`] or [`AccessError::Refused`].
    pub fn created(&self) -> Result<&[u8], AccessError> {
        if self.status == 201 {
            Ok(&self.body)
        } else {
            self.ok()
        }
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

/// Randomness for one-time values such as an assertion's `jti` (T-32 rule 2).
pub trait Random: Send + Sync {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`AccessError::KeyStore`] when no randomness is available.
    fn fill(&self, out: &mut [u8]) -> Result<(), AccessError>;
}

/// The stored stream: its id, its last status (`None` while missing) and how often Work opened
/// it again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredStream {
    /// The stream id.
    pub id: Option<String>,
    /// The last status read.
    pub status: Option<StreamStatus>,
    /// Reopenings so far.
    pub recreated: u64,
}

/// Work's realm table and stream row (T-103 item 5).
pub trait PairingStore: Send + Sync {
    /// The stored realms of `tenant`.
    fn realms(
        &self,
        tenant: &TenantId,
    ) -> impl Future<Output = Result<Vec<StoredRealm>, AccessError>> + Send;

    /// Applies one change at `at_ms`; for [`RealmChange::Failed`] the failed runs in a row now.
    fn apply(
        &self,
        tenant: &TenantId,
        change: &RealmChange,
        at_ms: u64,
    ) -> impl Future<Output = Result<Option<u64>, AccessError>> + Send;

    /// How many live realms have at least `runs` failed runs in a row.
    fn stalled(&self, runs: u64) -> impl Future<Output = Result<u64, AccessError>> + Send;

    /// The stored stream.
    fn stream(&self) -> impl Future<Output = Result<Option<StoredStream>, AccessError>> + Send;

    /// Records the stream `id` read with `status` at `at_ms` (`None` for both while missing);
    /// `recreated` counts one more reopening.
    fn record_stream(
        &self,
        id: Option<&str>,
        status: Option<StreamStatus>,
        recreated: bool,
        at_ms: u64,
    ) -> impl Future<Output = Result<StoredStream, AccessError>> + Send;
}

/// One inbound event as its deduplication row names it (T-102 item 4, P-35 item 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrival<'a> {
    /// The tenant the event happened in.
    pub tenant: &'a TenantId,
    /// `iss`.
    pub source: &'a str,
    /// `jti`.
    pub id: &'a str,
    /// SHA-256 of the bytes as received.
    pub digest: [u8; 32],
    /// Work's clock at arrival, Unix milliseconds.
    pub at_ms: u64,
}

/// The `work.inbound_seen` row of the tenant (T-102 item 4).
pub trait InboundLog: Send + Sync {
    /// Writes the row unless `(tenant, source, id)` is already there; `true` for a first
    /// arrival.
    fn note(&self, arrival: &Arrival<'_>)
    -> impl Future<Output = Result<bool, AccessError>> + Send;
}

/// The actor kinds Access recorded for Parties a record names but that sign nothing in it: its
/// `on_behalf_of` principals and evidence presenters (P-12, MD-7 item 3). A Party left out of
/// the answer has no binding and stays `declared_unverified`.
pub trait PartyKinds: Send + Sync {
    /// The kinds of `parties` in `domain` that Access binds.
    fn kinds(
        &self,
        domain: DomainId,
        parties: &[KernelId],
    ) -> impl Future<Output = Result<BTreeMap<KernelId, ActorKind>, AccessError>> + Send;
}

/// The Party lookup while Access serves no signed Party status lookup: it binds no Party, so
/// every principal and presenter stays `declared_unverified` (P-12).
#[derive(Clone, Copy, Debug, Default)]
pub struct Unpublished;

impl PartyKinds for Unpublished {
    fn kinds(
        &self,
        _domain: DomainId,
        _parties: &[KernelId],
    ) -> impl Future<Output = Result<BTreeMap<KernelId, ActorKind>, AccessError>> + Send {
        std::future::ready(Ok(BTreeMap::new()))
    }
}

/// What an accepted Access event does outside the intake (T-102 item 5).
pub trait Effects: Send + Sync {
    /// Starts the pairing step for `tenant` (T-103 item 1).
    fn pair(&self, tenant: &TenantId);

    /// Drops every cached key of `domain` at once.
    fn forget_domain(&self, domain: DomainId);

    /// Fails every consequential action closed: Work's own Access client is disabled (T-28).
    fn disable_client(&self);

    /// Tells the operator.
    fn signal(&self, signal: &Signal);
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
