//! What the client needs from outside (T-32): an HTTPS exchange with Access or Relay under a bound, the time, and Work's tenant map for the reconciliation.

use std::collections::BTreeMap;
use std::future::Future;

use work_proto::id::TenantId;

use crate::domain::AccessError;
use crate::domain::tenants::TenantChange;

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

    /// The body of a `200`; any other status is the peer's refusal with its problem `code`.
    ///
    /// # Errors
    /// [`AccessError::Refused`].
    pub fn ok(&self) -> Result<&[u8], AccessError> {
        if self.status == 200 {
            return Ok(&self.body);
        }
        let code = serde_json::from_slice::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| {
                v.get("code")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        Err(AccessError::Refused {
            status: self.status,
            code,
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
