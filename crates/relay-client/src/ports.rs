//! What the client needs from outside (T-32): one `https` exchange with Relay under a bound, Work's Access service token for Relay with a `DPoP` proof per call (T-99 item 4), the pairwise `sub`s of Parties in Relay's sector from Access (T-99 item 5), the outbox the intents wait in until Relay takes or refuses them (T-17, T-28), and for Relay's events at Work's entry (T-100) the last checked discovery document, the paired tenants, the deduplication rows, the Party of a responder's `sub` and the time.

use std::collections::BTreeMap;
use std::future::Future;

use work_proto::id::TenantId;

use crate::domain::answer::{Accepted, RelayError};
use crate::domain::inbound::{Attribution, Event};
use crate::domain::intent::{IdempotencyKey, NotificationIntent};
use crate::domain::request::RequestError;

/// The method of a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`, without a body.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
}

impl Method {
    /// The method token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// One call, with a JSON body unless it is a `GET`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// Absolute `https` URL.
    pub url: String,
    /// Headers, lower-case names.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Request {
    /// The value of header `name`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
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
}

/// The `https` exchange with Relay; a call that does not reach Relay or ends past its bound is
/// [`RelayError::Unreachable`].
pub trait Transport: Send + Sync {
    /// Sends `request`.
    fn send(&self, request: Request) -> impl Future<Output = Result<Response, RelayError>> + Send;
}

/// The headers that say who is calling: Work's Access service token for Relay and the proof of
/// one call (T-99 item 4, Relay E-93).
#[derive(Clone, PartialEq, Eq)]
pub struct Authorization {
    /// `DPoP <token>`.
    pub authorization: String,
    /// The `DPoP` proof of this call.
    pub dpop: String,
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization").finish_non_exhaustive()
    }
}

/// Work's Access service token for Relay, bound by `DPoP` (T-99 item 4; Access A28 (a)).
pub trait Credential: Send + Sync {
    /// The headers of one `method` call to `url`, with a fresh proof.
    fn authorize(
        &self,
        method: &str,
        url: &str,
    ) -> impl Future<Output = Result<Authorization, RelayError>> + Send;

    /// Relay answered `401`; the next call asks for a new token.
    fn rejected(&self) {}
}

/// Access did not answer the resolution; the intent waits.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("recipients not resolved: {0}")]
pub struct Unresolvable(pub String);

/// The pairwise `sub`s of Parties.
pub trait Recipients: Send + Sync {
    /// The `sub` of each of `parties` (base64url `PartyID`s) in `realm` of `tenant` for the
    /// sector `client_id`; `None` where Access does not know the Party.
    fn subs(
        &self,
        tenant: &TenantId,
        realm: &str,
        client_id: &str,
        parties: &[String],
    ) -> impl Future<Output = Result<BTreeMap<String, Option<String>>, Unresolvable>> + Send;
}

/// How an intent left the outbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Relay took it.
    Delivered(Accepted),
    /// Relay refused it.
    Refused(RelayError),
    /// Its request could not be built.
    Invalid(RequestError),
    /// None of its recipients resolved; nothing was sent.
    NoRecipient,
}

/// What became of an intent, with the recipients that did not resolve, for the "recipient not
/// resolved" attention item of the accountable Party (T-99 item 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    /// How it left.
    pub outcome: Outcome,
    /// Parties Access did not know; they got nothing.
    pub unresolved: Vec<String>,
}

/// The outbox could not be read or written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("intent outbox: {0}")]
pub struct OutboxError(pub String);

/// The outbox of intents.
pub trait Intents: Send + Sync {
    /// Up to `limit` intents not yet settled, oldest first.
    fn pending(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<NotificationIntent>, OutboxError>> + Send;

    /// Settles the intent of `key`; it is not offered again.
    fn settle(
        &self,
        key: &IdempotencyKey,
        settlement: Settlement,
    ) -> impl Future<Output = Result<(), OutboxError>> + Send;
}

/// What the event entry needs of Relay's last checked discovery document (T-100 item 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    /// Relay's issuer: the `source` of its events.
    pub issuer: String,
    /// The product event key set.
    pub jwks_uri: String,
    /// The sector of every responder `sub` (T-104).
    pub access_client_id: String,
}

/// Relay's discovery as the process last read and checked it.
pub trait Discovery: Send + Sync {
    /// The document, `None` while Relay's discovery has not been read.
    fn current(&self) -> Option<Discovered>;
}

/// Something the entry needs did not answer; the event is asked for again.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unavailable(pub String);

/// Work's tenant pairing (T-96 item 4).
pub trait Tenants: Send + Sync {
    /// Whether `tenant` is a paired tenant of Work.
    fn paired(&self, tenant: &TenantId) -> impl Future<Output = Result<bool, Unavailable>> + Send;
}

/// One Relay event as its deduplication row names it (P-35 item 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrival<'a> {
    /// The tenant, `accesstenant`.
    pub tenant: &'a TenantId,
    /// `source`.
    pub source: &'a str,
    /// `id`.
    pub id: &'a str,
    /// SHA-256 of the body as received.
    pub digest: [u8; 32],
    /// When it arrived, Unix milliseconds.
    pub at_ms: u64,
}

/// The deduplication rows of inbound events.
pub trait Seen: Send + Sync {
    /// Writes the row unless `(tenant, source, id)` is already there; `true` for a first
    /// arrival.
    fn note(&self, arrival: &Arrival<'_>)
    -> impl Future<Output = Result<bool, Unavailable>> + Send;
}

/// The Party behind a responder's pairwise `sub` (T-100 item 6, T-104).
pub trait Responders: Send + Sync {
    /// The base64url `PartyID` of `sub` in the sector `client_id` of `tenant`; `None` when
    /// Access knows no Party for it.
    fn party(
        &self,
        tenant: &TenantId,
        client_id: &str,
        sub: &str,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send;
}

/// Time for the timestamp tolerance and the key set's age, Unix milliseconds.
pub trait Clock: Send + Sync {
    /// Now.
    fn now_ms(&self) -> u64;
}

/// What a first arrival does once it is attributed (P-114).
pub trait Attributed: Send + Sync {
    /// `event` may become a record of `attribution` alone.
    fn attributed(&self, event: &Event, attribution: &Attribution);
}
