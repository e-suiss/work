//! What the client needs from outside (T-32): an `https` `POST` to Relay under a bound, Work's Access service token for Relay with a `DPoP` proof per call (T-99 item 4), the pairwise `sub`s of Parties in Relay's sector from Access (T-99 item 5), and the outbox the intents wait in until Relay takes or refuses them (T-17, T-28).

use std::collections::BTreeMap;
use std::future::Future;

use work_proto::id::TenantId;

use crate::domain::answer::{Accepted, RelayError};
use crate::domain::intent::{IdempotencyKey, NotificationIntent};
use crate::domain::request::RequestError;

/// One `POST` with a JSON body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
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
    fn post(&self, request: Request) -> impl Future<Output = Result<Response, RelayError>> + Send;
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
