//! Access events pushed to Work's event entry (T-102, RFC 8935, RFC 8417): the `Content-Type` alone picks the verifier; an Access SET is a compact JWS whose header is `typ` `secevent+jwt`, `alg` `ES256` or `Ed25519` (never `EdDSA`) and a 43-character `kid`, signed by a key of the platform realm's JWKS; its claims name `[suiss] access` as `iss`, Work's `client_id` in `aud`, an `iat` no older than the discovery freshness bound, a 43-character `jti`, the `access_tenant` the event happened in and exactly one member of `events`, `urn:suiss:access:event:<name>`. Every refusal is one of the RFC 8935 error codes.

use serde_json::{Map, Value};
use suiss_crypto::cose::{KeySet, PublicKey};
use suiss_crypto::sig::{PureBackend, ed25519, p256};
use work_proto::id::TenantId;

use crate::domain::discovery::REFRESH_GRACE_MS;
use crate::domain::keys::{DomainId, Kid};
use crate::domain::{fixed_b64url, from_b64url};

/// The media type of an Access SET (RFC 8417 §2.3).
pub const SET_CONTENT_TYPE: &str = "application/secevent+jwt";

/// The media type of a Relay event (T-100 item 4).
pub const CLOUDEVENTS_CONTENT_TYPE: &str = "application/cloudevents+json";

/// The JWS `typ` of a SET.
pub const SET_TYPE: &str = "secevent+jwt";

/// The prefix of every Access event type.
pub const EVENT_PREFIX: &str = "urn:suiss:access:event:";

/// The largest SET the entry reads.
pub const MAX_SET_BYTES: usize = 65_536;

/// How old an `iat` may be: the discovery refresh interval and its grace (T-102 item 3).
pub const IAT_MAX_AGE_MS: u64 = 5 * 60 * 1000 + REFRESH_GRACE_MS;

/// How far ahead of Work's clock an `iat` may be.
pub const IAT_SKEW_MS: u64 = 60_000;

/// Which verifier a request goes to, by its `Content-Type` only (T-102 item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verifier {
    /// An Access SET.
    Access,
    /// A Relay event.
    Relay,
    /// Neither: `415`.
    Unsupported,
}

/// The verifier of a `Content-Type` value; parameters are not allowed.
#[must_use]
pub fn verifier(content_type: Option<&str>) -> Verifier {
    match content_type.map(str::trim) {
        Some(t) if t.eq_ignore_ascii_case(SET_CONTENT_TYPE) => Verifier::Access,
        Some(t) if t.eq_ignore_ascii_case(CLOUDEVENTS_CONTENT_TYPE) => Verifier::Relay,
        _ => Verifier::Unsupported,
    }
}

/// Why a SET is refused, as RFC 8935 §2.3 names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The SET is malformed or misses a claim, `access_tenant` among them.
    #[error("invalid_request: {0}")]
    InvalidRequest(&'static str),
    /// The `kid` is not a key of the platform realm or does not fit `alg`.
    #[error("invalid_key: {0}")]
    InvalidKey(&'static str),
    /// `iss` is not `[suiss] access`.
    #[error("invalid_issuer")]
    InvalidIssuer,
    /// `aud` does not name Work's client.
    #[error("invalid_audience")]
    InvalidAudience,
    /// The signature does not verify.
    #[error("authentication_failed")]
    AuthenticationFailed,
}

impl Refusal {
    /// The `err` code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidKey(_) => "invalid_key",
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidAudience => "invalid_audience",
            Self::AuthenticationFailed => "authentication_failed",
        }
    }

    /// The RFC 8935 error body, `{"err", "description"}`.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        serde_json::json!({"err": self.code(), "description": self.to_string()})
            .to_string()
            .into_bytes()
    }
}

/// The JWS algorithm of a SET.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    /// ECDSA P-256 with SHA-256.
    Es256,
    /// Ed25519 (RFC 9864).
    Ed25519,
}

/// A SET split into its parts; nothing of it is trusted yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unverified {
    /// The header's algorithm.
    pub alg: Alg,
    /// The header's `kid`.
    pub kid: [u8; 32],
    signing_input: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn part(text: &str, what: &'static str) -> Result<Vec<u8>, Refusal> {
    from_b64url(text).map_err(|_| Refusal::InvalidRequest(what))
}

fn object(bytes: &[u8], what: &'static str) -> Result<Map<String, Value>, Refusal> {
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(Refusal::InvalidRequest(what)),
    }
}

/// Splits a compact SET and reads its header.
///
/// # Errors
/// [`Refusal::InvalidRequest`] for a malformed SET, a `typ` other than `secevent+jwt`, an
/// `alg` other than `ES256` or `Ed25519` (`EdDSA` included) or a header with other members.
pub fn parse(bytes: &[u8]) -> Result<Unverified, Refusal> {
    if bytes.len() > MAX_SET_BYTES {
        return Err(Refusal::InvalidRequest("size"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal::InvalidRequest("encoding"))?;
    let text = text.trim_end_matches(['\r', '\n']);
    let mut parts = text.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::InvalidRequest("compact serialization"));
    };
    let header = object(&part(h, "header")?, "header")?;
    if header.get("typ").and_then(Value::as_str) != Some(SET_TYPE) {
        return Err(Refusal::InvalidRequest("typ"));
    }
    let alg = match header.get("alg").and_then(Value::as_str) {
        Some("ES256") => Alg::Es256,
        Some("Ed25519") => Alg::Ed25519,
        _ => return Err(Refusal::InvalidRequest("alg")),
    };
    if header
        .keys()
        .any(|k| !matches!(k.as_str(), "alg" | "kid" | "typ"))
    {
        return Err(Refusal::InvalidRequest("header"));
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .and_then(|k| fixed_b64url::<32>(k).ok())
        .ok_or(Refusal::InvalidKey("kid"))?;
    let signing_len = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(Refusal::InvalidRequest("size"))?;
    Ok(Unverified {
        alg,
        kid,
        signing_input: text
            .as_bytes()
            .get(..signing_len)
            .ok_or(Refusal::InvalidRequest("size"))?
            .to_vec(),
        payload: part(p, "payload")?,
        signature: part(s, "signature")?,
    })
}

impl Unverified {
    /// Verifies the signature under the key `kid` names in `keys`, the platform realm's JWKS,
    /// and gives the claims bytes.
    ///
    /// # Errors
    /// [`Refusal::InvalidKey`] for a `kid` the set does not hold or a key that does not fit
    /// `alg`; [`Refusal::AuthenticationFailed`] for a signature that does not verify.
    pub fn verify(&self, keys: &KeySet) -> Result<&[u8], Refusal> {
        let key = keys
            .keys
            .get(&self.kid)
            .ok_or(Refusal::InvalidKey("unknown kid"))?;
        let checked = match (self.alg, key) {
            (Alg::Es256, PublicKey::P256(sec1)) => p256(
                &PureBackend,
                sec1,
                &self.signing_input,
                &self.signature,
                false,
            ),
            (Alg::Ed25519, PublicKey::Ed25519(pk)) => {
                ed25519(&PureBackend, pk, &self.signing_input, &self.signature)
            }
            _ => return Err(Refusal::InvalidKey("alg does not fit the key")),
        };
        checked.map_err(|_| Refusal::AuthenticationFailed)?;
        Ok(&self.payload)
    }
}

/// What the claims of a SET must say.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    /// `[suiss] access`, the platform realm's issuer.
    pub issuer: &'a str,
    /// `WORK_ACCESS_CLIENT_ID`.
    pub audience: &'a str,
    /// Work's clock, Unix milliseconds.
    pub now_ms: u64,
}

/// How an `api_client` event changed the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientChange {
    /// `api_client.created`.
    Created,
    /// `api_client.updated`.
    Updated,
    /// `api_client.disabled`.
    Disabled,
}

/// What an Access event is about (T-102 item 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// `authority-revoked`, `authority-narrowed`, `authority-expired`, `mandate-ended`,
    /// `revalidation-required` or `projection-invalidated`: the domain's cache is dropped.
    Revocation {
        /// The event name.
        name: String,
        /// The governing domain.
        domain: DomainId,
    },
    /// `instance-terminated`: the domain's cached keys are dropped.
    InstanceTerminated {
        /// The governing domain.
        domain: DomainId,
    },
    /// `party.compromised`.
    Compromised {
        /// The governing domain.
        domain: DomainId,
        /// The Party, as Access wrote it.
        party: String,
        /// The compromised keys.
        kids: Vec<Kid>,
        /// `window_from`–`declared_at`, Unix milliseconds; `None` when the event does not carry
        /// `window_from`, which leaves it unprocessed (T-102 item 5).
        window: Option<(u64, u64)>,
    },
    /// `party.disabled`.
    PartyDisabled {
        /// The governing domain.
        domain: DomainId,
        /// The Party, as Access wrote it.
        party: String,
    },
    /// `tenant.created`.
    TenantCreated,
    /// `api_client.*`.
    ApiClient {
        /// What changed.
        change: ClientChange,
        /// The client.
        client_id: String,
    },
    /// `organization.*`, ignored until Access's organization model (T-96 note item 4).
    Organization(String),
    /// A type Work does not know; only its deduplication row is written.
    Unknown(String),
}

impl Event {
    /// The event name, without the type prefix.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Revocation { name, .. } | Self::Organization(name) | Self::Unknown(name) => {
                name.as_str()
            }
            Self::InstanceTerminated { .. } => "instance-terminated",
            Self::Compromised { .. } => "party.compromised",
            Self::PartyDisabled { .. } => "party.disabled",
            Self::TenantCreated => "tenant.created",
            Self::ApiClient { change, .. } => match change {
                ClientChange::Created => "api_client.created",
                ClientChange::Updated => "api_client.updated",
                ClientChange::Disabled => "api_client.disabled",
            },
        }
    }
}

/// A verified SET.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Set {
    /// `iss`.
    pub iss: String,
    /// `jti`.
    pub jti: String,
    /// The tenant the event happened in.
    pub tenant: TenantId,
    /// The event.
    pub event: Event,
}

const REVOCATIONS: [&str; 6] = [
    "authority-revoked",
    "authority-narrowed",
    "authority-expired",
    "mandate-ended",
    "revalidation-required",
    "projection-invalidated",
];

fn text<'a>(payload: &'a Map<String, Value>, key: &'static str) -> Result<&'a str, Refusal> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Refusal::InvalidRequest(key))
}

fn domain(payload: &Map<String, Value>) -> Result<DomainId, Refusal> {
    fixed_b64url::<32>(text(payload, "domain")?)
        .map(DomainId)
        .map_err(|_| Refusal::InvalidRequest("domain"))
}

fn compromised(payload: &Map<String, Value>) -> Result<Event, Refusal> {
    let kids = payload
        .get("kids")
        .and_then(Value::as_array)
        .ok_or(Refusal::InvalidRequest("kids"))?
        .iter()
        .map(|k| {
            k.as_str()
                .and_then(|k| Kid::parse(k).ok())
                .ok_or(Refusal::InvalidRequest("kids"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let declared = payload
        .get("declared_at")
        .and_then(Value::as_u64)
        .ok_or(Refusal::InvalidRequest("declared_at"))?;
    let window = match payload.get("window_from") {
        None | Some(Value::Null) => None,
        Some(from) => {
            let from = from
                .as_u64()
                .filter(|f| *f <= declared)
                .ok_or(Refusal::InvalidRequest("window_from"))?;
            Some((from, declared))
        }
    };
    Ok(Event::Compromised {
        domain: domain(payload)?,
        party: text(payload, "party")?.to_owned(),
        kids,
        window,
    })
}

fn event(name: &str, payload: &Map<String, Value>) -> Result<Event, Refusal> {
    Ok(match name {
        n if REVOCATIONS.contains(&n) => Event::Revocation {
            name: n.to_owned(),
            domain: domain(payload)?,
        },
        "instance-terminated" => Event::InstanceTerminated {
            domain: domain(payload)?,
        },
        "party.compromised" => compromised(payload)?,
        "party.disabled" => Event::PartyDisabled {
            domain: domain(payload)?,
            party: text(payload, "party")?.to_owned(),
        },
        "tenant.created" => Event::TenantCreated,
        "api_client.created" | "api_client.updated" | "api_client.disabled" => Event::ApiClient {
            change: match name {
                "api_client.created" => ClientChange::Created,
                "api_client.updated" => ClientChange::Updated,
                _ => ClientChange::Disabled,
            },
            client_id: text(payload, "client_id")?.to_owned(),
        },
        n if n.starts_with("organization.") => Event::Organization(n.to_owned()),
        n => Event::Unknown(n.to_owned()),
    })
}

fn audience_ok(aud: Option<&Value>, audience: &str) -> bool {
    match aud {
        Some(Value::String(a)) => a == audience,
        Some(Value::Array(all)) => all.iter().any(|a| a.as_str() == Some(audience)),
        _ => false,
    }
}

/// Reads verified claims (T-102 item 3 and its WD-105 note).
///
/// The tenant is the signed `access_tenant`. Access leaves it out of the events of the
/// platform tenant itself, so an `api_client` event without it takes the signed payload's
/// `tenant`; any other SET without it is `invalid_request`.
///
/// # Errors
/// [`Refusal`].
pub fn claims(payload: &[u8], expected: &Expected<'_>) -> Result<Set, Refusal> {
    let c = object(payload, "claims")?;
    if c.get("iss").and_then(Value::as_str) != Some(expected.issuer) {
        return Err(Refusal::InvalidIssuer);
    }
    if !audience_ok(c.get("aud"), expected.audience) {
        return Err(Refusal::InvalidAudience);
    }
    let iat_ms = c
        .get("iat")
        .and_then(Value::as_u64)
        .and_then(|s| s.checked_mul(1000))
        .ok_or(Refusal::InvalidRequest("iat"))?;
    if expected.now_ms.saturating_sub(iat_ms) > IAT_MAX_AGE_MS
        || iat_ms.saturating_sub(expected.now_ms) > IAT_SKEW_MS
    {
        return Err(Refusal::InvalidRequest("iat"));
    }
    let jti = text(&c, "jti")?;
    if fixed_b64url::<32>(jti).is_err() {
        return Err(Refusal::InvalidRequest("jti"));
    }
    let events = c
        .get("events")
        .and_then(Value::as_object)
        .ok_or(Refusal::InvalidRequest("events"))?;
    let mut members = events.iter();
    let (Some((urn, member)), None) = (members.next(), members.next()) else {
        return Err(Refusal::InvalidRequest("events"));
    };
    let name = urn
        .strip_prefix(EVENT_PREFIX)
        .filter(|n| !n.is_empty())
        .ok_or(Refusal::InvalidRequest("events"))?;
    let member = member
        .as_object()
        .ok_or(Refusal::InvalidRequest("events"))?;
    let event = event(name, member)?;
    let tenant = match (c.get("access_tenant"), &event) {
        (Some(t), _) => t.as_str(),
        (None, Event::ApiClient { .. }) => member.get("tenant").and_then(Value::as_str),
        (None, _) => None,
    }
    .filter(|t| t.starts_with("tnt_"))
    .and_then(TenantId::new)
    .ok_or(Refusal::InvalidRequest("access_tenant"))?;
    Ok(Set {
        iss: expected.issuer.to_owned(),
        jti: jti.to_owned(),
        tenant,
        event,
    })
}

/// What an Access event tells the operator (T-102 items 5, 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// `party.compromised` with its window: the SEC-36 notice is due for it.
    Compromised {
        /// The tenant.
        tenant: TenantId,
        /// The governing domain.
        domain: DomainId,
        /// The Party.
        party: String,
        /// `window_from`–`declared_at`.
        window: (u64, u64),
    },
    /// `party.compromised` without `window_from`: outside its schema, nothing is marked.
    CompromiseUnprocessed {
        /// The tenant.
        tenant: TenantId,
        /// The Party.
        party: String,
    },
    /// `party.disabled`: open work the Party answers for needs attention.
    PartyDisabled {
        /// The tenant.
        tenant: TenantId,
        /// The Party.
        party: String,
    },
    /// Work's own Access client changed.
    ClientUpdated {
        /// The client.
        client_id: String,
    },
    /// Work's own Access client is disabled; consequential actions fail closed.
    ClientDisabled {
        /// The client.
        client_id: String,
    },
}

impl Signal {
    /// The log event name.
    #[must_use]
    pub const fn event(&self) -> &'static str {
        match self {
            Self::Compromised { .. } => "access.party_compromised",
            Self::CompromiseUnprocessed { .. } => "access.compromise_unprocessed",
            Self::PartyDisabled { .. } => "access.party_disabled",
            Self::ClientUpdated { .. } => "access.client_updated",
            Self::ClientDisabled { .. } => "access.client_disabled",
        }
    }
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compromised {
                tenant,
                domain,
                party,
                window: (from, to),
            } => write!(
                f,
                "{} party {party} of {} compromised from {from} to {to}",
                tenant.as_str(),
                domain.text()
            ),
            Self::CompromiseUnprocessed { tenant, party } => write!(
                f,
                "{} party {party}: compromise without window_from, nothing marked",
                tenant.as_str()
            ),
            Self::PartyDisabled { tenant, party } => {
                write!(f, "{} party {party} disabled", tenant.as_str())
            }
            Self::ClientUpdated { client_id } => write!(f, "Access client {client_id} updated"),
            Self::ClientDisabled { client_id } => write!(
                f,
                "Access client {client_id} disabled; consequential actions refused"
            ),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
