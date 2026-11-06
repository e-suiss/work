//! The Access `auth_context` artifact of an unsigned human record (P-116; Access OP-149 m.8, `auth-context.cddl`): on the admission path and before the kernel, its `COSE_Sign1` verifies under the realm token key (`-9` or `-19`) the realm JWKS names by `kid`, its payload is the Access CDDL in deterministic CBOR, its realm is a paired realm of the tenant and the issuer of the request's Access token, Access's `digest` recomputes, it is bound to exactly this record and it was issued no later than its admission. The envelope's `AuthContextRef` comes from the verified payload alone; a failure is `422 auth_context_invalid` and nothing enters the log.

use std::collections::BTreeSet;

use suiss_crypto::cose::{self, Algorithm, KeySet};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::{Digest, context_digest};
use suiss_crypto::sig::PureBackend;

/// The content type of the artifact's `COSE_Sign1` (Access OP-149 m.8).
pub const ARTIFACT_CONTENT_TYPE: &str = "application/access-auth-context+cbor";

/// The context label of Access's `digest` (Access OP-149 m.8).
pub const DIGEST_LABEL: &str = "suiss/auth-context/v1";

/// The content type a record binds its artifact to (P-116 item 2).
pub const RECORD_CONTENT_TYPE: &str = "application/work-record+cbor";

/// The problem code of an artifact that does not verify (T-98 item 6).
pub const AUTH_CONTEXT_INVALID: &str = "auth_context_invalid";

const VERSION: u64 = 1;

const AALS: [&str; 3] = ["aal1", "aal2", "aal3"];

const FLAGS: [&str; 7] = [
    "app_controlled_factor",
    "hardware_bound",
    "human_presence",
    "non_custodial",
    "phishing_resistant",
    "synced",
    "uv",
];

const FIELDS: [&str; 11] = [
    "v",
    "realm",
    "session_ref",
    "aal",
    "assurance_flags",
    "auth_time",
    "step_up_time",
    "ais_digest",
    "instance",
    "content_type",
    "content_digest",
];

const MAX_URL_REST: usize = 2040;

const MAX_MEDIA_PART: usize = 63;

/// What a request carries for an unsigned human record, with what Work looked up for it.
#[derive(Clone, Copy)]
pub struct AuthContext<'a> {
    /// The tagged `COSE_Sign1` as received; it is kept in `work.received_bytes` as it is.
    pub bytes: &'a [u8],
    /// Access's `digest` of the artifact, as the client received it with the artifact.
    pub digest: &'a [u8; 32],
    /// The keys of the realm JWKS of `issuer`, from Access.
    pub realm_keys: &'a KeySet,
    /// The `iss` of the Access token the request carries.
    pub issuer: &'a str,
    /// The realms the tenant is paired with (P-115 item 2).
    pub paired: &'a BTreeSet<String>,
    /// The admission time, Unix milliseconds from the Clock port.
    pub now_ms: u64,
}

impl std::fmt::Debug for AuthContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext")
            .field("bytes", &self.bytes.len())
            .field("issuer", &self.issuer)
            .field("now_ms", &self.now_ms)
            .finish_non_exhaustive()
    }
}

/// A verified artifact: what the envelope's `AuthContextRef` takes from it (P-116 item 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Access's `digest`, the `ref`.
    pub digest: [u8; 32],
    /// The realm's issuer.
    pub realm: String,
    /// The `aal`, the `assurance`.
    pub aal: &'static str,
    /// Whether the payload carries `step_up_time`, the `step_up`.
    pub step_up: bool,
    /// The session's latest authentication, Unix milliseconds.
    pub auth_time: u64,
    /// The device Instance the session is bound to, when it registered one (Access OP-149
    /// m.30 (c)).
    pub instance: Option<[u8; 16]>,
}

/// Why an artifact is refused; every case is the `auth_context_invalid` problem (P-116 item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthContextInvalid {
    /// The `COSE_Sign1` does not verify under the realm keys; the shared crate's code.
    #[error("signature: {0}")]
    Signature(&'static str),
    /// Signed with an algorithm other than ESP256 (`-9`) or Ed25519 (`-19`).
    #[error("algorithm")]
    Algorithm,
    /// The payload is not the Access CDDL in deterministic CBOR.
    #[error("payload")]
    Payload,
    /// Access's `digest` does not recompute.
    #[error("digest")]
    Digest,
    /// The realm is not the token's issuer or not a paired realm of the tenant.
    #[error("realm")]
    Realm,
    /// The artifact is bound to no content.
    #[error("unbound")]
    Unbound,
    /// The artifact is bound to another content type or another record.
    #[error("bound to other content")]
    OtherContent,
    /// The authentication or step-up is later than the admission.
    #[error("authentication after admission")]
    AuthTime,
}

impl AuthContextInvalid {
    /// The RFC 9457 problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        AUTH_CONTEXT_INVALID
    }

    /// A stable sub-code for the log, never for the record.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::Signature(code) => code,
            Self::Algorithm => "algorithm",
            Self::Payload => "payload",
            Self::Digest => "digest",
            Self::Realm => "realm",
            Self::Unbound => "unbound",
            Self::OtherContent => "other_content",
            Self::AuthTime => "auth_time",
        }
    }
}

struct Payload {
    realm: String,
    aal: &'static str,
    auth_time: u64,
    step_up_time: Option<u64>,
    instance: Option<[u8; 16]>,
    content: Option<(String, [u8; 32])>,
}

fn https_url(text: &str) -> bool {
    text.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && rest.len() <= MAX_URL_REST
            && rest.bytes().all(|b| (b'!'..=b'~').contains(&b))
    })
}

fn media_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= MAX_MEDIA_PART
        && part
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(&b))
}

fn media_type(text: &str) -> bool {
    text.split_once('/')
        .is_some_and(|(t, s)| media_part(t) && media_part(s))
}

fn uint(v: &Value) -> Result<u64, AuthContextInvalid> {
    match v {
        Value::Unsigned(u) => Ok(*u),
        _ => Err(AuthContextInvalid::Payload),
    }
}

fn digest(v: &Value) -> Result<[u8; 32], AuthContextInvalid> {
    Digest::from_value(v)
        .map(|d| d.0)
        .ok_or(AuthContextInvalid::Payload)
}

fn instance(v: &Value) -> Result<[u8; 16], AuthContextInvalid> {
    match v {
        Value::Bytes(b) => {
            <[u8; 16]>::try_from(b.as_slice()).map_err(|_| AuthContextInvalid::Payload)
        }
        _ => Err(AuthContextInvalid::Payload),
    }
}

fn flags(v: &Value) -> Result<(), AuthContextInvalid> {
    let Value::Array(items) = v else {
        return Err(AuthContextInvalid::Payload);
    };
    let mut names = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Text(t) if FLAGS.contains(&t.as_str()) => names.push(t.as_str()),
            _ => return Err(AuthContextInvalid::Payload),
        }
    }
    if names.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
        Ok(())
    } else {
        Err(AuthContextInvalid::Payload)
    }
}

fn payload(bytes: &[u8]) -> Result<Payload, AuthContextInvalid> {
    let bad = AuthContextInvalid::Payload;
    let v = dcbor::decode(bytes, Limits::CEILING).map_err(|_| bad)?;
    if dcbor::encode(&v, Limits::CEILING).ok().as_deref() != Some(bytes) {
        return Err(bad);
    }
    let Value::Map(entries) = &v else {
        return Err(bad);
    };
    for (key, _) in entries {
        match key {
            Value::Text(name) if FIELDS.contains(&name.as_str()) => {}
            _ => return Err(bad),
        }
    }
    let req = |name: &str| v.get(name).ok_or(bad);
    if uint(req("v")?)? != VERSION {
        return Err(bad);
    }
    let realm = match req("realm")? {
        Value::Text(t) if https_url(t) => t.clone(),
        _ => return Err(bad),
    };
    digest(req("session_ref")?)?;
    let aal = match req("aal")? {
        Value::Text(t) => AALS.into_iter().find(|a| *a == t.as_str()).ok_or(bad)?,
        _ => return Err(bad),
    };
    flags(req("assurance_flags")?)?;
    let auth_time = uint(req("auth_time")?)?;
    let step_up_time = v.get("step_up_time").map(uint).transpose()?;
    digest(req("ais_digest")?)?;
    let instance = v.get("instance").map(instance).transpose()?;
    let content = match (v.get("content_type"), v.get("content_digest")) {
        (None, None) => None,
        (Some(Value::Text(t)), Some(d)) if media_type(t) => Some((t.clone(), digest(d)?)),
        _ => return Err(bad),
    };
    Ok(Payload {
        realm,
        aal,
        auth_time,
        step_up_time,
        instance,
        content,
    })
}

/// The `kid` in the protected header of `bytes`, unverified: which realm key the caller needs.
#[must_use]
pub fn kid(bytes: &[u8]) -> Option<[u8; 32]> {
    let msg = cose::parse_sign1(bytes).ok()?;
    match dcbor::decode(&msg.protected, Limits::CEILING).ok()? {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match (k, v) {
            (Value::Unsigned(cose::KID), Value::Bytes(b)) => {
                <[u8; 32]>::try_from(b.as_slice()).ok()
            }
            _ => None,
        }),
        _ => None,
    }
}

/// Verifies `context` as the artifact of the record whose identifier is `record` (P-116 items
/// 2–4).
///
/// # Errors
/// [`AuthContextInvalid`].
pub fn verify(
    context: &AuthContext<'_>,
    record: &[u8; 32],
) -> Result<Verified, AuthContextInvalid> {
    let signed = cose::verify_sign1(
        &PureBackend,
        context.bytes,
        context.realm_keys,
        ARTIFACT_CONTENT_TYPE,
    )
    .map_err(|e| AuthContextInvalid::Signature(e.code()))?;
    if !matches!(signed.algorithm, Algorithm::Ed25519 | Algorithm::Esp256) {
        return Err(AuthContextInvalid::Algorithm);
    }
    let p = payload(&signed.payload)?;
    let recomputed = context_digest(DIGEST_LABEL, &signed.payload).0;
    if recomputed != *context.digest {
        return Err(AuthContextInvalid::Digest);
    }
    if p.realm != context.issuer || !context.paired.contains(&p.realm) {
        return Err(AuthContextInvalid::Realm);
    }
    match &p.content {
        None => return Err(AuthContextInvalid::Unbound),
        Some((t, d)) if t.as_str() != RECORD_CONTENT_TYPE || d != record => {
            return Err(AuthContextInvalid::OtherContent);
        }
        Some(_) => {}
    }
    if p.auth_time > context.now_ms || p.step_up_time.is_some_and(|t| t > context.now_ms) {
        return Err(AuthContextInvalid::AuthTime);
    }
    Ok(Verified {
        digest: recomputed,
        realm: p.realm,
        aal: p.aal,
        step_up: p.step_up_time.is_some(),
        auth_time: p.auth_time,
        instance: p.instance,
    })
}

#[cfg(test)]
mod tests;
