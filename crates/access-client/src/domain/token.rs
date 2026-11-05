//! The Access access token a caller presents to Work and its `DPoP` proof (RFC 9068, RFC 9449; Access OP-146 m.16 (d), TN-27, MD-10): a compact JWS of `typ` `at+jwt` whose header is exactly `alg`, `kid` and `typ`, signed with `ES256` or `Ed25519` under the realm token key its JWKS names by `kid`, whose `iss` is the realm, whose `aud` names Work, which has not expired, and which is bound by `cnf.jkt` to the key of a `DPoP` proof over this request's method and URL, the token's hash and a fresh `iat`; the caller is then the realm's pairwise `sub` of the token's `client_id`. There is no bearer token; nothing of the token is trusted before its signature verifies, and its unverified `iss` and `kid` only choose the keys it is verified under.

use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use suiss_crypto::cose::{KeySet, PublicKey};
use suiss_crypto::sig::{PureBackend, ed25519, p256};

use crate::domain::metadata::thumbprint;
use crate::domain::{b64url, fixed_b64url, from_b64url};

/// `typ` of an Access access token (RFC 9068 section 2.1).
pub const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// `typ` of a `DPoP` proof (RFC 9449 section 4.2).
pub const DPOP_TYP: &str = "dpop+jwt";

/// The algorithms of a token or proof, by their RFC 9864 names (Access MD-3); `EdDSA` is
/// refused.
pub const ALGORITHMS: [&str; 2] = ["ES256", "Ed25519"];

/// The longest token or proof read, before any decoding (PD).
pub const MAX_JWT: usize = 8192;

/// The clock skew a token's times are held to, Access's own (`SKEW_MS`).
pub const SKEW_MS: u64 = 60_000;

/// How far a proof's `iat` may be from now, either way (RFC 9449 section 11.1; PD).
pub const PROOF_WINDOW_MS: u64 = 60_000;

/// The longest `sub`, `client_id`, `jti` or `scope` read (PD).
const MAX_CLAIM: usize = 1024;

/// Why a presented token or proof does not name a caller. Every one is `401 unauthenticated`;
/// the code is for the log only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenRefusal {
    /// Not a compact JWS of canonical base64url parts within [`MAX_JWT`].
    #[error("not a compact JWS")]
    Format,
    /// A header outside the profile: other members, or `typ` of another kind.
    #[error("header not in profile")]
    Header,
    /// An algorithm outside [`ALGORITHMS`] or one that does not fit the key.
    #[error("algorithm not allowed")]
    Algorithm,
    /// The realm keys hold no key of this `kid`.
    #[error("unknown kid")]
    UnknownKid,
    /// The signature does not verify.
    #[error("signature does not verify")]
    Signature,
    /// The claims do not parse or a required claim is missing or malformed.
    #[error("claims malformed")]
    Claims,
    /// `iss` is not the realm whose keys verified the token.
    #[error("issuer")]
    Issuer,
    /// `aud` does not name Work.
    #[error("audience")]
    Audience,
    /// The token has expired.
    #[error("expired")]
    Expired,
    /// `nbf` or `iat` is in the future.
    #[error("not yet valid")]
    NotYetValid,
    /// The proof does not fit the request, the token or the clock.
    #[error("dpop proof: {0}")]
    Proof(&'static str),
    /// The proof's `jti` was seen before within its window.
    #[error("dpop proof replayed")]
    Replayed,
}

impl TokenRefusal {
    /// The stable code, for the log.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Format => "token_format",
            Self::Header => "token_header",
            Self::Algorithm => "token_algorithm",
            Self::UnknownKid => "token_kid_unknown",
            Self::Signature => "token_signature",
            Self::Claims => "token_claims",
            Self::Issuer => "token_issuer",
            Self::Audience => "token_audience",
            Self::Expired => "token_expired",
            Self::NotYetValid => "token_not_yet_valid",
            Self::Proof(_) => "dpop_proof_invalid",
            Self::Replayed => "dpop_proof_replayed",
        }
    }
}

/// What a verified access token says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessClaims {
    /// The realm issuer.
    pub issuer: String,
    /// The pairwise subject of `client_id` (MD-10).
    pub sub: String,
    /// The client the token was issued to: the sector of `sub`.
    pub client_id: String,
    /// The RFC 7638 thumbprint of the `DPoP` key the token is bound to.
    pub jkt: [u8; 32],
    /// The space-separated scopes, as issued.
    pub scope: String,
    /// The end of the token, Unix milliseconds.
    pub exp_ms: u64,
}

/// What a verified `DPoP` proof says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofClaims {
    /// The proof's unique id.
    pub jti: String,
    /// When the proof was made, Unix milliseconds.
    pub iat_ms: u64,
}

/// What the token is held against.
#[derive(Clone, Copy, Debug)]
pub struct TokenRules<'a> {
    /// The realm whose keys verify it.
    pub issuer: &'a str,
    /// Work's audience value.
    pub audience: &'a str,
    /// Now, Unix milliseconds.
    pub now_ms: u64,
}

/// The request a proof must be about.
#[derive(Clone, Copy, Debug)]
pub struct ProofRules<'a> {
    /// The HTTP method.
    pub method: &'a str,
    /// The target URI without query and fragment.
    pub url: &'a str,
    /// The access token the proof travels with.
    pub token: &'a str,
    /// The thumbprint the token is bound to.
    pub jkt: &'a [u8; 32],
    /// Now, Unix milliseconds.
    pub now_ms: u64,
}

struct Parts<'a> {
    header: Map<String, Value>,
    signing_input: &'a str,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn split(jwt: &str) -> Result<Parts<'_>, TokenRefusal> {
    if jwt.len() > MAX_JWT {
        return Err(TokenRefusal::Format);
    }
    let mut parts = jwt.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenRefusal::Format);
    };
    let decode = |part: &str| from_b64url(part).map_err(|_| TokenRefusal::Format);
    let end = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(TokenRefusal::Format)?;
    let Ok(Value::Object(header)) = serde_json::from_slice::<Value>(&decode(h)?) else {
        return Err(TokenRefusal::Header);
    };
    Ok(Parts {
        header,
        signing_input: jwt.get(..end).ok_or(TokenRefusal::Format)?,
        payload: decode(p)?,
        signature: decode(s)?,
    })
}

fn member<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    map.get(name).and_then(Value::as_str)
}

fn only(header: &Map<String, Value>, allowed: &[&str]) -> Result<(), TokenRefusal> {
    if header.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(TokenRefusal::Header)
    }
}

fn verify_signature(
    alg: &str,
    key: &PublicKey,
    parts: &Parts<'_>,
    native: bool,
) -> Result<(), TokenRefusal> {
    let input = parts.signing_input.as_bytes();
    let checked = match (alg, key) {
        ("ES256", PublicKey::P256(sec1)) => {
            p256(&PureBackend, sec1, input, &parts.signature, native)
        }
        ("Ed25519", PublicKey::Ed25519(pk)) => ed25519(&PureBackend, pk, input, &parts.signature),
        _ => return Err(TokenRefusal::Algorithm),
    };
    checked.map_err(|_| TokenRefusal::Signature)
}

fn header_kid(header: &Map<String, Value>) -> Result<[u8; 32], TokenRefusal> {
    fixed_b64url::<32>(member(header, "kid").ok_or(TokenRefusal::Header)?)
        .map_err(|_| TokenRefusal::Header)
}

#[derive(Deserialize)]
struct Unverified {
    iss: String,
}

/// The `iss` and `kid` of a token before it is verified: they only choose the realm and the key
/// it is verified under.
///
/// # Errors
/// [`TokenRefusal::Format`], [`TokenRefusal::Header`] or [`TokenRefusal::Claims`].
pub fn unverified(jwt: &str) -> Result<(String, [u8; 32]), TokenRefusal> {
    let parts = split(jwt)?;
    let kid = header_kid(&parts.header)?;
    let claims: Unverified =
        serde_json::from_slice(&parts.payload).map_err(|_| TokenRefusal::Claims)?;
    Ok((claims.iss, kid))
}

fn millis(claims: &Map<String, Value>, name: &str) -> Result<Option<u64>, TokenRefusal> {
    claims
        .get(name)
        .map(|v| {
            v.as_u64()
                .and_then(|s| s.checked_mul(1000))
                .ok_or(TokenRefusal::Claims)
        })
        .transpose()
}

fn text(claims: &Map<String, Value>, name: &str) -> Result<String, TokenRefusal> {
    member(claims, name)
        .filter(|v| !v.is_empty() && v.len() <= MAX_CLAIM)
        .map(str::to_owned)
        .ok_or(TokenRefusal::Claims)
}

fn audience_named(aud: Option<&Value>, audience: &str) -> bool {
    match aud {
        Some(Value::String(a)) => a == audience,
        Some(Value::Array(items)) => items.iter().any(|a| a.as_str() == Some(audience)),
        _ => false,
    }
}

/// Verifies an access token under the realm `keys` and holds its claims to `rules`: `typ`
/// `at+jwt`, the header exactly `alg`, `kid` and `typ`, `ES256` (low S, as Access signs) or
/// `Ed25519`, `iss` the realm, `aud` naming Work, `exp` required with `now ≤ exp + skew`, `nbf`
/// and `iat` not after `now + skew`, `sub` and `client_id` present and `cnf.jkt` 32 bytes.
///
/// # Errors
/// [`TokenRefusal`].
pub fn verify_access_token(
    jwt: &str,
    keys: &KeySet,
    rules: &TokenRules<'_>,
) -> Result<AccessClaims, TokenRefusal> {
    let parts = split(jwt)?;
    only(&parts.header, &["alg", "kid", "typ"])?;
    if member(&parts.header, "typ") != Some(ACCESS_TOKEN_TYP) {
        return Err(TokenRefusal::Header);
    }
    let alg = member(&parts.header, "alg").ok_or(TokenRefusal::Header)?;
    if !ALGORITHMS.contains(&alg) {
        return Err(TokenRefusal::Algorithm);
    }
    let kid = header_kid(&parts.header)?;
    let key = keys.keys.get(&kid).ok_or(TokenRefusal::UnknownKid)?;
    verify_signature(alg, key, &parts, true)?;
    let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(&parts.payload) else {
        return Err(TokenRefusal::Claims);
    };
    if member(&claims, "iss") != Some(rules.issuer) {
        return Err(TokenRefusal::Issuer);
    }
    if !audience_named(claims.get("aud"), rules.audience) {
        return Err(TokenRefusal::Audience);
    }
    let exp_ms = millis(&claims, "exp")?.ok_or(TokenRefusal::Claims)?;
    if rules.now_ms > exp_ms.saturating_add(SKEW_MS) {
        return Err(TokenRefusal::Expired);
    }
    let latest = rules.now_ms.saturating_add(SKEW_MS);
    for name in ["nbf", "iat"] {
        if millis(&claims, name)?.is_some_and(|t| t > latest) {
            return Err(TokenRefusal::NotYetValid);
        }
    }
    let jkt = claims
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|cnf| member(cnf, "jkt"))
        .and_then(|j| fixed_b64url::<32>(j).ok())
        .ok_or(TokenRefusal::Claims)?;
    let scope = match claims.get("scope") {
        None => String::new(),
        Some(_) => text(&claims, "scope")?,
    };
    Ok(AccessClaims {
        issuer: rules.issuer.to_owned(),
        sub: text(&claims, "sub")?,
        client_id: text(&claims, "client_id")?,
        jkt,
        scope,
        exp_ms,
    })
}

fn proof_key(jwk: &Map<String, Value>) -> Result<PublicKey, TokenRefusal> {
    let bad = || TokenRefusal::Proof("jwk");
    if jwk.contains_key("d") {
        return Err(bad());
    }
    let coordinate = |name: &str| {
        member(jwk, name)
            .and_then(|v| fixed_b64url::<32>(v).ok())
            .ok_or_else(bad)
    };
    match (member(jwk, "kty"), member(jwk, "crv")) {
        (Some("OKP"), Some("Ed25519")) => Ok(PublicKey::Ed25519(coordinate("x")?)),
        (Some("EC"), Some("P-256")) => {
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend(coordinate("x")?);
            sec1.extend(coordinate("y")?);
            Ok(PublicKey::P256(sec1))
        }
        _ => Err(bad()),
    }
}

/// The `htu` a proof must carry for `url`: the URL without its query and fragment (RFC 9449
/// section 4.3).
#[must_use]
pub fn target_uri(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or_default()
}

/// The `ath` of `token`: the unpadded base64url SHA-256 of its ASCII bytes (RFC 9449 section
/// 4.2).
#[must_use]
pub fn token_hash(token: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    b64url(&digest)
}

/// Verifies a `DPoP` proof for `rules`: `typ` `dpop+jwt`, the header exactly `alg`, `typ` and a
/// public `jwk` whose thumbprint is the token's `cnf.jkt`, signed by that key with `ES256` or
/// `Ed25519`, `htm` the method, `htu` the target URI, `ath` the token's hash, `jti` present and
/// `iat` within [`PROOF_WINDOW_MS`] of now. Replay of `jti` is the caller's to refuse.
///
/// # Errors
/// [`TokenRefusal::Proof`], [`TokenRefusal::Format`] or [`TokenRefusal::Algorithm`].
pub fn verify_proof(proof: &str, rules: &ProofRules<'_>) -> Result<ProofClaims, TokenRefusal> {
    let parts = split(proof)?;
    only(&parts.header, &["alg", "jwk", "typ"]).map_err(|_| TokenRefusal::Proof("header"))?;
    if member(&parts.header, "typ") != Some(DPOP_TYP) {
        return Err(TokenRefusal::Proof("typ"));
    }
    let alg = member(&parts.header, "alg").ok_or(TokenRefusal::Proof("alg"))?;
    if !ALGORITHMS.contains(&alg) {
        return Err(TokenRefusal::Algorithm);
    }
    let jwk = parts
        .header
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or(TokenRefusal::Proof("jwk"))?;
    let key = proof_key(jwk)?;
    if thumbprint(&key) != *rules.jkt {
        return Err(TokenRefusal::Proof("jkt"));
    }
    verify_signature(alg, &key, &parts, false).map_err(|_| TokenRefusal::Proof("signature"))?;
    let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(&parts.payload) else {
        return Err(TokenRefusal::Proof("claims"));
    };
    if member(&claims, "htm") != Some(rules.method) {
        return Err(TokenRefusal::Proof("htm"));
    }
    if member(&claims, "htu").map(target_uri) != Some(target_uri(rules.url)) {
        return Err(TokenRefusal::Proof("htu"));
    }
    if member(&claims, "ath") != Some(token_hash(rules.token).as_str()) {
        return Err(TokenRefusal::Proof("ath"));
    }
    let jti = text(&claims, "jti").map_err(|_| TokenRefusal::Proof("jti"))?;
    let iat_ms = millis(&claims, "iat")
        .ok()
        .flatten()
        .ok_or(TokenRefusal::Proof("iat"))?;
    if iat_ms.abs_diff(rules.now_ms) > PROOF_WINDOW_MS {
        return Err(TokenRefusal::Proof("iat"));
    }
    Ok(ProofClaims { jti, iat_ms })
}

#[cfg(test)]
pub(crate) mod tests;
