//! The service token of one platform product for another (T-99 item 4; Access A28 (a), OP-149 m.31 (a)): Work asks its platform realm's token endpoint `<issuer>/token` with `grant_type=client_credentials`, its client assertion, `resource` the other product's `client_id` and no `authorization_details`, under a `DPoP` proof (RFC 9449 section 4.2) of the P-256 key `work-access-dpop`, and gets a `DPoP` token that only says who is calling. Every call to the other product carries the token as `Authorization: DPoP` with a fresh proof naming the call's method, its URL without query or fragment, the token's hash `ath`, a new `jti` and `iat` now.

use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::secret::Secret;

use crate::domain::discovery::{Issuer, percent};
use crate::domain::token::DPOP_TYP;
use crate::domain::{AccessError, b64url};

/// The RFC 7523 client assertion type.
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The OAuth error of a token endpoint that wants its nonce in the proof (RFC 9449 section 8).
pub const NONCE_ERROR: &str = "use_dpop_nonce";

/// The header that carries the server's nonce.
pub const NONCE_HEADER: &str = "dpop-nonce";

/// The longest life Work gives a service token, seconds: Access's own ceiling (A28 (a)).
pub const MAX_LIFETIME_S: u64 = 300;

/// How long before its end a cached token is replaced (PD).
pub const REFRESH_BEFORE_MS: u64 = 60_000;

/// The token endpoint of the platform realm `issuer`.
#[must_use]
pub fn token_url(issuer: &Issuer) -> String {
    format!("{}/token", issuer.as_str())
}

/// The form body of the token request for `resource`.
#[must_use]
pub fn token_body(assertion: &str, resource: &str) -> Vec<u8> {
    [
        ("grant_type", "client_credentials"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion),
        ("resource", resource),
    ]
    .iter()
    .map(|(n, v)| format!("{n}={}", percent(v)))
    .collect::<Vec<_>>()
    .join("&")
    .into_bytes()
}

/// The `htu` of a call to `url`: the URL without query and fragment.
#[must_use]
pub fn htu(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

/// The `ath` of `token`: the unpadded base64url SHA-256 of its text.
#[must_use]
pub fn ath(token: &str) -> String {
    b64url(&Sha256::digest(token.as_bytes()))
}

/// What one proof says.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof<'a> {
    /// The public key of `work-access-dpop`, SEC1 uncompressed P-256.
    pub key: &'a PublicKey,
    /// The call's method.
    pub method: &'a str,
    /// The call's URL.
    pub url: &'a str,
    /// The fresh `jti` bytes from the RNG port.
    pub jti: [u8; 32],
    /// Now, Unix milliseconds.
    pub now_ms: u64,
    /// The server's nonce, once it asked for one.
    pub nonce: Option<&'a str>,
    /// The access token the call presents; none at the token endpoint.
    pub token: Option<&'a str>,
}

impl std::fmt::Debug for Proof<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("now_ms", &self.now_ms)
            .finish_non_exhaustive()
    }
}

impl Proof<'_> {
    /// The JWS signing input, `base64url(header) "." base64url(claims)`.
    ///
    /// # Errors
    /// [`AccessError::KeyStore`] for a key that is not an uncompressed P-256 point.
    pub fn signing_input(&self) -> Result<String, AccessError> {
        let not_p256 = || AccessError::KeyStore("work-access-dpop is not P-256".to_owned());
        let PublicKey::P256(sec1) = self.key else {
            return Err(not_p256());
        };
        let (x, y) = match sec1.as_slice() {
            [4, xy @ ..] if xy.len() == 64 => xy.split_at_checked(32).ok_or_else(not_p256)?,
            _ => return Err(not_p256()),
        };
        let header = json!({
            "typ": DPOP_TYP,
            "alg": "ES256",
            "jwk": {"kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y)},
        });
        let mut claims = Map::new();
        claims.insert("jti".into(), b64url(&self.jti).into());
        claims.insert("htm".into(), self.method.into());
        claims.insert("htu".into(), htu(self.url).into());
        claims.insert(
            "iat".into(),
            self.now_ms.checked_div(1000).unwrap_or_default().into(),
        );
        if let Some(nonce) = self.nonce {
            claims.insert("nonce".into(), nonce.into());
        }
        if let Some(token) = self.token {
            claims.insert("ath".into(), ath(token).into());
        }
        Ok(format!(
            "{}.{}",
            b64url(header.to_string().as_bytes()),
            b64url(Value::Object(claims).to_string().as_bytes())
        ))
    }
}

#[derive(Deserialize)]
struct Wire {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

/// A service token and when Work stops using it.
pub struct ServiceToken {
    token: Secret<String>,
    /// Unix milliseconds after which the token is asked for again.
    pub renew_at_ms: u64,
}

impl std::fmt::Debug for ServiceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceToken")
            .field("renew_at_ms", &self.renew_at_ms)
            .finish_non_exhaustive()
    }
}

impl ServiceToken {
    /// Reads the `200` answer of the token endpoint received at `now_ms`: a `DPoP` token with a
    /// positive lifetime, kept until [`REFRESH_BEFORE_MS`] before the shorter of its
    /// `expires_in` and [`MAX_LIFETIME_S`].
    ///
    /// # Errors
    /// [`AccessError::Document`] for an answer that does not parse, [`AccessError::Answer`] for
    /// another token type or no lifetime.
    pub fn from_json(body: &[u8], now_ms: u64) -> Result<Self, AccessError> {
        let w: Wire = serde_json::from_slice(body).map_err(|_| AccessError::Document("token"))?;
        if !w.token_type.eq_ignore_ascii_case("DPoP") {
            return Err(AccessError::Answer("token_type"));
        }
        if w.expires_in == 0 || w.access_token.is_empty() {
            return Err(AccessError::Answer("expires_in"));
        }
        let life_ms = w
            .expires_in
            .min(MAX_LIFETIME_S)
            .saturating_mul(1000)
            .saturating_sub(REFRESH_BEFORE_MS);
        Ok(Self {
            token: Secret::new(w.access_token),
            renew_at_ms: now_ms.saturating_add(life_ms),
        })
    }

    /// The token text.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.token.expose()
    }

    /// Whether the token is still used at `now_ms`.
    #[must_use]
    pub const fn fresh(&self, now_ms: u64) -> bool {
        now_ms < self.renew_at_ms
    }
}

impl Clone for ServiceToken {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            renew_at_ms: self.renew_at_ms,
        }
    }
}

/// The refusal of a token endpoint answer that is not `200`: the RFC 6749 `error` as its code,
/// a `503` as the endpoint's outage.
#[must_use]
pub fn refusal(status: u16, body: &[u8]) -> AccessError {
    let error = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default();
    if status == 503 {
        return AccessError::Unavailable { reason: None };
    }
    AccessError::Refused {
        status,
        code: error,
        reason: None,
        errors: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test code")]
mod tests {
    use super::*;
    use crate::domain::from_b64url;

    fn part(text: &str, n: usize) -> Value {
        let raw = from_b64url(text.split('.').nth(n).unwrap()).unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    fn key() -> PublicKey {
        let mut sec1 = vec![4];
        sec1.extend([1; 32]);
        sec1.extend([2; 32]);
        PublicKey::P256(sec1)
    }

    // T-99
    #[test]
    fn t_99_the_token_request_names_the_assertion_and_the_other_product_only() {
        let issuer = Issuer::parse("https://access.example/realms/platform").unwrap();
        assert_eq!(
            token_url(&issuer),
            "https://access.example/realms/platform/token"
        );
        let body = String::from_utf8(token_body("a.b.c", "app_relay 1")).unwrap();
        assert_eq!(
            body,
            "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=a.b.c&resource=app_relay%201"
        );
        assert!(!body.contains("authorization_details"));
        assert!(!body.contains("scope"));
    }

    // T-99
    #[test]
    fn t_99_a_proof_names_the_call_its_key_the_token_hash_and_the_nonce() {
        let key = key();
        let proof = Proof {
            key: &key,
            method: "POST",
            url: "https://relay/v1/events?x=1#f",
            jti: [9; 32],
            now_ms: 1_793_793_600_999,
            nonce: Some("n-1"),
            token: Some("at"),
        };
        let input = proof.signing_input().unwrap();
        let header = part(&input, 0);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(
            header["jwk"],
            json!({"kty": "EC", "crv": "P-256", "x": b64url(&[1; 32]), "y": b64url(&[2; 32])})
        );
        assert_eq!(header.as_object().unwrap().len(), 3);
        let claims = part(&input, 1);
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://relay/v1/events");
        assert_eq!(claims["iat"], 1_793_793_600_u64);
        assert_eq!(claims["jti"], b64url(&[9; 32]));
        assert_eq!(claims["nonce"], "n-1");
        assert_eq!(claims["ath"], b64url(&Sha256::digest(b"at")));
        let bare = Proof {
            nonce: None,
            token: None,
            ..proof
        };
        let claims = part(&bare.signing_input().unwrap(), 1);
        assert!(claims.get("nonce").is_none());
        assert!(claims.get("ath").is_none());
        let ed = PublicKey::Ed25519([1; 32]);
        assert!(Proof { key: &ed, ..proof }.signing_input().is_err());
        let short = PublicKey::P256(vec![4; 33]);
        assert!(
            Proof {
                key: &short,
                ..proof
            }
            .signing_input()
            .is_err()
        );
    }

    // T-99
    #[test]
    fn t_99_a_service_token_is_a_dpop_token_kept_until_shortly_before_it_ends() {
        let now = 1_000_000;
        let t = ServiceToken::from_json(
            br#"{"access_token":"at","token_type":"DPoP","expires_in":300}"#,
            now,
        )
        .unwrap();
        assert_eq!(t.expose(), "at");
        assert_eq!(t.renew_at_ms, now + 240_000);
        assert!(t.fresh(now + 239_999));
        assert!(!t.fresh(now + 240_000));
        let long = ServiceToken::from_json(
            br#"{"access_token":"at","token_type":"dpop","expires_in":3600}"#,
            now,
        )
        .unwrap();
        assert_eq!(long.renew_at_ms, now + 240_000);
        let brief = ServiceToken::from_json(
            br#"{"access_token":"at","token_type":"DPoP","expires_in":30}"#,
            now,
        )
        .unwrap();
        assert!(!brief.fresh(now));
        assert_eq!(
            ServiceToken::from_json(
                br#"{"access_token":"at","token_type":"Bearer","expires_in":300}"#,
                now
            )
            .unwrap_err(),
            AccessError::Answer("token_type")
        );
        assert_eq!(
            ServiceToken::from_json(
                br#"{"access_token":"at","token_type":"DPoP","expires_in":0}"#,
                now
            )
            .unwrap_err(),
            AccessError::Answer("expires_in")
        );
        assert!(!format!("{t:?}").contains("\"at\""));
    }

    // T-99 T-28
    #[test]
    fn t_99_a_refused_token_request_carries_its_oauth_error() {
        assert_eq!(
            refusal(400, br#"{"error":"invalid_target"}"#),
            AccessError::Refused {
                status: 400,
                code: "invalid_target".to_owned(),
                reason: None,
                errors: Vec::new(),
            }
        );
        assert!(refusal(503, b"").is_temporary());
    }
}
