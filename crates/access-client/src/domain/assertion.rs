//! The client assertion of the platform routes (T-101 item 8, RFC 7523, Access OP-149 m.19 (e)): a compact JWS with header `{alg: ES256, kid, typ: client-authentication+jwt}`, `iss` and `sub` the `client_id`, `aud` the platform realm's issuer, a fresh 32-byte `jti`, `iat` now and `exp` sixty seconds later; one per request, never kept.

use serde_json::json;

use crate::domain::{AccessError, b64url};

/// The JWS `typ` of a client assertion.
pub const ASSERTION_TYPE: &str = "client-authentication+jwt";

/// How long an assertion is valid, seconds (PD; Access accepts up to five minutes).
pub const ASSERTION_LIFETIME_S: u64 = 60;

/// What one assertion says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims<'a> {
    /// The RFC 7638 `kid` of `work-access-client`.
    pub kid: &'a str,
    /// `WORK_ACCESS_CLIENT_ID`, `iss` and `sub`.
    pub client_id: &'a str,
    /// The platform realm's issuer, `[suiss] access`.
    pub audience: &'a str,
    /// The fresh `jti` bytes from the RNG port.
    pub jti: [u8; 32],
    /// Now, Unix milliseconds.
    pub now_ms: u64,
}

impl Claims<'_> {
    /// The JWS signing input, `base64url(header) "." base64url(claims)`.
    ///
    /// # Errors
    /// [`AccessError::Answer`] when the lifetime overflows.
    pub fn signing_input(&self) -> Result<String, AccessError> {
        let iat = self.now_ms.checked_div(1000).unwrap_or_default();
        let exp = iat
            .checked_add(ASSERTION_LIFETIME_S)
            .ok_or(AccessError::Answer("assertion time"))?;
        let header = json!({"alg": "ES256", "kid": self.kid, "typ": ASSERTION_TYPE});
        let claims = json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.audience,
            "jti": b64url(&self.jti),
            "iat": iat,
            "exp": exp,
        });
        Ok(format!(
            "{}.{}",
            b64url(header.to_string().as_bytes()),
            b64url(claims.to_string().as_bytes())
        ))
    }
}

/// The compact assertion of `signing_input` and its ES256 signature `r ‖ s`.
///
/// # Errors
/// [`AccessError::KeyStore`] for a signature that is not 64 bytes.
pub fn compact(signing_input: &str, signature: &[u8]) -> Result<String, AccessError> {
    if signature.len() != 64 {
        return Err(AccessError::KeyStore("ES256 signature length".to_owned()));
    }
    Ok(format!("{signing_input}.{}", b64url(signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::from_b64url;

    fn part(text: &str, n: usize) -> serde_json::Value {
        let raw = from_b64url(text.split('.').nth(n).unwrap()).unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    // T-101
    #[test]
    fn t_101_the_assertion_names_the_client_the_platform_issuer_and_lives_sixty_seconds() {
        let claims = Claims {
            kid: "s8yHkUNz5Wl1rYw2nQz6kq3n7zW3yQ2bP0mG1tA4hXc",
            client_id: "cli_work",
            audience: "https://access.example",
            jti: [7; 32],
            now_ms: 1_793_793_600_999,
        };
        let input = claims.signing_input().unwrap();
        let header = part(&input, 0);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], ASSERTION_TYPE);
        assert_eq!(header["kid"], claims.kid);
        let body = part(&input, 1);
        assert_eq!(body["iss"], "cli_work");
        assert_eq!(body["sub"], "cli_work");
        assert_eq!(body["aud"], "https://access.example");
        assert_eq!(body["jti"], b64url(&[7; 32]));
        assert_eq!(body["iat"], 1_793_793_600_u64);
        assert_eq!(body["exp"], 1_793_793_660_u64);
        assert_eq!(body["jti"].as_str().unwrap().len(), 43);
        let jwt = compact(&input, &[1; 64]).unwrap();
        assert_eq!(jwt.split('.').count(), 3);
        assert!(compact(&input, &[1; 72]).is_err());
    }
}
