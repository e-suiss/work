//! The realm token keys that verify an `auth_context` artifact (P-116 items 1, 4; Access OP-149 m.8, CR-24): the realm's OIDC discovery document under its issuer names its JWKS, whose Ed25519 and P-256 signing keys, each named by its RFC 7638 thumbprint, become the key set an artifact verifies under with Ed25519 (`-19`) or ESP256 (`-9`) only.

use std::collections::BTreeSet;

use serde::Deserialize;
use suiss_crypto::cose::{Algorithm, KeySet, PublicKey};

use crate::domain::discovery::{Issuer, MAX_URL};
use crate::domain::metadata::thumbprint;
use crate::domain::{AccessError, fixed_b64url};

/// The well-known suffix of the realm's OIDC discovery document.
pub const OPENID_CONFIGURATION: &str = "openid-configuration";

/// The algorithms an artifact may be signed with (P-116 item 4).
pub const ARTIFACT_ALGORITHMS: [Algorithm; 2] = [Algorithm::Ed25519, Algorithm::Esp256];

#[derive(Deserialize)]
struct Configuration {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    usage: Option<String>,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

fn jwks_error() -> AccessError {
    AccessError::Answer("jwks")
}

/// The `jwks_uri` of the OIDC discovery document of `realm`: its `issuer` must be `realm` and the
/// URI an `https` URL.
///
/// # Errors
/// [`AccessError::Document`], [`AccessError::Issuer`] or [`AccessError::Endpoint`].
pub fn jwks_uri(body: &[u8], realm: &Issuer) -> Result<String, AccessError> {
    let c: Configuration =
        serde_json::from_slice(body).map_err(|_| AccessError::Document("openid-configuration"))?;
    if c.issuer != realm.as_str() {
        return Err(AccessError::Issuer("openid-configuration"));
    }
    let printable = c.jwks_uri.bytes().all(|b| (b'!'..=b'~').contains(&b));
    let rest = c.jwks_uri.strip_prefix("https://").unwrap_or_default();
    if rest.is_empty() || !printable || c.jwks_uri.len() > MAX_URL || c.jwks_uri.contains('#') {
        return Err(AccessError::Endpoint("jwks_uri".to_owned()));
    }
    Ok(c.jwks_uri)
}

fn key_of(k: &Jwk) -> Result<Option<PublicKey>, AccessError> {
    let coordinate = |v: Option<&str>| -> Result<[u8; 32], AccessError> {
        fixed_b64url::<32>(v.ok_or_else(jwks_error)?).map_err(|_| jwks_error())
    };
    let alg = k.alg.as_deref();
    match (k.kty.as_str(), k.crv.as_deref()) {
        ("OKP", Some("Ed25519")) if k.y.is_none() => {
            if !matches!(alg, None | Some("Ed25519" | "EdDSA")) {
                return Err(jwks_error());
            }
            Ok(Some(PublicKey::Ed25519(coordinate(k.x.as_deref())?)))
        }
        ("EC", Some("P-256")) => {
            if !matches!(alg, None | Some("ES256" | "ESP256")) {
                return Err(jwks_error());
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend(coordinate(k.x.as_deref())?);
            sec1.extend(coordinate(k.y.as_deref())?);
            Ok(Some(PublicKey::P256(sec1)))
        }
        ("OKP" | "EC", _) => Err(jwks_error()),
        _ => Ok(None),
    }
}

/// The key set of a realm JWKS: every Ed25519 and P-256 signing key, each under its `kid`,
/// which must be the key's RFC 7638 thumbprint; keys of other types are not used, and only
/// [`ARTIFACT_ALGORITHMS`] are allowed.
///
/// # Errors
/// [`AccessError::Document`] when it does not parse; [`AccessError::Answer`] for a key that is
/// malformed, has another `kid` or an `alg` that does not fit it, a repeated `kid`, or no
/// usable key.
pub fn realm_keys(body: &[u8]) -> Result<KeySet, AccessError> {
    let jwks: Jwks = serde_json::from_slice(body).map_err(|_| AccessError::Document("jwks"))?;
    let mut set = KeySet {
        allowed: BTreeSet::from(ARTIFACT_ALGORITHMS),
        ..KeySet::default()
    };
    for k in &jwks.keys {
        if k.usage.as_deref().is_some_and(|u| u != "sig") {
            continue;
        }
        let Some(key) = key_of(k)? else {
            continue;
        };
        let kid = fixed_b64url::<32>(k.kid.as_deref().ok_or_else(jwks_error)?)
            .map_err(|_| jwks_error())?;
        if thumbprint(&key) != kid || set.keys.contains_key(&kid) {
            return Err(jwks_error());
        }
        set.insert(kid, key).map_err(|_| jwks_error())?;
    }
    if set.keys.is_empty() {
        return Err(jwks_error());
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::b64url;

    const ED_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const EC_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const EC_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    fn realm() -> Issuer {
        Issuer::parse("https://acme.suiss.example").unwrap()
    }

    fn ed() -> PublicKey {
        PublicKey::Ed25519(fixed_b64url::<32>(ED_X).unwrap())
    }

    fn ec() -> PublicKey {
        let mut sec1 = vec![0x04];
        sec1.extend(fixed_b64url::<32>(EC_X).unwrap());
        sec1.extend(fixed_b64url::<32>(EC_Y).unwrap());
        PublicKey::P256(sec1)
    }

    fn ed_jwk(kid: &str) -> serde_json::Value {
        serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": ED_X, "kid": kid, "alg": "Ed25519", "use": "sig"})
    }

    fn ec_jwk(kid: &str) -> serde_json::Value {
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "kid": kid, "alg": "ES256", "use": "sig"})
    }

    fn keys(jwks: &serde_json::Value) -> Result<KeySet, AccessError> {
        realm_keys(&serde_json::to_vec(jwks).unwrap())
    }

    // P-116
    #[test]
    fn p_116_the_realm_jwks_gives_the_token_keys_by_thumbprint() {
        let ed_kid = b64url(&thumbprint(&ed()));
        assert_eq!(ed_kid, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
        let ec_kid = b64url(&thumbprint(&ec()));
        let set = keys(&serde_json::json!({"keys": [
            ed_jwk(&ed_kid),
            ec_jwk(&ec_kid),
            {"kty": "AKP", "alg": "ML-DSA-65", "pub": "AA", "kid": "x"},
            {"kty": "OKP", "crv": "Ed25519", "x": ED_X, "kid": ed_kid, "use": "enc"},
        ]}))
        .unwrap();
        assert_eq!(set.keys.len(), 2);
        assert_eq!(set.keys.get(&thumbprint(&ed())), Some(&ed()));
        assert_eq!(set.keys.get(&thumbprint(&ec())), Some(&ec()));
        assert_eq!(
            set.allowed,
            BTreeSet::from([Algorithm::Ed25519, Algorithm::Esp256])
        );
    }

    // P-116
    #[test]
    fn p_116_a_realm_key_named_by_another_kid_or_algorithm_is_refused() {
        let ed_kid = b64url(&thumbprint(&ed()));
        let ec_kid = b64url(&thumbprint(&ec()));
        let refused = AccessError::Answer("jwks");
        for jwks in [
            serde_json::json!({"keys": [ed_jwk(&ec_kid)]}),
            serde_json::json!({"keys": [ed_jwk(&ed_kid), ed_jwk(&ed_kid)]}),
            serde_json::json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": ED_X, "kid": ed_kid, "alg": "ES256"}]}),
            serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": EC_X, "kid": ec_kid}]}),
            serde_json::json!({"keys": [{"kty": "OKP", "crv": "X25519", "x": ED_X, "kid": ed_kid}]}),
            serde_json::json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": ED_X}]}),
            serde_json::json!({"keys": []}),
        ] {
            assert_eq!(keys(&jwks), Err(refused.clone()), "{jwks}");
        }
        assert_eq!(realm_keys(b"{}"), Err(AccessError::Document("jwks")));
    }

    // P-116
    #[test]
    fn p_116_the_jwks_uri_comes_from_the_realm_openid_configuration() {
        let body = |issuer: &str, uri: &str| {
            serde_json::to_vec(&serde_json::json!({"issuer": issuer, "jwks_uri": uri})).unwrap()
        };
        assert_eq!(
            realm().well_known(OPENID_CONFIGURATION),
            "https://acme.suiss.example/.well-known/openid-configuration"
        );
        assert_eq!(
            jwks_uri(
                &body(
                    "https://acme.suiss.example",
                    "https://acme.suiss.example/jwks.json"
                ),
                &realm()
            )
            .unwrap(),
            "https://acme.suiss.example/jwks.json"
        );
        assert_eq!(
            jwks_uri(
                &body(
                    "https://globex.suiss.example",
                    "https://acme.suiss.example/jwks.json"
                ),
                &realm()
            ),
            Err(AccessError::Issuer("openid-configuration"))
        );
        assert_eq!(
            jwks_uri(
                &body(
                    "https://acme.suiss.example",
                    "http://acme.suiss.example/jwks.json"
                ),
                &realm()
            ),
            Err(AccessError::Endpoint("jwks_uri".to_owned()))
        );
    }
}
