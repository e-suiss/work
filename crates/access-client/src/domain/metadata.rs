//! Domain Metadata and the operational key of a signed Access answer (T-101 item 4; Access CR-58, T20, OP-149 m.15 (c)): the binding-signed metadata, the binding-signed key excerpt an answer carries in `Access-Key-Excerpt`, and the scope, usage, algorithm and window rules that make its key the one that may sign it, read as Access's kernel reads them and checked against Access's `key-scope` vectors.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};
use suiss_crypto::cose::{self, Algorithm, CoseError, KeySet, PublicKey};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::Digest;
use suiss_crypto::sig::PureBackend;

use crate::domain::b64url;

/// Content type of the binding-signed excerpt.
pub const EXCERPT_CONTENT_TYPE: &str = "application/access-key-excerpt+cbor";
/// Content type of the binding-signed Domain Metadata.
pub const METADATA_CONTENT_TYPE: &str = "application/access-domain-metadata+cbor";
/// Upper bound of an operational key window.
pub const MAX_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// What an operational key may sign (Access CR-58 m.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyUsage {
    /// Decision receipts.
    Receipt,
    /// Portable Authority Proofs.
    Pap,
    /// Authority-carrying tokens.
    Token,
    /// Checkpoints.
    Checkpoint,
    /// Security event tokens.
    Set,
    /// Status lists.
    StatusList,
    /// Instance key lookup answers (Access OP-149 m.5).
    KeyLookup,
    /// Party status lookup answers (Access OP-149 m.28 (c)).
    PartyLookup,
}

const USAGES: [(&str, KeyUsage); 8] = [
    ("receipt", KeyUsage::Receipt),
    ("pap", KeyUsage::Pap),
    ("token", KeyUsage::Token),
    ("checkpoint", KeyUsage::Checkpoint),
    ("set", KeyUsage::Set),
    ("status-list", KeyUsage::StatusList),
    ("key-lookup", KeyUsage::KeyLookup),
    ("party-lookup", KeyUsage::PartyLookup),
];

impl KeyUsage {
    /// The usage of its wire word.
    #[must_use]
    pub fn named(word: &str) -> Option<Self> {
        USAGES.iter().find(|(w, _)| *w == word).map(|(_, u)| *u)
    }
}

/// Why a key is not accepted for an answer, each a refusal; [`KeyScopeError::code`] is the
/// name Access's vectors give it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyScopeError {
    /// A signature does not verify, its `kid` is unknown or its content type is wrong.
    #[error("signature: {0}")]
    Signature(CoseError),
    /// A payload is not a value of the model.
    #[error("payload does not decode")]
    Payload,
    /// The binding key was superseded.
    #[error("binding key superseded")]
    Superseded,
    /// The binding key does not speak for the domain.
    #[error("binding key does not cover the domain")]
    OutOfScope,
    /// The excerpt names another domain.
    #[error("excerpt domain mismatch")]
    DomainMismatch,
    /// `kid` is not the key's thumbprint.
    #[error("kid is not the key thumbprint")]
    Thumbprint,
    /// Algorithm not in the allowlist, not enabled, or not the key's type.
    #[error("algorithm not allowed")]
    Algorithm,
    /// The key may not sign this kind of answer.
    #[error("usage not allowed")]
    Usage,
    /// The window is inverted, too long, or does not contain `iat`.
    #[error("outside the key window")]
    Window,
}

impl KeyScopeError {
    /// The stable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Signature(CoseError::UnknownKid) => "unknown-binding",
            Self::Signature(CoseError::ContentType) => "content-type",
            Self::Signature(_) => "signature",
            Self::Payload => "payload",
            Self::Superseded => "superseded",
            Self::OutOfScope => "outside-binding-scope",
            Self::DomainMismatch => "domain-mismatch",
            Self::Thumbprint => "thumbprint",
            Self::Algorithm => "algorithm",
            Self::Usage => "usage",
            Self::Window => "window",
        }
    }
}

type Read<T> = Result<T, KeyScopeError>;

/// An operational key declaration (Access T20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalKey {
    /// RFC 7638 thumbprint of `key`.
    pub kid: [u8; 32],
    /// Algorithm.
    pub alg: Algorithm,
    /// Public key.
    pub key: PublicKey,
    /// First instant a signature may carry.
    pub valid_from: u64,
    /// Last instant a signature may carry.
    pub valid_until: u64,
    /// What the key may sign; never empty.
    pub usage: BTreeSet<KeyUsage>,
}

impl OperationalKey {
    /// The key set that verifies an answer signed with this key.
    #[must_use]
    pub fn key_set(&self) -> KeySet {
        KeySet {
            keys: BTreeMap::from([(self.kid, self.key.clone())]),
            allowed: BTreeSet::from([self.alg]),
        }
    }

    /// Reads the canonical CBOR of an operational key.
    ///
    /// # Errors
    /// [`KeyScopeError::Payload`].
    pub fn from_bytes(bytes: &[u8]) -> Read<Self> {
        Self::from_value(&decode(bytes)?)
    }

    fn from_value(v: &Value) -> Read<Self> {
        let f = Fields::of(v)?;
        let key = Self {
            kid: bytes32(f.req("kid")?)?,
            alg: alg_of(f.req("alg")?)?,
            key: public_key(f.req("key")?)?,
            valid_from: uint(f.req("valid_from")?)?,
            valid_until: uint(f.req("valid_until")?)?,
            usage: set_items(f.req("usage")?, true)?
                .iter()
                .map(|u| match u {
                    Value::Text(t) => KeyUsage::named(t).ok_or(KeyScopeError::Payload),
                    _ => Err(KeyScopeError::Payload),
                })
                .collect::<Read<_>>()?,
        };
        f.done(&["kid", "alg", "key", "valid_from", "valid_until", "usage"])?;
        Ok(key)
    }

    fn fits(&self) -> bool {
        self.key.check().is_ok()
            && matches!(
                (&self.key, self.alg),
                (PublicKey::Ed25519(_), Algorithm::Ed25519)
                    | (PublicKey::P256(_), Algorithm::Esp256 | Algorithm::Es256)
            )
    }
}

/// Which domains a binding key speaks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingScope {
    /// Only the metadata's own domain.
    Domain,
    /// A provider-wide key declared for these domains.
    Provider(BTreeSet<[u8; 32]>),
}

/// A binding key of Domain Metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingKey {
    /// RFC 7638 thumbprint.
    pub kid: [u8; 32],
    /// Algorithm.
    pub alg: Algorithm,
    /// Public key.
    pub key: PublicKey,
    /// Scope.
    pub scope: BindingScope,
    /// Set after a handover or recovery; such a key no longer signs.
    pub superseded: bool,
}

/// The authority fields of Domain Metadata this client reads (Access CR-58 m.3); the others are
/// left unread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainMetadata {
    /// Domain identifier.
    pub domain: [u8; 32],
    /// Binding keys by `kid`.
    pub binding: BTreeMap<[u8; 32], BindingKey>,
    /// The only algorithm allowlist.
    pub algorithms: BTreeSet<Algorithm>,
    /// Operational key window ceiling.
    pub operational_window_max_ms: u64,
    /// Hybrid policy word, when set.
    pub hybrid: Option<String>,
    /// The opaque discovery bytes (`suiss-discovery.cddl`).
    pub discovery: Option<Vec<u8>>,
}

impl DomainMetadata {
    /// Reads the metadata payload.
    ///
    /// # Errors
    /// [`KeyScopeError::Payload`].
    pub fn from_bytes(bytes: &[u8]) -> Read<Self> {
        let v = decode(bytes)?;
        let f = Fields::of(&v)?;
        let mut binding = BTreeMap::new();
        for b in set_items(f.req("binding")?, true)? {
            let b = binding_key(b)?;
            if binding.insert(b.kid, b).is_some() {
                return Err(KeyScopeError::Payload);
            }
        }
        let algorithms = set_items(f.req("algorithms")?, true)?
            .iter()
            .map(alg_of)
            .collect::<Read<_>>()?;
        let hybrid = match f.opt("hybrid") {
            None => None,
            Some(Value::Text(t)) if ["classic", "both", "pq"].contains(&t.as_str()) => {
                Some(t.clone())
            }
            Some(_) => return Err(KeyScopeError::Payload),
        };
        let discovery = match f.opt("discovery") {
            None => None,
            Some(Value::Bytes(b)) => Some(b.clone()),
            Some(_) => return Err(KeyScopeError::Payload),
        };
        let out = Self {
            domain: digest(f.req("domain")?)?,
            binding,
            algorithms,
            operational_window_max_ms: uint(f.req("operational_window_max_ms")?)?,
            hybrid,
            discovery,
        };
        if out.operational_window_max_ms > MAX_WINDOW_MS {
            return Err(KeyScopeError::Payload);
        }
        Ok(out)
    }

    /// The binding keys that may still sign, as a key set under the metadata's allowlist.
    #[must_use]
    pub fn binding_set(&self) -> KeySet {
        KeySet {
            keys: self
                .binding
                .values()
                .filter(|b| !b.superseded)
                .map(|b| (b.kid, b.key.clone()))
                .collect(),
            allowed: self.algorithms.clone(),
        }
    }
}

/// Verifies binding-signed Domain Metadata against `trusted`, the binding keys the verifier
/// already holds, and reads it.
///
/// # Errors
/// [`KeyScopeError`].
pub fn verify_metadata(bytes: &[u8], trusted: &KeySet) -> Read<DomainMetadata> {
    let verified = cose::verify_sign1(&PureBackend, bytes, trusted, METADATA_CONTENT_TYPE)
        .map_err(KeyScopeError::Signature)?;
    let metadata = DomainMetadata::from_bytes(&verified.payload)?;
    let signer = metadata
        .binding
        .get(&verified.kid)
        .ok_or(KeyScopeError::Signature(CoseError::UnknownKid))?;
    if signer.superseded {
        return Err(KeyScopeError::Superseded);
    }
    if signer.alg != verified.algorithm || !metadata.algorithms.contains(&signer.alg) {
        return Err(KeyScopeError::Algorithm);
    }
    Ok(metadata)
}

/// The payload of a `COSE_Sign1` before its signature is checked, to learn the key it names.
///
/// # Errors
/// [`KeyScopeError::Signature`] for bytes that are not a tagged `COSE_Sign1` with a payload.
pub fn unverified_payload(bytes: &[u8]) -> Read<Vec<u8>> {
    cose::parse_sign1(bytes)
        .map_err(KeyScopeError::Signature)?
        .payload
        .ok_or(KeyScopeError::Signature(CoseError::Payload))
}

/// The operational key that signed an answer of `domain` at `iat` with `usage`, from the
/// binding-signed `excerpt` (Access CR-58 m.5).
///
/// # Errors
/// The first step that fails, as [`KeyScopeError`].
pub fn operational_key(
    metadata: &DomainMetadata,
    domain: &[u8; 32],
    excerpt: &[u8],
    usage: KeyUsage,
    iat: u64,
) -> Read<OperationalKey> {
    let bindings = KeySet {
        keys: metadata
            .binding
            .values()
            .map(|b| (b.kid, b.key.clone()))
            .collect(),
        allowed: metadata.algorithms.clone(),
    };
    let verified = cose::verify_sign1(&PureBackend, excerpt, &bindings, EXCERPT_CONTENT_TYPE)
        .map_err(KeyScopeError::Signature)?;
    let binding = metadata
        .binding
        .get(&verified.kid)
        .ok_or(KeyScopeError::Signature(CoseError::UnknownKid))?;
    if binding.alg != verified.algorithm {
        return Err(KeyScopeError::Algorithm);
    }
    if binding.superseded {
        return Err(KeyScopeError::Superseded);
    }
    let in_scope = match &binding.scope {
        BindingScope::Domain => metadata.domain == *domain,
        BindingScope::Provider(domains) => domains.contains(domain),
    };
    if !in_scope {
        return Err(KeyScopeError::OutOfScope);
    }
    let v = decode(&verified.payload)?;
    let f = Fields::of(&v)?;
    let excerpt_domain = digest(f.req("domain")?)?;
    let key = OperationalKey::from_value(f.req("key")?)?;
    f.done(&["domain", "key"])?;
    if excerpt_domain != *domain {
        return Err(KeyScopeError::DomainMismatch);
    }
    if key.kid != thumbprint(&key.key) {
        return Err(KeyScopeError::Thumbprint);
    }
    let hybrid_classic = metadata.hybrid.as_deref().is_none_or(|h| h == "classic");
    if !metadata.algorithms.contains(&key.alg)
        || !key.alg.enabled()
        || !key.fits()
        || !hybrid_classic
    {
        return Err(KeyScopeError::Algorithm);
    }
    if !key.usage.contains(&usage) {
        return Err(KeyScopeError::Usage);
    }
    let width = key
        .valid_until
        .checked_sub(key.valid_from)
        .ok_or(KeyScopeError::Window)?;
    if width > metadata.operational_window_max_ms.min(MAX_WINDOW_MS)
        || iat < key.valid_from
        || iat > key.valid_until
    {
        return Err(KeyScopeError::Window);
    }
    Ok(key)
}

/// RFC 7638 SHA-256 JWK thumbprint, as Access computes it (Access CR-24).
#[must_use]
pub fn thumbprint(key: &PublicKey) -> [u8; 32] {
    let json = match key {
        PublicKey::Ed25519(x) => format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, b64url(x)),
        PublicKey::P256(sec1) => {
            let (x, y) = sec1
                .get(1..)
                .and_then(|xy| xy.split_at_checked(32))
                .unwrap_or_default();
            format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                b64url(x),
                b64url(y)
            )
        }
        PublicKey::MlDsa(alg, public) => {
            let name = match alg {
                Algorithm::MlDsa44 => "ML-DSA-44",
                Algorithm::MlDsa65 => "ML-DSA-65",
                _ => "ML-DSA-87",
            };
            format!(
                r#"{{"alg":"{name}","kty":"AKP","pub":"{}"}}"#,
                b64url(public)
            )
        }
    };
    Sha256::digest(json.as_bytes()).into()
}

fn binding_key(v: &Value) -> Read<BindingKey> {
    let f = Fields::of(v)?;
    let superseded = match f.opt("superseded") {
        None => false,
        Some(s) => {
            let g = Fields::of(s)?;
            digest(g.req("at")?)?;
            digest(g.req("cited")?)?;
            g.done(&["at", "cited"])?;
            true
        }
    };
    let scope = match f.req("scope")? {
        Value::Text(t) if t == "domain" => BindingScope::Domain,
        other => {
            let g = Fields::of(other)?;
            let domains = set_items(g.req("provider")?, true)?
                .iter()
                .map(digest)
                .collect::<Read<_>>()?;
            g.done(&["provider"])?;
            BindingScope::Provider(domains)
        }
    };
    let key = BindingKey {
        kid: bytes32(f.req("kid")?)?,
        alg: alg_of(f.req("alg")?)?,
        key: public_key(f.req("key")?)?,
        scope,
        superseded,
    };
    f.done(&["kid", "alg", "key", "scope", "superseded"])?;
    if key.kid != thumbprint(&key.key) {
        return Err(KeyScopeError::Payload);
    }
    Ok(key)
}

fn public_key(v: &Value) -> Read<PublicKey> {
    let f = Fields::of(v)?;
    let key = match (f.opt("ed25519"), f.opt("p256"), f.opt("ml_dsa")) {
        (Some(k), None, None) => PublicKey::Ed25519(bytes32(k)?),
        (None, Some(Value::Bytes(k)), None) => PublicKey::P256(k.clone()),
        (None, None, Some(Value::Array(parts))) => match parts.as_slice() {
            [a, Value::Bytes(k)] => PublicKey::MlDsa(alg_of(a)?, k.clone()),
            _ => return Err(KeyScopeError::Payload),
        },
        _ => return Err(KeyScopeError::Payload),
    };
    f.done(&["ed25519", "p256", "ml_dsa"])?;
    key.check().map_err(|_| KeyScopeError::Payload)?;
    Ok(key)
}

fn decode(bytes: &[u8]) -> Read<Value> {
    dcbor::decode(bytes, Limits::CEILING).map_err(|_| KeyScopeError::Payload)
}

fn uint(v: &Value) -> Read<u64> {
    match v {
        Value::Unsigned(u) => Ok(*u),
        _ => Err(KeyScopeError::Payload),
    }
}

fn bytes32(v: &Value) -> Read<[u8; 32]> {
    match v {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| KeyScopeError::Payload),
        _ => Err(KeyScopeError::Payload),
    }
}

fn digest(v: &Value) -> Read<[u8; 32]> {
    Digest::from_value(v)
        .map(|d| d.0)
        .ok_or(KeyScopeError::Payload)
}

fn alg_of(v: &Value) -> Read<Algorithm> {
    v.as_i64()
        .and_then(Algorithm::from_cose)
        .ok_or(KeyScopeError::Payload)
}

/// The items of a canonical set: strictly ascending by encoding, so also without duplicates.
fn set_items(v: &Value, non_empty: bool) -> Read<&[Value]> {
    let Value::Array(items) = v else {
        return Err(KeyScopeError::Payload);
    };
    if non_empty && items.is_empty() {
        return Err(KeyScopeError::Payload);
    }
    let mut previous: Option<Vec<u8>> = None;
    for item in items {
        let bytes = dcbor::encode(item, Limits::CEILING).map_err(|_| KeyScopeError::Payload)?;
        if previous.as_ref().is_some_and(|p| *p >= bytes) {
            return Err(KeyScopeError::Payload);
        }
        previous = Some(bytes);
    }
    Ok(items)
}

/// The members of a CBOR map with text keys.
pub(crate) struct Fields<'a>(BTreeMap<&'a str, &'a Value>);

impl<'a> Fields<'a> {
    pub(crate) fn of(v: &'a Value) -> Read<Self> {
        let Value::Map(entries) = v else {
            return Err(KeyScopeError::Payload);
        };
        let mut out = BTreeMap::new();
        for (k, v) in entries {
            let Value::Text(k) = k else {
                return Err(KeyScopeError::Payload);
            };
            if out.insert(k.as_str(), v).is_some() {
                return Err(KeyScopeError::Payload);
            }
        }
        Ok(Self(out))
    }

    pub(crate) fn req(&self, name: &str) -> Read<&'a Value> {
        self.0.get(name).copied().ok_or(KeyScopeError::Payload)
    }

    pub(crate) fn opt(&self, name: &str) -> Option<&'a Value> {
        self.0.get(name).copied()
    }

    /// Refuses members other than `known`.
    pub(crate) fn done(&self, known: &[&str]) -> Read<()> {
        if self.0.keys().all(|k| known.contains(k)) {
            Ok(())
        } else {
            Err(KeyScopeError::Payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::tests::hex;

    const VECTORS: &str = include_str!("../../../../conformance/vectors/access/key-scope.json");

    // T-101
    #[test]
    fn t_101_the_operational_key_is_resolved_as_the_access_key_scope_vectors_say() {
        let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert!(cases.len() >= 29);
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let want = case["error"].as_str();
            let got = DomainMetadata::from_bytes(&hex(case["metadata"].as_str().unwrap()))
                .and_then(|m| {
                    let domain = digest(&decode(&hex(case["domain"].as_str().unwrap())).unwrap())?;
                    let usage = KeyUsage::named(case["usage"].as_str().unwrap()).unwrap();
                    operational_key(
                        &m,
                        &domain,
                        &hex(case["excerpt"].as_str().unwrap()),
                        usage,
                        case["iat"].as_u64().unwrap(),
                    )
                });
            match (want, got) {
                (None, Ok(key)) => {
                    let expected =
                        OperationalKey::from_bytes(&hex(case["key"].as_str().unwrap())).unwrap();
                    assert_eq!(key, expected, "{id}");
                }
                (Some(name), Err(e)) => assert_eq!(e.code(), name, "{id}"),
                (want, got) => panic!("{id}: expected {want:?}, got {got:?}"),
            }
        }
    }

    // T-101
    #[test]
    fn t_101_a_key_without_the_key_lookup_usage_does_not_sign_an_answer() {
        let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let case = &vectors["cases"][0];
        let m = DomainMetadata::from_bytes(&hex(case["metadata"].as_str().unwrap())).unwrap();
        let domain = digest(&decode(&hex(case["domain"].as_str().unwrap())).unwrap()).unwrap();
        assert_eq!(
            operational_key(
                &m,
                &domain,
                &hex(case["excerpt"].as_str().unwrap()),
                KeyUsage::KeyLookup,
                case["iat"].as_u64().unwrap(),
            ),
            Err(KeyScopeError::Usage)
        );
    }
}
