//! Instance key lookup (T-101 item 4; Access OP-149 m.5, m.15 (b)–(e), `key-lookup.cddl`): the identifiers Access writes on the wire, the batch request, and the canonical `COSE_Sign1` answer verified under the domain's operational key with usage `key-lookup` and checked entry by entry before any key is used.

use std::collections::BTreeSet;
use std::sync::Arc;

use suiss_crypto::cose::{self, Algorithm, PublicKey};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::Digest;
use suiss_crypto::sig::PureBackend;

use crate::domain::metadata::{
    DomainMetadata, Fields, KeyScopeError, KeyUsage, operational_key, thumbprint,
    unverified_payload,
};
use crate::domain::{AccessError, b64url, fixed_b64url};

/// Content type of the signed key lookup payload.
pub const LOOKUP_CONTENT_TYPE: &str = "application/access-key-lookup+cbor";

/// What Work asks for: the canonical signed answer (Access OP-149 m.15 (c)).
pub const ACCEPT_COSE: &str = "application/cose";

/// The answer header with the binding-signed excerpt of the signing key, base64url.
pub const EXCERPT_HEADER: &str = "access-key-excerpt";

/// Most kids one batch asks for (Access OP-149 m.5).
pub const MAX_KIDS: usize = 100;

/// An RFC 7638 SHA-256 thumbprint, written as 43 characters of unpadded base64url.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kid(pub [u8; 32]);

impl Kid {
    /// Reads the wire text.
    ///
    /// # Errors
    /// [`AccessError::Identifier`].
    pub fn parse(text: &str) -> Result<Self, AccessError> {
        fixed_b64url(text).map(Self)
    }

    /// The wire text.
    #[must_use]
    pub fn text(&self) -> String {
        b64url(&self.0)
    }
}

/// An authority domain, written `sha-256:` and the unpadded base64url of its digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(pub [u8; 32]);

impl DomainId {
    /// Reads the wire text.
    ///
    /// # Errors
    /// [`AccessError::Identifier`].
    pub fn parse(text: &str) -> Result<Self, AccessError> {
        let b64 = text
            .strip_prefix("sha-256:")
            .ok_or(AccessError::Identifier("domain"))?;
        fixed_b64url(b64).map(Self)
    }

    /// The wire text.
    #[must_use]
    pub fn text(&self) -> String {
        format!("sha-256:{}", b64url(&self.0))
    }
}

/// A Party, Instance or Claim identifier: 16 bytes, unpadded base64url on the wire, no prefix
/// (Access OP-149 m.16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KernelId(pub [u8; 16]);

impl KernelId {
    /// Reads the wire text.
    ///
    /// # Errors
    /// [`AccessError::Identifier`].
    pub fn parse(text: &str) -> Result<Self, AccessError> {
        fixed_b64url(text).map(Self)
    }

    /// The wire text.
    #[must_use]
    pub fn text(&self) -> String {
        b64url(&self.0)
    }
}

/// The ledger point a lookup reads at: the head, a position, or a record's ledger time.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AsOf {
    /// The head.
    Head,
    /// A ledger position.
    Position(u64),
    /// An RFC 3339 trusted time, the record's ledger time (T-101 item 4).
    Time(String),
}

impl AsOf {
    /// The `as_of` text, absent at the head.
    #[must_use]
    pub fn text(&self) -> Option<String> {
        match self {
            Self::Head => None,
            Self::Position(p) => Some(p.to_string()),
            Self::Time(t) => Some(t.clone()),
        }
    }
}

/// The `POST keys:batchGet` body: the domain, the kids without duplicates, `as_of`.
///
/// # Errors
/// [`AccessError::Answer`] for zero, more than [`MAX_KIDS`] or repeated kids.
pub fn batch_body(domain: &DomainId, kids: &[Kid], as_of: &AsOf) -> Result<Vec<u8>, AccessError> {
    let unique: BTreeSet<&Kid> = kids.iter().collect();
    if kids.is_empty() || kids.len() > MAX_KIDS || unique.len() != kids.len() {
        return Err(AccessError::Answer("kids"));
    }
    let mut body = serde_json::json!({
        "domain": domain.text(),
        "kids": kids.iter().map(Kid::text).collect::<Vec<_>>(),
    });
    if let (Some(t), serde_json::Value::Object(m)) = (as_of.text(), &mut body) {
        m.insert("as_of".to_owned(), t.into());
    }
    serde_json::to_vec(&body).map_err(|_| AccessError::Answer("kids"))
}

/// The state of a key at the answer's position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// Its Instance holds it.
    Active,
    /// Its Instance no longer holds it.
    Ended,
    /// It was established inside a `party_compromise` window.
    Compromised,
}

/// A ledger position and its trusted time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerPoint {
    /// Position.
    pub pos: u64,
    /// Trusted time, Unix milliseconds.
    pub at: u64,
}

/// The `party_compromise` Claim that covers a key. Work reads it only to know the key is
/// compromised; the SEC-36 window starts only at the `party.compromised` event's `window_from`
/// (WD-104 item 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compromise {
    /// Access's `from`; never the start of the SEC-36 window.
    pub from: u64,
    /// Commit time of the declaration.
    pub declared_at: u64,
    /// The `ClaimID`.
    pub source: KernelId,
}

/// One Instance key as the answer states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceKey {
    /// The thumbprint, checked against `key`.
    pub kid: Kid,
    /// Algorithm: Ed25519 (`-19`) or ESP256 (`-9`).
    pub alg: Algorithm,
    /// The key.
    pub key: PublicKey,
    /// The Party.
    pub party: KernelId,
    /// The Instance.
    pub instance: KernelId,
    /// From when the Instance holds it.
    pub since: LedgerPoint,
    /// When it stopped holding it.
    pub ended: Option<LedgerPoint>,
    /// The recovery successor.
    pub successor: Option<KernelId>,
    /// State.
    pub state: KeyState,
    /// The covering compromise.
    pub compromise: Option<Compromise>,
}

/// The signed bytes an answer was verified from, kept as evidence for offline verification
/// (T-101 item 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// The `COSE_Sign1` answer.
    pub sign1: Vec<u8>,
    /// The binding-signed excerpt of its key.
    pub excerpt: Vec<u8>,
}

/// A verified key lookup answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyAnswer {
    /// The domain.
    pub domain: DomainId,
    /// The ledger position it was read at.
    pub pos: u64,
    /// Trusted time of the answer.
    pub iat: u64,
    /// The keys known at `pos`.
    pub keys: Vec<InstanceKey>,
    /// The kids not known at `pos`.
    pub unknown: Vec<Kid>,
    /// The bytes it was verified from.
    pub evidence: Arc<Evidence>,
}

fn answer(code: &'static str) -> AccessError {
    AccessError::Answer(code)
}

fn metadata_error(e: KeyScopeError) -> AccessError {
    AccessError::Metadata(e.code())
}

/// Verifies a `COSE_Sign1` key lookup answer for `asked` in `domain`: the excerpt binds its
/// key to `metadata` with usage `key-lookup` at the answer's `iat`, the signature verifies, the
/// `ETag` is its position, it answers exactly the kids asked, and every entry is consistent.
///
/// # Errors
/// [`AccessError::Metadata`] or [`AccessError::Answer`].
pub fn verify_answer(
    metadata: &DomainMetadata,
    domain: &DomainId,
    asked: &[Kid],
    sign1: &[u8],
    excerpt: &[u8],
    etag: Option<u64>,
) -> Result<KeyAnswer, AccessError> {
    let iat = iat_of(&unverified_payload(sign1).map_err(metadata_error)?)?;
    let key = operational_key(metadata, &domain.0, excerpt, KeyUsage::KeyLookup, iat)
        .map_err(metadata_error)?;
    let verified = cose::verify_sign1(&PureBackend, sign1, &key.key_set(), LOOKUP_CONTENT_TYPE)
        .map_err(|e| metadata_error(KeyScopeError::Signature(e)))?;
    let evidence = Arc::new(Evidence {
        sign1: sign1.to_vec(),
        excerpt: excerpt.to_vec(),
    });
    let out = decode_lookup(&verified.payload, evidence)?;
    if out.domain != *domain {
        return Err(answer("domain"));
    }
    if etag != Some(out.pos) {
        return Err(answer("etag"));
    }
    let mut seen = BTreeSet::new();
    for kid in out.keys.iter().map(|k| &k.kid).chain(&out.unknown) {
        if !seen.insert(*kid) {
            return Err(answer("kids"));
        }
    }
    if seen != asked.iter().copied().collect::<BTreeSet<_>>() {
        return Err(answer("kids"));
    }
    for k in &out.keys {
        check_entry(k, out.pos)?;
    }
    Ok(out)
}

fn check_entry(k: &InstanceKey, pos: u64) -> Result<(), AccessError> {
    if thumbprint(&k.key) != k.kid.0 {
        return Err(answer("thumbprint"));
    }
    let fits = matches!(
        (&k.key, k.alg),
        (PublicKey::Ed25519(_), Algorithm::Ed25519) | (PublicKey::P256(_), Algorithm::Esp256)
    );
    let consistent = match k.state {
        KeyState::Active => k.ended.is_none() && k.compromise.is_none(),
        KeyState::Ended => k.ended.is_some() && k.compromise.is_none(),
        KeyState::Compromised => k.compromise.is_some(),
    };
    let ordered =
        k.since.pos <= pos && k.ended.is_none_or(|e| e.pos <= pos && e.pos >= k.since.pos);
    if !fits {
        return Err(answer("alg"));
    }
    if !consistent || !ordered {
        return Err(answer("key_state"));
    }
    Ok(())
}

fn iat_of(payload: &[u8]) -> Result<u64, AccessError> {
    let v = dcbor::decode(payload, Limits::CEILING).map_err(|_| answer("payload"))?;
    match v.get("iat") {
        Some(Value::Unsigned(t)) => Ok(*t),
        _ => Err(answer("payload")),
    }
}

fn payload_error(_: KeyScopeError) -> AccessError {
    answer("payload")
}

fn uint(v: &Value) -> Result<u64, AccessError> {
    match v {
        Value::Unsigned(u) => Ok(*u),
        _ => Err(answer("payload")),
    }
}

fn bytes<const N: usize>(v: &Value) -> Result<[u8; N], AccessError> {
    match v {
        Value::Bytes(b) => <[u8; N]>::try_from(b.as_slice()).map_err(|_| answer("payload")),
        _ => Err(answer("payload")),
    }
}

fn point(v: &Value) -> Result<LedgerPoint, AccessError> {
    let f = Fields::of(v).map_err(payload_error)?;
    let p = LedgerPoint {
        pos: uint(f.req("pos").map_err(payload_error)?)?,
        at: uint(f.req("at").map_err(payload_error)?)?,
    };
    f.done(&["pos", "at"]).map_err(payload_error)?;
    Ok(p)
}

/// Reads an RFC 9052 `COSE_Key`: OKP Ed25519 or EC2 P-256, the Instance key types (Access
/// OP-149 m.14 (a)).
///
/// # Errors
/// [`AccessError::Answer`].
pub fn cose_key(v: &Value) -> Result<(Algorithm, PublicKey), AccessError> {
    let Value::Map(entries) = v else {
        return Err(answer("public_key"));
    };
    let (mut kty, mut alg, mut crv, mut x, mut y) = (None, None, None, None, None);
    for (k, val) in entries {
        let slot = match k.as_i64() {
            Some(1) => &mut kty,
            Some(3) => &mut alg,
            Some(-1) => &mut crv,
            Some(-2) => &mut x,
            Some(-3) => &mut y,
            _ => return Err(answer("public_key")),
        };
        *slot = Some(val);
    }
    let int = |v: Option<&Value>| v.and_then(Value::as_i64);
    let raw = |v: Option<&Value>| match v {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let key = match (int(kty), int(alg), int(crv)) {
        (Some(1), Some(-19), Some(6)) if y.is_none() => {
            let x = raw(x).and_then(|b| <[u8; 32]>::try_from(b).ok());
            (
                Algorithm::Ed25519,
                PublicKey::Ed25519(x.ok_or_else(|| answer("public_key"))?),
            )
        }
        (Some(2), Some(-9), Some(1)) => {
            let (x, y) = raw(x).zip(raw(y)).ok_or_else(|| answer("public_key"))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(answer("public_key"));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend(x);
            sec1.extend(y);
            (Algorithm::Esp256, PublicKey::P256(sec1))
        }
        _ => return Err(answer("public_key")),
    };
    key.1.check().map_err(|_| answer("public_key"))?;
    Ok(key)
}

fn entry(v: &Value) -> Result<InstanceKey, AccessError> {
    let f = Fields::of(v).map_err(payload_error)?;
    let req = |name: &str| f.req(name).map_err(payload_error);
    let alg = req("alg")?
        .as_i64()
        .and_then(Algorithm::from_cose)
        .ok_or_else(|| answer("alg"))?;
    let (key_alg, key) = cose_key(req("public_key")?)?;
    if key_alg != alg {
        return Err(answer("alg"));
    }
    let state = match req("key_state")? {
        Value::Text(t) if t == "active" => KeyState::Active,
        Value::Text(t) if t == "ended" => KeyState::Ended,
        Value::Text(t) if t == "compromised" => KeyState::Compromised,
        _ => return Err(answer("key_state")),
    };
    let compromise = match f.opt("compromise") {
        None => None,
        Some(c) => {
            let g = Fields::of(c).map_err(payload_error)?;
            let out = Compromise {
                from: uint(g.req("from").map_err(payload_error)?)?,
                declared_at: uint(g.req("declared_at").map_err(payload_error)?)?,
                source: KernelId(bytes(g.req("source").map_err(payload_error)?)?),
            };
            g.done(&["from", "declared_at", "source"])
                .map_err(payload_error)?;
            Some(out)
        }
    };
    let out = InstanceKey {
        kid: Kid(bytes(req("kid")?)?),
        alg,
        key,
        party: KernelId(bytes(req("party")?)?),
        instance: KernelId(bytes(req("instance")?)?),
        since: point(req("since")?)?,
        ended: f.opt("ended").map(point).transpose()?,
        successor: f
            .opt("successor")
            .map(|s| bytes(s).map(KernelId))
            .transpose()?,
        state,
        compromise,
    };
    f.done(&[
        "kid",
        "alg",
        "public_key",
        "party",
        "instance",
        "since",
        "ended",
        "successor",
        "key_state",
        "compromise",
    ])
    .map_err(payload_error)?;
    Ok(out)
}

fn decode_lookup(payload: &[u8], evidence: Arc<Evidence>) -> Result<KeyAnswer, AccessError> {
    let v = dcbor::decode(payload, Limits::CEILING).map_err(|_| answer("payload"))?;
    let f = Fields::of(&v).map_err(payload_error)?;
    let req = |name: &str| f.req(name).map_err(payload_error);
    let domain = Digest::from_value(req("domain")?).ok_or_else(|| answer("domain"))?;
    let Value::Array(keys) = req("keys")? else {
        return Err(answer("payload"));
    };
    let Value::Array(unknown) = req("unknown")? else {
        return Err(answer("payload"));
    };
    let out = KeyAnswer {
        domain: DomainId(domain.0),
        pos: uint(req("pos")?)?,
        iat: uint(req("iat")?)?,
        keys: keys.iter().map(entry).collect::<Result<_, _>>()?,
        unknown: unknown
            .iter()
            .map(|k| bytes(k).map(Kid))
            .collect::<Result<_, _>>()?,
        evidence,
    };
    f.done(&["domain", "pos", "iat", "keys", "unknown"])
        .map_err(payload_error)?;
    Ok(out)
}

/// The position an `ETag` names: a quoted decimal.
#[must_use]
pub fn etag_position(etag: Option<&str>) -> Option<u64> {
    let inner = etag?.strip_prefix('"')?.strip_suffix('"')?;
    if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    inner.parse().ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
    use suiss_crypto::secret::Secret;
    use suiss_crypto::signer::{Signer as _, sign_sign1};

    use super::*;
    use crate::domain::metadata::{EXCERPT_CONTENT_TYPE, METADATA_CONTENT_TYPE, verify_metadata};

    const PIN: &str = "4711";
    pub(crate) const IAT: u64 = 1_790_000_000_000;

    pub(crate) fn module() -> PathBuf {
        std::env::var_os("PKCS11_MODULE").map_or_else(
            || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
            PathBuf::from,
        )
    }

    /// A `SoftHSM` token of the test's own (T-56): no KMS mock.
    pub(crate) fn token(test: &str) -> (String, KeyStore) {
        let label = format!("ac-{test}-{}", std::process::id());
        let init = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                &label,
                "--so-pin",
                "12345678",
                "--pin",
                PIN,
            ])
            .output()
            .expect("softhsm2-util runs (T-56)");
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let store = KeyStore::open(&module(), &label, &Secret::new(PIN.to_owned())).unwrap();
        (label, store)
    }

    pub(crate) fn pin() -> Secret<String> {
        Secret::new(PIN.to_owned())
    }

    fn text(s: &str) -> Value {
        Value::text(s)
    }

    fn map(entries: Vec<(&str, Value)>) -> Value {
        let mut e: Vec<(Vec<u8>, (Value, Value))> = entries
            .into_iter()
            .map(|(k, v)| {
                (
                    dcbor::encode(&text(k), Limits::CEILING).unwrap(),
                    (text(k), v),
                )
            })
            .collect();
        e.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Map(e.into_iter().map(|(_, kv)| kv).collect())
    }

    fn enc(v: &Value) -> Vec<u8> {
        dcbor::encode(v, Limits::CEILING).unwrap()
    }

    fn ed(signer: &HsmSigner) -> [u8; 32] {
        match signer.public_key() {
            PublicKey::Ed25519(k) => k,
            PublicKey::P256(_) | PublicKey::MlDsa(..) => panic!("an Ed25519 key"),
        }
    }

    fn digest_value(d: [u8; 32]) -> Value {
        Digest(d).to_value()
    }

    /// The domain's binding key, its operational key and the instance key a test answers about.
    pub(crate) struct Domain {
        pub(crate) id: DomainId,
        binding: HsmSigner,
        operational: HsmSigner,
        pub(crate) metadata: Vec<u8>,
        pub(crate) instance: [u8; 32],
    }

    pub(crate) fn domain(store: &KeyStore) -> Domain {
        domain_named(store, "")
    }

    /// A domain whose keys carry `prefix` in their labels, so one token holds several.
    pub(crate) fn domain_named(store: &KeyStore, prefix: &str) -> Domain {
        let binding = store.generate_ed25519(&format!("{prefix}binding")).unwrap();
        let operational = store
            .generate_ed25519(&format!("{prefix}operational"))
            .unwrap();
        let instance = ed(&store
            .generate_ed25519(&format!("{prefix}instance"))
            .unwrap());
        let id = DomainId([1; 32]);
        let b = ed(&binding);
        let payload = map(vec![
            ("domain", digest_value(id.0)),
            (
                "binding",
                Value::Array(vec![map(vec![
                    (
                        "kid",
                        Value::Bytes(thumbprint(&PublicKey::Ed25519(b)).to_vec()),
                    ),
                    ("alg", Value::int(-19)),
                    ("key", map(vec![("ed25519", Value::Bytes(b.to_vec()))])),
                    ("scope", text("domain")),
                ])]),
            ),
            ("algorithms", Value::Array(vec![Value::int(-19)])),
            ("operational_window_max_ms", Value::Unsigned(MAX_WINDOW)),
        ]);
        let metadata = sign_sign1(
            &binding,
            thumbprint(&PublicKey::Ed25519(b)),
            METADATA_CONTENT_TYPE,
            &enc(&payload),
        )
        .unwrap();
        Domain {
            id,
            binding,
            operational,
            metadata,
            instance,
        }
    }

    const MAX_WINDOW: u64 = 3_600_000;

    impl Domain {
        pub(crate) fn excerpt(&self, usage: &str) -> Vec<u8> {
            let o = ed(&self.operational);
            let key = map(vec![
                (
                    "kid",
                    Value::Bytes(thumbprint(&PublicKey::Ed25519(o)).to_vec()),
                ),
                ("alg", Value::int(-19)),
                ("key", map(vec![("ed25519", Value::Bytes(o.to_vec()))])),
                ("valid_from", Value::Unsigned(IAT.saturating_sub(1000))),
                ("valid_until", Value::Unsigned(IAT.saturating_add(1000))),
                ("usage", Value::Array(vec![text(usage)])),
            ]);
            let payload = map(vec![("domain", digest_value(self.id.0)), ("key", key)]);
            sign_sign1(
                &self.binding,
                thumbprint(&PublicKey::Ed25519(ed(&self.binding))),
                EXCERPT_CONTENT_TYPE,
                &enc(&payload),
            )
            .unwrap()
        }

        pub(crate) fn kid(&self) -> Kid {
            Kid(thumbprint(&PublicKey::Ed25519(self.instance)))
        }

        pub(crate) fn entry(&self, state: &str, compromise: bool) -> Value {
            let mut e = vec![
                ("kid", Value::Bytes(self.kid().0.to_vec())),
                ("alg", Value::int(-19)),
                (
                    "public_key",
                    Value::Map(vec![
                        (Value::Unsigned(1), Value::Unsigned(1)),
                        (Value::Unsigned(3), Value::int(-19)),
                        (Value::int(-1), Value::Unsigned(6)),
                        (Value::int(-2), Value::Bytes(self.instance.to_vec())),
                    ]),
                ),
                ("party", Value::Bytes(vec![2; 16])),
                ("instance", Value::Bytes(vec![3; 16])),
                (
                    "since",
                    map(vec![
                        ("pos", Value::Unsigned(1)),
                        ("at", Value::Unsigned(5)),
                    ]),
                ),
                ("key_state", text(state)),
            ];
            if state == "ended" {
                e.push((
                    "ended",
                    map(vec![
                        ("pos", Value::Unsigned(2)),
                        ("at", Value::Unsigned(6)),
                    ]),
                ));
            }
            if compromise {
                e.push((
                    "compromise",
                    map(vec![
                        ("from", Value::Unsigned(4)),
                        ("declared_at", Value::Unsigned(7)),
                        ("source", Value::Bytes(vec![9; 16])),
                    ]),
                ));
            }
            map(e)
        }

        pub(crate) fn answer(&self, keys: Vec<Value>, unknown: &[Kid], pos: u64) -> Vec<u8> {
            let payload = map(vec![
                ("domain", digest_value(self.id.0)),
                ("pos", Value::Unsigned(pos)),
                ("iat", Value::Unsigned(IAT)),
                ("keys", Value::Array(keys)),
                (
                    "unknown",
                    Value::Array(unknown.iter().map(|k| Value::Bytes(k.0.to_vec())).collect()),
                ),
            ]);
            sign_sign1(
                &self.operational,
                thumbprint(&PublicKey::Ed25519(ed(&self.operational))),
                LOOKUP_CONTENT_TYPE,
                &enc(&payload),
            )
            .unwrap()
        }

        pub(crate) fn read(&self) -> DomainMetadata {
            let unsigned =
                DomainMetadata::from_bytes(&unverified_payload(&self.metadata).unwrap()).unwrap();
            verify_metadata(&self.metadata, &unsigned.binding_set()).unwrap()
        }
    }

    // T-101
    #[test]
    fn t_101_key_lookup_verifies_the_cose_answer_against_domain_metadata() {
        let (_, store) = token("lookup");
        let d = domain(&store);
        let m = d.read();
        let excerpt = d.excerpt("key-lookup");
        let other = Kid([8; 32]);
        let sign1 = d.answer(vec![d.entry("active", false)], &[other], 3);
        let got = verify_answer(&m, &d.id, &[d.kid(), other], &sign1, &excerpt, Some(3)).unwrap();
        assert_eq!(got.pos, 3);
        assert_eq!(got.keys.len(), 1);
        assert_eq!(got.keys[0].state, KeyState::Active);
        assert_eq!(got.keys[0].key, PublicKey::Ed25519(d.instance));
        assert_eq!(got.unknown, vec![other]);
        assert_eq!(got.evidence.excerpt, excerpt);
        assert_eq!(
            verify_answer(&m, &d.id, &[d.kid(), other], &sign1, &excerpt, Some(4)),
            Err(AccessError::Answer("etag"))
        );
        assert_eq!(
            verify_answer(&m, &d.id, &[d.kid()], &sign1, &excerpt, Some(3)),
            Err(AccessError::Answer("kids"))
        );
        assert_eq!(
            verify_answer(
                &m,
                &DomainId([2; 32]),
                &[d.kid(), other],
                &sign1,
                &excerpt,
                Some(3)
            ),
            Err(AccessError::Metadata("outside-binding-scope"))
        );
        let mut forged = sign1.clone();
        let last = forged.len().saturating_sub(1);
        forged[last] ^= 1;
        assert_eq!(
            verify_answer(&m, &d.id, &[d.kid(), other], &forged, &excerpt, Some(3)),
            Err(AccessError::Metadata("signature"))
        );
    }

    // T-101
    #[test]
    fn t_101_an_excerpt_without_key_lookup_usage_or_signed_by_another_key_is_refused() {
        let (_, store) = token("usage");
        let d = domain(&store);
        let m = d.read();
        let sign1 = d.answer(vec![d.entry("active", false)], &[], 3);
        assert_eq!(
            verify_answer(
                &m,
                &d.id,
                &[d.kid()],
                &sign1,
                &d.excerpt("receipt"),
                Some(3)
            ),
            Err(AccessError::Metadata("usage"))
        );
        let other = domain_named(&store, "other-");
        assert_eq!(
            verify_answer(
                &m,
                &d.id,
                &[d.kid()],
                &sign1,
                &other.excerpt("key-lookup"),
                Some(3)
            ),
            Err(AccessError::Metadata("unknown-binding"))
        );
    }

    // T-101
    #[test]
    fn t_101_entries_must_state_their_key_consistently() {
        let (_, store) = token("entries");
        let d = domain(&store);
        let m = d.read();
        let excerpt = d.excerpt("key-lookup");
        for (state, compromise, ok) in [
            ("active", false, true),
            ("ended", false, true),
            ("compromised", true, true),
            ("compromised", false, false),
            ("active", true, false),
        ] {
            let sign1 = d.answer(vec![d.entry(state, compromise)], &[], 3);
            let got = verify_answer(&m, &d.id, &[d.kid()], &sign1, &excerpt, Some(3));
            assert_eq!(got.is_ok(), ok, "{state} {compromise}: {got:?}");
        }
        let sign1 = d.answer(vec![d.entry("compromised", true)], &[], 3);
        let got = verify_answer(&m, &d.id, &[d.kid()], &sign1, &excerpt, Some(3)).unwrap();
        let c = got.keys[0].compromise.unwrap();
        assert_eq!((c.from, c.declared_at), (4, 7));
    }

    // T-101
    #[test]
    fn t_101_identifiers_and_the_batch_body_are_in_access_wire_form() {
        let kid = Kid([5; 32]);
        assert_eq!(Kid::parse(&kid.text()).unwrap(), kid);
        let domain = DomainId([1; 32]);
        assert_eq!(DomainId::parse(&domain.text()).unwrap(), domain);
        assert!(DomainId::parse(&b64url(&[1; 32])).is_err());
        let body: serde_json::Value = serde_json::from_slice(
            &batch_body(
                &domain,
                &[kid],
                &AsOf::Time("2026-11-04T00:00:00Z".to_owned()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(body["domain"], domain.text());
        assert_eq!(body["kids"][0], kid.text());
        assert_eq!(body["as_of"], "2026-11-04T00:00:00Z");
        assert!(batch_body(&domain, &[kid, kid], &AsOf::Head).is_err());
        assert!(batch_body(&domain, &[], &AsOf::Head).is_err());
        let many: Vec<Kid> = (0..=100_u8).map(|i| Kid([i; 32])).collect();
        assert!(batch_body(&domain, &many, &AsOf::Head).is_err());
        assert_eq!(etag_position(Some("\"42\"")), Some(42));
        assert_eq!(etag_position(Some("42")), None);
        assert_eq!(etag_position(Some("W/\"42\"")), None);
    }
}
