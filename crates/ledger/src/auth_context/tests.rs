#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::Value as Json;
use suiss_crypto::cose::PublicKey;
use work_testkit::realm::{self, ADMITTED_AT, AUTH_TIME, ISSUER, Realm};

use super::*;

const ACCESS: &str = include_str!("../../../../conformance/vectors/access/auth-context.json");

const RECORD: [u8; 32] = [0x2a; 32];

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn encode(v: &Value) -> Vec<u8> {
    dcbor::encode(v, Limits::CEILING).unwrap()
}

fn with(payload: &Value, name: &str, value: Option<Value>) -> Value {
    let Value::Map(entries) = payload else {
        panic!("a map");
    };
    let mut entries: Vec<(Value, Value)> = entries
        .iter()
        .filter(|(k, _)| *k != Value::text(name))
        .cloned()
        .collect();
    if let Some(v) = value {
        entries.push((Value::text(name), v));
    }
    Value::Map(entries)
}

struct Fixture {
    realm: Realm,
    paired: BTreeSet<String>,
}

impl Fixture {
    fn new(test: &str) -> Self {
        Self {
            realm: Realm::open(test).unwrap(),
            paired: realm::paired(),
        }
    }

    fn check(
        &self,
        cose: &[u8],
        digest: &[u8; 32],
        issuer: &str,
    ) -> Result<Verified, AuthContextInvalid> {
        verify(
            &AuthContext {
                bytes: cose,
                digest,
                realm_keys: self.realm.keys(),
                issuer,
                paired: &self.paired,
                now_ms: ADMITTED_AT,
            },
            &RECORD,
        )
    }

    fn verify_payload(&self, payload: &Value) -> Result<Verified, AuthContextInvalid> {
        let a = self.realm.artifact(payload).unwrap();
        self.check(&a.cose, &a.digest, ISSUER)
    }

    fn signed_bytes(&self, payload: &[u8]) -> Result<Verified, AuthContextInvalid> {
        let cose = self.realm.sign_as(ARTIFACT_CONTENT_TYPE, payload).unwrap();
        self.check(&cose, &context_digest(DIGEST_LABEL, payload).0, ISSUER)
    }
}

// P-116 P-21
#[test]
fn p_116_the_reference_is_the_access_digest() {
    let f = Fixture::new("reference");
    let payload = realm::record_payload(RECORD);
    let a = f.realm.artifact(&payload).unwrap();
    let got = f.check(&a.cose, &a.digest, ISSUER).unwrap();
    let mut input = DIGEST_LABEL.as_bytes().to_vec();
    input.push(0);
    input.extend(encode(&payload));
    assert_eq!(got.digest, suiss_crypto::digest::sha256(&input));
    assert_eq!(got.digest, realm::digest(&payload).unwrap());
    assert_ne!(got.digest, suiss_crypto::digest::sha256(&a.cose));
    assert_eq!(got.realm, ISSUER);
    assert_eq!(got.auth_time, AUTH_TIME);
    assert_eq!(kid(&a.cose), Some(f.realm.kid()));
    let mut forwarded = a.digest;
    forwarded[0] ^= 1;
    assert_eq!(
        f.check(&a.cose, &forwarded, ISSUER),
        Err(AuthContextInvalid::Digest)
    );
}

// P-116 P-21
#[test]
fn p_116_assurance_and_step_up_come_from_the_payload() {
    let f = Fixture::new("assurance");
    let plain = realm::record_payload(RECORD);
    let got = f.verify_payload(&plain).unwrap();
    assert_eq!((got.aal, got.step_up), ("aal2", false));
    let stepped = with(
        &with(&plain, "aal", Some(Value::text("aal3"))),
        "step_up_time",
        Some(Value::Unsigned(AUTH_TIME)),
    );
    let got = f.verify_payload(&stepped).unwrap();
    assert_eq!((got.aal, got.step_up), ("aal3", true));
    let later = with(
        &plain,
        "step_up_time",
        Some(Value::Unsigned(ADMITTED_AT.saturating_add(1))),
    );
    assert_eq!(f.verify_payload(&later), Err(AuthContextInvalid::AuthTime));
    let future = with(
        &plain,
        "auth_time",
        Some(Value::Unsigned(ADMITTED_AT.saturating_add(1))),
    );
    assert_eq!(f.verify_payload(&future), Err(AuthContextInvalid::AuthTime));
}

// P-116
#[test]
fn p_116_an_auth_context_bound_to_another_record_is_refused() {
    let f = Fixture::new("other");
    let other = realm::record_payload([0x2b; 32]);
    assert_eq!(
        f.verify_payload(&other),
        Err(AuthContextInvalid::OtherContent)
    );
    let typed = realm::payload(Some(("application/cbor", RECORD)));
    assert_eq!(
        f.verify_payload(&typed),
        Err(AuthContextInvalid::OtherContent)
    );
}

// P-116
#[test]
fn p_116_an_unbound_auth_context_is_refused() {
    let f = Fixture::new("unbound");
    assert_eq!(
        f.verify_payload(&realm::payload(None)),
        Err(AuthContextInvalid::Unbound)
    );
    let half = with(
        &realm::payload(None),
        "content_type",
        Some(Value::text(RECORD_CONTENT_TYPE)),
    );
    assert_eq!(f.verify_payload(&half), Err(AuthContextInvalid::Payload));
}

// P-116
#[test]
fn p_116_a_context_of_an_unpaired_realm_is_refused() {
    let f = Fixture::new("realm");
    let foreign = with(
        &realm::record_payload(RECORD),
        "realm",
        Some(Value::text("https://globex.suiss.example")),
    );
    let a = f.realm.artifact(&foreign).unwrap();
    assert_eq!(
        f.check(&a.cose, &a.digest, "https://globex.suiss.example"),
        Err(AuthContextInvalid::Realm)
    );
    assert_eq!(
        f.check(&a.cose, &a.digest, ISSUER),
        Err(AuthContextInvalid::Realm)
    );
    let ours = f.realm.for_record(RECORD).unwrap();
    assert_eq!(
        f.check(&ours.cose, &ours.digest, "https://globex.suiss.example"),
        Err(AuthContextInvalid::Realm)
    );
}

// P-116
#[test]
fn p_116_only_the_realm_token_key_signs_the_artifact() {
    let f = Fixture::new("signature");
    let other = f.realm.another("other").unwrap();
    let a = other.for_record(RECORD).unwrap();
    assert_eq!(
        f.check(&a.cose, &a.digest, ISSUER),
        Err(AuthContextInvalid::Signature("cose-unknown-kid"))
    );
    let mut tampered = f.realm.for_record(RECORD).unwrap();
    let last = tampered.cose.len().saturating_sub(1);
    tampered.cose[last] ^= 1;
    assert!(matches!(
        f.check(&tampered.cose, &tampered.digest, ISSUER),
        Err(AuthContextInvalid::Signature(_))
    ));
    let bytes = encode(&realm::record_payload(RECORD));
    let typed = f.realm.sign_as("application/cbor", &bytes).unwrap();
    assert_eq!(
        f.check(&typed, &context_digest(DIGEST_LABEL, &bytes).0, ISSUER),
        Err(AuthContextInvalid::Signature("cose-content-type"))
    );
    let mut narrow = f.realm.keys().clone();
    narrow.allowed.remove(&Algorithm::Ed25519);
    let ours = f.realm.for_record(RECORD).unwrap();
    let refused = verify(
        &AuthContext {
            bytes: &ours.cose,
            digest: &ours.digest,
            realm_keys: &narrow,
            issuer: ISSUER,
            paired: &f.paired,
            now_ms: ADMITTED_AT,
        },
        &RECORD,
    );
    assert_eq!(
        refused,
        Err(AuthContextInvalid::Signature("cose-algorithm"))
    );
    assert!(matches!(
        f.realm.keys().keys.get(&f.realm.kid()),
        Some(PublicKey::Ed25519(_))
    ));
}

// P-116
#[test]
fn p_116_the_payload_follows_the_access_cddl_and_its_vectors() {
    let f = Fixture::new("cddl");
    let vectors: Json = serde_json::from_str(ACCESS).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let Some(hex) = case.get("cbor").and_then(Json::as_str) else {
            continue;
        };
        assert!(case["valid"].as_bool().unwrap(), "{id}");
        let bytes = unhex(hex);
        let got = f.signed_bytes(&bytes);
        let expected = if id == "session-only" {
            AuthContextInvalid::Unbound
        } else {
            AuthContextInvalid::OtherContent
        };
        assert_eq!(got, Err(expected), "{id}");
    }
    let base = realm::record_payload(RECORD);
    let digest_value = |b: u8| Digest([b; 32]).to_value();
    let invalid = [
        ("missing-ais-digest", with(&base, "ais_digest", None)),
        (
            "unknown-flag",
            with(
                &base,
                "assurance_flags",
                Some(Value::Array(vec![Value::text("telepathy")])),
            ),
        ),
        (
            "aal-as-number",
            with(&base, "aal", Some(Value::Unsigned(2))),
        ),
        (
            "session-id-in-the-clear",
            with(&base, "session_ref", Some(Value::Bytes(vec![1; 16]))),
        ),
        (
            "content-type-with-parameters",
            with(
                &base,
                "content_type",
                Some(Value::text("application/json; charset=utf-8")),
            ),
        ),
        (
            "unknown-field",
            with(&base, "session_id", Some(Value::Bytes(vec![1; 16]))),
        ),
        ("version-2", with(&base, "v", Some(Value::Unsigned(2)))),
        (
            "http-realm",
            with(
                &base,
                "realm",
                Some(Value::text("http://acme.suiss.example")),
            ),
        ),
        (
            "unordered-flags",
            with(
                &base,
                "assurance_flags",
                Some(Value::Array(vec![Value::text("uv"), Value::text("synced")])),
            ),
        ),
        (
            "repeated-flag",
            with(
                &base,
                "assurance_flags",
                Some(Value::Array(vec![Value::text("uv"), Value::text("uv")])),
            ),
        ),
        (
            "sha-512-digest",
            with(
                &base,
                "content_digest",
                Some(Value::Array(vec![
                    Value::int(-44),
                    Value::Bytes(vec![0x2a; 32]),
                ])),
            ),
        ),
        (
            "short-digest",
            with(
                &base,
                "ais_digest",
                Some(Value::Array(vec![
                    Value::int(-16),
                    Value::Bytes(vec![1; 16]),
                ])),
            ),
        ),
        (
            "upper-case-type",
            with(
                &base,
                "content_type",
                Some(Value::text("Application/work-record+cbor")),
            ),
        ),
        (
            "digest-as-session",
            with(&base, "session_ref", Some(digest_value(3))),
        ),
    ];
    for (id, payload) in &invalid {
        let got = f.verify_payload(payload);
        if *id == "digest-as-session" {
            assert!(got.is_ok(), "{id}: {got:?}");
        } else {
            assert_eq!(got, Err(AuthContextInvalid::Payload), "{id}");
        }
    }
    let mut long = encode(&base);
    long.push(0);
    assert_eq!(f.signed_bytes(&long), Err(AuthContextInvalid::Payload));
    assert_eq!(f.signed_bytes(&[0xa0]), Err(AuthContextInvalid::Payload));
}

// P-116 T-98
#[test]
fn p_116_every_refusal_is_auth_context_invalid() {
    for e in [
        AuthContextInvalid::Signature("cose-unknown-kid"),
        AuthContextInvalid::Algorithm,
        AuthContextInvalid::Payload,
        AuthContextInvalid::Digest,
        AuthContextInvalid::Realm,
        AuthContextInvalid::Unbound,
        AuthContextInvalid::OtherContent,
        AuthContextInvalid::AuthTime,
    ] {
        assert_eq!(e.code(), "auth_context_invalid");
        assert!(!e.detail().is_empty());
    }
    assert_eq!(AUTH_CONTEXT_INVALID, "auth_context_invalid");
    assert_eq!(realm::ARTIFACT_CONTENT_TYPE, ARTIFACT_CONTENT_TYPE);
    assert_eq!(realm::RECORD_CONTENT_TYPE, RECORD_CONTENT_TYPE);
    assert_eq!(realm::DIGEST_LABEL, DIGEST_LABEL);
}
