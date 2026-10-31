//! Record signatures through the kernel's `COSE_Sign1` profile over the shared crate (P-6, P-7, P-102, Access CR-9): the signed payload is the first `records.json` record; the Ed25519 key is the RFC 8032 test 1 key and the P-256 key the RFC 6979 A.2.5 key, both signing deterministically.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::BTreeSet;

use serde_json::Value as Json;
use suiss_crypto::dcbor::{Limits, Value, encode};
use work_kernel::codec::{Decoded, decode_record, record_id};
use work_kernel::cose::{
    Algorithm, AuthorKeys, CONTENT_TYPE, KeySet, PublicKey, SignedPayload, signature_detail,
    verify_record_signature,
};
use work_kernel::id::PartyRef;
use work_kernel::reason::{Reason, Schema, Signature};
use work_kernel::verify::{AuthorBinding, VerifyOutcome, verify_signed};

const RECORDS: &str = include_str!("../../../conformance/vectors/records/records.json");
const ED25519_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ED25519_SIGNATURE: &str = "e0000f0e3c44364b7848ba4e4df7c3089e045c6f64fd9c7187360159389b2e03003419507ae86bfcecab3570822220fb769b2f054e1cd21e044053f8f71e5e06";
const P256_PUBLIC: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const ESP256_LOW_S: &str = "6feff64a6bbe55e7cf4120a75c1b21d20c63672ac2031cebe2bcbba7e1671c7565cdbc725467c5a064ff31a1bd2d38a3c8e784d2c0e59a7c098b729cf0706d3f";
const ESP256_HIGH_S: &str = "6feff64a6bbe55e7cf4120a75c1b21d20c63672ac2031cebe2bcbba7e1671c759a32438cab983a609b00ce5e42d2c75bf3ff75dae6320408ea2e58260bf2b812";
const ES256_LOW_S: &str = "6bbe81c8a2e50a1d1051fc0f910b6ba272857d6bf59ed3464fe989c69adf385c704d9d6aeccc646a929ba35b15ac025dbfc25647aacb609e27f765a67522ead6";
const ES256_HIGH_S: &str = "6bbe81c8a2e50a1d1051fc0f910b6ba272857d6bf59ed3464fe989c69adf385c8fb2629413339b966d645ca4ea53fda1fd24a465fc4c3de6cbc2651c87403a7b";
const ED_KID: [u8; 32] = [0x11; 32];
const P256_KID: [u8; 32] = [0x22; 32];

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn payload() -> Vec<u8> {
    let file: Json = serde_json::from_str(RECORDS).unwrap();
    hex(file["records"][0]["hex"].as_str().unwrap())
}

fn cbor(value: &Value) -> Vec<u8> {
    encode(value, Limits::CEILING).unwrap()
}

fn header(entries: Vec<(Value, Value)>) -> Vec<u8> {
    cbor(&Value::Map(entries))
}

fn profile(alg: i64, kid: &[u8]) -> Vec<u8> {
    header(vec![
        (Value::Unsigned(1), Value::int(alg)),
        (Value::Unsigned(3), Value::text(CONTENT_TYPE)),
        (Value::Unsigned(4), Value::Bytes(kid.to_vec())),
    ])
}

fn framed(protected: &[u8], unprotected: &Value, payload: Option<&[u8]>, sig: &[u8]) -> Vec<u8> {
    let mut out = vec![0xd2, 0x84];
    out.extend(cbor(&Value::Bytes(protected.to_vec())));
    out.extend(cbor(unprotected));
    match payload {
        Some(p) => out.extend(cbor(&Value::Bytes(p.to_vec()))),
        None => out.push(0xf6),
    }
    out.extend(cbor(&Value::Bytes(sig.to_vec())));
    out
}

fn sign1(protected: &[u8], sig: &str) -> Vec<u8> {
    framed(
        protected,
        &Value::Map(Vec::new()),
        Some(&payload()),
        &hex(sig),
    )
}

fn ed25519_message() -> Vec<u8> {
    sign1(&profile(-19, &ED_KID), ED25519_SIGNATURE)
}

fn keys(allowed: &[Algorithm]) -> KeySet {
    let mut keys = KeySet {
        allowed: allowed.iter().copied().collect::<BTreeSet<_>>(),
        ..KeySet::default()
    };
    keys.insert(
        ED_KID,
        PublicKey::Ed25519(hex(ED25519_PUBLIC).try_into().unwrap()),
    )
    .unwrap();
    keys.insert(P256_KID, PublicKey::P256(hex(P256_PUBLIC)))
        .unwrap();
    keys
}

fn all() -> KeySet {
    keys(&[Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256])
}

fn rejected(detail: Signature) -> Result<SignedPayload, Reason> {
    Err(Reason::Signature(detail))
}

// P-6 P-8 P-79
#[test]
fn p_6_ed25519_record_signature_verifies_over_the_signed_record_bytes() {
    let signed = verify_record_signature(&ed25519_message(), &all()).unwrap();
    assert_eq!(signed.algorithm, Algorithm::Ed25519);
    assert_eq!(signed.kid, ED_KID);
    assert_eq!(signed.payload, payload());
    assert!(matches!(
        decode_record(&signed.payload),
        Ok(Decoded::Record(_))
    ));
}

// P-6 P-7 Access CR-9
#[test]
fn p_6_esp256_and_es256_verify_with_low_s() {
    for (alg, sig, algorithm) in [
        (-9, ESP256_LOW_S, Algorithm::Esp256),
        (-7, ES256_LOW_S, Algorithm::Es256),
    ] {
        let signed = verify_record_signature(&sign1(&profile(alg, &P256_KID), sig), &all());
        assert_eq!(signed.map(|s| s.algorithm), Ok(algorithm));
    }
}

// P-7 Access CR-9
#[test]
fn p_7_high_s_ecdsa_on_a_work_record_is_rejected() {
    for (alg, sig) in [(-9, ESP256_HIGH_S), (-7, ES256_HIGH_S)] {
        assert_eq!(
            verify_record_signature(&sign1(&profile(alg, &P256_KID), sig), &all()),
            rejected(Signature::HighS)
        );
    }
}

// P-6
#[test]
fn p_6_a_changed_payload_or_signature_is_invalid() {
    let mut tampered = payload();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let message = framed(
        &profile(-19, &ED_KID),
        &Value::Map(Vec::new()),
        Some(&tampered),
        &hex(ED25519_SIGNATURE),
    );
    assert_eq!(
        verify_record_signature(&message, &all()),
        rejected(Signature::Invalid)
    );
    let mut sig = hex(ED25519_SIGNATURE);
    sig.pop();
    let short = framed(
        &profile(-19, &ED_KID),
        &Value::Map(Vec::new()),
        Some(&payload()),
        &sig,
    );
    assert_eq!(
        verify_record_signature(&short, &all()),
        rejected(Signature::Invalid)
    );
}

// P-6 Access CR-7
#[test]
fn p_6_the_algorithm_comes_from_policy_never_from_the_header() {
    let only_ed = keys(&[Algorithm::Ed25519]);
    assert!(verify_record_signature(&ed25519_message(), &only_ed).is_ok());
    assert_eq!(
        verify_record_signature(&sign1(&profile(-9, &P256_KID), ESP256_LOW_S), &only_ed),
        rejected(Signature::AlgNotAllowed)
    );
    let ml_dsa = keys(&[Algorithm::MlDsa65]);
    assert_eq!(
        verify_record_signature(&sign1(&profile(-49, &ED_KID), ED25519_SIGNATURE), &ml_dsa),
        rejected(Signature::AlgNotAllowed)
    );
    for unknown in [-8, -257, 0] {
        assert_eq!(
            verify_record_signature(
                &sign1(&profile(unknown, &ED_KID), ED25519_SIGNATURE),
                &all()
            ),
            rejected(Signature::AlgNotAllowed)
        );
    }
    assert_eq!(
        verify_record_signature(&sign1(&profile(-19, &P256_KID), ED25519_SIGNATURE), &all()),
        rejected(Signature::AlgNotAllowed)
    );
}

// P-6 Access CR-55
#[test]
fn p_6_a_kid_without_a_bound_key_is_kid_unknown() {
    assert_eq!(
        verify_record_signature(
            &sign1(&profile(-19, &[0x33; 32]), ED25519_SIGNATURE),
            &all()
        ),
        rejected(Signature::KidUnknown)
    );
}

// P-6 P-69 Access CR-5
#[test]
fn p_6_headers_outside_the_profile_are_header_profile() {
    let with = |label: u64, value: Value| {
        let mut entries = vec![
            (Value::Unsigned(1), Value::int(-19)),
            (Value::Unsigned(3), Value::text(CONTENT_TYPE)),
            (Value::Unsigned(4), Value::Bytes(ED_KID.to_vec())),
        ];
        entries.push((Value::Unsigned(label), value));
        header(entries)
    };
    let headers = [
        with(2, Value::Array(vec![Value::Unsigned(1)])),
        with(5, Value::Bytes(vec![0; 12])),
        header(vec![(Value::Unsigned(1), Value::int(-19))]),
        profile(-19, &[0x11; 31]),
        vec![0xa2, 0x04, 0x58, 0x20],
    ];
    for protected in headers {
        assert_eq!(
            verify_record_signature(&sign1(&protected, ED25519_SIGNATURE), &all()),
            rejected(Signature::HeaderProfile)
        );
    }
    let unprotected = framed(
        &profile(-19, &ED_KID),
        &Value::Map(vec![(Value::Unsigned(4), Value::Bytes(ED_KID.to_vec()))]),
        Some(&payload()),
        &hex(ED25519_SIGNATURE),
    );
    assert_eq!(
        verify_record_signature(&unprotected, &all()),
        rejected(Signature::HeaderProfile)
    );
}

// P-6 P-72
#[test]
fn p_6_only_a_tagged_attached_cose_sign1_is_a_record_container() {
    let message = ed25519_message();
    let untagged = message[1..].to_vec();
    let detached = framed(
        &profile(-19, &ED_KID),
        &Value::Map(Vec::new()),
        None,
        &hex(ED25519_SIGNATURE),
    );
    let mut three = message.clone();
    three[1] = 0x83;
    for bytes in [untagged, detached, three] {
        assert_eq!(
            verify_record_signature(&bytes, &all()),
            Err(Reason::Schema(Schema::Container))
        );
    }
    let mut trailing = message;
    trailing.push(0);
    assert_eq!(
        verify_record_signature(&trailing, &all()).map(|_| ()),
        Err(Reason::from_code("malformed_cbor:trailing_bytes").unwrap())
    );
}

// P-7 Access CR-9 Access CR-53
#[test]
fn p_7_non_canonical_ed25519_signatures_and_small_order_keys_are_rejected() {
    let mut sig = hex(ED25519_SIGNATURE);
    sig[63] = 0xff;
    let unreduced = framed(
        &profile(-19, &ED_KID),
        &Value::Map(Vec::new()),
        Some(&payload()),
        &sig,
    );
    assert_eq!(
        verify_record_signature(&unreduced, &all()),
        rejected(Signature::NonCanonicalEd25519)
    );
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    let error = KeySet::default()
        .insert([0; 32], PublicKey::Ed25519(identity))
        .unwrap_err();
    assert_eq!(signature_detail(error), Signature::SmallOrderKey);
}

// P-102 P-6 Access CR-5
#[test]
fn p_102_the_protected_header_carries_the_work_record_content_type() {
    assert_eq!(CONTENT_TYPE, "application/work-record+cbor");
    assert!(verify_record_signature(&ed25519_message(), &all()).is_ok());
    let with = |content_type: Option<Value>| {
        let mut entries = vec![(Value::Unsigned(1), Value::int(-19))];
        entries.extend(content_type.map(|t| (Value::Unsigned(3), t)));
        entries.push((Value::Unsigned(4), Value::Bytes(ED_KID.to_vec())));
        header(entries)
    };
    for content_type in [
        None,
        Some(Value::text("application/cbor")),
        Some(Value::text("application/work-record+cbor; v=1")),
        Some(Value::Unsigned(60)),
    ] {
        assert_eq!(
            verify_record_signature(&sign1(&with(content_type), ED25519_SIGNATURE), &all()),
            rejected(Signature::HeaderProfile)
        );
    }
}

// P-8 P-79 P-21 SEC-5 T-87
#[test]
fn p_8_the_shared_verifier_fills_the_signature_port_and_names_the_record_by_its_payload() {
    let author = PartyRef::new("party:acme:agent-procure-7").unwrap();
    let keys = all();
    let port = AuthorKeys {
        author: &author,
        keys: &keys,
    };
    let VerifyOutcome::Verified(verified) = verify_signed(&port, &ed25519_message(), None) else {
        panic!("expected verified");
    };
    assert_eq!(verified.record, record_id(&payload()));
    assert_eq!(verified.author, author);
    assert_eq!(verified.binding, AuthorBinding::SignatureValid);
    let unbound = sign1(&profile(-19, &[0x33; 32]), ED25519_SIGNATURE);
    assert_eq!(
        verify_signed(&port, &unbound, None),
        VerifyOutcome::Rejected(Reason::Signature(Signature::KidUnknown))
    );
    let untagged = ed25519_message()[1..].to_vec();
    assert_eq!(
        verify_signed(&port, &untagged, None),
        VerifyOutcome::Rejected(Reason::Schema(Schema::Container))
    );
}
