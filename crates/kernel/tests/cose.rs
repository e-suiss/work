//! Record signatures through the kernel's `COSE_Sign1` profile over the shared crate (P-6, P-7, P-102, P-103, P-105, P-106, Access CR-9): the signed payload is the first `records.json` record, that record with its `author` replaced by a Party of the same length, that record also carrying protocol 2.0, or the CBOR text `"hello"`; the Ed25519 key is the RFC 8032 test 1 key and the P-256 key the RFC 6979 A.2.5 key, both signing deterministically.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::BTreeSet;

use serde_json::Value as Json;
use suiss_crypto::dcbor::{Limits, Value, encode};
use suiss_crypto::sig::{P256_N, SignatureError};
use work_kernel::codec::{Decoded, decode_record, proof_commit, record_id};
use work_kernel::cose::{
    Algorithm, AuthorKeys, CONTENT_TYPE, KeySet, PublicKey, SignedPayload, signature_detail,
    verify_record_signature,
};
use work_kernel::id::PartyRef;
use work_kernel::reason::{Reason, Schema, Signature};
use work_kernel::record::ProtocolVersion;
use work_kernel::verify::{
    AuthorBinding, SignatureCheck, SignatureVerifier, VerifyOutcome, verify_signed,
};

const RECORDS: &str = include_str!("../../../conformance/vectors/records/records.json");
const ED25519_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ED25519_SIGNATURE: &str = "dbd8cf82ff9261c812a755f2b0263d64ce4dd7513631a64c4b374b5a734d6ce934955ec501671bffcecad4ba042403f15179a75814f9aa40845e5ef12bf8cb09";
const ED25519_OTHER_AUTHOR_SIGNATURE: &str = "d997f76cc846779db1179504049583c13c27d1e1794ff5d0993d10ec670b4990c583e1473d24121682fdd21735598eb953b2eda8092780e02b7d0fb4a601450e";
const AUTHOR: &str = "party:acme:agent-procure-7";
const OTHER_AUTHOR: &str = "party:acme:agent-procure-8";
const ED25519_UNKNOWN_PROTOCOL_SIGNATURE: &str = "0b50f7b0d0c6b12f1d08fc0d1aae1d06e9c4f89745fb54238df10b66d59b83e9f1366b207b490f59276174416a7044418942981ae434b3912f0cbb25f0d3700b";
const ED25519_TEXT_SIGNATURE: &str = "364827975ea7eac8d021523721ff52640a09c4575ca513162fc31b034087a47cd4712822d917c9f9272a174e80c39bdd67aa0e9967c7f29095f3d9502550880e";
const PROTOCOL_1_0: &[u8] = b"protocol\x82\x01\x00";
const PROTOCOL_2_0: &[u8] = b"protocol\x82\x02\x00";
const P256_PUBLIC: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const ESP256_LOW_S: &str = "232e3e0a735be4797d0719a3a9ff81bf0927c5bd39a424179c36c6b651ba23c304d65bba6dd65e88b5fdf6e43d73f50e2e0980f94880de9815719fcbae1e4d8a";
const ESP256_HIGH_S: &str = "232e3e0a735be4797d0719a3a9ff81bf0927c5bd39a424179c36c6b651ba23c3fb29a4449229a1784a02091bc28c0af18edd79b45e96bfecde482af74e44d7c7";
const ES256_LOW_S: &str = "ddaac9f1bccae68c8e34c063337b6c7e634b9b331192dbf06548cd2dc252d1975fa368177eabbdccdec7747d6242b08eb876563e67bb7a836e403206186536c9";
const ES256_HIGH_S: &str = "ddaac9f1bccae68c8e34c063337b6c7e634b9b331192dbf06548cd2dc252d197a05c97e78154423421388b829dbd4f710470a46f3f5c2401857998bce3fdee88";
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

fn with_signature(alg: i64, kid: &[u8], sig: &[u8]) -> Vec<u8> {
    framed(
        &profile(alg, kid),
        &Value::Map(Vec::new()),
        Some(&payload()),
        sig,
    )
}

// P-103 P-7 Access CR-9
#[test]
fn p_103_a_small_order_r_and_an_out_of_range_ecdsa_scalar_are_invalid() {
    let mut small_order_r = [0_u8; 64];
    small_order_r[0] = 1;
    let got = verify_record_signature(&with_signature(-19, &ED_KID, &small_order_r), &all());
    assert_eq!(got, rejected(Signature::Invalid));
    let low_s = hex(ESP256_LOW_S);
    let (r, s) = low_s.split_at(32);
    let zero = [0_u8; 32];
    let out_of_range = [
        [zero.as_slice(), s].concat(),
        [P256_N.as_slice(), s].concat(),
        [r, zero.as_slice()].concat(),
        [r, P256_N.as_slice()].concat(),
    ];
    for sig in out_of_range {
        let got = verify_record_signature(&with_signature(-9, &P256_KID, &sig), &all());
        assert_eq!(got, rejected(Signature::Invalid));
    }
    for error in [SignatureError::SmallOrderR, SignatureError::ScalarRange] {
        assert_eq!(signature_detail(error), Signature::Invalid);
    }
}

// P-7 Access CR-9 Access CR-53
#[test]
fn p_7_a_non_canonical_r_or_key_is_non_canonical_ed25519() {
    let mut non_canonical = [0xff_u8; 32];
    non_canonical[0] = 0xee;
    non_canonical[31] = 0x7f;
    let sig = hex(ED25519_SIGNATURE);
    let (_, s) = sig.split_at(32);
    let message = with_signature(-19, &ED_KID, &[non_canonical.as_slice(), s].concat());
    let got = verify_record_signature(&message, &all());
    assert_eq!(got, rejected(Signature::NonCanonicalEd25519));
    let error = KeySet::default()
        .insert([0; 32], PublicKey::Ed25519(non_canonical))
        .unwrap_err();
    assert_eq!(error, SignatureError::NonCanonicalKey);
    assert_eq!(signature_detail(error), Signature::NonCanonicalEd25519);
    assert_eq!(
        signature_detail(SignatureError::NonCanonicalR),
        Signature::NonCanonicalEd25519
    );
}

// P-6 P-75 P-79
#[test]
fn p_6_two_containers_of_one_record_name_one_record() {
    let es256_message = sign1(&profile(-7, &P256_KID), ES256_LOW_S);
    let first = verify_record_signature(&ed25519_message(), &all()).unwrap();
    let second = verify_record_signature(&es256_message, &all()).unwrap();
    assert_eq!(first.algorithm, Algorithm::Ed25519);
    assert_eq!(second.algorithm, Algorithm::Es256);
    assert_eq!(record_id(&first.payload), record_id(&second.payload));
    assert_eq!(record_id(&second.payload), record_id(&payload()));
    assert_ne!(
        proof_commit(&ed25519_message()),
        proof_commit(&es256_message)
    );
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
    let author = PartyRef::new(AUTHOR).unwrap();
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

fn spliced(original: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = original
        .windows(from.len())
        .position(|w| w == from)
        .unwrap();
    let (head, tail) = original.split_at(at);
    let mut out = head.to_vec();
    out.extend_from_slice(to);
    out.extend_from_slice(tail.strip_prefix(from).unwrap());
    out
}

fn other_author_payload() -> Vec<u8> {
    spliced(&payload(), AUTHOR.as_bytes(), OTHER_AUTHOR.as_bytes())
}

fn unknown_protocol_payload() -> Vec<u8> {
    spliced(&other_author_payload(), PROTOCOL_1_0, PROTOCOL_2_0)
}

// P-105 P-6 P-8 P-21
#[test]
fn p_105_a_record_whose_author_is_not_the_key_owner_is_kid_unknown() {
    let party_a = PartyRef::new(AUTHOR).unwrap();
    let party_b = PartyRef::new(OTHER_AUTHOR).unwrap();
    let keys = all();
    let port_a = AuthorKeys {
        author: &party_a,
        keys: &keys,
    };
    let port_b = AuthorKeys {
        author: &party_b,
        keys: &keys,
    };
    let authored_by_b = framed(
        &profile(-19, &ED_KID),
        &Value::Map(Vec::new()),
        Some(&other_author_payload()),
        &hex(ED25519_OTHER_AUTHOR_SIGNATURE),
    );
    let Ok(Decoded::Record(record)) = decode_record(&other_author_payload()) else {
        panic!("expected a record");
    };
    assert_eq!(record.core().author, party_b);
    assert!(verify_record_signature(&authored_by_b, &keys).is_ok());
    assert_eq!(
        verify_signed(&port_a, &authored_by_b, None),
        VerifyOutcome::Rejected(Reason::Signature(Signature::KidUnknown))
    );
    let VerifyOutcome::Verified(verified) = verify_signed(&port_a, &ed25519_message(), None) else {
        panic!("expected verified");
    };
    assert_eq!(verified.author, party_a);
    assert_eq!(
        verify_signed(&port_b, &ed25519_message(), None),
        VerifyOutcome::Rejected(Reason::Signature(Signature::KidUnknown))
    );
    let VerifyOutcome::Verified(verified) = verify_signed(&port_b, &authored_by_b, None) else {
        panic!("expected verified");
    };
    assert_eq!(verified.author, party_b);
    assert_eq!(verified.record, record_id(&other_author_payload()));
}

// P-106 P-94
#[test]
fn p_106_an_unknown_protocol_record_is_valid_without_reading_its_author() {
    let party_a = PartyRef::new(AUTHOR).unwrap();
    let keys = all();
    let port_a = AuthorKeys {
        author: &party_a,
        keys: &keys,
    };
    let unknown = unknown_protocol_payload();
    assert_eq!(
        decode_record(&unknown),
        Ok(Decoded::UnknownProtocol(ProtocolVersion {
            major: 2,
            minor: 0
        }))
    );
    let message = framed(
        &profile(-19, &ED_KID),
        &Value::Map(Vec::new()),
        Some(&unknown),
        &hex(ED25519_UNKNOWN_PROTOCOL_SIGNATURE),
    );
    assert_eq!(
        port_a.check(&message),
        SignatureCheck::Valid {
            record: record_id(&unknown),
            author: party_a,
        }
    );
}

// P-106 P-7
#[test]
fn p_106_a_signed_payload_that_is_not_a_record_keeps_its_decoding_reason() {
    let author = PartyRef::new(AUTHOR).unwrap();
    let keys = all();
    let port = AuthorKeys {
        author: &author,
        keys: &keys,
    };
    let text = cbor(&Value::text("hello"));
    let message = framed(
        &profile(-19, &ED_KID),
        &Value::Map(Vec::new()),
        Some(&text),
        &hex(ED25519_TEXT_SIGNATURE),
    );
    assert!(verify_record_signature(&message, &keys).is_ok());
    assert_eq!(
        port.check(&message),
        SignatureCheck::Rejected(Reason::Schema(Schema::RequiredField))
    );
}
