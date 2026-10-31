//! The deterministic CBOR, digest, genesis and envelope vectors in `conformance/vectors/records` natively through the kernel's codec over the shared crate (P-5, P-7, P-67, P-100, P-101, Access CR-10).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::Value;
use work_kernel::codec::{
    Limits, TagAllowlist, body_commitment, decode_digest, decode_with, encode_digest, leaf_hash,
};
use work_kernel::cose::parse_container;
use work_kernel::envelope::{Envelope, EnvelopeIngest, decode_envelope};
use work_kernel::id::Digest;
use work_kernel::reason::QuarantineReason;
use work_kernel::record::PartName;

const CBOR: &str = include_str!("../../../conformance/vectors/records/cbor-canonical.json");
const DIGEST: &str = include_str!("../../../conformance/vectors/records/digest.json");
const GENESIS: &str = include_str!("../../../conformance/vectors/records/genesis.json");
const RECORDS: &str = include_str!("../../../conformance/vectors/records/records.json");
const QUARANTINE: &str =
    include_str!("../../../conformance/vectors/records/records-quarantine.json");

const COSE_SIGN1: u64 = 18;

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex_of(v: &Value) -> Vec<u8> {
    hex(v.as_str().unwrap())
}

fn digest_of(v: &Value) -> Digest {
    Digest::sha256(hex_of(v).try_into().unwrap())
}

fn file(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn outcome<T>(result: &Result<T, work_kernel::reason::Reason>) -> Value {
    match result {
        Ok(_) => serde_json::json!({ "outcome": "accept" }),
        Err(reason) => serde_json::json!({ "outcome": "reject", "reason": reason.to_string() }),
    }
}

fn input(case: &Value) -> Vec<u8> {
    if let Some(h) = case.get("hex") {
        return hex_of(h);
    }
    let g = &case["generator"];
    let mut bytes = hex_of(&g["head_hex"]);
    let fill = hex_of(&g["fill_hex"]);
    for _ in 0..g["fill_count"].as_u64().unwrap() {
        bytes.extend_from_slice(&fill);
    }
    bytes
}

// P-5 P-7 P-72 P-103 Access CR-10
#[test]
fn p_5_cbor_canonical_vectors_through_the_shared_decoder() {
    let cbor = file(CBOR);
    let limits = &cbor["limits"];
    assert_eq!(limits["depth"], Limits::MAX_DEPTH);
    assert_eq!(limits["items"], Limits::MAX_ITEMS);
    assert_eq!(limits["string_bytes"], Limits::MAX_STRING);
    let cases = cbor["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 43);
    for case in cases {
        let tags: Vec<u64> = case["context"]["tag_allowlist"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_u64().unwrap())
            .collect();
        let bytes = input(case);
        let allow = TagAllowlist::only(&tags);
        let decoded = if allow.allows(COSE_SIGN1) && bytes.first() == Some(&0xd2) {
            outcome(&parse_container(&bytes))
        } else {
            outcome(&decode_with(&bytes, Limits::CEILING, &allow))
        };
        assert_eq!(decoded, case["expect"], "{}", case["id"]);
    }
}

fn digest_cases() -> Vec<Value> {
    file(DIGEST)["cases"].as_array().unwrap().clone()
}

fn digest_case(id: &str) -> Value {
    digest_cases().into_iter().find(|c| c["id"] == id).unwrap()
}

// P-5 P-67 Access CR-1
#[test]
fn p_67_digest_vectors_decode_encode_and_reject() {
    let mut checked = 0;
    for case in digest_cases() {
        let Some(encoded) = case.get("encoded_digest_hex") else {
            continue;
        };
        let decoded = decode_digest(&hex_of(encoded));
        if let Some(value) = case.get("digest_hex") {
            assert_eq!(decoded, Ok(digest_of(value)), "{}", case["id"]);
            assert_eq!(encode_digest(&digest_of(value)), hex_of(encoded));
        } else {
            assert_eq!(outcome(&decoded), case["expect"], "{}", case["id"]);
        }
        checked += 1;
    }
    assert_eq!(checked, 3);
}

// P-67 P-100 P-101
#[test]
fn p_101_leaf_hash_vector_uses_the_shared_prefix_0x00() {
    let case = digest_case("digest/leaf-0x00");
    let envelope = &file(RECORDS)["envelopes"][0];
    assert_eq!(
        leaf_hash(&hex_of(&envelope["hex"])),
        digest_of(&case["digest_hex"])
    );
}

// P-17 P-68 P-101
#[test]
fn p_101_body_commitment_vector_uses_the_shared_prefix_0x03() {
    let case = digest_case("digest/body-commit-0x03");
    let part = &case["part"];
    let commit = body_commitment(
        &hex_of(&case["salt_hex"]).try_into().unwrap(),
        &PartName::parse(part["name"].as_str().unwrap()).unwrap(),
        part["media_type"].as_str().unwrap(),
        &hex_of(&part["content_hex"]),
    );
    assert_eq!(commit, Ok(digest_of(&case["digest_hex"])));
}

// P-100 P-11 P-18 P-27 P-67 T-32 Access CR-1
#[test]
fn p_100_genesis_vectors_select_the_schema_by_position() {
    let genesis = file(GENESIS);
    let cases = genesis["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let bytes = hex_of(&case["hex"]);
        let decoded = decode_envelope(&bytes);
        assert_eq!(outcome(&decoded), case["expect"], "{}", case["id"]);
        if let Ok(envelope) = decoded {
            let Envelope::Genesis(g) = envelope else {
                panic!("{}: not a genesis", case["id"]);
            };
            assert_eq!(g.nonce.to_vec(), hex_of(&case["decoded"]["nonce"]));
            assert_eq!(g.recorded_at.0, case["decoded"]["recorded_at"]);
            assert_eq!(leaf_hash(&bytes), digest_of(&case["leaf_hash"]));
        }
    }
}

// P-11 P-12 P-21 P-75 P-100 INV-18
#[test]
fn p_100_envelope_vectors_decode_and_chain_from_the_genesis() {
    let genesis = file(GENESIS);
    let records = file(RECORDS);
    let quarantine = file(QUARANTINE);
    let mut prev = digest_of(&genesis["cases"][0]["leaf_hash"]);
    let accepted = records["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(records["envelopes"].as_array().unwrap());
    let quarantined = quarantine["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c, &c["envelope"]));
    let mut position = 0;
    for (record, envelope) in accepted.chain(quarantined) {
        position += 1;
        let bytes = hex_of(&envelope["hex"]);
        let Ok(Envelope::Ledger(e)) = decode_envelope(&bytes) else {
            panic!("{}: not a ledger envelope", record["id"]);
        };
        assert_eq!(e.position, position);
        assert_eq!(e.prev, prev, "{}", record["id"]);
        assert_eq!(
            encode_digest(&e.record.0),
            hex_of(&record["record_digest"]),
            "{}",
            record["id"]
        );
        assert_eq!(
            e.auth_context.is_some(),
            envelope["decoded"].get("auth_context").is_some()
        );
        assert_eq!(
            e.proof_commit.is_some(),
            envelope["decoded"].get("proof_commit").is_some()
        );
        let rings = envelope["decoded"]["actor_type"]
            .get("on_behalf_of")
            .map_or(0, |r| r.as_array().unwrap().len());
        assert_eq!(e.actor_types.on_behalf_of.len(), rings);
        let expected = match record["expect"]["reason"].as_str() {
            None => EnvelopeIngest::Admitted,
            Some(code) => EnvelopeIngest::Quarantined(QuarantineReason::from_code(code).unwrap()),
        };
        assert_eq!(e.ingest, expected, "{}", record["id"]);
        let leaf = leaf_hash(&bytes);
        assert_eq!(leaf, digest_of(&envelope["leaf_hash"]), "{}", record["id"]);
        prev = leaf;
    }
    assert_eq!(position, 16);
}
