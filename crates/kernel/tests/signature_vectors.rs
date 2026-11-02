//! The `COSE_Sign1` and evidence vectors in `conformance/vectors/records` through the kernel's signature profile over the shared crate (P-6, P-7, P-32, P-75, P-79, P-102, P-103, P-105, P-106, EV-3, EV-8, Access CR-9): every envelope `proof_commit` is the digest of a real signature, the signature strictness cases have their Work reason, and a presenter signs the statement of its evidence reference.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use work_kernel::codec::{Decoded, decode_record, proof_commit, record_id};
use work_kernel::cose::{
    Algorithm, AuthorKeys, KeySet, PresenterKeys, PublicKey, evidence_statement, signature_detail,
};
use work_kernel::envelope::{Envelope, decode_envelope};
use work_kernel::id::{Digest, PartyRef};
use work_kernel::reason::Reason;
use work_kernel::verify::{SignatureCheck, SignatureVerifier};

const COSE: &str = include_str!("../../../conformance/vectors/records/cose-sign1.json");
const EVIDENCE: &str = include_str!("../../../conformance/vectors/records/evidence.json");
const RECORDS: &str = include_str!("../../../conformance/vectors/records/records.json");
const QUARANTINE: &str =
    include_str!("../../../conformance/vectors/records/records-quarantine.json");

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

fn public_key(key: &Value) -> PublicKey {
    let bytes = hex_of(&key["public_key_hex"]);
    match key["alg"].as_i64().unwrap() {
        -19 => PublicKey::Ed25519(bytes.try_into().unwrap()),
        _ => PublicKey::P256(bytes),
    }
}

fn allowed() -> BTreeSet<Algorithm> {
    BTreeSet::from([Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256])
}

/// The key set Access binds to each party of `cose-sign1.json`.
fn key_sets() -> BTreeMap<String, KeySet> {
    let mut sets: BTreeMap<String, KeySet> = BTreeMap::new();
    for key in file(COSE)["keys"].as_array().unwrap() {
        let owner = key["party"].as_str().unwrap().to_owned();
        let kid: [u8; 32] = hex_of(&key["kid_hex"]).try_into().unwrap();
        let set = sets.entry(owner).or_insert_with(|| KeySet {
            allowed: allowed(),
            ..KeySet::default()
        });
        set.insert(kid, public_key(key)).unwrap();
    }
    sets
}

fn party(v: &Value) -> PartyRef {
    PartyRef::new(v.as_str().unwrap()).unwrap()
}

fn outcome<T>(result: &Result<T, Reason>) -> Value {
    match result {
        Ok(_) => serde_json::json!({ "outcome": "accept" }),
        Err(reason) => serde_json::json!({ "outcome": "reject", "reason": reason.to_string() }),
    }
}

fn check_outcome(check: &SignatureCheck) -> Value {
    match check {
        SignatureCheck::Valid { .. } => serde_json::json!({ "outcome": "accept" }),
        SignatureCheck::Rejected(reason) => {
            serde_json::json!({ "outcome": "reject", "reason": reason.to_string() })
        }
    }
}

// P-32 P-6 P-7 P-102 P-103 P-105 P-106 Access CR-9
#[test]
fn p_32_cose_sign1_vectors_through_the_kernel_signature_port() {
    let sets = key_sets();
    let mut checked = 0;
    for case in file(COSE)["cases"].as_array().unwrap() {
        let author = party(&case["author"]);
        let port = AuthorKeys {
            author: &author,
            keys: &sets[author.as_str()],
        };
        let cose = hex_of(&case["cose_hex"]);
        let check = port.check(&cose);
        assert_eq!(check_outcome(&check), case["expect"], "{}", case["id"]);
        if let SignatureCheck::Valid { record, .. } = check {
            assert_eq!(
                record.0,
                digest_of(&case["record_id_hex"]),
                "{}",
                case["id"]
            );
            assert_eq!(
                proof_commit(&cose),
                digest_of(&case["proof_commit_hex"]),
                "{}",
                case["id"]
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 21);
}

// P-7 P-32 Access CR-9 Access CR-53
#[test]
fn p_7_key_vectors_are_rejected_with_their_detail() {
    for case in file(COSE)["key_cases"].as_array().unwrap() {
        let error = KeySet::default()
            .insert([0; 32], public_key(case))
            .unwrap_err();
        let reason = Reason::Signature(signature_detail(error));
        assert_eq!(
            reason.to_string(),
            case["expect"]["reason"].as_str().unwrap(),
            "{}",
            case["id"]
        );
    }
}

// P-75 P-76 P-79
#[test]
fn p_75_every_envelope_proof_commit_is_the_digest_of_a_vector_signature() {
    let commits: BTreeMap<Vec<u8>, Digest> = file(COSE)["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c.get("envelope").is_some())
        .map(|c| {
            (
                hex_of(&c["record_id_hex"]),
                digest_of(&c["proof_commit_hex"]),
            )
        })
        .collect();
    let records = file(RECORDS);
    let quarantine = file(QUARANTINE);
    let envelopes = records["envelopes"].as_array().unwrap().iter().chain(
        quarantine["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| &c["envelope"]),
    );
    let mut signed: Vec<&Digest> = Vec::new();
    for envelope in envelopes {
        let Ok(Envelope::Ledger(e)) = decode_envelope(&hex_of(&envelope["hex"])) else {
            panic!("not a ledger envelope");
        };
        let commit = commits.get(e.record.0.as_bytes().as_slice());
        assert_eq!(e.proof_commit.as_ref(), commit);
        signed.extend(commit);
    }
    assert_eq!(signed.len(), commits.len());
    assert_eq!(signed.len(), 6);
}

// P-6 P-79
#[test]
fn p_6_the_container_is_not_semantic() {
    let cases = file(COSE)["cases"].as_array().unwrap().clone();
    let by_id = |id: &str| cases.iter().find(|c| c["id"] == id).unwrap().clone();
    let second = by_id("cose-sign1/container-es256");
    let first = by_id(second["same_record_as"].as_str().unwrap());
    assert_eq!(first["record_id_hex"], second["record_id_hex"]);
    assert_ne!(first["proof_commit_hex"], second["proof_commit_hex"]);
    assert_ne!(first["key"], second["key"]);
    let payload = hex_of(&file(RECORDS)["records"][0]["hex"]);
    assert_eq!(record_id(&payload).0, digest_of(&second["record_id_hex"]));
}

// EV-3 EV-8 P-6 P-102 P-107
#[test]
fn ev_3_evidence_vectors_bind_the_presenter_signature_to_the_statement() {
    let sets = key_sets();
    let mut checked = 0;
    for case in file(EVIDENCE)["cases"].as_array().unwrap() {
        let bytes = hex_of(&case["hex"]);
        let got = match case.get("cose_hex") {
            Some(cose) => {
                let statement = evidence_statement(&bytes, 0).unwrap();
                let signed = hex_of(&case["statement_hex"]);
                let changed = case["id"] == "evidence/statement-changed";
                assert_eq!(statement.bytes == signed, !changed);
                let presenter = party(&case["presenter"]);
                let keys = PresenterKeys {
                    presenter: &presenter,
                    keys: &sets[presenter.as_str()],
                };
                keys.check(&bytes, 0, &hex_of(cose)).map(|_| ())
            }
            None => decode_record(&bytes).map(|_| ()),
        };
        assert_eq!(outcome(&got), case["expect"], "{}", case["id"]);
        checked += 1;
    }
    assert_eq!(checked, 9);
}

// EV-3 P-10 P-107
#[test]
fn ev_3_a_record_without_the_evidence_reference_has_no_statement() {
    let accepted = &file(EVIDENCE)["cases"][0];
    let bytes = hex_of(&accepted["hex"]);
    assert!(matches!(decode_record(&bytes), Ok(Decoded::Record(_))));
    assert!(evidence_statement(&bytes, 0).is_ok());
    assert_eq!(
        evidence_statement(&bytes, 1).map(|_| ()),
        Err(Reason::from_code("schema:required_field").unwrap())
    );
    let without = hex_of(&file(RECORDS)["records"][0]["hex"]);
    assert_eq!(
        evidence_statement(&without, 0).map(|_| ()),
        Err(Reason::from_code("schema:required_field").unwrap())
    );
}
