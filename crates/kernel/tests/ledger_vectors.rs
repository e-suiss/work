//! The ledger vectors in `conformance/vectors/records` through the kernel verifier (T-4, T-10, P-11, P-20, P-32, P-75, P-79, P-100, P-101): every stored entry is verified from its bytes with the record ID recomputed, and its inclusion in a log-signed, witness-cosigned checkpoint is proven with the shared crate's Merkle and note verification.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use work_kernel::codec::{Decoded, leaf_hash, record_id};
use work_kernel::cose::{Algorithm, AuthorKeys, KeySet, PublicKey, verify_record_signature};
use work_kernel::derive::{AuthorityIssuer, Entry, Restriction};
use work_kernel::id::{Digest, LedgerId, PartyRef};
use work_kernel::proof::{
    Accepted, NoteError, ProofError, Verifier, node_hash, root, verify_checkpoint,
    verify_consistency, verify_inclusion,
};
use work_kernel::reason::Reason;
use work_kernel::verify::{
    AuthorBinding, ChainPoint, SignatureCheck, SignatureVerifier, StoredEntry, verify_entry,
};

const COSE: &str = include_str!("../../../conformance/vectors/records/cose-sign1.json");
const GENESIS: &str = include_str!("../../../conformance/vectors/records/genesis.json");
const MERKLE: &str = include_str!("../../../conformance/vectors/records/merkle.json");
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

fn digests(v: &Value) -> Vec<Digest> {
    v.as_array().unwrap().iter().map(digest_of).collect()
}

fn file(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn uint(v: &Value) -> u64 {
    v.as_u64().unwrap()
}

fn outcome(result: Result<(), ProofError>) -> Value {
    match result {
        Ok(()) => serde_json::json!({ "outcome": "accept" }),
        Err(error) => serde_json::json!({ "outcome": "reject", "reason": error.code() }),
    }
}

/// The record bytes, envelope bytes and, when signed, `COSE_Sign1` bytes of one stored entry.
type Stored = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// Every stored entry after the genesis, in ledger order.
fn stored() -> Vec<Stored> {
    let mut cose = BTreeMap::new();
    for case in file(COSE)["cases"].as_array().unwrap() {
        if let Some(envelope) = case.get("envelope") {
            let name = envelope.as_str().unwrap().to_owned();
            cose.insert(name, hex_of(&case["cose_hex"]));
        }
    }
    let records = file(RECORDS);
    let quarantine = file(QUARANTINE);
    let signed_cases = records["records"].as_array().unwrap();
    let envelopes = records["envelopes"].as_array().unwrap();
    let mut out = Vec::new();
    for (r, e) in signed_cases.iter().zip(envelopes) {
        let id = e["id"].as_str().unwrap();
        let name = format!("records.json {id}");
        out.push((
            hex_of(&r["hex"]),
            hex_of(&e["hex"]),
            cose.get(&name).cloned(),
        ));
    }
    for c in quarantine["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let name = format!("records-quarantine.json {id} envelope");
        out.push((
            hex_of(&c["hex"]),
            hex_of(&c["envelope"]["hex"]),
            cose.get(&name).cloned(),
        ));
    }
    out
}

fn genesis_bytes() -> Vec<u8> {
    hex_of(&file(GENESIS)["cases"][0]["hex"])
}

fn allowed() -> BTreeSet<Algorithm> {
    BTreeSet::from([Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256])
}

/// The signature port: the keys Access binds to the record's author, read from the payload the port is handed.
struct Directory(BTreeMap<String, KeySet>);

impl Directory {
    fn new() -> Self {
        let mut sets: BTreeMap<String, KeySet> = BTreeMap::new();
        for key in file(COSE)["keys"].as_array().unwrap() {
            let owner = key["party"].as_str().unwrap().to_owned();
            let kid: [u8; 32] = hex_of(&key["kid_hex"]).try_into().unwrap();
            let bytes = hex_of(&key["public_key_hex"]);
            let public = match key["alg"].as_i64().unwrap() {
                -19 => PublicKey::Ed25519(bytes.try_into().unwrap()),
                _ => PublicKey::P256(bytes),
            };
            let set = sets.entry(owner).or_insert_with(|| KeySet {
                allowed: allowed(),
                ..KeySet::default()
            });
            set.insert(kid, public).unwrap();
        }
        Self(sets)
    }
}

impl SignatureVerifier for Directory {
    fn check(&self, cose_sign1: &[u8]) -> SignatureCheck {
        let (author, keys) = self
            .0
            .iter()
            .find(|(_, keys)| verify_record_signature(cose_sign1, keys).is_ok())
            .unwrap();
        let author = PartyRef::new(author).unwrap();
        AuthorKeys {
            author: &author,
            keys,
        }
        .check(cose_sign1)
    }
}

// T-10 P-11 P-75 P-79 P-100 P-21
#[test]
fn t_10_the_verifier_recomputes_every_record_id_from_the_stored_bytes() {
    let directory = Directory::new();
    let mut at = ChainPoint::genesis(&genesis_bytes()).unwrap();
    let mut verified = Vec::new();
    for (record, envelope, cose) in stored() {
        let entry = StoredEntry {
            envelope: &envelope,
            record: &record,
            cose_sign1: cose.as_deref(),
        };
        match verify_entry(&directory, &at, &entry) {
            Ok(v) => {
                assert_eq!(v.verification().record, record_id(&record));
                assert_eq!(v.leaf(), leaf_hash(&envelope));
                let binding = if cose.is_some() {
                    AuthorBinding::SignatureValid
                } else {
                    AuthorBinding::AuthContext
                };
                assert_eq!(v.verification().binding, binding);
                at = v.next();
                verified.push(v);
            }
            Err(reason) => {
                assert!(cose.is_none());
                assert_eq!(reason, Reason::ProtocolVersionUnknown);
                at.prev = leaf_hash(&envelope);
            }
        }
    }
    assert_eq!(verified.len(), 14);
    let positions: Vec<u64> = verified
        .iter()
        .filter_map(|v| v.verification().inclusion.map(|i| i.position))
        .collect();
    assert_eq!(positions.first(), Some(&1));
    assert_eq!(positions.last(), Some(&14));
    let entries: Vec<Entry<'_>> = verified
        .iter()
        .filter_map(|v| Entry::verified(v, Restriction::NoObjection, AuthorityIssuer::Local))
        .collect();
    assert_eq!(entries.len(), 13);
    for (entry, v) in entries.iter().zip(&verified) {
        assert_eq!(entry.id, v.verification().record);
        assert!(matches!(v.record(), Decoded::Record(r) if **r == *entry.record));
    }
}

fn check(directory: &Directory, entry: StoredEntry<'_>, at: &ChainPoint) -> Result<(), String> {
    verify_entry(directory, at, &entry)
        .map(|_| ())
        .map_err(|r| r.to_string())
}

fn mismatch(field: &str) -> Result<(), String> {
    Err(format!("envelope_mismatch:{field}"))
}

fn first_signed() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (record, envelope, cose) = stored().into_iter().next().unwrap();
    (record, envelope, cose.unwrap())
}

// T-10 P-11 P-75 P-79
#[test]
fn t_10_an_entry_that_does_not_match_its_bytes_is_an_envelope_mismatch() {
    let directory = Directory::new();
    let genesis = genesis_bytes();
    let at = ChainPoint::genesis(&genesis).unwrap();
    let (record, envelope, cose) = first_signed();
    let good = StoredEntry {
        envelope: &envelope,
        record: &record,
        cose_sign1: Some(cose.as_slice()),
    };
    assert_eq!(check(&directory, good, &at), Ok(()));
    let mut other_record = record.clone();
    other_record.push(0);
    let changed = StoredEntry {
        record: &other_record,
        ..good
    };
    assert_eq!(check(&directory, changed, &at), mismatch("record"));
    let mut other_cose = cose.clone();
    other_cose.push(0);
    let unsigned = StoredEntry {
        cose_sign1: None,
        ..good
    };
    let resigned = StoredEntry {
        cose_sign1: Some(other_cose.as_slice()),
        ..good
    };
    assert_eq!(check(&directory, unsigned, &at), mismatch("proof_commit"));
    assert_eq!(check(&directory, resigned, &at), mismatch("proof_commit"));
    let elsewhere = ChainPoint {
        ledger: LedgerId(Digest::sha256([7; 32])),
        ..at
    };
    let later = ChainPoint {
        prev: Digest::sha256([7; 32]),
        ..at
    };
    assert_eq!(check(&directory, good, &elsewhere), mismatch("ledger"));
    assert_eq!(check(&directory, good, &later), mismatch("prev"));
    let genesis_in_place = StoredEntry {
        envelope: &genesis,
        ..good
    };
    assert_eq!(check(&directory, genesis_in_place, &at), mismatch("prev"));
    assert!(ChainPoint::genesis(&envelope).is_err());
}

// P-101 P-100 T-4
#[test]
fn p_101_merkle_node_and_root_vectors_through_the_shared_crate() {
    let merkle = file(MERKLE);
    let node = &merkle["nodes"][0];
    assert_eq!(
        node_hash(
            &digest_of(&node["left_hex"]),
            &digest_of(&node["right_hex"])
        ),
        digest_of(&node["digest_hex"])
    );
    let genesis = genesis_bytes();
    let mut leaves: Vec<Vec<u8>> = vec![genesis];
    leaves.extend(stored().into_iter().map(|(_, envelope, _)| envelope));
    assert_eq!(digest_of(&node["left_hex"]), leaf_hash(&leaves[0]));
    for case in merkle["roots"].as_array().unwrap() {
        let size = usize::try_from(uint(&case["size"])).unwrap();
        let (prefix, _) = leaves.split_at(size);
        let slices: Vec<&[u8]> = prefix.iter().map(Vec::as_slice).collect();
        assert_eq!(root(&slices), digest_of(&case["root_hex"]), "size {size}");
    }
}

// T-4 P-11 P-101
#[test]
fn t_4_inclusion_and_consistency_vectors_through_the_kernel_verifier() {
    let merkle = file(MERKLE);
    for case in merkle["inclusion"].as_array().unwrap() {
        let got = verify_inclusion(
            uint(&case["index"]),
            uint(&case["size"]),
            &digest_of(&case["leaf_hash_hex"]),
            &digests(&case["path_hex"]),
            &digest_of(&case["root_hex"]),
        );
        assert_eq!(outcome(got), case["expect"], "{}", case["id"]);
    }
    for case in merkle["consistency"].as_array().unwrap() {
        let got = verify_consistency(
            uint(&case["first"]),
            uint(&case["second"]),
            &digest_of(&case["first_root_hex"]),
            &digest_of(&case["second_root_hex"]),
            &digests(&case["path_hex"]),
        );
        assert_eq!(outcome(got), case["expect"], "{}", case["id"]);
    }
}

fn checkpoint_keys() -> (Verifier, Vec<Verifier>) {
    let keys = &file(MERKLE)["keys"];
    let log = Verifier::parse(keys["log"].as_str().unwrap()).unwrap();
    let witnesses = keys["witnesses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| Verifier::parse(w.as_str().unwrap()).unwrap())
        .collect();
    (log, witnesses)
}

// T-4 P-20 OP-33 T-64
#[test]
fn t_4_checkpoint_and_cosignature_vectors_through_the_kernel_verifier() {
    let (log, witnesses) = checkpoint_keys();
    let merkle = file(MERKLE);
    for case in merkle["checkpoints"].as_array().unwrap() {
        let got = verify_checkpoint(
            case["note"].as_str().unwrap(),
            case["origin"].as_str().unwrap(),
            &log,
            &witnesses,
        );
        let expect = &case["expect"];
        match got {
            Ok(signed) => {
                assert_eq!(expect["outcome"], "accept", "{}", case["id"]);
                assert_eq!(signed.size(), uint(&expect["size"]));
                assert_eq!(signed.root(), digest_of(&expect["root_hex"]));
                let cosigned: Vec<Value> = signed
                    .cosignatures
                    .iter()
                    .map(|a| serde_json::json!({ "name": a.name, "timestamp": a.timestamp }))
                    .collect();
                assert_eq!(Value::Array(cosigned), expect["cosignatures"]);
            }
            Err(error) => {
                assert_eq!(expect["reason"], error.code(), "{}", case["id"]);
            }
        }
    }
}

// T-4 P-11 P-20 P-101
#[test]
fn t_4_every_entry_is_included_in_the_cosigned_checkpoint() {
    let (log, witnesses) = checkpoint_keys();
    let merkle = file(MERKLE);
    let note = &merkle["checkpoints"][0];
    let signed = verify_checkpoint(
        note["note"].as_str().unwrap(),
        note["origin"].as_str().unwrap(),
        &log,
        &witnesses,
    )
    .unwrap();
    assert_eq!(signed.cosignatures.len(), 1);
    let mut leaves = vec![genesis_bytes()];
    leaves.extend(stored().into_iter().map(|(_, e, _)| e));
    let mut included = 0;
    for (position, envelope) in (0_u64..).zip(leaves) {
        let case = merkle["inclusion"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["index"] == position && c["size"] == signed.size())
            .unwrap();
        let path = digests(&case["path_hex"]);
        assert_eq!(
            signed.includes(position, &leaf_hash(&envelope), &path),
            Ok(())
        );
        included += 1;
    }
    assert_eq!(included, 17);
    let older = verify_checkpoint(
        note["note"].as_str().unwrap(),
        note["origin"].as_str().unwrap(),
        &log,
        &[],
    )
    .unwrap();
    assert_eq!(older.cosignatures, Vec::<Accepted>::new());
    assert_eq!(older.extends_to(&signed, &[]), Ok(()));
    let text = note["note"].as_str().unwrap();
    let (body, _) = text.split_once("\n\n").unwrap();
    let unsigned = format!("{body}\n");
    let origin = note["origin"].as_str().unwrap();
    let got = verify_checkpoint(&unsigned, origin, &log, &witnesses);
    assert_eq!(got.map(|_| ()), Err(NoteError::Malformed));
}
