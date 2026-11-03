//! The ledger vectors in `conformance/vectors/records` through the kernel verifier (T-4, T-10, P-11, P-20, P-32, P-75, P-79, P-100, P-101): every stored entry is verified from its bytes with the record ID recomputed, and its inclusion in a log-signed, witness-cosigned checkpoint is proven with the shared crate's Merkle and note verification.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
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

// T-10 P-11 P-75 P-79 P-100 P-21 P-108
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
        assert_eq!(entry.id(), v.verification().record);
        assert!(matches!(v.record(), Decoded::Record(r) if **r == *entry.record()));
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

// T-10 P-11 P-75 P-79 P-108
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

/// The envelope bytes with the `evidence` entry of their `actor_type` annotation replaced, or removed.
fn with_presenters(envelope: &[u8], evidence: Option<&Cbor>) -> Vec<u8> {
    let Ok(Cbor::Map(mut fields)) = dcbor::decode(envelope, Limits::CEILING) else {
        panic!("envelope");
    };
    for (key, value) in &mut fields {
        if let (Cbor::Text(name), Cbor::Map(actors)) = (&*key, value)
            && name == "actor_type"
        {
            actors.retain(|(k, _)| !matches!(k, Cbor::Text(t) if t == "evidence"));
            if let Some(e) = evidence {
                actors.push((Cbor::text("evidence"), e.clone()));
            }
        }
    }
    dcbor::encode(&Cbor::Map(fields), Limits::CEILING).unwrap()
}

fn checked_with(
    directory: &Directory,
    at: &ChainPoint,
    stored: &Stored,
    envelope: &[u8],
) -> Result<(), String> {
    let (record, _, cose) = stored;
    let entry = StoredEntry {
        envelope,
        record,
        cose_sign1: cose.as_deref(),
    };
    check(directory, entry, at)
}

// EV-35 P-12 T-10
#[test]
fn ev_35_a_stored_presenter_annotation_must_match_the_record_evidence() {
    let directory = Directory::new();
    let entries = stored();
    let start = ChainPoint::genesis(&genesis_bytes()).unwrap();
    let (promise, act) = (&entries[0], &entries[1]);
    let pair = ["organization", "access_binding"].map(Cbor::text);
    let presenter = Cbor::Array(Vec::from(pair));
    let one = Cbor::Array(vec![presenter.clone()]);
    let two = Cbor::Array(vec![presenter.clone(), presenter]);
    let added = with_presenters(&promise.1, Some(&one));
    assert_eq!(
        checked_with(&directory, &start, promise, &added),
        mismatch("actor_type")
    );
    let first = StoredEntry {
        envelope: &promise.1,
        record: &promise.0,
        cose_sign1: promise.2.as_deref(),
    };
    let at = verify_entry(&directory, &start, &first).unwrap().next();
    assert_eq!(checked_with(&directory, &at, act, &act.1), Ok(()));
    for evidence in [None, Some(&two)] {
        let changed = with_presenters(&act.1, evidence);
        assert_eq!(
            checked_with(&directory, &at, act, &changed),
            mismatch("actor_type")
        );
    }
}

// P-109 P-5 P-11
#[test]
fn p_109_no_record_of_the_golden_ledger_repeats_another() {
    let entries = stored();
    let records: BTreeSet<&[u8]> = entries.iter().map(|(r, _, _)| r.as_slice()).collect();
    assert_eq!(entries.len(), 16);
    assert_eq!(records.len(), entries.len());
}

// P-101 P-100 P-108 T-4
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

// T-4 P-11 P-101 T-88
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

fn name_and_key(key: &Value) -> (&str, [u8; 32]) {
    let public = hex_of(&key["public_key_hex"]).try_into().unwrap();
    (key["name"].as_str().unwrap(), public)
}

fn checkpoint_keys() -> (Verifier, Vec<Verifier>) {
    let merkle = file(MERKLE);
    let keys = &merkle["keys"];
    let (name, public) = name_and_key(&keys["log"]);
    let vkey = keys["log"]["vkey"].as_str().unwrap();
    let log = Verifier::parse(vkey).unwrap();
    assert_eq!(log, Verifier::ed25519(name, public).unwrap());
    assert_eq!(log.to_vkey(), vkey);
    let mut witnesses = Vec::new();
    for witness in keys["witnesses"].as_array().unwrap() {
        let (name, public) = name_and_key(witness);
        let vkey = witness["vkey"].as_str().unwrap();
        let cosigner = Verifier::parse(vkey).unwrap();
        assert_eq!(cosigner, Verifier::cosigner(name, public).unwrap());
        assert_eq!(cosigner.to_vkey(), vkey);
        witnesses.push(cosigner);
    }
    (log, witnesses)
}

// T-4 P-20 OP-33 T-64 T-88
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
                assert_eq!(
                    serde_json::json!(signed.profile.to_extensions()),
                    expect["profile"],
                    "{}",
                    case["id"]
                );
            }
            Err(error) => {
                assert_eq!(expect["reason"], error.code(), "{}", case["id"]);
            }
        }
    }
}

// OP-46 T-88
#[test]
fn op_46_a_checkpoint_without_exactly_its_three_profile_lines_is_malformed() {
    let (log, witnesses) = checkpoint_keys();
    let merkle = file(MERKLE);
    let mut rejected = 0;
    for case in merkle["checkpoints"].as_array().unwrap() {
        let got = verify_checkpoint(
            case["note"].as_str().unwrap(),
            case["origin"].as_str().unwrap(),
            &log,
            &witnesses,
        );
        let profiled = case["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "OP-46");
        match (got, case["expect"]["outcome"].as_str().unwrap()) {
            (Ok(signed), "accept") => {
                assert_eq!(
                    serde_json::json!(signed.checkpoint.extensions),
                    case["expect"]["profile"],
                    "{}",
                    case["id"]
                );
            }
            (Err(error), "reject") if profiled => {
                assert_eq!(error, NoteError::Checkpoint, "{}", case["id"]);
                rejected += 1;
            }
            (Err(_), "reject") => {}
            (got, _) => panic!("{}: {got:?}", case["id"]),
        }
    }
    assert_eq!(rejected, 10);
}

// T-4 P-11 P-20 P-101 P-108 T-88
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
