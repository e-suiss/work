#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::BTreeMap;

use serde_json::{Value as Json, json};
use work_kernel::codec::{leaf_hash, ledger_id};

use super::*;

const COSE: &str = include_str!("../../../../conformance/vectors/records/cose-sign1.json");
const GENESIS: &str = include_str!("../../../../conformance/vectors/records/genesis.json");
const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
const QUARANTINE: &str =
    include_str!("../../../../conformance/vectors/records/records-quarantine.json");
const MERKLE: &str = include_str!("../../../../conformance/vectors/records/merkle.json");

fn json_of(text: &str) -> Json {
    serde_json::from_str(text).unwrap()
}

fn bytes_of(v: &Json) -> Vec<u8> {
    unhex(v.as_str().unwrap()).unwrap()
}

fn recorded_at(envelope: &[u8]) -> u64 {
    match decode_envelope(envelope).unwrap() {
        Envelope::Genesis(g) => g.recorded_at.0,
        Envelope::Ledger(e) => e.recorded_at.0,
        Envelope::Activation(a) => a.recorded_at.0,
    }
}

/// The golden ledger as a bundle: its genesis and the entries at positions 1 to 18.
fn golden() -> Bundle {
    let mut cose = BTreeMap::new();
    for case in json_of(COSE)["cases"].as_array().unwrap() {
        if let Some(name) = case.get("envelope").and_then(Json::as_str) {
            cose.insert(name.to_owned(), bytes_of(&case["cose_hex"]));
        }
    }
    let records = json_of(RECORDS);
    let quarantine = json_of(QUARANTINE);
    let mut cases = Vec::new();
    for (r, e) in records["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(records["envelopes"].as_array().unwrap())
    {
        let name = format!("records.json {}", e["id"].as_str().unwrap());
        cases.push((bytes_of(&r["hex"]), bytes_of(&e["hex"]), name));
    }
    for c in quarantine["cases"].as_array().unwrap().iter().take(3) {
        let name = format!("records-quarantine.json {} envelope", c["id"].as_str().unwrap());
        cases.push((bytes_of(&c["hex"]), bytes_of(&c["envelope"]["hex"]), name));
    }
    let genesis = bytes_of(&json_of(GENESIS)["cases"][0]["hex"]);
    let mut entries = vec![BundleEntry {
        pos: 0,
        recorded_at_ms: recorded_at(&genesis),
        record: genesis.clone(),
        envelope: genesis.clone(),
        received: Vec::new(),
    }];
    for (pos, (record, envelope, name)) in (1_u64..).zip(cases) {
        let received = cose
            .get(&name)
            .map(|bytes| Received {
                kind: "cose_sign1".to_owned(),
                role: AUTHOR_SIGNATURE.to_owned(),
                bytes: bytes.clone(),
            })
            .into_iter()
            .collect();
        entries.push(BundleEntry {
            pos,
            recorded_at_ms: recorded_at(&envelope),
            record,
            envelope,
            received,
        });
    }
    Bundle {
        ledger: *ledger_id(&genesis).0.as_bytes(),
        entries,
        checkpoints: Vec::new(),
    }
}

fn authors() -> Vec<Json> {
    json_of(COSE)["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            json!({
                "alg": k["alg"],
                "kid_hex": k["kid_hex"],
                "party": k["party"],
                "public_key_hex": k["public_key_hex"],
            })
        })
        .collect()
}

fn trust() -> Trust {
    Trust::parse(&json!({ "authors": authors() }).to_string()).unwrap()
}

fn root_at(size: u64) -> [u8; 32] {
    let roots = json_of(MERKLE);
    let root = roots["roots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["size"].as_u64() == Some(size))
        .unwrap();
    bytes_of(&root["root_hex"]).try_into().unwrap()
}

// P-2 MD-12 P-11 P-20 T-10
#[test]
fn p_2_the_golden_ledger_verifies_offline_from_its_bundle() {
    let bundle = golden();
    let parsed = parse(&encode(&bundle)).unwrap();
    let report = verify(&parsed, &trust()).unwrap();
    assert_eq!(report.ledger, bundle.ledger);
    assert_eq!(report.entries, 19);
    assert_eq!(report.records, 18);
    assert_eq!(report.activations, 0);
    assert_eq!(report.signed, 6);
    assert_eq!(report.auth_context, 12);
    assert_eq!(report.root, root_at(19));
    assert_eq!(report.checkpoints, 0);
    assert_eq!(report.folded_through, 17);
    assert!(report.chains > 0);
}

// P-2 P-8 SEC-5
#[test]
fn p_2_a_signed_record_verifies_only_under_a_trusted_author_key() {
    let bundle = golden();
    let refused = verify(&bundle, &Trust::default()).unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Entry { reason, .. } if reason == "signature:kid_unknown"),
        "{refused:?}"
    );
    let others: Vec<Json> = authors()
        .into_iter()
        .filter(|k| k["party"] != "party:acme:agent-procure-7")
        .collect();
    let narrowed = Trust::parse(&json!({ "authors": others }).to_string()).unwrap();
    assert!(verify(&bundle, &narrowed).is_err());
    for bad in [
        "{}",
        r#"{"authors": [], "extra": 1}"#,
        r#"{"authors": [{"alg": -19, "kid_hex": "00", "party": "p", "public_key_hex": "00"}]}"#,
        r#"{"authors": [], "log": "not a key"}"#,
    ] {
        assert!(Trust::parse(bad).is_err(), "{bad}");
    }
}

// T-10 P-2
#[test]
fn t_10_a_bundle_is_canonical_json_lines_that_round_trip() {
    let bundle = golden();
    let text = encode(&bundle);
    assert_eq!(parse(&text).unwrap(), bundle);
    assert_eq!(encode(&parse(&text).unwrap()), text);
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    assert_eq!(lines.len(), 21);
    assert!(lines[0].starts_with(r#"{"format":"work-export/1","kind":"header","ledger":""#));
    assert!(lines[1].starts_with(r#"{"envelope":""#));
    assert_eq!(lines[20], "{\"checkpoints\":0,\"entries\":19,\"kind\":\"end\"}\n");
    let without_end: String = lines[..20].concat();
    assert_eq!(parse(&without_end), Err(FormatError::Truncated));
    let continued = format!("{text}{}", lines[1]);
    assert_eq!(parse(&continued), Err(FormatError::Truncated));
    let miscounted = text.replace("\"entries\":19", "\"entries\":18");
    assert_eq!(parse(&miscounted), Err(FormatError::Truncated));
    let spaced = text.replacen("{\"envelope\":", "{ \"envelope\":", 1);
    assert!(matches!(parse(&spaced), Err(FormatError::Line { line: 2, .. })));
    let upper = text.replacen(&hex(&bundle.ledger), &hex(&bundle.ledger).to_uppercase(), 1);
    assert!(matches!(parse(&upper), Err(FormatError::Line { line: 1, .. })));
    let missing = text.replacen(",\"received\":[]", "", 1);
    assert!(matches!(parse(&missing), Err(FormatError::Line { .. })));
    assert_eq!(parse(""), Err(FormatError::Truncated));
}

// P-2 P-11 T-10
#[test]
fn p_2_a_tampered_bundle_does_not_verify() {
    let trust = trust();
    let mut flipped = golden();
    let last = flipped.entries[3].record.len() - 1;
    flipped.entries[3].record[last] ^= 1;
    assert!(matches!(verify(&flipped, &trust), Err(VerifyError::Entry { pos: 3, .. })));
    let mut dropped = golden();
    dropped.entries.remove(5);
    assert_eq!(verify(&dropped, &trust), Err(VerifyError::Order(6)));
    let mut moved = golden();
    moved.entries[2].recorded_at_ms += 1;
    assert_eq!(verify(&moved, &trust), Err(VerifyError::Time(2)));
    let mut other = golden();
    other.ledger = [7; 32];
    assert_eq!(verify(&other, &trust), Err(VerifyError::Genesis));
    let mut empty = golden();
    empty.entries.clear();
    assert_eq!(verify(&empty, &trust), Err(VerifyError::Empty));
}

// P-20 P-101 OP-33
#[test]
fn p_20_a_checkpoint_must_match_the_bundle_root() {
    let mut bundle = golden();
    let head = *leaf_hash(&bundle.entries[18].envelope).as_bytes();
    let checkpoint = BundleCheckpoint {
        size: 19,
        root: root_at(19),
        head_leaf: head,
        issued_at_ms: bundle.entries[18].recorded_at_ms,
        note: "unsigned\n".to_owned(),
        cosignatures: Vec::new(),
    };
    bundle.checkpoints.push(checkpoint.clone());
    let parsed = parse(&encode(&bundle)).unwrap();
    let report = verify(&parsed, &trust()).unwrap();
    assert_eq!((report.checkpoints, report.checkpoints_signed), (1, 0));
    let bad = |c: BundleCheckpoint| {
        let mut b = golden();
        b.checkpoints.push(c);
        verify(&b, &trust()).unwrap_err()
    };
    let wrong_root = BundleCheckpoint {
        root: root_at(18),
        ..checkpoint.clone()
    };
    assert_eq!(
        bad(wrong_root),
        VerifyError::Checkpoint {
            size: 19,
            what: "root"
        }
    );
    let wrong_head = BundleCheckpoint {
        head_leaf: [0; 32],
        ..checkpoint.clone()
    };
    assert_eq!(
        bad(wrong_head),
        VerifyError::Checkpoint {
            size: 19,
            what: "head_leaf"
        }
    );
    let beyond = BundleCheckpoint {
        size: 21,
        ..checkpoint.clone()
    };
    assert_eq!(
        bad(beyond),
        VerifyError::Checkpoint {
            size: 21,
            what: "size outside the bundle"
        }
    );
    let keys = json_of(MERKLE);
    let logged = Trust::parse(
        &json!({ "authors": authors(), "log": keys["keys"]["log"]["vkey"] }).to_string(),
    )
    .unwrap();
    let mut unsigned = golden();
    unsigned.checkpoints.push(checkpoint);
    assert!(matches!(verify(&unsigned, &logged), Err(VerifyError::Checkpoint { size: 19, .. })));
}
