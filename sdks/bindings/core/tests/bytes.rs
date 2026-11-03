//! The byte entry points of the bindings' front end natively against every record format vector in `conformance/vectors/records` and the touched item vector in `conformance/vectors/kernel`, which WebAssembly and Swift run through their bindings for the same bytes: each answer is the JSON the vector states, byte for byte (T-5, T-37, T-69, INV-7, INV-8, X-24).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::BTreeMap;

use serde_json::{Value, json};
use work_bindings_core::{
    body_commitment, check_activations, check_cbor, check_public_key, checkpoint_extends_to,
    checkpoint_includes, decode_digest, decode_envelope, decode_record_cbor, evidence_statement,
    genesis_chain_point, leaf_hash, ledger_id, merkle_node_hash, merkle_root, parse_cose_container,
    proof_commit, record_id, touched, verify_checkpoint, verify_consistency, verify_entry,
    verify_evidence_signature, verify_inclusion, verify_record_signature,
};

const ACTIVATION: &str = include_str!("../../../../conformance/vectors/records/activation.json");
const CBOR: &str = include_str!("../../../../conformance/vectors/records/cbor-canonical.json");
const COSE: &str = include_str!("../../../../conformance/vectors/records/cose-sign1.json");
const DIGEST: &str = include_str!("../../../../conformance/vectors/records/digest.json");
const EVIDENCE: &str = include_str!("../../../../conformance/vectors/records/evidence.json");
const GENESIS: &str = include_str!("../../../../conformance/vectors/records/genesis.json");
const MERKLE: &str = include_str!("../../../../conformance/vectors/records/merkle.json");
const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
const QUARANTINE: &str =
    include_str!("../../../../conformance/vectors/records/records-quarantine.json");
const ITEMS: &str = include_str!("../../../../conformance/vectors/kernel/items-touched.json");

const ALLOWED: [i64; 3] = [-19, -9, -7];
const COSE_SIGN1_TAG: u64 = 18;

fn file(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn cases(v: &Value, key: &str) -> Vec<Value> {
    let list = v[key].as_array().unwrap().clone();
    assert!(!list.is_empty(), "{key}");
    list
}

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex(v.as_str().unwrap())
}

fn digest(v: &Value) -> Value {
    json!([-16, v])
}

fn encoded_digest(v: &Value) -> Value {
    json!([-16, v.as_str().unwrap().strip_prefix("822f5820").unwrap()])
}

fn found(digest_value: &Value) -> Value {
    json!({ "digest": digest_value })
}

fn accept(fields: Value) -> Value {
    let mut out = fields;
    out["outcome"] = json!("accept");
    out
}

fn same(id: &str, got: &str, want: &Value) {
    assert_eq!(got, want.to_string(), "{id}");
}

/// The keys Access binds to each party of `cose-sign1.json`, in the binding's keys shape.
fn key_sets() -> BTreeMap<String, Vec<Value>> {
    let mut sets: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for key in cases(&file(COSE), "keys") {
        let entry = json!({
            "kid": key["kid_hex"],
            "alg": key["alg"],
            "public_key": key["public_key_hex"],
        });
        sets.entry(key["party"].as_str().unwrap().to_owned())
            .or_default()
            .push(entry);
    }
    sets
}

fn keys_of(sets: &BTreeMap<String, Vec<Value>>, party: &Value) -> String {
    let keys = sets
        .get(party.as_str().unwrap())
        .cloned()
        .unwrap_or_default();
    json!({ "party": party, "allowed": ALLOWED, "keys": keys }).to_string()
}

fn content(part: &Value) -> Vec<u8> {
    if let Some(h) = part.get("content_hex") {
        bytes(h)
    } else {
        let spec = &part["content"];
        let count = usize::try_from(spec["fill_count"].as_u64().unwrap()).unwrap();
        bytes(&spec["fill_hex"]).repeat(count)
    }
}

fn cbor_input(case: &Value) -> Vec<u8> {
    if let Some(h) = case.get("hex") {
        return bytes(h);
    }
    let g = &case["generator"];
    let mut out = bytes(&g["head_hex"]);
    let fill = bytes(&g["fill_hex"]);
    for _ in 0..g["fill_count"].as_u64().unwrap() {
        out.extend_from_slice(&fill);
    }
    out
}

// P-5 P-7 P-72 P-103 T-37 T-95 Access CR-10
#[test]
fn p_5_cbor_canonical_vectors_through_bindings_core() {
    let all = cases(&file(CBOR), "cases");
    for case in &all {
        let tags = &case["context"]["tag_allowlist"];
        let input = cbor_input(case);
        let cose = tags.as_array().unwrap().contains(&json!(COSE_SIGN1_TAG))
            && input.first() == Some(&0xd2);
        let got = if cose {
            parse_cose_container(&input)
        } else {
            check_cbor(&input, &tags.to_string())
        };
        same(case["id"].as_str().unwrap(), &got, &case["expect"]);
    }
    assert_eq!(all.len(), 43);
}

// P-5 P-67 P-68 P-75 P-79 P-101 P-104 T-37 T-95 Access CR-1
#[test]
fn p_79_digest_vectors_through_bindings_core() {
    let records = file(RECORDS);
    let first = &records["records"][0];
    let mut checked = 0;
    for case in cases(&file(DIGEST), "cases") {
        let id = case["id"].as_str().unwrap();
        if let Some(encoded) = case.get("encoded_digest_hex") {
            let want = match case.get("digest_hex") {
                Some(d) => accept(json!({ "digest": digest(d) })),
                None => case["expect"].clone(),
            };
            same(id, &decode_digest(&bytes(encoded)), &want);
        } else if let Some(part) = case.get("part") {
            let got = body_commitment(
                &bytes(&case["salt_hex"]),
                part["name"].as_str().unwrap(),
                part["media_type"].as_str().unwrap(),
                &content(part),
            );
            same(
                id,
                &got,
                &accept(json!({ "digest": digest(&case["digest_hex"]) })),
            );
        } else if id == "digest/record-id" {
            let got = record_id(&bytes(&first["hex"]));
            same(id, &got, &found(&digest(&case["digest_hex"])));
        } else if id == "digest/leaf-0x00" {
            let got = leaf_hash(&bytes(&records["envelopes"][0]["hex"]));
            same(id, &got, &found(&digest(&case["digest_hex"])));
        } else if id == "digest/proof-commit" {
            let cose = bytes(&case["cose_hex"]);
            same(
                id,
                &proof_commit(&cose),
                &found(&digest(&case["digest_hex"])),
            );
            let keys = json!({
                "party": first["decoded"]["author"],
                "allowed": [-19],
                "keys": [{
                    "kid": case["kid_hex"],
                    "alg": -19,
                    "public_key": case["public_key_hex"],
                }],
            });
            let want = accept(json!({
                "author": first["decoded"]["author"],
                "record": digest(&case["record_id_hex"]),
            }));
            same(
                id,
                &verify_record_signature(&cose, &keys.to_string()),
                &want,
            );
        } else {
            panic!("{id}: no binding check");
        }
        checked += 1;
    }
    assert_eq!(checked, 11);
}

fn records_and_envelopes() -> Vec<(Value, Value)> {
    let records = file(RECORDS);
    let quarantine = file(QUARANTINE);
    let mut out: Vec<(Value, Value)> = cases(&records, "records")
        .into_iter()
        .zip(cases(&records, "envelopes"))
        .collect();
    for c in cases(&quarantine, "cases") {
        let envelope = c["envelope"].clone();
        out.push((c, envelope));
    }
    out
}

// P-100 P-11 P-67 P-87 P-101 T-37 T-95
#[test]
fn p_100_genesis_envelope_and_record_bytes_decode_through_bindings_core() {
    let genesis = cases(&file(GENESIS), "cases");
    for case in &genesis {
        let id = case["id"].as_str().unwrap();
        let input = bytes(&case["hex"]);
        let want = if case["expect"]["outcome"] == "accept" {
            accept(json!({ "decoded": case["decoded"] }))
        } else {
            case["expect"].clone()
        };
        same(id, &decode_envelope(&input), &want);
    }
    let first = &genesis[0];
    let input = bytes(&first["hex"]);
    let ledger = digest(&first["ledger_id"]["digest_hex"]);
    let prev = digest(&first["leaf_hash"]);
    same("ledger_id", &ledger_id(&input), &found(&ledger));
    same("leaf_hash", &leaf_hash(&input), &found(&prev));
    let point = accept(json!({ "ledger": ledger, "prev": prev }));
    same("genesis", &genesis_chain_point(&input), &point);
    for (record, envelope) in records_and_envelopes() {
        let id = record["id"].as_str().unwrap();
        let input = bytes(&record["hex"]);
        let want = if record["expect"]["reason"] == "protocol_version_unknown" {
            record["expect"].clone()
        } else {
            accept(json!({ "decoded": record["decoded"] }))
        };
        same(id, &decode_record_cbor(&input), &want);
        same(
            id,
            &record_id(&input),
            &found(&encoded_digest(&record["record_digest"])),
        );
        let input = bytes(&envelope["hex"]);
        let want = accept(json!({ "decoded": envelope["decoded"] }));
        same(id, &decode_envelope(&input), &want);
        same(
            id,
            &leaf_hash(&input),
            &found(&digest(&envelope["leaf_hash"])),
        );
    }
}

// P-110 P-100 P-108 T-37 T-95
#[test]
fn p_110_activation_vectors_through_bindings_core() {
    let v = file(ACTIVATION);
    for case in cases(&v, "cases") {
        let id = case["id"].as_str().unwrap();
        let input = bytes(&case["hex"]);
        same(id, &decode_envelope(&input), &case["expect"]);
        if case["expect"]["outcome"] == "accept" {
            let entry = digest(&case["entry_id"]);
            let leaf = digest(&case["leaf_hash"]);
            same(id, &record_id(&input), &found(&entry));
            same(id, &leaf_hash(&input), &found(&leaf));
        }
    }
    for case in cases(&v, "sequences") {
        let id = case["id"].as_str().unwrap();
        let got = check_activations(&case["entries"].to_string());
        same(id, &got, &case["expect"]);
    }
    let keys = json!({ "party": "party:acme:operator", "allowed": ALLOWED, "keys": [] });
    for case in cases(&v, "verify") {
        let id = case["id"].as_str().unwrap();
        let got = verify_entry(
            &case["at"].to_string(),
            &bytes(&case["envelope"]),
            &bytes(&case["record"]),
            None,
            &keys.to_string(),
        );
        same(id, &got, &case["expect"]);
    }
}

// P-32 P-6 P-7 P-75 P-102 P-105 P-106 T-37 T-95 Access CR-9
#[test]
fn p_32_cose_sign1_and_key_vectors_through_bindings_core() {
    let sets = key_sets();
    let cose = file(COSE);
    for case in cases(&cose, "cases") {
        let id = case["id"].as_str().unwrap();
        let input = bytes(&case["cose_hex"]);
        let got = verify_record_signature(&input, &keys_of(&sets, &case["author"]));
        if case["expect"]["outcome"] == "accept" {
            let want = accept(json!({
                "author": case["author"],
                "record": digest(&case["record_id_hex"]),
            }));
            same(id, &got, &want);
            same(
                id,
                &proof_commit(&input),
                &found(&digest(&case["proof_commit_hex"])),
            );
        } else {
            same(id, &got, &case["expect"]);
        }
    }
    for key in cases(&cose, "keys") {
        let got = check_public_key(key["alg"].as_i64().unwrap(), &bytes(&key["public_key_hex"]));
        same(
            key["id"].as_str().unwrap(),
            &got,
            &json!({ "outcome": "accept" }),
        );
    }
    for case in cases(&cose, "key_cases") {
        let got = check_public_key(
            case["alg"].as_i64().unwrap(),
            &bytes(&case["public_key_hex"]),
        );
        same(case["id"].as_str().unwrap(), &got, &case["expect"]);
    }
}

// EV-3 EV-8 P-6 P-10 P-102 P-107 T-37 T-95
#[test]
fn ev_3_evidence_vectors_through_bindings_core() {
    let sets = key_sets();
    let all = cases(&file(EVIDENCE), "cases");
    for case in &all {
        let id = case["id"].as_str().unwrap();
        let record = bytes(&case["hex"]);
        let Some(cose) = case.get("cose_hex") else {
            same(id, &decode_record_cbor(&record), &case["expect"]);
            continue;
        };
        let index = u32::try_from(case["evidence_index"].as_u64().unwrap()).unwrap();
        let presenter = &case["presenter"];
        let keys = keys_of(&sets, presenter);
        let got = verify_evidence_signature(&record, index, &bytes(cose), &keys);
        same(id, &got, &case["expect"]);
        if id != "evidence/statement-changed" {
            let reference = &case["decoded"]["evidence"][usize::try_from(index).unwrap()];
            let want = accept(json!({
                "statement": case["statement_hex"],
                "presenter": reference["presenter"],
                "signature": reference["signature"],
            }));
            same(id, &evidence_statement(&record, index), &want);
        }
    }
    assert_eq!(all.len(), 9);
}

/// The `COSE_Sign1` bytes of each signed envelope, by the envelope's name in `cose-sign1.json`.
fn signatures() -> BTreeMap<String, Vec<u8>> {
    cases(&file(COSE), "cases")
        .into_iter()
        .filter_map(|c| {
            let name = c.get("envelope")?.as_str()?.to_owned();
            Some((name, bytes(&c["cose_hex"])))
        })
        .collect()
}

fn envelope_name(record: &Value, envelope: &Value) -> String {
    match envelope.get("id") {
        Some(id) => format!("records.json {}", id.as_str().unwrap()),
        None => format!(
            "records-quarantine.json {} envelope",
            record["id"].as_str().unwrap()
        ),
    }
}

// T-10 P-11 P-21 P-75 P-79 P-100 P-108 EV-35 T-37 T-95
#[test]
fn t_10_stored_entries_verify_from_their_bytes_through_bindings_core() {
    let sets = key_sets();
    let signed = signatures();
    let genesis = &file(GENESIS)["cases"][0];
    let mut at = json!({
        "ledger": digest(&genesis["ledger_id"]["digest_hex"]),
        "prev": digest(&genesis["leaf_hash"]),
    });
    let mut verified = 0;
    for (record, envelope) in records_and_envelopes() {
        let id = record["id"].as_str().unwrap();
        let cose = signed.get(&envelope_name(&record, &envelope));
        let author = &record["decoded"]["author"];
        let keys = keys_of(&sets, author);
        let got = verify_entry(
            &at.to_string(),
            &bytes(&envelope["hex"]),
            &bytes(&record["hex"]),
            cose.map(Vec::as_slice),
            &keys,
        );
        let e = &envelope["decoded"];
        let leaf = digest(&envelope["leaf_hash"]);
        let next = json!({ "ledger": e["ledger"], "prev": leaf });
        let unknown = record["expect"]["reason"] == "protocol_version_unknown";
        let want = if unknown && cose.is_none() {
            json!({ "outcome": "reject", "reason": "protocol_version_unknown" })
        } else {
            verified += 1;
            let binding = if cose.is_some() {
                "signature_valid"
            } else {
                "auth_context"
            };
            accept(json!({
                "record": e["record"],
                "author": author,
                "binding": binding,
                "ledger": e["ledger"],
                "position": e["pos"],
                "recorded_at": e["recorded_at"],
                "ingest": e["ingest"],
                "leaf": leaf,
                "next": next,
            }))
        };
        same(id, &got, &want);
        at = next;
    }
    assert_eq!(verified, 18);
}

fn leaves() -> Vec<Value> {
    let mut out = vec![file(GENESIS)["cases"][0]["hex"].clone()];
    out.extend(
        records_and_envelopes()
            .into_iter()
            .map(|(_, e)| e["hex"].clone()),
    );
    out
}

fn path(v: &Value) -> Value {
    Value::Array(v.as_array().unwrap().iter().map(digest).collect())
}

// T-4 P-11 P-100 P-101 T-88 T-37 T-95
#[test]
fn t_4_merkle_vectors_through_bindings_core() {
    let merkle = file(MERKLE);
    for node in cases(&merkle, "nodes") {
        let got = merkle_node_hash(
            &digest(&node["left_hex"]).to_string(),
            &digest(&node["right_hex"]).to_string(),
        );
        same(
            node["id"].as_str().unwrap(),
            &got,
            &found(&digest(&node["digest_hex"])),
        );
    }
    let leaves = leaves();
    for case in cases(&merkle, "roots") {
        let size = usize::try_from(case["size"].as_u64().unwrap()).unwrap();
        let got = merkle_root(&Value::from(leaves[..size].to_vec()).to_string());
        same(
            &format!("root {size}"),
            &got,
            &found(&digest(&case["root_hex"])),
        );
    }
    for case in cases(&merkle, "inclusion") {
        let proof = json!({
            "position": case["index"],
            "size": case["size"],
            "leaf": digest(&case["leaf_hash_hex"]),
            "path": path(&case["path_hex"]),
            "root": digest(&case["root_hex"]),
        });
        let got = verify_inclusion(&proof.to_string());
        same(case["id"].as_str().unwrap(), &got, &case["expect"]);
    }
    for case in cases(&merkle, "consistency") {
        let proof = json!({
            "first": case["first"],
            "second": case["second"],
            "first_root": digest(&case["first_root_hex"]),
            "second_root": digest(&case["second_root_hex"]),
            "path": path(&case["path_hex"]),
        });
        let got = verify_consistency(&proof.to_string());
        same(case["id"].as_str().unwrap(), &got, &case["expect"]);
    }
}

fn note_key(key: &Value) -> Value {
    json!({ "name": key["name"], "public_key": key["public_key_hex"] })
}

fn checkpoint(case: &Value, witnesses: bool) -> String {
    let keys = &file(MERKLE)["keys"];
    let witnesses: Vec<Value> = if witnesses {
        keys["witnesses"]
            .as_array()
            .unwrap()
            .iter()
            .map(note_key)
            .collect()
    } else {
        Vec::new()
    };
    json!({
        "note": case["note"],
        "origin": case["origin"],
        "log": note_key(&keys["log"]),
        "witnesses": witnesses,
    })
    .to_string()
}

// T-4 T-88 P-11 P-20 P-108 OP-33 OP-46 T-37 T-95
#[test]
fn t_88_checkpoint_vectors_through_bindings_core() {
    let merkle = file(MERKLE);
    let notes = cases(&merkle, "checkpoints");
    for case in &notes {
        let expect = &case["expect"];
        let want = if expect["outcome"] == "accept" {
            accept(json!({
                "size": expect["size"],
                "root": digest(&expect["root_hex"]),
                "profile": expect["profile"],
                "cosignatures": expect["cosignatures"],
            }))
        } else {
            expect.clone()
        };
        let got = verify_checkpoint(&checkpoint(case, true));
        same(case["id"].as_str().unwrap(), &got, &want);
    }
    let signed = checkpoint(&notes[0], true);
    let size = &notes[0]["expect"]["size"];
    let mut included = 0;
    for case in cases(&merkle, "inclusion") {
        if case["size"] != *size || case["expect"]["outcome"] != "accept" {
            continue;
        }
        let proof = json!({
            "position": case["index"],
            "leaf": digest(&case["leaf_hash_hex"]),
            "path": path(&case["path_hex"]),
        });
        let got = checkpoint_includes(&signed, &proof.to_string());
        same(
            case["id"].as_str().unwrap(),
            &got,
            &json!({ "outcome": "accept" }),
        );
        included += 1;
    }
    assert_eq!(included, 21);
    let older = checkpoint(&notes[0], false);
    same(
        "extends",
        &checkpoint_extends_to(&older, &signed, "[]"),
        &json!({ "outcome": "accept" }),
    );
}

fn record_hex(files: &[Value], id: &str) -> Vec<u8> {
    for f in files {
        let list = f.get("records").unwrap_or(&f["cases"]);
        if let Some(r) = list.as_array().unwrap().iter().find(|r| r["id"] == id) {
            return bytes(&r["hex"]);
        }
    }
    panic!("{id}");
}

// T-89 P-29 C-34 T-37 T-95
#[test]
fn t_89_touched_item_vectors_through_bindings_core() {
    let files = [file(RECORDS), file(QUARANTINE)];
    let all = cases(&file(ITEMS), "cases");
    for case in &all {
        let id = case["id"].as_str().unwrap();
        let want = accept(json!({ "touches": case["touches"] }));
        same(id, &touched(&record_hex(&files, id)), &want);
    }
    assert_eq!(all.len(), 17);
    for case in cases(&files[1], "cases") {
        if case["expect"]["reason"] == "protocol_version_unknown" {
            let id = case["id"].as_str().unwrap();
            same(id, &touched(&bytes(&case["hex"])), &case["expect"]);
        }
    }
}

// T-5 T-37 T-69 T-95
#[test]
fn t_5_t_37_byte_entry_points_answer_input_errors_without_deciding() {
    let error = |code: &str| json!({ "error": { "code": code } });
    same("tags", &check_cbor(&[0], "{"), &error("invalid_json"));
    same("tags", &check_cbor(&[0], "[-1]"), &error("invalid_tags"));
    let digests = cases(&file(DIGEST), "cases");
    let salted = digests.iter().find_map(|c| c.get("salt_hex")).unwrap();
    let salt = bytes(salted);
    let short = body_commitment(&salt[..31], "terms", "text/plain", &[]);
    same("salt", &short, &error("invalid_salt"));
    let named = body_commitment(&salt, "Terms", "text/plain", &[]);
    same("name", &named, &error("invalid_part_name"));
    same(
        "key",
        &check_public_key(-19, &[0; 31]),
        &error("invalid_key"),
    );
    same(
        "alg",
        &check_public_key(-1, &[0; 32]),
        &error("invalid_key"),
    );
    same(
        "keys",
        &verify_record_signature(&[], "{"),
        &error("invalid_json"),
    );
    same(
        "keys",
        &verify_record_signature(&[], "{}"),
        &error("invalid_keys"),
    );
    let bad = json!({ "party": "party:acme:alice", "allowed": [-19], "keys": [{ "kid": "00" }] });
    let indexed = json!({ "error": { "code": "invalid_keys", "index": 0 } });
    same(
        "keys",
        &verify_record_signature(&[], &bad.to_string()),
        &indexed,
    );
    let empty = json!({ "party": "party:acme:alice", "allowed": [], "keys": [] }).to_string();
    same(
        "at",
        &verify_entry("{}", &[], &[], None, &empty),
        &error("invalid_chain_point"),
    );
    same(
        "node",
        &merkle_node_hash("[]", "[]"),
        &error("invalid_digest"),
    );
    same("root", &merkle_root("[1]"), &error("invalid_envelopes"));
    same("inclusion", &verify_inclusion("{"), &error("invalid_json"));
    same(
        "inclusion",
        &verify_inclusion(r#"{"position":0}"#),
        &error("invalid_proof"),
    );
    same(
        "consistency",
        &verify_consistency("{}"),
        &error("invalid_proof"),
    );
    same(
        "checkpoint",
        &verify_checkpoint(r#"{"note":""}"#),
        &error("invalid_checkpoint"),
    );
    same(
        "extends",
        &checkpoint_extends_to("{}", "{}", "{"),
        &error("invalid_json"),
    );
    let sha256_of_nothing = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let empty_root = found(&json!([-16, sha256_of_nothing]));
    same("empty", &merkle_root("[]"), &empty_root);
}
