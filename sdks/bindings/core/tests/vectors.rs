//! The bindings' front ends natively against the record, rejection and quarantine vectors in `conformance/vectors/records` and the derivation golden vector in `conformance/vectors/kernel`, which WebAssembly and Swift run through their bindings for the same bytes: the CBOR entry point on each case's `hex` and the JSON entry point on its `decoded` projection give the expected answer byte for byte (T-5, T-37, T-69, INV-7, INV-8, X-24); the byte entry points run the other record format vectors in `bytes.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::{Value, json};
use work_bindings_core::{derive_records, record_id, validate_record, validate_record_cbor};
use work_kernel::reason::Reason;

const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
const REJECTS: &str = include_str!("../../../../conformance/vectors/records/records-reject.json");
const QUARANTINE: &str =
    include_str!("../../../../conformance/vectors/records/records-quarantine.json");
const CBOR: &str = include_str!("../../../../conformance/vectors/records/cbor-canonical.json");
const DIGEST: &str = include_str!("../../../../conformance/vectors/records/digest.json");
const DIGEST_PREFIX: &str = "822f5820";
const DERIVE_ENTRIES: &str =
    include_str!("../../../../conformance/vectors/records/derive-entries.json");
const DERIVE_INPUTS: &str =
    include_str!("../../../../conformance/vectors/kernel/derive-inputs.json");
const DERIVE_EXPECTED: &str =
    include_str!("../../../../conformance/vectors/kernel/derive-expected.json");

fn cases() -> Vec<Value> {
    let mut all = Vec::new();
    for (text, key) in [
        (RECORDS, "records"),
        (REJECTS, "cases"),
        (QUARANTINE, "cases"),
    ] {
        let file: Value = serde_json::from_str(text).unwrap();
        all.extend(file[key].as_array().unwrap().iter().cloned());
    }
    all
}

// T-5 T-37 T-69 INV-7 INV-8 X-24 P-11 P-19 P-72
#[test]
fn t_5_t_37_inv_7_native_record_vectors_through_bindings_core() {
    let cases = cases();
    for outcome in ["accept", "quarantine", "reject"] {
        assert!(cases.iter().any(|c| c["expect"]["outcome"] == outcome));
    }
    for case in &cases {
        let out = validate_record(&case["decoded"].to_string(), &case["context"].to_string());
        assert_eq!(out, case["expect"].to_string(), "{}", case["id"]);
    }
}

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// T-69 P-5 T-37 INV-7
#[test]
fn t_69_cbor_entry_point_answers_like_the_json_projection() {
    let cases = cases();
    for case in &cases {
        let context = case["context"].to_string();
        let out = validate_record_cbor(&hex(case["hex"].as_str().unwrap()), &context);
        assert_eq!(out, case["expect"].to_string(), "{}", case["id"]);
        assert_eq!(
            out,
            validate_record(&case["decoded"].to_string(), &context),
            "{}",
            case["id"]
        );
    }
    let context = cases[0]["context"].to_string();
    assert_eq!(
        validate_record_cbor(&[0xa0, 0x00], &context),
        r#"{"outcome":"reject","reason":"malformed_cbor:trailing_bytes"}"#
    );
    assert_eq!(
        validate_record_cbor(&[0xa0], "{"),
        r#"{"error":{"code":"invalid_json"}}"#
    );
}

/// The accepted records of `records.json` as stored entries chained from the genesis.
fn entries() -> Value {
    serde_json::from_str(DERIVE_ENTRIES).unwrap()
}

// T-5 T-37 T-69 INV-7 P-31
#[test]
fn t_5_t_37_inv_7_native_derivation_through_bindings_core() {
    let derived = derive_records(DERIVE_ENTRIES, DERIVE_INPUTS);
    if std::env::var_os("WORK_WRITE_GENERATED").is_some() {
        std::fs::write(
            "../../../conformance/vectors/kernel/derive-expected.json",
            format!("{derived}\n"),
        )
        .unwrap();
        return;
    }
    assert_eq!(
        derived,
        DERIVE_EXPECTED.trim_end(),
        "conformance/vectors/kernel/derive-expected.json is stale: WORK_WRITE_GENERATED=1 cargo test -p work-bindings-core --test vectors"
    );
}

// T-10 T-4 P-79 T-95 T-37
#[test]
fn t_10_derivation_takes_record_ids_from_the_stored_bytes_through_bindings_core() {
    let text = derive_records(DERIVE_ENTRIES, DERIVE_INPUTS);
    let derived: Value = serde_json::from_str(&text).unwrap();
    let ids: Vec<Value> = derived["derivation"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].clone())
        .collect();
    let stored = entries();
    let from_bytes: Vec<Value> = stored["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let bytes = hex(e["record"].as_str().unwrap());
            let digest: Value = serde_json::from_str(&record_id(&bytes)).unwrap();
            digest["digest"].clone()
        })
        .collect();
    assert_eq!(ids.len(), 11);
    assert_eq!(ids, from_bytes);
}

// T-5 T-37 T-69
#[test]
fn t_5_t_37_input_errors_are_not_decisions() {
    let context = r#"{"origin":"direct","actor_type":{"author":["human","access_binding"]},"understood_extensions":[]}"#;
    assert_eq!(
        validate_record("{", context),
        r#"{"error":{"code":"invalid_json"}}"#
    );
    assert_eq!(
        validate_record("{}", r#"{"origin":"elsewhere"}"#),
        r#"{"error":{"code":"invalid_context"}}"#
    );
    assert_eq!(
        validate_record("[]", context),
        r#"{"outcome":"reject","reason":"schema:required_field"}"#
    );
    assert_eq!(
        derive_records("[]", "{}"),
        r#"{"error":{"code":"invalid_inputs"}}"#
    );
    assert_eq!(
        derive_records("[]", DERIVE_INPUTS),
        r#"{"error":{"code":"invalid_entries"}}"#
    );
    let empty = json!({ "at": entries()["at"], "entries": [] }).to_string();
    assert_eq!(
        derive_records(&empty, DERIVE_INPUTS),
        r#"{"derivation":{"chains":[],"records":[]}}"#
    );
    let nowhere = json!({ "at": {}, "entries": [] }).to_string();
    assert_eq!(
        derive_records(&nowhere, DERIVE_INPUTS),
        r#"{"error":{"code":"invalid_chain_point"}}"#
    );
}

// T-5 T-10 T-37 T-69 P-31 P-11
#[test]
fn t_5_t_10_entries_that_do_not_verify_cross_the_binding_as_input_errors() {
    let mut dropped = entries();
    dropped["entries"].as_array_mut().unwrap().remove(1);
    assert_eq!(
        derive_records(&dropped.to_string(), DERIVE_INPUTS),
        r#"{"error":{"code":"invalid_entry","index":1,"reason":"envelope_mismatch:prev"}}"#
    );
    let mut changed = entries();
    let mut record = changed["entries"][1]["record"].as_str().unwrap().to_owned();
    let last = record.pop().unwrap();
    record.push(if last == '0' { '1' } else { '0' });
    changed["entries"][1]["record"] = json!(record);
    assert_eq!(
        derive_records(&changed.to_string(), DERIVE_INPUTS),
        r#"{"error":{"code":"invalid_entry","index":1,"reason":"envelope_mismatch:record"}}"#
    );
    let mut unshaped = entries();
    unshaped["entries"][0]["position"] = json!(1);
    assert_eq!(
        derive_records(&unshaped.to_string(), DERIVE_INPUTS),
        r#"{"error":{"code":"invalid_entry","index":0}}"#
    );
}

fn all_cases() -> Vec<Value> {
    let mut all = cases();
    for text in [CBOR, DIGEST] {
        let file: Value = serde_json::from_str(text).unwrap();
        all.extend(file["cases"].as_array().unwrap().iter().cloned());
    }
    all
}

// P-11 P-5 T-37
#[test]
fn p_11_every_vector_reason_is_a_kernel_code_and_every_id_is_unique() {
    let cases = all_cases();
    let mut ids: Vec<&str> = cases.iter().map(|c| c["id"].as_str().unwrap()).collect();
    ids.sort_unstable();
    assert!(ids.windows(2).all(|w| w[0] != w[1]));
    for case in &cases {
        if let Some(code) = case["expect"].get("reason") {
            let code = code.as_str().unwrap();
            assert!(
                Reason::from_code(code).is_some_and(|r| r.to_string() == code),
                "{}: {code}",
                case["id"]
            );
        }
    }
}

// P-5 P-67 P-79 Access CR-1
#[test]
fn p_67_digests_are_encoded_as_the_sha_256_label_and_32_bytes() {
    let digest: Value = serde_json::from_str(DIGEST).unwrap();
    let mut checked = 0;
    for case in digest["cases"].as_array().unwrap() {
        if let (Some(encoded), Some(value)) =
            (case.get("encoded_digest_hex"), case.get("digest_hex"))
        {
            assert_eq!(
                encoded.as_str().unwrap(),
                format!("{DIGEST_PREFIX}{}", value.as_str().unwrap()),
                "{}",
                case["id"]
            );
            checked += 1;
        }
    }
    let records: Value = serde_json::from_str(RECORDS).unwrap();
    let quarantine: Value = serde_json::from_str(QUARANTINE).unwrap();
    let with_digest = records["records"]
        .as_array()
        .unwrap()
        .iter()
        .chain(quarantine["cases"].as_array().unwrap());
    let envelopes = records["envelopes"].as_array().unwrap().iter().chain(
        quarantine["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| &c["envelope"]),
    );
    for (record, envelope) in with_digest.zip(envelopes) {
        let id = &envelope["decoded"]["record"];
        assert_eq!(id[0], json!(-16));
        assert_eq!(
            record["record_digest"].as_str().unwrap(),
            format!("{DIGEST_PREFIX}{}", id[1].as_str().unwrap()),
            "{}",
            record["id"]
        );
        checked += 1;
    }
    assert!(checked > 2);
}
