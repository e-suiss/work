//! The bindings' JSON front end natively against the record, rejection and quarantine vectors in `conformance/vectors/records` and the derivation fixture, which WebAssembly and Swift run through their bindings for the same bytes; the CBOR and digest vectors need the shared CBOR and crypto crates (P-8), so until then only their reason codes and digest encodings are checked here (T-5, T-37, INV-7, INV-8, X-24).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::{Value, json};
use work_bindings_core::{derive_records, validate_record};
use work_kernel::reason::Reason;

const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
const REJECTS: &str = include_str!("../../../../conformance/vectors/records/records-reject.json");
const QUARANTINE: &str =
    include_str!("../../../../conformance/vectors/records/records-quarantine.json");
const CBOR: &str = include_str!("../../../../conformance/vectors/records/cbor-canonical.json");
const DIGEST: &str = include_str!("../../../../conformance/vectors/records/digest.json");
const DIGEST_PREFIX: &str = "822f5820";
const DERIVE_INPUTS: &str = include_str!("fixtures/derive-inputs.json");
const DERIVE_EXPECTED: &str = include_str!("fixtures/derive-expected.json");

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

/// The accepted records with their chained envelopes, as ledger entries in order.
fn entries() -> String {
    let records: Value = serde_json::from_str(RECORDS).unwrap();
    let pairs = records["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(records["envelopes"].as_array().unwrap());
    let entries: Vec<Value> = pairs
        .map(|(r, e)| {
            let e = &e["decoded"];
            json!({
                "id": e["record"],
                "record": r["decoded"],
                "position": e["pos"],
                "recorded_at": e["recorded_at"],
                "ingest": e["ingest"],
                "restriction": "no_objection",
                "issuer": "local",
            })
        })
        .collect();
    Value::from(entries).to_string()
}

// T-5 T-37 T-69 INV-7 P-31
#[test]
fn t_5_t_37_inv_7_native_derivation_through_bindings_core() {
    assert_eq!(
        derive_records(&entries(), DERIVE_INPUTS),
        DERIVE_EXPECTED.trim_end()
    );
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
        r#"{"derivation":{"chains":[],"records":[]}}"#
    );
}

// T-5 T-37 T-69 P-31
#[test]
fn t_5_t_37_kernel_derivation_errors_cross_the_binding() {
    let mut entries: Vec<Value> = serde_json::from_str(&entries()).unwrap();
    entries[1]["position"] = json!(99);
    assert_eq!(
        derive_records(&Value::from(entries.clone()).to_string(), DERIVE_INPUTS),
        r#"{"error":{"code":"position_gap","position":99}}"#
    );
    entries[1]["position"] = json!(42);
    entries[1]["record"]["kind"] = json!("note");
    assert_eq!(
        derive_records(&Value::from(entries).to_string(), DERIVE_INPUTS),
        r#"{"error":{"code":"invalid_entry","index":1,"reason":"schema:kind"}}"#
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
