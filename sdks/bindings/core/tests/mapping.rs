//! The external standard mappings of the bindings' front end natively against `conformance/vectors/records/mapping.json`, which WebAssembly and Swift run through their bindings for the same bytes: each answer is the JSON the vector states, byte for byte (P-48, P-49, P-51, P-52, T-5, T-37).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::{Value, json};
use work_bindings_core::{decode_record_cbor, map_record};

const MAPPING: &str = include_str!("../../../../conformance/vectors/records/mapping.json");
const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");

fn file(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    let text = v.as_str().unwrap();
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn same(id: &str, got: &str, want: &Value) {
    assert_eq!(got, want.to_string(), "{id}");
}

// P-49 P-51 T-5 T-37
#[test]
fn p_49_p_51_mapping_vectors_through_bindings_core() {
    let mapping = file(MAPPING);
    let cases = mapping["cases"].as_array().unwrap();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let got = map_record(&bytes(&case["hex"]), &case["context"].to_string());
        same(id, &got, &case["expect"]);
    }
    assert_eq!(cases.len(), 25);
    for record in file(RECORDS)["records"].as_array().unwrap() {
        assert!(
            cases.iter().any(|c| c["id"] == record["id"]),
            "{}",
            record["id"]
        );
    }
}

// P-48 P-52
#[test]
fn p_52_export_documents_given_back_are_not_records() {
    let mapping = file(MAPPING);
    let reimport = mapping["reimport"].as_array().unwrap();
    for case in reimport {
        let id = case["id"].as_str().unwrap();
        let got = decode_record_cbor(&bytes(&case["hex"]));
        same(id, &got, &case["expect"]);
    }
    assert_eq!(reimport.len(), 2);
}

// P-49 EV-12 T-5
#[test]
fn p_49_a_context_that_does_not_fit_is_an_input_error() {
    let mapping = file(MAPPING);
    let promise = &mapping["cases"][0];
    let record = bytes(&promise["hex"]);
    let invalid_json = json!({ "error": { "code": "invalid_json" } });
    same("json", &map_record(&record, "{"), &invalid_json);
    let author = &promise["context"]["actor_type"]["author"];
    let contexts = [
        json!({}),
        json!({ "actor_type": { "author": author } }),
        json!({ "actor_type": { "author": author, "evidence": [] } }),
        json!({ "actor_type": { "author": author }, "withheld": [[-16, "00"]] }),
    ];
    let invalid = json!({ "error": { "code": "invalid_context" } });
    for context in contexts {
        let text = context.to_string();
        same(&text, &map_record(&record, &text), &invalid);
    }
}
