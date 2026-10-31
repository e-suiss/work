//! The record rules against the shared record vectors in `conformance/vectors/records`: each case's deterministic CBOR `hex` through the kernel's decoder, and its `decoded` projection through the one JSON front end the bindings share, give the expected answer (P-5, P-11, T-5, T-37, T-69).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::Value;
use work_bindings_core::{validate_record, validate_record_cbor};
use work_kernel::reason::Reason;

const RECORDS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/records/records.json"
));
const REJECTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/records/records-reject.json"
));
const QUARANTINE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/records/records-quarantine.json"
));

fn check_all(cases: &[Value]) {
    assert_ne!(cases.len(), 0);
    for case in cases {
        let expect = &case["expect"];
        if let Some(code) = expect.get("reason") {
            let code = code.as_str().unwrap();
            assert!(
                Reason::from_code(code).is_some_and(|r| r.to_string() == code),
                "{}: {code} is not a kernel reason code",
                case["id"]
            );
        }
        let context = case["context"].to_string();
        let out = validate_record(&case["decoded"].to_string(), &context);
        assert_eq!(out, expect.to_string(), "{}", case["id"]);
        let bytes: Vec<u8> = case["hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(
            validate_record_cbor(&bytes, &context),
            out,
            "{}",
            case["id"]
        );
    }
}

// P-9 P-10 P-11 P-13 P-19 P-77 P-80 P-83 C-16 INV-20
#[test]
fn p_11_accepted_record_vectors() {
    let file: Value = serde_json::from_str(RECORDS).unwrap();
    check_all(file["records"].as_array().unwrap());
}

// P-19 P-69 P-87
#[test]
fn p_19_quarantine_record_vectors() {
    let file: Value = serde_json::from_str(QUARANTINE).unwrap();
    check_all(file["cases"].as_array().unwrap());
}

// P-5 P-13 P-14 P-33 P-69 P-70 P-72 P-77 P-78 P-80 P-81 P-83 C-5 C-26 C-27 INV-4 INV-20
#[test]
fn p_72_rejected_record_vectors() {
    let file: Value = serde_json::from_str(REJECTS).unwrap();
    check_all(file["cases"].as_array().unwrap());
}
