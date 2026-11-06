//! The `work/compromise-window/1` body against its vectors in `conformance/vectors/compromise-window` (SEC-36, WD-123): a valid case decodes and encodes back byte for byte, an invalid one is refused naming the member the vector names.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::Value;
use work_kernel::compromise::{Window, WindowError};

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/compromise-window/compromise-window.json"
));

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

// SEC-36
#[test]
fn sec_36_the_notice_body_matches_its_vectors() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["contract"], "work/compromise-window/1");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.iter().any(|c| c["valid"] == true));
    assert!(cases.iter().any(|c| c["valid"] == false));
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let bytes = unhex(case["cbor"].as_str().unwrap());
        let read = Window::decode(&bytes);
        if case["valid"] == true {
            let window = read.unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(window.encode().unwrap(), bytes, "{id}");
            assert!(window.holds(window.window_from), "{id}");
            assert!(window.holds(window.window_to), "{id}");
        } else {
            let refused = case["refused"].as_str().unwrap();
            let WindowError(member) = read.unwrap_err();
            assert_eq!(member, refused, "{id}");
        }
    }
}
