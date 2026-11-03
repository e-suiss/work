//! The version activation vectors in `conformance/vectors/records/activation.json` natively through the kernel (P-110, P-100, P-108): decoding selects the activation envelope by its key above position 0, the sequence rule is `check_activations`, and a stored activation verifies after the genesis with no record or signature step.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::fmt::Write as _;

use serde_json::{Value, json};
use work_kernel::activation::check_activations;
use work_kernel::codec::{leaf_hash, record_id};
use work_kernel::envelope::{Envelope, decode_envelope};
use work_kernel::id::{Digest, LedgerId};
use work_kernel::reason::{EnvelopeField, Reason, Signature};
use work_kernel::verify::{
    ChainPoint, SignatureCheck, SignatureVerifier, StoredEntry, Verified, verify_entry,
};

const ACTIVATION: &str = include_str!("../../../conformance/vectors/records/activation.json");

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex_of(v: &Value) -> Vec<u8> {
    hex(v.as_str().unwrap())
}

fn raw(v: &Value) -> Digest {
    Digest::sha256(hex_of(v).try_into().unwrap())
}

fn digest_of(v: &Value) -> Digest {
    raw(&v[1])
}

fn hex_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    for b in bytes {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

fn file() -> Value {
    serde_json::from_str(ACTIVATION).unwrap()
}

fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    let items = v[key].as_array().unwrap();
    assert!(!items.is_empty(), "{key}");
    items
}

fn rejected(reason: Reason) -> Value {
    json!({ "outcome": "reject", "reason": reason.to_string() })
}

fn point(v: &Value) -> ChainPoint {
    ChainPoint {
        ledger: LedgerId(digest_of(&v["ledger"])),
        prev: digest_of(&v["prev"]),
    }
}

struct NoSignature;

impl SignatureVerifier for NoSignature {
    fn check(&self, _cose_sign1: &[u8]) -> SignatureCheck {
        SignatureCheck::Rejected(Reason::Signature(Signature::KidUnknown))
    }
}

// P-110 P-100 P-11 P-21
#[test]
fn p_110_activation_envelopes_decode_by_their_key_above_position_0() {
    let v = file();
    for case in list(&v, "cases") {
        let id = case["id"].as_str().unwrap();
        let bytes = hex_of(&case["hex"]);
        match decode_envelope(&bytes) {
            Ok(Envelope::Activation(a)) => {
                assert_eq!(case["expect"]["outcome"], "accept", "{id}");
                assert_eq!(record_id(&bytes).0, raw(&case["entry_id"]));
                assert_eq!(leaf_hash(&bytes), raw(&case["leaf_hash"]));
                let decoded = &case["decoded"];
                assert_eq!(a.position, decoded["pos"].as_u64().unwrap(), "{id}");
                assert_eq!(
                    a.activation.schema,
                    digest_of(&decoded["activation"]["schema"])
                );
            }
            Ok(other) => panic!("{id}: {other:?}"),
            Err(reason) => assert_eq!(rejected(reason), case["expect"], "{id}"),
        }
    }
}

// P-110 P-87 OP-28
#[test]
fn p_110_activation_sequences_through_the_kernel() {
    let v = file();
    for case in list(&v, "sequences") {
        let id = case["id"].as_str().unwrap();
        let entries: Vec<Vec<u8>> = list(case, "entries").iter().map(hex_of).collect();
        let slices: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        let got = match check_activations(&slices) {
            Ok(found) => {
                let activations: Vec<Value> = found
                    .iter()
                    .map(|a| {
                        json!({
                            "position": a.position,
                            "protocol": [a.protocol.major, a.protocol.minor],
                            "schema": [-16, hex_text(a.schema.as_bytes())],
                        })
                    })
                    .collect();
                json!({ "outcome": "accept", "activations": activations })
            }
            Err(reason) => rejected(reason),
        };
        assert_eq!(got, case["expect"], "{id}");
    }
}

// P-110 P-108 T-10
#[test]
fn p_110_a_stored_activation_verifies_after_the_genesis_without_a_record_step() {
    let v = file();
    for case in list(&v, "verify") {
        let id = case["id"].as_str().unwrap();
        let envelope = hex_of(&case["envelope"]);
        let record = hex_of(&case["record"]);
        let entry = StoredEntry {
            envelope: &envelope,
            record: &record,
            cose_sign1: None,
        };
        let want = &case["expect"];
        match verify_entry(&NoSignature, &point(&case["at"]), &entry) {
            Ok(Verified::Activation(a)) => {
                assert_eq!(want["outcome"], "accept", "{id}");
                assert_eq!(a.id().0, digest_of(&want["record"]));
                assert_eq!(a.leaf(), digest_of(&want["leaf"]));
                assert_eq!(a.next(), point(&want["next"]));
                let at = want["recorded_at"].as_u64().unwrap();
                assert_eq!(a.envelope().recorded_at.0, at);
            }
            Ok(Verified::Record(_)) => panic!("{id}: record"),
            Err(reason) => assert_eq!(rejected(reason), *want, "{id}"),
        }
    }
    let accepted = &list(&v, "verify")[0];
    let envelope = hex_of(&accepted["envelope"]);
    let signed = StoredEntry {
        envelope: &envelope,
        record: &envelope,
        cose_sign1: Some(&envelope),
    };
    let at = point(&accepted["at"]);
    assert_eq!(
        verify_entry(&NoSignature, &at, &signed).map(|_| ()),
        Err(Reason::EnvelopeMismatch(EnvelopeField::ProofCommit))
    );
    assert!(ChainPoint::genesis(&envelope).is_err());
}
