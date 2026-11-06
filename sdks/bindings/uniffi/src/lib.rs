//! uniffi binding of the Work kernel, proto and restriction engine for Swift and Kotlin (T-5, T-23): a thin mapping of the kernel API and of the `work-bindings-core` JSON front end, with no logic of its own.

#![forbid(unsafe_code)]
#![allow(
    clippy::needless_pass_by_value,
    reason = "uniffi passes byte strings as owned vectors"
)]

use core::cmp::Ordering;

use work_kernel::ApiVersion;
use work_kernel::policy_default::{
    ChangeOutcome, Direction, PolicyDefault, Stricter, SwitchBasis, SwitchOutcome,
};

uniffi::setup_scaffolding!();

#[uniffi::remote(Record)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}

#[uniffi::remote(Enum)]
pub enum Stricter {
    Higher,
    Lower,
}

#[uniffi::remote(Enum)]
pub enum Direction {
    TightenOnly(Stricter),
    ExtendOnly,
    Bounded,
}

#[uniffi::remote(Record)]
pub struct PolicyDefault {
    pub direction: Direction,
    pub min: u64,
    pub max: u64,
}

#[uniffi::remote(Enum)]
pub enum ChangeOutcome {
    Allowed,
    OutOfBounds,
    Loosens,
    Shortens,
}

#[uniffi::remote(Enum)]
pub enum SwitchBasis {
    RecordedDeclaration,
    Unrecorded,
}

#[uniffi::remote(Enum)]
pub enum SwitchOutcome {
    Allowed,
    RequiresRecordedDeclaration,
}

/// How one API version orders against another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum VersionOrder {
    /// The first version is older.
    Less,
    /// Both versions are the same.
    Equal,
    /// The first version is newer.
    Greater,
}

/// Kernel public API version.
#[uniffi::export]
#[must_use]
pub fn api_version() -> ApiVersion {
    work_kernel::API_VERSION
}

/// Orders API version `a` against `b`, major first.
#[uniffi::export]
#[must_use]
pub fn compare_api_versions(a: ApiVersion, b: ApiVersion) -> VersionOrder {
    match a.cmp(&b) {
        Ordering::Less => VersionOrder::Less,
        Ordering::Equal => VersionOrder::Equal,
        Ordering::Greater => VersionOrder::Greater,
    }
}

/// Evaluates moving `policy` from `current` to `proposed` (F-26).
#[uniffi::export]
#[must_use]
pub fn evaluate_policy_change(policy: PolicyDefault, current: u64, proposed: u64) -> ChangeOutcome {
    policy.evaluate(current, proposed)
}

/// Evaluates turning a security switch from `current` to `proposed` (`true` is on; F-26).
#[uniffi::export]
#[must_use]
pub fn evaluate_security_switch(
    current: bool,
    proposed: bool,
    basis: SwitchBasis,
) -> SwitchOutcome {
    work_kernel::policy_default::evaluate_security_switch(current, proposed, basis)
}

/// Validates one record given as its `decoded` JSON projection against a verifier context in the vector `context` shape;
/// returns `{"outcome", "reason"?}` or `{"error": {"code"}}` as JSON text (P-11, P-19).
#[uniffi::export]
#[must_use]
pub fn validate_record(decoded: &str, context: &str) -> String {
    work_bindings_core::validate_record(decoded, context)
}

/// Folds ledger entries into the derived view under the given inputs;
/// returns `{"derivation": …}` or `{"error": {"code", …}}` as JSON text (P-31, T-6).
#[uniffi::export]
#[must_use]
pub fn derive_records(entries: &str, inputs: &str) -> String {
    work_bindings_core::derive_records(entries, inputs)
}

/// Validates one record given as its deterministic CBOR `SignedRecord` bytes against a verifier context in the vector `context` shape;
/// returns `{"outcome", "reason"?}` or `{"error": {"code"}}` as JSON text (P-5, P-11, T-69).
#[uniffi::export]
#[must_use]
pub fn validate_record_cbor(record: Vec<u8>, context: &str) -> String {
    work_bindings_core::validate_record_cbor(&record, context)
}

/// Decodes `SignedRecord` bytes; returns `{"outcome", "decoded"?, "reason"?}` as JSON text (P-5, P-87).
#[uniffi::export]
#[must_use]
pub fn decode_record(record: Vec<u8>) -> String {
    work_bindings_core::decode_record_cbor(&record)
}

/// Decodes genesis or ledger envelope bytes; returns `{"outcome", "decoded"?, "reason"?}` as JSON text (P-11, P-100).
#[uniffi::export]
#[must_use]
pub fn decode_envelope(envelope: Vec<u8>) -> String {
    work_bindings_core::decode_envelope(&envelope)
}

/// Decodes one deterministic CBOR item allowing only the tags in the JSON array `tags`;
/// returns `{"outcome", "reason"?}` or `{"error": {"code"}}` as JSON text (P-5, P-7).
#[uniffi::export]
#[must_use]
pub fn check_cbor(bytes: Vec<u8>, tags: &str) -> String {
    work_bindings_core::check_cbor(&bytes, tags)
}

/// Parses tagged `COSE_Sign1` framing; returns `{"outcome", "reason"?}` as JSON text (P-6).
#[uniffi::export]
#[must_use]
pub fn parse_cose_container(bytes: Vec<u8>) -> String {
    work_bindings_core::parse_cose_container(&bytes)
}

/// Decodes the CBOR bytes of one digest; returns `{"outcome", "digest"?, "reason"?}` as JSON text (P-67).
#[uniffi::export]
#[must_use]
pub fn decode_digest(bytes: Vec<u8>) -> String {
    work_bindings_core::decode_digest(&bytes)
}

/// The record identifier of `SignedRecord` bytes; returns `{"digest"}` as JSON text (P-79).
#[uniffi::export]
#[must_use]
pub fn record_id(record: Vec<u8>) -> String {
    work_bindings_core::record_id(&record)
}

/// The `LedgerID` of genesis bytes; returns `{"digest"}` as JSON text (P-100).
#[uniffi::export]
#[must_use]
pub fn ledger_id(genesis: Vec<u8>) -> String {
    work_bindings_core::ledger_id(&genesis)
}

/// The RFC 9162 leaf hash of envelope bytes; returns `{"digest"}` as JSON text (P-101).
#[uniffi::export]
#[must_use]
pub fn leaf_hash(envelope: Vec<u8>) -> String {
    work_bindings_core::leaf_hash(&envelope)
}

/// The `proof_commit` of `COSE_Sign1` bytes; returns `{"digest"}` as JSON text (P-75).
#[uniffi::export]
#[must_use]
pub fn proof_commit(cose_sign1: Vec<u8>) -> String {
    work_bindings_core::proof_commit(&cose_sign1)
}

/// The salted commitment of one body part;
/// returns `{"outcome", "digest"?, "reason"?}` or `{"error": {"code"}}` as JSON text (P-68, P-104).
#[uniffi::export]
#[must_use]
pub fn body_commitment(salt: Vec<u8>, name: &str, media_type: &str, content: Vec<u8>) -> String {
    work_bindings_core::body_commitment(&salt, name, media_type, &content)
}

/// Checks one public key with COSE algorithm `alg`;
/// returns `{"outcome", "reason"?}` or `{"error": {"code"}}` as JSON text (P-7).
#[uniffi::export]
#[must_use]
pub fn check_public_key(alg: i64, public_key: Vec<u8>) -> String {
    work_bindings_core::check_public_key(alg, &public_key)
}

/// Verifies a record's `COSE_Sign1` bytes against its author's keys;
/// returns `{"outcome", "record"?, "author"?, "reason"?}` or `{"error": …}` as JSON text (P-6, P-105).
#[uniffi::export]
#[must_use]
pub fn verify_record_signature(cose_sign1: Vec<u8>, author_keys: &str) -> String {
    work_bindings_core::verify_record_signature(&cose_sign1, author_keys)
}

/// The `EvidenceStatement` of evidence reference `index`;
/// returns `{"outcome", "statement"?, "presenter"?, "signature"?, "reason"?}` as JSON text (EV-3).
#[uniffi::export]
#[must_use]
pub fn evidence_statement(record: Vec<u8>, index: u32) -> String {
    work_bindings_core::evidence_statement(&record, index)
}

/// Verifies a presenter's `COSE_Sign1` bytes for evidence reference `index`;
/// returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (EV-3, EV-8).
#[uniffi::export]
#[must_use]
pub fn verify_evidence_signature(
    record: Vec<u8>,
    index: u32,
    cose_sign1: Vec<u8>,
    presenter_keys: &str,
) -> String {
    work_bindings_core::verify_evidence_signature(&record, index, &cose_sign1, presenter_keys)
}

/// The chain point after genesis bytes; returns `{"outcome", "ledger"?, "prev"?, "reason"?}` as JSON text (P-100).
#[uniffi::export]
#[must_use]
pub fn genesis_chain_point(genesis: Vec<u8>) -> String {
    work_bindings_core::genesis_chain_point(&genesis)
}

/// Verifies one stored ledger entry after the chain point `at` from its bytes;
/// returns the verification, `{"outcome": "reject", "reason"}` or `{"error": …}` as JSON text (T-10, P-108).
#[uniffi::export]
#[must_use]
pub fn verify_entry(
    at: &str,
    envelope: Vec<u8>,
    record: Vec<u8>,
    cose_sign1: Option<Vec<u8>>,
    author_keys: &str,
) -> String {
    work_bindings_core::verify_entry(at, &envelope, &record, cose_sign1.as_deref(), author_keys)
}

/// The RFC 9162 node hash of two digests; returns `{"digest"}` or `{"error": …}` as JSON text (P-101).
#[uniffi::export]
#[must_use]
pub fn merkle_node_hash(left: &str, right: &str) -> String {
    work_bindings_core::merkle_node_hash(left, right)
}

/// Checks a ledger's activation entries, given as a JSON array of envelope hex strings in log
/// order with the genesis first; returns `{"outcome", "activations"?, "reason"?}` or
/// `{"error": …}` as JSON text (P-110).
#[uniffi::export]
#[must_use]
pub fn check_activations(entries: &str) -> String {
    work_bindings_core::check_activations(entries)
}

/// The RFC 9162 root over envelope bytes given as a JSON array of hex strings;
/// returns `{"digest"}` or `{"error": …}` as JSON text (P-101).
#[uniffi::export]
#[must_use]
pub fn merkle_root(envelopes: &str) -> String {
    work_bindings_core::merkle_root(envelopes)
}

/// Verifies an inclusion proof; returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (T-4, T-88).
#[uniffi::export]
#[must_use]
pub fn verify_inclusion(inclusion: &str) -> String {
    work_bindings_core::verify_inclusion(inclusion)
}

/// Verifies a consistency proof; returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (T-4, T-88).
#[uniffi::export]
#[must_use]
pub fn verify_consistency(consistency: &str) -> String {
    work_bindings_core::verify_consistency(consistency)
}

/// Verifies a signed checkpoint note and its witness cosignatures;
/// returns `{"outcome", "size"?, "root"?, "profile"?, "cosignatures"?, "reason"?}` or `{"error": …}` as JSON text (T-88, OP-46).
#[uniffi::export]
#[must_use]
pub fn verify_checkpoint(checkpoint: &str) -> String {
    work_bindings_core::verify_checkpoint(checkpoint)
}

/// Verifies that an envelope leaf is in a verified checkpoint's tree;
/// returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (T-88, P-108).
#[uniffi::export]
#[must_use]
pub fn checkpoint_includes(checkpoint: &str, inclusion: &str) -> String {
    work_bindings_core::checkpoint_includes(checkpoint, inclusion)
}

/// Verifies that a verified checkpoint's tree is a prefix of a newer one's;
/// returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (T-88).
#[uniffi::export]
#[must_use]
pub fn checkpoint_extends_to(older: &str, newer: &str, path: &str) -> String {
    work_bindings_core::checkpoint_extends_to(older, newer, path)
}

/// The work items a record's bytes touch; returns `{"outcome", "touches"?, "reason"?}` as JSON text (T-89).
#[uniffi::export]
#[must_use]
pub fn touched(record: Vec<u8>) -> String {
    work_bindings_core::touched(&record)
}

/// The PROV-JSON document and Activity Streams 2.0 activity of a record's bytes under a mapping context;
/// returns `{"outcome", "prov"?, "as2"?, "reason"?}` or `{"error": …}` as JSON text (P-49, P-51).
#[uniffi::export]
#[must_use]
pub fn map_record(record: Vec<u8>, context: &str) -> String {
    work_bindings_core::map_record(&record, context)
}

/// One restriction rule set evaluated against one request by the shared engine; returns
/// `{"outcome", "requirements"?, "policies"?, "attention"?, "explanation"?}` or `{"error": …}` as
/// JSON text, `explanation` in the format shared with Access (T-23, PR-11, PR-17, PR-23).
#[uniffi::export]
#[must_use]
pub fn evaluate_restriction(rule_set: &str, request: &str) -> String {
    work_bindings_core::evaluate_restriction(rule_set, request)
}
