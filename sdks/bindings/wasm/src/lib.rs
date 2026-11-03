//! WebAssembly binding of the Work kernel (T-5): a thin mapping of the kernel API and of the `work-bindings-core` JSON front end to JavaScript, with no logic of its own.

#![forbid(unsafe_code)]

use core::cmp::Ordering;
use core::fmt::Write as _;

use wasm_bindgen::prelude::wasm_bindgen;
use work_kernel::ApiVersion;
use work_kernel::policy_default as kernel;

pub use js::{ChangeOutcome, PolicyDirection, SwitchBasis, SwitchOutcome, VersionOrder};

#[allow(
    missing_docs,
    reason = "wasm-bindgen adds undocumented hidden items to string enums"
)]
mod js {
    use wasm_bindgen::prelude::wasm_bindgen;

    /// How one API version orders against another.
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum VersionOrder {
        /// The first version is older.
        Less = "less",
        /// Both versions are the same.
        Equal = "equal",
        /// The first version is newer.
        Greater = "greater",
    }

    /// The kind of a numeric policy default and its permitted direction of change (F-26).
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PolicyDirection {
        /// Security value where a larger value is stricter.
        TightenOnlyHigher = "tighten_only_higher",
        /// Security value where a smaller value is stricter.
        TightenOnlyLower = "tighten_only_lower",
        /// Retention period.
        ExtendOnly = "extend_only",
        /// Operational value.
        Bounded = "bounded",
    }

    /// Outcome of a proposed policy default change (F-26).
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ChangeOutcome {
        /// The change is permitted.
        Allowed = "allowed",
        /// The proposed value is outside the declared bounds.
        OutOfBounds = "out_of_bounds",
        /// The change loosens a security or accountability value.
        Loosens = "loosens",
        /// The change shortens a retention period.
        Shortens = "shortens",
    }

    /// What backs a request to turn off a security default (F-26).
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SwitchBasis {
        /// An explicit, recorded and attributable declaration.
        RecordedDeclaration = "recorded_declaration",
        /// A setting, an import or an implicit default.
        Unrecorded = "unrecorded",
    }

    /// Outcome of changing a security switch (F-26).
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SwitchOutcome {
        /// The change is permitted.
        Allowed = "allowed",
        /// Turning the switch off needs a recorded declaration.
        RequiresRecordedDeclaration = "requires_recorded_declaration",
    }
}

/// Kernel public API version as `"major.minor"`.
#[wasm_bindgen(js_name = apiVersion)]
#[must_use]
pub fn api_version() -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{}.{}",
        work_kernel::API_VERSION.major,
        work_kernel::API_VERSION.minor
    );
    out
}

/// Orders API version `a` against `b`, major first.
#[wasm_bindgen(js_name = compareApiVersions)]
#[must_use]
pub fn compare_api_versions(
    a_major: u16,
    a_minor: u16,
    b_major: u16,
    b_minor: u16,
) -> VersionOrder {
    let a = ApiVersion {
        major: a_major,
        minor: a_minor,
    };
    let b = ApiVersion {
        major: b_major,
        minor: b_minor,
    };
    match a.cmp(&b) {
        Ordering::Less => VersionOrder::Less,
        Ordering::Equal => VersionOrder::Equal,
        Ordering::Greater => VersionOrder::Greater,
    }
}

/// Evaluates moving a policy default from `current` to `proposed` inside `[min, max]` (F-26);
/// `undefined` when `direction` is not one of the declared values.
#[wasm_bindgen(js_name = evaluatePolicyChange)]
#[must_use]
pub fn evaluate_policy_change(
    direction: PolicyDirection,
    min: u64,
    max: u64,
    current: u64,
    proposed: u64,
) -> Option<ChangeOutcome> {
    let direction = match direction {
        PolicyDirection::TightenOnlyHigher => {
            kernel::Direction::TightenOnly(kernel::Stricter::Higher)
        }
        PolicyDirection::TightenOnlyLower => {
            kernel::Direction::TightenOnly(kernel::Stricter::Lower)
        }
        PolicyDirection::ExtendOnly => kernel::Direction::ExtendOnly,
        PolicyDirection::Bounded => kernel::Direction::Bounded,
        PolicyDirection::__Invalid => return None,
    };
    let policy = kernel::PolicyDefault {
        direction,
        min,
        max,
    };
    Some(match policy.evaluate(current, proposed) {
        kernel::ChangeOutcome::Allowed => ChangeOutcome::Allowed,
        kernel::ChangeOutcome::OutOfBounds => ChangeOutcome::OutOfBounds,
        kernel::ChangeOutcome::Loosens => ChangeOutcome::Loosens,
        kernel::ChangeOutcome::Shortens => ChangeOutcome::Shortens,
    })
}

/// Evaluates turning a security switch from `current` to `proposed` (`true` is on);
/// `undefined` when `basis` is not one of the declared values.
#[wasm_bindgen(js_name = evaluateSecuritySwitch)]
#[must_use]
pub fn evaluate_security_switch(
    current: bool,
    proposed: bool,
    basis: SwitchBasis,
) -> Option<SwitchOutcome> {
    let basis = match basis {
        SwitchBasis::RecordedDeclaration => kernel::SwitchBasis::RecordedDeclaration,
        SwitchBasis::Unrecorded => kernel::SwitchBasis::Unrecorded,
        SwitchBasis::__Invalid => return None,
    };
    Some(
        match kernel::evaluate_security_switch(current, proposed, basis) {
            kernel::SwitchOutcome::Allowed => SwitchOutcome::Allowed,
            kernel::SwitchOutcome::RequiresRecordedDeclaration => {
                SwitchOutcome::RequiresRecordedDeclaration
            }
        },
    )
}

/// Validates one record given as its `decoded` JSON projection against a verifier context in the vector `context` shape;
/// returns `{"outcome", "reason"?}` or `{"error": {"code"}}` as JSON text (P-11, P-19).
#[wasm_bindgen(js_name = validateRecord)]
#[must_use]
pub fn validate_record(decoded: &str, context: &str) -> String {
    work_bindings_core::validate_record(decoded, context)
}

/// Folds ledger entries into the derived view under the given inputs;
/// returns `{"derivation": …}` or `{"error": {"code", …}}` as JSON text (P-31, T-6).
#[wasm_bindgen(js_name = deriveRecords)]
#[must_use]
pub fn derive_records(entries: &str, inputs: &str) -> String {
    work_bindings_core::derive_records(entries, inputs)
}

/// Validates one record given as its deterministic CBOR `SignedRecord` bytes against a verifier context in the vector `context` shape;
/// returns `{"outcome", "reason"?}` or `{"error": {"code"}}` as JSON text (P-5, P-11, T-69).
#[wasm_bindgen(js_name = validateRecordCbor)]
#[must_use]
pub fn validate_record_cbor(record: &[u8], context: &str) -> String {
    work_bindings_core::validate_record_cbor(record, context)
}

/// Decodes `SignedRecord` bytes; returns `{"outcome", "decoded"?, "reason"?}` as JSON text (P-5, P-87).
#[wasm_bindgen(js_name = decodeRecord)]
#[must_use]
pub fn decode_record(record: &[u8]) -> String {
    work_bindings_core::decode_record_cbor(record)
}

/// Decodes genesis or ledger envelope bytes; returns `{"outcome", "decoded"?, "reason"?}` as JSON text (P-11, P-100).
#[wasm_bindgen(js_name = decodeEnvelope)]
#[must_use]
pub fn decode_envelope(envelope: &[u8]) -> String {
    work_bindings_core::decode_envelope(envelope)
}

/// Decodes one deterministic CBOR item allowing only the tags in the JSON array `tags`;
/// returns `{"outcome", "reason"?}` or `{"error": {"code"}}` as JSON text (P-5, P-7).
#[wasm_bindgen(js_name = checkCbor)]
#[must_use]
pub fn check_cbor(bytes: &[u8], tags: &str) -> String {
    work_bindings_core::check_cbor(bytes, tags)
}

/// Parses tagged `COSE_Sign1` framing; returns `{"outcome", "reason"?}` as JSON text (P-6).
#[wasm_bindgen(js_name = parseCoseContainer)]
#[must_use]
pub fn parse_cose_container(bytes: &[u8]) -> String {
    work_bindings_core::parse_cose_container(bytes)
}

/// Decodes the CBOR bytes of one digest; returns `{"outcome", "digest"?, "reason"?}` as JSON text (P-67).
#[wasm_bindgen(js_name = decodeDigest)]
#[must_use]
pub fn decode_digest(bytes: &[u8]) -> String {
    work_bindings_core::decode_digest(bytes)
}

/// The record identifier of `SignedRecord` bytes; returns `{"digest"}` as JSON text (P-79).
#[wasm_bindgen(js_name = recordId)]
#[must_use]
pub fn record_id(record: &[u8]) -> String {
    work_bindings_core::record_id(record)
}

/// The `LedgerID` of genesis bytes; returns `{"digest"}` as JSON text (P-100).
#[wasm_bindgen(js_name = ledgerId)]
#[must_use]
pub fn ledger_id(genesis: &[u8]) -> String {
    work_bindings_core::ledger_id(genesis)
}

/// The RFC 9162 leaf hash of envelope bytes; returns `{"digest"}` as JSON text (P-101).
#[wasm_bindgen(js_name = leafHash)]
#[must_use]
pub fn leaf_hash(envelope: &[u8]) -> String {
    work_bindings_core::leaf_hash(envelope)
}

/// The `proof_commit` of `COSE_Sign1` bytes; returns `{"digest"}` as JSON text (P-75).
#[wasm_bindgen(js_name = proofCommit)]
#[must_use]
pub fn proof_commit(cose_sign1: &[u8]) -> String {
    work_bindings_core::proof_commit(cose_sign1)
}

/// The salted commitment of one body part;
/// returns `{"outcome", "digest"?, "reason"?}` or `{"error": {"code"}}` as JSON text (P-68, P-104).
#[wasm_bindgen(js_name = bodyCommitment)]
#[must_use]
pub fn body_commitment(salt: &[u8], name: &str, media_type: &str, content: &[u8]) -> String {
    work_bindings_core::body_commitment(salt, name, media_type, content)
}

/// Checks one public key with COSE algorithm `alg`;
/// returns `{"outcome", "reason"?}` or `{"error": {"code"}}` as JSON text (P-7).
#[wasm_bindgen(js_name = checkPublicKey)]
#[must_use]
pub fn check_public_key(alg: i32, public_key: &[u8]) -> String {
    work_bindings_core::check_public_key(i64::from(alg), public_key)
}

/// Verifies a record's `COSE_Sign1` bytes against its author's keys;
/// returns `{"outcome", "record"?, "author"?, "reason"?}` or `{"error": …}` as JSON text (P-6, P-105).
#[wasm_bindgen(js_name = verifyRecordSignature)]
#[must_use]
pub fn verify_record_signature(cose_sign1: &[u8], author_keys: &str) -> String {
    work_bindings_core::verify_record_signature(cose_sign1, author_keys)
}

/// The `EvidenceStatement` of evidence reference `index`;
/// returns `{"outcome", "statement"?, "presenter"?, "signature"?, "reason"?}` as JSON text (EV-3).
#[wasm_bindgen(js_name = evidenceStatement)]
#[must_use]
pub fn evidence_statement(record: &[u8], index: u32) -> String {
    work_bindings_core::evidence_statement(record, index)
}

/// Verifies a presenter's `COSE_Sign1` bytes for evidence reference `index`;
/// returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (EV-3, EV-8).
#[wasm_bindgen(js_name = verifyEvidenceSignature)]
#[must_use]
pub fn verify_evidence_signature(
    record: &[u8],
    index: u32,
    cose_sign1: &[u8],
    presenter_keys: &str,
) -> String {
    work_bindings_core::verify_evidence_signature(record, index, cose_sign1, presenter_keys)
}

/// The chain point after genesis bytes; returns `{"outcome", "ledger"?, "prev"?, "reason"?}` as JSON text (P-100).
#[wasm_bindgen(js_name = genesisChainPoint)]
#[must_use]
pub fn genesis_chain_point(genesis: &[u8]) -> String {
    work_bindings_core::genesis_chain_point(genesis)
}

/// Verifies one stored ledger entry after the chain point `at` from its bytes;
/// returns the verification, `{"outcome": "reject", "reason"}` or `{"error": …}` as JSON text (T-10, P-108).
#[wasm_bindgen(js_name = verifyEntry)]
#[must_use]
#[allow(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen passes an optional byte string as an owned vector"
)]
pub fn verify_entry(
    at: &str,
    envelope: &[u8],
    record: &[u8],
    cose_sign1: Option<Vec<u8>>,
    author_keys: &str,
) -> String {
    work_bindings_core::verify_entry(at, envelope, record, cose_sign1.as_deref(), author_keys)
}

/// The RFC 9162 node hash of two digests; returns `{"digest"}` or `{"error": …}` as JSON text (P-101).
#[wasm_bindgen(js_name = merkleNodeHash)]
#[must_use]
pub fn merkle_node_hash(left: &str, right: &str) -> String {
    work_bindings_core::merkle_node_hash(left, right)
}

/// The RFC 9162 root over envelope bytes given as a JSON array of hex strings;
/// returns `{"digest"}` or `{"error": …}` as JSON text (P-101).
#[wasm_bindgen(js_name = merkleRoot)]
#[must_use]
pub fn merkle_root(envelopes: &str) -> String {
    work_bindings_core::merkle_root(envelopes)
}

/// Verifies an inclusion proof; returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (T-4, T-88).
#[wasm_bindgen(js_name = verifyInclusion)]
#[must_use]
pub fn verify_inclusion(inclusion: &str) -> String {
    work_bindings_core::verify_inclusion(inclusion)
}

/// Verifies a consistency proof; returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (T-4, T-88).
#[wasm_bindgen(js_name = verifyConsistency)]
#[must_use]
pub fn verify_consistency(consistency: &str) -> String {
    work_bindings_core::verify_consistency(consistency)
}

/// Verifies a signed checkpoint note and its witness cosignatures;
/// returns `{"outcome", "size"?, "root"?, "profile"?, "cosignatures"?, "reason"?}` or `{"error": …}` as JSON text (T-88, OP-46).
#[wasm_bindgen(js_name = verifyCheckpoint)]
#[must_use]
pub fn verify_checkpoint(checkpoint: &str) -> String {
    work_bindings_core::verify_checkpoint(checkpoint)
}

/// Verifies that an envelope leaf is in a verified checkpoint's tree;
/// returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (T-88, P-108).
#[wasm_bindgen(js_name = checkpointIncludes)]
#[must_use]
pub fn checkpoint_includes(checkpoint: &str, inclusion: &str) -> String {
    work_bindings_core::checkpoint_includes(checkpoint, inclusion)
}

/// Verifies that a verified checkpoint's tree is a prefix of a newer one's;
/// returns `{"outcome", "reason"?}` or `{"error": …}` as JSON text (T-88).
#[wasm_bindgen(js_name = checkpointExtendsTo)]
#[must_use]
pub fn checkpoint_extends_to(older: &str, newer: &str, path: &str) -> String {
    work_bindings_core::checkpoint_extends_to(older, newer, path)
}

/// The work items a record's bytes touch; returns `{"outcome", "touches"?, "reason"?}` as JSON text (T-89).
#[wasm_bindgen]
#[must_use]
pub fn touched(record: &[u8]) -> String {
    work_bindings_core::touched(record)
}
