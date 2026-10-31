//! Deterministic CBOR with the Access profile and algorithm-tagged digests, both from `suiss-crypto` (P-5, P-7, P-8, P-67, P-101, T-87, Access CR-10): the shared strict decoder under the shared structural limits, its errors mapped onto Work reason codes, the shared digest form, the shared leaf and body commitment hashes and the shared plain SHA-256 behind the unprefixed record identifier, `LedgerID`, `proof_commit` and large part digest; the kernel holds no second encoder, decoder or hash.

mod read;
mod record;

use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, DecodeError};
use suiss_crypto::digest;

pub use record::{Decoded, check_record, decode_record, decode_record_with, record_from_value};
pub use suiss_crypto::dcbor::{Limits, TagAllowlist, Value};

pub(crate) use read::{
    MISSING, Mapped, UNKNOWN_FIELD, bytes_exact, digest_value, entries, list, pair, text, uint,
    versions,
};

use crate::id::{Digest, LedgerId, RecordId};
use crate::reason::{Limit, MalformedCbor, NonCanonicalCbor, Reason, Schema};
use crate::record::PartName;

/// The Work reason for a decoder error of the shared crate (P-5, P-7, P-103, Access CR-10).
///
/// `cbor-reserved` (additional information 28 to 30 outside major type 7) is `malformed_cbor:reserved_additional_info`; any error a later shared crate adds has no Work detail yet and reads as `malformed_cbor:truncated`.
#[must_use]
pub const fn cbor_reason(error: DecodeError) -> Reason {
    match error {
        DecodeError::TrailingBytes => Reason::MalformedCbor(MalformedCbor::TrailingBytes),
        DecodeError::Utf8 => Reason::MalformedCbor(MalformedCbor::InvalidUtf8),
        DecodeError::Reserved => Reason::MalformedCbor(MalformedCbor::ReservedAdditionalInfo),
        DecodeError::NonShortest => {
            Reason::NonCanonicalCbor(NonCanonicalCbor::NonPreferredArgument)
        }
        DecodeError::Indefinite => Reason::NonCanonicalCbor(NonCanonicalCbor::IndefiniteLength),
        DecodeError::Float => Reason::NonCanonicalCbor(NonCanonicalCbor::FloatNotInProfile),
        DecodeError::Tag => Reason::NonCanonicalCbor(NonCanonicalCbor::TagNotAllowed),
        DecodeError::Simple => Reason::NonCanonicalCbor(NonCanonicalCbor::SimpleNotInProfile),
        DecodeError::DuplicateKey => Reason::NonCanonicalCbor(NonCanonicalCbor::DuplicateMapKey),
        DecodeError::KeyOrder => Reason::NonCanonicalCbor(NonCanonicalCbor::UnsortedMapKeys),
        DecodeError::Depth => Reason::LimitExceeded(Limit::Depth),
        DecodeError::Items => Reason::LimitExceeded(Limit::Items),
        DecodeError::StringLength => Reason::LimitExceeded(Limit::String),
        _ => Reason::MalformedCbor(MalformedCbor::Truncated),
    }
}

/// Decodes exactly one deterministic CBOR item without tags, as `SignedRecord` and every envelope are written (P-5, P-72).
///
/// # Errors
///
/// The [`cbor_reason`] of the first violation.
pub fn decode(bytes: &[u8], limits: Limits) -> Result<Value, Reason> {
    dcbor::decode(bytes, limits).map_err(cbor_reason)
}

/// Decodes exactly one deterministic CBOR item that may carry the tags in `tags` (P-5, Access CR-10).
///
/// # Errors
///
/// The [`cbor_reason`] of the first violation.
pub fn decode_with(bytes: &[u8], limits: Limits, tags: &TagAllowlist) -> Result<Value, Reason> {
    dcbor::decode_with(bytes, limits, tags).map_err(cbor_reason)
}

/// Reads a `Digest` (`[-16, bstr .size 32]`): another label is `schema:digest_alg`, another length `schema:digest_length` (P-67, Access CR-1).
///
/// # Errors
///
/// `schema:digest_alg`, `schema:digest_length`, or `schema:required_field` for any other shape.
pub fn digest_from_value(value: &Value) -> Result<Digest, Reason> {
    digest_value(value)
}

/// The CBOR form of a digest (P-67).
#[must_use]
pub fn digest_to_value(value: &Digest) -> Value {
    digest::Digest(*value.as_bytes()).to_value()
}

/// The deterministic CBOR bytes of a digest (P-5, P-67).
#[must_use]
pub fn encode_digest(value: &Digest) -> Vec<u8> {
    dcbor::encode(&digest_to_value(value), Limits::CEILING).unwrap_or_default()
}

/// Decodes the deterministic CBOR bytes of one digest (P-5, P-67).
///
/// # Errors
///
/// A CBOR reason, or the reason of [`digest_from_value`].
pub fn decode_digest(bytes: &[u8]) -> Result<Digest, Reason> {
    digest_from_value(&decode(bytes, Limits::CEILING)?)
}

/// The RFC 9162 leaf hash `SHA-256(0x00 ‖ bytes)` of an envelope as received, genesis included (P-67, P-100, P-101).
#[must_use]
pub fn leaf_hash(envelope: &[u8]) -> Digest {
    Digest::sha256(digest::leaf_hash(envelope))
}

/// The unprefixed SHA-256 of `bytes` as a `Digest` (P-67, P-101, T-87).
#[must_use]
pub fn plain_digest(bytes: &[u8]) -> Digest {
    Digest::sha256(digest::sha256(bytes))
}

/// The record identifier `SHA-256(det-CBOR(SignedRecord))`: the unprefixed digest of the `COSE_Sign1` payload bytes as received (P-6 item 4, P-79, P-101).
#[must_use]
pub fn record_id(signed_record: &[u8]) -> RecordId {
    RecordId(plain_digest(signed_record))
}

/// The `LedgerID` `SHA-256(det-CBOR(GenesisEnvelope))`: the unprefixed digest of the genesis bytes as written (P-67, P-100 item 3, P-101).
#[must_use]
pub fn ledger_id(genesis: &[u8]) -> LedgerId {
    LedgerId(plain_digest(genesis))
}

/// The envelope `proof_commit`: the unprefixed digest of the full tagged `COSE_Sign1` bytes as received (P-75, P-76 item 4).
#[must_use]
pub fn proof_commit(cose_sign1: &[u8]) -> Digest {
    plain_digest(cose_sign1)
}

/// The genesis `versions.schema`: the unprefixed digest of the normative CDDL bytes of the protocol version a ledger opens with (P-100 item 7).
#[must_use]
pub fn schema_digest(cddl: &[u8]) -> Digest {
    plain_digest(cddl)
}

/// The content length above which a body part is committed by the digest of its content: the shared decoder's default single string bound, a protocol constant that no narrowing changes (P-104 item 3, Access CR-10).
pub const LARGE_PART: usize = 65_536;

/// The salted commitment `SHA-256(0x03 ‖ salt ‖ det-CBOR([name, media_type, content]))` of one body part, where content longer than [`LARGE_PART`] bytes is replaced by its unprefixed `Digest` (P-17, P-68, P-101, P-104).
///
/// # Errors
///
/// `limit_exceeded:string` when the name or media type does not fit the shared structural limits.
pub fn body_commitment(
    salt: &[u8; 32],
    name: &PartName,
    media_type: &str,
    content: &[u8],
) -> Result<Digest, Reason> {
    let committed = if content.len() > LARGE_PART {
        digest_to_value(&plain_digest(content))
    } else {
        Value::Bytes(content.to_vec())
    };
    let part = Value::Array(alloc::vec![
        Value::text(name.as_str()),
        Value::text(media_type),
        committed,
    ]);
    let encoded =
        dcbor::encode(&part, Limits::CEILING).map_err(|_| Reason::LimitExceeded(Limit::String))?;
    Ok(Digest::sha256(digest::body_commit(salt, &encoded)))
}

pub(crate) const fn schema(detail: Schema) -> Reason {
    Reason::Schema(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-5 P-103 Access CR-10
    #[test]
    fn p_5_every_shared_decoder_error_has_a_work_code() {
        let cases = [
            (DecodeError::Truncated, "malformed_cbor:truncated"),
            (DecodeError::TrailingBytes, "malformed_cbor:trailing_bytes"),
            (DecodeError::Utf8, "malformed_cbor:invalid_utf8"),
            (
                DecodeError::NonShortest,
                "non_canonical_cbor:non_preferred_argument",
            ),
            (
                DecodeError::Indefinite,
                "non_canonical_cbor:indefinite_length",
            ),
            (
                DecodeError::Float,
                "non_canonical_cbor:float_not_in_profile",
            ),
            (DecodeError::Tag, "non_canonical_cbor:tag_not_allowed"),
            (
                DecodeError::Simple,
                "non_canonical_cbor:simple_not_in_profile",
            ),
            (
                DecodeError::DuplicateKey,
                "non_canonical_cbor:duplicate_map_key",
            ),
            (
                DecodeError::KeyOrder,
                "non_canonical_cbor:unsorted_map_keys",
            ),
            (DecodeError::Depth, "limit_exceeded:depth"),
            (DecodeError::Items, "limit_exceeded:items"),
            (DecodeError::StringLength, "limit_exceeded:string"),
            (
                DecodeError::Reserved,
                "malformed_cbor:reserved_additional_info",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(
                alloc::string::ToString::to_string(&cbor_reason(error)),
                code
            );
        }
    }

    // P-7 Access CR-10
    #[test]
    fn p_7_structural_limits_only_narrow() {
        assert!(Limits::tightened(Limits::MAX_DEPTH + 1, 1, 1).is_none());
        let narrow = Limits::tightened(1, 256, 64).unwrap();
        assert_eq!(
            decode(&[0x81, 0x00], narrow),
            Ok(Value::Array(alloc::vec![Value::Unsigned(0)]))
        );
        assert_eq!(
            decode(&[0x81, 0x81, 0x00], narrow),
            Err(Reason::LimitExceeded(Limit::Depth))
        );
    }

    // P-67 P-101
    #[test]
    fn p_101_digest_round_trips_and_body_commitment_uses_prefix_0x03() {
        let d = Digest::sha256([7; 32]);
        assert_eq!(decode_digest(&encode_digest(&d)), Ok(d));
        let name = PartName::parse("terms").unwrap();
        let salt: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(u8::MAX));
        let commit = body_commitment(&salt, &name, "text/plain", b"x").unwrap();
        let mut part = alloc::vec![0x83, 0x65];
        part.extend_from_slice(b"terms");
        part.push(0x6a);
        part.extend_from_slice(b"text/plain");
        part.extend_from_slice(&[0x41, b'x']);
        assert_eq!(commit.as_bytes(), &digest::body_commit(&salt, &part));
        assert_ne!(commit.as_bytes(), &digest::field_commit(&salt, &part));
        assert_eq!(
            body_commitment(&salt, &name, &"a".repeat(Limits::MAX_STRING + 1), b"x"),
            Err(Reason::LimitExceeded(Limit::String))
        );
    }

    // P-79 P-100 P-75 P-101 T-87
    #[test]
    fn p_79_record_id_ledger_id_and_proof_commit_are_unprefixed_sha_256() {
        let bytes = [0xa1, 0x61, b'a', 0x00];
        let plain = digest::sha256(&bytes);
        assert_eq!(record_id(&bytes).0.as_bytes(), &plain);
        assert_eq!(ledger_id(&bytes).0.as_bytes(), &plain);
        assert_eq!(proof_commit(&bytes).as_bytes(), &plain);
        assert_eq!(schema_digest(&bytes).as_bytes(), &plain);
        assert_ne!(record_id(&bytes).0, leaf_hash(&bytes));
    }

    const MEDIA: &str = "application/octet-stream";

    fn part(third: Value) -> Vec<u8> {
        let fields = alloc::vec![Value::text("file"), Value::text(MEDIA), third];
        dcbor::encode(&Value::Array(fields), Limits::CEILING).unwrap()
    }

    // P-104 P-68 P-101 Access CR-10
    #[test]
    fn p_104_a_part_above_64_kib_commits_to_the_digest_of_its_content() {
        assert_eq!(LARGE_PART, Limits::MAX_STRING);
        let name = PartName::parse("file").unwrap();
        let salt: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(u8::MAX));
        let at_bound = alloc::vec![0x61; LARGE_PART];
        let small = body_commitment(&salt, &name, MEDIA, &at_bound).unwrap();
        let by_content = part(Value::Bytes(at_bound));
        assert_eq!(small.as_bytes(), &digest::body_commit(&salt, &by_content));
        let above = alloc::vec![0x61; LARGE_PART + 1];
        let large = body_commitment(&salt, &name, MEDIA, &above).unwrap();
        let by_digest = part(digest_to_value(&plain_digest(&above)));
        assert_eq!(large.as_bytes(), &digest::body_commit(&salt, &by_digest));
    }
}
