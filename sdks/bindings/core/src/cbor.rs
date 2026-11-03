//! Deterministic CBOR bytes through the kernel codec (P-5, P-7, P-67, P-79, P-100, P-101, P-104, T-69 item 6): the strict decoder, the `COSE_Sign1` container, records and envelopes as their `decoded` projection, and the digests computed from bytes as received, never from a projection.

use work_kernel::codec::{self, Decoded, Limits, TagAllowlist, decode_record, decode_with};
use work_kernel::cose::parse_container;
use work_kernel::envelope;
use work_kernel::reason::QuarantineReason;
use work_kernel::record::PartName;

use crate::decode::{list, uint};
use crate::project::{
    accept, accepted, cbor, digest_answer, digest_json, fields, quarantine, reject,
};
use crate::{input_error, parse};

fn projected(bytes: &[u8]) -> String {
    match codec::decode(bytes, Limits::CEILING)
        .ok()
        .as_ref()
        .and_then(cbor)
    {
        Some(decoded) => accept(fields([("decoded", decoded)])),
        None => input_error("unprojectable"),
    }
}

/// Decodes exactly one deterministic CBOR item that may carry only the tags in `tags`, a JSON array of tag numbers, under the shared structural ceilings (P-5, P-7, Access CR-10).
///
/// Returns `{"outcome":"accept"}` or `{"outcome":"reject","reason":<code>}`; `tags` that are not a JSON array of unsigned integers return `{"error":{"code":"invalid_json"}}` or `{"error":{"code":"invalid_tags"}}`.
#[must_use]
pub fn check_cbor(bytes: &[u8], tags: &str) -> String {
    let Some(tags) = parse(tags) else {
        return input_error("invalid_json");
    };
    let Ok(tags) = list(&tags, uint) else {
        return input_error("invalid_tags");
    };
    match decode_with(bytes, Limits::CEILING, &TagAllowlist::only(&tags)) {
        Ok(_) => accepted(),
        Err(reason) => reject(&reason.to_string()),
    }
}

/// Parses tagged `COSE_Sign1` framing, the only place tag 18 is allowed (P-5 item 4, P-6, Access CR-10).
///
/// Returns `{"outcome":"accept"}` or `{"outcome":"reject","reason":<code>}`.
#[must_use]
pub fn parse_cose_container(bytes: &[u8]) -> String {
    match parse_container(bytes) {
        Ok(_) => accepted(),
        Err(reason) => reject(&reason.to_string()),
    }
}

/// Decodes `SignedRecord` bytes under the shared structural ceilings (P-5, P-7, P-87).
///
/// Returns `{"outcome":"accept","decoded":<projection>}` for a protocol 1.0 record, `{"outcome":"quarantine","reason":"protocol_version_unknown"}` for a record of a protocol version without a rule set, or `{"outcome":"reject","reason":<code>}`; decoding is not validation, which [`crate::validate_record_cbor`] adds.
#[must_use]
pub fn decode_record_cbor(record: &[u8]) -> String {
    match decode_record(record) {
        Ok(Decoded::Record(_)) => projected(record),
        Ok(Decoded::UnknownProtocol(_)) => {
            quarantine(&QuarantineReason::ProtocolVersionUnknown.to_string())
        }
        Err(reason) => reject(&reason.to_string()),
    }
}

/// Decodes `GenesisEnvelope` or `LedgerEnvelope` bytes by the schema their position selects (P-11, P-100 item 6).
///
/// Returns `{"outcome":"accept","decoded":<projection>}` or `{"outcome":"reject","reason":<code>}`.
#[must_use]
pub fn decode_envelope(envelope: &[u8]) -> String {
    match envelope::decode_envelope(envelope) {
        Ok(_) => projected(envelope),
        Err(reason) => reject(&reason.to_string()),
    }
}

/// Decodes the deterministic CBOR bytes of one `Digest` (P-5, P-67, Access CR-1).
///
/// Returns `{"outcome":"accept","digest":[-16,<hex>]}` or `{"outcome":"reject","reason":<code>}`.
#[must_use]
pub fn decode_digest(bytes: &[u8]) -> String {
    match codec::decode_digest(bytes) {
        Ok(d) => accept(fields([("digest", digest_json(&d))])),
        Err(reason) => reject(&reason.to_string()),
    }
}

/// The record identifier of `SignedRecord` bytes as received, `{"digest":[-16,<hex>]}` (P-79).
#[must_use]
pub fn record_id(record: &[u8]) -> String {
    digest_answer(&codec::record_id(record).0)
}

/// The `LedgerID` of genesis bytes as written, `{"digest":[-16,<hex>]}` (P-67, P-100).
#[must_use]
pub fn ledger_id(genesis: &[u8]) -> String {
    digest_answer(&codec::ledger_id(genesis).0)
}

/// The RFC 9162 leaf hash of envelope bytes as received, genesis included, `{"digest":[-16,<hex>]}` (P-101).
#[must_use]
pub fn leaf_hash(envelope: &[u8]) -> String {
    digest_answer(&codec::leaf_hash(envelope))
}

/// The envelope `proof_commit` of `COSE_Sign1` bytes as received, `{"digest":[-16,<hex>]}` (P-75, P-76).
#[must_use]
pub fn proof_commit(cose_sign1: &[u8]) -> String {
    digest_answer(&codec::proof_commit(cose_sign1))
}

/// The salted commitment of one body part, where content above 65,536 bytes is committed by its digest (P-17, P-68, P-101, P-104); the 32-byte salt comes from the caller's random source, fresh per part.
///
/// Returns `{"outcome":"accept","digest":[-16,<hex>]}` or `{"outcome":"reject","reason":<code>}`; a salt that is not 32 bytes or a part name outside the schema returns `{"error":{"code":"invalid_salt"}}` or `{"error":{"code":"invalid_part_name"}}`.
#[must_use]
pub fn body_commitment(salt: &[u8], name: &str, media_type: &str, content: &[u8]) -> String {
    let Ok(salt) = <[u8; 32]>::try_from(salt) else {
        return input_error("invalid_salt");
    };
    let Some(name) = PartName::parse(name) else {
        return input_error("invalid_part_name");
    };
    match codec::body_commitment(&salt, &name, media_type, content) {
        Ok(d) => accept(fields([("digest", digest_json(&d))])),
        Err(reason) => reject(&reason.to_string()),
    }
}
