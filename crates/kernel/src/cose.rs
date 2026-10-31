//! `COSE_Sign1` author signatures of Work records through the shared crate's parser and verifier with its pure backend (P-6, P-7, P-8, P-102, Access CR-9): the protected header is exactly `{1: alg, 3: "application/work-record+cbor", 4: kid}` of the normative CDDL, the algorithm must be in the caller's policy, and a Work record's ECDSA signature must be low-S.

use alloc::vec::Vec;

use suiss_crypto::cose::{self, CoseError};
use suiss_crypto::dcbor::DecodeError;
use suiss_crypto::sig::{PureBackend, SignatureError};

pub use suiss_crypto::cose::{Algorithm, KeySet, PublicKey, Sign1};

use crate::codec::cbor_reason;
use crate::reason::{Reason, Schema, Signature};

/// A verified record signature: the author key and the `SignedRecord` bytes it covers (P-6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPayload {
    /// The algorithm of the protected header.
    pub algorithm: Algorithm,
    /// The key identifier of the protected header (Access CR-55).
    pub kid: [u8; 32],
    /// The `SignedRecord` bytes as received.
    pub payload: Vec<u8>,
}

/// The Work detail of a signature or key rejected by the shared strictness checks (P-7, Access CR-9).
///
/// A wrong length, an ECDSA scalar out of range and a small-order Ed25519 `R` have no Work detail of their own and read as `signature:invalid`.
#[must_use]
pub const fn signature_detail(error: SignatureError) -> Signature {
    match error {
        SignatureError::NonCanonicalKey
        | SignatureError::NonCanonicalR
        | SignatureError::UnreducedS => Signature::NonCanonicalEd25519,
        SignatureError::SmallOrderKey => Signature::SmallOrderKey,
        SignatureError::HighS => Signature::HighS,
        _ => Signature::Invalid,
    }
}

const fn signature(detail: Signature) -> Reason {
    Reason::Signature(detail)
}

/// The `content type` a Work record's protected header carries (P-102).
pub const CONTENT_TYPE: &str = "application/work-record+cbor";

const CONTAINER: Reason = Reason::Schema(Schema::Container);
const HEADER: Reason = signature(Signature::HeaderProfile);
const ALG: Reason = signature(Signature::AlgNotAllowed);

fn parse_reason(error: CoseError) -> Reason {
    match error {
        CoseError::Cbor(DecodeError::Tag) | CoseError::Shape | CoseError::Payload => CONTAINER,
        CoseError::Cbor(e) => cbor_reason(e),
        CoseError::Signature(e) => signature(signature_detail(e)),
        _ => HEADER,
    }
}

fn verify_reason(error: CoseError) -> Reason {
    match error {
        CoseError::Shape | CoseError::Payload => CONTAINER,
        CoseError::Algorithm | CoseError::KeyType => ALG,
        CoseError::UnknownKid => signature(Signature::KidUnknown),
        CoseError::Signature(e) => signature(signature_detail(e)),
        _ => HEADER,
    }
}

/// Parses tagged `COSE_Sign1` framing, the only place tag 18 is allowed, keeping the protected header, payload and signature bytes as received; the payload may be detached (`nil`) here (P-5 item 4, P-6, Access CR-10).
///
/// # Errors
///
/// `schema:container` for bytes that are not a tagged `COSE_Sign1`, a CBOR reason for non-canonical framing, or `signature:header_profile` for a non-empty unprotected header.
pub fn parse_container(bytes: &[u8]) -> Result<Sign1, Reason> {
    cose::parse_sign1(bytes).map_err(parse_reason)
}

/// Verifies the tagged `COSE_Sign1` bytes of a Work record exactly as received with the shared verifier: the payload is attached, the unprotected header empty, the protected header `{1: alg, 3: "application/work-record+cbor", 4: kid}`, the algorithm in `keys.allowed` (the caller's policy, never the header; Access CR-7), the key bound to `kid`, and an ECDSA signature low-S (P-6, P-7, P-102, Access CR-9).
///
/// # Errors
///
/// `schema:container` for bytes that are not a tagged, attached `COSE_Sign1`, a CBOR reason for non-canonical framing, or a `signature:*` reason.
pub fn verify_record_signature(bytes: &[u8], keys: &KeySet) -> Result<SignedPayload, Reason> {
    parse_container(bytes)?;
    let verified =
        cose::verify_sign1(&PureBackend, bytes, keys, CONTENT_TYPE).map_err(verify_reason)?;
    Ok(SignedPayload {
        algorithm: verified.algorithm,
        kid: verified.kid,
        payload: verified.payload,
    })
}
