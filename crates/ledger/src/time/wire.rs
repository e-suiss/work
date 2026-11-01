//! Roughtime requests and response verification for the RFC version and draft-11 (OP-42 item 3),
//! on `roughenough-protocol`: framing, the tag header, nested value lookup and the RFC request
//! come from it; draft-11 differs in its signature context strings, its top-level `VER` and the
//! absent `TYPE`, so one verifier serves both with the version's parameters.

use roughenough_protocol::header::{RawHeader, find_value_range};
use roughenough_protocol::request::Request;
use roughenough_protocol::tag::Tag;
use roughenough_protocol::tags::{Nonce, ProtocolVersion, SrvCommitment};
use roughenough_protocol::wire::{FRAME_MAGIC, ToFrame as _};
use sha2::{Digest as _, Sha512};
use suiss_crypto::sig::{PureBackend, SignatureError, ed25519};

/// The Roughtime version a server speaks (OP-42 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// RFC 10049, version 1.
    Rfc,
    /// draft-ietf-ntp-roughtime-11, version `0x8000000b`.
    Draft11,
}

const DRAFT_11: u32 = 0x8000_000b;
const DRAFT_11_SREP_CONTEXT: &[u8] = b"RoughTime v1 response signature\0";
const DRAFT_11_DELE_CONTEXT: &[u8] = b"RoughTime v1 delegation signature--\0";
const RESPONSE_TYPE: u32 = 1;
const FRAME_HEADER: usize = 12;
const REQUEST_SIZE: usize = 1024;
const DRAFT_11_BODY: u32 = 1012;
const DRAFT_11_OFFSETS: [u32; 3] = [4, 36, 68];

/// Why a response was not accepted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum WireError {
    /// The request could not be encoded.
    #[error("request encoding: {0}")]
    Encode(roughenough_protocol::error::Error),
    /// The response is not a well-formed Roughtime packet.
    #[error("malformed response: {0}")]
    Malformed(&'static str),
    /// A tag header or nested message did not parse.
    #[error("response: {0}")]
    Parse(#[from] roughenough_protocol::error::Error),
    /// The response names another version than the one asked for.
    #[error("unexpected version {0:#010x}")]
    Version(u32),
    /// The response answers another nonce.
    #[error("nonce mismatch")]
    Nonce,
    /// A signature does not verify.
    #[error("{0} signature: {1}")]
    Signature(&'static str, SignatureError),
    /// The Merkle path does not lead from the nonce to the signed root.
    #[error("nonce not in the signed Merkle tree")]
    Merkle,
    /// The midpoint is outside the delegation's validity.
    #[error("midpoint outside the delegation window")]
    Delegation,
}

/// What a verified response states, in whole seconds as on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Verified {
    /// `MIDP`, Unix seconds.
    pub(crate) midpoint_s: u64,
    /// `RADI`, seconds.
    pub(crate) radius_s: u32,
}

impl Version {
    fn srep_context(self) -> &'static [u8] {
        match self {
            Self::Rfc => ProtocolVersion::RFC.srep_prefix(),
            Self::Draft11 => DRAFT_11_SREP_CONTEXT,
        }
    }

    fn dele_context(self) -> &'static [u8] {
        match self {
            Self::Rfc => ProtocolVersion::RFC.dele_prefix(),
            Self::Draft11 => DRAFT_11_DELE_CONTEXT,
        }
    }
}

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    for p in parts {
        hasher.update(p);
    }
    let full: [u8; 64] = hasher.finalize().into();
    full.first_chunk::<32>().copied().unwrap_or([0; 32])
}

/// `SRV`: the first 32 bytes of SHA-512 over `0xff` and the long-term public key.
#[must_use]
pub(crate) fn srv(public_key: &[u8; 32]) -> [u8; 32] {
    h(&[&[0xff], public_key])
}

/// The framed 1024-byte request for `version` carrying `nonce` and the `SRV` of `public_key`.
///
/// # Errors
/// [`WireError::Encode`] when the RFC request does not encode.
pub(crate) fn request(
    version: Version,
    nonce: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<Vec<u8>, WireError> {
    let commitment = srv(public_key);
    match version {
        Version::Rfc => Request::new_with_server_and_versions(
            &Nonce::from(*nonce),
            &SrvCommitment::from(commitment),
            &[ProtocolVersion::RFC],
        )
        .as_frame_bytes()
        .map_err(WireError::Encode),
        Version::Draft11 => Ok(draft_11_request(nonce, &commitment)),
    }
}

fn draft_11_request(nonce: &[u8; 32], commitment: &[u8; 32]) -> Vec<u8> {
    let tags: [&[u8; 4]; 4] = [b"VER\0", b"SRV\0", b"NONC", b"ZZZZ"];
    let mut out = Vec::with_capacity(REQUEST_SIZE);
    out.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
    out.extend_from_slice(&DRAFT_11_BODY.to_le_bytes());
    out.extend_from_slice(&4_u32.to_le_bytes());
    for offset in DRAFT_11_OFFSETS {
        out.extend_from_slice(&offset.to_le_bytes());
    }
    for tag in tags {
        out.extend_from_slice(tag);
    }
    out.extend_from_slice(&DRAFT_11.to_le_bytes());
    out.extend_from_slice(commitment);
    out.extend_from_slice(nonce);
    out.resize(REQUEST_SIZE, 0);
    out
}

fn message(packet: &[u8]) -> Result<&[u8], WireError> {
    let (head, rest) = packet
        .split_first_chunk::<FRAME_HEADER>()
        .ok_or(WireError::Malformed("shorter than the frame header"))?;
    let (magic, len) = head
        .split_first_chunk::<8>()
        .ok_or(WireError::Malformed("frame"))?;
    if u64::from_be_bytes(*magic) != FRAME_MAGIC {
        return Err(WireError::Malformed("frame magic"));
    }
    let len: [u8; 4] = len.try_into().map_err(|_| WireError::Malformed("frame"))?;
    let len =
        usize::try_from(u32::from_le_bytes(len)).map_err(|_| WireError::Malformed("length"))?;
    let msg = rest.get(..len).ok_or(WireError::Malformed("truncated"))?;
    RawHeader::parse(msg)?;
    Ok(msg)
}

fn value<'a>(msg: &'a [u8], path: &[Tag]) -> Result<&'a [u8], WireError> {
    let range = find_value_range(msg, path)?;
    msg.get(range).ok_or(WireError::Malformed("value range"))
}

fn fixed<const N: usize>(bytes: &[u8], what: &'static str) -> Result<[u8; N], WireError> {
    bytes.try_into().map_err(|_| WireError::Malformed(what))
}

fn u32_of(msg: &[u8], path: &[Tag], what: &'static str) -> Result<u32, WireError> {
    Ok(u32::from_le_bytes(fixed(value(msg, path)?, what)?))
}

fn u64_of(msg: &[u8], path: &[Tag], what: &'static str) -> Result<u64, WireError> {
    Ok(u64::from_le_bytes(fixed(value(msg, path)?, what)?))
}

fn verify_signature(
    which: &'static str,
    key: &[u8],
    context: &[u8],
    signed: &[u8],
    signature: &[u8],
) -> Result<(), WireError> {
    let mut msg = Vec::with_capacity(context.len().saturating_add(signed.len()));
    msg.extend_from_slice(context);
    msg.extend_from_slice(signed);
    ed25519(&PureBackend, key, &msg, signature).map_err(|e| WireError::Signature(which, e))
}

fn merkle_root(nonce: &[u8; 32], index: u32, path: &[u8]) -> Result<[u8; 32], WireError> {
    let (nodes, rest) = path.as_chunks::<32>();
    if !rest.is_empty() {
        return Err(WireError::Malformed("PATH length"));
    }
    let mut hash = h(&[&[0x00], nonce]);
    let mut index = index;
    for node in nodes {
        hash = if index & 1 == 0 {
            h(&[&[0x01], &hash, node])
        } else {
            h(&[&[0x01], node, &hash])
        };
        index = index.checked_shr(1).unwrap_or(0);
    }
    if index != 0 {
        return Err(WireError::Merkle);
    }
    Ok(hash)
}

/// Verifies `packet` as `version`'s answer to `nonce` from the server whose long-term key is
/// `public_key`: the delegation signed by the long-term key, the signed response signed by the
/// delegated key, the nonce in the signed Merkle tree and the midpoint inside the delegation.
///
/// # Errors
/// [`WireError`] naming the first check that failed.
pub(crate) fn verify(
    version: Version,
    public_key: &[u8; 32],
    nonce: &[u8; 32],
    packet: &[u8],
) -> Result<Verified, WireError> {
    let msg = message(packet)?;
    match version {
        Version::Rfc => {
            let kind = u32_of(msg, &[Tag::TYPE], "TYPE")?;
            if kind != RESPONSE_TYPE {
                return Err(WireError::Malformed("TYPE is not a response"));
            }
            let ver = u32_of(msg, &[Tag::SREP, Tag::VER], "VER")?;
            if ver != ProtocolVersion::RFC.as_u32() {
                return Err(WireError::Version(ver));
            }
            if value(msg, &[Tag::NONC])? != nonce {
                return Err(WireError::Nonce);
            }
        }
        Version::Draft11 => {
            let ver = u32_of(msg, &[Tag::VER], "VER")?;
            if ver != DRAFT_11 {
                return Err(WireError::Version(ver));
            }
            if find_value_range(msg, &[Tag::NONC]).is_ok() && value(msg, &[Tag::NONC])? != nonce {
                return Err(WireError::Nonce);
            }
        }
    }
    let dele = value(msg, &[Tag::CERT, Tag::DELE])?;
    verify_signature(
        "delegation",
        public_key,
        version.dele_context(),
        dele,
        value(msg, &[Tag::CERT, Tag::SIG])?,
    )?;
    let srep = value(msg, &[Tag::SREP])?;
    verify_signature(
        "response",
        value(dele, &[Tag::PUBK])?,
        version.srep_context(),
        srep,
        value(msg, &[Tag::SIG])?,
    )?;
    let root: [u8; 32] = fixed(value(srep, &[Tag::ROOT])?, "ROOT")?;
    let index = u32_of(msg, &[Tag::INDX], "INDX")?;
    if merkle_root(nonce, index, value(msg, &[Tag::PATH])?)? != root {
        return Err(WireError::Merkle);
    }
    let midpoint_s = u64_of(srep, &[Tag::MIDP], "MIDP")?;
    let radius_s = u32_of(srep, &[Tag::RADI], "RADI")?;
    let mint = u64_of(dele, &[Tag::MINT], "MINT")?;
    let maxt = u64_of(dele, &[Tag::MAXT], "MAXT")?;
    if midpoint_s < mint || midpoint_s > maxt {
        return Err(WireError::Delegation);
    }
    Ok(Verified {
        midpoint_s,
        radius_s,
    })
}

#[cfg(test)]
mod tests;
