//! The frames of the `work-signer` socket (T-7, T-10, P-20): a request is a version byte, a kind
//! byte, a big-endian `u32` length and that many payload bytes; the response has the same shape
//! with a status byte in place of the kind. The signer answers two kinds only, its public log key
//! and a C2SP note signature over a `tlog-checkpoint` body; no kind asks for an author signature.

use alloc::string::String;
use alloc::vec::Vec;

/// The frame version.
pub const VERSION: u8 = 1;

/// Bytes before the payload: version, kind or status, length.
pub const HEADER: usize = 6;

/// The largest payload, the C2SP signed-note ceiling (256 KiB).
pub const MAX_PAYLOAD: usize = 262_144;

/// What a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// The log key: its note key name and Ed25519 public key.
    LogKey,
    /// A note signature line over a `tlog-checkpoint` body, the ledger acknowledgement (P-20,
    /// T-88).
    Checkpoint,
}

impl Kind {
    /// The kind byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::LogKey => 1,
            Self::Checkpoint => 2,
        }
    }

    /// The kind of a byte, `None` for every byte the signer does not answer.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::LogKey),
            2 => Some(Self::Checkpoint),
            _ => None,
        }
    }
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// Answered; the payload is the answer.
    Signed,
    /// Refused; the payload is a stable reason code.
    Refused,
}

impl Status {
    /// The status byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Signed => 0,
            Self::Refused => 1,
        }
    }

    /// The status of a byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Signed),
            1 => Some(Self::Refused),
            _ => None,
        }
    }
}

/// Reason codes of a refused request.
pub mod refusal {
    /// A kind byte the signer does not answer.
    pub const KIND: &str = "signer-kind";
    /// A payload that is not the canonical body of a `tlog-checkpoint`.
    pub const NOT_CHECKPOINT: &str = "signer-not-checkpoint";
    /// A checkpoint of an origin outside the configured prefix.
    pub const ORIGIN: &str = "signer-origin";
    /// A request with a payload where none belongs.
    pub const PAYLOAD: &str = "signer-payload";
    /// The key store failed to sign.
    pub const SIGN: &str = "signer-sign";
}

/// Why a frame is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// Another frame version.
    #[error("frame version {0}")]
    Version(u8),
    /// A payload above [`MAX_PAYLOAD`].
    #[error("payload too large")]
    TooLarge,
    /// A status byte that is neither signed nor refused.
    #[error("unknown status")]
    Status,
    /// A log key answer that is not a 32-byte key followed by a key name.
    #[error("malformed log key")]
    LogKey,
    /// A payload that is not UTF-8 where text belongs.
    #[error("payload is not UTF-8")]
    Text,
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The kind byte of a request, the status byte of a response.
    pub code: u8,
    /// Payload length.
    pub len: usize,
}

/// The frame of `code` and `payload`.
///
/// # Errors
/// [`FrameError::TooLarge`].
pub fn frame(code: u8, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge)?;
    let mut out = Vec::with_capacity(HEADER.saturating_add(payload.len()));
    out.push(VERSION);
    out.push(code);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes a frame header.
///
/// # Errors
/// [`FrameError::Version`] or [`FrameError::TooLarge`].
pub fn header(bytes: [u8; HEADER]) -> Result<Header, FrameError> {
    let [version, code, a, b, c, d] = bytes;
    if version != VERSION {
        return Err(FrameError::Version(version));
    }
    let len = usize::try_from(u32::from_be_bytes([a, b, c, d]))
        .map_err(|_| FrameError::TooLarge)?;
    if len > MAX_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    Ok(Header { code, len })
}

/// The log key answer: the 32-byte Ed25519 public key, then the note key name.
#[must_use]
pub fn log_key(public: &[u8; 32], name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32_usize.saturating_add(name.len()));
    out.extend_from_slice(public);
    out.extend_from_slice(name.as_bytes());
    out
}

/// Splits a log key answer into the public key and the key name.
///
/// # Errors
/// [`FrameError::LogKey`].
pub fn parse_log_key(payload: &[u8]) -> Result<([u8; 32], String), FrameError> {
    let (key, name) = payload
        .split_first_chunk::<32>()
        .ok_or(FrameError::LogKey)?;
    let name = core::str::from_utf8(name).map_err(|_| FrameError::LogKey)?;
    if name.is_empty() {
        return Err(FrameError::LogKey);
    }
    Ok((*key, String::from(name)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // T-7 P-20
    #[test]
    fn t_7_no_kind_byte_but_the_log_key_and_the_checkpoint_is_answered() {
        let answered: Vec<Kind> = (0..=u8::MAX).filter_map(Kind::from_byte).collect();
        assert_eq!(answered, [Kind::LogKey, Kind::Checkpoint]);
        for kind in answered {
            assert_eq!(Kind::from_byte(kind.as_byte()), Some(kind));
        }
    }

    // T-7
    #[test]
    fn t_7_a_frame_round_trips_and_an_oversized_or_foreign_one_is_refused() {
        let bytes = frame(Kind::Checkpoint.as_byte(), b"body").unwrap();
        let head: [u8; HEADER] = bytes.get(..HEADER).unwrap().try_into().unwrap();
        assert_eq!(
            header(head),
            Ok(Header {
                code: Kind::Checkpoint.as_byte(),
                len: 4
            })
        );
        assert_eq!(bytes.get(HEADER..), Some(b"body".as_slice()));
        assert_eq!(
            frame(0, &alloc::vec![0; MAX_PAYLOAD + 1]),
            Err(FrameError::TooLarge)
        );
        assert_eq!(header([2, 1, 0, 0, 0, 0]), Err(FrameError::Version(2)));
        assert_eq!(header([1, 1, 0, 4, 0, 1]), Err(FrameError::TooLarge));
        let key = log_key(&[7; 32], "work.localhost");
        assert_eq!(
            parse_log_key(&key),
            Ok(([7; 32], String::from("work.localhost")))
        );
        assert_eq!(parse_log_key(&[7; 32]), Err(FrameError::LogKey));
    }
}
