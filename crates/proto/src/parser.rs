//! The frames between the server and a parser worker over the worker's standard input and output
//! (T-72, SEC-35, P-95): a request is a version byte, a kind byte, a big-endian `u32` length and
//! that many payload bytes; the answer has the same shape with a status byte in place of the
//! kind. The one kind is a secret scan of decoded body parts, and a detection is answered with the
//! part name and the rule id only, never with the matched bytes.

use alloc::vec::Vec;

/// The frame version.
pub const VERSION: u8 = 1;

/// Bytes before the payload: version, kind or status, length.
pub const HEADER: usize = 6;

/// The most parts in one scan request, the shared decoder's array and map bound (Access CR-10).
pub const MAX_PARTS: usize = 256;

/// The longest part name (P-68).
pub const MAX_NAME: usize = 64;

/// The most content bytes a scan request is framed for, the request limit (P-33).
pub const MAX_CONTENT: usize = 262_144;

/// The largest payload: a two-byte part count, a name length byte, a name of [`MAX_NAME`] bytes
/// and a four-byte content length for each of [`MAX_PARTS`] parts, and [`MAX_CONTENT`] bytes.
pub const MAX_PAYLOAD: usize = 279_810;

/// What a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A secret scan of decoded body parts (SEC-35).
    Scan,
}

impl Kind {
    /// The kind byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Scan => 1,
        }
    }

    /// The kind of a byte, `None` for every byte the worker does not answer.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Scan),
            _ => None,
        }
    }
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// No rule matched; the payload is empty.
    Clean,
    /// A rule matched; the payload is a [`detection`].
    Detected,
    /// Refused; the payload is a stable reason code.
    Refused,
}

impl Status {
    /// The status byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Detected => 1,
            Self::Refused => 2,
        }
    }

    /// The status of a byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Clean),
            1 => Some(Self::Detected),
            2 => Some(Self::Refused),
            _ => None,
        }
    }
}

/// Reason codes of a refused request.
pub mod refusal {
    /// A kind byte the worker does not answer.
    pub const KIND: &str = "parser-kind";
    /// A payload that is not a well-formed scan request.
    pub const MALFORMED: &str = "parser-malformed";
    /// Parts over the per-part or per-scan byte limit (SEC-18).
    pub const TOO_LARGE: &str = "parser-too-large";
    /// A frame of another version or over [`super::MAX_PAYLOAD`]; the worker stops after it.
    pub const FRAME: &str = "parser-frame";

    /// Every code, in a fixed order.
    pub const ALL: [&str; 4] = [KIND, MALFORMED, TOO_LARGE, FRAME];
}

/// Why a frame or a payload is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// Another frame version.
    #[error("frame version {0}")]
    Version(u8),
    /// A payload above [`MAX_PAYLOAD`].
    #[error("payload too large")]
    TooLarge,
    /// A status byte the worker does not send.
    #[error("unknown status")]
    Status,
    /// A payload that does not have the shape of its kind or status.
    #[error("malformed payload")]
    Malformed,
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The kind byte of a request, the status byte of an answer.
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
    let len =
        usize::try_from(u32::from_be_bytes([a, b, c, d])).map_err(|_| FrameError::TooLarge)?;
    if len > MAX_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    Ok(Header { code, len })
}

fn name_fits(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
}

/// The payload of a scan request: the big-endian `u16` part count, then for each part its name
/// length byte, its name and its big-endian `u32` content length and content.
///
/// # Errors
/// [`FrameError::Malformed`] for more than [`MAX_PARTS`] parts or a name that is empty or longer
/// than [`MAX_NAME`] bytes, [`FrameError::TooLarge`] for a payload above [`MAX_PAYLOAD`].
pub fn scan_request(parts: &[(&str, &[u8])]) -> Result<Vec<u8>, FrameError> {
    if parts.len() > MAX_PARTS {
        return Err(FrameError::Malformed);
    }
    let count = u16::try_from(parts.len()).map_err(|_| FrameError::Malformed)?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for (name, content) in parts {
        if !name_fits(name) {
            return Err(FrameError::Malformed);
        }
        let name_len = u8::try_from(name.len()).map_err(|_| FrameError::Malformed)?;
        let content_len = u32::try_from(content.len()).map_err(|_| FrameError::TooLarge)?;
        out.push(name_len);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&content_len.to_be_bytes());
        out.extend_from_slice(content);
        if out.len() > MAX_PAYLOAD {
            return Err(FrameError::TooLarge);
        }
    }
    Ok(out)
}

fn take(bytes: &[u8], len: usize) -> Result<(&[u8], &[u8]), FrameError> {
    bytes.split_at_checked(len).ok_or(FrameError::Malformed)
}

fn chunk<const N: usize>(bytes: &[u8]) -> Result<(&[u8; N], &[u8]), FrameError> {
    bytes.split_first_chunk::<N>().ok_or(FrameError::Malformed)
}

/// The parts of a scan request payload, in order, with their names as UTF-8 text.
///
/// # Errors
/// [`FrameError::Malformed`] for a truncated payload, trailing bytes, more than [`MAX_PARTS`]
/// parts, or a name that is empty, longer than [`MAX_NAME`] bytes or not UTF-8.
pub fn scan_parts(payload: &[u8]) -> Result<Vec<(&str, &[u8])>, FrameError> {
    let (count, mut rest) = chunk::<2>(payload)?;
    let count = usize::from(u16::from_be_bytes(*count));
    if count > MAX_PARTS {
        return Err(FrameError::Malformed);
    }
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        let (name_len, after) = rest.split_first().ok_or(FrameError::Malformed)?;
        let (name, after) = take(after, usize::from(*name_len))?;
        let name = core::str::from_utf8(name).map_err(|_| FrameError::Malformed)?;
        if !name_fits(name) {
            return Err(FrameError::Malformed);
        }
        let (len, after) = chunk::<4>(after)?;
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| FrameError::Malformed)?;
        let (content, after) = take(after, len)?;
        parts.push((name, content));
        rest = after;
    }
    if !rest.is_empty() {
        return Err(FrameError::Malformed);
    }
    Ok(parts)
}

/// The payload of a detection: the part name length byte, the part name, then the rule id.
///
/// # Errors
/// [`FrameError::Malformed`] for an empty or too long part name or an empty rule id.
pub fn detection(part: &str, rule_id: &str) -> Result<Vec<u8>, FrameError> {
    if !name_fits(part) || rule_id.is_empty() {
        return Err(FrameError::Malformed);
    }
    let len = u8::try_from(part.len()).map_err(|_| FrameError::Malformed)?;
    let mut out = alloc::vec![len];
    out.extend_from_slice(part.as_bytes());
    out.extend_from_slice(rule_id.as_bytes());
    Ok(out)
}

/// Splits a detection payload into the part name and the rule id.
///
/// # Errors
/// [`FrameError::Malformed`] for a truncated payload, an empty or too long part name, an empty
/// rule id or text that is not UTF-8.
pub fn parse_detection(payload: &[u8]) -> Result<(&str, &str), FrameError> {
    let (len, rest) = payload.split_first().ok_or(FrameError::Malformed)?;
    let (part, rule_id) = take(rest, usize::from(*len))?;
    let part = core::str::from_utf8(part).map_err(|_| FrameError::Malformed)?;
    let rule_id = core::str::from_utf8(rule_id).map_err(|_| FrameError::Malformed)?;
    if !name_fits(part) || rule_id.is_empty() {
        return Err(FrameError::Malformed);
    }
    Ok((part, rule_id))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // T-72
    #[test]
    fn t_72_only_the_scan_kind_is_answered_and_the_status_bytes_round_trip() {
        let answered: Vec<Kind> = (0..=u8::MAX).filter_map(Kind::from_byte).collect();
        assert_eq!(answered, [Kind::Scan]);
        assert_eq!(Kind::from_byte(Kind::Scan.as_byte()), Some(Kind::Scan));
        let statuses: Vec<Status> = (0..=u8::MAX).filter_map(Status::from_byte).collect();
        let all = [Status::Clean, Status::Detected, Status::Refused];
        assert_eq!(statuses, all);
        for status in statuses {
            assert_eq!(Status::from_byte(status.as_byte()), Some(status));
        }
        assert!(refusal::ALL.iter().all(|c| c.starts_with("parser-")));
    }

    // T-72 SEC-18 P-33
    #[test]
    fn t_72_the_frame_ceiling_holds_the_largest_scan_request_and_no_more() {
        let overhead = MAX_PARTS.checked_mul(1 + MAX_NAME + 4).unwrap();
        assert_eq!(MAX_PAYLOAD, overhead.checked_add(2 + MAX_CONTENT).unwrap());
        let names: Vec<alloc::string::String> = (0..MAX_PARTS)
            .map(|i| alloc::format!("{:x<64}", alloc::format!("p{i}")))
            .collect();
        let share = alloc::vec![7_u8; MAX_CONTENT / MAX_PARTS];
        let parts: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), share.as_slice()))
            .collect();
        let payload = scan_request(&parts).unwrap();
        assert_eq!(payload.len(), MAX_PAYLOAD);
        assert_eq!(scan_parts(&payload).unwrap(), parts);
        assert!(frame(Kind::Scan.as_byte(), &payload).is_ok());
        assert_eq!(
            frame(0, &alloc::vec![0; MAX_PAYLOAD + 1]),
            Err(FrameError::TooLarge)
        );
        let bytes = frame(Kind::Scan.as_byte(), b"ab").unwrap();
        let head: [u8; HEADER] = bytes.get(..HEADER).unwrap().try_into().unwrap();
        assert_eq!(header(head), Ok(Header { code: 1, len: 2 }));
        assert_eq!(header([2, 1, 0, 0, 0, 0]), Err(FrameError::Version(2)));
        let over = u32::try_from(MAX_PAYLOAD + 1).unwrap().to_be_bytes();
        assert_eq!(
            header([1, 1, over[0], over[1], over[2], over[3]]),
            Err(FrameError::TooLarge)
        );
    }

    // T-72
    #[test]
    fn t_72_a_scan_request_decodes_only_in_its_exact_shape() {
        let parts: [(&str, &[u8]); 2] = [("title", b"hello".as_slice()), ("note", &[])];
        let payload = scan_request(&parts).unwrap();
        assert_eq!(scan_parts(&payload).unwrap(), parts);
        assert!(scan_parts(&[0, 0]).unwrap().is_empty());
        let mut trailing = payload.clone();
        trailing.push(0);
        let mut empty_name = alloc::vec![0, 1, 0];
        empty_name.extend_from_slice(&[0, 0, 0, 0]);
        let mut not_text = alloc::vec![0, 1, 1, 0xff];
        not_text.extend_from_slice(&[0, 0, 0, 0]);
        let too_many = u16::try_from(MAX_PARTS + 1).unwrap().to_be_bytes();
        for bad in [
            alloc::vec![],
            alloc::vec![0],
            alloc::vec![0, 1],
            payload.split_last().unwrap().1.to_vec(),
            trailing,
            empty_name,
            not_text,
            too_many.to_vec(),
        ] {
            assert_eq!(scan_parts(&bad), Err(FrameError::Malformed), "{bad:?}");
        }
        let long = "n".repeat(MAX_NAME + 1);
        let none: &[u8] = &[];
        assert_eq!(
            scan_request(&[(long.as_str(), none)]),
            Err(FrameError::Malformed)
        );
        assert_eq!(scan_request(&[("", none)]), Err(FrameError::Malformed));
        let big = alloc::vec![0_u8; MAX_PAYLOAD];
        assert_eq!(
            scan_request(&[("note", big.as_slice())]),
            Err(FrameError::TooLarge)
        );
    }

    // T-72 P-95
    #[test]
    fn t_72_a_detection_carries_the_part_name_and_the_rule_id_only() {
        let payload = detection("note", "github-pat").unwrap();
        assert_eq!(payload, b"\x04notegithub-pat");
        assert_eq!(parse_detection(&payload), Ok(("note", "github-pat")));
        assert_eq!(detection("", "github-pat"), Err(FrameError::Malformed));
        assert_eq!(detection("note", ""), Err(FrameError::Malformed));
        let bad: [&[u8]; 5] = [
            b"",
            b"\x04note",
            b"\x05note",
            b"\x00github-pat",
            b"\x04no\xfferule",
        ];
        for bad in bad {
            assert_eq!(parse_detection(bad), Err(FrameError::Malformed), "{bad:?}");
        }
    }
}
