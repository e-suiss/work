//! The external identifiers of the API and its JSON projection (P-112, P-54 item 7): a closed list of type prefixes; the body of a stored object is its identifier bytes in lower-case hex, the body of `pty_` and of the opaque tokens is unpadded base64url; a wrong prefix, the prefix of another type or a malformed body is `invalid_id`. Prefixes are a projection only and never enter the canonical bytes (P-112 item 5).

use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, WorkId};

/// The problem code of an identifier that does not parse (P-112 item 3).
pub const INVALID_ID: &str = "invalid_id";

/// One prefix of the closed list (P-112 item 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Prefix {
    /// `wrk_`: a Work.
    Work,
    /// `cmt_`: a Commitment.
    Commitment,
    /// `cnd_`: a Condition, gates included.
    Condition,
    /// `aim_`: an Aim.
    Aim,
    /// `ref_`: a Reference.
    Reference,
    /// `rec_`: a record (Act, Declaration, Claim).
    Record,
    /// `led_`: a ledger.
    Ledger,
    /// `pty_`: a Party, the projection of an Access `PartyRef`.
    Party,
    /// `prc_`: a Practice package version.
    Practice,
    /// `sub_`: an event subscription.
    Subscription,
    /// `exp_`: an export job.
    Export,
    /// `cur_`: a pagination and incremental sync cursor.
    Cursor,
    /// `pos_`: a read position token (T-97).
    Position,
}

/// How the body after a prefix is written (P-112 item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyForm {
    /// Exactly this many bytes in lower-case hex.
    Hex(usize),
    /// One or more bytes in unpadded base64url.
    Base64Url,
}

impl Prefix {
    /// Every prefix, in the order of the P-112 list.
    pub const ALL: [Self; 13] = [
        Self::Work,
        Self::Commitment,
        Self::Condition,
        Self::Aim,
        Self::Reference,
        Self::Record,
        Self::Ledger,
        Self::Party,
        Self::Practice,
        Self::Subscription,
        Self::Export,
        Self::Cursor,
        Self::Position,
    ];

    /// The prefix text, underscore included.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Work => "wrk_",
            Self::Commitment => "cmt_",
            Self::Condition => "cnd_",
            Self::Aim => "aim_",
            Self::Reference => "ref_",
            Self::Record => "rec_",
            Self::Ledger => "led_",
            Self::Party => "pty_",
            Self::Practice => "prc_",
            Self::Subscription => "sub_",
            Self::Export => "exp_",
            Self::Cursor => "cur_",
            Self::Position => "pos_",
        }
    }

    /// How the body is written: 16 bytes for a Work and the `UUIDv7` rows, 32 bytes for a record
    /// digest, a ledger, a package digest and the items a record opens, base64url otherwise.
    #[must_use]
    pub const fn body(self) -> BodyForm {
        match self {
            Self::Work | Self::Subscription | Self::Export => BodyForm::Hex(16),
            Self::Commitment
            | Self::Condition
            | Self::Aim
            | Self::Reference
            | Self::Record
            | Self::Ledger
            | Self::Practice => BodyForm::Hex(32),
            Self::Party | Self::Cursor | Self::Position => BodyForm::Base64Url,
        }
    }

    /// The prefix `text` starts with, if it is on the list.
    #[must_use]
    pub fn of(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|prefix| text.starts_with(prefix.as_str()))
    }
}

/// Why an external identifier does not parse; every case is the `invalid_id` problem (P-112
/// item 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvalidId {
    /// No prefix of the list.
    #[error("unknown identifier prefix")]
    UnknownPrefix,
    /// The prefix of another type.
    #[error("identifier of another type")]
    OtherType {
        /// The prefix the caller asked for.
        expected: Prefix,
        /// The prefix the text carries.
        found: Prefix,
    },
    /// A body that is not in the one written form of its prefix.
    #[error("malformed identifier body")]
    Body,
}

impl InvalidId {
    /// The RFC 9457 problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        INVALID_ID
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            out.extend(HEX.get(usize::from(nibble)).map(|&c| char::from(c)));
        }
    }
    out
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => digit.checked_sub(b'a').and_then(|n| n.checked_add(10)),
        _ => None,
    }
}

fn unhex(text: &str, len: usize) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if digits.len() != len.checked_mul(2)? {
        return None;
    }
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| nibble(high)?.checked_mul(16)?.checked_add(nibble(low)?))
        .collect()
}

/// `prefix` followed by `bytes` in the body form of the prefix.
#[must_use]
pub fn format(prefix: Prefix, bytes: &[u8]) -> String {
    let body = match prefix.body() {
        BodyForm::Hex(_) => hex(bytes),
        BodyForm::Base64Url => URL_SAFE_NO_PAD.encode(bytes),
    };
    let mut out = String::with_capacity(prefix.as_str().len().saturating_add(body.len()));
    out.push_str(prefix.as_str());
    out.push_str(&body);
    out
}

/// The body bytes of `text`, which must carry `expected`.
///
/// # Errors
/// [`InvalidId`] for an unknown prefix, the prefix of another type, or a body that is not the
/// one written form: upper-case or short hex, padded or non-canonical base64url, or empty.
pub fn parse(expected: Prefix, text: &str) -> Result<Vec<u8>, InvalidId> {
    let found = Prefix::of(text).ok_or(InvalidId::UnknownPrefix)?;
    if found != expected {
        return Err(InvalidId::OtherType { expected, found });
    }
    let body = text.get(found.as_str().len()..).ok_or(InvalidId::Body)?;
    let bytes = match found.body() {
        BodyForm::Hex(len) => unhex(body, len),
        BodyForm::Base64Url => URL_SAFE_NO_PAD.decode(body).ok(),
    };
    bytes
        .filter(|bytes| !bytes.is_empty())
        .ok_or(InvalidId::Body)
}

/// A typed identifier with an external form (P-112, §17.13.3 item 5).
pub trait ExternalId: Sized {
    /// The prefix of the type.
    const PREFIX: Prefix;

    /// The body bytes.
    #[must_use]
    fn body_bytes(&self) -> Vec<u8>;

    /// The identifier of body bytes; `None` when they do not form one.
    #[must_use]
    fn from_body_bytes(bytes: &[u8]) -> Option<Self>;

    /// The external form.
    #[must_use]
    fn to_external(&self) -> String {
        format(Self::PREFIX, &self.body_bytes())
    }

    /// The identifier of an external form.
    ///
    /// # Errors
    /// [`InvalidId`] as [`parse`] returns it, and [`InvalidId::Body`] for bytes that do not form
    /// an identifier of the type.
    fn parse_external(text: &str) -> Result<Self, InvalidId> {
        Self::from_body_bytes(&parse(Self::PREFIX, text)?).ok_or(InvalidId::Body)
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

impl ExternalId for WorkId {
    const PREFIX: Prefix = Prefix::Work;

    fn body_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_body_bytes(bytes: &[u8]) -> Option<Self> {
        array(bytes).map(Self::from_bytes)
    }
}

impl ExternalId for RecordId {
    const PREFIX: Prefix = Prefix::Record;

    fn body_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn from_body_bytes(bytes: &[u8]) -> Option<Self> {
        array(bytes).map(|b| Self(Digest::sha256(b)))
    }
}

impl ExternalId for LedgerId {
    const PREFIX: Prefix = Prefix::Ledger;

    fn body_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn from_body_bytes(bytes: &[u8]) -> Option<Self> {
        array(bytes).map(|b| Self(Digest::sha256(b)))
    }
}

/// The raw bytes of a `PartyRef`, without a CBOR head (P-112 note, WD-104): the UTF-8 bytes of
/// the kernel's text form, so an Access `party-ref` becomes `pty_` and Access's own spelling.
#[must_use]
pub fn party_ref_bytes(party: &PartyRef) -> Vec<u8> {
    party.as_str().as_bytes().to_vec()
}

fn party_ref_of_bytes(bytes: &[u8]) -> Option<PartyRef> {
    PartyRef::new(core::str::from_utf8(bytes).ok()?)
}

impl ExternalId for PartyRef {
    const PREFIX: Prefix = Prefix::Party;

    fn body_bytes(&self) -> Vec<u8> {
        party_ref_bytes(self)
    }

    fn from_body_bytes(bytes: &[u8]) -> Option<Self> {
        party_ref_of_bytes(bytes)
    }
}

macro_rules! digest_id {
    ($(#[$doc:meta])* $name:ident, $prefix:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub RecordId);

        impl ExternalId for $name {
            const PREFIX: Prefix = Prefix::$prefix;

            fn body_bytes(&self) -> Vec<u8> {
                self.0.0.as_bytes().to_vec()
            }

            fn from_body_bytes(bytes: &[u8]) -> Option<Self> {
                array(bytes).map(|b| Self(RecordId(Digest::sha256(b))))
            }
        }
    };
}

digest_id!(
    /// A Commitment, by the record that opened it (T-89).
    CommitmentId,
    Commitment
);
digest_id!(
    /// A Condition, gates included, by the record that opened it (T-89).
    ConditionId,
    Condition
);
digest_id!(
    /// An Aim, by the record that opened it.
    AimId,
    Aim
);
digest_id!(
    /// A Reference, by the record that opened it.
    ReferenceId,
    Reference
);

/// A Practice package version, by its package digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PracticeId(pub Digest);

impl ExternalId for PracticeId {
    const PREFIX: Prefix = Prefix::Practice;

    fn body_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn from_body_bytes(bytes: &[u8]) -> Option<Self> {
        array(bytes).map(|b| Self(Digest::sha256(b)))
    }
}

macro_rules! row_id {
    ($(#[$doc:meta])* $name:ident, $prefix:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 16]);

        impl ExternalId for $name {
            const PREFIX: Prefix = Prefix::$prefix;

            fn body_bytes(&self) -> Vec<u8> {
                self.0.to_vec()
            }

            fn from_body_bytes(bytes: &[u8]) -> Option<Self> {
                array(bytes).map(Self)
            }
        }
    };
}

row_id!(
    /// An event subscription, by its internal `UUIDv7`.
    SubscriptionId,
    Subscription
);
row_id!(
    /// An export job, by its internal `UUIDv7`.
    ExportId,
    Export
);

macro_rules! token {
    ($(#[$doc:meta])* $name:ident, $prefix:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Wraps sealed token bytes; `None` when empty.
            #[must_use]
            pub fn new(bytes: Vec<u8>) -> Option<Self> {
                (!bytes.is_empty()).then_some(Self(bytes))
            }

            /// The sealed token bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl ExternalId for $name {
            const PREFIX: Prefix = Prefix::$prefix;

            fn body_bytes(&self) -> Vec<u8> {
                self.0.clone()
            }

            fn from_body_bytes(bytes: &[u8]) -> Option<Self> {
                Self::new(bytes.to_vec())
            }
        }
    };
}

token!(
    /// An opaque, sealed pagination and incremental sync cursor.
    Cursor,
    Cursor
);
token!(
    /// An opaque, sealed read position token (T-97).
    PositionToken,
    Position
);

/// An Access tenant in Access's own spelling; Work adds no prefix to it (P-112 item 4).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Wraps a non-empty Access tenant id.
    #[must_use]
    pub fn new(id: &str) -> Option<Self> {
        (!id.is_empty()).then(|| Self(String::from(id)))
    }

    /// The tenant id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The tenant id bytes, as a read position MAC binds them (T-97 item 1).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned as _;
    use alloc::format;
    use alloc::vec;

    use super::*;

    fn digest(byte: u8) -> Digest {
        Digest::sha256([byte; 32])
    }

    fn round_trip<T: ExternalId + PartialEq + core::fmt::Debug>(id: &T) -> String {
        let text = id.to_external();
        assert!(text.starts_with(T::PREFIX.as_str()), "{text}");
        assert_eq!(&T::parse_external(&text).unwrap(), id);
        text
    }

    // P-112
    #[test]
    fn p_112_every_prefix_round_trips_to_its_typed_id() {
        let record = RecordId(digest(0xab));
        let work = round_trip(&WorkId::from_bytes([0x0f; 16]));
        assert_eq!(work, "wrk_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        let rec = round_trip(&record);
        assert_eq!(rec.len(), 4 + 64);
        assert_eq!(rec, format!("rec_{}", "ab".repeat(32)));
        round_trip(&LedgerId(digest(1)));
        round_trip(&CommitmentId(record));
        round_trip(&ConditionId(record));
        round_trip(&AimId(record));
        round_trip(&ReferenceId(record));
        round_trip(&PracticeId(digest(2)));
        round_trip(&SubscriptionId([3; 16]));
        round_trip(&ExportId([4; 16]));
        round_trip(&PartyRef::new("party:acme:alice").unwrap());
        round_trip(&Cursor::new(vec![0xfb, 0xff, 0x00]).unwrap());
        let pos = round_trip(&PositionToken::new(vec![0xfb, 0xff]).unwrap());
        assert_eq!(pos, "pos_-_8");
        let prefixes: Vec<&str> = Prefix::ALL.into_iter().map(Prefix::as_str).collect();
        assert_eq!(
            prefixes,
            [
                "wrk_", "cmt_", "cnd_", "aim_", "ref_", "rec_", "led_", "pty_", "prc_", "sub_",
                "exp_", "cur_", "pos_"
            ]
        );
        assert!(
            Prefix::ALL
                .iter()
                .all(|p| Prefix::of(p.as_str()) == Some(*p))
        );
    }

    // P-112
    #[test]
    fn p_112_a_wrong_prefix_is_invalid_id() {
        let commitment = CommitmentId(RecordId(digest(5))).to_external();
        assert_eq!(
            ConditionId::parse_external(&commitment),
            Err(InvalidId::OtherType {
                expected: Prefix::Condition,
                found: Prefix::Commitment
            })
        );
        let body = commitment.trim_start_matches("cmt_");
        for text in [
            format!("abc_{body}"),
            format!("CMT_{body}"),
            format!("cmt{body}"),
            body.to_owned(),
            String::new(),
        ] {
            assert_eq!(
                CommitmentId::parse_external(&text),
                Err(InvalidId::UnknownPrefix),
                "{text}"
            );
        }
        for error in [
            InvalidId::UnknownPrefix,
            InvalidId::Body,
            InvalidId::OtherType {
                expected: Prefix::Work,
                found: Prefix::Record,
            },
        ] {
            assert_eq!(error.code(), "invalid_id");
        }
    }

    // P-112
    #[test]
    fn p_112_uppercase_hex_is_invalid_id() {
        let work = WorkId::from_bytes([0xab; 16]).to_external();
        assert_eq!(
            WorkId::parse_external(&work.to_uppercase().replacen("WRK_", "wrk_", 1)),
            Err(InvalidId::Body)
        );
        for text in [
            "wrk_",
            "wrk_abab",
            "wrk_ababababababababababababababababab",
            "wrk_abababababababababababababababaG",
            "wrk_ababababababababababababababab ",
        ] {
            assert_eq!(WorkId::parse_external(text), Err(InvalidId::Body), "{text}");
        }
        for text in ["pos_", "pos_-_8=", "pos_-_9", "pos_-+8", "pos_a"] {
            assert_eq!(
                PositionToken::parse_external(text),
                Err(InvalidId::Body),
                "{text}"
            );
        }
    }

    // P-112
    #[test]
    fn p_112_pty_body_is_the_partyref_bytes() {
        let short = PartyRef::new("p:a").unwrap();
        assert_eq!(party_ref_bytes(&short), b"p:a");
        assert_eq!(short.to_external(), "pty_cDph");
        let long = PartyRef::new(&"x".repeat(24)).unwrap();
        assert_eq!(party_ref_bytes(&long), "x".repeat(24).as_bytes());
        assert_eq!(long.to_external(), format!("pty_{}", "eHh4".repeat(8)));
        assert_eq!(PartyRef::parse_external(&long.to_external()), Ok(long));
        let max = PartyRef::new(&"y".repeat(255)).unwrap();
        assert_eq!(PartyRef::parse_external(&max.to_external()), Ok(max));
        for bytes in [vec![0xff, 0xfe], vec![0x63, 0xff], vec![b'y'; 256]] {
            let text = format(Prefix::Party, &bytes);
            assert_eq!(
                PartyRef::parse_external(&text),
                Err(InvalidId::Body),
                "{bytes:?}"
            );
        }
    }
}
