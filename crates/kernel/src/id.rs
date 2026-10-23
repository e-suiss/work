//! Typed identifiers and opaque shared primitives (C-35, P-67); none of them encodes a location, region, cell or tenant, and the byte forms of `PartyRef`, `Digest` and `Time` stay opaque until Access fixes them.

use alloc::string::String;
use core::cmp::Ordering;

/// A SHA-256 digest carrying the algorithm label `-16` on the wire (P-5, P-67).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Wraps a SHA-256 value; computing it belongs to the shared crypto crate (P-8).
    #[must_use]
    pub const fn sha256(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// The 32 digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The identifier of a record: the digest of its `SignedRecord` bytes (P-6, P-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(pub Digest);

/// The identifier of a ledger: its genesis digest (C-35, P-67).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LedgerId(pub Digest);

/// An opaque 16-byte Work identifier (C-8, C-35, P-67).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkId([u8; 16]);

impl WorkId {
    /// Wraps 16 opaque bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// An Access Party reference; its byte form is pending Access (P-67), the draft is 1 to 255 bytes of text, ordered as its canonical CBOR encoding orders (P-72).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PartyRef(String);

impl Ord for PartyRef {
    fn cmp(&self, other: &Self) -> Ordering {
        canonical_text_cmp(&self.0, &other.0)
    }
}

impl PartialOrd for PartyRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartyRef {
    /// Longest accepted reference, in bytes.
    pub const MAX_LEN: usize = 255;

    /// Wraps a reference of 1 to 255 bytes.
    #[must_use]
    pub fn new(value: &str) -> Option<Self> {
        (!value.is_empty() && value.len() <= Self::MAX_LEN).then(|| Self(String::from(value)))
    }

    /// The reference text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A point in time as untagged Unix epoch milliseconds (P-27, P-67).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(pub u64);

/// Orders two text values as their canonical CBOR encodings order: shorter first, then bytewise (P-5, P-72).
#[must_use]
pub fn canonical_text_cmp(a: &str, b: &str) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // C-35
    #[test]
    fn c_35_work_id_is_sixteen_opaque_bytes() {
        let id = WorkId::from_bytes([7; 16]);
        assert_eq!(id.as_bytes(), &[7; 16]);
    }

    // P-67
    #[test]
    fn p_67_party_ref_is_one_to_255_bytes() {
        assert!(PartyRef::new("").is_none());
        assert!(PartyRef::new(&"a".repeat(255)).is_some());
        assert!(PartyRef::new(&"a".repeat(256)).is_none());
    }

    // P-72 P-77
    #[test]
    fn p_72_party_refs_order_canonically() {
        let short = PartyRef::new("party:x:zz").unwrap();
        let long = PartyRef::new("party:x:aaa").unwrap();
        assert!(short < long);
        assert_eq!(short.cmp(&short.clone()), Ordering::Equal);
    }

    // P-72
    #[test]
    fn p_72_text_orders_by_encoded_length_first() {
        assert_eq!(canonical_text_cmp("zz", "aaa"), Ordering::Less);
        assert_eq!(canonical_text_cmp("ab", "aa"), Ordering::Greater);
        assert_eq!(canonical_text_cmp("ab", "ab"), Ordering::Equal);
    }
}
