//! Rule sets keyed by protocol version: a record is evaluated only with the rules of the protocol version its `versions` vector carries, so an old record is never reinterpreted under newer rules and a record of a version this kernel does not know is quarantined, never judged (T-4 rule 4, P-18, P-87).

use crate::id::Digest;
use crate::record::{ProtocolVersion, Record};

/// The SHA-256 of `conformance/cddl/work-record.cddl`, the normative CDDL of protocol 1.0 (P-100 item 7, P-110 item 8).
const V1_0_SCHEMA: [u8; 32] = [
    0xcc, 0x12, 0xd1, 0x28, 0x5b, 0x54, 0xb4, 0x2d, 0xb7, 0x38, 0xfe, 0x4b, 0x1f, 0x3a, 0x6e, 0x47,
    0xfa, 0x64, 0xd8, 0x49, 0xd3, 0x53, 0xed, 0x6c, 0xb2, 0x6f, 0xd3, 0xf7, 0x6d, 0x1c, 0x00, 0xd6,
];

/// The record and derivation rules of one protocol version (T-4 rule 4, P-87).
///
/// There is no public way to apply a rule set to a record: [`crate::validate::validate`] and [`crate::derive::derive`] select it with [`RuleSet::of`], from the record alone; a decoder asks [`RuleSet::for_version`] first, so a record of an unknown version is quarantined before it is mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RuleSet {
    /// Protocol 1.0: the Stage 1 record and derivation rules.
    V1_0,
    /// The rules of protocol 1.0 under the version value 1.1, for the kernel's own tests of an activation's positive path only; it is in neither [`RuleSet::ALL`] nor any build outside them (P-110 item 10).
    #[cfg(test)]
    TestV1_1,
}

impl RuleSet {
    /// Every rule set this kernel carries, oldest first; a new protocol version adds a set and never changes an earlier one.
    pub const ALL: &'static [Self] = &[Self::V1_0];

    #[cfg(not(test))]
    const KNOWN: &'static [Self] = Self::ALL;

    #[cfg(test)]
    const KNOWN: &'static [Self] = &[Self::V1_0, Self::TestV1_1];

    /// The protocol version whose rules this set holds.
    #[must_use]
    pub const fn protocol(self) -> ProtocolVersion {
        match self {
            Self::V1_0 => ProtocolVersion { major: 1, minor: 0 },
            #[cfg(test)]
            Self::TestV1_1 => ProtocolVersion { major: 1, minor: 1 },
        }
    }

    /// The digest of the normative CDDL bytes of the set's protocol version, which a genesis or activation of that version must carry as its `schema` (P-100 item 7, P-110 items 6, 8).
    #[must_use]
    pub const fn schema(self) -> Digest {
        match self {
            Self::V1_0 => Digest::sha256(V1_0_SCHEMA),
            #[cfg(test)]
            Self::TestV1_1 => Digest::sha256([0x11; 32]),
        }
    }

    /// The rule set of exactly this protocol version; `None` when this kernel does not carry it and the record is quarantined as `protocol_version_unknown` (P-87).
    #[must_use]
    pub fn for_version(version: ProtocolVersion) -> Option<Self> {
        Self::KNOWN
            .iter()
            .copied()
            .find(|r| r.protocol() == version)
    }

    /// The rule set of the protocol version the record carries (P-87).
    #[must_use]
    pub fn of(record: &Record) -> Option<Self> {
        Self::for_version(record.core().versions.protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::schema_digest;

    const CDDL: &[u8] = include_bytes!("../../../conformance/cddl/work-record.cddl");

    // T-4 P-87
    #[test]
    fn t_4_rule_sets_are_ordered_and_unique_by_protocol_version() {
        assert!(
            RuleSet::ALL
                .windows(2)
                .all(|w| matches!(w, [a, b] if a.protocol() < b.protocol()))
        );
        assert_eq!(
            RuleSet::V1_0.protocol(),
            ProtocolVersion { major: 1, minor: 0 }
        );
    }

    // P-87
    #[test]
    fn p_87_rule_set_is_decided_from_the_version_alone() {
        for set in RuleSet::ALL {
            assert_eq!(RuleSet::for_version(set.protocol()), Some(*set));
        }
        for (major, minor) in [(2, 0), (0, 9), (u64::MAX, 0)] {
            assert_eq!(RuleSet::for_version(ProtocolVersion { major, minor }), None);
        }
    }

    // P-100 P-110
    #[test]
    fn p_110_the_1_0_schema_is_the_digest_of_the_normative_cddl() {
        assert_eq!(RuleSet::V1_0.schema(), schema_digest(CDDL));
        assert!(!RuleSet::ALL.contains(&RuleSet::TestV1_1));
        assert_ne!(RuleSet::TestV1_1.schema(), RuleSet::V1_0.schema());
    }
}
