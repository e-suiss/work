//! Rule sets keyed by protocol version: a record is evaluated only with the rules of the protocol version its `versions` vector carries, so an old record is never reinterpreted under newer rules and a record of a version this kernel does not know is quarantined, never judged (T-4 rule 4, P-18, P-87).

use crate::record::{ProtocolVersion, Record};

/// The record and derivation rules of one protocol version (T-4 rule 4, P-87).
///
/// There is no public way to apply a rule set to a record: [`crate::validate::validate`] and [`crate::derive::derive`] select it with [`RuleSet::of`], from the record alone; a decoder asks [`RuleSet::for_version`] first, so a record of an unknown version is quarantined before it is mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RuleSet {
    /// Protocol 1.0: the Stage 1 record and derivation rules.
    V1_0,
}

impl RuleSet {
    /// Every rule set this kernel carries, oldest first; a new protocol version adds a set and never changes an earlier one.
    pub const ALL: &'static [Self] = &[Self::V1_0];

    /// The protocol version whose rules this set holds.
    #[must_use]
    pub const fn protocol(self) -> ProtocolVersion {
        match self {
            Self::V1_0 => ProtocolVersion { major: 1, minor: 0 },
        }
    }

    /// The rule set of exactly this protocol version; `None` when this kernel does not carry it and the record is quarantined as `protocol_version_unknown` (P-87).
    #[must_use]
    pub fn for_version(version: ProtocolVersion) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.protocol() == version)
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
        for (major, minor) in [(1, 1), (2, 0), (0, 9), (u64::MAX, 0)] {
            assert_eq!(RuleSet::for_version(ProtocolVersion { major, minor }), None);
        }
    }
}
