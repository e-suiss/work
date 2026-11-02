//! The work items a record touches, read from its signed core fields only (T-89, P-29, OP-7): the sequencer writes one item head per touch in the record's append transaction and takes the version it writes as the outbox `seq` (T-81); until the Commitment and Condition lifecycles exist, a record touches each Work it concerns, in `concerns` order, whatever its `ingest`.

use alloc::vec::Vec;

use crate::id::{RecordId, WorkId};
use crate::record::Record;

/// A work item whose version the sequencer keeps (P-29).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ItemKey {
    /// A Work.
    Work(WorkId),
    /// A Commitment, by the record that opened it.
    Commitment(RecordId),
    /// A Condition, by the record that opened it.
    Condition(RecordId),
}

/// What the sequencer expects of the stored item head (T-89, OP-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Expect {
    /// The next version: the stored version plus one, or 1 for a new item; never refused.
    Next,
    /// The stored version must be this one, 0 for an item not stored yet; otherwise the record is refused with an item conflict.
    Version(u64),
}

/// One item a record touches (T-89).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Touch {
    /// The item.
    pub item: ItemKey,
    /// What the stored head must be.
    pub expect: Expect,
    /// The chain heads of a Commitment or Condition after the record; `None` for a Work.
    pub heads: Option<Vec<RecordId>>,
}

/// The items `record` touches, from its signed core fields only (T-89): one [`Expect::Next`] Work touch per `concerns` entry, in `concerns` order.
#[must_use]
pub fn touched(record: &Record) -> Vec<Touch> {
    record
        .core()
        .concerns
        .iter()
        .map(|work| Touch {
            item: ItemKey::Work(*work),
            expect: Expect::Next,
            heads: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::id::{Digest, LedgerId, PartyRef, Time};
    use crate::record::{
        Audience, Claim, ClaimType, ProtocolVersion, RecordCore, VersionVector, Visibility,
    };

    fn claim(concerns: Vec<WorkId>) -> Record {
        Record::Claim(Claim {
            subtype: ClaimType::Core(crate::catalog::ClaimSubtype::Observation),
            occurred_at: Time(1),
            core: RecordCore {
                author: PartyRef::new("party:acme:alice").unwrap(),
                on_behalf_of: None,
                capacity: None,
                basis: None,
                visibility: Visibility {
                    see: Audience::Work,
                    search_excluded: false,
                    agent_context_excluded: false,
                },
                ledger: LedgerId(Digest::sha256([1; 32])),
                concerns,
                relations: None,
                authority: None,
                producer: None,
                correlation: None,
                evidence: None,
                body: None,
                params: None,
                versions: VersionVector {
                    protocol: ProtocolVersion { major: 1, minor: 0 },
                    schema: Digest::sha256([2; 32]),
                    practices: None,
                },
                ext: None,
                critical: None,
            },
        })
    }

    // T-89 P-29 C-34
    #[test]
    fn t_89_each_concerned_work_is_touched_once_in_concerns_order() {
        let a = WorkId::from_bytes([1; 16]);
        let b = WorkId::from_bytes([2; 16]);
        let touches = touched(&claim(vec![a, b]));
        assert_eq!(
            touches,
            vec![
                Touch {
                    item: ItemKey::Work(a),
                    expect: Expect::Next,
                    heads: None,
                },
                Touch {
                    item: ItemKey::Work(b),
                    expect: Expect::Next,
                    heads: None,
                },
            ]
        );
    }

    // T-89 T-81
    #[test]
    fn t_89_a_record_that_concerns_no_work_touches_nothing() {
        assert!(touched(&claim(vec![])).is_empty());
    }
}
