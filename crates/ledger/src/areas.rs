//! The Commitment and Condition conflict areas a ledger's records leave (T-89 items 3, 6, OP-7, P-28): replaying the log in position order gives, for every area, the version and chain heads the sequencer stored and the records that touched it; a record that opens a Commitment or Condition touches its new area at version 0, a record whose first superseded record touched an area touches that area at its stored version, and its heads are the heads it did not see by `basis` or `supersedes` with the record itself. The live admission and the rebuild read the same replay, so both write the same item heads.

use std::collections::BTreeMap;

use work_kernel::codec::{Decoded, decode_record, record_id};
use work_kernel::id::RecordId;
use work_kernel::items::{Area, Expect, ItemKey, Touch, touched_in};
use work_kernel::record::Record;

/// The conflict areas of one ledger, as its records left them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Areas {
    member: BTreeMap<RecordId, ItemKey>,
    stored: BTreeMap<ItemKey, (u64, Vec<RecordId>)>,
}

impl Areas {
    /// The area record `target` touched, at its stored version and heads.
    #[must_use]
    pub fn area_of(&self, target: &RecordId) -> Option<Area> {
        let item = self.member.get(target)?;
        let (version, heads) = self.stored.get(item)?;
        Some(Area {
            item: *item,
            version: *version,
            heads: heads.clone(),
        })
    }

    /// The stored version of `item`, 0 before its first record.
    #[must_use]
    pub fn version(&self, item: &ItemKey) -> u64 {
        self.stored.get(item).map_or(0, |(v, _)| *v)
    }

    /// The items record `id` touches over these areas (T-89).
    #[must_use]
    pub fn touches(&self, record: &Record, id: RecordId) -> Vec<Touch> {
        touched_in(record, id, &|target: &RecordId| self.area_of(target))
    }

    /// Keeps the area touches of record `id` as the sequencer stores them: the version after the
    /// record and its heads.
    pub fn keep(&mut self, id: RecordId, touches: &[Touch]) {
        for t in touches {
            let Some(heads) = &t.heads else {
                continue;
            };
            let version = match t.expect {
                Expect::Version(v) => v.saturating_add(1),
                Expect::Next => self.version(&t.item).saturating_add(1),
            };
            self.stored.insert(t.item, (version, heads.clone()));
            self.member.insert(id, t.item);
        }
    }

    /// Replays the stored `SignedRecord` bytes of the next log entry; a record of a protocol
    /// version without a rule set touches no area.
    pub fn replay(&mut self, record_bytes: &[u8]) {
        if let Ok(Decoded::Record(record)) = decode_record(record_bytes) {
            let id = record_id(record_bytes);
            let touches = self.touches(&record, id);
            self.keep(id, &touches);
        }
    }
}

#[cfg(test)]
mod tests {
    use work_kernel::id::Digest;

    use super::*;

    fn id(n: u8) -> RecordId {
        RecordId(Digest::sha256([n; 32]))
    }

    fn opening(n: u8) -> Touch {
        Touch {
            item: ItemKey::Commitment(id(n)),
            expect: Expect::Version(0),
            heads: Some(vec![id(n)]),
        }
    }

    // T-89 OP-7 P-28
    #[test]
    fn t_89_an_area_keeps_the_version_and_heads_the_sequencer_stores() {
        let mut areas = Areas::default();
        assert_eq!(areas.area_of(&id(1)), None);
        areas.keep(id(1), &[opening(1)]);
        let item = ItemKey::Commitment(id(1));
        assert_eq!(areas.version(&item), 1);
        assert_eq!(
            areas.area_of(&id(1)),
            Some(Area {
                item,
                version: 1,
                heads: vec![id(1)],
            })
        );
        let next = Touch {
            item,
            expect: Expect::Version(1),
            heads: Some(vec![id(2)]),
        };
        let work = Touch {
            item: ItemKey::Work(work_kernel::id::WorkId::from_bytes([7; 16])),
            expect: Expect::Next,
            heads: None,
        };
        areas.keep(id(2), &[work, next]);
        assert_eq!(areas.version(&item), 2);
        assert_eq!(areas.area_of(&id(1)).map(|a| a.heads), Some(vec![id(2)]));
        assert_eq!(areas.area_of(&id(2)).map(|a| a.version), Some(2));
        assert_eq!(areas.area_of(&id(3)), None);
    }
}
