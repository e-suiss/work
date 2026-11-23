use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::catalog::DeclarationSubtype;
use crate::derive::{Derivation, Effect, Entry};
use crate::id::RecordId;
use crate::record::Record;

/// One version of a versioned Declaration chain; the chain root is its identity (RC-10, RC-48).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Version<'r> {
    pub(crate) root: RecordId,
    pub(crate) id: RecordId,
    pub(crate) position: u64,
    pub(crate) record: &'r Record,
}

pub(crate) fn subtype_of(record: &Record) -> Option<DeclarationSubtype> {
    match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str()),
        Record::Act(_) | Record::Claim(_) => None,
    }
}

/// The versions of every chain of `subtype` with normative effect, in ledger order; a record whose first superseded record is no version of such a chain starts none.
pub(crate) fn versions<'r>(
    entries: &[Entry<'r>],
    derivation: &Derivation,
    subtype: DeclarationSubtype,
) -> Vec<Version<'r>> {
    let mut roots: BTreeMap<RecordId, RecordId> = BTreeMap::new();
    let mut out = Vec::new();
    for (entry, derived) in entries.iter().zip(&derivation.records) {
        let record = entry.record();
        if derived.id != entry.id()
            || derived.effect != Effect::Normative
            || subtype_of(record) != Some(subtype)
        {
            continue;
        }
        let root = match record.supersedes().next() {
            None => entry.id(),
            Some(target) => match roots.get(target) {
                Some(root) => *root,
                None => continue,
            },
        };
        roots.insert(entry.id(), root);
        out.push(Version {
            root,
            id: entry.id(),
            position: entry.position(),
            record,
        });
    }
    out
}
