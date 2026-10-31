use suiss_crypto::dcbor::{self, EncodeError, Limits, Value};
use suiss_crypto::digest::{Digest, leaf_hash};
use suiss_ledger::Hash;
use suiss_ledger::sequencer::{Entry, Slot};
use work_store::{CallerRef, IdempotencyKey, ItemRef, LedgerId};

/// An admitted record waiting for its slot: what the sequencer needs to seal its
/// `LedgerEnvelope` (P-11) and to write its item heads and outbox pointers in the same
/// transaction (T-81).
#[derive(Clone, PartialEq, Eq)]
pub struct PendingRecord {
    /// The record id, the unprefixed SHA-256 of the `SignedRecord` bytes (P-79).
    pub record_id: [u8; 32],
    /// The record bytes stored in the log.
    pub record_bytes: Vec<u8>,
    /// The envelope `actor_type` annotation, as det-CBOR value (P-12).
    pub actor_type: Value,
    /// The digest of the author signature bytes (P-75).
    pub proof_commit: Option<[u8; 32]>,
    /// The Access authentication context reference (P-21).
    pub auth_context: Option<Value>,
    /// The envelope `ingest` value (P-11).
    pub ingest: Value,
    /// The item heads the record moves (P-29).
    pub items: Vec<ItemChange>,
    /// The outbox pointers the record emits, one per affected item (T-81 item 2).
    pub outbox: Vec<EventPointer>,
    /// The idempotency key of the request the record answers (OP-8).
    pub idempotency: Option<KeyClaim>,
}

/// The idempotency key a fresh request carries, written with its record (OP-8, OP-36).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyClaim {
    /// The caller the key belongs to.
    pub caller: CallerRef,
    /// The key.
    pub key: IdempotencyKey,
    /// The digest of the request.
    pub request_digest: [u8; 32],
}

impl std::fmt::Debug for PendingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRecord")
            .field("record_bytes", &self.record_bytes.len())
            .field("items", &self.items.len())
            .field("outbox", &self.outbox.len())
            .finish_non_exhaustive()
    }
}

/// A change of one item head (P-29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemChange {
    /// The item.
    pub item: ItemRef,
    /// Its version after the record; 1 for a new item.
    pub version: u64,
    /// Chain heads of a Commitment or Condition; `None` for a Work.
    pub heads: Option<Vec<[u8; 32]>>,
}

/// One outbox pointer of a record (T-17, T-81).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPointer {
    /// The event id.
    pub event_id: String,
    /// The event type.
    pub event_type: String,
    /// The W3C `traceparent` of the request (P-42).
    pub traceparent: String,
    /// The affected item.
    pub item: ItemRef,
    /// Its version after the record, the event `seq`.
    pub version: u64,
}

/// A record sealed into its slot: the envelope bytes the leaf hash covers.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedRecord {
    /// The det-CBOR `LedgerEnvelope`.
    pub envelope: Vec<u8>,
    /// The record it seals.
    pub record: PendingRecord,
}

impl std::fmt::Debug for SealedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedRecord")
            .field("envelope", &self.envelope.len())
            .field("record", &self.record)
            .finish()
    }
}

/// A pending record bound to the ledger it is written to.
pub(crate) struct Bound<'a> {
    pub(crate) ledger: &'a LedgerId,
    pub(crate) record: &'a PendingRecord,
}

fn digest(bytes: &[u8; 32]) -> Value {
    Digest(*bytes).to_value()
}

/// The `LedgerEnvelope` of `record` at `slot` (P-11, P-75, P-100 item 4).
pub(crate) fn envelope(ledger: &LedgerId, record: &PendingRecord, slot: &Slot) -> Value {
    let mut entries = vec![
        (Value::text("record"), digest(&record.record_id)),
        (Value::text("ledger"), digest(ledger.as_bytes())),
        (Value::text("pos"), Value::Unsigned(slot.pos)),
        (
            Value::text("recorded_at"),
            Value::Unsigned(slot.recorded_at),
        ),
        (Value::text("prev"), digest(&slot.prev)),
        (Value::text("actor_type"), record.actor_type.clone()),
        (Value::text("ingest"), record.ingest.clone()),
    ];
    if let Some(p) = &record.proof_commit {
        entries.push((Value::text("proof_commit"), digest(p)));
    }
    if let Some(a) = &record.auth_context {
        entries.push((Value::text("auth_context"), a.clone()));
    }
    Value::Map(entries)
}

impl Entry for Bound<'_> {
    type Sealed = SealedRecord;
    type Error = EncodeError;

    fn seal(&self, slot: &Slot) -> Result<(Hash, SealedRecord), EncodeError> {
        let bytes = dcbor::encode(&envelope(self.ledger, self.record, slot), Limits::CEILING)?;
        Ok((
            leaf_hash(&bytes),
            SealedRecord {
                envelope: bytes,
                record: self.record.clone(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "test code"
    )]

    use suiss_crypto::dcbor::decode;

    use super::*;

    const RECORDS: &str = include_str!("../../../conformance/vectors/records/records.json");

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn digest32(v: Option<&Value>) -> [u8; 32] {
        Digest::from_value(v.unwrap()).unwrap().0
    }

    // P-11 P-75 P-100 P-101 T-74
    #[test]
    fn p_100_every_golden_envelope_is_sealed_from_its_slot() {
        let file: serde_json::Value = serde_json::from_str(RECORDS).unwrap();
        for case in file["envelopes"].as_array().unwrap() {
            let bytes = hex(case["hex"].as_str().unwrap());
            let v = decode(&bytes, Limits::CEILING).unwrap();
            let Value::Unsigned(pos) = v.get("pos").unwrap() else {
                panic!("pos")
            };
            let Value::Unsigned(recorded_at) = v.get("recorded_at").unwrap() else {
                panic!("recorded_at")
            };
            let slot = Slot {
                pos: *pos,
                prev: digest32(v.get("prev")),
                recorded_at: *recorded_at,
            };
            let ledger = LedgerId::from_bytes(digest32(v.get("ledger")));
            let record = PendingRecord {
                record_id: digest32(v.get("record")),
                record_bytes: vec![0xa0],
                actor_type: v.get("actor_type").unwrap().clone(),
                proof_commit: v.get("proof_commit").map(|p| digest32(Some(p))),
                auth_context: v.get("auth_context").cloned(),
                ingest: v.get("ingest").unwrap().clone(),
                items: vec![],
                outbox: vec![],
                idempotency: None,
            };
            let (leaf, sealed) = Bound {
                ledger: &ledger,
                record: &record,
            }
            .seal(&slot)
            .unwrap();
            assert_eq!(sealed.envelope, bytes, "{}", case["id"]);
            assert_eq!(leaf.to_vec(), hex(case["leaf_hash"].as_str().unwrap()));
        }
    }
}
