use suiss_crypto::dcbor::{self, EncodeError, Limits, Value};
use suiss_crypto::digest::{Digest, leaf_hash, sha256};
use suiss_ledger::Hash;
use suiss_ledger::sequencer::{Entry, Slot};
use work_store::{
    BodyPartRow, CallerRef, Expect, IdempotencyKey, ItemRef, LedgerId, ReceivedRow, Skeleton,
    Stored,
};

/// An admitted record waiting for its slot: what the sequencer needs to seal its
/// `LedgerEnvelope` (P-11) and to write, in the same transaction, the bytes it was received as,
/// its skeleton, its item heads and outbox pointers (T-81, T-89, T-90). Only the admission path
/// builds one, from the kernel's verification, validation and [`work_kernel::items::touched`].
#[derive(Clone, PartialEq, Eq)]
pub struct PendingRecord {
    /// The `SignedRecord` bytes stored in the log; the record id is computed from them.
    pub(crate) record_bytes: Vec<u8>,
    /// The envelope `actor_type` annotation, as det-CBOR value (P-12).
    pub(crate) actor_type: Value,
    /// The digest of the author signature bytes (P-75).
    pub(crate) proof_commit: Option<[u8; 32]>,
    /// The Access authentication context reference (P-21).
    pub(crate) auth_context: Option<Value>,
    /// The envelope `ingest` value (P-11).
    pub(crate) ingest: Value,
    /// The externally signed bytes as received, the author signature among them (T-90).
    pub(crate) received: Vec<ReceivedRow>,
    /// The skeleton of a decoded record (OP-13).
    pub(crate) skeleton: Option<Skeleton>,
    /// The encrypted body parts, sealed against the skeleton's commitments (OP-45).
    pub(crate) body: Vec<BodyPartRow>,
    /// The items the record touches (T-89).
    pub(crate) items: Vec<ItemTouch>,
    /// The outbox pointers the record emits, one per touched item (T-81 item 2).
    pub(crate) outbox: Vec<EventPointer>,
    /// The idempotency key of the request the record answers (OP-8).
    pub(crate) idempotency: Option<KeyClaim>,
    /// The inbound event the record answers (OP-8, OP-38 item 5).
    pub(crate) inbound: Option<Inbound>,
    /// `params.effective_at` of a Declaration, checked against the ledger time the sequencer
    /// assigns (P-27, P-80).
    pub(crate) effective_at: Option<u64>,
}

/// An inbound event or federated record by its source and id (OP-8, P-35 item 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// The event source.
    pub source: String,
    /// The event id at the source.
    pub source_id: String,
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

impl PendingRecord {
    /// The record id, the unprefixed SHA-256 of the `SignedRecord` bytes, recomputed and never taken from the caller (P-79, T-10).
    #[must_use]
    pub fn record_id(&self) -> [u8; 32] {
        sha256(&self.record_bytes)
    }

    /// The items the record touches (T-89).
    #[must_use]
    pub fn items(&self) -> &[ItemTouch] {
        &self.items
    }

    /// The outbox pointers the record emits (T-81).
    #[must_use]
    pub fn outbox(&self) -> &[EventPointer] {
        &self.outbox
    }

    /// The bytes the record was received as (T-90).
    #[must_use]
    pub fn received(&self) -> &[ReceivedRow] {
        &self.received
    }

    /// The skeleton of a decoded record.
    #[must_use]
    pub const fn skeleton(&self) -> Option<&Skeleton> {
        self.skeleton.as_ref()
    }

    /// The encrypted body parts (OP-45).
    #[must_use]
    pub fn body(&self) -> &[BodyPartRow] {
        &self.body
    }

    /// The bytes a group commit counts for the record: the record, what it was received as and
    /// its inline body ciphertexts (OP-31 item 2, T-90, OP-45).
    #[must_use]
    pub fn size(&self) -> usize {
        let received = self.received.iter().fold(self.record_bytes.len(), |n, r| {
            n.saturating_add(r.bytes.len())
        });
        self.body.iter().fold(received, |n, p| match &p.stored {
            Stored::Inline(c) => n.saturating_add(c.len()),
            Stored::Object(_) => n,
        })
    }
}

impl std::fmt::Debug for PendingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRecord")
            .field("record_bytes", &self.record_bytes.len())
            .field("items", &self.items.len())
            .field("outbox", &self.outbox.len())
            .field("body", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// One item a record touches (T-89): its version is assigned by the sequencer in the append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemTouch {
    /// The item.
    pub item: ItemRef,
    /// What the stored head must be.
    pub expect: Expect,
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
    /// The affected item; the event `seq` is the version the same append writes to its head.
    pub item: ItemRef,
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
        (Value::text("record"), digest(&record.record_id())),
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
        let signed_cases = file["records"].as_array().unwrap();
        let envelopes = file["envelopes"].as_array().unwrap();
        for (signed, case) in signed_cases.iter().zip(envelopes) {
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
                record_bytes: hex(signed["hex"].as_str().unwrap()),
                actor_type: v.get("actor_type").unwrap().clone(),
                proof_commit: v.get("proof_commit").map(|p| digest32(Some(p))),
                auth_context: v.get("auth_context").cloned(),
                ingest: v.get("ingest").unwrap().clone(),
                received: vec![],
                skeleton: None,
                body: vec![],
                items: vec![],
                outbox: vec![],
                idempotency: None,
                inbound: None,
                effective_at: None,
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

    // P-79 T-10
    #[test]
    fn t_10_the_pending_record_id_is_recomputed_from_its_bytes() {
        let file: serde_json::Value = serde_json::from_str(RECORDS).unwrap();
        let signed = &file["records"][0];
        let mut record = PendingRecord {
            record_bytes: hex(signed["hex"].as_str().unwrap()),
            actor_type: Value::Map(vec![]),
            proof_commit: None,
            auth_context: None,
            ingest: Value::text("admitted"),
            received: vec![],
            skeleton: None,
            body: vec![],
            items: vec![],
            outbox: vec![],
            idempotency: None,
            inbound: None,
            effective_at: None,
        };
        let expected = decode(
            &hex(signed["record_digest"].as_str().unwrap()),
            Limits::CEILING,
        );
        assert_eq!(record.record_id(), digest32(expected.as_ref().ok()));
        record.record_bytes.push(0);
        assert_ne!(record.record_id(), digest32(expected.as_ref().ok()));
    }
}
