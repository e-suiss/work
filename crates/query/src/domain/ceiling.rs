//! The attention an `agent.ceiling_exceeded` event raises (E-23, P-114 item 2, RC-31): the tenant's Work service system Party writes, with `origin = automation`, an `observation` Claim into the ledger of the record Work sent with the Relay intent, resting on that record as its `basis`, visible to that record's author, concerning its Works, naming the Relay event as an external reference (`urn:suiss:relay:event:<id>:sha-256:<digest of source and id>`) and carrying the agent and the event as the [`NOTICE_EXT_KEY`] extension. A Declaration needs an Access decision receipt Work's service Party does not hold, so the attention is this Claim, and the attributable decision is the caller's `acknowledgement` whose `basis` cites it. Without the record it rests on nothing is written.

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::sha256;
use work_access_client::domain::b64url;
use work_kernel::catalog::ClaimSubtype;
use work_kernel::codec::{Decoded, decode_record};
use work_kernel::id::{LedgerId, PartyRef, RecordId, WorkId};
use work_kernel::record::{ClaimType, Record};
use work_kernel::uri::{CORE_ROOT, ExternalRef};

use crate::domain::kinds::{MAX_CEILING_AGENT, MAX_CEILING_EVENT};

/// The extension key of the attention body.
pub const NOTICE_EXT_KEY: &str = "https://suiss.app/ns/work/agent-ceiling/1";

/// The CDDL of the attention body; the record's `versions.schema` is its SHA-256.
pub const NOTICE_CDDL: &str = r"; E-23 P-114

agent-ceiling = {
  event: tstr .size (1..512),
  source: tstr .size (1..512),
  ? agent: tstr .size (1..256),
}
";

/// The external reference prefix of a Relay event.
pub const EVENT_PREFIX: &str = "urn:suiss:relay:event:";

/// The protocol version the attention is written under.
pub const PROTOCOL: (u64, u64) = (1, 0);

/// Why no attention can be written for an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NoticeRefusal {
    /// The event carries no `correlationid` naming a record Work sent (P-114 item 2).
    #[error("the event names no record of Work")]
    Basis,
    /// The event id, its source or its agent cannot be written.
    #[error("the event cannot be written: {0}")]
    Event(&'static str),
    /// The record would not decode as the attention.
    #[error("the attention does not encode")]
    Record,
}

/// What the attention is written from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoticeInput {
    /// The tenant's Work service system Party.
    pub author: PartyRef,
    /// The ledger of the record it rests on.
    pub ledger: LedgerId,
    /// The record Work sent with the intent.
    pub basis: RecordId,
    /// That record's author, who decides; `None` when it is the service Party itself.
    pub audience: Option<PartyRef>,
    /// The Works that record concerns, ascending.
    pub concerns: Vec<WorkId>,
    /// The Relay event's `id`.
    pub event: String,
    /// The Relay event's `source`.
    pub source: String,
    /// The agent, `agt_…`, when the event names one.
    pub agent: Option<String>,
    /// When Work took the event, Unix milliseconds.
    pub at_ms: u64,
}

/// The record a `correlationid` names: 64 lower-case hex digits of its id (T-99 item 7).
#[must_use]
pub fn basis_of(correlation: &str) -> Option<RecordId> {
    let bytes = correlation.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (o, pair) in out.iter_mut().zip(bytes.chunks(2)) {
        let [hi, lo] = pair else {
            return None;
        };
        let digit = |c: u8| match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a').and_then(|d| d.checked_add(10)),
            _ => None,
        };
        *o = digit(*hi)?.checked_mul(16)?.checked_add(digit(*lo)?)?;
    }
    Some(RecordId(work_kernel::id::Digest::sha256(out)))
}

/// The author and the Works of the record `bytes`, the `SignedRecord` the attention rests on.
#[must_use]
pub fn rests_on(bytes: &[u8]) -> Option<(PartyRef, Vec<WorkId>)> {
    match decode_record(bytes).ok()? {
        Decoded::Record(r) => Some((r.core().author.clone(), r.core().concerns.clone())),
        Decoded::UnknownProtocol(_) => None,
    }
}

/// The external reference of a Relay event: its id and the SHA-256 of `source`, a line feed and
/// `id` (P-114 item 2).
///
/// # Errors
/// [`NoticeRefusal::Event`] for an id or source that is empty, too long or not printable ASCII.
pub fn event_ref(source: &str, id: &str) -> Result<String, NoticeRefusal> {
    let printable = |t: &str| {
        !t.is_empty()
            && t.len() <= MAX_CEILING_EVENT
            && t.bytes().all(|b| (b'!'..=b'~').contains(&b))
    };
    if !printable(id) {
        return Err(NoticeRefusal::Event("id"));
    }
    if !printable(source) {
        return Err(NoticeRefusal::Event("source"));
    }
    let digest = sha256(&[source.as_bytes(), b"\n", id.as_bytes()].concat());
    let text = format!("{EVENT_PREFIX}{id}:sha-256:{}", b64url(&digest));
    ExternalRef::parse(&text)
        .map(|r| r.as_str().to_owned())
        .ok_or(NoticeRefusal::Event("id"))
}

fn digest_value(d: &[u8; 32]) -> Value {
    Value::Array(vec![Value::int(-16), Value::Bytes(d.to_vec())])
}

/// The attention body.
fn body(input: &NoticeInput) -> Result<Value, NoticeRefusal> {
    let mut entries = vec![
        (Value::text("event"), Value::text(&input.event)),
        (Value::text("source"), Value::text(&input.source)),
    ];
    if let Some(agent) = &input.agent {
        if agent.is_empty() || agent.len() > MAX_CEILING_AGENT {
            return Err(NoticeRefusal::Event("agent"));
        }
        entries.push((Value::text("agent"), Value::text(agent)));
    }
    Ok(Value::Map(entries))
}

/// The `SignedRecord` bytes of the attention (E-23, P-114 item 2).
///
/// # Errors
/// [`NoticeRefusal`].
pub fn notice_record(input: &NoticeInput) -> Result<Vec<u8>, NoticeRefusal> {
    let event = event_ref(&input.source, &input.event)?;
    let see = match &input.audience {
        Some(p) if *p != input.author => Value::Array(vec![
            Value::text("parties"),
            Value::Array(vec![Value::text(p.as_str())]),
        ]),
        _ => Value::text("author"),
    };
    let record = Value::Map(vec![
        (Value::text("kind"), Value::text("claim")),
        (
            Value::text("type"),
            Value::Text(format!(
                "{CORE_ROOT}claim/{}",
                ClaimSubtype::Observation.wire_name()
            )),
        ),
        (Value::text("occurred_at"), Value::Unsigned(input.at_ms)),
        (Value::text("author"), Value::text(input.author.as_str())),
        (
            Value::text("basis"),
            Value::Array(vec![digest_value(input.basis.0.as_bytes())]),
        ),
        (
            Value::text("visibility"),
            Value::Map(vec![(Value::text("see"), see)]),
        ),
        (
            Value::text("ledger"),
            digest_value(input.ledger.0.as_bytes()),
        ),
        (
            Value::text("concerns"),
            Value::Array(
                input
                    .concerns
                    .iter()
                    .map(|w| Value::Bytes(w.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (
            Value::text("relations"),
            Value::Array(vec![Value::Map(vec![
                (Value::text("rel"), Value::text("references")),
                (
                    Value::text("target"),
                    Value::Array(vec![Value::text("external"), Value::Text(event)]),
                ),
            ])]),
        ),
        (
            Value::text("versions"),
            Value::Map(vec![
                (
                    Value::text("protocol"),
                    Value::Array(vec![
                        Value::Unsigned(PROTOCOL.0),
                        Value::Unsigned(PROTOCOL.1),
                    ]),
                ),
                (
                    Value::text("schema"),
                    digest_value(&sha256(NOTICE_CDDL.as_bytes())),
                ),
            ]),
        ),
        (
            Value::text("ext"),
            Value::Map(vec![(Value::text(NOTICE_EXT_KEY), body(input)?)]),
        ),
    ]);
    let bytes = dcbor::encode(&record, Limits::CEILING).map_err(|_| NoticeRefusal::Record)?;
    match decode_record(&bytes) {
        Ok(Decoded::Record(r)) if notice(&r).is_some() => Ok(bytes),
        _ => Err(NoticeRefusal::Record),
    }
}

/// The attention `record` is, if it is one: a core `observation` Claim resting on one record and
/// carrying the [`NOTICE_EXT_KEY`] extension with the event id, the source and the agent.
#[must_use]
pub fn notice(record: &Record) -> Option<(String, Option<String>)> {
    let Record::Claim(claim) = record else {
        return None;
    };
    if claim.subtype != ClaimType::Core(ClaimSubtype::Observation) || record.basis().len() != 1 {
        return None;
    }
    let ext = claim
        .core
        .ext
        .iter()
        .flatten()
        .find(|e| e.key.as_str() == NOTICE_EXT_KEY)?;
    let Value::Map(entries) = dcbor::decode(&ext.value.0, Limits::CEILING).ok()? else {
        return None;
    };
    let text = |name: &str| {
        entries.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Text(t)) if k == name => Some(t.clone()),
            _ => None,
        })
    };
    Some((text("event")?, text("agent")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

    use work_kernel::id::Digest;
    use work_kernel::record::Audience;
    use work_kernel::relation::{ReferenceTarget, Relation};

    use super::*;

    const SERVICE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const OWNER: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const AGENT: &str = "agt_01jc8z3k5m7p9r1t3v5x7z9b2d";

    fn input() -> NoticeInput {
        NoticeInput {
            author: PartyRef::new(SERVICE).unwrap(),
            ledger: LedgerId(Digest::sha256([0x4c; 32])),
            basis: RecordId(Digest::sha256([0x09; 32])),
            audience: Some(PartyRef::new(OWNER).unwrap()),
            concerns: vec![WorkId::from_bytes([0x57; 16])],
            event: "evt_1".to_owned(),
            source: "https://relay.example".to_owned(),
            agent: Some(AGENT.to_owned()),
            at_ms: 1_793_000_000_000,
        }
    }

    fn decoded(bytes: &[u8]) -> Record {
        match decode_record(bytes).unwrap() {
            Decoded::Record(r) => *r,
            Decoded::UnknownProtocol(_) => panic!("a record"),
        }
    }

    // E-23 P-114 RC-31
    #[test]
    fn e_23_the_ceiling_attention_rests_on_work_s_record_and_names_the_relay_event() {
        let bytes = notice_record(&input()).unwrap();
        assert_eq!(notice_record(&input()).unwrap(), bytes);
        let record = decoded(&bytes);
        assert_eq!(
            notice(&record),
            Some(("evt_1".to_owned(), Some(AGENT.to_owned())))
        );
        let core = record.core();
        assert_eq!(core.author.as_str(), SERVICE);
        assert_eq!(record.basis(), [RecordId(Digest::sha256([0x09; 32]))]);
        assert_eq!(core.concerns, vec![WorkId::from_bytes([0x57; 16])]);
        assert_eq!(
            core.visibility.see,
            Audience::Parties(vec![PartyRef::new(OWNER).unwrap()])
        );
        let event = event_ref("https://relay.example", "evt_1").unwrap();
        assert!(event.starts_with("urn:suiss:relay:event:evt_1:sha-256:"));
        assert!(core.relations.iter().flatten().any(|r| matches!(
            r,
            Relation::References { target: ReferenceTarget::External(e), .. } if e.as_str() == event
        )));
        let own = NoticeInput {
            audience: Some(PartyRef::new(SERVICE).unwrap()),
            agent: None,
            ..input()
        };
        let own = decoded(&notice_record(&own).unwrap());
        assert_eq!(own.core().visibility.see, Audience::Author);
        assert_eq!(notice(&own), Some(("evt_1".to_owned(), None)));
    }

    // P-114 E-23 T-99
    #[test]
    fn p_114_without_work_s_record_or_a_printable_event_no_attention_is_written() {
        assert_eq!(
            basis_of(&"09".repeat(32)),
            Some(RecordId(Digest::sha256([0x09; 32])))
        );
        for bad in [
            String::new(),
            "09".to_owned(),
            "0G".repeat(32),
            "AB".repeat(32),
            "0".repeat(65),
        ] {
            assert_eq!(basis_of(&bad), None, "{bad}");
        }
        assert_eq!(
            event_ref("https://relay.example", "evt 1"),
            Err(NoticeRefusal::Event("id"))
        );
        assert_eq!(event_ref("", "evt_1"), Err(NoticeRefusal::Event("source")));
        let long = NoticeInput {
            agent: Some("a".repeat(MAX_CEILING_AGENT.saturating_add(1))),
            ..input()
        };
        assert_eq!(notice_record(&long), Err(NoticeRefusal::Event("agent")));
        assert_eq!(rests_on(b"not a record"), None);
    }
}
