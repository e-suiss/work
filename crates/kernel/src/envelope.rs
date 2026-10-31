//! The ledger envelopes as the normative CDDL writes them: the genesis at position 0 and a `LedgerEnvelope` at every later position, the schema chosen by `pos` (P-11, P-12, P-21, P-75, P-100).

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{Limits, Value};

use crate::codec::{
    MISSING, Mapped, UNKNOWN_FIELD, bytes_exact, decode, digest_value, entries, list, pair, text,
    uint, versions,
};
use crate::id::{Digest, LedgerId, RecordId, Time, canonical_text_cmp};
use crate::reason::{Limit, QuarantineReason, Reason, Schema};
use crate::record::VersionVector;
use crate::validate::{ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes};

/// The authorless first entry of every ledger; its digest is the `LedgerID` (P-100, Access CR-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisEnvelope {
    /// The sequencer's trusted time (P-27).
    pub recorded_at: Time,
    /// The protocol version the ledger opens with (P-18).
    pub versions: VersionVector,
    /// 32 bytes from the `Rng` port (T-32).
    pub nonce: [u8; 32],
}

/// A reference to the Access authentication context of an unsigned human record (P-21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContextRef {
    /// The digest of the Access authentication context.
    pub reference: Digest,
    /// The assurance level, 1 to 64 bytes.
    pub assurance: String,
    /// Whether the context came from a step-up.
    pub step_up: bool,
}

/// How the ledger took the record in (P-11, P-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeIngest {
    /// `admitted`.
    Admitted,
    /// `["quarantined", code]`.
    Quarantined(QuarantineReason),
    /// `["rejected", code]`.
    Rejected(Reason),
}

/// The envelope of one record at a position above 0 (P-11, P-75, P-100).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEnvelope {
    /// The record identifier (P-79).
    pub record: RecordId,
    /// The ledger.
    pub ledger: LedgerId,
    /// The position, above 0.
    pub position: u64,
    /// The trusted record time (P-27).
    pub recorded_at: Time,
    /// The leaf hash of the previous envelope (P-100).
    pub prev: Digest,
    /// Actor types of the author and every `on_behalf_of` ring (P-12, INV-18).
    pub actor_types: ActorTypes,
    /// The digest of the `COSE_Sign1` bytes as received (P-75, P-76).
    pub proof_commit: Option<Digest>,
    /// The authentication context of an unsigned human record (P-21).
    pub auth_context: Option<AuthContextRef>,
    /// How the record was taken in.
    pub ingest: EnvelopeIngest,
}

/// An envelope, by the schema its position selects (P-100 item 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Envelope {
    /// Position 0.
    Genesis(GenesisEnvelope),
    /// Any later position.
    Ledger(LedgerEnvelope),
}

const GENESIS_FIELDS: &[(&str, bool)] = &[
    ("pos", true),
    ("nonce", true),
    ("versions", true),
    ("recorded_at", true),
];

const LEDGER_FIELDS: &[(&str, bool)] = &[
    ("pos", true),
    ("prev", true),
    ("ingest", true),
    ("ledger", true),
    ("record", true),
    ("actor_type", true),
    ("recorded_at", true),
    ("auth_context", false),
    ("proof_commit", false),
];

const ACTOR_FIELDS: &[(&str, bool)] = &[("author", true), ("on_behalf_of", false)];
const AUTH_CONTEXT_FIELDS: &[(&str, bool)] =
    &[("ref", true), ("step_up", true), ("assurance", true)];
const MAX_ASSURANCE: usize = 64;
const MAX_RINGS: usize = 8;

/// Walks the keys of a closed map and of its schema together in canonical order: the first key the schema lacks is `schema:unknown_core_field`, the first required key the map lacks is `schema:required_field` (P-72, P-100 item 6).
fn walk<'a>(v: &'a Value, schema: &[(&str, bool)]) -> Mapped<Vec<Option<&'a Value>>> {
    let m = entries(v)?;
    let mut out = Vec::with_capacity(schema.len());
    let mut input = m.iter().peekable();
    for (name, needed) in schema {
        let next = match input.peek() {
            None => core::cmp::Ordering::Greater,
            Some((Value::Text(key), _)) => canonical_text_cmp(key, name),
            Some(_) => return Err(UNKNOWN_FIELD),
        };
        match next {
            core::cmp::Ordering::Less => return Err(UNKNOWN_FIELD),
            core::cmp::Ordering::Greater if *needed => return Err(MISSING),
            core::cmp::Ordering::Greater => out.push(None),
            core::cmp::Ordering::Equal => out.push(input.next().map(|(_, value)| value)),
        }
    }
    if input.next().is_some() {
        return Err(UNKNOWN_FIELD);
    }
    Ok(out)
}

fn field<'a>(fields: &[Option<&'a Value>], at: usize) -> Mapped<&'a Value> {
    fields.get(at).copied().flatten().ok_or(MISSING)
}

fn optional_field<T>(
    fields: &[Option<&Value>],
    at: usize,
    f: impl Fn(&Value) -> Mapped<T>,
) -> Mapped<Option<T>> {
    fields.get(at).copied().flatten().map(f).transpose()
}

fn actor_entry(v: &Value) -> Mapped<ActorTypeEntry> {
    let (actor_type, source) = pair(v)?;
    Ok(ActorTypeEntry {
        actor_type: ActorType::from_wire_name(text(actor_type)?).ok_or(MISSING)?,
        source: ActorTypeSource::from_wire_name(text(source)?).ok_or(MISSING)?,
    })
}

fn actor_types(v: &Value) -> Mapped<ActorTypes> {
    let f = walk(v, ACTOR_FIELDS)?;
    let on_behalf_of =
        optional_field(&f, 1, |l| list(l, actor_entry))?.map_or(Ok(Vec::new()), |rings| {
            if rings.is_empty() {
                Err(Reason::Schema(Schema::EmptyOptionalList))
            } else if rings.len() > MAX_RINGS {
                Err(Reason::LimitExceeded(Limit::OnBehalfOf))
            } else {
                Ok(rings)
            }
        })?;
    Ok(ActorTypes {
        author: actor_entry(field(&f, 0)?)?,
        on_behalf_of,
    })
}

fn auth_context(v: &Value) -> Mapped<AuthContextRef> {
    let f = walk(v, AUTH_CONTEXT_FIELDS)?;
    let reference = digest_value(field(&f, 0)?)?;
    let step_up = match field(&f, 1)? {
        Value::Bool(b) => *b,
        _ => return Err(MISSING),
    };
    let assurance = text(field(&f, 2)?)?;
    if assurance.is_empty() || assurance.len() > MAX_ASSURANCE {
        return Err(Reason::LimitExceeded(Limit::String));
    }
    Ok(AuthContextRef {
        reference,
        assurance: String::from(assurance),
        step_up,
    })
}

fn ingest(v: &Value) -> Mapped<EnvelopeIngest> {
    let invalid = Reason::Schema(Schema::Ingest);
    match v {
        Value::Text(t) if t == "admitted" => Ok(EnvelopeIngest::Admitted),
        Value::Array(items) => match items.as_slice() {
            [Value::Text(tag), Value::Text(code)] if tag == "quarantined" => {
                QuarantineReason::from_code(code)
                    .map(EnvelopeIngest::Quarantined)
                    .ok_or(invalid)
            }
            [Value::Text(tag), Value::Text(code)] if tag == "rejected" => Reason::from_code(code)
                .map(EnvelopeIngest::Rejected)
                .ok_or(invalid),
            _ => Err(invalid),
        },
        _ => Err(invalid),
    }
}

fn genesis(v: &Value) -> Mapped<GenesisEnvelope> {
    let f = walk(v, GENESIS_FIELDS)?;
    Ok(GenesisEnvelope {
        nonce: bytes_exact(field(&f, 1)?)?,
        versions: versions(field(&f, 2)?)?,
        recorded_at: Time(uint(field(&f, 3)?)?),
    })
}

fn ledger(v: &Value, position: u64) -> Mapped<LedgerEnvelope> {
    let f = walk(v, LEDGER_FIELDS)?;
    Ok(LedgerEnvelope {
        prev: digest_value(field(&f, 1)?)?,
        ingest: ingest(field(&f, 2)?)?,
        ledger: LedgerId(digest_value(field(&f, 3)?)?),
        record: RecordId(digest_value(field(&f, 4)?)?),
        actor_types: actor_types(field(&f, 5)?)?,
        recorded_at: Time(uint(field(&f, 6)?)?),
        auth_context: optional_field(&f, 7, auth_context)?,
        proof_commit: optional_field(&f, 8, digest_value)?,
        position,
    })
}

/// Maps a decoded envelope by its position: `pos = 0` is read as the genesis and any other position as a `LedgerEnvelope`, so a misplaced one fails with the selected schema's own code (P-100 item 6).
///
/// # Errors
///
/// A schema or limit reason.
pub fn envelope_from_value(v: &Value) -> Result<Envelope, Reason> {
    let position = uint(
        entries(v)?
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "pos"))
            .map(|(_, p)| p)
            .ok_or(MISSING)?,
    )?;
    if position == 0 {
        genesis(v).map(Envelope::Genesis)
    } else {
        ledger(v, position).map(Envelope::Ledger)
    }
}

/// Decodes envelope bytes under the shared structural ceilings (P-5, P-7, P-100).
///
/// # Errors
///
/// A CBOR, limit or schema reason.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, Reason> {
    envelope_from_value(&decode(bytes, Limits::CEILING)?)
}

impl Envelope {
    /// The position.
    #[must_use]
    pub const fn position(&self) -> u64 {
        match self {
            Self::Genesis(_) => 0,
            Self::Ledger(e) => e.position,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(k, v)| (Value::text(k), v.clone()))
                .collect(),
        )
    }

    // P-72 P-100
    #[test]
    fn p_100_closed_maps_report_the_first_key_out_of_place() {
        let schema: &[(&str, bool)] = &[("a", true), ("bb", false), ("ccc", true)];
        let one = Value::Unsigned(1);
        assert!(walk(&map(&[("a", one.clone()), ("ccc", one.clone())]), schema).is_ok());
        assert_eq!(
            walk(
                &map(&[("a", one.clone()), ("b", one.clone()), ("ccc", one.clone())]),
                schema
            ),
            Err(UNKNOWN_FIELD)
        );
        assert_eq!(walk(&map(&[("ccc", one.clone())]), schema), Err(MISSING));
        assert_eq!(walk(&map(&[("a", one.clone())]), schema), Err(MISSING));
        assert_eq!(
            walk(
                &map(&[("a", one.clone()), ("ccc", one.clone()), ("dddd", one)]),
                schema
            ),
            Err(UNKNOWN_FIELD)
        );
        let non_text = Value::Map(vec![(Value::Unsigned(0), Value::Unsigned(0))]);
        assert_eq!(walk(&non_text, schema), Err(UNKNOWN_FIELD));
        for fields in [
            GENESIS_FIELDS,
            LEDGER_FIELDS,
            ACTOR_FIELDS,
            AUTH_CONTEXT_FIELDS,
        ] {
            assert!(fields.windows(2).all(|w| matches!(
                w,
                [a, b] if canonical_text_cmp(a.0, b.0) == core::cmp::Ordering::Less
            )));
        }
    }

    // P-11 P-19
    #[test]
    fn p_11_ingest_is_one_of_the_three_forms() {
        let pair = |tag: &str, code: &str| Value::Array(vec![Value::text(tag), Value::text(code)]);
        assert_eq!(
            ingest(&Value::text("admitted")),
            Ok(EnvelopeIngest::Admitted)
        );
        assert_eq!(
            ingest(&pair("quarantined", "protocol_version_unknown")),
            Ok(EnvelopeIngest::Quarantined(
                QuarantineReason::ProtocolVersionUnknown
            ))
        );
        assert_eq!(
            ingest(&pair("rejected", "authority_missing")),
            Ok(EnvelopeIngest::Rejected(Reason::AuthorityMissing))
        );
        let invalid = Err(Reason::Schema(Schema::Ingest));
        assert_eq!(ingest(&pair("quarantined", "authority_missing")), invalid);
        assert_eq!(ingest(&pair("rejected", "nope")), invalid);
        assert_eq!(ingest(&Value::text("accepted")), invalid);
    }

    // P-21
    #[test]
    fn p_21_auth_context_assurance_is_one_to_64_bytes() {
        let context = |assurance: &str| {
            map(&[
                (
                    "ref",
                    Value::Array(vec![Value::int(-16), Value::Bytes(vec![0; 32])]),
                ),
                ("step_up", Value::Bool(true)),
                ("assurance", Value::text(assurance)),
            ])
        };
        assert!(auth_context(&context("aal2")).is_ok_and(|c| c.step_up));
        assert_eq!(
            auth_context(&context("")),
            Err(Reason::LimitExceeded(Limit::String))
        );
        assert_eq!(
            auth_context(&context(&"a".repeat(65))),
            Err(Reason::LimitExceeded(Limit::String))
        );
    }
}
