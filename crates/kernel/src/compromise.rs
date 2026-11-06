//! The SEC-36 compromise window notice (WD-123): the `work/compromise-window/1` body, carried verbatim as the non-critical extension [`EXT_KEY`] of a core `observation` Claim that the domain's Work service system Party writes into each ledger holding a record of the window; the Access event it answers is an external `references` target ([`event_ref`]) and the compromised Party another ([`party_ref`]); the `compromise_window` mark of a record is derived from such notices (C-4) and never changes the record or its effects.

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::sha256;

use crate::catalog::ClaimSubtype;
use crate::codec::{Decoded, decode_record};
use crate::explanation::b64url;
use crate::id::{LedgerId, PartyRef, RecordId};
use crate::record::{Audience, ClaimType, Record};
use crate::relation::{ReferenceTarget, Relation};
use crate::uri::CORE_ROOT;

/// The extension key the notice body is written under.
pub const EXT_KEY: &str = "https://suiss.app/ns/work/compromise-window/1";

/// The CDDL of the body, byte for byte `conformance/cddl/work-compromise-window.cddl`; the
/// notice's `versions.schema` is its SHA-256.
pub const CDDL: &str = r#"; SEC-36

compromise-window = {
  instance: bstr .size 16,
  kids: [+ kid],
  window_from: uint,
  window_to: uint,
  event_digest: digest,
  domain: bstr .size 32,
  source: tstr,
}

kid = tstr .size 43
digest = [-16, bstr .size 32]
"#;

/// The external reference prefix of the Access event a notice answers.
pub const EVENT_PREFIX: &str = "urn:suiss:access:event:";

/// The external reference prefix of the compromised Party.
pub const PARTY_PREFIX: &str = "urn:suiss:access:party:";

/// The protocol version the notice is written under.
pub const PROTOCOL: (u64, u64) = (1, 0);

const FIELDS: [&str; 7] = [
    "instance",
    "kids",
    "window_from",
    "window_to",
    "event_digest",
    "domain",
    "source",
];

/// Most kids one notice names, the CDDL list bound of the record model.
pub const MAX_KIDS: usize = 256;

/// Why a value is not a `work/compromise-window/1` body or a notice cannot be written,
/// naming the member it refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowError(pub &'static str);

impl core::fmt::Display for WindowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not a compromise window: {}", self.0)
    }
}

impl core::error::Error for WindowError {}

/// The body: the Instance, the kids, the window and the Access event (WD-123 item 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    /// The Instance the notice names.
    pub instance: [u8; 16],
    /// The compromised kids, ascending and without repeats.
    pub kids: Vec<[u8; 32]>,
    /// `window_from` of the event, Unix milliseconds.
    pub window_from: u64,
    /// `declared_at` of the event, Unix milliseconds.
    pub window_to: u64,
    /// SHA-256 of the SET bytes.
    pub event_digest: [u8; 32],
    /// The governing domain.
    pub domain: [u8; 32],
    /// The Access Claim identifier, as Access writes it.
    pub source: String,
}

fn digest_value(d: &[u8; 32]) -> Value {
    Value::Array(alloc::vec![Value::int(-16), Value::Bytes(d.to_vec())])
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn six(c: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|p| u32::try_from(p).ok())
}

fn b64url_decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = Vec::with_capacity(N);
    for chunk in text.as_bytes().chunks(4) {
        let mut n: u32 = 0;
        for (shift, &c) in [18_u32, 12, 6, 0].iter().zip(chunk) {
            n |= six(c)?.checked_shl(*shift)?;
        }
        let take = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return None,
        };
        out.extend(n.to_be_bytes().iter().skip(1).take(take));
    }
    let fixed: [u8; N] = out.try_into().ok()?;
    (b64url(&fixed) == text).then_some(fixed)
}

fn fixed<const N: usize>(v: Option<&Value>, what: &'static str) -> Result<[u8; N], WindowError> {
    match v {
        Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| WindowError(what)),
        _ => Err(WindowError(what)),
    }
}

fn number(v: Option<&Value>, what: &'static str) -> Result<u64, WindowError> {
    match v {
        Some(Value::Unsigned(u)) => Ok(*u),
        _ => Err(WindowError(what)),
    }
}

impl Window {
    /// The body as a CBOR value, kids in ascending order.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut kids = self.kids.clone();
        kids.sort_unstable();
        kids.dedup();
        Value::Map(alloc::vec![
            (
                Value::text("instance"),
                Value::Bytes(self.instance.to_vec())
            ),
            (
                Value::text("kids"),
                Value::Array(kids.iter().map(|k| Value::Text(b64url(k))).collect()),
            ),
            (
                Value::text("window_from"),
                Value::Unsigned(self.window_from)
            ),
            (Value::text("window_to"), Value::Unsigned(self.window_to)),
            (
                Value::text("event_digest"),
                digest_value(&self.event_digest)
            ),
            (Value::text("domain"), Value::Bytes(self.domain.to_vec())),
            (Value::text("source"), Value::text(&self.source)),
        ])
    }

    /// The deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`WindowError`] for a body [`Window::from_value`] would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, WindowError> {
        let value = self.to_value();
        Self::from_value(&value)?;
        dcbor::encode(&value, Limits::CEILING).map_err(|_| WindowError("encoding"))
    }

    /// Reads deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`WindowError`] naming the member that does not fit `work-compromise-window.cddl`.
    pub fn decode(bytes: &[u8]) -> Result<Self, WindowError> {
        let value = dcbor::decode(bytes, Limits::CEILING).map_err(|_| WindowError("cbor"))?;
        Self::from_value(&value)
    }

    /// Checks `value` against `work-compromise-window.cddl`: exactly its seven members, 43
    /// character kids, at least one and in ascending order without repeats, and a window that
    /// does not end before it starts.
    ///
    /// # Errors
    /// [`WindowError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Result<Self, WindowError> {
        let Value::Map(entries) = value else {
            return Err(WindowError("body"));
        };
        for (k, _) in entries {
            if !matches!(k, Value::Text(t) if FIELDS.contains(&t.as_str())) {
                return Err(WindowError("member"));
            }
        }
        let kids = match value.get("kids") {
            Some(Value::Array(list)) if !list.is_empty() && list.len() <= MAX_KIDS => list
                .iter()
                .map(|k| match k {
                    Value::Text(t) if t.len() == 43 => {
                        b64url_decode::<32>(t).ok_or(WindowError("kids"))
                    }
                    _ => Err(WindowError("kids")),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(WindowError("kids")),
        };
        if !kids.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
            return Err(WindowError("kids"));
        }
        let event_digest = match value.get("event_digest") {
            Some(Value::Array(pair)) => match pair.as_slice() {
                [alg, Value::Bytes(d)] if alg.as_i64() == Some(-16) => {
                    <[u8; 32]>::try_from(d.as_slice()).map_err(|_| WindowError("event_digest"))?
                }
                _ => return Err(WindowError("event_digest")),
            },
            _ => return Err(WindowError("event_digest")),
        };
        let source = match value.get("source") {
            Some(Value::Text(t)) => t.clone(),
            _ => return Err(WindowError("source")),
        };
        let out = Self {
            instance: fixed(value.get("instance"), "instance")?,
            kids,
            window_from: number(value.get("window_from"), "window_from")?,
            window_to: number(value.get("window_to"), "window_to")?,
            event_digest,
            domain: fixed(value.get("domain"), "domain")?,
            source,
        };
        if out.window_from > out.window_to {
            return Err(WindowError("window_to"));
        }
        Ok(out)
    }

    /// Whether a record recorded at `recorded_at` falls inside the window, the bounds
    /// included (SEC-36 item 2).
    #[must_use]
    pub const fn holds(&self, recorded_at: u64) -> bool {
        self.window_from <= recorded_at && recorded_at <= self.window_to
    }

    /// Whether the window marks a record recorded at `recorded_at` that was signed with `kid`,
    /// or written unsigned by `author` while `party` is the compromised Party (SEC-36 item 3).
    #[must_use]
    pub fn marks(
        &self,
        recorded_at: u64,
        kid: Option<&[u8; 32]>,
        author: Option<&str>,
        party: Option<&str>,
    ) -> bool {
        let by_key = kid.is_some_and(|k| self.kids.contains(k));
        let by_session = matches!((author, party), (Some(a), Some(p)) if a == p);
        self.holds(recorded_at) && (by_key || by_session)
    }
}

/// The external reference of the Access event: its SET `jti` and the SHA-256 of its bytes.
///
/// # Errors
/// [`WindowError`] for a `jti` outside printable ASCII.
pub fn event_ref(jti: &str, event_digest: &[u8; 32]) -> Result<String, WindowError> {
    if jti.is_empty() || !jti.bytes().all(|b| (b'!'..=b'~').contains(&b)) {
        return Err(WindowError("jti"));
    }
    Ok(alloc::format!(
        "{EVENT_PREFIX}{jti}:sha-256:{}",
        b64url(event_digest)
    ))
}

/// The external reference of the compromised Party.
///
/// # Errors
/// [`WindowError`] for a Party reference outside printable ASCII.
pub fn party_ref(party: &PartyRef) -> Result<String, WindowError> {
    let text = party.as_str();
    if !text.bytes().all(|b| (b'!'..=b'~').contains(&b)) {
        return Err(WindowError("party"));
    }
    Ok(alloc::format!("{PARTY_PREFIX}{text}"))
}

/// What a notice is written from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoticeInput {
    /// The Work service system Party of the event's domain.
    pub author: PartyRef,
    /// The ledger it is written into.
    pub ledger: LedgerId,
    /// The compromised Party.
    pub party: PartyRef,
    /// The SET `jti`.
    pub jti: String,
    /// The body.
    pub window: Window,
}

fn external(target: String) -> Value {
    Value::Map(alloc::vec![
        (Value::text("rel"), Value::text("references")),
        (
            Value::text("target"),
            Value::Array(alloc::vec![Value::text("external"), Value::Text(target)]),
        ),
    ])
}

/// The `SignedRecord` bytes of the notice: a core `observation` Claim of the service Party,
/// visible to its author, concerning no Work, with `occurred_at` the declaration's commit time,
/// the event and the Party as external references and the body as extension. The bytes depend
/// only on the input, so one event gives one record per ledger.
///
/// # Errors
/// [`WindowError`] for a body, `jti` or Party that cannot be written.
pub fn notice_record(input: &NoticeInput) -> Result<Vec<u8>, WindowError> {
    let body = input.window.to_value();
    Window::from_value(&body)?;
    let event = event_ref(&input.jti, &input.window.event_digest)?;
    let party = party_ref(&input.party)?;
    let relations = alloc::vec![external(event), external(party)];
    let record = Value::Map(alloc::vec![
        (Value::text("kind"), Value::text("claim")),
        (
            Value::text("type"),
            Value::Text(alloc::format!(
                "{CORE_ROOT}claim/{}",
                ClaimSubtype::Observation.wire_name()
            )),
        ),
        (
            Value::text("occurred_at"),
            Value::Unsigned(input.window.window_to),
        ),
        (Value::text("author"), Value::text(input.author.as_str())),
        (
            Value::text("visibility"),
            Value::Map(alloc::vec![(Value::text("see"), Value::text("author"))]),
        ),
        (
            Value::text("ledger"),
            digest_value(input.ledger.0.as_bytes()),
        ),
        (Value::text("concerns"), Value::Array(Vec::new())),
        (Value::text("relations"), Value::Array(relations)),
        (
            Value::text("versions"),
            Value::Map(alloc::vec![
                (
                    Value::text("protocol"),
                    Value::Array(alloc::vec![
                        Value::Unsigned(PROTOCOL.0),
                        Value::Unsigned(PROTOCOL.1)
                    ]),
                ),
                (
                    Value::text("schema"),
                    digest_value(&sha256(CDDL.as_bytes()))
                ),
            ]),
        ),
        (
            Value::text("ext"),
            Value::Map(alloc::vec![(Value::text(EXT_KEY), body)]),
        ),
    ]);
    let bytes = dcbor::encode(&record, Limits::CEILING).map_err(|_| WindowError("encoding"))?;
    match decode_record(&bytes) {
        Ok(Decoded::Record(r)) if notice(&r).is_some() => Ok(bytes),
        _ => Err(WindowError("record")),
    }
}

/// A notice read from a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The body.
    pub window: Window,
    /// The compromised Party, from its external reference.
    pub party: Option<String>,
    /// The Access event reference.
    pub event: Option<String>,
}

/// The notice `record` is, if it is one: a core `observation` Claim visible to its author whose
/// [`EXT_KEY`] extension is a valid body.
#[must_use]
pub fn notice(record: &Record) -> Option<Notice> {
    let Record::Claim(claim) = record else {
        return None;
    };
    if claim.subtype != ClaimType::Core(ClaimSubtype::Observation)
        || claim.core.visibility.see != Audience::Author
    {
        return None;
    }
    let ext = claim
        .core
        .ext
        .iter()
        .flatten()
        .find(|e| e.key.as_str() == EXT_KEY)?;
    let window = Window::decode(&ext.value.0).ok()?;
    let mut party = None;
    let mut event = None;
    for r in claim.core.relations.iter().flatten() {
        if let Relation::References {
            source: None,
            target: ReferenceTarget::External(e),
            qualifier: None,
        } = r
        {
            if let Some(p) = e.as_str().strip_prefix(PARTY_PREFIX) {
                party = Some(String::from(p));
            } else if e.as_str().starts_with(EVENT_PREFIX) {
                event = Some(String::from(e.as_str()));
            }
        }
    }
    Some(Notice {
        window,
        party,
        event,
    })
}

/// The record a notice is, by its `SignedRecord` bytes.
#[must_use]
pub fn notice_of_bytes(bytes: &[u8]) -> Option<(RecordId, Notice)> {
    match decode_record(bytes) {
        Ok(Decoded::Record(r)) => notice(&r).map(|n| (crate::codec::record_id(bytes), n)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
