//! The `work/commitment-time/1` bodies (CM-48, CM-50, CM-53): the budget, the budget consumption, the commitment clock and the periodic update definitions of `conformance/cddl/work-commitment-time.cddl`, read and written as deterministic CBOR, each refusal naming the member it refused.

use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

/// The contract name of the bodies.
pub const CONTRACT: &str = "work/commitment-time/1";

/// The CDDL of the bodies, byte for byte `conformance/cddl/work-commitment-time.cddl`.
pub const CDDL: &str = r#"; CM-48 CM-49 CM-62 CM-63 E-35

budget = effort-budget / money-budget / count-budget

effort-budget = {
  measure: "effort",
  limit: uint .ge 1,
  ? warnings: warnings,
}

money-budget = {
  measure: "money",
  currency: currency,
  limit: uint .ge 1,
  ? warnings: warnings,
}

count-budget = {
  measure: "operations" / "tokens",
  limit: uint .ge 1,
  ? warnings: warnings,
}

consumption = effort-consumption / money-consumption / count-consumption

effort-consumption = {
  measure: "effort",
  amount: uint,
}

money-consumption = {
  measure: "money",
  currency: currency,
  amount: uint,
}

count-consumption = {
  measure: "operations" / "tokens",
  amount: uint,
}

; CM-50 CM-51 CM-52 CM-64

clock = {
  version: uint .ge 1,
  target: "response" / "start" / "finish",
  duration: uint .ge 1,
  ? calendar: calendar,
  ? warnings: warnings,
  ? grace: uint .ge 1,
  ? pause: [1*16 pause-condition],
  start: [1*8 event],
  stop: [1*8 event],
}

pause-condition = {
  reason: tstr .size (1..256),
  awaited: "creditor" / "obligor" / "acceptor" / "third_party",
}

event = tstr .size (1..256)

; CM-53 CM-64

periodic = {
  version: uint .ge 1,
  rule: tstr .size (1..512),
  dtstart: local-datetime,
  zone: zone,
  tolerance: uint,
  ? schema: tstr .size (1..256),
}

calendar = {
  zone: zone,
  week: [7*7 day],
  ? holidays: [1*256 local-date],
}

day = [0*8 interval]
interval = [uint .le 1439, uint .le 1440]

warnings = [1*8 permille]
permille = 1..999
currency = tstr .regexp "[A-Z]{3}"
zone = tstr .size (1..64)
local-date = tstr .regexp "[0-9]{4}-[0-9]{2}-[0-9]{2}"
local-datetime = tstr .regexp "[0-9]{8}T[0-9]{6}"
"#;

/// The body part of a clock, periodic or budget Condition record that holds its definition body (WD-146).
pub const DEFINITION_PART: &str = "definition";

/// The Condition types a commitment's clock, periodic update and budget are declared with (CM-48, CM-50, CM-53).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TimeCondition {
    /// A commitment clock, `https://suiss.app/ns/work/condition/clock`.
    Clock,
    /// A periodic update, `https://suiss.app/ns/work/condition/periodic`.
    Periodic,
    /// A budget, `https://suiss.app/ns/work/condition/budget`.
    Budget,
}

impl TimeCondition {
    /// The three types.
    pub const ALL: [Self; 3] = [Self::Clock, Self::Periodic, Self::Budget];

    /// The `condition_type` URI.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Clock => "https://suiss.app/ns/work/condition/clock",
            Self::Periodic => "https://suiss.app/ns/work/condition/periodic",
            Self::Budget => "https://suiss.app/ns/work/condition/budget",
        }
    }

    /// The type a `condition_type` URI names.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.uri() == uri)
    }
}

/// Most warning tiers one budget or clock declares.
pub const MAX_WARNINGS: usize = 8;

/// Why a value is not a `work/commitment-time/1` body, naming the member it refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyError(pub &'static str);

impl core::fmt::Display for BodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not a commitment time body: {}", self.0)
    }
}

impl core::error::Error for BodyError {}

/// Reads deterministic CBOR bytes.
pub(crate) fn decode(bytes: &[u8]) -> Result<Value, BodyError> {
    dcbor::decode(bytes, Limits::CEILING).map_err(|_| BodyError("cbor"))
}

/// Writes deterministic CBOR bytes.
pub(crate) fn encode(value: &Value) -> Result<Vec<u8>, BodyError> {
    dcbor::encode(value, Limits::CEILING).map_err(|_| BodyError("encoding"))
}

/// Refuses anything but a map whose keys are among `allowed`.
pub(crate) fn members(value: &Value, allowed: &[&str]) -> Result<(), BodyError> {
    let Value::Map(entries) = value else {
        return Err(BodyError("body"));
    };
    for (k, _) in entries {
        if !matches!(k, Value::Text(t) if allowed.contains(&t.as_str())) {
            return Err(BodyError("member"));
        }
    }
    Ok(())
}

/// A required unsigned member.
pub(crate) fn uint(value: &Value, key: &'static str) -> Result<u64, BodyError> {
    match value.get(key) {
        Some(Value::Unsigned(u)) => Ok(*u),
        _ => Err(BodyError(key)),
    }
}

/// An optional unsigned member, zero when absent.
pub(crate) fn uint_or_zero(value: &Value, key: &'static str) -> Result<u64, BodyError> {
    match value.get(key) {
        None => Ok(0),
        Some(Value::Unsigned(u)) => Ok(*u),
        Some(_) => Err(BodyError(key)),
    }
}

/// A required text member of 1 to `max` bytes.
pub(crate) fn text<'v>(
    value: &'v Value,
    key: &'static str,
    max: usize,
) -> Result<&'v str, BodyError> {
    match value.get(key) {
        Some(Value::Text(t)) if !t.is_empty() && t.len() <= max => Ok(t.as_str()),
        _ => Err(BodyError(key)),
    }
}

/// A version member: at least 1, at most `u32::MAX`.
pub(crate) fn version(value: &Value) -> Result<u32, BodyError> {
    let v = uint(value, "version")?;
    match u32::try_from(v) {
        Ok(v) if v >= 1 => Ok(v),
        _ => Err(BodyError("version")),
    }
}

/// The optional `warnings` member: 1 to 8 permille tiers between 1 and 999, strictly ascending; absent is no tier.
pub(crate) fn warnings(value: &Value) -> Result<Vec<u16>, BodyError> {
    let Some(found) = value.get("warnings") else {
        return Ok(Vec::new());
    };
    let Value::Array(list) = found else {
        return Err(BodyError("warnings"));
    };
    if list.is_empty() || list.len() > MAX_WARNINGS {
        return Err(BodyError("warnings"));
    }
    let mut out: Vec<u16> = Vec::with_capacity(list.len());
    for item in list {
        let tier = match item {
            Value::Unsigned(u) => u16::try_from(*u).map_err(|_| BodyError("warnings"))?,
            _ => return Err(BodyError("warnings")),
        };
        if !(1..=999).contains(&tier) || out.last().is_some_and(|last| *last >= tier) {
            return Err(BodyError("warnings"));
        }
        out.push(tier);
    }
    Ok(out)
}

/// Appends the `warnings` member when there is a tier.
pub(crate) fn push_warnings(entries: &mut Vec<(Value, Value)>, tiers: &[u16]) {
    if !tiers.is_empty() {
        entries.push((
            Value::text("warnings"),
            Value::Array(
                tiers
                    .iter()
                    .map(|t| Value::Unsigned(u64::from(*t)))
                    .collect(),
            ),
        ));
    }
}
