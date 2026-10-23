//! Maps ledger entries and derivation inputs from JSON onto the kernel fold and writes the derived view back as JSON.

use core::fmt::Write as _;

use serde_json::{Map, Value, json};
use work_kernel::derive::{
    Admission, AuthorityIssuer, BusinessCalendar, Chain, ChainStatus, DerivationInputs,
    DeriveError, DerivedRecord, Effect, Entry, Ingest, NoEffect, ProfileVersion, Restriction,
    TrustInputs, derive,
};
use work_kernel::id::{Digest, PartyRef, RecordId, Time};
use work_kernel::reason::{QuarantineReason, Reason, Schema};
use work_kernel::record::{PracticePin, ProtocolVersion, Record};

use crate::decode::{self, Mapped, digest, list, object, pair, party, required, text, uint};
use crate::{error, input_error, parse};

const MISSING: Reason = Reason::Schema(Schema::RequiredField);

const ENTRY_FIELDS: &[&str] = &[
    "id",
    "record",
    "position",
    "recorded_at",
    "ingest",
    "restriction",
    "issuer",
];

const INPUT_FIELDS: &[&str] = &[
    "protocol",
    "profile",
    "practices",
    "trusted_publishers",
    "ledger_time",
    "calendar",
];

struct EntryParts {
    id: RecordId,
    position: u64,
    recorded_at: Time,
    ingest: Ingest,
    restriction: Restriction,
    issuer: AuthorityIssuer,
}

struct Inputs {
    protocol: ProtocolVersion,
    profile: ProfileVersion,
    practices: Vec<PracticePin>,
    trusted_publishers: Vec<PartyRef>,
    ledger_time: Time,
    calendar: BusinessCalendar,
}

fn exact_keys(m: &Map<String, Value>, allowed: &[&str]) -> Mapped<()> {
    if m.keys().any(|k| !allowed.contains(&k.as_str())) {
        Err(MISSING)
    } else {
        Ok(())
    }
}

fn ingest(v: &Value) -> Mapped<Ingest> {
    if v == "admitted" {
        return Ok(Ingest::Admitted);
    }
    let (tag, code) = pair(v)?;
    if tag != "quarantined" {
        return Err(MISSING);
    }
    QuarantineReason::from_code(text(code)?)
        .map(Ingest::Quarantined)
        .ok_or(MISSING)
}

fn restriction(v: &Value) -> Mapped<Restriction> {
    match text(v)? {
        "no_objection" => Ok(Restriction::NoObjection),
        "deny" => Ok(Restriction::Deny),
        "require" => Ok(Restriction::Require),
        _ => Err(MISSING),
    }
}

fn issuer(v: &Value) -> Mapped<AuthorityIssuer> {
    if v == "local" {
        return Ok(AuthorityIssuer::Local);
    }
    let (tag, publisher) = pair(v)?;
    if tag != "federated" {
        return Err(MISSING);
    }
    Ok(AuthorityIssuer::Federated(party(publisher)?))
}

fn entry_parts(m: &Map<String, Value>) -> Mapped<EntryParts> {
    exact_keys(m, ENTRY_FIELDS)?;
    Ok(EntryParts {
        id: RecordId(digest(required(m, "id")?)?),
        position: uint(required(m, "position")?)?,
        recorded_at: Time(uint(required(m, "recorded_at")?)?),
        ingest: ingest(required(m, "ingest")?)?,
        restriction: restriction(required(m, "restriction")?)?,
        issuer: issuer(required(m, "issuer")?)?,
    })
}

fn inputs(v: &Value) -> Mapped<Inputs> {
    let m = object(v)?;
    exact_keys(m, INPUT_FIELDS)?;
    let (major, minor) = pair(required(m, "protocol")?)?;
    Ok(Inputs {
        protocol: ProtocolVersion {
            major: uint(major)?,
            minor: uint(minor)?,
        },
        profile: ProfileVersion(
            u32::try_from(uint(required(m, "profile")?)?).map_err(|_| MISSING)?,
        ),
        practices: decode::practices(required(m, "practices")?)?,
        trusted_publishers: list(required(m, "trusted_publishers")?, party)?,
        ledger_time: Time(uint(required(m, "ledger_time")?)?),
        calendar: match text(required(m, "calendar")?)? {
            "continuous" => BusinessCalendar::Continuous,
            _ => return Err(MISSING),
        },
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn digest_json(d: &Digest) -> Value {
    json!([-16, hex(d.as_bytes())])
}

fn ids(list: &[RecordId]) -> Value {
    Value::Array(list.iter().map(|r| digest_json(&r.0)).collect())
}

fn admission(a: Admission) -> Value {
    match a {
        Admission::Admitted => json!("admitted"),
        Admission::Quarantined(r) => json!(["quarantined", r.to_string()]),
        Admission::Rejected(r) => json!(["rejected", r.to_string()]),
    }
}

const fn no_effect(n: NoEffect) -> &'static str {
    match n {
        NoEffect::NotADeclaration => "not_a_declaration",
        NoEffect::NotAdmitted => "not_admitted",
        NoEffect::ProtocolVersion => "protocol_version",
        NoEffect::Denied => "denied",
        NoEffect::RequirementPending => "requirement_pending",
        NoEffect::UntrustedAuthority => "untrusted_authority",
        NoEffect::NotYetEffective => "not_yet_effective",
        NoEffect::UnknownTarget => "unknown_target",
        NoEffect::TerminalOutcome => "terminal_outcome",
        NoEffect::Conflicted => "conflicted",
        NoEffect::Stale => "stale",
    }
}

fn effect(e: Effect) -> Value {
    match e {
        Effect::Normative => json!("normative"),
        Effect::Conflicted => json!("conflicted"),
        Effect::None(n) => json!(["none", no_effect(n)]),
    }
}

fn derived(r: &DerivedRecord) -> Value {
    json!({
        "id": digest_json(&r.id.0),
        "admission": admission(r.admission),
        "effect": effect(r.effect),
        "superseded_by": ids(&r.superseded_by),
    })
}

fn chain(c: &Chain) -> Value {
    json!({
        "root": digest_json(&c.root.0),
        "version": c.version,
        "heads": ids(&c.heads),
        "status": match c.status {
            ChainStatus::Open => "open",
            ChainStatus::Terminal => "terminal",
            ChainStatus::Conflicted => "conflicted",
        },
    })
}

fn derive_error(e: DeriveError) -> String {
    let mut extra = Map::new();
    match e {
        DeriveError::PositionGap { position }
        | DeriveError::RecordedAtOutOfOrder { position }
        | DeriveError::LedgerMismatch { position } => {
            extra.insert("position".to_owned(), Value::from(position));
        }
        DeriveError::DuplicateRecord(id) => {
            extra.insert("record".to_owned(), digest_json(&id.0));
        }
        _ => {}
    }
    error(e.code(), extra)
}

fn invalid_entry(index: usize, reason: Option<Reason>) -> String {
    let mut extra = Map::new();
    extra.insert("index".to_owned(), Value::from(index));
    if let Some(reason) = reason {
        extra.insert("reason".to_owned(), Value::from(reason.to_string()));
    }
    error("invalid_entry", extra)
}

/// Folds ledger entries into the derived view (P-31, T-6).
///
/// `entries` is a JSON array in ledger order of `{"id", "record", "position", "recorded_at", "ingest", "restriction", "issuer"}`: `record` is the `decoded` projection, `ingest` is `"admitted"` or `["quarantined", <code>]`, `restriction` is `"no_objection"`, `"deny"` or `"require"`, and `issuer` is `"local"` or `["federated", <PartyRef>]`. `inputs` is `{"protocol": [major, minor], "profile", "practices": {<namespace>: <digest>}, "trusted_publishers", "ledger_time", "calendar": "continuous"}`.
///
/// Returns `{"derivation":{"records":[…],"chains":[…]}}`, or `{"error":{"code":…}}` with `invalid_json`, `invalid_inputs`, `invalid_entry` (with `index`, and `reason` when the record does not map) or a kernel derivation error (`position_gap`, `recorded_at_out_of_order`, `duplicate_record`, `ledger_mismatch`, `overflow`).
#[must_use]
pub fn derive_records(entries: &str, inputs_json: &str) -> String {
    let (Some(entries), Some(inputs_value)) = (parse(entries), parse(inputs_json)) else {
        return input_error("invalid_json");
    };
    let Ok(inputs) = inputs(&inputs_value) else {
        return input_error("invalid_inputs");
    };
    let Some(items) = entries.as_array() else {
        return input_error("invalid_json");
    };
    let mut parts = Vec::with_capacity(items.len());
    let mut records: Vec<Record> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Ok(m) = object(item) else {
            return invalid_entry(index, None);
        };
        let Ok(p) = entry_parts(m) else {
            return invalid_entry(index, None);
        };
        let record = match required(m, "record")
            .and_then(|r| decode::structure(r).and_then(|()| decode::record(r)))
        {
            Ok(r) => r,
            Err(reason) => return invalid_entry(index, Some(reason)),
        };
        parts.push(p);
        records.push(record);
    }
    let entries: Vec<Entry<'_>> = parts
        .into_iter()
        .zip(&records)
        .map(|(p, record)| Entry {
            id: p.id,
            record,
            position: p.position,
            recorded_at: p.recorded_at,
            ingest: p.ingest,
            restriction: p.restriction,
            issuer: p.issuer,
        })
        .collect();
    let kernel_inputs = DerivationInputs {
        protocol: inputs.protocol,
        profile: inputs.profile,
        practices: &inputs.practices,
        trust: TrustInputs {
            trusted_publishers: &inputs.trusted_publishers,
        },
        ledger_time: inputs.ledger_time,
        calendar: inputs.calendar,
    };
    match derive(&entries, &kernel_inputs) {
        Ok(d) => json!({
            "derivation": {
                "records": d.records.iter().map(derived).collect::<Vec<_>>(),
                "chains": d.chains.iter().map(chain).collect::<Vec<_>>(),
            }
        })
        .to_string(),
        Err(e) => derive_error(e),
    }
}
