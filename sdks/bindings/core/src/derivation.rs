//! Verifies stored ledger entries from their bytes, folds them with the derivation inputs from JSON through the kernel and writes the derived view back as JSON; every record ID, position, time and ingest comes from the verified bytes, never from the caller (T-10).

use serde_json::{Map, Value, json};
use work_kernel::codec::Decoded;
use work_kernel::cose::AuthorKeys;
use work_kernel::derive::{
    Admission, AuthorityIssuer, BusinessCalendar, Chain, ChainStatus, DerivationInputs,
    DeriveError, DerivedRecord, Effect, Entry, NoEffect, ProfileVersion, Restriction, TrustInputs,
    derive,
};
use work_kernel::id::{PartyRef, RecordId, Time};
use work_kernel::reason::{Reason, Schema};
use work_kernel::record::{PracticePin, ProtocolVersion};
use work_kernel::verify::{StoredEntry, Verified as Stored, VerifiedEntry, verify_entry};

use crate::decode::{
    self, Mapped, exact_keys, hex, list, object, optional, pair, party, required, text, uint,
};
use crate::ledger::point;
use crate::project::digest_json;
use crate::signature::keys;
use crate::{error, input_error, parse};

const MISSING: Reason = Reason::Schema(Schema::RequiredField);

const ENTRIES_FIELDS: &[&str] = &["at", "entries"];

const ENTRY_FIELDS: &[&str] = &[
    "envelope",
    "record",
    "cose_sign1",
    "author_keys",
    "restriction",
    "issuer",
];

const INPUT_FIELDS: &[&str] = &[
    "activations",
    "profile",
    "practices",
    "trusted_publishers",
    "ledger_time",
    "calendar",
];

struct EntryParts {
    envelope: Vec<u8>,
    record: Vec<u8>,
    cose_sign1: Option<Vec<u8>>,
    author_keys: String,
    restriction: Restriction,
    issuer: AuthorityIssuer,
}

struct Inputs {
    activations: Vec<(u64, ProtocolVersion)>,
    profile: ProfileVersion,
    practices: Vec<PracticePin>,
    trusted_publishers: Vec<PartyRef>,
    ledger_time: Time,
    calendar: BusinessCalendar,
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
        envelope: hex(required(m, "envelope")?)?,
        record: hex(required(m, "record")?)?,
        cose_sign1: optional(m, "cose_sign1", hex)?,
        author_keys: required(m, "author_keys")?.to_string(),
        restriction: restriction(required(m, "restriction")?)?,
        issuer: issuer(required(m, "issuer")?)?,
    })
}

fn protocol(v: &Value) -> Mapped<ProtocolVersion> {
    let (major, minor) = pair(v)?;
    Ok(ProtocolVersion {
        major: uint(major)?,
        minor: uint(minor)?,
    })
}

fn activation(v: &Value) -> Mapped<(u64, ProtocolVersion)> {
    let (position, version) = pair(v)?;
    Ok((uint(position)?, protocol(version)?))
}

fn inputs(v: &Value) -> Mapped<Inputs> {
    let m = object(v)?;
    exact_keys(m, INPUT_FIELDS)?;
    Ok(Inputs {
        activations: list(required(m, "activations")?, activation)?,
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

struct Verified {
    index: usize,
    entry: VerifiedEntry,
    restriction: Restriction,
    issuer: AuthorityIssuer,
}

fn shape(v: &Value) -> Option<(&Value, &[Value])> {
    let m = v.as_object()?;
    exact_keys(m, ENTRIES_FIELDS).ok()?;
    let items = m.get("entries")?.as_array()?;
    Some((m.get("at")?, items.as_slice()))
}

fn verified_entries(at: &Value, items: &[Value]) -> Result<Vec<Verified>, String> {
    let Ok(mut at) = point(at) else {
        return Err(input_error("invalid_chain_point"));
    };
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Ok(p) = object(item).and_then(entry_parts) else {
            return Err(invalid_entry(index, None));
        };
        let Ok(k) = keys(&p.author_keys) else {
            return Err(invalid_entry(index, None));
        };
        let port = AuthorKeys {
            author: &k.party,
            keys: &k.set,
        };
        let stored = StoredEntry {
            envelope: &p.envelope,
            record: &p.record,
            cose_sign1: p.cose_sign1.as_deref(),
        };
        let entry = match verify_entry(&port, &at, &stored) {
            Ok(v) => v,
            Err(reason) => return Err(invalid_entry(index, Some(reason))),
        };
        at = entry.next();
        if let Stored::Record(entry) = entry {
            out.push(Verified {
                index,
                entry,
                restriction: p.restriction,
                issuer: p.issuer,
            });
        }
    }
    Ok(out)
}

/// Verifies stored ledger entries from their bytes and folds them into the derived view (P-31, T-6, T-10).
///
/// `entries` is `{"at": {"ledger": [-16, <hex>], "prev": [-16, <hex>]}, "entries": [...]}`: `at` is the chain point the first entry continues (from [`crate::genesis_chain_point`] or an earlier entry's `next`), and each entry in ledger order is `{"envelope": <hex>, "record": <hex>, "cose_sign1"?: <hex>, "author_keys", "restriction", "issuer"}` with `author_keys` in the shape of [`crate::verify_record_signature`]'s keys, `restriction` `"no_objection"`, `"deny"` or `"require"`, and `issuer` `"local"` or `["federated", <PartyRef>]`. Each entry is verified as [`crate::verify_entry`] verifies it; the record ID, record, position, time and ingest the fold reads come from the verified bytes, never from the caller. `inputs` is `{"activations": [[position, [major, minor]]], "profile", "practices": {<namespace>: <digest>}, "trusted_publishers", "ledger_time", "calendar": "continuous"}`.
///
/// Returns `{"derivation":{"records":[…],"chains":[…]}}`, or `{"error":{"code":…}}` with `invalid_json`, `invalid_inputs`, `invalid_entries`, `invalid_chain_point`, `invalid_entry` (with `index`, and `reason` when the entry does not verify or its record is of an unknown protocol version) or a kernel derivation error (`position_gap`, `recorded_at_out_of_order`, `duplicate_record`, `ledger_mismatch`, `overflow`).
#[must_use]
pub fn derive_records(entries: &str, inputs_json: &str) -> String {
    let (Some(entries), Some(inputs_value)) = (parse(entries), parse(inputs_json)) else {
        return input_error("invalid_json");
    };
    let Ok(inputs) = inputs(&inputs_value) else {
        return input_error("invalid_inputs");
    };
    let Some((at, items)) = shape(&entries) else {
        return input_error("invalid_entries");
    };
    let verified = match verified_entries(at, items) {
        Ok(v) => v,
        Err(answer) => return answer,
    };
    let mut entries: Vec<Entry<'_>> = Vec::with_capacity(verified.len());
    for v in &verified {
        let Some(entry) = Entry::verified(&v.entry, v.restriction, v.issuer.clone()) else {
            let unknown = matches!(v.entry.record(), Decoded::UnknownProtocol(_));
            return invalid_entry(v.index, unknown.then_some(Reason::ProtocolVersionUnknown));
        };
        entries.push(entry);
    }
    let kernel_inputs = DerivationInputs {
        activations: &inputs.activations,
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
