//! Decodes `SignedRecord` bytes into the kernel's typed record: the shared strict decoder and its structural limits first, then the protocol version, then the protocol 1.0 schema, where the first field that does not fit decides the reason (P-5, P-7, P-72, P-87, P-94).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::SHA256_ALG;

use super::read::{
    MISSING, Mapped, bytes, closed, digest_value, entries, get, list, optional, pair, party,
    protocol, required, text, text_entries, uint, versions,
};
use super::{decode, schema};
use crate::id::{LedgerId, RecordId, Time, WorkId};
use crate::reason::{QuarantineReason, Reason, Schema};
use crate::record::{
    Act, Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Claim, ClaimType,
    Correlation, Declaration, EvidenceRef, EvidenceSubject, EvidenceType, ExtValue, Extension,
    Kind, Param, ParamScalar, ParamValue, PartName, ProducerRef, ProtocolVersion, Record,
    RecordCore, Visibility,
};
use crate::relation::{Endpoint, Relation};
use crate::rules::RuleSet;
use crate::uri::{ExtKey, ExternalRef, TypeUri};
use crate::validate::{Outcome, ValidationContext, validate};

const FIELDS: &[&str] = &[
    "kind",
    "type",
    "occurred_at",
    "author",
    "on_behalf_of",
    "capacity",
    "basis",
    "visibility",
    "ledger",
    "concerns",
    "relations",
    "authority",
    "producer",
    "correlation",
    "evidence",
    "body",
    "params",
    "versions",
    "ext",
    "critical",
];
const VISIBILITY_FIELDS: &[&str] = &["see", "search", "agent_context"];
const RELATION_FIELDS: &[&str] = &["rel", "source", "target", "qualifier"];
const AUTHORITY_FIELDS: &[&str] = &["proof", "digest"];
const PRODUCER_FIELDS: &[&str] = &[
    "version",
    "config",
    "model",
    "toolset",
    "instructions",
    "attestation",
];
const EVIDENCE_FIELDS: &[&str] = &[
    "subject",
    "type",
    "presenter",
    "claimed_at",
    "source",
    "observation",
    "visibility",
    "signature",
];
const BODY_FIELDS: &[&str] = &["part", "commit"];

/// A decoded `SignedRecord`, or the protocol version of one this kernel has no rule set for (P-87).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// A protocol 1.0 record.
    Record(Box<Record>),
    /// A record of a protocol version without a rule set; it is quarantined, never mapped (P-87, P-94).
    UnknownProtocol(ProtocolVersion),
}

/// Decodes `SignedRecord` bytes under the shared structural ceilings (P-5, P-7).
///
/// # Errors
///
/// A CBOR, limit or schema reason.
pub fn decode_record(bytes: &[u8]) -> Result<Decoded, Reason> {
    decode_record_with(bytes, Limits::CEILING)
}

/// Decodes `SignedRecord` bytes under narrowed structural limits (P-7, T-65).
///
/// # Errors
///
/// A CBOR, limit or schema reason.
pub fn decode_record_with(bytes: &[u8], limits: Limits) -> Result<Decoded, Reason> {
    record_from_value(&decode(bytes, limits)?)
}

/// Decodes and validates `SignedRecord` bytes: the decision the kernel gives for the bytes as received (P-11, P-19, P-87).
#[must_use]
pub fn check_record(bytes: &[u8], ctx: &ValidationContext<'_>) -> Outcome {
    match decode_record(bytes) {
        Err(reason) => Outcome::Rejected(reason),
        Ok(Decoded::UnknownProtocol(_)) => {
            Outcome::Quarantined(QuarantineReason::ProtocolVersionUnknown)
        }
        Ok(Decoded::Record(record)) => validate(&record, ctx),
    }
}

/// Maps a decoded value onto a record, reading `versions.protocol` before anything else (P-87, P-94).
///
/// # Errors
///
/// A schema or limit reason.
pub fn record_from_value(v: &Value) -> Result<Decoded, Reason> {
    let version = get(entries(v)?, "versions")
        .and_then(|versions| entries(versions).ok())
        .and_then(|versions| get(versions, "protocol"))
        .map(protocol);
    match version {
        Some(Ok(p)) if RuleSet::for_version(p).is_none() => Ok(Decoded::UnknownProtocol(p)),
        _ => record(v).map(|r| Decoded::Record(Box::new(r))),
    }
}

fn type_uri(v: &Value) -> Mapped<TypeUri> {
    TypeUri::parse(text(v)?).ok_or(schema(Schema::TypeUri))
}

fn ext_key(v: &str) -> Mapped<ExtKey> {
    TypeUri::parse(v).ok_or(schema(Schema::ExtKey))
}

fn external(v: &Value) -> Mapped<ExternalRef> {
    ExternalRef::parse(text(v)?).ok_or(MISSING)
}

fn time(v: &Value) -> Mapped<Time> {
    uint(v).map(Time)
}

fn work_id(v: &Value) -> Mapped<WorkId> {
    let id: [u8; 16] = bytes(v)?.try_into().map_err(|_| MISSING)?;
    Ok(WorkId::from_bytes(id))
}

fn record_id(v: &Value) -> Mapped<RecordId> {
    digest_value(v).map(RecordId)
}

/// `search` and `agent_context` are written only as `false` (P-77, EV-21).
fn exclusion(m: &[(Value, Value)], key: &str) -> Mapped<bool> {
    match get(m, key) {
        None => Ok(false),
        Some(Value::Bool(false)) => Ok(true),
        Some(_) => Err(MISSING),
    }
}

fn visibility(v: &Value) -> Mapped<Visibility> {
    let m = closed(v, VISIBILITY_FIELDS)?;
    let see = match required(m, "see")? {
        Value::Text(s) if s == "work" => Audience::Work,
        Value::Text(s) if s == "author" => Audience::Author,
        Value::Array(a) => match a.as_slice() {
            [Value::Text(tag), parties] if tag == "parties" => {
                Audience::Parties(list(parties, party)?)
            }
            _ => return Err(MISSING),
        },
        _ => return Err(MISSING),
    };
    Ok(Visibility {
        see,
        search_excluded: exclusion(m, "search")?,
        agent_context_excluded: exclusion(m, "agent_context")?,
    })
}

fn endpoint(v: &Value) -> Mapped<Endpoint> {
    let mismatch = schema(Schema::Relation);
    let Value::Array(items) = v else {
        return Err(mismatch);
    };
    let [tag, value] = items.as_slice() else {
        return Err(mismatch);
    };
    let tag = match tag {
        Value::Text(t) => t.as_str(),
        _ => return Err(mismatch),
    };
    Ok(match tag {
        "record" => Endpoint::Record(record_id(value)?),
        "work" => Endpoint::Work(work_id(value)?),
        "party" => Endpoint::Party(party(value)?),
        "external" => Endpoint::External(external(value)?),
        "evidence" => Endpoint::Evidence(digest_value(value)?),
        _ => return Err(mismatch),
    })
}

fn relation(v: &Value) -> Mapped<Relation> {
    let m = closed(v, RELATION_FIELDS)?;
    let qualifier = match get(m, "qualifier") {
        None => None,
        Some(Value::Text(q)) => Some(q.as_str()),
        Some(_) => return Err(schema(Schema::Relation)),
    };
    Relation::from_wire(
        text(required(m, "rel")?)?,
        optional(m, "source", endpoint)?,
        endpoint(required(m, "target")?)?,
        qualifier,
    )
}

fn evidence(v: &Value) -> Mapped<EvidenceRef> {
    let m = closed(v, EVIDENCE_FIELDS)?;
    let subject = match required(m, "subject")? {
        Value::Text(s) => EvidenceSubject::StableId(s.clone()),
        other => EvidenceSubject::Digest(digest_value(other)?),
    };
    Ok(EvidenceRef {
        subject,
        evidence_type: EvidenceType::from_uri(type_uri(required(m, "type")?)?),
        presenter: party(required(m, "presenter")?)?,
        claimed_at: optional(m, "claimed_at", time)?,
        source: optional(m, "source", external)?,
        observation: optional(m, "observation", digest_value)?,
        visibility: optional(m, "visibility", visibility)?,
        signature: digest_value(required(m, "signature")?)?,
    })
}

/// A `[-16, _]` value is a digest, never a list of two scalars (P-80).
fn is_digest(v: &Value) -> bool {
    matches!(v, Value::Array(items) if matches!(items.as_slice(), [alg, _] if alg.as_i64() == Some(SHA256_ALG)))
}

fn scalar(v: &Value) -> Mapped<ParamScalar> {
    let params = schema(Schema::Params);
    match v {
        Value::Unsigned(u) => Ok(ParamScalar::Uint(*u)),
        Value::Bool(b) => Ok(ParamScalar::Bool(*b)),
        Value::Text(t) => Ok(ParamScalar::Text(t.clone())),
        Value::Bytes(b) => <[u8; 16]>::try_from(b.as_slice())
            .map(|id| ParamScalar::WorkId(WorkId::from_bytes(id)))
            .map_err(|_| params),
        Value::Array(_) if is_digest(v) => digest_value(v).map(ParamScalar::Digest),
        Value::Negative(_) | Value::Array(_) | Value::Map(_) | Value::Tag(..) => Err(params),
    }
}

fn param_value(v: &Value) -> Mapped<ParamValue> {
    match v {
        Value::Array(items) if !is_digest(v) => Ok(ParamValue::List(
            items.iter().map(scalar).collect::<Mapped<Vec<_>>>()?,
        )),
        other => Ok(ParamValue::Scalar(scalar(other)?)),
    }
}

fn params(v: &Value) -> Mapped<Vec<Param>> {
    text_entries(v, schema(Schema::Params))?
        .into_iter()
        .map(|(k, v)| {
            Ok(Param {
                name: PartName::parse(k).ok_or(schema(Schema::Params))?,
                value: param_value(v)?,
            })
        })
        .collect()
}

/// Extension values keep their deterministic CBOR bytes; the kernel never interprets them (P-19, P-69).
fn extensions(v: &Value) -> Mapped<Vec<Extension>> {
    text_entries(v, schema(Schema::ExtKey))?
        .into_iter()
        .map(|(k, x)| {
            Ok(Extension {
                key: ext_key(k)?,
                value: ExtValue(dcbor::encode(x, Limits::CEILING).map_err(|_| MISSING)?),
            })
        })
        .collect()
}

fn capacity(v: &Value) -> Mapped<Capacity> {
    match v {
        Value::Text(s) if s == "own" => Ok(Capacity::Own),
        Value::Array(a) => match a.as_slice() {
            [Value::Text(tag), principal] if tag == "for" => Ok(Capacity::For(party(principal)?)),
            _ => Err(MISSING),
        },
        _ => Err(MISSING),
    }
}

fn authority(v: &Value) -> Mapped<AuthorityRef> {
    let a = closed(v, AUTHORITY_FIELDS)?;
    Ok(AuthorityRef {
        proof: AuthorityProofKind::from_wire_name(text(required(a, "proof")?)?).ok_or(MISSING)?,
        digest: digest_value(required(a, "digest")?)?,
    })
}

fn producer(v: &Value) -> Mapped<ProducerRef> {
    let p = closed(v, PRODUCER_FIELDS)?;
    Ok(ProducerRef {
        version: String::from(text(required(p, "version")?)?),
        config: digest_value(required(p, "config")?)?,
        model: optional(p, "model", external)?,
        toolset: optional(p, "toolset", digest_value)?,
        instructions: optional(p, "instructions", digest_value)?,
        attestation: optional(p, "attestation", digest_value)?,
    })
}

fn correlation(v: &Value) -> Mapped<Correlation> {
    let (scheme, id) = pair(v)?;
    Ok(Correlation {
        scheme: type_uri(scheme)?,
        id: String::from(text(id)?),
    })
}

fn body(v: &Value) -> Mapped<BodyCommitment> {
    let b = closed(v, BODY_FIELDS)?;
    Ok(BodyCommitment {
        part: PartName::parse(text(required(b, "part")?)?).ok_or(MISSING)?,
        commit: digest_value(required(b, "commit")?)?,
    })
}

fn record(v: &Value) -> Mapped<Record> {
    let m = closed(v, FIELDS)?;
    let kind = Kind::from_wire_name(text(required(m, "kind")?)?).ok_or(schema(Schema::Kind))?;
    let subtype = type_uri(required(m, "type")?)?;
    let ext = optional(m, "ext", extensions)?;
    let core = RecordCore {
        author: party(required(m, "author")?)?,
        on_behalf_of: optional(m, "on_behalf_of", |l| list(l, party))?,
        capacity: optional(m, "capacity", capacity)?,
        basis: optional(m, "basis", |l| list(l, record_id))?,
        visibility: visibility(required(m, "visibility")?)?,
        ledger: LedgerId(digest_value(required(m, "ledger")?)?),
        concerns: list(required(m, "concerns")?, work_id)?,
        relations: optional(m, "relations", |l| list(l, relation))?,
        authority: optional(m, "authority", authority)?,
        producer: optional(m, "producer", producer)?,
        correlation: optional(m, "correlation", |l| list(l, correlation))?,
        evidence: optional(m, "evidence", |l| list(l, evidence))?,
        body: optional(m, "body", |l| list(l, body))?,
        params: optional(m, "params", params)?,
        versions: versions(required(m, "versions")?)?,
        ext,
        critical: optional(m, "critical", |l| list(l, |k| ext_key(text(k)?)))?,
    };
    let occurred_at = optional(m, "occurred_at", time)?;
    Ok(match kind {
        Kind::Act => Record::Act(Act {
            subtype,
            occurred_at: occurred_at.ok_or(MISSING)?,
            core,
        }),
        Kind::Declaration => Record::Declaration(Declaration {
            subtype,
            occurred_at,
            core,
        }),
        Kind::Claim => Record::Claim(Claim {
            subtype: ClaimType::from_uri(subtype),
            occurred_at: occurred_at.ok_or(MISSING)?,
            core,
        }),
    })
}
