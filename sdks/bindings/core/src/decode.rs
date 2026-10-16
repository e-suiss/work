//! Maps the `decoded` JSON projection of a record onto the kernel's typed record; a value the projection cannot carry is the `schema:*` reason the kernel would give for the same bytes.

use serde_json::{Map, Value};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time, WorkId, canonical_text_cmp};
use work_kernel::reason::{Reason, Schema};
use work_kernel::record::{
    Act, Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Claim, ClaimType,
    Correlation, Declaration, EvidenceRef, EvidenceSubject, EvidenceType, ExtValue, Extension,
    Kind, Param, ParamScalar, ParamValue, PartName, PracticePin, ProducerRef, ProtocolVersion,
    Record, RecordCore, VersionVector, Visibility,
};
use work_kernel::relation::{Endpoint, Relation};
use work_kernel::uri::{ExtKey, ExternalRef, TypeUri};

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

pub(crate) type Mapped<T> = Result<T, Reason>;

const fn schema(detail: Schema) -> Reason {
    Reason::Schema(detail)
}

const MISSING: Reason = schema(Schema::RequiredField);

pub(crate) fn text(v: &Value) -> Mapped<&str> {
    v.as_str().ok_or(MISSING)
}

/// An unsigned integer: a JSON number, or a decimal string beyond 2^53.
pub(crate) fn uint(v: &Value) -> Mapped<u64> {
    match v {
        Value::Number(n) => n.as_u64().ok_or(MISSING),
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().map_err(|_| MISSING)
        }
        _ => Err(MISSING),
    }
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|n| n.checked_add(10)),
        _ => None,
    }
}

fn hex(v: &Value) -> Mapped<Vec<u8>> {
    let s = text(v)?.as_bytes();
    if !s.len().is_multiple_of(2) {
        return Err(MISSING);
    }
    let (pairs, _) = s.as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| {
            nibble(hi)
                .and_then(|h| h.checked_shl(4))
                .zip(nibble(lo))
                .map(|(h, l)| h | l)
                .ok_or(MISSING)
        })
        .collect()
}

pub(crate) fn digest(v: &Value) -> Mapped<Digest> {
    let [alg, value] = v.as_array().map(Vec::as_slice).ok_or(MISSING)? else {
        return Err(MISSING);
    };
    if alg.as_i64() != Some(-16) {
        return Err(schema(Schema::DigestAlg));
    }
    let bytes: [u8; 32] = hex(value)?
        .try_into()
        .map_err(|_| schema(Schema::DigestLength))?;
    Ok(Digest::sha256(bytes))
}

pub(crate) fn party(v: &Value) -> Mapped<PartyRef> {
    PartyRef::new(text(v)?).ok_or(MISSING)
}

fn type_uri(v: &Value) -> Mapped<TypeUri> {
    TypeUri::parse(text(v)?).ok_or(schema(Schema::TypeUri))
}

pub(crate) fn ext_key(v: &str) -> Mapped<ExtKey> {
    TypeUri::parse(v).ok_or(schema(Schema::ExtKey))
}

fn external(v: &Value) -> Mapped<ExternalRef> {
    ExternalRef::parse(text(v)?).ok_or(MISSING)
}

pub(crate) fn list<T>(v: &Value, f: impl Fn(&Value) -> Mapped<T>) -> Mapped<Vec<T>> {
    v.as_array().ok_or(MISSING)?.iter().map(f).collect()
}

pub(crate) fn optional<T>(
    m: &Map<String, Value>,
    key: &str,
    f: impl Fn(&Value) -> Mapped<T>,
) -> Mapped<Option<T>> {
    m.get(key).map(f).transpose()
}

pub(crate) fn required<'a>(m: &'a Map<String, Value>, key: &str) -> Mapped<&'a Value> {
    m.get(key).ok_or(MISSING)
}

pub(crate) fn object(v: &Value) -> Mapped<&Map<String, Value>> {
    v.as_object().ok_or(MISSING)
}

fn canonical_entries(m: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut entries: Vec<_> = m.iter().collect();
    entries.sort_by(|a, b| canonical_text_cmp(a.0, b.0));
    entries
}

pub(crate) fn practices(v: &Value) -> Mapped<Vec<PracticePin>> {
    canonical_entries(object(v)?)
        .into_iter()
        .map(|(k, d)| {
            Ok(PracticePin {
                namespace: TypeUri::parse(k).ok_or(schema(Schema::TypeUri))?,
                digest: digest(d)?,
            })
        })
        .collect()
}

pub(crate) fn pair(v: &Value) -> Mapped<(&Value, &Value)> {
    match v.as_array().map(Vec::as_slice) {
        Some([a, b]) => Ok((a, b)),
        _ => Err(MISSING),
    }
}

fn time(v: &Value) -> Mapped<Time> {
    uint(v).map(Time)
}

fn work_id(v: &Value) -> Mapped<WorkId> {
    let bytes: [u8; 16] = hex(v)?.try_into().map_err(|_| MISSING)?;
    Ok(WorkId::from_bytes(bytes))
}

fn visibility(v: &Value) -> Mapped<Visibility> {
    let m = object(v)?;
    let see = match required(m, "see")? {
        Value::String(s) if s == "work" => Audience::Work,
        Value::String(s) if s == "author" => Audience::Author,
        Value::Array(a) => match a.as_slice() {
            [tag, parties] if tag == "parties" => Audience::Parties(list(parties, party)?),
            _ => return Err(MISSING),
        },
        _ => return Err(MISSING),
    };
    Ok(Visibility {
        see,
        search_excluded: m.get("search") == Some(&Value::Bool(false)),
        agent_context_excluded: m.get("agent_context") == Some(&Value::Bool(false)),
    })
}

fn endpoint(v: &Value) -> Mapped<Endpoint> {
    let mismatch = schema(Schema::Relation);
    let Some([tag, value, ..]) = v.as_array().map(Vec::as_slice) else {
        return Err(mismatch);
    };
    Ok(match tag.as_str() {
        Some("record") => Endpoint::Record(RecordId(digest(value)?)),
        Some("work") => Endpoint::Work(work_id(value)?),
        Some("party") => Endpoint::Party(party(value)?),
        Some("external") => Endpoint::External(external(value)?),
        Some("evidence") => Endpoint::Evidence(digest(value)?),
        _ => return Err(mismatch),
    })
}

fn relation(v: &Value) -> Mapped<Relation> {
    let m = object(v)?;
    Relation::from_wire(
        text(required(m, "rel")?)?,
        optional(m, "source", endpoint)?,
        endpoint(required(m, "target")?)?,
        m.get("qualifier").and_then(Value::as_str),
    )
}

fn evidence(v: &Value) -> Mapped<EvidenceRef> {
    let m = object(v)?;
    let subject = match required(m, "subject")? {
        Value::String(s) => EvidenceSubject::StableId(s.clone()),
        other => EvidenceSubject::Digest(digest(other)?),
    };
    Ok(EvidenceRef {
        subject,
        evidence_type: EvidenceType::from_uri(type_uri(required(m, "type")?)?),
        presenter: party(required(m, "presenter")?)?,
        claimed_at: optional(m, "claimed_at", time)?,
        source: optional(m, "source", external)?,
        observation: optional(m, "observation", digest)?,
        visibility: optional(m, "visibility", visibility)?,
        signature: digest(required(m, "signature")?)?,
    })
}

fn versions(v: &Value) -> Mapped<VersionVector> {
    let m = object(v)?;
    let (major, minor) = pair(required(m, "protocol")?)?;
    let protocol = ProtocolVersion {
        major: uint(major)?,
        minor: uint(minor)?,
    };
    let practices = optional(m, "practices", practices)?;
    Ok(VersionVector {
        protocol,
        schema: digest(required(m, "schema")?)?,
        practices,
    })
}

fn scalar(v: &Value) -> Mapped<ParamScalar> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .map(ParamScalar::Uint)
            .ok_or(schema(Schema::Params)),
        Value::Bool(b) => Ok(ParamScalar::Bool(*b)),
        Value::String(t) => Ok(ParamScalar::Text(t.clone())),
        Value::Array(_) => digest(v).map(ParamScalar::Digest),
        Value::Null | Value::Object(_) => Err(schema(Schema::Params)),
    }
}

fn params(v: &Value) -> Mapped<Vec<Param>> {
    canonical_entries(object(v)?)
        .into_iter()
        .map(|(k, v)| {
            Ok(Param {
                name: PartName::parse(k).ok_or(schema(Schema::Params))?,
                value: match v {
                    Value::Array(items) => {
                        ParamValue::List(items.iter().map(scalar).collect::<Mapped<Vec<_>>>()?)
                    }
                    other => ParamValue::Scalar(scalar(other)?),
                },
            })
        })
        .collect()
}

/// Extension values keep their compact JSON text until CBOR decoding exists; the kernel never interprets them (P-19).
fn extensions(v: &Value) -> Mapped<Vec<Extension>> {
    canonical_entries(object(v)?)
        .into_iter()
        .map(|(k, x)| {
            Ok(Extension {
                key: ext_key(k)?,
                value: ExtValue(serde_json::to_vec(x).map_err(|_| MISSING)?),
            })
        })
        .collect()
}

fn capacity(v: &Value) -> Mapped<Capacity> {
    match v {
        Value::String(s) if s == "own" => Ok(Capacity::Own),
        Value::Array(a) => match a.as_slice() {
            [tag, principal] if tag == "for" => Ok(Capacity::For(party(principal)?)),
            _ => Err(MISSING),
        },
        _ => Err(MISSING),
    }
}

fn authority(v: &Value) -> Mapped<AuthorityRef> {
    let a = object(v)?;
    Ok(AuthorityRef {
        proof: AuthorityProofKind::from_wire_name(text(required(a, "proof")?)?).ok_or(MISSING)?,
        digest: digest(required(a, "digest")?)?,
    })
}

fn producer(v: &Value) -> Mapped<ProducerRef> {
    let p = object(v)?;
    Ok(ProducerRef {
        version: text(required(p, "version")?)?.to_owned(),
        config: digest(required(p, "config")?)?,
        model: optional(p, "model", external)?,
        toolset: optional(p, "toolset", digest)?,
        instructions: optional(p, "instructions", digest)?,
        attestation: optional(p, "attestation", digest)?,
    })
}

fn correlation(v: &Value) -> Mapped<Correlation> {
    let (scheme, id) = pair(v)?;
    Ok(Correlation {
        scheme: type_uri(scheme)?,
        id: text(id)?.to_owned(),
    })
}

fn body(v: &Value) -> Mapped<BodyCommitment> {
    let b = object(v)?;
    Ok(BodyCommitment {
        part: PartName::parse(text(required(b, "part")?)?).ok_or(MISSING)?,
        commit: digest(required(b, "commit")?)?,
    })
}

/// Maps a decoded record; the first field that does not fit decides the reason, in the order the vectors expect.
pub(crate) fn record(v: &Value) -> Mapped<Record> {
    let m = object(v)?;
    if m.keys().any(|k| !FIELDS.contains(&k.as_str())) {
        return Err(schema(Schema::UnknownCoreField));
    }
    let kind = Kind::from_wire_name(text(required(m, "kind")?)?).ok_or(schema(Schema::Kind))?;
    let subtype = type_uri(required(m, "type")?)?;
    let ext = optional(m, "ext", extensions)?;
    let core = RecordCore {
        author: party(required(m, "author")?)?,
        on_behalf_of: optional(m, "on_behalf_of", |l| list(l, party))?,
        capacity: optional(m, "capacity", capacity)?,
        basis: optional(m, "basis", |l| list(l, |d| Ok(RecordId(digest(d)?))))?,
        visibility: visibility(required(m, "visibility")?)?,
        ledger: LedgerId(digest(required(m, "ledger")?)?),
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
