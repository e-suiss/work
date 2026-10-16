//! The record rules against the `decoded` projection of the shared record vectors in `conformance/vectors/records` (P-11, T-37).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "test code"
)]

use serde_json::{Map, Value};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time, WorkId, canonical_text_cmp};
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::{Reason, Schema};
use work_kernel::record::{
    Act, Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Claim, ClaimType,
    Correlation, Declaration, EvidenceRef, EvidenceSubject, EvidenceType, ExtValue, Extension,
    Kind, Param, ParamScalar, ParamValue, PartName, PracticePin, ProducerRef, ProtocolVersion,
    Record, RecordCore, VersionVector, Visibility,
};
use work_kernel::relation::{Endpoint, Relation};
use work_kernel::uri::{ExtKey, ExternalRef, TypeUri};
use work_kernel::validate::{
    ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin, Outcome, ValidationContext,
    validate,
};

const RECORDS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/records/records.json"
));
const REJECTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/records/records-reject.json"
));
const QUARANTINE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/records/records-quarantine.json"
));

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

type Mapped<T> = Result<T, Reason>;

fn schema(detail: Schema) -> Reason {
    Reason::Schema(detail)
}

fn text(v: &Value) -> Mapped<&str> {
    v.as_str().ok_or(schema(Schema::RequiredField))
}

fn hex(v: &Value) -> Mapped<Vec<u8>> {
    let s = text(v)?;
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| schema(Schema::RequiredField)))
        .collect()
}

fn digest(v: &Value) -> Mapped<Digest> {
    let pair = v.as_array().ok_or(schema(Schema::RequiredField))?;
    if pair.len() != 2 {
        return Err(schema(Schema::RequiredField));
    }
    if pair[0].as_i64() != Some(-16) {
        return Err(schema(Schema::DigestAlg));
    }
    let bytes: [u8; 32] = hex(&pair[1])?
        .try_into()
        .map_err(|_| schema(Schema::DigestLength))?;
    Ok(Digest::sha256(bytes))
}

fn party(v: &Value) -> Mapped<PartyRef> {
    PartyRef::new(text(v)?).ok_or(schema(Schema::RequiredField))
}

fn type_uri(v: &Value) -> Mapped<TypeUri> {
    TypeUri::parse(text(v)?).ok_or(schema(Schema::TypeUri))
}

fn ext_key(v: &str) -> Mapped<ExtKey> {
    TypeUri::parse(v).ok_or(schema(Schema::ExtKey))
}

fn external(v: &Value) -> Mapped<ExternalRef> {
    ExternalRef::parse(text(v)?).ok_or(schema(Schema::RequiredField))
}

fn list<T>(v: &Value, f: impl Fn(&Value) -> Mapped<T>) -> Mapped<Vec<T>> {
    v.as_array()
        .ok_or(schema(Schema::RequiredField))?
        .iter()
        .map(f)
        .collect()
}

fn optional<T>(
    m: &Map<String, Value>,
    key: &str,
    f: impl Fn(&Value) -> Mapped<T>,
) -> Mapped<Option<T>> {
    m.get(key).map(f).transpose()
}

fn required<'a>(m: &'a Map<String, Value>, key: &str) -> Mapped<&'a Value> {
    m.get(key).ok_or(schema(Schema::RequiredField))
}

fn object(v: &Value) -> Mapped<&Map<String, Value>> {
    v.as_object().ok_or(schema(Schema::RequiredField))
}

fn canonical_entries(m: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut entries: Vec<_> = m.iter().collect();
    entries.sort_by(|a, b| canonical_text_cmp(a.0, b.0));
    entries
}

fn work_id(v: &Value) -> Mapped<WorkId> {
    let bytes: [u8; 16] = hex(v)?
        .try_into()
        .map_err(|_| schema(Schema::RequiredField))?;
    Ok(WorkId::from_bytes(bytes))
}

fn visibility(v: &Value) -> Mapped<Visibility> {
    let m = object(v)?;
    let see = match required(m, "see")? {
        Value::String(s) if s == "work" => Audience::Work,
        Value::String(s) if s == "author" => Audience::Author,
        Value::Array(a) if a.len() == 2 && a[0] == "parties" => {
            Audience::Parties(list(&a[1], party)?)
        }
        _ => return Err(schema(Schema::RequiredField)),
    };
    Ok(Visibility {
        see,
        search_excluded: m.get("search") == Some(&Value::Bool(false)),
        agent_context_excluded: m.get("agent_context") == Some(&Value::Bool(false)),
    })
}

fn endpoint(v: &Value) -> Mapped<Endpoint> {
    let pair = v.as_array().ok_or(schema(Schema::Relation))?;
    let value = pair.get(1).ok_or(schema(Schema::Relation))?;
    Ok(match pair[0].as_str() {
        Some("record") => Endpoint::Record(RecordId(digest(value)?)),
        Some("work") => Endpoint::Work(work_id(value)?),
        Some("party") => Endpoint::Party(party(value)?),
        Some("external") => Endpoint::External(external(value)?),
        Some("evidence") => Endpoint::Evidence(digest(value)?),
        _ => return Err(schema(Schema::Relation)),
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
        claimed_at: optional(m, "claimed_at", |t| Ok(Time(t.as_u64().unwrap())))?,
        source: optional(m, "source", external)?,
        observation: optional(m, "observation", digest)?,
        visibility: optional(m, "visibility", visibility)?,
        signature: digest(required(m, "signature")?)?,
    })
}

fn versions(v: &Value) -> Mapped<VersionVector> {
    let m = object(v)?;
    let protocol = required(m, "protocol")?.as_array().unwrap();
    let practices = optional(m, "practices", |p| {
        canonical_entries(object(p)?)
            .into_iter()
            .map(|(k, d)| {
                Ok(PracticePin {
                    namespace: TypeUri::parse(k).ok_or(schema(Schema::TypeUri))?,
                    digest: digest(d)?,
                })
            })
            .collect()
    })?;
    Ok(VersionVector {
        protocol: ProtocolVersion {
            major: protocol[0].as_u64().unwrap(),
            minor: protocol[1].as_u64().unwrap(),
        },
        schema: digest(required(m, "schema")?)?,
        practices,
    })
}

fn record(v: &Value) -> Mapped<Record> {
    let m = object(v)?;
    if m.keys().any(|k| !FIELDS.contains(&k.as_str())) {
        return Err(schema(Schema::UnknownCoreField));
    }
    let kind = Kind::from_wire_name(text(required(m, "kind")?)?).ok_or(schema(Schema::Kind))?;
    let subtype = type_uri(required(m, "type")?)?;
    let ext = optional(m, "ext", |e| {
        canonical_entries(object(e)?)
            .into_iter()
            .map(|(k, x)| {
                Ok(Extension {
                    key: ext_key(k)?,
                    value: ExtValue(serde_json::to_vec(x).unwrap()),
                })
            })
            .collect()
    })?;
    let core = RecordCore {
        author: party(required(m, "author")?)?,
        on_behalf_of: optional(m, "on_behalf_of", |l| list(l, party))?,
        capacity: optional(m, "capacity", |c| match c {
            Value::String(s) if s == "own" => Ok(Capacity::Own),
            Value::Array(a) if a.len() == 2 && a[0] == "for" => Ok(Capacity::For(party(&a[1])?)),
            _ => Err(schema(Schema::RequiredField)),
        })?,
        basis: optional(m, "basis", |l| list(l, |d| Ok(RecordId(digest(d)?))))?,
        visibility: visibility(required(m, "visibility")?)?,
        ledger: LedgerId(digest(required(m, "ledger")?)?),
        concerns: list(required(m, "concerns")?, work_id)?,
        relations: optional(m, "relations", |l| list(l, relation))?,
        authority: optional(m, "authority", |a| {
            let a = object(a)?;
            Ok(AuthorityRef {
                proof: AuthorityProofKind::from_wire_name(text(required(a, "proof")?)?)
                    .ok_or(schema(Schema::RequiredField))?,
                digest: digest(required(a, "digest")?)?,
            })
        })?,
        producer: optional(m, "producer", |p| {
            let p = object(p)?;
            Ok(ProducerRef {
                version: text(required(p, "version")?)?.to_owned(),
                config: digest(required(p, "config")?)?,
                model: optional(p, "model", external)?,
                toolset: optional(p, "toolset", digest)?,
                instructions: optional(p, "instructions", digest)?,
                attestation: optional(p, "attestation", digest)?,
            })
        })?,
        correlation: optional(m, "correlation", |l| {
            list(l, |c| {
                let pair = c.as_array().unwrap();
                Ok(Correlation {
                    scheme: type_uri(&pair[0])?,
                    id: text(&pair[1])?.to_owned(),
                })
            })
        })?,
        evidence: optional(m, "evidence", |l| list(l, evidence))?,
        body: optional(m, "body", |l| {
            list(l, |b| {
                let b = object(b)?;
                Ok(BodyCommitment {
                    part: PartName::parse(text(required(b, "part")?)?)
                        .ok_or(schema(Schema::RequiredField))?,
                    commit: digest(required(b, "commit")?)?,
                })
            })
        })?,
        params: optional(m, "params", |p| {
            canonical_entries(object(p)?)
                .into_iter()
                .map(|(k, v)| {
                    Ok(Param {
                        name: PartName::parse(k).ok_or(schema(Schema::Params))?,
                        value: match v {
                            Value::Array(items) => ParamValue::List(
                                items.iter().map(scalar).collect::<Mapped<Vec<_>>>()?,
                            ),
                            other => ParamValue::Scalar(scalar(other)?),
                        },
                    })
                })
                .collect()
        })?,
        versions: versions(required(m, "versions")?)?,
        ext,
        critical: optional(m, "critical", |l| list(l, |k| ext_key(text(k)?)))?,
    };
    let occurred_at = optional(m, "occurred_at", |t| Ok(Time(t.as_u64().unwrap())))?;
    Ok(match kind {
        Kind::Act => Record::Act(Act {
            subtype,
            occurred_at: occurred_at.ok_or(schema(Schema::RequiredField))?,
            core,
        }),
        Kind::Declaration => Record::Declaration(Declaration {
            subtype,
            occurred_at,
            core,
        }),
        Kind::Claim => Record::Claim(Claim {
            subtype: ClaimType::from_uri(subtype),
            occurred_at: occurred_at.ok_or(schema(Schema::RequiredField))?,
            core,
        }),
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

fn actor_entry(v: &Value) -> ActorTypeEntry {
    let pair = v.as_array().unwrap();
    ActorTypeEntry {
        actor_type: ActorType::from_wire_name(pair[0].as_str().unwrap()).unwrap(),
        source: ActorTypeSource::from_wire_name(pair[1].as_str().unwrap()).unwrap(),
    }
}

fn actor_types(case: &Value) -> ActorTypes {
    let actors = &case["context"]["actor_type"];
    ActorTypes {
        author: actor_entry(&actors["author"]),
        on_behalf_of: actors
            .get("on_behalf_of")
            .map(|l| l.as_array().unwrap().iter().map(actor_entry).collect())
            .unwrap_or_default(),
    }
}

fn outcome_of(case: &Value) -> Outcome {
    let actors = &actor_types(case);
    let record = match record(&case["decoded"]) {
        Ok(r) => r,
        Err(reason) => return Outcome::Rejected(reason),
    };
    let context = &case["context"];
    let origin = Origin::from_wire_name(context["origin"].as_str().unwrap()).unwrap();
    let understood: Vec<ExtKey> = context["understood_extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| TypeUri::parse(k.as_str().unwrap()).unwrap())
        .collect();
    validate(
        &record,
        &ValidationContext {
            origin,
            actor_types: actors,
            understood_extensions: &understood,
            limits: SemanticLimits::DEFAULT,
            recorded_at: context.get("recorded_at").and_then(Value::as_u64).map(Time),
        },
    )
}

fn expected(case: &Value) -> Outcome {
    let expect = &case["expect"];
    let reason = || Reason::from_code(expect["reason"].as_str().unwrap()).unwrap();
    match expect["outcome"].as_str().unwrap() {
        "accept" => Outcome::Accepted,
        "reject" => Outcome::Rejected(reason()),
        "quarantine" => Outcome::Quarantined(reason()),
        other => panic!("unknown outcome {other}"),
    }
}

// P-9 P-10 P-11 P-13 P-19 P-77 P-80 P-83 C-16 INV-20
#[test]
fn p_11_accepted_record_vectors() {
    let file: Value = serde_json::from_str(RECORDS).unwrap();
    check_all(file["records"].as_array().unwrap());
}

// P-19 P-69
#[test]
fn p_19_quarantine_record_vectors() {
    let file: Value = serde_json::from_str(QUARANTINE).unwrap();
    check_all(file["cases"].as_array().unwrap());
}

// P-5 P-13 P-14 P-33 P-69 P-70 P-72 P-77 P-78 P-80 P-81 P-83 C-5 C-26 C-27 INV-4 INV-20
#[test]
fn p_72_rejected_record_vectors() {
    let file: Value = serde_json::from_str(REJECTS).unwrap();
    check_all(file["cases"].as_array().unwrap());
}

fn check_all(cases: &[Value]) {
    assert_ne!(cases.len(), 0);
    for case in cases {
        assert_eq!(outcome_of(case), expected(case), "{}", case["id"]);
    }
}
