//! The records the executor writes (RC-42, P-68, P-21): every contract element travels as a record of a fixed kind authored by the executor's Party, its `work/control/1` body in the salted `definition` body part, its `authority` the digest of the decision receipt Work's PEP handed back, its basis the record the element answers; the record is checked with the kernel's decoder before the executor's service Instance key signs it in the token.

use serde_json::{Value as Json, json};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::sha256;
use suiss_crypto::signer::{Signer, sign_sign1};
use work_access_client::domain::b64url;
use work_access_client::domain::metadata::thumbprint;
use work_kernel::catalog::{ClaimSubtype, DeclarationSubtype};
use work_kernel::codec::{Decoded, body_commitment, decode_record};
use work_kernel::control::body::CDDL;
use work_kernel::control::executor::CONTRACT_PART;
use work_kernel::cose::CONTENT_TYPE;
use work_kernel::record::PartName;
use work_kernel::uri::CORE_ROOT;

/// The media type of a contract body part.
pub(crate) const CBOR: &str = "application/cbor";

/// The media type of a refusal's `note`.
const TEXT: &str = "text/plain";

/// The protocol version the records are written under.
const PROTOCOL: (u64, u64) = (1, 0);

/// What kind of record an element is.
#[derive(Clone, Debug)]
pub(crate) enum Shape {
    /// A Claim, carrying one executor extension key when it is a contract element.
    Claim(ClaimSubtype, Option<&'static str>),
    /// An Act carrying the report extension key.
    Act(&'static str),
    /// A core Declaration with its `params`.
    Declaration(DeclarationSubtype, Vec<(&'static str, Value)>),
}

/// One body part: its name, media type, content and salt (P-68).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Part {
    /// The part name.
    pub(crate) name: &'static str,
    /// The media type.
    pub(crate) media_type: &'static str,
    /// The content.
    pub(crate) content: Vec<u8>,
    /// The salt.
    pub(crate) salt: [u8; 32],
}

impl std::fmt::Debug for Part {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Part")
            .field("name", &self.name)
            .field("content", &self.content.len())
            .finish_non_exhaustive()
    }
}

impl Part {
    /// The `definition` part carrying the contract body `body`.
    pub(crate) fn contract(body: Vec<u8>, salt: [u8; 32]) -> Self {
        Self {
            name: CONTRACT_PART,
            media_type: CBOR,
            content: body,
            salt,
        }
    }

    /// The `note` part carrying a refusal's reason (RC-36).
    pub(crate) fn note(reason: &str, salt: [u8; 32]) -> Self {
        Self {
            name: "note",
            media_type: TEXT,
            content: reason.as_bytes().to_vec(),
            salt,
        }
    }

    /// The opening a write carries (P-68).
    pub(crate) fn opening(&self) -> Json {
        json!({
            "part": self.name,
            "media_type": self.media_type,
            "content": b64url(&self.content),
            "salt": b64url(&self.salt),
        })
    }
}

/// One record to write.
#[derive(Clone, Debug)]
pub(crate) struct Draft {
    /// Its kind.
    pub(crate) shape: Shape,
    /// The executor's Party.
    pub(crate) author: String,
    /// The ledger.
    pub(crate) ledger: [u8; 32],
    /// When it happened, Unix milliseconds.
    pub(crate) occurred_at: u64,
    /// The SHA-256 of the decision receipt it is written under (P-13).
    pub(crate) receipt: [u8; 32],
    /// The records it rests on.
    pub(crate) basis: Vec<[u8; 32]>,
    /// Its body parts.
    pub(crate) parts: Vec<Part>,
}

/// Why a record is not written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RecordError {
    /// The record does not encode or does not decode as a record.
    #[error("record: {0}")]
    Record(&'static str),
    /// The token did not sign.
    #[error("signature: {0}")]
    Sign(String),
}

fn digest(bytes: &[u8; 32]) -> Value {
    Value::Array(vec![Value::int(-16), Value::Bytes(bytes.to_vec())])
}

fn map(entries: Vec<(&str, Value)>) -> Result<Value, RecordError> {
    let mut keyed = entries
        .into_iter()
        .map(|(k, v)| {
            let key = Value::text(k);
            dcbor::encode(&key, Limits::CEILING)
                .map(|bytes| (bytes, (key, v)))
                .map_err(|_| RecordError::Record("encoding"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Value::Map(keyed.into_iter().map(|(_, kv)| kv).collect()))
}

fn type_uri(shape: &Shape) -> (&'static str, String) {
    match shape {
        Shape::Claim(subtype, _) => ("claim", format!("{CORE_ROOT}claim/{}", subtype.wire_name())),
        Shape::Act(_) => ("act", format!("{CORE_ROOT}act/action")),
        Shape::Declaration(subtype, _) => (
            "declaration",
            format!("{CORE_ROOT}declaration/{}", subtype.wire_name()),
        ),
    }
}

impl Draft {
    /// The deterministic CBOR of the record, checked with the kernel's decoder.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let (kind, subtype) = type_uri(&self.shape);
        let body = self
            .parts
            .iter()
            .map(|p| {
                let name = PartName::parse(p.name).ok_or(RecordError::Record("part"))?;
                let commit = body_commitment(&p.salt, &name, p.media_type, &p.content)
                    .map_err(|_| RecordError::Record("part"))?;
                map(vec![
                    ("part", Value::text(p.name)),
                    ("commit", digest(commit.as_bytes())),
                ])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut entries = vec![
            ("kind", Value::text(kind)),
            ("type", Value::Text(subtype)),
            ("occurred_at", Value::Unsigned(self.occurred_at)),
            ("author", Value::text(&self.author)),
            ("capacity", Value::text("own")),
            ("visibility", map(vec![("see", Value::text("work"))])?),
            ("ledger", digest(&self.ledger)),
            ("concerns", Value::Array(Vec::new())),
            (
                "authority",
                map(vec![
                    ("proof", Value::text("decision_receipt")),
                    ("digest", digest(&self.receipt)),
                ])?,
            ),
            (
                "versions",
                map(vec![
                    (
                        "protocol",
                        Value::Array(vec![
                            Value::Unsigned(PROTOCOL.0),
                            Value::Unsigned(PROTOCOL.1),
                        ]),
                    ),
                    ("schema", digest(&sha256(CDDL.as_bytes()))),
                ])?,
            ),
        ];
        if !self.basis.is_empty() {
            entries.push((
                "basis",
                Value::Array(self.basis.iter().map(digest).collect()),
            ));
        }
        if !body.is_empty() {
            entries.push(("body", Value::Array(body)));
        }
        match &self.shape {
            Shape::Claim(_, Some(ext)) | Shape::Act(ext) => {
                entries.push((
                    "ext",
                    map(vec![(
                        *ext,
                        Value::text(work_kernel::control::body::CONTRACT),
                    )])?,
                ));
            }
            Shape::Declaration(_, params) if !params.is_empty() => {
                entries.push(("params", map(params.clone())?));
            }
            Shape::Claim(_, None) | Shape::Declaration(..) => {}
        }
        let bytes = dcbor::encode(&map(entries)?, Limits::CEILING)
            .map_err(|_| RecordError::Record("encoding"))?;
        match decode_record(&bytes) {
            Ok(Decoded::Record(_)) => Ok(bytes),
            _ => Err(RecordError::Record("decoding")),
        }
    }
}

/// The tagged `COSE_Sign1` of `record` by `key`, `kid` its RFC 7638 thumbprint (P-21).
pub(crate) fn sign(key: &impl Signer, record: &[u8]) -> Result<Vec<u8>, RecordError> {
    let kid = thumbprint(&key.public_key());
    sign_sign1(key, kid, CONTENT_TYPE, record).map_err(|e| RecordError::Sign(e.to_string()))
}

#[cfg(test)]
mod tests {
    use work_kernel::control::executor::{CAPABILITY_EXT_KEY, REPORT_EXT_KEY};
    use work_kernel::record::Record;

    use super::*;

    fn draft(shape: Shape, parts: Vec<Part>) -> Draft {
        Draft {
            shape,
            author: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            ledger: [7; 32],
            occurred_at: 1_793_000_000_000,
            receipt: [5; 32],
            basis: vec![[2; 32]],
            parts,
        }
    }

    fn decoded(bytes: &[u8]) -> Record {
        let Ok(Decoded::Record(r)) = decode_record(bytes) else {
            panic!("not a record");
        };
        r
    }

    // RC-42 P-68 T-105
    #[test]
    fn rc_42_a_contract_element_is_a_record_of_its_kind_with_the_body_in_definition() {
        let body = crate::protocol::tests::capability().encode().unwrap();
        let claim = draft(
            Shape::Claim(ClaimSubtype::Observation, Some(CAPABILITY_EXT_KEY)),
            vec![Part::contract(body, [1; 32])],
        );
        let record = decoded(&claim.encode().unwrap());
        assert!(matches!(record, Record::Claim(_)));
        let core = record.core();
        assert_eq!(core.author.as_str(), "AAAAAAAAAAAAAAAAAAAAAA");
        assert!(core.authority.is_some());
        assert_eq!(core.body.as_ref().unwrap()[0].part.as_str(), "definition");
        assert_eq!(
            core.ext.as_ref().unwrap()[0].key.as_str(),
            CAPABILITY_EXT_KEY
        );
        let act = draft(
            Shape::Act(REPORT_EXT_KEY),
            vec![Part::contract(vec![0xa0], [1; 32])],
        );
        assert!(matches!(decoded(&act.encode().unwrap()), Record::Act(_)));
        assert_eq!(claim.parts[0].opening()["media_type"], CBOR);
    }

    // RC-36 RC-34 P-84
    #[test]
    fn rc_36_a_stop_response_cites_its_request_and_a_refusal_carries_its_note() {
        let response = draft(
            Shape::Declaration(
                DeclarationSubtype::StopResponse,
                vec![("response", Value::text("refuse"))],
            ),
            vec![
                Part::contract(vec![0xa0], [1; 32]),
                Part::note("local policy", [2; 32]),
            ],
        );
        let record = decoded(&response.encode().unwrap());
        assert!(matches!(record, Record::Declaration(_)));
        assert_eq!(record.basis().len(), 1);
        assert_eq!(
            work_kernel::control::stop::answer_of(&record),
            Some(work_kernel::catalog::StopAnswer::Refuse)
        );
        let note = draft(
            Shape::Declaration(
                DeclarationSubtype::HandoffNote,
                vec![
                    ("handover_reason", Value::text("control_transfer")),
                    ("stateful", Value::Bool(true)),
                ],
            ),
            vec![Part::contract(vec![0xa0], [1; 32])],
        );
        assert!(matches!(
            decoded(&note.encode().unwrap()),
            Record::Declaration(_)
        ));
    }
}
