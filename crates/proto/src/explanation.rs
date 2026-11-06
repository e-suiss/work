//! The JSON form of the decision explanation shared with Access (`urn:suiss:access:schema:explanation:1`; Access E43, PR-11, PR-17): the members of [`Explanation`] in the ADP encodings, an id and a party as unpadded base64url of their 16 bytes and a digest as unpadded base64url of its 32 SHA-256 bytes, every integer within `0..=2^53-1` but a conjunct value; a byte-valued conjunct value has no JSON form. The requirement terms a rule set names for its `@require` references come in the same form, and a rule set's verdict is explained the way Access explains a restriction result.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Number, Value as Json};
use work_kernel::codec::Value;
use work_kernel::explanation::{Explanation, ExplanationError, check_term};

const JSON_MAX: u64 = 9_007_199_254_740_991;
const JSON_MIN: i64 = -9_007_199_254_740_991;
const SHA256_ALG: u64 = 15;

type Mapped<T> = Result<T, ExplanationError>;

fn refused<T>(what: &'static str) -> Mapped<T> {
    Err(ExplanationError(what))
}

fn uint_from(n: &Number, what: &'static str) -> Mapped<Value> {
    match n.as_u64() {
        Some(u) if u <= JSON_MAX => Ok(Value::Unsigned(u)),
        _ => refused(what),
    }
}

fn generic_from(v: &Json, what: &'static str) -> Mapped<Value> {
    Ok(match v {
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => uint_from(n, what)?,
        Json::String(s) => Value::Text(s.clone()),
        Json::Array(items) => Value::Array(
            items
                .iter()
                .map(|i| generic_from(i, what))
                .collect::<Mapped<_>>()?,
        ),
        Json::Object(m) => Value::Map(
            m.iter()
                .map(|(k, v)| Ok((Value::Text(k.clone()), generic_from(v, what)?)))
                .collect::<Mapped<_>>()?,
        ),
        Json::Null => return refused(what),
    })
}

fn bytes_from<const N: usize>(v: &Json, what: &'static str) -> Mapped<Vec<u8>> {
    let Json::String(s) = v else {
        return refused(what);
    };
    match URL_SAFE_NO_PAD.decode(s) {
        Ok(b) if b.len() == N => Ok(b),
        _ => refused(what),
    }
}

fn object<'a>(v: &'a Json, what: &'static str) -> Mapped<&'a Map<String, Json>> {
    match v {
        Json::Object(m) => Ok(m),
        _ => refused(what),
    }
}

fn conjunct_from(v: &Json) -> Mapped<Value> {
    let m = object(v, "conjunct")?;
    let mut out = Vec::with_capacity(m.len());
    for (k, v) in m {
        let value = if k == "value" {
            match v {
                Json::String(s) => Value::Text(s.clone()),
                Json::Bool(b) => Value::Bool(*b),
                Json::Number(n) => match (n.as_u64(), n.as_i64()) {
                    (Some(u), _) if u <= JSON_MAX => Value::Unsigned(u),
                    (None, Some(i)) if i >= JSON_MIN => {
                        Value::Negative(i.unsigned_abs().saturating_sub(1))
                    }
                    _ => return refused("conjunct.value"),
                },
                _ => return refused("conjunct.value"),
            }
        } else {
            generic_from(v, "conjunct")?
        };
        out.push((Value::Text(k.clone()), value));
    }
    Ok(Value::Map(out))
}

fn selector_from(v: &Json) -> Mapped<Value> {
    let Json::Object(m) = v else {
        return generic_from(v, "source");
    };
    let mut out = Vec::with_capacity(m.len());
    for (k, v) in m {
        let value = match k.as_str() {
            "party" => Value::Bytes(bytes_from::<16>(v, "source.party")?),
            "pred" => match v {
                Json::Array(items) => {
                    Value::Array(items.iter().map(conjunct_from).collect::<Mapped<_>>()?)
                }
                _ => return refused("source"),
            },
            "foreign" => {
                let f = object(v, "source.foreign")?;
                let mut inner = Vec::with_capacity(f.len());
                for (k, v) in f {
                    let value = if k == "domain" {
                        Value::Array(Vec::from([
                            Value::Negative(SHA256_ALG),
                            Value::Bytes(bytes_from::<32>(v, "digest")?),
                        ]))
                    } else {
                        generic_from(v, "source.foreign")?
                    };
                    inner.push((Value::Text(k.clone()), value));
                }
                Value::Map(inner)
            }
            _ => generic_from(v, "source")?,
        };
        out.push((Value::Text(k.clone()), value));
    }
    Ok(Value::Map(out))
}

/// The CBOR value of one requirement term in its JSON form, checked against the CDDL.
///
/// # Errors
/// [`ExplanationError`] naming the member that does not fit.
pub fn term_from_json(v: &Json) -> Mapped<Value> {
    let m = object(v, "term")?;
    let mut out = Vec::with_capacity(m.len());
    for (k, v) in m {
        let value = if k == "source" {
            selector_from(v)?
        } else {
            generic_from(v, "term")?
        };
        out.push((Value::Text(k.clone()), value));
    }
    let term = Value::Map(out);
    check_term(&term)?;
    Ok(term)
}

fn unmet_from(v: &Json) -> Mapped<Value> {
    let m = object(v, "unmet")?;
    let mut out = Vec::with_capacity(m.len());
    for (k, v) in m {
        let value = if k == "term" {
            term_from_json(v)?
        } else {
            generic_from(v, "unmet")?
        };
        out.push((Value::Text(k.clone()), value));
    }
    Ok(Value::Map(out))
}

/// The explanation in its JSON form.
///
/// # Errors
/// [`ExplanationError`] naming the member that does not fit the schema or the CDDL.
pub fn from_json(v: &Json) -> Mapped<Explanation> {
    let m = object(v, "explanation")?;
    let mut out = Vec::with_capacity(m.len());
    for (k, v) in m {
        let value = match (k.as_str(), v) {
            ("unmet", Json::Array(items)) => {
                Value::Array(items.iter().map(unmet_from).collect::<Mapped<_>>()?)
            }
            ("relied_on", Json::Array(items)) => Value::Array(
                items
                    .iter()
                    .map(|i| bytes_from::<16>(i, "relied_on").map(Value::Bytes))
                    .collect::<Mapped<_>>()?,
            ),
            ("unmet" | "relied_on", _) => return refused("explanation"),
            _ => generic_from(v, "explanation")?,
        };
        out.push((Value::Text(k.clone()), value));
    }
    Explanation::from_value(Value::Map(out))
}

fn uint_json(n: u64, what: &'static str) -> Mapped<Json> {
    if n > JSON_MAX {
        return refused(what);
    }
    Ok(Json::Number(Number::from(n)))
}

fn b64(bytes: &[u8]) -> Json {
    Json::String(URL_SAFE_NO_PAD.encode(bytes))
}

fn key(k: &Value, what: &'static str) -> Mapped<String> {
    match k {
        Value::Text(t) => Ok(t.clone()),
        _ => refused(what),
    }
}

fn generic_json(v: &Value, what: &'static str) -> Mapped<Json> {
    Ok(match v {
        Value::Unsigned(n) => uint_json(*n, what)?,
        Value::Text(t) => Json::String(t.clone()),
        Value::Bool(b) => Json::Bool(*b),
        Value::Array(items) => Json::Array(
            items
                .iter()
                .map(|i| generic_json(i, what))
                .collect::<Mapped<_>>()?,
        ),
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(k, v)| Ok((key(k, what)?, generic_json(v, what)?)))
                .collect::<Mapped<_>>()?,
        ),
        _ => return refused(what),
    })
}

fn map_json(
    v: &Value,
    what: &'static str,
    member: impl Fn(&str, &Value) -> Mapped<Json>,
) -> Mapped<Json> {
    let Value::Map(entries) = v else {
        return generic_json(v, what);
    };
    entries
        .iter()
        .map(|(k, v)| {
            let k = key(k, what)?;
            let json = member(&k, v)?;
            Ok((k, json))
        })
        .collect::<Mapped<Map<String, Json>>>()
        .map(Json::Object)
}

fn conjunct_json(v: &Value) -> Mapped<Json> {
    map_json(v, "conjunct", |k, v| match (k, v) {
        ("value", Value::Negative(n)) if *n < JSON_MAX => {
            let magnitude = i64::try_from(*n).map_err(|_| ExplanationError("conjunct.value"))?;
            Ok(Json::Number(Number::from(
                magnitude
                    .checked_neg()
                    .and_then(|m| m.checked_sub(1))
                    .ok_or(ExplanationError("conjunct.value"))?,
            )))
        }
        ("value", Value::Bytes(_)) => refused("conjunct.value"),
        _ => generic_json(v, "conjunct"),
    })
}

fn selector_json(v: &Value) -> Mapped<Json> {
    map_json(v, "source", |k, v| match (k, v) {
        ("party", Value::Bytes(b)) => Ok(b64(b)),
        ("pred", Value::Array(items)) => items
            .iter()
            .map(conjunct_json)
            .collect::<Mapped<_>>()
            .map(Json::Array),
        ("foreign", _) => map_json(v, "source.foreign", |k, v| match (k, v) {
            ("domain", Value::Array(d)) => match d.as_slice() {
                [_, Value::Bytes(b)] => Ok(b64(b)),
                _ => refused("digest"),
            },
            _ => generic_json(v, "source.foreign"),
        }),
        _ => generic_json(v, "source"),
    })
}

fn term_json(v: &Value) -> Mapped<Json> {
    map_json(v, "term", |k, v| {
        if k == "source" {
            selector_json(v)
        } else {
            generic_json(v, "term")
        }
    })
}

/// The JSON form of an explanation.
///
/// # Errors
/// [`ExplanationError`] for an integer above `2^53-1` or a byte-valued conjunct value, which
/// have no JSON form.
pub fn to_json(e: &Explanation) -> Mapped<Json> {
    map_json(e.value(), "explanation", |k, v| match (k, v) {
        ("unmet", Value::Array(items)) => items
            .iter()
            .map(|u| {
                map_json(u, "unmet", |k, v| {
                    if k == "term" {
                        term_json(v)
                    } else {
                        generic_json(v, "unmet")
                    }
                })
            })
            .collect::<Mapped<_>>()
            .map(Json::Array),
        ("relied_on", Value::Array(items)) => items
            .iter()
            .map(|i| match i {
                Value::Bytes(b) => Ok(b64(b)),
                _ => refused("relied_on"),
            })
            .collect::<Mapped<_>>()
            .map(Json::Array),
        _ => generic_json(v, "explanation"),
    })
}

/// A rule set's 16-byte reference, as its explanation names it, from unpadded base64url.
///
/// # Errors
/// [`ExplanationError`] `ref` for anything else.
pub fn reference_from_json(v: &Json) -> Mapped<[u8; 16]> {
    bytes_from::<16>(v, "ref")?
        .try_into()
        .map_err(|_| ExplanationError("ref"))
}

/// The requirement terms of a rule set, by its `@require` reference (Access `requirements` of a
/// restriction policy).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Requirements(BTreeMap<String, Vec<Value>>);

impl Requirements {
    /// The JSON object `{"<reference>": [<requirement term>…]}`; every reference names at least
    /// one term.
    ///
    /// # Errors
    /// [`ExplanationError`] `requirements` for another shape, or the member of a term that does
    /// not fit.
    pub fn from_json(v: &Json) -> Mapped<Self> {
        let m = object(v, "requirements")?;
        let mut out = BTreeMap::new();
        for (reference, terms) in m {
            let Json::Array(terms) = terms else {
                return refused("requirements");
            };
            if terms.is_empty() {
                return refused("requirements");
            }
            let terms = terms.iter().map(term_from_json).collect::<Mapped<_>>()?;
            out.insert(reference.to_string(), terms);
        }
        Ok(Self(out))
    }

    /// Whether `reference` names terms.
    #[must_use]
    pub fn names(&self, reference: &str) -> bool {
        self.0.contains_key(reference)
    }
}

/// What one restriction rule set said about a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleOutcome<'a> {
    /// No objection: no effect on the explanation.
    NoObjection,
    /// `REQUIRE` with these `@require` references.
    Require(&'a [String]),
    /// `DENY`, whatever its cause.
    Deny,
}

/// The explanation of one rule set's result (Access L0-EVAL-18): none for `NO_OBJECTION`, the
/// rule set's `restricted` blocker for `DENY` and the terms its references name for `REQUIRE`.
///
/// # Errors
/// [`ExplanationError`] `requirements` for a reference the rule set does not map to terms.
pub fn explain(
    outcome: RuleOutcome<'_>,
    reference: Option<&[u8; 16]>,
    requirements: &Requirements,
) -> Mapped<Option<Explanation>> {
    match outcome {
        RuleOutcome::NoObjection => Ok(None),
        RuleOutcome::Deny => Ok(Some(Explanation::restricted(reference))),
        RuleOutcome::Require(references) => {
            let mut terms = Vec::new();
            for r in references {
                terms.extend(
                    requirements
                        .0
                        .get(r)
                        .ok_or(ExplanationError("requirements"))?,
                );
            }
            Explanation::required(terms).map(Some)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const VECTORS: &str = include_str!("../../../conformance/vectors/access/explanation.json");

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    // PR-11 PR-17
    #[test]
    fn pr_11_pr_17_the_access_explanation_examples_round_trip() {
        let file: Json = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(file["contract"], "explanation");
        let cases = file["cases"].as_array().unwrap();
        let mut valid = 0;
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let parsed = from_json(&case["json"]);
            if case["valid"] == true {
                let e = parsed.unwrap_or_else(|r| panic!("{id}: {r}"));
                let cbor = hex(case["cbor"].as_str().unwrap());
                assert_eq!(e.encode().unwrap(), cbor, "{id}");
                let decoded = Explanation::decode(&cbor).unwrap();
                assert_eq!(decoded, e, "{id}");
                assert_eq!(to_json(&decoded).unwrap(), case["json"], "{id}");
                valid += 1;
            } else {
                assert!(parsed.is_err(), "{id}");
            }
        }
        assert_eq!(valid, 6);
        assert_eq!(cases.len(), 12);
    }

    // PR-11 PR-17
    #[test]
    fn pr_11_pr_17_a_rule_set_result_is_explained_as_access_explains_a_restriction() {
        let requirements = Requirements::from_json(&json!({
            "rs-a": [{"proof_kind": "authentication", "class": "step_up", "assurance": {"aal": 2}}],
            "rs-b": [{"proof_kind": "claim", "class": "kyc", "source": {"party": "RERERERERERERERERERERA"}}],
        }))
        .unwrap();
        assert!(requirements.names("rs-a") && !requirements.names("rs-c"));
        assert_eq!(
            reference_from_json(&json!("MzMzMzMzMzMzMzMzMzMzMw")),
            Ok([0x33; 16])
        );
        for bad in [json!("MzMz"), json!("MzMzMzMzMzMzMzMzMzMzMw=="), json!(1)] {
            assert_eq!(reference_from_json(&bad), Err(ExplanationError("ref")));
        }
        assert_eq!(
            explain(RuleOutcome::NoObjection, None, &requirements),
            Ok(None)
        );
        let denied = explain(RuleOutcome::Deny, Some(&[0x33; 16]), &requirements)
            .unwrap()
            .unwrap();
        assert_eq!(
            to_json(&denied).unwrap(),
            json!({"outcome": "deny", "blockers": [{
                "class": "restricted",
                "subcode": "restricted/policy:MzMzMzMzMzMzMzMzMzMzMw",
                "position": "domain-policy",
                "resolver": "restriction-owner",
                "remediation": "not-satisfiable-by-actor",
            }]})
        );
        let refs = [String::from("rs-b"), String::from("rs-a")];
        let required = explain(RuleOutcome::Require(&refs), None, &requirements)
            .unwrap()
            .unwrap();
        let json = to_json(&required).unwrap();
        assert_eq!(json["outcome"], "require_action");
        assert_eq!(
            json["unmet"][0]["term"]["source"]["party"],
            "RERERERERERERERERERERA"
        );
        assert_eq!(json["unmet"][1]["term"]["class"], "step_up");
        assert_eq!(from_json(&json).unwrap(), required);
        let unknown = [String::from("rs-c")];
        assert_eq!(
            explain(RuleOutcome::Require(&unknown), None, &requirements),
            Err(ExplanationError("requirements"))
        );
        for bad in [
            json!([]),
            json!({"rs": []}),
            json!({"rs": [{"proof_kind": "claim"}]}),
            json!({"rs": [{"proof_kind": "claim", "class": "kyc", "count": 1}]}),
        ] {
            assert!(Requirements::from_json(&bad).is_err(), "{bad}");
        }
    }
}
