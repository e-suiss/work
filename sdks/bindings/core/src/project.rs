//! Writes kernel values in the `decoded` JSON projection (P-10, P-87): byte strings as lowercase hex, digests as `[-16, hex]`, integers beyond ±2^53 as decimal strings, and kernel decisions as `{"outcome", "reason"?}` objects with the decision's own fields beside them.

use core::fmt::Write as _;

use serde_json::{Map, Value, json};
use work_kernel::codec::Value as Cbor;
use work_kernel::id::Digest;

const SAFE: u64 = 1 << 53;

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub(crate) fn digest_json(d: &Digest) -> Value {
    json!([-16, hex(d.as_bytes())])
}

/// `{"digest": [-16, hex]}`.
pub(crate) fn digest_answer(d: &Digest) -> String {
    json!({ "digest": digest_json(d) }).to_string()
}

pub(crate) fn uint_json(n: u64) -> Value {
    if n <= SAFE {
        Value::from(n)
    } else {
        Value::from(n.to_string())
    }
}

/// The projection of a decoded CBOR item; `None` for a map key that is not text or a tag, which no record or envelope carries.
pub(crate) fn cbor(v: &Cbor) -> Option<Value> {
    Some(match v {
        Cbor::Unsigned(n) => uint_json(*n),
        Cbor::Negative(n) => {
            let value = (-1_i128).checked_sub(i128::from(*n))?;
            if *n < SAFE {
                Value::from(i64::try_from(value).ok()?)
            } else {
                Value::from(value.to_string())
            }
        }
        Cbor::Bytes(b) => Value::from(hex(b)),
        Cbor::Text(t) => Value::from(t.as_str()),
        Cbor::Array(items) => Value::Array(items.iter().map(cbor).collect::<Option<_>>()?),
        Cbor::Map(entries) => {
            let mut m = Map::new();
            for (k, x) in entries {
                let Cbor::Text(key) = k else {
                    return None;
                };
                m.insert(key.clone(), cbor(x)?);
            }
            Value::Object(m)
        }
        Cbor::Bool(b) => Value::from(*b),
        Cbor::Tag(..) => return None,
    })
}

/// `{"outcome": "accept"}` with `fields` beside it.
pub(crate) fn accept(fields: Map<String, Value>) -> String {
    let mut out = fields;
    out.insert("outcome".to_owned(), Value::from("accept"));
    Value::Object(out).to_string()
}

/// `{"outcome": "accept"}` alone.
pub(crate) fn accepted() -> String {
    accept(Map::new())
}

/// `{"outcome": "reject", "reason": code}`.
pub(crate) fn reject(code: &str) -> String {
    json!({ "outcome": "reject", "reason": code }).to_string()
}

/// `{"outcome": "quarantine", "reason": code}`.
pub(crate) fn quarantine(code: &str) -> String {
    json!({ "outcome": "quarantine", "reason": code }).to_string()
}

/// A JSON object from key and value pairs.
pub(crate) fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}
