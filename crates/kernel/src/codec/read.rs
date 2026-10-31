//! Typed reads over a decoded CBOR value, where a value of the wrong shape is the `schema:*` or `limit_exceeded:*` reason of the normative CDDL (P-7, P-11, P-67, P-72).

use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;
use suiss_crypto::digest::{Digest as SharedDigest, SHA256_ALG};

use super::schema;
use crate::id::{Digest, PartyRef};
use crate::reason::{Limit, Reason, Schema};
use crate::record::{PracticePin, ProtocolVersion, VersionVector};
use crate::uri::TypeUri;

pub(crate) type Mapped<T> = Result<T, Reason>;

pub(crate) const MISSING: Reason = schema(Schema::RequiredField);
pub(crate) const UNKNOWN_FIELD: Reason = schema(Schema::UnknownCoreField);
const STRING_BOUND: Reason = Reason::LimitExceeded(Limit::String);
const VERSION_FIELDS: &[&str] = &["protocol", "schema", "practices"];

pub(crate) fn text(v: &Value) -> Mapped<&str> {
    match v {
        Value::Text(t) => Ok(t),
        _ => Err(MISSING),
    }
}

pub(crate) fn uint(v: &Value) -> Mapped<u64> {
    match v {
        Value::Unsigned(u) => Ok(*u),
        _ => Err(MISSING),
    }
}

pub(crate) fn bytes(v: &Value) -> Mapped<&[u8]> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(MISSING),
    }
}

/// A byte string of exactly `N` bytes; another length is `limit_exceeded:string` (P-91).
pub(crate) fn bytes_exact<const N: usize>(v: &Value) -> Mapped<[u8; N]> {
    bytes(v)?.try_into().map_err(|_| STRING_BOUND)
}

pub(crate) fn digest_value(v: &Value) -> Mapped<Digest> {
    let Value::Array(items) = v else {
        return Err(MISSING);
    };
    let [alg, value] = items.as_slice() else {
        return Err(MISSING);
    };
    if alg.as_i64() != Some(SHA256_ALG) {
        return Err(schema(Schema::DigestAlg));
    }
    bytes(value)?;
    SharedDigest::from_value(v)
        .map(|d| Digest::sha256(d.0))
        .ok_or(schema(Schema::DigestLength))
}

/// A Party reference outside its 1 to 255 byte bound is `limit_exceeded:string` (P-67, P-72).
pub(crate) fn party(v: &Value) -> Mapped<PartyRef> {
    PartyRef::new(text(v)?).ok_or(STRING_BOUND)
}

pub(crate) fn list<T>(v: &Value, f: impl Fn(&Value) -> Mapped<T>) -> Mapped<Vec<T>> {
    match v {
        Value::Array(items) => items.iter().map(f).collect(),
        _ => Err(MISSING),
    }
}

pub(crate) fn entries(v: &Value) -> Mapped<&[(Value, Value)]> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(MISSING),
    }
}

pub(crate) fn get<'a>(m: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    m.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

pub(crate) fn required<'a>(m: &'a [(Value, Value)], key: &str) -> Mapped<&'a Value> {
    get(m, key).ok_or(MISSING)
}

pub(crate) fn optional<T>(
    m: &[(Value, Value)],
    key: &str,
    f: impl Fn(&Value) -> Mapped<T>,
) -> Mapped<Option<T>> {
    get(m, key).map(f).transpose()
}

/// A core map that allows only the text keys of its CDDL rule (P-10, P-72).
pub(crate) fn closed<'a>(v: &'a Value, allowed: &[&str]) -> Mapped<&'a [(Value, Value)]> {
    let m = entries(v)?;
    let known = |k: &Value| matches!(k, Value::Text(t) if allowed.contains(&t.as_str()));
    if m.iter().all(|(k, _)| known(k)) {
        Ok(m)
    } else {
        Err(UNKNOWN_FIELD)
    }
}

/// The text keys of an open map with their values, in the canonical order the decoder already enforced; a key that is not text is `invalid`.
pub(crate) fn text_entries(v: &Value, invalid: Reason) -> Mapped<Vec<(&str, &Value)>> {
    entries(v)?
        .iter()
        .map(|(k, x)| match k {
            Value::Text(t) => Ok((t.as_str(), x)),
            _ => Err(invalid),
        })
        .collect()
}

pub(crate) fn pair(v: &Value) -> Mapped<(&Value, &Value)> {
    match v {
        Value::Array(items) => match items.as_slice() {
            [a, b] => Ok((a, b)),
            _ => Err(MISSING),
        },
        _ => Err(MISSING),
    }
}

pub(crate) fn protocol(v: &Value) -> Mapped<ProtocolVersion> {
    let (major, minor) = pair(v)?;
    Ok(ProtocolVersion {
        major: uint(major)?,
        minor: uint(minor)?,
    })
}

fn practices(v: &Value) -> Mapped<Vec<PracticePin>> {
    text_entries(v, schema(Schema::TypeUri))?
        .into_iter()
        .map(|(k, d)| {
            Ok(PracticePin {
                namespace: TypeUri::parse(k).ok_or(schema(Schema::TypeUri))?,
                digest: digest_value(d)?,
            })
        })
        .collect()
}

pub(crate) fn versions(v: &Value) -> Mapped<VersionVector> {
    let m = closed(v, VERSION_FIELDS)?;
    let protocol = protocol(required(m, "protocol")?)?;
    let practices = optional(m, "practices", practices)?;
    Ok(VersionVector {
        protocol,
        schema: digest_value(required(m, "schema")?)?,
        practices,
    })
}
