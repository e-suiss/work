//! Record and evidence signatures through the kernel's `COSE_Sign1` profile over the shared verifier (P-6, P-7, P-8, P-102, P-105, P-106, P-107, EV-3, EV-8): the caller hands the keys Access binds to one Party and the algorithms its policy allows, and the kernel decides; the binding holds no key lookup and no signature logic of its own.

use serde_json::{Map, Value};
use work_kernel::cose::{
    Algorithm, AuthorKeys, KeySet, PresenterKeys, PublicKey, evidence_statement as statement,
    signature_detail,
};
use work_kernel::id::PartyRef;
use work_kernel::reason::Reason;
use work_kernel::verify::{SignatureCheck, SignatureVerifier as _};

use crate::decode::{exact_keys, hex as hex_bytes, object, party};
use crate::project::{accept, accepted, digest_json, fields, hex, reject};
use crate::{error, input_error, parse};

const KEYS_FIELDS: &[&str] = &["party", "allowed", "keys"];
const KEY_FIELDS: &[&str] = &["kid", "alg", "public_key"];

/// The keys Access binds to one Party, with the algorithms the caller's policy allows.
pub(crate) struct Keys {
    pub(crate) party: PartyRef,
    pub(crate) set: KeySet,
}

fn public_key(alg: i64, bytes: Vec<u8>) -> Option<PublicKey> {
    Some(match Algorithm::from_cose(alg)? {
        Algorithm::Ed25519 => PublicKey::Ed25519(bytes.try_into().ok()?),
        Algorithm::Esp256 | Algorithm::Es256 => PublicKey::P256(bytes),
        a @ (Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87) => {
            PublicKey::MlDsa(a, bytes)
        }
    })
}

fn algorithm(v: &Value) -> Option<Algorithm> {
    Algorithm::from_cose(v.as_i64()?)
}

struct Entry {
    kid: [u8; 32],
    key: PublicKey,
}

fn entry(v: &Value) -> Option<Entry> {
    let m = v.as_object()?;
    exact_keys(m, KEY_FIELDS).ok()?;
    let kid = hex_bytes(m.get("kid")?).ok()?.try_into().ok()?;
    let bytes = hex_bytes(m.get("public_key")?).ok()?;
    Some(Entry {
        kid,
        key: public_key(m.get("alg")?.as_i64()?, bytes)?,
    })
}

fn shape(v: &Value) -> Option<(PartyRef, Vec<Algorithm>, &[Value])> {
    let m = object(v).ok()?;
    exact_keys(m, KEYS_FIELDS).ok()?;
    let allowed: Vec<Algorithm> = m
        .get("allowed")?
        .as_array()?
        .iter()
        .map(algorithm)
        .collect::<Option<_>>()?;
    let keys: &[Value] = m.get("keys")?.as_array()?;
    Some((party(m.get("party")?).ok()?, allowed, keys))
}

/// Reads `{"party", "allowed": [<COSE alg>], "keys": [{"kid", "alg", "public_key"}]}`, with `kid` and `public_key` in hex; the error is the JSON answer to return.
pub(crate) fn keys(json: &str) -> Result<Keys, String> {
    let Some(v) = parse(json) else {
        return Err(input_error("invalid_json"));
    };
    let Some((party, allowed, entries)) = shape(&v) else {
        return Err(input_error("invalid_keys"));
    };
    let mut set = KeySet {
        allowed: allowed.into_iter().collect(),
        ..KeySet::default()
    };
    for (index, v) in entries.iter().enumerate() {
        let Some(Entry { kid, key }) = entry(v) else {
            return Err(invalid_key(index, None));
        };
        if let Err(e) = set.insert(kid, key) {
            return Err(invalid_key(index, Some(Reason::Signature(signature_detail(e)))));
        }
    }
    Ok(Keys { party, set })
}

fn invalid_key(index: usize, reason: Option<Reason>) -> String {
    let mut extra = Map::new();
    extra.insert("index".to_owned(), Value::from(index));
    if let Some(reason) = reason {
        extra.insert("reason".to_owned(), Value::from(reason.to_string()));
    }
    error("invalid_keys", extra)
}

fn index(i: u32) -> usize {
    usize::try_from(i).unwrap_or(usize::MAX)
}

/// Checks one public key against the shared strictness rules (P-7, Access CR-9, Access CR-53).
///
/// Returns `{"outcome":"accept"}` or `{"outcome":"reject","reason":"signature:<detail>"}`; an algorithm the profile does not know, or an Ed25519 key that is not 32 bytes, returns `{"error":{"code":"invalid_key"}}`.
#[must_use]
pub fn check_public_key(alg: i64, public_key_bytes: &[u8]) -> String {
    let Some(key) = public_key(alg, public_key_bytes.to_vec()) else {
        return input_error("invalid_key");
    };
    match key.check() {
        Ok(()) => accepted(),
        Err(e) => reject(&Reason::Signature(signature_detail(e)).to_string()),
    }
}

/// Verifies the tagged `COSE_Sign1` bytes of a Work record as received against the keys Access binds to its author (P-6, P-7, P-102, P-105, P-106).
///
/// `author_keys` is `{"party", "allowed": [<COSE alg>], "keys": [{"kid", "alg", "public_key"}]}` with hex byte strings. Returns `{"outcome":"accept","record":[-16,<hex>],"author":<PartyRef>}`, where `record` is the digest of the payload, or `{"outcome":"reject","reason":<code>}`; keys that do not fit return `{"error":{"code":"invalid_json"}}` or `{"error":{"code":"invalid_keys","index"?,"reason"?}}`.
#[must_use]
pub fn verify_record_signature(cose_sign1: &[u8], author_keys: &str) -> String {
    let keys = match keys(author_keys) {
        Ok(k) => k,
        Err(answer) => return answer,
    };
    let port = AuthorKeys {
        author: &keys.party,
        keys: &keys.set,
    };
    match port.check(cose_sign1) {
        SignatureCheck::Valid { record, author } => accept(fields([
            ("record", digest_json(&record.0)),
            ("author", Value::from(author.as_str())),
        ])),
        SignatureCheck::Rejected(reason) => reject(&reason.to_string()),
    }
}

/// The `EvidenceStatement` of evidence reference `index` of protocol 1.0 `SignedRecord` bytes: what its presenter signs (EV-3, EV-8).
///
/// Returns `{"outcome":"accept","statement":<hex>,"presenter":<PartyRef>,"signature":[-16,<hex>]}` or `{"outcome":"reject","reason":<code>}`.
#[must_use]
pub fn evidence_statement(record: &[u8], evidence_index: u32) -> String {
    match statement(record, index(evidence_index)) {
        Ok(s) => accept(fields([
            ("statement", Value::from(hex(&s.bytes))),
            ("presenter", Value::from(s.presenter.as_str())),
            ("signature", digest_json(&s.signature)),
        ])),
        Err(reason) => reject(&reason.to_string()),
    }
}

/// Verifies the presenter's `COSE_Sign1` bytes as received for evidence reference `index` of `record` against the keys Access binds to the presenter (EV-3, EV-8, P-6, P-102, P-105, P-107).
///
/// `presenter_keys` has the shape of [`verify_record_signature`]'s keys. Returns `{"outcome":"accept"}` or `{"outcome":"reject","reason":<code>}`.
#[must_use]
pub fn verify_evidence_signature(
    record: &[u8],
    evidence_index: u32,
    cose_sign1: &[u8],
    presenter_keys: &str,
) -> String {
    let keys = match keys(presenter_keys) {
        Ok(k) => k,
        Err(answer) => return answer,
    };
    let port = PresenterKeys {
        presenter: &keys.party,
        keys: &keys.set,
    };
    match port.check(record, index(evidence_index), cose_sign1) {
        Ok(_) => accepted(),
        Err(reason) => reject(&reason.to_string()),
    }
}
