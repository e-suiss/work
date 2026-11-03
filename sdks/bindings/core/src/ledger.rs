//! Stored ledger entries, Merkle proofs and checkpoints through the kernel verifier (T-4, T-7, T-10, T-88, P-11, P-20, P-100, P-101, P-108, OP-33, OP-46): an entry is verified from its stored bytes with the record ID recomputed, a proof or checkpoint answers with the shared crate's codes, and none of it states truth or authorisation (SEC-5).

use serde_json::{Value, json};
use work_kernel::cose::AuthorKeys;
use work_kernel::envelope::EnvelopeIngest;
use work_kernel::id::{Digest, LedgerId};
use work_kernel::proof::{self, NoteError, ProofError, SignedCheckpoint, Verifier};
use work_kernel::verify::{AuthorBinding, ChainPoint, StoredEntry, VerifiedEntry};

use crate::decode::{Mapped, digest, exact_keys, hex, list, object, required, text, uint};
use crate::project::{accept, accepted, digest_answer, digest_json, fields, reject, uint_json};
use crate::signature::keys;
use crate::{input_error, parse};

const POINT_FIELDS: &[&str] = &["ledger", "prev"];
const INCLUSION_FIELDS: &[&str] = &["position", "size", "leaf", "path", "root"];
const CONSISTENCY_FIELDS: &[&str] = &["first", "second", "first_root", "second_root", "path"];
const CHECKPOINT_FIELDS: &[&str] = &["note", "origin", "log", "witnesses"];
const NOTE_KEY_FIELDS: &[&str] = &["name", "public_key"];
const INCLUDES_FIELDS: &[&str] = &["position", "leaf", "path"];

fn point_json(p: &ChainPoint) -> Value {
    json!({ "ledger": digest_json(&p.ledger.0), "prev": digest_json(&p.prev) })
}

pub(crate) fn point(v: &Value) -> Mapped<ChainPoint> {
    let m = object(v)?;
    exact_keys(m, POINT_FIELDS)?;
    Ok(ChainPoint {
        ledger: LedgerId(digest(required(m, "ledger")?)?),
        prev: digest(required(m, "prev")?)?,
    })
}

/// The chain point after genesis bytes: the `LedgerID` and the genesis leaf hash the first envelope's `prev` names (P-100).
///
/// Returns `{"outcome":"accept","ledger":[-16,<hex>],"prev":[-16,<hex>]}` or `{"outcome":"reject","reason":<code>}`.
#[must_use]
pub fn genesis_chain_point(genesis: &[u8]) -> String {
    match ChainPoint::genesis(genesis) {
        Ok(p) => accept(fields([
            ("ledger", digest_json(&p.ledger.0)),
            ("prev", digest_json(&p.prev)),
        ])),
        Err(reason) => reject(&reason.to_string()),
    }
}

fn ingest(i: EnvelopeIngest) -> Value {
    match i {
        EnvelopeIngest::Admitted => json!("admitted"),
        EnvelopeIngest::Quarantined(r) => json!(["quarantined", r.to_string()]),
        EnvelopeIngest::Rejected(r) => json!(["rejected", r.to_string()]),
    }
}

fn verified(v: &VerifiedEntry) -> String {
    let verification = v.verification();
    let envelope = v.envelope();
    let binding = match verification.binding {
        AuthorBinding::SignatureValid => "signature_valid",
        AuthorBinding::AuthContext => "auth_context",
    };
    accept(fields([
        ("record", digest_json(&verification.record.0)),
        ("author", Value::from(verification.author.as_str())),
        ("binding", Value::from(binding)),
        ("ledger", digest_json(&envelope.ledger.0)),
        ("position", uint_json(envelope.position)),
        ("recorded_at", uint_json(envelope.recorded_at.0)),
        ("ingest", ingest(envelope.ingest)),
        ("leaf", digest_json(&v.leaf())),
        ("next", point_json(&v.next())),
    ]))
}

/// Verifies one stored ledger entry after the chain point `at` from its bytes alone: the envelope names the ledger and the previous leaf, its `record` is the digest of the stored record bytes, a signed record's `proof_commit` is the digest of the `COSE_Sign1` bytes and its signature verifies under the keys Access binds to its author, and an unsigned record is a human record with an authentication context (T-10, P-11, P-12, P-21, P-75, P-79, P-100, P-108, EV-35).
///
/// `at` is `{"ledger":[-16,<hex>],"prev":[-16,<hex>]}`, from [`genesis_chain_point`] or the previous entry's `next`; `author_keys` has the shape of [`crate::verify_record_signature`]'s keys. Returns `{"outcome":"accept","record","author","binding":"signature_valid"|"auth_context","ledger","position","recorded_at","ingest","leaf","next"}` or `{"outcome":"reject","reason":<code>}`; input that does not fit returns `{"error":{"code":"invalid_json"}}`, `{"error":{"code":"invalid_chain_point"}}` or a keys error.
#[must_use]
pub fn verify_entry(
    at: &str,
    envelope: &[u8],
    record: &[u8],
    cose_sign1: Option<&[u8]>,
    author_keys: &str,
) -> String {
    let Some(at) = parse(at) else {
        return input_error("invalid_json");
    };
    let Ok(at) = point(&at) else {
        return input_error("invalid_chain_point");
    };
    let keys = match keys(author_keys) {
        Ok(k) => k,
        Err(answer) => return answer,
    };
    let port = AuthorKeys {
        author: &keys.party,
        keys: &keys.set,
    };
    let entry = StoredEntry {
        envelope,
        record,
        cose_sign1,
    };
    match work_kernel::verify::verify_entry(&port, &at, &entry) {
        Ok(v) => verified(&v),
        Err(reason) => reject(&reason.to_string()),
    }
}

fn digest_text(json: &str) -> Option<Digest> {
    digest(&parse(json)?).ok()
}

/// The RFC 9162 interior node hash of two digests given as `[-16,<hex>]` (P-101).
///
/// Returns `{"digest":[-16,<hex>]}`, or `{"error":{"code":"invalid_digest"}}`.
#[must_use]
pub fn merkle_node_hash(left: &str, right: &str) -> String {
    let (Some(left), Some(right)) = (digest_text(left), digest_text(right)) else {
        return input_error("invalid_digest");
    };
    digest_answer(&proof::node_hash(&left, &right))
}

/// The RFC 9162 tree hash over envelope bytes in ledger order, the genesis first, given as a JSON array of hex strings; the empty tree is `SHA-256("")` (P-100, P-101).
///
/// Returns `{"digest":[-16,<hex>]}`, or `{"error":{"code":"invalid_json"}}` or `{"error":{"code":"invalid_envelopes"}}`.
#[must_use]
pub fn merkle_root(envelopes: &str) -> String {
    let Some(envelopes) = parse(envelopes) else {
        return input_error("invalid_json");
    };
    let Ok(leaves) = list(&envelopes, hex) else {
        return input_error("invalid_envelopes");
    };
    let slices: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    digest_answer(&proof::root(&slices))
}

fn proof_answer(result: Result<(), ProofError>) -> String {
    match result {
        Ok(()) => accepted(),
        Err(e) => reject(e.code()),
    }
}

fn digests(v: &Value) -> Mapped<Vec<Digest>> {
    list(v, digest)
}

fn with_proof<T>(json: &str, read: impl FnOnce(&Value) -> Mapped<T>) -> Result<T, String> {
    let Some(v) = parse(json) else {
        return Err(input_error("invalid_json"));
    };
    read(&v).map_err(|_| input_error("invalid_proof"))
}

struct Inclusion {
    position: u64,
    size: u64,
    leaf: Digest,
    path: Vec<Digest>,
    root: Digest,
}

fn inclusion_proof(v: &Value) -> Mapped<Inclusion> {
    let m = object(v)?;
    exact_keys(m, INCLUSION_FIELDS)?;
    Ok(Inclusion {
        position: uint(required(m, "position")?)?,
        size: uint(required(m, "size")?)?,
        leaf: digest(required(m, "leaf")?)?,
        path: digests(required(m, "path")?)?,
        root: digest(required(m, "root")?)?,
    })
}

struct Consistency {
    first: u64,
    second: u64,
    first_root: Digest,
    second_root: Digest,
    path: Vec<Digest>,
}

fn consistency_proof(v: &Value) -> Mapped<Consistency> {
    let m = object(v)?;
    exact_keys(m, CONSISTENCY_FIELDS)?;
    Ok(Consistency {
        first: uint(required(m, "first")?)?,
        second: uint(required(m, "second")?)?,
        first_root: digest(required(m, "first_root")?)?,
        second_root: digest(required(m, "second_root")?)?,
        path: digests(required(m, "path")?)?,
    })
}

struct Included {
    position: u64,
    leaf: Digest,
    path: Vec<Digest>,
}

fn included(v: &Value) -> Mapped<Included> {
    let m = object(v)?;
    exact_keys(m, INCLUDES_FIELDS)?;
    Ok(Included {
        position: uint(required(m, "position")?)?,
        leaf: digest(required(m, "leaf")?)?,
        path: digests(required(m, "path")?)?,
    })
}

/// Verifies an RFC 9162 inclusion proof `{"position","size","leaf","path","root"}` with digests as `[-16,<hex>]` (T-4, T-88, P-11, P-101).
///
/// Returns `{"outcome":"accept"}` or `{"outcome":"reject","reason":"proof-range"|"proof-length"|"proof-mismatch"}`, or `{"error":{"code":"invalid_json"}}` or `{"error":{"code":"invalid_proof"}}`.
#[must_use]
pub fn verify_inclusion(inclusion: &str) -> String {
    match with_proof(inclusion, inclusion_proof) {
        Ok(p) => {
            let result = proof::verify_inclusion(p.position, p.size, &p.leaf, &p.path, &p.root);
            proof_answer(result)
        }
        Err(answer) => answer,
    }
}

/// Verifies an RFC 9162 consistency proof `{"first","second","first_root","second_root","path"}` with digests as `[-16,<hex>]` (T-4, T-88, P-11, P-101).
///
/// Returns `{"outcome":"accept"}` or `{"outcome":"reject","reason":"proof-range"|"proof-length"|"proof-mismatch"}`, or `{"error":{"code":"invalid_json"}}` or `{"error":{"code":"invalid_proof"}}`.
#[must_use]
pub fn verify_consistency(consistency: &str) -> String {
    match with_proof(consistency, consistency_proof) {
        Ok(p) => {
            let result = proof::verify_consistency(
                p.first,
                p.second,
                &p.first_root,
                &p.second_root,
                &p.path,
            );
            proof_answer(result)
        }
        Err(answer) => answer,
    }
}

fn note_key(v: &Value, cosigner: bool) -> Option<Verifier> {
    let m = v.as_object()?;
    exact_keys(m, NOTE_KEY_FIELDS).ok()?;
    let name = m.get("name")?.as_str()?;
    let key: [u8; 32] = hex(m.get("public_key")?).ok()?.try_into().ok()?;
    if cosigner {
        Verifier::cosigner(name, key).ok()
    } else {
        Verifier::ed25519(name, key).ok()
    }
}

struct CheckpointInput {
    note: String,
    origin: String,
    log: Verifier,
    witnesses: Vec<Verifier>,
}

fn checkpoint_input(v: &Value) -> Option<CheckpointInput> {
    let m = object(v).ok()?;
    exact_keys(m, CHECKPOINT_FIELDS).ok()?;
    let witnesses = m
        .get("witnesses")?
        .as_array()?
        .iter()
        .map(|w| note_key(w, true))
        .collect::<Option<Vec<_>>>()?;
    Some(CheckpointInput {
        note: text(m.get("note")?).ok()?.to_owned(),
        origin: text(m.get("origin")?).ok()?.to_owned(),
        log: note_key(m.get("log")?, false)?,
        witnesses,
    })
}

fn signed(json: &str) -> Result<Result<SignedCheckpoint, NoteError>, String> {
    let Some(v) = parse(json) else {
        return Err(input_error("invalid_json"));
    };
    let Some(c) = checkpoint_input(&v) else {
        return Err(input_error("invalid_checkpoint"));
    };
    let result = proof::verify_checkpoint(&c.note, &c.origin, &c.log, &c.witnesses);
    Ok(result)
}

/// Verifies a C2SP signed note as a checkpoint of `origin` (T-4, T-88, P-20, OP-33, OP-46): the log's own signature must verify, every signature line from a known witness must verify, lines from unknown keys are ignored, and the body carries the three profile lines.
///
/// `checkpoint` is `{"note","origin","log":{"name","public_key"},"witnesses":[{"name","public_key"}]}` with Ed25519 public keys in hex. Returns `{"outcome":"accept","size","root":[-16,<hex>],"profile":[<line>],"cosignatures":[{"name","timestamp"}]}` or `{"outcome":"reject","reason":<shared crate code>}`, or `{"error":{"code":"invalid_json"}}` or `{"error":{"code":"invalid_checkpoint"}}`.
#[must_use]
pub fn verify_checkpoint(checkpoint: &str) -> String {
    match signed(checkpoint) {
        Ok(Ok(s)) => {
            let cosignatures: Vec<Value> = s
                .cosignatures
                .iter()
                .map(|a| json!({ "name": a.name, "timestamp": a.timestamp }))
                .collect();
            accept(fields([
                ("size", uint_json(s.size())),
                ("root", digest_json(&s.root())),
                ("profile", Value::from(s.profile.to_extensions())),
                ("cosignatures", Value::Array(cosignatures)),
            ]))
        }
        Ok(Err(e)) => reject(e.code()),
        Err(answer) => answer,
    }
}

/// Verifies that the envelope with leaf hash `leaf` at `position` is in the tree of a verified checkpoint (T-4, T-88, P-11, P-108); `inclusion` is `{"position","leaf","path"}`.
///
/// Returns `{"outcome":"accept"}`, `{"outcome":"reject","reason":<code>}` with the checkpoint's or the proof's shared crate code, or an input error of [`verify_checkpoint`] or [`verify_inclusion`].
#[must_use]
pub fn checkpoint_includes(checkpoint: &str, inclusion: &str) -> String {
    let p = match with_proof(inclusion, included) {
        Ok(p) => p,
        Err(answer) => return answer,
    };
    match signed(checkpoint) {
        Ok(Ok(s)) => proof_answer(s.includes(p.position, &p.leaf, &p.path)),
        Ok(Err(e)) => reject(e.code()),
        Err(answer) => answer,
    }
}

/// Verifies that the tree of the verified checkpoint `older` is a prefix of the tree of the verified checkpoint `newer` of the same origin (T-4, T-88, P-11); `path` is a JSON array of `[-16,<hex>]` digests.
///
/// Returns `{"outcome":"accept"}`, `{"outcome":"reject","reason":<code>}` with a checkpoint's or the proof's shared crate code (`proof-mismatch` for another origin), or an input error of [`verify_checkpoint`] or [`verify_consistency`].
#[must_use]
pub fn checkpoint_extends_to(older: &str, newer: &str, path: &str) -> String {
    let path = match with_proof(path, digests) {
        Ok(p) => p,
        Err(answer) => return answer,
    };
    match (signed(older), signed(newer)) {
        (Err(answer), _) | (_, Err(answer)) => answer,
        (Ok(Err(e)), _) | (_, Ok(Err(e))) => reject(e.code()),
        (Ok(Ok(a)), Ok(Ok(b))) => proof_answer(a.extends_to(&b, &path)),
    }
}
