//! The `work-export/1` bundle and its offline verification (P-2 items 2 and 3, T-10, MD-12 item 5): a bundle is JSON Lines, one header, the ledger's canonical entries from the genesis on with the externally signed bytes each record was received as, its signed checkpoints with their witness cosignatures and an end line with the counts, every member written in byte order and every byte string in lower-case hex, so equal ledgers give equal bytes and a line in another form is refused; verification needs nothing but the bundle, the trusted keys and the kernel: every entry is verified from its stored bytes along the chain from the genesis, the RFC 9162 root is recomputed over the envelopes, every checkpoint is checked against it and, under a trusted log key, its note signature and witness cosignatures, and the records are folded by the kernel's derivation. No database, network or clock is read, and no derived view is part of a bundle.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::{Map, Value};
use work_kernel::codec::leaf_hash;
use work_kernel::cose::{Algorithm, AuthorKeys, KeySet, PublicKey, verify_record_signature};
use work_kernel::derive::{
    AuthorityIssuer, BusinessCalendar, ChainStatus, DerivationInputs, Entry, ProfileVersion,
    Restriction, TrustInputs, derive,
};
use work_kernel::envelope::{Envelope, decode_envelope};
use work_kernel::id::{PartyRef, Time};
use work_kernel::proof::{self, Verifier};
use work_kernel::record::ProtocolVersion;
use work_kernel::reason::{Reason, Signature};
use work_kernel::verify::{
    ChainPoint, SignatureCheck, SignatureVerifier, StoredEntry, Verified, verify_entry,
};

/// The format name of the header line.
pub const FORMAT: &str = "work-export/1";

/// The stored role of the author's `COSE_Sign1` among the received bytes (T-90).
pub const AUTHOR_SIGNATURE: &str = "author_signature";

/// Externally signed bytes a record was received with (T-90).
#[derive(Clone, PartialEq, Eq)]
pub struct Received {
    /// The stored kind, such as `cose_sign1`.
    pub kind: String,
    /// The stored role for the record, such as `author_signature`.
    pub role: String,
    /// The bytes as received.
    pub bytes: Vec<u8>,
}

impl fmt::Debug for Received {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Received")
            .field("kind", &self.kind)
            .field("role", &self.role)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// One canonical ledger entry as stored (P-5 item 4, T-90).
#[derive(Clone, PartialEq, Eq)]
pub struct BundleEntry {
    /// Log position.
    pub pos: u64,
    /// Ledger time, Unix milliseconds.
    pub recorded_at_ms: u64,
    /// The stored record bytes; the genesis bytes at position 0.
    pub record: Vec<u8>,
    /// The stored envelope bytes.
    pub envelope: Vec<u8>,
    /// The externally signed bytes linked to the record, in stored order.
    pub received: Vec<Received>,
}

impl fmt::Debug for BundleEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleEntry")
            .field("pos", &self.pos)
            .field("recorded_at_ms", &self.recorded_at_ms)
            .field("record", &self.record.len())
            .field("envelope", &self.envelope.len())
            .field("received", &self.received)
            .finish()
    }
}

/// A witness cosignature line of a checkpoint, as received (OP-33).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosignature {
    /// The witness, by its configured identifier.
    pub witness_id: String,
    /// The cosignature timestamp, Unix milliseconds.
    pub cosigned_at_ms: u64,
    /// The note signature line.
    pub line: String,
}

/// A signed checkpoint as stored: the ledger acknowledgement of every entry below `size` (P-20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleCheckpoint {
    /// Tree size.
    pub size: u64,
    /// RFC 9162 root at that size.
    pub root: [u8; 32],
    /// Leaf hash of the entry at `size - 1`.
    pub head_leaf: [u8; 32],
    /// When the log signed it, ledger time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// The C2SP signed note, as signed by the log.
    pub note: String,
    /// The witness cosignatures taken for it.
    pub cosignatures: Vec<Cosignature>,
}

/// A whole bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// The ledger, the digest of its genesis.
    pub ledger: [u8; 32],
    /// Its entries in position order, the genesis first.
    pub entries: Vec<BundleEntry>,
    /// Its checkpoints in size order.
    pub checkpoints: Vec<BundleCheckpoint>,
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            out.extend(DIGITS.get(usize::from(n)).map(|&c| char::from(c)));
        }
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|d| d.checked_add(10)),
        _ => None,
    };
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[hi, lo]| Some(digit(*hi)?.checked_shl(4)? | digit(*lo)?))
        .collect()
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in members {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

fn line(value: &Value) -> String {
    let mut text = value.to_string();
    text.push('\n');
    text
}

/// The header line of a bundle of `ledger`.
#[must_use]
pub fn header_line(ledger: &[u8; 32]) -> String {
    line(&object(vec![
        ("format", Value::from(FORMAT)),
        ("kind", Value::from("header")),
        ("ledger", Value::from(hex(ledger))),
    ]))
}

/// The line of one entry.
#[must_use]
pub fn entry_line(entry: &BundleEntry) -> String {
    let received = entry
        .received
        .iter()
        .map(|r| {
            object(vec![
                ("bytes", Value::from(hex(&r.bytes))),
                ("kind", Value::from(r.kind.as_str())),
                ("role", Value::from(r.role.as_str())),
            ])
        })
        .collect();
    line(&object(vec![
        ("envelope", Value::from(hex(&entry.envelope))),
        ("kind", Value::from("entry")),
        ("pos", Value::from(entry.pos)),
        ("received", Value::Array(received)),
        ("record", Value::from(hex(&entry.record))),
        ("recorded_at_ms", Value::from(entry.recorded_at_ms)),
    ]))
}

/// The line of one checkpoint.
#[must_use]
pub fn checkpoint_line(checkpoint: &BundleCheckpoint) -> String {
    let cosignatures = checkpoint
        .cosignatures
        .iter()
        .map(|c| {
            object(vec![
                ("cosigned_at_ms", Value::from(c.cosigned_at_ms)),
                ("line", Value::from(c.line.as_str())),
                ("witness_id", Value::from(c.witness_id.as_str())),
            ])
        })
        .collect();
    line(&object(vec![
        ("cosignatures", Value::Array(cosignatures)),
        ("head_leaf", Value::from(hex(&checkpoint.head_leaf))),
        ("issued_at_ms", Value::from(checkpoint.issued_at_ms)),
        ("kind", Value::from("checkpoint")),
        ("note", Value::from(checkpoint.note.as_str())),
        ("root", Value::from(hex(&checkpoint.root))),
        ("size", Value::from(checkpoint.size)),
    ]))
}

/// The end line, with the number of entry and checkpoint lines before it.
#[must_use]
pub fn end_line(entries: u64, checkpoints: u64) -> String {
    line(&object(vec![
        ("checkpoints", Value::from(checkpoints)),
        ("entries", Value::from(entries)),
        ("kind", Value::from("end")),
    ]))
}

/// The whole bundle as text.
#[must_use]
pub fn encode(bundle: &Bundle) -> String {
    let mut text = header_line(&bundle.ledger);
    for e in &bundle.entries {
        text.push_str(&entry_line(e));
    }
    for c in &bundle.checkpoints {
        text.push_str(&checkpoint_line(c));
    }
    text.push_str(&end_line(count(bundle.entries.len()), count(bundle.checkpoints.len())));
    text
}

/// A bundle that is not in the `work-export/1` format.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// A line that does not parse, has other members, or is not in its canonical form.
    #[error("line {line}: {what}")]
    Line {
        /// The 1-based line number.
        line: usize,
        /// What is wrong with it.
        what: &'static str,
    },
    /// The bundle ends before its end line, or continues after it.
    #[error("the bundle is truncated or continues after its end line")]
    Truncated,
}

fn members<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let map = value.as_object()?;
    let exact = map.len() == keys.len() && keys.iter().all(|k| map.contains_key(*k));
    exact.then_some(map)
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)?.as_str()
}

fn uint(map: &Map<String, Value>, key: &str) -> Option<u64> {
    map.get(key)?.as_u64()
}

fn bytes(map: &Map<String, Value>, key: &str) -> Option<Vec<u8>> {
    unhex(text(map, key)?)
}

fn digest(map: &Map<String, Value>, key: &str) -> Option<[u8; 32]> {
    bytes(map, key)?.try_into().ok()
}

fn received_of(value: &Value) -> Option<Received> {
    let m = members(value, &["bytes", "kind", "role"])?;
    Some(Received {
        kind: text(m, "kind")?.to_owned(),
        role: text(m, "role")?.to_owned(),
        bytes: bytes(m, "bytes")?,
    })
}

fn entry_of(value: &Value) -> Option<BundleEntry> {
    let m = members(value, &["envelope", "kind", "pos", "received", "record", "recorded_at_ms"])?;
    Some(BundleEntry {
        pos: uint(m, "pos")?,
        recorded_at_ms: uint(m, "recorded_at_ms")?,
        record: bytes(m, "record")?,
        envelope: bytes(m, "envelope")?,
        received: m
            .get("received")?
            .as_array()?
            .iter()
            .map(received_of)
            .collect::<Option<Vec<_>>>()?,
    })
}

fn cosignature_of(value: &Value) -> Option<Cosignature> {
    let m = members(value, &["cosigned_at_ms", "line", "witness_id"])?;
    Some(Cosignature {
        witness_id: text(m, "witness_id")?.to_owned(),
        cosigned_at_ms: uint(m, "cosigned_at_ms")?,
        line: text(m, "line")?.to_owned(),
    })
}

fn checkpoint_of(value: &Value) -> Option<BundleCheckpoint> {
    let m = members(
        value,
        &["cosignatures", "head_leaf", "issued_at_ms", "kind", "note", "root", "size"],
    )?;
    Some(BundleCheckpoint {
        size: uint(m, "size")?,
        root: digest(m, "root")?,
        head_leaf: digest(m, "head_leaf")?,
        issued_at_ms: uint(m, "issued_at_ms")?,
        note: text(m, "note")?.to_owned(),
        cosignatures: m
            .get("cosignatures")?
            .as_array()?
            .iter()
            .map(cosignature_of)
            .collect::<Option<Vec<_>>>()?,
    })
}

enum Part {
    Entries,
    Checkpoints,
    Ended,
}

/// Parses a bundle; every line must be in the form [`encode`] writes it.
///
/// # Errors
/// [`FormatError`].
pub fn parse(bundle: &str) -> Result<Bundle, FormatError> {
    let mut lines = bundle.split_inclusive('\n').enumerate();
    let bad = |at: usize, what: &'static str| FormatError::Line {
        line: at.saturating_add(1),
        what,
    };
    let (at, first) = lines.next().ok_or(FormatError::Truncated)?;
    let header: Value = serde_json::from_str(first).map_err(|_| bad(at, "not JSON"))?;
    let ledger = members(&header, &["format", "kind", "ledger"])
        .filter(|m| text(m, "format") == Some(FORMAT) && text(m, "kind") == Some("header"))
        .and_then(|m| digest(m, "ledger"))
        .ok_or_else(|| bad(at, "not a work-export/1 header"))?;
    if header_line(&ledger) != first {
        return Err(bad(at, "not in canonical form"));
    }
    let mut out = Bundle {
        ledger,
        entries: Vec::new(),
        checkpoints: Vec::new(),
    };
    let mut part = Part::Entries;
    for (at, raw) in lines {
        if matches!(part, Part::Ended) {
            return Err(FormatError::Truncated);
        }
        let value: Value = serde_json::from_str(raw).map_err(|_| bad(at, "not JSON"))?;
        match value.get("kind").and_then(Value::as_str) {
            Some("entry") if matches!(part, Part::Entries) => {
                let e = entry_of(&value).ok_or_else(|| bad(at, "not an entry"))?;
                if entry_line(&e) != raw {
                    return Err(bad(at, "not in canonical form"));
                }
                out.entries.push(e);
            }
            Some("checkpoint") => {
                let c = checkpoint_of(&value).ok_or_else(|| bad(at, "not a checkpoint"))?;
                if checkpoint_line(&c) != raw {
                    return Err(bad(at, "not in canonical form"));
                }
                out.checkpoints.push(c);
                part = Part::Checkpoints;
            }
            Some("end") => {
                let m = members(&value, &["checkpoints", "entries", "kind"])
                    .ok_or_else(|| bad(at, "not an end line"))?;
                let counted = |n: usize| u64::try_from(n).ok();
                if uint(m, "entries") != counted(out.entries.len())
                    || uint(m, "checkpoints") != counted(out.checkpoints.len())
                {
                    return Err(FormatError::Truncated);
                }
                part = Part::Ended;
            }
            _ => return Err(bad(at, "unexpected line")),
        }
    }
    if matches!(part, Part::Ended) {
        Ok(out)
    } else {
        Err(FormatError::Truncated)
    }
}

/// The keys a verifier trusts, given apart from the bundle: the author keys Access binds to each
/// Party, and the C2SP verifier keys of the log and of the witnesses (P-2 item 2, P-20).
#[derive(Clone, Debug, Default)]
pub struct Trust {
    authors: BTreeMap<String, KeySet>,
    log: Option<Verifier>,
    witnesses: Vec<Verifier>,
}

/// A trust file that does not parse.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// Not the expected JSON shape.
    #[error("trust file: {0}")]
    Shape(&'static str),
    /// A key the shared crate refuses.
    #[error("trust file: author key {0} is refused")]
    Key(usize),
    /// A verifier key that does not parse.
    #[error("trust file: verifier key {0}")]
    Verifier(&'static str),
}

fn algorithm(cose: i64) -> Option<Algorithm> {
    [Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256]
        .into_iter()
        .find(|a| a.cose() == cose)
}

impl Trust {
    /// Parses `{"authors": [{"alg", "kid_hex", "party", "public_key_hex"}], "log"?: <vkey>,
    /// "witnesses"?: [<vkey>]}`: each author key with its COSE algorithm (Ed25519 `-19`, ESP256
    /// `-9` or ES256 `-7`), its 32-byte `kid` and its public key, and the note verifier keys.
    ///
    /// # Errors
    /// [`TrustError`].
    pub fn parse(text_in: &str) -> Result<Self, TrustError> {
        let value: Value =
            serde_json::from_str(text_in).map_err(|_| TrustError::Shape("not JSON"))?;
        let map = value.as_object().ok_or(TrustError::Shape("not an object"))?;
        if map
            .keys()
            .any(|k| !["authors", "log", "witnesses"].contains(&k.as_str()))
        {
            return Err(TrustError::Shape("unknown member"));
        }
        let mut trust = Self::default();
        let authors = map
            .get("authors")
            .and_then(Value::as_array)
            .ok_or(TrustError::Shape("authors"))?;
        for (i, author) in authors.iter().enumerate() {
            let m = members(author, &["alg", "kid_hex", "party", "public_key_hex"])
                .ok_or(TrustError::Shape("author key"))?;
            let party = text(m, "party")
                .filter(|p| PartyRef::new(p).is_some())
                .ok_or(TrustError::Shape("party"))?;
            let alg = m
                .get("alg")
                .and_then(Value::as_i64)
                .and_then(algorithm)
                .ok_or(TrustError::Shape("alg"))?;
            let kid: [u8; 32] = bytes(m, "kid_hex")
                .and_then(|k| k.try_into().ok())
                .ok_or(TrustError::Shape("kid_hex"))?;
            let raw = bytes(m, "public_key_hex").ok_or(TrustError::Shape("public_key_hex"))?;
            let public = if alg == Algorithm::Ed25519 {
                PublicKey::Ed25519(raw.try_into().map_err(|_| TrustError::Key(i))?)
            } else {
                PublicKey::P256(raw)
            };
            let set = trust.authors.entry(party.to_owned()).or_default();
            set.allowed.insert(alg);
            set.insert(kid, public).map_err(|_| TrustError::Key(i))?;
        }
        if let Some(log) = map.get("log") {
            let vkey = log.as_str().ok_or(TrustError::Shape("log"))?;
            trust.log = Some(Verifier::parse(vkey).map_err(|e| TrustError::Verifier(e.code()))?);
        }
        if let Some(witnesses) = map.get("witnesses") {
            for w in witnesses.as_array().ok_or(TrustError::Shape("witnesses"))? {
                let vkey = w.as_str().ok_or(TrustError::Shape("witnesses"))?;
                trust
                    .witnesses
                    .push(Verifier::parse(vkey).map_err(|e| TrustError::Verifier(e.code()))?);
            }
        }
        Ok(trust)
    }
}

struct Authors<'a>(&'a BTreeMap<String, KeySet>);

impl SignatureVerifier for Authors<'_> {
    fn check(&self, cose_sign1: &[u8]) -> SignatureCheck {
        for (party, keys) in self.0 {
            if verify_record_signature(cose_sign1, keys).is_err() {
                continue;
            }
            let Some(author) = PartyRef::new(party) else {
                continue;
            };
            return AuthorKeys {
                author: &author,
                keys,
            }
            .check(cose_sign1);
        }
        SignatureCheck::Rejected(Reason::Signature(Signature::KidUnknown))
    }
}

/// What an offline verification established; no field states truth or authorisation (SEC-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The ledger.
    pub ledger: [u8; 32],
    /// Entries verified along the chain, the genesis included.
    pub entries: u64,
    /// Record entries among them.
    pub records: u64,
    /// Version activation entries among them (P-110).
    pub activations: u64,
    /// Records whose author signature verified under a trusted key.
    pub signed: u64,
    /// Unsigned human records bound to an Access authentication context (P-21 item 3).
    pub auth_context: u64,
    /// The RFC 9162 root over every envelope of the bundle (P-101).
    pub root: [u8; 32],
    /// Checkpoints whose root and head leaf match the bundle.
    pub checkpoints: u64,
    /// Checkpoints whose note signature verified under the trusted log key.
    pub checkpoints_signed: u64,
    /// Witness cosignatures that verified under a trusted witness key.
    pub cosignatures: u64,
    /// The last position the kernel's fold reached; a record of a protocol version without a
    /// rule set stops it (P-106).
    pub folded_through: u64,
    /// Supersede chains of the fold.
    pub chains: u64,
    /// Conflicted chains among them (P-28).
    pub conflicted: u64,
}

/// Why a bundle does not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The bundle holds no entry.
    #[error("the bundle holds no entry")]
    Empty,
    /// The first entry is not the genesis of the bundle's ledger (P-100).
    #[error("the first entry is not the genesis of the ledger")]
    Genesis,
    /// An entry is not at the next position.
    #[error("entry {0} is not at the next position")]
    Order(u64),
    /// An entry does not verify; `reason` is the kernel's protocol reason.
    #[error("entry {pos}: {reason}")]
    Entry {
        /// Its position.
        pos: u64,
        /// The kernel's reason.
        reason: String,
    },
    /// An entry's ledger time is not its envelope's.
    #[error("entry {0}: recorded_at is not the envelope's")]
    Time(u64),
    /// A checkpoint does not match the bundle or its note does not verify.
    #[error("checkpoint {size}: {what}")]
    Checkpoint {
        /// Its size.
        size: u64,
        /// What does not match, or the note error code.
        what: &'static str,
    },
    /// The kernel's fold refused the sequence.
    #[error("fold: {0}")]
    Fold(&'static str),
}

fn genesis_of(bundle: &Bundle) -> Result<(ChainPoint, ProtocolVersion), VerifyError> {
    let first = bundle.entries.first().ok_or(VerifyError::Empty)?;
    let Ok(Envelope::Genesis(g)) = decode_envelope(&first.record) else {
        return Err(VerifyError::Genesis);
    };
    let point = ChainPoint::genesis(&first.record).map_err(|_| VerifyError::Genesis)?;
    if first.pos != 0
        || first.envelope != first.record
        || !first.received.is_empty()
        || point.ledger.0.as_bytes() != &bundle.ledger
        || g.recorded_at.0 != first.recorded_at_ms
    {
        return Err(VerifyError::Genesis);
    }
    Ok((point, g.versions.protocol))
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Verifies `bundle` offline under `trust` (P-2 item 2, P-20, P-11, T-10).
///
/// # Errors
/// [`VerifyError`].
pub fn verify(bundle: &Bundle, trust: &Trust) -> Result<Report, VerifyError> {
    let (mut at, protocol) = genesis_of(bundle)?;
    let authors = Authors(&trust.authors);
    let mut activations = vec![(0, protocol)];
    let mut verified = Vec::with_capacity(bundle.entries.len());
    let (mut signed, mut bound) = (0_u64, 0_u64);
    for (i, e) in bundle.entries.iter().enumerate().skip(1) {
        let pos = u64::try_from(i).map_err(|_| VerifyError::Order(e.pos))?;
        if e.pos != pos {
            return Err(VerifyError::Order(e.pos));
        }
        let cose = e
            .received
            .iter()
            .find(|r| r.role == AUTHOR_SIGNATURE)
            .map(|r| r.bytes.as_slice());
        let stored = StoredEntry {
            envelope: &e.envelope,
            record: &e.record,
            cose_sign1: cose,
        };
        let v = verify_entry(&authors, &at, &stored).map_err(|reason| VerifyError::Entry {
            pos,
            reason: reason.to_string(),
        })?;
        let recorded = match &v {
            Verified::Record(r) => {
                if cose.is_some() {
                    signed = signed.saturating_add(1);
                } else {
                    bound = bound.saturating_add(1);
                }
                r.envelope().recorded_at
            }
            Verified::Activation(a) => {
                activations.push((pos, a.envelope().activation.protocol));
                a.envelope().recorded_at
            }
        };
        if recorded.0 != e.recorded_at_ms {
            return Err(VerifyError::Time(pos));
        }
        at = v.next();
        verified.push(v);
    }
    let envelopes: Vec<&[u8]> = bundle
        .entries
        .iter()
        .map(|e| e.envelope.as_slice())
        .collect();
    let (checkpoints_signed, cosignatures) = checkpoints(bundle, trust, &envelopes)?;
    let mut entries = Vec::new();
    for v in &verified {
        if let Verified::Record(r) = v {
            match Entry::verified(r, Restriction::NoObjection, AuthorityIssuer::Local) {
                Some(entry) => entries.push(entry),
                None => break,
            }
        }
    }
    let last = bundle.entries.last().map_or(0, |e| e.recorded_at_ms);
    let derivation = derive(
        &entries,
        &DerivationInputs {
            activations: &activations,
            profile: ProfileVersion(1),
            practices: &[],
            trust: TrustInputs {
                trusted_publishers: &[],
            },
            ledger_time: Time(last),
            calendar: BusinessCalendar::Continuous,
        },
    )
    .map_err(|e| VerifyError::Fold(e.code()))?;
    let records = verified.iter().filter(|v| v.as_record().is_some()).count();
    Ok(Report {
        ledger: bundle.ledger,
        entries: count(bundle.entries.len()),
        records: count(records),
        activations: count(activations.len().saturating_sub(1)),
        signed,
        auth_context: bound,
        root: *proof::root(&envelopes).as_bytes(),
        checkpoints: count(bundle.checkpoints.len()),
        checkpoints_signed,
        cosignatures,
        folded_through: entries.last().map_or(0, Entry::position),
        chains: count(derivation.chains.len()),
        conflicted: count(
            derivation
                .chains
                .iter()
                .filter(|c| c.status == ChainStatus::Conflicted)
                .count(),
        ),
    })
}

fn checkpoints(
    bundle: &Bundle,
    trust: &Trust,
    envelopes: &[&[u8]],
) -> Result<(u64, u64), VerifyError> {
    let (mut signed, mut cosigned) = (0_u64, 0_u64);
    let mut sizes = BTreeSet::new();
    for c in &bundle.checkpoints {
        let bad = |what: &'static str| VerifyError::Checkpoint { size: c.size, what };
        if !sizes.insert(c.size) {
            return Err(bad("repeated"));
        }
        let prefix = usize::try_from(c.size)
            .ok()
            .and_then(|n| envelopes.get(..n))
            .filter(|p| !p.is_empty())
            .ok_or_else(|| bad("size outside the bundle"))?;
        if proof::root(prefix).as_bytes() != &c.root {
            return Err(bad("root"));
        }
        let head = prefix.last().map(|e| *leaf_hash(e).as_bytes());
        if head != Some(c.head_leaf) {
            return Err(bad("head_leaf"));
        }
        let Some(log) = &trust.log else {
            continue;
        };
        let mut note = c.note.clone();
        for s in &c.cosignatures {
            note.push_str(&s.line);
            note.push('\n');
        }
        let origin = c.note.lines().next().unwrap_or_default();
        let accepted = proof::verify_checkpoint(&note, origin, log, &trust.witnesses)
            .map_err(|e| bad(e.code()))?;
        if accepted.size() != c.size || accepted.root().as_bytes() != &c.root {
            return Err(bad("note"));
        }
        signed = signed.saturating_add(1);
        cosigned = cosigned.saturating_add(count(accepted.cosignatures.len()));
    }
    Ok((signed, cosigned))
}

#[cfg(test)]
mod tests;
