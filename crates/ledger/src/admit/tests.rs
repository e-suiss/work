#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value as Json;
use suiss_crypto::dcbor::{Limits, decode};
use suiss_ledger::sequencer::{Entry as _, Slot};
use work_kernel::cose::{Algorithm, AuthorKeys, KeySet, PublicKey, verify_record_signature};
use work_kernel::envelope::{Envelope, decode_envelope};
use work_kernel::id::PartyRef;
use work_kernel::validate::{ActorType, ActorTypeSource};
use work_kernel::verify::SignatureCheck;
use work_testkit::realm::{self, ADMITTED_AT, Artifact, ISSUER, Realm};

use super::*;
use crate::actors::Declared;
use crate::envelope::Bound;

const COSE: &str = include_str!("../../../../conformance/vectors/records/cose-sign1.json");
const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
const QUARANTINE: &str =
    include_str!("../../../../conformance/vectors/records/records-quarantine.json");
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn json(text: &str) -> Json {
    serde_json::from_str(text).unwrap()
}

/// The signature port over the golden keys: the keys bound to whichever Party signed.
struct Directory(BTreeMap<String, KeySet>);

impl Directory {
    fn golden() -> Self {
        let mut sets: BTreeMap<String, KeySet> = BTreeMap::new();
        for key in json(COSE)["keys"].as_array().unwrap() {
            let kid: [u8; 32] = unhex(key["kid_hex"].as_str().unwrap()).try_into().unwrap();
            let bytes = unhex(key["public_key_hex"].as_str().unwrap());
            let public = match key["alg"].as_i64().unwrap() {
                -19 => PublicKey::Ed25519(bytes.try_into().unwrap()),
                _ => PublicKey::P256(bytes),
            };
            let set = sets
                .entry(key["party"].as_str().unwrap().to_owned())
                .or_insert_with(|| KeySet {
                    allowed: BTreeSet::from([
                        Algorithm::Ed25519,
                        Algorithm::Esp256,
                        Algorithm::Es256,
                    ]),
                    ..KeySet::default()
                });
            set.insert(kid, public).unwrap();
        }
        Self(sets)
    }
}

impl SignatureVerifier for Directory {
    fn check(&self, cose_sign1: &[u8]) -> SignatureCheck {
        let Some((author, keys)) = self
            .0
            .iter()
            .find(|(_, keys)| verify_record_signature(cose_sign1, keys).is_ok())
        else {
            return SignatureCheck::Rejected(Reason::Schema(Schema::Container));
        };
        let author = PartyRef::new(author).unwrap();
        AuthorKeys {
            author: &author,
            keys,
        }
        .check(cose_sign1)
    }
}

/// One golden ledger entry: its record, envelope, `COSE_Sign1` and verifier context.
struct Golden {
    id: String,
    record: Vec<u8>,
    envelope: Vec<u8>,
    cose: Option<Vec<u8>>,
    declared: DeclaredActors,
    bindings: ActorBindings,
    origin: Origin,
    understood: Vec<ExtKey>,
}

/// The author, `on_behalf_of` and evidence presenter Parties `record` names, read from its
/// CBOR map, so a record of an unknown protocol names them too.
fn parties(record: &[u8]) -> (PartyRef, Vec<PartyRef>, Vec<PartyRef>) {
    let v = decode(record, Limits::CEILING).unwrap();
    let party = |p: &Value| match p {
        Value::Text(t) => PartyRef::new(t).unwrap(),
        _ => panic!("a Party"),
    };
    let list = |key: &str| match v.get(key) {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    (
        party(v.get("author").unwrap()),
        list("on_behalf_of").iter().map(party).collect(),
        list("evidence")
            .iter()
            .map(|e| party(e.get("presenter").unwrap()))
            .collect(),
    )
}

/// The declaration and Access bindings that give `record` the vector's actor types `ctx`: a
/// Party with `access_binding` is bound to its type, every Party declares its type.
fn actor_inputs(record: &[u8], ctx: &Json) -> (DeclaredActors, ActorBindings) {
    let (author, rings, presenters) = parties(record);
    let mut bindings = ActorBindings::new();
    let mut declare = |party: PartyRef, v: &Json| {
        let actor_type = ActorType::from_wire_name(v[0].as_str().unwrap()).unwrap();
        if ActorTypeSource::from_wire_name(v[1].as_str().unwrap())
            == Some(ActorTypeSource::AccessBinding)
        {
            bindings.bind(party.clone(), actor_type).unwrap();
        }
        Declared { party, actor_type }
    };
    let entries = |key: &str| ctx[key].as_array().cloned().unwrap_or_default();
    let author = declare(author, &ctx["author"]);
    let on_behalf_of = rings
        .into_iter()
        .zip(entries("on_behalf_of"))
        .map(|(p, v)| declare(p, &v))
        .collect();
    let evidence = presenters
        .into_iter()
        .zip(entries("evidence"))
        .map(|(p, v)| declare(p, &v))
        .collect();
    (
        DeclaredActors {
            author,
            on_behalf_of,
            evidence,
        },
        bindings,
    )
}

/// The entries at positions 1 to 14 of the golden ledger, in order.
fn golden() -> Vec<Golden> {
    let mut cose = BTreeMap::new();
    for case in json(COSE)["cases"].as_array().unwrap() {
        if let Some(name) = case.get("envelope").and_then(Json::as_str) {
            cose.insert(name.to_owned(), unhex(case["cose_hex"].as_str().unwrap()));
        }
    }
    let records = json(RECORDS);
    let quarantine = json(QUARANTINE);
    let mut out = Vec::new();
    let signed = records["records"].as_array().unwrap();
    let envelopes = records["envelopes"].as_array().unwrap();
    let held = quarantine["cases"].as_array().unwrap();
    let pairs = signed
        .iter()
        .zip(envelopes)
        .map(|(r, e)| (r, e, format!("records.json {}", e["id"].as_str().unwrap())))
        .chain(held.iter().take(3).map(|c| {
            let name = format!(
                "records-quarantine.json {} envelope",
                c["id"].as_str().unwrap()
            );
            (c, &c["envelope"], name)
        }));
    for (r, e, name) in pairs {
        let ctx = &r["context"];
        let record = unhex(r["hex"].as_str().unwrap());
        let (declared, bindings) = actor_inputs(&record, &ctx["actor_type"]);
        out.push(Golden {
            id: r["id"].as_str().unwrap().to_owned(),
            record,
            envelope: unhex(e["hex"].as_str().unwrap()),
            cose: cose.get(&name).cloned(),
            declared,
            bindings,
            origin: Origin::from_wire_name(ctx["origin"].as_str().unwrap()).unwrap(),
            understood: ctx["understood_extensions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| TypeUri::parse(k.as_str().unwrap()).unwrap())
                .collect(),
        });
    }
    out
}

thread_local! {
    static REALM: Realm = Realm::open("admit").unwrap();
}

/// The golden artifact of `record`, signed by the test realm.
fn artifact_of(record: &[u8]) -> Artifact {
    REALM.with(|r| r.for_record(sha256(record)).unwrap())
}

fn pending(g: &Golden, ledger: &LedgerId) -> Result<PendingRecord, AdmitError> {
    let artifact = artifact_of(&g.record);
    pending_with(g, ledger, &artifact)
}

fn pending_with(
    g: &Golden,
    ledger: &LedgerId,
    artifact: &Artifact,
) -> Result<PendingRecord, AdmitError> {
    let paired = realm::paired();
    REALM.with(|r| {
        let arrival = g.cose.as_deref().map_or(
            Arrival::Unsigned {
                record: &g.record,
                auth_context: AuthContext {
                    bytes: &artifact.cose,
                    digest: &artifact.digest,
                    realm_keys: r.keys(),
                    issuer: ISSUER,
                    paired: &paired,
                    now_ms: ADMITTED_AT,
                },
            },
            Arrival::Signed,
        );
        submit(g, ledger, arrival)
    })
}

fn rejected(e: &AdmitError) -> Reason {
    match e {
        AdmitError::Rejected(reason) => *reason,
        AdmitError::AuthContext(invalid) => panic!("auth_context_invalid: {invalid}"),
    }
}

fn submit(
    g: &Golden,
    ledger: &LedgerId,
    arrival: Arrival<'_>,
) -> Result<PendingRecord, AdmitError> {
    admit(
        &Directory::golden(),
        ledger,
        Submission {
            arrival,
            declared: &g.declared,
            bindings: &g.bindings,
            origin: g.origin,
            understood_extensions: &g.understood,
            limits: SemanticLimits::default(),
            event_type: "work.updated",
            traceparent: TRACE,
            idempotency: None,
            inbound: None,
        },
    )
}

fn slot_of(envelope: &[u8]) -> (LedgerId, Slot) {
    let v = decode(envelope, Limits::CEILING).unwrap();
    let digest = |key: &str| Digest::from_value(v.get(key).unwrap()).unwrap().0;
    let uint = |key: &str| match v.get(key) {
        Some(Value::Unsigned(n)) => *n,
        _ => panic!("{key}"),
    };
    (
        LedgerId::from_bytes(digest("ledger")),
        Slot {
            pos: uint("pos"),
            prev: digest("prev"),
            recorded_at: uint("recorded_at"),
        },
    )
}

// P-100 P-11 P-12 P-21 P-75 P-19 P-87 T-89 T-90 T-91 OP-5 EV-35
#[test]
fn p_100_the_admission_path_seals_the_golden_ledger_byte_for_byte() {
    let entries = golden();
    assert_eq!(entries.len(), 18);
    for g in &entries {
        let (ledger, slot) = slot_of(&g.envelope);
        let record = pending(g, &ledger).unwrap_or_else(|r| panic!("{}: {r}", g.id));
        let (_, sealed) = Bound {
            ledger: &ledger,
            record: &record,
        }
        .seal(&slot)
        .unwrap();
        assert_eq!(sealed.envelope, g.envelope, "{}", g.id);
        assert_eq!(record.record_bytes, g.record, "{}", g.id);
    }
}

// T-90 P-5 P-75
#[test]
fn t_90_a_signed_record_keeps_its_cose_sign1_and_an_unsigned_one_its_context() {
    for g in &golden() {
        let (ledger, _) = slot_of(&g.envelope);
        let record = pending(g, &ledger).unwrap();
        let [kept] = record.received() else {
            panic!("{}", g.id);
        };
        if let Some(cose) = &g.cose {
            assert_eq!(&kept.bytes, cose);
            assert_eq!(kept.role, ReceivedRole::AuthorSignature);
            assert_eq!(kept.kind, ReceivedKind::CoseSign1);
            assert_eq!(record.proof_commit, Some(sha256(cose)));
        } else {
            assert_eq!(kept.bytes, artifact_of(&g.record).cose);
            assert_eq!(kept.role, ReceivedRole::AuthContext);
            assert_eq!(kept.kind, ReceivedKind::AccessAuthContext);
            assert_eq!(record.proof_commit, None);
        }
        if let Some(s) = record.skeleton() {
            assert_eq!(s.header.proof_commit, record.proof_commit, "{}", g.id);
        }
    }
}

// T-89 T-81 T-91 C-34 OP-13
#[test]
fn t_89_the_items_and_pointers_come_from_the_concerned_works() {
    for g in &golden() {
        let (ledger, _) = slot_of(&g.envelope);
        let record = pending(g, &ledger).unwrap();
        let concerns = record
            .skeleton()
            .map(|s| s.concerns.clone())
            .unwrap_or_default();
        let items: Vec<ItemRef> = record.items().iter().map(|t| t.item).collect();
        let works: Vec<ItemRef> = concerns.iter().map(|w| ItemRef::Work(*w)).collect();
        assert_eq!(items, works, "{}", g.id);
        assert!(record.items().iter().all(|t| t.expect == Expect::Next));
        let pointed: Vec<ItemRef> = record.outbox().iter().map(|p| p.item).collect();
        assert_eq!(pointed, works, "{}", g.id);
        let id = hex(&record.record_id());
        assert!(record.outbox().iter().all(|p| p.event_id.starts_with(&id)));
    }
}

// T-98 P-38 T-89
#[test]
fn t_98_the_item_a_record_is_about_takes_its_type_and_every_other_item_changed() {
    let touch = |item| ItemTouch {
        item,
        expect: Expect::Next,
        heads: None,
    };
    let touches = [
        touch(ItemRef::Work([1; 16])),
        touch(ItemRef::Work([2; 16])),
        touch(ItemRef::Commitment([3; 32])),
    ];
    let updated = work_proto::events::find("work.updated");
    assert_eq!(
        pointer_types(updated, "work.opened", &touches),
        ["work.updated", "work.changed", "commitment.changed"]
    );
    let promised = work_proto::events::find("commitment.promised");
    assert_eq!(
        pointer_types(promised, "work.opened", &touches),
        ["work.changed", "work.changed", "commitment.promised"]
    );
    assert_eq!(
        pointer_types(promised, "work.opened", &touches[..2]),
        ["work.changed", "work.changed"]
    );
    assert_eq!(
        pointer_types(None, "work.opened", &touches[..2]),
        ["work.opened", "work.opened"]
    );
    for g in &golden() {
        let (ledger, _) = slot_of(&g.envelope);
        let record = pending(g, &ledger).unwrap();
        let typed = work_proto::events::RecordFacts::decode(&record.record_bytes)
            .and_then(|f| f.primary())
            .is_some();
        let primary = record
            .outbox()
            .iter()
            .filter(|p| !p.event_type.ends_with(".changed"))
            .count();
        assert!(!typed || primary <= 1, "{}", g.id);
        assert!(
            record
                .outbox()
                .iter()
                .all(|p| work_proto::events::find(&p.event_type).is_some()),
            "{}",
            g.id
        );
    }
}

// P-19 P-87 P-11
#[test]
fn p_19_a_quarantined_record_is_written_with_its_reason() {
    let entries = golden();
    let critical = entries
        .iter()
        .find(|g| g.id.ends_with("critical-ext-not-understood"));
    let critical = critical.unwrap();
    let (ledger, _) = slot_of(&critical.envelope);
    let record = pending(critical, &ledger).unwrap();
    let header = &record.skeleton().unwrap().header;
    assert_eq!(header.ingest, "quarantined");
    assert_eq!(
        header.ingest_reason.as_deref(),
        Some("extension_critical_unknown")
    );
    let unknown = entries.last().unwrap();
    let record = pending(unknown, &ledger).unwrap();
    assert!(record.skeleton().is_none());
    assert_eq!(record.items().len(), 0);
    assert_eq!(record.outbox().len(), 0);
}

// C-34 OP-9 P-11 T-91
#[test]
fn op_9_a_record_declaring_another_ledger_is_refused() {
    let g = &golden()[0];
    assert_eq!(
        pending(g, &LedgerId::from_bytes([0xee; 32]))
            .err()
            .as_ref()
            .map(rejected),
        Some(Reason::EnvelopeMismatch(EnvelopeField::Ledger))
    );
}

// P-21 P-108 T-91
#[test]
fn p_21_an_unsigned_record_of_an_unknown_protocol_is_refused() {
    let quarantine = json(QUARANTINE);
    let case = &quarantine["cases"][3];
    let record = unhex(case["hex"].as_str().unwrap());
    let (declared, bindings) = actor_inputs(
        &record,
        &serde_json::json!({"author": ["human", "access_binding"]}),
    );
    let g = Golden {
        id: case["id"].as_str().unwrap().to_owned(),
        record,
        envelope: unhex(case["envelope"]["hex"].as_str().unwrap()),
        cose: None,
        declared,
        bindings,
        origin: Origin::Direct,
        understood: vec![],
    };
    let (ledger, _) = slot_of(&g.envelope);
    assert_eq!(
        pending(&g, &ledger).err().as_ref().map(rejected),
        Some(Reason::ProtocolVersionUnknown)
    );
}

// P-21 T-90 T-91
#[test]
fn p_21_a_signed_agent_record_sent_unsigned_is_refused() {
    let g = &golden()[0];
    let unsigned = Golden {
        id: g.id.clone(),
        record: g.record.clone(),
        envelope: g.envelope.clone(),
        cose: None,
        declared: g.declared.clone(),
        bindings: g.bindings.clone(),
        origin: g.origin,
        understood: g.understood.clone(),
    };
    let (ledger, _) = slot_of(&g.envelope);
    assert_eq!(
        pending(&unsigned, &ledger).err().as_ref().map(rejected),
        Some(Reason::AuthorSignatureMissing)
    );
}

// T-91 T-90 P-33
#[test]
fn t_91_received_bytes_above_262_144_are_limit_exceeded_request() {
    let g = &golden()[0];
    let (ledger, _) = slot_of(&g.envelope);
    let too_long = Golden {
        id: g.id.clone(),
        record: g.record.clone(),
        envelope: g.envelope.clone(),
        cose: Some(vec![0; 262_145]),
        declared: g.declared.clone(),
        bindings: g.bindings.clone(),
        origin: g.origin,
        understood: g.understood.clone(),
    };
    assert_eq!(
        pending(&too_long, &ledger).err().as_ref().map(rejected),
        Some(Reason::LimitExceeded(Limit::Request))
    );
}

fn sealed_actors(g: &Golden, ledger: &LedgerId, slot: &Slot) -> (ActorTypes, Vec<u8>) {
    let record = pending(g, ledger).unwrap_or_else(|r| panic!("{}: {r}", g.id));
    let (_, sealed) = Bound {
        ledger,
        record: &record,
    }
    .seal(slot)
    .unwrap();
    let Ok(Envelope::Ledger(e)) = decode_envelope(&sealed.envelope) else {
        panic!("{}", g.id);
    };
    (e.actor_types, sealed.envelope)
}

fn entry(actor_type: ActorType, source: ActorTypeSource) -> ActorTypeEntry {
    ActorTypeEntry { actor_type, source }
}

// EV-35 P-12 C-17 T-91
#[test]
fn ev_35_a_presenter_without_an_access_binding_is_declared_unverified_in_the_envelope() {
    let entries = golden();
    let act = entries
        .iter()
        .find(|g| g.id == "record/act-action-fulfills")
        .unwrap();
    let (ledger, slot) = slot_of(&act.envelope);
    let unbound = Golden {
        id: act.id.clone(),
        record: act.record.clone(),
        envelope: act.envelope.clone(),
        cose: act.cose.clone(),
        declared: act.declared.clone(),
        bindings: ActorBindings::new(),
        origin: act.origin,
        understood: act.understood.clone(),
    };
    let (actors, envelope) = sealed_actors(&unbound, &ledger, &slot);
    let declared = entry(ActorType::Organization, ActorTypeSource::DeclaredUnverified);
    assert_eq!(actors.author, declared);
    assert_eq!(actors.evidence, [declared]);
    assert_ne!(envelope, act.envelope);
    let mut missing = unbound;
    missing.declared.evidence.clear();
    assert_eq!(
        pending(&missing, &ledger).err().as_ref().map(rejected),
        Some(Reason::EnvelopeMismatch(EnvelopeField::ActorType))
    );
}

// P-12 C-17 MD-7
#[test]
fn p_12_the_envelope_takes_each_party_s_type_from_its_access_binding_never_from_the_request() {
    let entries = golden();
    let promise = &entries[0];
    assert_eq!(promise.id, "record/declaration-promise-for-principal");
    let (ledger, slot) = slot_of(&promise.envelope);
    let mut claimed = Golden {
        id: promise.id.clone(),
        record: promise.record.clone(),
        envelope: promise.envelope.clone(),
        cose: promise.cose.clone(),
        declared: promise.declared.clone(),
        bindings: promise.bindings.clone(),
        origin: promise.origin,
        understood: promise.understood.clone(),
    };
    claimed.declared.author.actor_type = ActorType::Human;
    claimed.declared.on_behalf_of[0].actor_type = ActorType::Human;
    let (actors, envelope) = sealed_actors(&claimed, &ledger, &slot);
    assert_eq!(
        actors.author,
        entry(ActorType::Agent, ActorTypeSource::AccessBinding)
    );
    assert_eq!(
        actors.on_behalf_of,
        [entry(
            ActorType::Organization,
            ActorTypeSource::AccessBinding
        )]
    );
    assert_eq!(envelope, promise.envelope);
    let mut author_only = ActorBindings::new();
    author_only
        .bind(claimed.declared.author.party.clone(), ActorType::Agent)
        .unwrap();
    claimed.bindings = author_only;
    let (actors, _) = sealed_actors(&claimed, &ledger, &slot);
    assert_eq!(
        actors.on_behalf_of,
        [entry(ActorType::Human, ActorTypeSource::DeclaredUnverified)]
    );
    claimed.declared.on_behalf_of[0].party = claimed.declared.author.party.clone();
    assert_eq!(
        pending(&claimed, &ledger).err().as_ref().map(rejected),
        Some(Reason::EnvelopeMismatch(EnvelopeField::ActorType))
    );
}

// OP-1 T-11 T-89 T-90 P-87
#[test]
fn op_1_the_golden_ledger_replays_from_its_stored_bytes_to_the_admitted_records() {
    for g in &golden() {
        let (ledger, slot) = slot_of(&g.envelope);
        let mut admitted = pending(g, &ledger).unwrap();
        let stored = work_store::CanonicalEntry {
            pos: slot.pos,
            recorded_at_ms: slot.recorded_at,
            record_bytes: g.record.clone(),
            envelope_bytes: g.envelope.clone(),
            received: admitted.received().to_vec(),
        };
        let replayed = crate::rebuild::replayed(&ledger, &stored).unwrap();
        admitted.outbox.clear();
        assert_eq!(replayed, admitted, "{}", g.id);
        let mut other = stored.clone();
        other.pos = slot.pos.checked_add(1).unwrap();
        assert!(
            crate::rebuild::replayed(&ledger, &other).is_err(),
            "{}",
            g.id
        );
        let mut foreign = stored.clone();
        foreign.record_bytes.push(0);
        assert!(
            crate::rebuild::replayed(&ledger, &foreign).is_err(),
            "{}",
            g.id
        );
    }
}

fn humans() -> Vec<Golden> {
    golden().into_iter().filter(|g| g.cose.is_none()).collect()
}

// P-116 P-21 T-91
#[test]
fn p_116_an_unsigned_record_is_refused_with_the_artifact_of_another_record() {
    let entries = humans();
    let [a, b, ..] = entries.as_slice() else {
        panic!("two human records");
    };
    let (ledger, _) = slot_of(&a.envelope);
    assert_eq!(
        pending_with(a, &ledger, &artifact_of(&b.record)).err(),
        Some(AdmitError::AuthContext(AuthContextInvalid::OtherContent))
    );
    let unbound = REALM.with(|r| r.artifact(&realm::payload(None)).unwrap());
    assert_eq!(
        pending_with(a, &ledger, &unbound).err(),
        Some(AdmitError::AuthContext(AuthContextInvalid::Unbound))
    );
    let other = REALM.with(|r| r.another("other").unwrap());
    let foreign = other.for_record(sha256(&a.record)).unwrap();
    assert!(matches!(
        pending_with(a, &ledger, &foreign).err(),
        Some(AdmitError::AuthContext(AuthContextInvalid::Signature(_)))
    ));
}

// P-116 P-21 P-75
#[test]
fn p_116_the_envelope_names_the_artifact_by_its_digest_with_the_payload_assurance() {
    let entries = humans();
    let g = &entries[0];
    let (ledger, slot) = slot_of(&g.envelope);
    let Value::Map(mut stepped) = realm::record_payload(sha256(&g.record)) else {
        panic!("a map");
    };
    stepped.retain(|(k, _)| *k != Value::text("aal"));
    stepped.push((Value::text("aal"), Value::text("aal3")));
    stepped.push((
        Value::text("step_up_time"),
        Value::Unsigned(realm::AUTH_TIME),
    ));
    let artifact = REALM.with(|r| r.artifact(&Value::Map(stepped)).unwrap());
    let record = pending_with(g, &ledger, &artifact).unwrap();
    assert_eq!(
        record.auth_context,
        Some(auth_context_value(&artifact.digest, true, "aal3"))
    );
    assert_eq!(
        record.skeleton().unwrap().header.auth_context_ref,
        Some(artifact.digest)
    );
    assert_eq!(record.received()[0].bytes, artifact.cose);
    let (_, sealed) = Bound {
        ledger: &ledger,
        record: &record,
    }
    .seal(&slot)
    .unwrap();
    let Ok(Envelope::Ledger(e)) = decode_envelope(&sealed.envelope) else {
        panic!("{}", g.id);
    };
    let context = e.auth_context.unwrap();
    assert_eq!(context.reference.as_bytes(), &artifact.digest);
    assert!(context.step_up);
    assert_eq!(context.assurance, "aal3");
}

/// `record` with its `authority` replaced by a decision receipt digest of `digest`.
fn with_authority(record: &[u8], digest: [u8; 32]) -> Vec<u8> {
    let Value::Map(mut entries) = decode(record, Limits::CEILING).unwrap() else {
        panic!("a map");
    };
    for (k, v) in &mut entries {
        if *k == Value::text("authority") {
            *v = Value::Map(vec![
                (Value::text("proof"), Value::text("decision_receipt")),
                (Value::text("digest"), Digest(digest).to_value()),
            ]);
        }
    }
    suiss_crypto::dcbor::encode(&Value::Map(entries), Limits::CEILING).unwrap()
}

// P-13 T-90 P-5
#[test]
fn p_13_the_authority_proof_is_kept_only_when_the_record_refers_to_it() {
    let proof = b"receipt bytes as Access sent them".to_vec();
    let mut g = humans()
        .into_iter()
        .find(|g| g.id == "record/declaration-cancel-reason-sub-code")
        .unwrap();
    g.record = with_authority(&g.record, sha256(&proof));
    let (ledger, _) = slot_of(&g.envelope);
    let mut record = pending(&g, &ledger).unwrap();
    let unchanged = record.clone();
    assert_eq!(
        record.keep_authority_proof(AuthorityProofKind::DecisionReceipt, b"other bytes"),
        Err(AuthorityProofMismatch::Digest)
    );
    assert_eq!(
        record.keep_authority_proof(AuthorityProofKind::PortableAuthorityProof, &proof),
        Err(AuthorityProofMismatch::Kind)
    );
    assert_eq!(
        record.keep_authority_proof(AuthorityProofKind::DecisionReceipt, &[]),
        Err(AuthorityProofMismatch::Digest)
    );
    assert_eq!(record, unchanged);
    record
        .keep_authority_proof(AuthorityProofKind::DecisionReceipt, &proof)
        .unwrap();
    let [context, kept] = record.received() else {
        panic!("two received rows");
    };
    assert_eq!(context.role, ReceivedRole::AuthContext);
    assert_eq!(kept.role, ReceivedRole::AuthorityProof);
    assert_eq!(kept.kind, ReceivedKind::AccessDecisionReceipt);
    assert_eq!(kept.bytes, proof);
    let claim = humans()
        .into_iter()
        .find(|g| g.id == "record/claim-comment-private")
        .unwrap();
    let mut comment = pending(&claim, &ledger).unwrap();
    assert_eq!(
        comment.keep_authority_proof(AuthorityProofKind::DecisionReceipt, &proof),
        Err(AuthorityProofMismatch::Unnamed)
    );
}
