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

use super::*;
use crate::envelope::Bound;

const COSE: &str = include_str!("../../../../conformance/vectors/records/cose-sign1.json");
const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
const QUARANTINE: &str =
    include_str!("../../../../conformance/vectors/records/records-quarantine.json");
const CONTEXT: &[u8] = b"work-vector:access:auth-context:alice";
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
    actors: ActorTypes,
    origin: Origin,
    understood: Vec<ExtKey>,
}

fn actor(v: &Json) -> ActorTypeEntry {
    ActorTypeEntry {
        actor_type: ActorType::from_wire_name(v[0].as_str().unwrap()).unwrap(),
        source: ActorTypeSource::from_wire_name(v[1].as_str().unwrap()).unwrap(),
    }
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
        out.push(Golden {
            id: r["id"].as_str().unwrap().to_owned(),
            record: unhex(r["hex"].as_str().unwrap()),
            envelope: unhex(e["hex"].as_str().unwrap()),
            cose: cose.get(&name).cloned(),
            actors: ActorTypes {
                author: actor(&ctx["actor_type"]["author"]),
                on_behalf_of: ctx["actor_type"]["on_behalf_of"]
                    .as_array()
                    .map(|rings| rings.iter().map(actor).collect())
                    .unwrap_or_default(),
                evidence: ctx["actor_type"]["evidence"]
                    .as_array()
                    .map(|presenters| presenters.iter().map(actor).collect())
                    .unwrap_or_default(),
            },
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

fn pending(g: &Golden, ledger: &LedgerId) -> Result<PendingRecord, Reason> {
    let arrival = g.cose.as_deref().map_or(
        Arrival::Unsigned {
            record: &g.record,
            auth_context: AuthContext {
                bytes: CONTEXT,
                assurance: "aal2",
                step_up: false,
            },
        },
        Arrival::Signed,
    );
    admit(
        &Directory::golden(),
        ledger,
        Submission {
            arrival,
            actor_types: &g.actors,
            origin: g.origin,
            understood_extensions: &g.understood,
            limits: SemanticLimits::default(),
            event_type: "work.recorded",
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
    assert_eq!(entries.len(), 14);
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
            assert_eq!(kept.bytes, CONTEXT);
            assert_eq!(kept.role, ReceivedRole::AuthContext);
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
        pending(g, &LedgerId::from_bytes([0xee; 32])).err(),
        Some(Reason::EnvelopeMismatch(EnvelopeField::Ledger))
    );
}

// P-21 P-108 T-91
#[test]
fn p_21_an_unsigned_record_of_an_unknown_protocol_is_refused() {
    let quarantine = json(QUARANTINE);
    let case = &quarantine["cases"][3];
    let g = Golden {
        id: case["id"].as_str().unwrap().to_owned(),
        record: unhex(case["hex"].as_str().unwrap()),
        envelope: unhex(case["envelope"]["hex"].as_str().unwrap()),
        cose: None,
        actors: ActorTypes {
            author: actor(&serde_json::json!(["human", "access_binding"])),
            on_behalf_of: vec![],
            evidence: vec![],
        },
        origin: Origin::Direct,
        understood: vec![],
    };
    let (ledger, _) = slot_of(&g.envelope);
    assert_eq!(
        pending(&g, &ledger).err(),
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
        actors: g.actors.clone(),
        origin: g.origin,
        understood: g.understood.clone(),
    };
    let (ledger, _) = slot_of(&g.envelope);
    assert_eq!(
        pending(&unsigned, &ledger).err(),
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
        actors: g.actors.clone(),
        origin: g.origin,
        understood: g.understood.clone(),
    };
    assert_eq!(
        pending(&too_long, &ledger).err(),
        Some(Reason::LimitExceeded(Limit::Request))
    );
}

// EV-35 P-12 T-91
#[test]
fn ev_35_the_envelope_carries_the_presenter_actor_types_the_caller_resolved() {
    let entries = golden();
    let act = entries
        .iter()
        .find(|g| g.id == "record/act-action-fulfills")
        .unwrap();
    let (ledger, slot) = slot_of(&act.envelope);
    let with = |actors: ActorTypes| Golden {
        id: act.id.clone(),
        record: act.record.clone(),
        envelope: act.envelope.clone(),
        cose: act.cose.clone(),
        actors,
        origin: act.origin,
        understood: act.understood.clone(),
    };
    let mut unbound = act.actors.clone();
    unbound.evidence = vec![ActorTypeEntry {
        actor_type: ActorType::Organization,
        source: ActorTypeSource::DeclaredUnverified,
    }];
    let record = pending(&with(unbound.clone()), &ledger).unwrap();
    let (_, sealed) = Bound {
        ledger: &ledger,
        record: &record,
    }
    .seal(&slot)
    .unwrap();
    let Ok(Envelope::Ledger(e)) = decode_envelope(&sealed.envelope) else {
        panic!("{}", act.id);
    };
    assert_eq!(e.actor_types, unbound);
    assert_ne!(sealed.envelope, act.envelope);
    let mut missing = act.actors.clone();
    missing.evidence.clear();
    assert_eq!(
        pending(&with(missing), &ledger).err(),
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
