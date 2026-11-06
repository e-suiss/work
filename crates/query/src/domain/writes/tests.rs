#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use serde_json::Value as Json;
use work_access_client::domain::exercise::AgencyLink;
use work_access_client::domain::keys::{Compromise, Kid, LedgerPoint};
use work_kernel::codec::{Decoded, decode_record};
use work_kernel::cose::{Algorithm, AuthorKeys, PublicKey};
use work_kernel::id::Digest;
use work_kernel::reason::{Reason, Signature};
use work_kernel::record::AuthorityRef;
use work_kernel::verify::{SignatureCheck, SignatureVerifier as _};

use super::*;

const COSE: &str = include_str!("../../../../../conformance/vectors/records/cose-sign1.json");
const RECORDS: &str = include_str!("../../../../../conformance/vectors/records/records.json");

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn json(text: &str) -> Json {
    serde_json::from_str(text).unwrap()
}

/// The golden promise the agent signed with its Ed25519 key, and that key.
fn promise() -> (Vec<u8>, [u8; 32], PublicKey) {
    let cose = json(COSE);
    let case = cose["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "cose-sign1/declaration-promise-for-principal")
        .unwrap();
    let key = cose["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == "agent-ed25519")
        .unwrap();
    let kid: [u8; 32] = unhex(key["kid_hex"].as_str().unwrap()).try_into().unwrap();
    let public: [u8; 32] = unhex(key["public_key_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    (
        unhex(case["cose_hex"].as_str().unwrap()),
        kid,
        PublicKey::Ed25519(public),
    )
}

fn record(id: &str) -> Record {
    let records = json(RECORDS);
    let r = records["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap();
    match decode_record(&unhex(r["hex"].as_str().unwrap())).unwrap() {
        Decoded::Record(record) => *record,
        Decoded::UnknownProtocol(_) => panic!("{id}"),
    }
}

fn entry(kid: [u8; 32], key: PublicKey, state: KeyState) -> InstanceKey {
    InstanceKey {
        kid: Kid(kid),
        alg: Algorithm::Ed25519,
        key,
        party: KernelId([2; 16]),
        actor_kind: ActorKind::Agent,
        instance: KernelId([3; 16]),
        since: LedgerPoint { pos: 1, at: 5 },
        ended: (state == KeyState::Ended).then_some(LedgerPoint { pos: 2, at: 6 }),
        successor: None,
        state,
        compromise: (state == KeyState::Compromised).then_some(Compromise {
            from: 4,
            declared_at: 7,
            source: KernelId([9; 16]),
        }),
    }
}

fn kid_unknown() -> SignatureCheck {
    SignatureCheck::Rejected(Reason::Signature(Signature::KidUnknown))
}

fn check(cose: &[u8], author: &PartyRef, signer: &Signer) -> SignatureCheck {
    AuthorKeys {
        author: signer.party.as_ref().map_or(author, |(p, _)| p),
        keys: &signer.keys,
    }
    .check(cose)
}

// SEC-19 SEC-31 P-105 T-101
#[test]
fn sec_19_a_record_signed_after_a_compromise_or_with_an_ended_key_is_kid_unknown() {
    let (cose, kid, key) = promise();
    let author = PartyRef::new("party:acme:agent-procure-7").unwrap();
    for state in [KeyState::Compromised, KeyState::Ended] {
        let s = signer(Some(&entry(kid, key.clone(), state)));
        assert!(s.party.is_none(), "{state:?}");
        assert!(s.keys.keys.is_empty(), "{state:?}");
        assert_eq!(check(&cose, &author, &s), kid_unknown(), "{state:?}");
    }
    assert_eq!(check(&cose, &author, &signer(None)), kid_unknown());
}

// P-105 P-21 T-101
#[test]
fn p_105_a_record_whose_author_is_not_the_key_s_party_is_kid_unknown() {
    let (cose, kid, key) = promise();
    let author = PartyRef::new("party:acme:agent-procure-7").unwrap();
    let s = signer(Some(&entry(kid, key, KeyState::Active)));
    let (party, _) = s.party.clone().unwrap();
    assert_eq!(party.as_str(), b64url(&[2; 16]));
    assert_eq!(check(&cose, &author, &s), kid_unknown());
    let as_author = Signer {
        party: Some((author.clone(), ActorType::Agent)),
        keys: s.keys,
    };
    assert!(matches!(
        check(&cose, &author, &as_author),
        SignatureCheck::Valid { .. }
    ));
    assert_eq!(header_kid(&cose), Some(kid));
    assert_eq!(header_kid(b"not cose"), None);
}

// P-12 MD-7 INV-18 C-17
#[test]
fn p_12_the_author_s_actor_type_is_the_actor_kind_of_its_key_s_party() {
    let (_, kid, key) = promise();
    for kind in ActorKind::ALL {
        let mut e = entry(kid, key.clone(), KeyState::Active);
        e.actor_kind = kind;
        let (_, actor) = signer(Some(&e)).party.unwrap();
        assert_eq!(actor, actor_type(kind));
        assert_eq!(actor.wire_name(), kind.wire_name());
    }
}

fn exercise(capacity: Held, agency: Vec<AgencyLink>, receipt: &[u8]) -> VerifiedExercise {
    VerifiedExercise {
        exercise: ExerciseId([1; 32]),
        domain: work_access_client::domain::keys::DomainId([1; 32]),
        position: 12,
        intent: [3; 32],
        instance: Some(KernelId([3; 16])),
        capacity,
        agency,
        iat: 1,
        receipt: receipt.to_vec(),
        excerpt: Vec::new(),
    }
}

fn citing(record: &Record, receipt: &[u8]) -> RecordCore {
    let mut core = record.core().clone();
    core.authority = Some(AuthorityRef {
        proof: AuthorityProofKind::DecisionReceipt,
        digest: Digest::sha256(sha256(receipt)),
    });
    core
}

// P-13 E-9
#[test]
fn p_13_the_authority_names_exactly_the_verified_receipt() {
    let receipt = b"receipt".to_vec();
    let cancel = record("record/declaration-cancel-reason-sub-code");
    let core = citing(&cancel, &receipt);
    let held = exercise(Held::Own, Vec::new(), &receipt);
    assert_eq!(check_authority(&core, &held), Ok(()));
    let other = exercise(Held::Own, Vec::new(), b"another receipt");
    assert_eq!(check_authority(&core, &other), Err("authority_digest"));
    let mut portable = core.clone();
    portable.authority = Some(AuthorityRef {
        proof: AuthorityProofKind::PortableAuthorityProof,
        ..core.authority.unwrap()
    });
    assert_eq!(check_authority(&portable, &held), Err("authority_kind"));
    let mut none = core;
    none.authority = None;
    assert_eq!(check_authority(&none, &held), Err("authority_kind"));
}

// E-13 C-25 SEC-4 P-13
#[test]
fn e_13_the_record_s_capacity_is_the_exercise_s_and_its_chain_is_covered() {
    let receipt = b"receipt".to_vec();
    let cancel = record("record/declaration-cancel-reason-sub-code");
    let own = citing(&cancel, &receipt);
    let principal = party_ref(&KernelId([2; 16])).unwrap();
    let for_principal = exercise(Held::For(KernelId([2; 16])), Vec::new(), &receipt);
    assert_eq!(
        check_authority(&own, &for_principal),
        Err("capacity_mismatch")
    );
    let mut acting = own.clone();
    acting.capacity = Some(Capacity::For(principal.clone()));
    acting.on_behalf_of = Some(vec![principal.clone()]);
    assert_eq!(check_authority(&acting, &for_principal), Ok(()));
    assert_eq!(
        check_authority(&acting, &exercise(Held::Own, Vec::new(), &receipt)),
        Err("capacity_mismatch")
    );
    let other = exercise(Held::For(KernelId([4; 16])), Vec::new(), &receipt);
    assert_eq!(check_authority(&acting, &other), Err("capacity_mismatch"));
    let root = party_ref(&KernelId([5; 16])).unwrap();
    let mut wider = acting.clone();
    wider.on_behalf_of = Some(vec![principal.clone(), root]);
    assert_eq!(
        check_authority(&wider, &for_principal),
        Err("on_behalf_of_uncovered")
    );
    let link = |agent: u8| AgencyLink {
        mandate: KernelId([7; 16]),
        principal: KernelId([5; 16]),
        agent: KernelId([agent; 16]),
    };
    let mut author = wider.clone();
    author.author = party_ref(&KernelId([6; 16])).unwrap();
    let chained = exercise(Held::For(KernelId([2; 16])), vec![link(6)], &receipt);
    assert_eq!(check_authority(&author, &chained), Ok(()));
    let foreign = exercise(Held::For(KernelId([2; 16])), vec![link(8)], &receipt);
    assert_eq!(check_authority(&author, &foreign), Err("agency_agent"));
}

fn intent(action: &str, ledger: &LedgerId) -> Intent {
    Intent {
        digest: [3; 32],
        namespace: ACTION_NAMESPACE.to_owned(),
        action: action.to_owned(),
        major: ACTION_MAJOR,
        resources: vec![work_access_client::domain::exercise::Resource {
            namespace: LEDGER_RESOURCE.to_owned(),
            path: vec![ledger.to_external()],
        }],
        valid_from_ms: 100,
        valid_until_ms: 200,
    }
}

// E-45 T-101 MD-4
#[test]
fn e_45_the_exercise_is_the_work_commit_intent_of_this_ledger_and_valid_now() {
    let ledger = record("record/declaration-cancel-reason-sub-code")
        .core()
        .ledger;
    let other = LedgerId(Digest::sha256([9; 32]));
    let commit = intent(COMMIT, &ledger);
    assert_eq!(check_intent(&commit, &ledger, 150), Ok(()));
    assert_eq!(check_intent(&commit, &ledger, 201), Err("intent_expired"));
    assert_eq!(check_intent(&commit, &ledger, 99), Err("intent_expired"));
    assert_eq!(check_intent(&commit, &other, 150), Err("intent_resource"));
    assert_eq!(
        check_intent(&intent("close", &ledger), &ledger, 150),
        Err("intent_action")
    );
    let mut foreign = commit;
    foreign.namespace = "pay".to_owned();
    assert_eq!(check_intent(&foreign, &ledger, 150), Err("intent_action"));
}

// E-45 P-83
#[test]
fn e_45_the_route_writes_only_operations_work_commit_covers() {
    assert!(commit_operation(&record(
        "record/declaration-cancel-reason-sub-code"
    )));
    assert!(commit_operation(&record(
        "record/declaration-promise-for-principal"
    )));
    assert!(!commit_operation(&record("record/declaration-redact")));
    assert!(!commit_operation(&record("record/claim-comment-private")));
    assert!(!commit_operation(&record("record/act-action-fulfills")));
}
