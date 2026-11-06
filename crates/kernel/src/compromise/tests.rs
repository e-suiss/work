use alloc::vec;

use super::*;
use crate::id::{Digest, Time};
use crate::limits::SemanticLimits;
use crate::validate::{
    ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin, Outcome, ValidationContext,
    validate,
};

fn window() -> Window {
    Window {
        instance: [4; 16],
        kids: vec![[7; 32], [2; 32]],
        window_from: 1_000,
        window_to: 5_000,
        event_digest: [8; 32],
        domain: [1; 32],
        source: String::from("CQkJCQkJCQkJCQkJCQkJCQ"),
    }
}

fn input() -> NoticeInput {
    NoticeInput {
        author: PartyRef::new("AwMDAwMDAwMDAwMDAwMDAw").unwrap(),
        ledger: LedgerId(Digest::sha256([0x4c; 32])),
        party: PartyRef::new("AgICAgICAgICAgICAgICAg").unwrap(),
        jti: String::from("8a2b6c4e-set"),
        window: window(),
    }
}

fn decoded(bytes: &[u8]) -> Record {
    match decode_record(bytes).unwrap() {
        Decoded::Record(r) => r,
        Decoded::UnknownProtocol(_) => panic!("a known protocol"),
    }
}

// SEC-36
#[test]
fn sec_36_one_notice_per_access_declaration() {
    let first = notice_record(&input()).unwrap();
    assert_eq!(notice_record(&input()).unwrap(), first);
    let mut other = input();
    other.window.event_digest = [9; 32];
    assert_ne!(notice_record(&other).unwrap(), first);
    let mut elsewhere = input();
    elsewhere.ledger = LedgerId(Digest::sha256([0x4d; 32]));
    assert_ne!(notice_record(&elsewhere).unwrap(), first);
    let (id, read) = notice_of_bytes(&first).unwrap();
    assert_eq!(id, crate::codec::record_id(&first));
    let mut sorted = window();
    sorted.kids.sort_unstable();
    assert_eq!(read.window, sorted);
    assert_eq!(read.party.as_deref(), Some("AgICAgICAgICAgICAgICAg"));
    assert_eq!(
        read.event,
        Some(event_ref("8a2b6c4e-set", &[8; 32]).unwrap())
    );
    let record = decoded(&first);
    assert_eq!(record.kind(), crate::record::Kind::Claim);
    assert!(record.basis().is_empty());
    assert_eq!(record.core().author.as_str(), "AwMDAwMDAwMDAwMDAwMDAw");
}

// SEC-36
#[test]
fn sec_36_the_notice_is_a_core_observation_claim_of_a_system_party() {
    let record = decoded(&notice_record(&input()).unwrap());
    let Record::Claim(claim) = &record else {
        panic!("a Claim");
    };
    assert_eq!(claim.subtype, ClaimType::Core(ClaimSubtype::Observation));
    assert_eq!(claim.occurred_at, Time(5_000));
    assert!(claim.core.critical.is_none());
    let actors = ActorTypes {
        author: ActorTypeEntry {
            actor_type: ActorType::System,
            source: ActorTypeSource::AccessBinding,
        },
        on_behalf_of: vec![],
        evidence: vec![],
    };
    let ctx = ValidationContext {
        origin: Origin::Direct,
        actor_types: &actors,
        understood_extensions: &[],
        limits: SemanticLimits::default(),
        recorded_at: None,
    };
    assert_eq!(validate(&record, &ctx), Outcome::Accepted);
}

// SEC-36
#[test]
fn sec_36_records_in_the_window_stay_and_are_marked() {
    let w = window();
    let kid = [7; 32];
    let party = Some("AgICAgICAgICAgICAgICAg");
    for (at, marked) in [(999, false), (1_000, true), (3_000, true), (5_000, true), (5_001, false)] {
        assert_eq!(w.marks(at, Some(&kid), None, party), marked, "{at}");
        assert_eq!(w.marks(at, None, party, party), marked, "{at}");
    }
    assert!(!w.marks(3_000, Some(&[6; 32]), None, party));
    assert!(!w.marks(3_000, None, Some("BQUFBQUFBQUFBQUFBQUFBQ"), party));
    assert!(!w.marks(3_000, None, party, None));
}

// SEC-36
#[test]
fn sec_36_a_body_without_kids_or_with_a_reversed_window_is_refused() {
    let mut empty = window();
    empty.kids.clear();
    assert_eq!(empty.encode(), Err(WindowError("kids")));
    let mut reversed = window();
    reversed.window_from = 6_000;
    assert_eq!(reversed.encode(), Err(WindowError("window_to")));
    let bytes = window().encode().unwrap();
    let mut back = window();
    back.kids.sort_unstable();
    assert_eq!(Window::decode(&bytes).unwrap(), back);
    assert_eq!(event_ref("a b", &[0; 32]), Err(WindowError("jti")));
    assert_eq!(event_ref("", &[0; 32]), Err(WindowError("jti")));
}
