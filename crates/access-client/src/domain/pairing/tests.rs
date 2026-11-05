use access_kernel::intent::IntentEnvelope;

use super::*;
use crate::domain::discovery::{Endpoint, Endpoints};
use crate::domain::tests::hex;

const CHALLENGES: &str =
    include_str!("../../../../../conformance/vectors/access/pairing-challenges.json");
const RESULT: &str = include_str!("../../../../../conformance/vectors/access/pairing-result.json");
const DIGESTS: &str = include_str!("../../../../../conformance/vectors/access/intent-digest.json");

pub(crate) const NOW: u64 = 1_793_793_600_000;
const TENANT: &str = "tnt_0123456789abcdefghjkmnpqrs";
const A1: &str = "019a0000-0000-7000-8000-0000000000a1";
const A2: &str = "019a0000-0000-7000-8000-0000000000a2";

fn service() -> PublicKey {
    let raw = hex("66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a");
    PublicKey::Ed25519(<[u8; 32]>::try_from(raw.as_slice()).unwrap())
}

fn realm(text: &str) -> RealmId {
    RealmId::parse(text).unwrap()
}

/// A challenge for `service` valid ten minutes from `now`, with the digests Access computes.
pub(crate) fn challenge_for(service: &PublicKey, now: u64) -> Unpaired {
    let domain = [0x0d; 32];
    let ExerciseBasis::Public(basis) = bootstrap_basis(&domain) else {
        panic!("a public basis");
    };
    let challenge = [0x0c; 32];
    let mut c = Unpaired {
        realm: realm(A1),
        domain,
        basis: basis.0,
        pep: "access-identity".to_owned(),
        party: [0x0a; 16],
        kid: thumbprint(service),
        challenge,
        valid_from_ms: now,
        valid_until_ms: now.checked_add(600_000).unwrap(),
        instance_create: Exercise {
            nonce: challenge.to_vec(),
            intent: [0; 32],
        },
        party_register: Some(Exercise {
            nonce: register_nonce(&challenge),
            intent: [0; 32],
        }),
    };
    c.instance_create.intent = instance_create_digest(&c, service).unwrap();
    let register = party_register_digest(&c).unwrap();
    if let Some(r) = c.party_register.as_mut() {
        r.intent = register;
    }
    c
}

fn answer(targets: Vec<Target>) -> Answer {
    Answer {
        tenant: TENANT.to_owned(),
        targets,
        event_stream: None,
    }
}

// T-103
#[test]
fn t_103_the_access_challenge_example_is_read_with_its_two_exercises() {
    let a = Answer::from_json(CHALLENGES.as_bytes(), TENANT).unwrap();
    assert_eq!(a.targets.len(), 2);
    let Target::Unpaired(c) = &a.targets[0] else {
        panic!("unpaired first");
    };
    assert_eq!(c.realm.as_str(), A1);
    assert_eq!(c.pep, "access-identity");
    assert_eq!(c.valid_until_ms.checked_sub(c.valid_from_ms), Some(600_000));
    assert_eq!(c.instance_create.nonce, c.challenge.to_vec());
    assert_eq!(
        c.party_register.as_ref().map(|r| r.nonce.clone()),
        Some(register_nonce(&c.challenge))
    );
    let Target::Paired(p) = &a.targets[1] else {
        panic!("paired second");
    };
    assert_eq!(p.realm.as_str(), A2);
    assert!(Answer::from_json(CHALLENGES.as_bytes(), "tnt_other").is_err());
    let twice = CHALLENGES.replace(A2, A1);
    assert!(Answer::from_json(twice.as_bytes(), TENANT).is_err());
    let upper = CHALLENGES.replace(A1, &A1.to_uppercase());
    assert!(Answer::from_json(upper.as_bytes(), TENANT).is_err());
}

// T-103
#[test]
fn t_103_rfc3339_times_are_read_to_the_millisecond() {
    assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(rfc3339_ms("1970-01-01T00:00:01.5Z"), Some(1500));
    assert_eq!(rfc3339_ms("1970-01-01T00:00:01.25Z"), Some(1250));
    assert_eq!(
        rfc3339_ms("2026-11-05T09:10:00.000Z"),
        Some(1_793_869_800_000)
    );
    for bad in [
        "2026-11-05T09:10:00.0001Z",
        "2026-11-05T09:10:00+00:00",
        "2026-11-05 09:10:00Z",
        "2026-13-05T09:10:00Z",
        "2026-11-05T09:10:00.Z",
        "2026-11-05T09:10:00",
    ] {
        assert_eq!(rfc3339_ms(bad), None, "{bad}");
    }
}

// T-103
#[test]
fn t_103_the_intent_digest_is_the_one_of_the_access_core_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(DIGESTS).unwrap();
    let cases: Vec<&serde_json::Value> = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["operation"] == "digest.intent")
        .collect();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let envelope = IntentEnvelope::from_bytes(&hex(case["intent"].as_str().unwrap())).unwrap();
        let digest = intent_digest(&envelope).unwrap();
        let want = hex(case["digest"].as_str().unwrap());
        assert_eq!(want[..4], [0x82, 0x2f, 0x58, 0x20], "{}", case["id"]);
        assert_eq!(want[4..], digest.0, "{}", case["id"]);
    }
}

// T-103
#[test]
fn t_103_the_self_signed_intent_names_the_action_the_party_and_the_payload() {
    let c = challenge_for(&service(), NOW);
    let payload = Payload::InstanceCreate {
        party: Id(c.party),
        key: service(),
        mandate: None,
    };
    let validity = Window {
        from: c.valid_from_ms,
        until: c.valid_until_ms,
    };
    let intent = self_signed_intent(&payload, Id(c.party), validity).unwrap();
    assert_eq!(intent.action.namespace, "access");
    assert_eq!(intent.action.name, "instance_create");
    assert_eq!(intent.action.major, 1);
    assert_eq!(intent.resources.len(), 1);
    assert_eq!(intent.resources[0].namespace, "access.party");
    assert_eq!(intent.resources[0].path, vec!["0a".repeat(16)]);
    assert_eq!(
        intent.opaque.get("payload"),
        Some(&payload.digest().unwrap())
    );
    assert_eq!(intent.validity, validity);
    assert_ne!(
        instance_create_digest(&c, &service()).unwrap(),
        party_register_digest(&c).unwrap()
    );
}

// T-103
#[test]
fn t_103_a_challenge_whose_checks_hold_becomes_two_statements() {
    let c = challenge_for(&service(), NOW);
    let s = statements(&c, &service(), NOW).unwrap();
    let create = Statement::from_bytes(&s.instance_create).unwrap();
    assert_eq!(create.domain, Digest(c.domain));
    assert_eq!(create.nonce, c.challenge.to_vec());
    assert_eq!(create.intent, Digest(c.instance_create.intent));
    assert_eq!(create.mode, Mode::Commit);
    assert_eq!(create.capacity, Capacity::Own);
    assert_eq!(create.basis, ExerciseBasis::Public(Id(c.basis)));
    assert_eq!(create.pep, "access-identity");
    assert_eq!((create.iat, create.exercise), (NOW, None));
    let register = Statement::from_bytes(&s.party_register.unwrap()).unwrap();
    assert_eq!(register.nonce, register_nonce(&c.challenge));
    assert_eq!(register.intent, Digest(party_register_digest(&c).unwrap()));
    let mut known = c;
    known.party_register = None;
    assert_eq!(
        statements(&known, &service(), NOW).unwrap().party_register,
        None
    );
}

// T-103
#[test]
fn t_103_a_digest_that_does_not_match_is_not_signed() {
    let c = challenge_for(&service(), NOW);
    let mut create = c.clone();
    create.instance_create.intent = [9; 32];
    assert_eq!(
        statements(&create, &service(), NOW),
        Err(Unsignable::InstanceIntent)
    );
    let mut register = c.clone();
    if let Some(r) = register.party_register.as_mut() {
        r.intent = [9; 32];
    }
    assert_eq!(
        statements(&register, &service(), NOW),
        Err(Unsignable::RegisterIntent)
    );
    let mut window = c.clone();
    window.valid_until_ms = window.valid_until_ms.checked_add(1).unwrap();
    assert_eq!(
        statements(&window, &service(), NOW),
        Err(Unsignable::InstanceIntent)
    );
    let mut party = c;
    party.party = [0x0b; 16];
    let plan = plan_challenges(
        &answer(vec![Target::Unpaired(Box::new(party))]),
        &service(),
        NOW,
    );
    assert_eq!(plan.sign.len(), 0);
    assert_eq!(
        plan.unsignable,
        vec![(realm(A1), Unsignable::InstanceIntent)]
    );
    assert!(
        plan.changes
            .contains(&RealmChange::Failed { realm: realm(A1) })
    );
}

// T-103
#[test]
fn t_103_nonces_must_be_the_challenge_and_the_challenge_with_0x01() {
    let c = challenge_for(&service(), NOW);
    let mut create = c.clone();
    create.instance_create.nonce = vec![0x0c; 31];
    assert_eq!(statements(&create, &service(), NOW), Err(Unsignable::Nonce));
    let mut register = c.clone();
    if let Some(r) = register.party_register.as_mut() {
        r.nonce = c.challenge.to_vec();
    }
    assert_eq!(
        statements(&register, &service(), NOW),
        Err(Unsignable::RegisterNonce)
    );
    assert_eq!(register_nonce(&[1, 2]), vec![1, 2, 0x01]);
}

// T-103
#[test]
fn t_103_less_than_sixty_seconds_left_is_not_signed() {
    let c = challenge_for(&service(), NOW);
    let last = c.valid_until_ms.checked_sub(MIN_VALIDITY_MS).unwrap();
    assert!(statements(&c, &service(), last).is_ok());
    let late = last.checked_add(1).unwrap();
    assert_eq!(statements(&c, &service(), late), Err(Unsignable::Validity));
    let after = c.valid_until_ms.checked_add(1).unwrap();
    assert_eq!(statements(&c, &service(), after), Err(Unsignable::Validity));
}

// T-103
#[test]
fn t_103_another_kid_basis_or_pep_is_not_signed() {
    let c = challenge_for(&service(), NOW);
    let other = PublicKey::Ed25519([0x22; 32]);
    assert_eq!(statements(&c, &other, NOW), Err(Unsignable::Kid));
    let mut basis = c.clone();
    basis.basis = [0x44; 16];
    assert_eq!(statements(&basis, &service(), NOW), Err(Unsignable::Basis));
    let mut pep = c;
    pep.pep = String::new();
    assert_eq!(statements(&pep, &service(), NOW), Err(Unsignable::Pep));
    assert_eq!(Unsignable::InstanceIntent.code(), "pairing-instance-intent");
}

// T-103
#[test]
fn t_103_a_paired_realm_is_stored_without_signing() {
    let a = Answer::from_json(CHALLENGES.as_bytes(), TENANT).unwrap();
    let paired = answer(vec![a.targets[1].clone()]);
    let plan = plan_challenges(&paired, &service(), NOW);
    assert_eq!(plan.sign.len(), 0);
    assert_eq!(plan.unsignable.len(), 0);
    assert!(matches!(
        plan.changes.as_slice(),
        [RealmChange::Paired { realm: r, domain: None, .. }] if r.as_str() == A2
    ));
    let signable = answer(vec![Target::Unpaired(Box::new(challenge_for(
        &service(),
        NOW,
    )))]);
    let plan = plan_challenges(&signable, &service(), NOW);
    assert_eq!(plan.sign.len(), 1);
    assert!(matches!(
        plan.changes.as_slice(),
        [RealmChange::Unpaired { realm: r, .. }] if r.as_str() == A1
    ));
}

// T-103
#[test]
fn t_103_a_refused_realm_writes_no_automation_record() {
    let refused = answer(vec![Target::Refused {
        realm: realm(A1),
        code: "party-held".to_owned(),
    }]);
    let plan = plan_challenges(&refused, &service(), NOW);
    assert_eq!(plan.sign.len(), 0);
    assert_eq!(plan.refused, vec![(realm(A1), "party-held".to_owned())]);
    assert_eq!(
        plan.changes,
        vec![
            RealmChange::Refused {
                realm: realm(A1),
                code: "party-held".to_owned()
            },
            RealmChange::Failed { realm: realm(A1) },
        ]
    );
    let result = Answer::from_json(
        br#"{"tenant": "tnt_0123456789abcdefghjkmnpqrs", "targets": [{"realm": "019a0000-0000-7000-8000-0000000000a1", "status": "refused", "code": "party-held"}]}"#,
        TENANT,
    )
    .unwrap();
    assert_eq!(plan_result(&result, &[realm(A1)]).refused.len(), 1);
}

// T-103
#[test]
fn t_103_the_result_stores_paired_realms_and_counts_the_rest_as_failed() {
    let result = Answer::from_json(RESULT.as_bytes(), TENANT).unwrap();
    assert_eq!(
        result.event_stream.as_deref(),
        Some("6f1c2a4e-9b0d-4c3e-8a71-2d5f0e9b4c11")
    );
    let plan = plan_result(&result, &[realm(A1), realm(A2)]);
    assert!(matches!(
        plan.changes.as_slice(),
        [RealmChange::Paired { realm: a, .. }, RealmChange::Failed { realm: b }]
            if a.as_str() == A1 && b.as_str() == A2
    ));
    let bad = RESULT.replace("6f1c2a4e-9b0d-4c3e-8a71-2d5f0e9b4c11", "stream");
    assert!(Answer::from_json(bad.as_bytes(), TENANT).is_err());
}

// T-103
#[test]
fn t_103_an_expired_challenge_is_retried_once_with_a_new_one() {
    let refused = |status: u16, code: &str| AccessError::Refused {
        status,
        code: code.to_owned(),
    };
    assert!(retryable(&refused(400, "invalid-challenge")));
    assert!(retryable(&refused(503, "temporarily-unavailable")));
    assert!(retryable(&AccessError::Transport("reset".to_owned())));
    assert!(retryable(&AccessError::Timeout));
    assert!(!retryable(&refused(400, "invalid-party")));
    assert!(!retryable(&refused(401, "client-unauthenticated")));
    assert!(!retryable(&refused(404, "tenant-unknown")));
    assert!(!retryable(&AccessError::Answer("pairing")));
}

// T-103
#[test]
fn t_103_the_pairing_body_carries_every_signed_target() {
    let signed = |r: &str, register: bool| Signed {
        realm: realm(r),
        challenge: [3; 32],
        ais: vec![0xd2, 0x84],
        register_ais: register.then(|| vec![0xd2]),
    };
    let body: serde_json::Value =
        serde_json::from_slice(&pairing_body(&[signed(A1, true), signed(A2, false)]).unwrap())
            .unwrap();
    let targets = body["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["realm"], A1);
    assert_eq!(targets[0]["challenge"], b64url(&[3; 32]));
    assert_eq!(targets[0]["ais"], b64url(&[0xd2, 0x84]));
    assert_eq!(targets[0]["register_ais"], b64url(&[0xd2]));
    assert!(targets[1].get("register_ais").is_none());
    assert!(pairing_body(&[]).is_err());
    let many: Vec<Signed> = (0..=MAX_TARGETS).map(|_| signed(A1, false)).collect();
    assert!(pairing_body(&many).is_err());
}

// T-103
#[test]
fn t_103_a_new_active_tenant_is_paired_on_reconciliation() {
    let kid = thumbprint(&service());
    let live = [realm(A1), realm(A2)];
    assert!(needs_pairing(&live, &[], &kid));
    let paired = |r: &str, kid: [u8; 32]| StoredRealm {
        realm: realm(r),
        state: PairState::Paired,
        kid: Some(kid),
    };
    let both = [paired(A1, kid), paired(A2, kid)];
    assert!(!needs_pairing(&live, &both, &kid));
    assert!(needs_pairing(&live, &[paired(A1, kid)], &kid));
    let rotated = [paired(A1, kid), paired(A2, [1; 32])];
    assert!(needs_pairing(&live, &rotated, &kid));
    let refused = [
        paired(A1, kid),
        StoredRealm {
            realm: realm(A2),
            state: PairState::Refused,
            kid: Some(kid),
        },
    ];
    assert!(needs_pairing(&live, &refused, &kid));
    assert!(!needs_pairing(&[], &[], &kid));
}

// T-103
#[test]
fn t_103_a_realm_that_leaves_the_snapshot_is_retired() {
    let realms = [SnapshotRealm {
        id: realm(A1),
        issuer: "https://shop1.id.example".to_owned(),
        slug: "shop1".to_owned(),
    }];
    assert_eq!(
        snapshot_changes(&realms),
        vec![
            RealmChange::Seen {
                realm: realm(A1),
                issuer: "https://shop1.id.example".to_owned(),
                slug: "shop1".to_owned(),
            },
            RealmChange::Retire {
                live: vec![realm(A1)]
            },
        ]
    );
    assert_eq!(
        snapshot_changes(&[]),
        vec![RealmChange::Retire { live: Vec::new() }]
    );
}

// T-103
#[test]
fn t_103_the_pairing_endpoints_are_read_from_discovery() {
    let e = Endpoints::from_pairs([
        (
            "pairing_challenges",
            "https://access.example/access/v1/tenants/{tenant}/pairing/challenges",
        ),
        (
            "pairing",
            "https://access.example/access/v1/tenants/{tenant}/pairing",
        ),
        (
            "platform_streams",
            "https://access.example/access/v1/platform/streams",
        ),
        (
            "subject_resolution",
            "https://access.example/access/v1/tenants/{tenant}/subjects:resolve",
        ),
        (
            "exercise",
            "https://access.example/access/v1/exercises/{exercise}",
        ),
        (
            "exercise_agency",
            "https://access.example/access/v1/exercises/{exercise}/agency",
        ),
    ])
    .unwrap();
    assert_eq!(
        e.get(Endpoint::PairingChallenges).unwrap().expand(TENANT),
        format!("https://access.example/access/v1/tenants/{TENANT}/pairing/challenges")
    );
    assert_eq!(
        e.get(Endpoint::Pairing).unwrap().expand(TENANT),
        format!("https://access.example/access/v1/tenants/{TENANT}/pairing")
    );
    assert_eq!(
        e.get(Endpoint::PlatformStreams).unwrap().expand(""),
        "https://access.example/access/v1/platform/streams"
    );
    assert!(
        Endpoints::from_pairs([(
            "pairing",
            "https://access.example/access/v1/tenants/pairing"
        )])
        .is_err()
    );
}
