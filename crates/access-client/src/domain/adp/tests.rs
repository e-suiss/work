use serde_json::json;
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};

use super::*;

const LEDGER: &str = "led_0101010101010101010101010101010101010101010101010101010101010101";
const PEP: &str = "x5t-of-work-s-pep";
const NOW: u64 = 1_767_225_600_000;
const FROM: u64 = 1_767_225_540_000;
const UNTIL: u64 = 1_767_226_200_000;
const EXPIRES: u64 = 1_767_229_200_000;

fn action() -> Action {
    Action {
        namespace: "work".to_owned(),
        name: "commit".to_owned(),
        major: 1,
        schema: [9; 32],
    }
}

fn intent() -> Vec<u8> {
    commit_intent(&action(), LEDGER, &[7; 32], FROM, UNTIL).unwrap()
}

fn holding() -> Holding {
    Holding {
        grant: KernelId([1; 16]),
        holder: KernelId([2; 16]),
        since: 4,
    }
}

const DOMAIN: DomainId = DomainId([3; 32]);
const NONCE: [u8; 16] = [5; 16];

fn statement(digest: &[u8; 32]) -> Statement<'_> {
    Statement {
        domain: &DOMAIN,
        nonce: &NONCE,
        intent: digest,
        pep: PEP,
        capacity: Capacity::Own,
        basis: holding(),
    }
}

fn sign1(payload: &[u8]) -> Vec<u8> {
    let protected = dcbor::encode(
        &Cbor::Map(vec![(Cbor::Unsigned(1), Cbor::int(-19))]),
        Limits::CEILING,
    )
    .unwrap();
    let message = Cbor::Tag(
        18,
        Box::new(Cbor::Array(vec![
            Cbor::Bytes(protected),
            Cbor::Map(Vec::new()),
            Cbor::Bytes(payload.to_vec()),
            Cbor::Bytes(vec![0; 64]),
        ])),
    );
    dcbor::encode(&message, Limits::CEILING).unwrap()
}

// T-101 E-45
#[test]
fn t_101_work_builds_the_canonical_commit_intent_of_a_ledger_and_its_adp_form() {
    let bytes = intent();
    let digest = intent_digest_of(&bytes).unwrap();
    assert_eq!(intent(), bytes);
    assert_ne!(
        intent_digest_of(
            &commit_intent(&action(), LEDGER, &[8; 32], FROM, UNTIL).unwrap()
        )
        .unwrap(),
        digest
    );
    assert_eq!(
        intent_json(&bytes).unwrap(),
        json!({
            "action": {"namespace": "work", "name": "commit", "major": 1, "schema": b64url(&[9; 32])},
            "resources": [{"namespace": "work.ledger", "path": [LEDGER]}],
            "params": {
                "declaration": {"eq": {"bytes": b64url(&[7; 32])}},
                "ledger": {"eq": LEDGER},
            },
            "validity": {"from": FROM, "until": UNTIL},
        })
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(intent_json(&trailing), Err(AccessError::Answer("intent")));
    assert_eq!(intent_digest_of(b"x"), Err(AccessError::Answer("intent")));
    assert_eq!(
        commit_intent(&action(), LEDGER, &[7; 32], UNTIL, FROM),
        Err(AccessError::Answer("intent"))
    );
}

// T-101 E-7 P-116
#[test]
fn t_101_work_s_pep_commits_only_the_statement_the_actor_s_device_signed() {
    let digest = intent_digest_of(&intent()).unwrap();
    let s = statement(&digest);
    let ais = sign1(&s.to_sign(NOW).unwrap());
    assert_eq!(s.check(&ais, NOW.saturating_add(1_000)), Ok(()));
    assert_eq!(
        s.check(&ais, NOW.saturating_add(61_000)),
        Err(AccessError::Answer("ais-time"))
    );
    let other_pep = Statement {
        pep: "another-pep",
        ..statement(&digest)
    };
    assert_eq!(
        other_pep.check(&ais, NOW),
        Err(AccessError::Answer("ais-mismatch"))
    );
    let other_intent = [0xee; 32];
    assert_eq!(
        statement(&other_intent).check(&ais, NOW),
        Err(AccessError::Answer("ais-mismatch"))
    );
    let principal = Statement {
        capacity: Capacity::For(KernelId([6; 16])),
        ..statement(&digest)
    };
    assert_eq!(
        principal.check(&ais, NOW),
        Err(AccessError::Answer("ais-mismatch"))
    );
    assert_eq!(
        s.check(&sign1(b"not a statement"), NOW),
        Err(AccessError::Answer("ais"))
    );
    assert_eq!(s.check(b"x", NOW), Err(AccessError::Answer("ais")));
}

// T-101 E-17
#[test]
fn t_101_the_evaluation_names_the_caller_the_intent_and_the_approvals_it_relies_on() {
    let bytes = intent();
    let digest = intent_digest_of(&bytes).unwrap();
    let ais = sign1(&statement(&digest).to_sign(NOW).unwrap());
    let contributions = [ExerciseId([0xc1; 32])];
    let e = Evaluation {
        party: "EREREREREREREREREREREQ",
        intent: &bytes,
        statement: statement(&digest),
        ais: &ais,
        contributions: &contributions,
    };
    let body: Value = serde_json::from_slice(&e.body().unwrap()).unwrap();
    assert_eq!(
        body["subject"],
        json!({"type": "access_party", "id": "EREREREREREREREREREREQ"})
    );
    assert_eq!(body["action"], json!({"name": "commit"}));
    assert_eq!(body["resource"], json!({"type": "work.ledger", "id": LEDGER}));
    let c = &body["context"];
    assert_eq!(c["mode"], "commit");
    assert_eq!(c["domain"], b64url(&[3; 32]));
    assert_eq!(c["nonce"], b64url(&NONCE));
    assert_eq!(c["intent"], intent_json(&bytes).unwrap());
    assert_eq!(c["basis"], holding().json());
    assert_eq!(c["capacity"], "own");
    assert_eq!(c["ais"], b64url(&ais));
    assert_eq!(
        c["proofs"],
        json!([{"contribution": ExerciseId([0xc1; 32]).text()}])
    );
    let first = Evaluation {
        contributions: &[],
        ..e
    };
    let body: Value = serde_json::from_slice(&first.body().unwrap()).unwrap();
    assert!(body["context"].get("proofs").is_none());
    assert_eq!(
        holding_from_json(&holding().json()).unwrap(),
        holding()
    );
    assert!(holding_from_json(&json!({"anchor": "x"})).is_err());
}

// T-101 E-17 P-13
#[test]
fn t_101_access_s_decision_reads_as_allow_deny_or_require_action() {
    let exercise = ExerciseId([0xe1; 32]);
    let allow = json!({"decision": true, "context": {
        "outcome": "allow",
        "exercise": exercise.text(),
        "receipt": {"sign1": b64url(b"s"), "excerpt": b64url(b"e")},
    }});
    assert_eq!(
        Decision::from_json(allow.to_string().as_bytes()),
        Ok(Decision::Allow {
            exercise,
            receipt: Some((b"s".to_vec(), b"e".to_vec())),
        })
    );
    let unsigned = json!({"decision": true, "context": {"outcome": "allow", "exercise": exercise.text()}});
    assert_eq!(
        Decision::from_json(unsigned.to_string().as_bytes()),
        Ok(Decision::Allow {
            exercise,
            receipt: None
        })
    );
    let blocker = json!({"class": "no-covering-authority", "resolver": "root", "remediation": "route-to-coordinator"});
    let deny = json!({"decision": false, "context": {"outcome": "deny", "blockers": [blocker]}});
    let Ok(Decision::Deny { blockers }) = Decision::from_json(deny.to_string().as_bytes()) else {
        panic!("a denial");
    };
    assert_eq!(denial_code(&blockers), "no-covering-authority");
    assert_eq!(denial_code(&[json!({"class": "made-up"})]), "denied");
    assert_eq!(denial_code(&[]), "denied");
    let term = json!({"proof_kind": "contribution", "class": "approve", "count": 1});
    let ask = json!({"decision": false, "context": {"outcome": "require_action", "unmet": [
        {"term": term, "missing": 1, "satisfiable_by_actor": false},
    ]}});
    let Ok(Decision::RequireAction { unmet, blockers }) =
        Decision::from_json(ask.to_string().as_bytes())
    else {
        panic!("a require_action");
    };
    assert!(needs_approval(&unmet));
    assert!(step_up(&unmet).is_empty());
    assert!(blockers.is_empty());
    for bad in [
        json!({"decision": true, "context": {"outcome": "deny"}}),
        json!({"decision": false, "context": {"outcome": "allow", "exercise": exercise.text()}}),
        json!({"decision": true, "context": {"outcome": "allow"}}),
        json!({"decision": true}),
        json!({"context": {"outcome": "allow"}}),
    ] {
        assert_eq!(
            Decision::from_json(bad.to_string().as_bytes()),
            Err(AccessError::Answer("decision")),
            "{bad}"
        );
    }
}

// P-116 E-7 T-101
#[test]
fn p_116_a_step_up_is_the_authentication_terms_access_names_and_work_adds_none() {
    let aal2 = json!({"term": {"proof_kind": "authentication", "class": "step_up", "count": 1, "assurance": {"aal": 2}}, "missing": 1, "satisfiable_by_actor": true});
    let approve = json!({"term": {"proof_kind": "contribution", "class": "approve", "count": 1}, "missing": 1, "satisfiable_by_actor": false});
    let unmet = vec![approve.clone(), aal2.clone()];
    assert_eq!(step_up(&unmet), vec![aal2.clone()]);
    assert!(needs_approval(&unmet));
    assert!(!needs_approval(&[aal2]));
    assert!(step_up(&[approve]).is_empty());
}

// E-17 T-101
#[test]
fn e_17_the_typed_authority_request_answers_the_require_action_it_was_built_for() {
    let bytes = intent();
    let digest = intent_digest_of(&bytes).unwrap();
    let r = AuthorityRequest {
        party: "EREREREREREREREREREREQ",
        intent: &bytes,
        statement: statement(&digest),
        reason: "Commit into the ledger",
        expires_at_ms: EXPIRES,
    };
    let json = intent_json(&bytes).unwrap();
    assert_eq!(
        r.json().unwrap(),
        json!({
            "requester": {"party": "EREREREREREREREREREREQ"},
            "action": json["action"],
            "resource": json["resources"][0],
            "params": json["params"],
            "capacity": "own",
            "reason": "Commit into the ledger",
            "require_action": {
                "domain": b64url(&[3; 32]),
                "nonce": b64url(&NONCE),
                "intent": b64url(&digest),
            },
            "expires_at": EXPIRES,
        })
    );
    for reason in ["", "a\nb"] {
        let bad = AuthorityRequest {
            reason,
            ..r.clone()
        };
        assert_eq!(bad.json(), Err(AccessError::Answer("reason")));
    }
    let long = "x".repeat(MAX_REASON.saturating_add(1));
    assert!(!valid_reason(&long));
    assert!(valid_reason(&"x".repeat(MAX_REASON)));
    assert_eq!(
        capacity_json(Capacity::For(KernelId([6; 16]))),
        json!({"for": KernelId([6; 16]).text()})
    );
}
