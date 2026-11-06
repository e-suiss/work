use std::collections::BTreeMap;

use access_kernel::intent::ContextRefs;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::receipt::AgencyLink as AccessLink;
use serde_json::json;
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::digest::context_digest;

use super::*;
use crate::domain::keys::tests::{Domain, IAT, domain, token};

const AUDIENCE: &str = "cli_work";
const LEDGER: &str = "led_0101";
const EXERCISE: ExerciseId = ExerciseId([0xe1; 32]);

type Edit = Box<dyn Fn(&mut Receipt)>;

fn envelope(action: &str, from: u64, until: u64) -> Vec<u8> {
    IntentEnvelope {
        action: ActionRef {
            namespace: "work".to_owned(),
            name: action.to_owned(),
            major: 1,
            schema: Digest([9; 32]),
        },
        resources: vec![ResourceRef {
            namespace: "work.ledger".to_owned(),
            path: vec![LEDGER.to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window { from, until },
    }
    .to_bytes()
    .unwrap()
}

fn intent() -> Intent {
    Intent::from_bytes(&envelope(
        "commit",
        IAT.saturating_sub(1000),
        IAT.saturating_add(1000),
    ))
    .unwrap()
}

fn receipt(d: &Domain, intent: &Intent, edit: impl FnOnce(&mut Receipt)) -> Vec<u8> {
    let mut r = Receipt {
        domain: Digest(d.id.0),
        exercise: Digest(EXERCISE.0),
        record: 12,
        intent: Digest(intent.digest),
        instance: Some(Id([3; 16])),
        ais: None,
        capacity: AccessCapacity::Own,
        basis: ExerciseBasis::Public(Id([5; 16])),
        audience: AUDIENCE.to_owned(),
        iat: IAT,
        drawn: false,
        agency: Vec::new(),
    };
    edit(&mut r);
    r.to_bytes().unwrap()
}

fn answer_json(d: &Domain, intent: &Intent, payload: &[u8], excerpt: &[u8]) -> serde_json::Value {
    json!({
        "exercise": EXERCISE.text(),
        "domain": d.id.text(),
        "status": "allowed",
        "position": "12",
        "intent": b64url(&intent.digest),
        "instance": b64url(&[3; 16]),
        "receipt": {
            "payload": b64url(payload),
            "cose_sign1": b64url(&d.sign(receipt::CONTENT_TYPE, payload)),
            "key_excerpt": b64url(excerpt),
        },
    })
}

fn expected<'a>(d: &'a Domain, intent: &'a Intent) -> Expected<'a> {
    Expected {
        exercise: &EXERCISE,
        domain: &d.id,
        intent,
        audience: AUDIENCE,
        now_ms: IAT,
    }
}

fn verify(
    d: &Domain,
    intent: &Intent,
    body: &serde_json::Value,
) -> Result<VerifiedExercise, AccessError> {
    verify_exercise(&d.read(), body.to_string().as_bytes(), &expected(d, intent))
}

// T-101 P-13 E-9
#[test]
fn t_101_an_allowed_exercise_with_its_receipt_is_the_authority_proof() {
    let (_, store) = token("exercise");
    let d = domain(&store);
    let i = intent();
    let payload = receipt(&d, &i, |_| {});
    let body = answer_json(&d, &i, &payload, &d.excerpt("receipt"));
    let got = verify(&d, &i, &body).unwrap();
    assert_eq!(got.exercise, EXERCISE);
    assert_eq!(got.position, 12);
    assert_eq!(got.intent, i.digest);
    assert_eq!(got.instance, Some(KernelId([3; 16])));
    assert_eq!(got.capacity, Capacity::Own);
    assert_eq!(got.agency, Vec::<AgencyLink>::new());
    assert_eq!(got.iat, IAT);
    assert_eq!(got.receipt, d.sign(receipt::CONTENT_TYPE, &payload));
}

// T-101 E-17
#[test]
fn t_101_a_receiptless_exercise_leaves_the_gate_waiting() {
    let (_, store) = token("receiptless");
    let d = domain(&store);
    let i = intent();
    let payload = receipt(&d, &i, |_| {});
    let mut body = answer_json(&d, &i, &payload, &d.excerpt("receipt"));
    body["receipt"]
        .as_object_mut()
        .unwrap()
        .remove("cose_sign1");
    assert_eq!(
        verify(&d, &i, &body),
        Err(AccessError::Answer("receipt-missing"))
    );
    body.as_object_mut().unwrap().remove("receipt");
    assert_eq!(
        verify(&d, &i, &body),
        Err(AccessError::Answer("receipt-missing"))
    );
}

// T-101 P-13
#[test]
fn t_101_an_exercise_for_another_intent_is_refused() {
    let (_, store) = token("other-intent");
    let d = domain(&store);
    let i = intent();
    let other = Intent::from_bytes(&envelope(
        "close",
        IAT.saturating_sub(1000),
        IAT.saturating_add(1000),
    ))
    .unwrap();
    assert_ne!(other.digest, i.digest);
    let payload = receipt(&d, &i, |_| {});
    let body = answer_json(&d, &i, &payload, &d.excerpt("receipt"));
    assert_eq!(
        verify(&d, &other, &body),
        Err(AccessError::Answer("exercise-intent"))
    );
    let signed_for_other = receipt(&d, &i, |r| r.intent = Digest(other.digest));
    let body = answer_json(&d, &i, &signed_for_other, &d.excerpt("receipt"));
    assert_eq!(
        verify(&d, &i, &body),
        Err(AccessError::Answer("receipt-intent"))
    );
}

// T-101 MD-4 E-14
#[test]
fn t_101_a_receipt_is_used_only_for_its_domain_exercise_audience_and_time() {
    let (_, store) = token("receipt-fields");
    let d = domain(&store);
    let i = intent();
    let excerpt = d.excerpt("receipt");
    let cases: [(&str, Edit); 4] = [
        (
            "receipt-domain",
            Box::new(|r: &mut Receipt| r.domain = Digest([7; 32])),
        ),
        (
            "receipt-exercise",
            Box::new(|r: &mut Receipt| r.exercise = Digest([7; 32])),
        ),
        (
            "receipt-audience",
            Box::new(|r: &mut Receipt| r.audience = "cli_other".to_owned()),
        ),
        (
            "receipt-instance",
            Box::new(|r: &mut Receipt| r.instance = Some(Id([4; 16]))),
        ),
    ];
    for (code, edit) in cases {
        let payload = receipt(&d, &i, |r| edit(r));
        let body = answer_json(&d, &i, &payload, &excerpt);
        assert_eq!(
            verify(&d, &i, &body),
            Err(AccessError::Answer(code)),
            "{code}"
        );
    }
    let payload = receipt(&d, &i, |_| {});
    let future = verify_exercise(
        &d.read(),
        answer_json(&d, &i, &payload, &excerpt)
            .to_string()
            .as_bytes(),
        &Expected {
            now_ms: IAT.saturating_sub(SKEW_MS).saturating_sub(1),
            ..expected(&d, &i)
        },
    );
    assert_eq!(future, Err(AccessError::Answer("receipt-future")));
}

// T-101 SEC-31
#[test]
fn t_101_a_receipt_signed_outside_the_receipt_key_or_changed_is_refused() {
    let (_, store) = token("receipt-key");
    let d = domain(&store);
    let i = intent();
    let payload = receipt(&d, &i, |_| {});
    let body = answer_json(&d, &i, &payload, &d.excerpt("key-lookup"));
    assert_eq!(
        verify(&d, &i, &body),
        Err(AccessError::Answer("receipt-key"))
    );
    let mut body = answer_json(&d, &i, &payload, &d.excerpt("receipt"));
    let other = receipt(&d, &i, |r| r.record = 13);
    body["receipt"]["payload"] = json!(b64url(&other));
    assert_eq!(
        verify(&d, &i, &body),
        Err(AccessError::Answer("receipt-payload"))
    );
    let mut body = answer_json(&d, &i, &payload, &d.excerpt("receipt"));
    body["status"] = json!("denied");
    assert_eq!(
        verify(&d, &i, &body),
        Err(AccessError::Answer("exercise-status"))
    );
    let mut body = answer_json(&d, &i, &payload, &d.excerpt("receipt"));
    body["exercise"] = json!(ExerciseId([2; 32]).text());
    assert_eq!(
        verify(&d, &i, &body),
        Err(AccessError::Answer("exercise-mismatch"))
    );
    let mut body = answer_json(&d, &i, &payload, &d.excerpt("receipt"));
    body["extra"] = json!(1);
    assert_eq!(verify(&d, &i, &body), Err(AccessError::Answer("exercise")));
}

// E-13 C-25 SEC-4
#[test]
fn e_13_the_capacity_and_chain_come_from_the_verified_receipt() {
    let (_, store) = token("agency");
    let d = domain(&store);
    let i = intent();
    let link = AccessLink {
        mandate: Id([4; 16]),
        principal: Id([2; 16]),
        agent: Id([6; 16]),
    };
    let payload = receipt(&d, &i, |r| {
        r.capacity = AccessCapacity::For(Id([2; 16]));
        r.agency = vec![link];
    });
    let excerpt = d.excerpt("receipt");
    let body = json!({
        "exercise": EXERCISE.text(),
        "domain": d.id.text(),
        "capacity": {"for": b64url(&[2; 16])},
        "agency": [{
            "mandate": b64url(&[4; 16]),
            "principal": b64url(&[2; 16]),
            "agent": b64url(&[6; 16]),
        }],
        "receipt": {
            "payload": b64url(&payload),
            "cose_sign1": b64url(&d.sign(receipt::CONTENT_TYPE, &payload)),
            "key_excerpt": b64url(&excerpt),
        },
    });
    let m = d.read();
    let got = verify_agency(&m, body.to_string().as_bytes(), &expected(&d, &i)).unwrap();
    assert_eq!(got.capacity, Capacity::For(KernelId([2; 16])));
    assert_eq!(
        got.agency,
        vec![AgencyLink {
            mandate: KernelId([4; 16]),
            principal: KernelId([2; 16]),
            agent: KernelId([6; 16]),
        }]
    );
    let mut own = body.clone();
    own["capacity"] = json!("own");
    assert_eq!(
        verify_agency(&m, own.to_string().as_bytes(), &expected(&d, &i)),
        Err(AccessError::Answer("agency-mismatch"))
    );
    let mut shorter = body;
    shorter["agency"] = json!([]);
    assert_eq!(
        verify_agency(&m, shorter.to_string().as_bytes(), &expected(&d, &i)),
        Err(AccessError::Answer("agency-mismatch"))
    );
}

// T-101 P-13
#[test]
fn t_101_the_intent_digest_is_recomputed_from_the_canonical_envelope() {
    const VECTORS: &str =
        include_str!("../../../../../conformance/vectors/access/intent-digest.json");
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let mut checked = 0_u32;
    for case in vectors["cases"].as_array().unwrap() {
        let (Some(bytes), Some(digest)) = (case["intent"].as_str(), case["digest"].as_str()) else {
            continue;
        };
        let digest = crate::domain::tests::hex(digest);
        let value = dcbor::decode(&digest, Limits::CEILING).unwrap();
        let want = Digest::from_value(&value).unwrap();
        let got = Intent::from_bytes(&crate::domain::tests::hex(bytes)).unwrap();
        assert_eq!(got.digest, want.0, "{}", case["id"]);
        checked = checked.saturating_add(1);
    }
    assert!(checked > 0);
    let i = intent();
    assert!(
        i.valid_at(IAT)
            && !i.valid_at(IAT.saturating_add(1001))
            && !i.valid_at(IAT.saturating_sub(1001))
    );
    assert!(i.names("work.ledger", LEDGER));
    assert!(!i.names("work.work", LEDGER));
    assert_eq!(
        (i.namespace.as_str(), i.action.as_str(), i.major),
        ("work", "commit", 1)
    );
    let mut longer = envelope("commit", IAT, IAT);
    longer.push(0);
    assert_eq!(
        Intent::from_bytes(&longer),
        Err(AccessError::Answer("intent"))
    );
}

// T-101 T-103
#[test]
fn t_101_an_exercise_id_is_the_domain_and_nonce_digest() {
    let domain = DomainId([1; 32]);
    let nonce = [0x2a; 32];
    let value = dcbor::Value::Array(vec![
        Digest(domain.0).to_value(),
        dcbor::Value::Bytes(nonce.to_vec()),
    ]);
    let want = context_digest(
        "access/exercise/v1",
        &dcbor::encode(&value, Limits::CEILING).unwrap(),
    );
    assert_eq!(ExerciseId::of(&domain, &nonce).unwrap(), ExerciseId(want.0));
    let id = ExerciseId([7; 32]);
    assert_eq!(ExerciseId::parse(&id.text()).unwrap(), id);
    assert!(ExerciseId::parse(&b64url(&[7; 16])).is_err());
}
