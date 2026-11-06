#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use std::collections::BTreeSet;
use std::future::ready;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use work_proto::id::TenantId;

use super::*;
use crate::domain::b64url;
use crate::domain::discovery::Issuer;
use crate::domain::events::tests::{
    CLIENT, DOMAIN, ISSUER, NOW, RealmKeys, TENANT, claims_of, compromised, keys_in, realm_keys,
    revoked, signed,
};
use crate::domain::events::{CLOUDEVENTS_CONTENT_TYPE, SET_CONTENT_TYPE};
use crate::domain::fixed_b64url;
use crate::domain::keys::tests::domain_named;
use crate::domain::keys::{AsOf, DomainId, verify_answer};
use crate::domain::pairing::{RealmChange, RealmId, StoredRealm};
use crate::domain::streams::StreamStatus;
use crate::ports::{Request, Response, StoredStream};

struct At(u64);

impl Clock for At {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

/// No network: every call to Access fails as an outage would.
struct Offline;

impl Transport for Offline {
    fn send(
        &self,
        _request: Request,
    ) -> impl Future<Output = Result<Response, AccessError>> + Send {
        ready(Err(AccessError::Transport("offline".to_owned())))
    }
}

/// Work's realm table with the tenants paired so far.
#[derive(Default)]
struct Realms(BTreeSet<String>);

impl PairingStore for Realms {
    fn realms(
        &self,
        tenant: &TenantId,
    ) -> impl Future<Output = Result<Vec<StoredRealm>, AccessError>> + Send {
        ready(Ok(if self.0.contains(tenant.as_str()) {
            vec![StoredRealm {
                realm: RealmId::parse("019a0000-0000-7000-8000-0000000000a1").unwrap(),
                state: PairState::Paired,
                kid: Some([7; 32]),
            }]
        } else {
            Vec::new()
        }))
    }

    fn apply(
        &self,
        _tenant: &TenantId,
        _change: &RealmChange,
        _at_ms: u64,
    ) -> impl Future<Output = Result<Option<u64>, AccessError>> + Send {
        ready(Ok(None))
    }

    fn stalled(&self, _runs: u64) -> impl Future<Output = Result<u64, AccessError>> + Send {
        ready(Ok(0))
    }

    fn stream(&self) -> impl Future<Output = Result<Option<StoredStream>, AccessError>> + Send {
        ready(Ok(None))
    }

    fn record_stream(
        &self,
        id: Option<&str>,
        status: Option<StreamStatus>,
        _recreated: bool,
        _at_ms: u64,
    ) -> impl Future<Output = Result<StoredStream, AccessError>> + Send {
        ready(Ok(StoredStream {
            id: id.map(str::to_owned),
            status,
            recreated: 0,
        }))
    }
}

/// The deduplication rows, `(tenant, source, id)`.
#[derive(Default)]
struct Seen(Mutex<BTreeSet<(String, String, String)>>);

impl InboundLog for Seen {
    fn note(&self, a: &Arrival<'_>) -> impl Future<Output = Result<bool, AccessError>> + Send {
        ready(Ok(self.0.lock().unwrap().insert((
            a.tenant.as_str().to_owned(),
            a.source.to_owned(),
            a.id.to_owned(),
        ))))
    }
}

/// What the effects were asked to do, in order; the cache and the client are the real ones.
struct Done(Mutex<Vec<String>>, Arc<Client<Offline, At>>);

impl Effects for Done {
    fn pair(&self, tenant: &TenantId) {
        self.0
            .lock()
            .unwrap()
            .push(format!("pair {}", tenant.as_str()));
    }

    fn forget_domain(&self, domain: DomainId) {
        self.1.forget_domain(domain).unwrap();
        self.0
            .lock()
            .unwrap()
            .push(format!("forget {}", domain.text()));
    }

    fn disable_client(&self) {
        self.1.disable().unwrap();
        self.0.lock().unwrap().push("disable".to_owned());
    }

    fn signal(&self, signal: &Signal) {
        self.0.lock().unwrap().push(signal.event().to_owned());
    }
}

struct World {
    keys: RealmKeys,
    client: Arc<Client<Offline, At>>,
    realms: Realms,
    seen: Seen,
    done: Done,
}

impl World {
    fn new(test: &str) -> Self {
        let keys = realm_keys(test);
        let client = Arc::new(Client::new(
            Offline,
            At(NOW),
            Issuer::parse(ISSUER).unwrap(),
            "local",
            NOW + 86_400_000,
        ));
        client.put_event_keys(keys.set.clone(), NOW);
        Self {
            keys,
            done: Done(Mutex::new(Vec::new()), Arc::clone(&client)),
            client,
            realms: Realms(BTreeSet::from([TENANT.to_owned()])),
            seen: Seen::default(),
        }
    }

    async fn push(&self, content_type: &str, body: &[u8]) -> Outcome {
        Intake {
            client: self.client.as_ref(),
            client_id: CLIENT,
            realms: &self.realms,
            log: &self.seen,
            effects: &self.done,
        }
        .receive(Some(content_type), body)
        .await
    }

    fn set(&self, name: &str, payload: &Value, tenant: Option<&str>, jti: u8) -> Vec<u8> {
        signed(
            &self.keys.es256,
            "ES256",
            &claims_of(name, payload, tenant, jti),
        )
    }

    fn done(&self) -> Vec<String> {
        self.done.0.lock().unwrap().clone()
    }
}

fn forget() -> String {
    format!("forget {}", DomainId(fixed_b64url(DOMAIN).unwrap()).text())
}

// T-102
#[tokio::test]
async fn t_102_a_repeated_jti_is_accepted_once() {
    let w = World::new("t102-repeat");
    let set = w.set("authority-revoked", &revoked(), Some(TENANT), 1);
    let first = w.push(SET_CONTENT_TYPE, &set).await;
    assert!(matches!(first, Outcome::Accepted { .. }), "{first:?}");
    assert_eq!(first.status(), 202);
    let again = w.push(SET_CONTENT_TYPE, &set).await;
    assert!(matches!(again, Outcome::Repeat { .. }), "{again:?}");
    assert_eq!((again.status(), again.body()), (202, Vec::new()));
    assert_eq!(w.done(), vec![forget()]);
    let other = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("authority-revoked", &revoked(), Some(TENANT), 2),
        )
        .await;
    assert!(matches!(other, Outcome::Accepted { .. }));
    assert_eq!(w.seen.0.lock().unwrap().len(), 2);
}

// T-102
#[tokio::test]
async fn t_102_a_revocation_drops_the_cache_at_once() {
    let w = World::new("t102-revoke");
    let d = domain_named(&w.keys.store, "revoke-");
    let sign1 = d.answer(vec![d.entry("active", false)], &[], 3);
    let answer = verify_answer(
        &d.read(),
        &d.id,
        &[d.kid()],
        &sign1,
        &d.excerpt("key-lookup"),
        Some(3),
    )
    .unwrap();
    let payload = |name: &str| {
        let mut p = revoked();
        p["domain"] = json!(b64url(&d.id.0));
        if name == "instance-terminated" {
            p["subject"] = json!({"kind": "instance", "id": "BAQEBAQEBAQEBAQEBAQEBA"});
        }
        p
    };
    for (n, name) in [
        "instance-terminated",
        "authority-revoked",
        "mandate-ended",
        "revalidation-required",
    ]
    .into_iter()
    .enumerate()
    {
        w.client.put_key(&answer, &AsOf::Head, NOW);
        assert_eq!(w.client.cached_keys().unwrap(), 1, "{name}");
        let jti = u8::try_from(n).unwrap() + 10;
        let pushed = w
            .push(
                SET_CONTENT_TYPE,
                &w.set(name, &payload(name), Some(TENANT), jti),
            )
            .await;
        assert!(
            matches!(pushed, Outcome::Accepted { .. }),
            "{name}: {pushed:?}"
        );
        let asked = w.done();
        assert_eq!(
            asked.last(),
            Some(&format!("forget {}", d.id.text())),
            "{name}"
        );
        assert_eq!(w.client.cached_keys().unwrap(), 0, "{name}");
    }
    w.client.put_key(&answer, &AsOf::Head, NOW);
    w.client
        .forget_domain(DomainId(fixed_b64url(DOMAIN).unwrap()))
        .unwrap();
    assert_eq!(w.client.cached_keys().unwrap(), 1);
}

// T-102
#[tokio::test]
async fn t_102_a_compromise_without_window_from_marks_nothing() {
    let w = World::new("t102-compromise");
    let bare = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("party.compromised", &compromised(None), Some(TENANT), 4),
        )
        .await;
    assert!(matches!(bare, Outcome::Accepted { .. }), "{bare:?}");
    assert_eq!(w.done(), vec!["access.compromise_unprocessed".to_owned()]);
    let windowed = w
        .push(
            SET_CONTENT_TYPE,
            &w.set(
                "party.compromised",
                &compromised(Some(NOW - 1000)),
                Some(TENANT),
                5,
            ),
        )
        .await;
    assert!(matches!(windowed, Outcome::Accepted { .. }));
    assert_eq!(
        w.done(),
        vec![
            "access.compromise_unprocessed".to_owned(),
            forget(),
            "access.party_compromised".to_owned(),
        ]
    );
}

// T-102
#[tokio::test]
async fn t_102_an_unpaired_tenant_is_only_logged_and_tenant_created_pairs() {
    let w = World::new("t102-unpaired");
    let stranger = "tnt_zzzzzzzzzzzzzzzzzzzzzzzzzz";
    let unpaired = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("authority-revoked", &revoked(), Some(stranger), 6),
        )
        .await;
    assert!(matches!(unpaired, Outcome::Unpaired { .. }), "{unpaired:?}");
    assert_eq!(unpaired.status(), 202);
    assert!(w.seen.0.lock().unwrap().is_empty());
    assert_eq!(w.done(), Vec::<String>::new());
    let created = json!({"tenant": stranger, "placement": "pool-default", "at": NOW});
    let pushed = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("tenant.created", &created, Some(stranger), 7),
        )
        .await;
    assert!(matches!(pushed, Outcome::Accepted { .. }), "{pushed:?}");
    assert_eq!(w.done(), vec![format!("pair {stranger}")]);
}

// T-102
#[tokio::test]
async fn t_102_only_works_own_disabled_client_fails_closed() {
    let w = World::new("t102-client");
    let client = |id: &str| json!({"tenant": TENANT, "realm": "019a0000-0000-7000-8000-0000000000a1", "client_id": id, "exercise": DOMAIN, "at": NOW});
    for (n, (name, id)) in [
        ("api_client.created", CLIENT),
        ("api_client.disabled", "cli_other"),
        ("api_client.updated", CLIENT),
        ("api_client.disabled", CLIENT),
    ]
    .into_iter()
    .enumerate()
    {
        let jti = u8::try_from(n).unwrap() + 40;
        let pushed = w
            .push(SET_CONTENT_TYPE, &w.set(name, &client(id), None, jti))
            .await;
        assert!(
            matches!(pushed, Outcome::Accepted { .. }),
            "{name} {id}: {pushed:?}"
        );
    }
    assert_eq!(
        w.done(),
        vec![
            "access.client_updated".to_owned(),
            "disable".to_owned(),
            "access.client_disabled".to_owned(),
        ]
    );
    assert_eq!(w.client.consequential(), Err(AccessError::Disabled));
}

// T-102
#[tokio::test]
async fn t_102_organization_and_unknown_types_write_only_the_deduplication_row() {
    let w = World::new("t102-ignored");
    let org = json!({"tenant": TENANT, "organization": "org_1", "at": NOW});
    for (n, name) in ["organization.updated", "verification"]
        .into_iter()
        .enumerate()
    {
        let jti = u8::try_from(n).unwrap() + 50;
        let pushed = w
            .push(SET_CONTENT_TYPE, &w.set(name, &org, Some(TENANT), jti))
            .await;
        assert!(matches!(pushed, Outcome::Accepted { .. }), "{name}");
    }
    assert_eq!(w.done(), Vec::<String>::new());
    assert_eq!(w.seen.0.lock().unwrap().len(), 2);
}

// T-102
#[tokio::test]
async fn t_102_the_answer_follows_rfc_8935_and_relay_is_asked_to_deliver_again() {
    let w = World::new("t102-answer");
    let mut wrong = claims_of("authority-revoked", &revoked(), Some(TENANT), 60);
    wrong["aud"] = json!("cli_other");
    let refused = w
        .push(SET_CONTENT_TYPE, &signed(&w.keys.es256, "ES256", &wrong))
        .await;
    assert_eq!(refused.status(), 400);
    let body: Value = serde_json::from_slice(&refused.body()).unwrap();
    assert_eq!(body["err"], "invalid_audience");
    assert!(body["description"].is_string());
    let set = w.set("authority-revoked", &revoked(), Some(TENANT), 61);
    assert_eq!(w.push("application/json", &set).await, Outcome::Unsupported);
    assert_eq!(w.push("application/json", &set).await.status(), 415);
    let relay = w
        .push(CLOUDEVENTS_CONTENT_TYPE, br#"{"specversion":"1.0"}"#)
        .await;
    assert_eq!((relay.clone(), relay.status()), (Outcome::RelayNotYet, 503));
    let (unknown, _, _) = keys_in(&w.keys.store, "other");
    let c = claims_of("authority-revoked", &revoked(), Some(TENANT), 62);
    let unreadable = w
        .push(SET_CONTENT_TYPE, &signed(&unknown, "ES256", &c))
        .await;
    assert!(
        matches!(unreadable, Outcome::Unavailable(_)),
        "{unreadable:?}"
    );
    assert_eq!(unreadable.status(), 503);
    assert!(w.seen.0.lock().unwrap().is_empty());
}
