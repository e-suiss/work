#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use std::collections::{BTreeMap, BTreeSet};
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
use crate::domain::organizations::{AccessPosition, OrganizationId};
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

/// Work's realm table with the tenants paired so far, and its organization map.
#[derive(Default)]
struct Realms(
    BTreeSet<String>,
    Mutex<BTreeMap<(String, OrganizationId), Option<AccessPosition>>>,
    Mutex<bool>,
);

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

    fn organizations(
        &self,
        tenant: &TenantId,
    ) -> impl Future<Output = Result<Vec<OrganizationId>, AccessError>> + Send {
        ready(Ok(self
            .1
            .lock()
            .unwrap()
            .keys()
            .filter(|(t, _)| t == tenant.as_str())
            .map(|(_, o)| o.clone())
            .collect()))
    }

    fn map_organization(
        &self,
        tenant: &TenantId,
        change: &OrganizationChange,
        _at_ms: u64,
    ) -> impl Future<Output = Result<OrganizationOutcome, AccessError>> + Send {
        if *self.2.lock().unwrap() {
            return ready(Err(AccessError::Transport("store".to_owned())));
        }
        let key = (tenant.as_str().to_owned(), change.organization().clone());
        let mut map = self.1.lock().unwrap();
        let at = match change {
            OrganizationChange::Listed { .. } => None,
            OrganizationChange::Event { position, .. } => Some(*position),
        };
        ready(Ok(match map.get(&key).copied() {
            None => {
                map.insert(key, at);
                OrganizationOutcome::Mapped
            }
            Some(before) if at.is_some() && before < at => {
                map.insert(key, at);
                OrganizationOutcome::Moved
            }
            Some(_) => OrganizationOutcome::Known,
        }))
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

    fn disable_party(&self, tenant: &TenantId, party: [u8; 16]) {
        self.1.disable_party(tenant, party).unwrap();
        self.0
            .lock()
            .unwrap()
            .push(format!("disable party {}", b64url(&party)));
    }

    fn disable_client(&self) {
        self.1.disable().unwrap();
        self.0.lock().unwrap().push("disable".to_owned());
    }

    fn signal(&self, signal: &Signal) {
        self.0.lock().unwrap().push(signal.event().to_owned());
    }

    fn compromised(&self, compromise: &Compromise) {
        self.0.lock().unwrap().push(format!(
            "notice {} {} {}",
            compromise.jti,
            compromise.instances.len(),
            compromise.source.as_deref().unwrap_or_default()
        ));
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
            realms: Realms(
                BTreeSet::from([TENANT.to_owned()]),
                Mutex::default(),
                Mutex::new(false),
            ),
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
    let Outcome::Accepted { jti, .. } = windowed else {
        panic!("{windowed:?}");
    };
    assert_eq!(
        w.done(),
        vec![
            "access.compromise_unprocessed".to_owned(),
            forget(),
            "access.party_compromised".to_owned(),
            format!("notice {jti} 1 CAgICAgICAgICAgICAgICA"),
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
            .push(
                SET_CONTENT_TYPE,
                &w.set(name, &client(id), Some(TENANT), jti),
            )
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

// T-102 T-28
#[tokio::test]
async fn t_102_a_disabled_party_loses_its_cache_and_is_refused_as_a_caller() {
    let w = World::new("t102-party-disabled");
    let tenant = TenantId::new(TENANT).unwrap();
    let party = b64url(&[2; 16]);
    assert!(!w.client.party_disabled(&tenant, &[2; 16]));
    let named = json!({"domain": DOMAIN, "source": {"exercise": DOMAIN}, "party": party, "at": NOW, "reason_class": "departed", "access_position": {"pos": 7, "idx": 0}});
    let first = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("party.disabled", &named, Some(TENANT), 90),
        )
        .await;
    assert!(matches!(first, Outcome::Accepted { .. }), "{first:?}");
    assert_eq!(
        w.done(),
        vec![
            forget(),
            format!("disable party {party}"),
            "access.party_disabled".to_owned()
        ]
    );
    assert!(w.client.party_disabled(&tenant, &[2; 16]));
    assert!(!w.client.party_disabled(&tenant, &[3; 16]));
    assert!(
        !w.client
            .party_disabled(&TenantId::new("tnt_other").unwrap(), &[2; 16])
    );
    let bare = json!({"party": b64url(&[3; 16]), "at": NOW, "reason_class": "suspended", "access_position": {"pos": 8, "idx": 0}});
    let second = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("party.disabled", &bare, Some(TENANT), 91),
        )
        .await;
    assert!(matches!(second, Outcome::Accepted { .. }), "{second:?}");
    assert_eq!(w.done().len(), 5);
    assert!(w.client.party_disabled(&tenant, &[3; 16]));
    let malformed = json!({"party": "not-a-party", "at": NOW, "reason_class": "other"});
    let refused = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("party.disabled", &malformed, Some(TENANT), 92),
        )
        .await;
    assert_eq!(refused, Outcome::Refused(Refusal::InvalidRequest("party")));
}

// T-102
#[tokio::test]
async fn t_102_an_unknown_type_writes_only_the_deduplication_row() {
    let w = World::new("t102-ignored");
    let member = json!({"realm": "019a0000-0000-7000-8000-0000000000a1", "account": "usr_1", "organization": ORG, "at": NOW});
    for (n, name) in ["membership.added", "verification"].into_iter().enumerate() {
        let jti = u8::try_from(n).unwrap() + 50;
        let pushed = w
            .push(SET_CONTENT_TYPE, &w.set(name, &member, Some(TENANT), jti))
            .await;
        assert!(matches!(pushed, Outcome::Accepted { .. }), "{name}");
    }
    assert_eq!(w.done(), Vec::<String>::new());
    assert_eq!(w.seen.0.lock().unwrap().len(), 2);
    assert!(w.realms.1.lock().unwrap().is_empty());
}

const ORG: &str = "019a0000-0000-7000-8000-0000000000b1";

fn organization(pos: u64) -> Value {
    json!({"tenant": TENANT, "organization": ORG, "at": NOW, "access_position": {"pos": pos, "idx": 0}})
}

// E-3 T-102
#[tokio::test]
async fn e_3_an_organization_event_maps_the_organization_and_a_later_one_moves_it() {
    let w = World::new("e3-organization");
    let created = w.set("organization.created", &organization(42), Some(TENANT), 70);
    let first = w.push(SET_CONTENT_TYPE, &created).await;
    assert!(matches!(first, Outcome::Accepted { .. }), "{first:?}");
    let again = w.push(SET_CONTENT_TYPE, &created).await;
    assert!(matches!(again, Outcome::Repeat { .. }), "{again:?}");
    let updated = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("organization.updated", &organization(43), Some(TENANT), 71),
        )
        .await;
    assert!(matches!(updated, Outcome::Accepted { .. }), "{updated:?}");
    let late = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("organization.updated", &organization(41), Some(TENANT), 72),
        )
        .await;
    assert!(matches!(late, Outcome::Accepted { .. }), "{late:?}");
    assert_eq!(
        w.done(),
        vec![
            "access.organization_mapped".to_owned(),
            "access.organization_changed".to_owned()
        ]
    );
    let tenant = TenantId::new(TENANT).unwrap();
    let mapped = w.realms.organizations(&tenant).await.unwrap();
    assert_eq!(
        mapped
            .iter()
            .map(OrganizationId::as_str)
            .collect::<Vec<_>>(),
        [ORG]
    );
    assert_eq!(
        w.realms
            .1
            .lock()
            .unwrap()
            .values()
            .copied()
            .collect::<Vec<_>>(),
        [Some(AccessPosition { pos: 43, idx: 0 })]
    );
}

// E-3 T-102
#[tokio::test]
async fn e_3_an_organization_event_the_store_cannot_take_is_asked_again() {
    let w = World::new("e3-organization-outage");
    let created = w.set("organization.created", &organization(42), Some(TENANT), 73);
    *w.realms.2.lock().unwrap() = true;
    let down = w.push(SET_CONTENT_TYPE, &created).await;
    assert!(matches!(down, Outcome::Unavailable(_)), "{down:?}");
    assert_eq!(down.status(), 503);
    assert!(w.seen.0.lock().unwrap().is_empty());
    *w.realms.2.lock().unwrap() = false;
    let back = w.push(SET_CONTENT_TYPE, &created).await;
    assert!(matches!(back, Outcome::Accepted { .. }), "{back:?}");
    assert_eq!(w.done(), vec!["access.organization_mapped".to_owned()]);
    let elsewhere = w
        .push(
            SET_CONTENT_TYPE,
            &w.set(
                "organization.created",
                &organization(44),
                Some("tnt_other"),
                74,
            ),
        )
        .await;
    assert_eq!(
        elsewhere,
        Outcome::Refused(Refusal::InvalidRequest("tenant"))
    );
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

// E-3 T-96
#[tokio::test]
async fn e_3_the_reconciliation_maps_the_organizations_the_snapshot_lists() {
    use crate::app::platform::{Report, Signal as Step, organization_step};
    use crate::domain::tenants::TenantSnapshot;

    const OTHER: &str = "019a0000-0000-7000-8000-0000000000b2";
    let w = World::new("e3-reconciliation");
    let tenant = TenantId::new(TENANT).unwrap();
    let snapshot = |organizations: &[&str]| {
        TenantSnapshot::from_json(
            json!({"tenant": TENANT, "organizations": organizations, "realms": [], "region": "local", "status": "active", "version": "v1", "retention": {}})
                .to_string()
                .as_bytes(),
        )
        .unwrap()
    };
    let mut report = Report::default();
    organization_step(&w.realms, &snapshot(&[]), NOW, &mut report)
        .await
        .unwrap();
    assert_eq!(report, Report::default());
    organization_step(&w.realms, &snapshot(&[ORG, OTHER]), NOW, &mut report)
        .await
        .unwrap();
    assert_eq!(report.organizations, 2);
    assert_eq!(
        report.signals,
        [ORG, OTHER].map(|o| Step::OrganizationMapped {
            tenant: tenant.clone(),
            organization: OrganizationId::parse(o).unwrap(),
        })
    );
    let mut again = Report::default();
    organization_step(&w.realms, &snapshot(&[ORG, OTHER]), NOW, &mut again)
        .await
        .unwrap();
    assert_eq!(again, Report::default());
    let pushed = w
        .push(
            SET_CONTENT_TYPE,
            &w.set("organization.updated", &organization(50), Some(TENANT), 75),
        )
        .await;
    assert!(matches!(pushed, Outcome::Accepted { .. }), "{pushed:?}");
    assert_eq!(w.done(), vec!["access.organization_changed".to_owned()]);
    let mut dropped = Report::default();
    organization_step(&w.realms, &snapshot(&[ORG]), NOW, &mut dropped)
        .await
        .unwrap();
    assert_eq!(
        dropped.signals,
        [Step::OrganizationUnlisted {
            tenant: tenant.clone(),
            organization: OrganizationId::parse(OTHER).unwrap(),
        }]
    );
    let mut empty = Report::default();
    organization_step(&w.realms, &snapshot(&[]), NOW, &mut empty)
        .await
        .unwrap();
    assert_eq!(empty, Report::default());
    assert_eq!(w.realms.organizations(&tenant).await.unwrap().len(), 2);
}
