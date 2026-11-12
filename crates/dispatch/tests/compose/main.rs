//! Work's delivery to the real Relay of the local environment under Work's Access service token (T-99, T-28, MD-3; Access A28 (a), Relay E-93): the platform realm gives Work a `DPoP` token for Relay's Access `client_id`, Relay takes Work's events with their interruption level and links and keeps the item and the correlation id Work sent, keeps a `critical` event only to lower it at send time while Work never sends one, refuses a link that is not `https`, and an intent waits in the outbox while Relay cannot be reached until a later pass delivers it. These tests need `just dev`; `just test-compose` runs them with `WORK_ACCESS_LOCAL` naming the directory `just dev-access` fills with Access's local CA, `bootstrap.json` and a copy of the `work-dev` token, `SOFTHSM2_CONF` naming that copy, and `access-server` and `relay` resolving to the loopback address.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::Signer as _;
use work_access_client::adapters::{
    AccessKeys, DEFAULT_TIMEOUT, HttpsTransport, TokenSigner, public_config, roots,
};
use work_access_client::app::service::{ServiceTokens, Target};
use work_access_client::domain::discovery::Issuer;
use work_access_client::domain::metadata::thumbprint;
use work_access_client::domain::{AccessError, b64url, from_b64url};
use work_access_client::ports::{
    Clock, Method, Random, Request as AccessRequest, Transport as AccessTransport,
};
use work_dispatch::RelayCredential;
use work_proto::id::TenantId;
use work_relay_client::RELAY_VERSION;
use work_relay_client::app::{Deliverer, Relay};
use work_relay_client::domain::answer::RelayError;
use work_relay_client::domain::intent::{
    Class, Committed, IdempotencyKey, NotificationIntent, Spec, hex,
};
use work_relay_client::domain::request::{EventRequest, Installation, RequestError};
use work_relay_client::ports::{
    Credential, Intents, Method as RelayMethod, OutboxError, Outcome, Recipients, Request,
    Response, Settlement, Transport, Unresolvable,
};

const RELAY_EVENTS: &str = "https://relay/v1/events";
const INSTALLATION: &str = "https://work-server:8443";
const TOKEN: &str = "work-dev";
const PIN: &str = "1234";
const TRACE: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const PAIRING_WAIT: Duration = Duration::from_secs(180);

fn module() -> PathBuf {
    std::env::var_os("PKCS11_MODULE").map_or_else(
        || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from,
    )
}

/// What `just dev-access` copied out of the local Access.
struct Local {
    dir: PathBuf,
    bootstrap: Value,
}

impl Local {
    fn open() -> Self {
        let dir = PathBuf::from(
            std::env::var_os("WORK_ACCESS_LOCAL")
                .expect("WORK_ACCESS_LOCAL names the directory `just dev-access` fills"),
        );
        let bootstrap =
            serde_json::from_slice(&std::fs::read(dir.join("bootstrap.json")).unwrap()).unwrap();
        Self { dir, bootstrap }
    }

    fn client_of(&self, product: &str) -> String {
        self.bootstrap["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["product"] == product)
            .unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn realm(&self, slug: &str) -> &Value {
        self.bootstrap["realms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["slug"] == slug)
            .unwrap()
    }

    fn issuer(&self, slug: &str) -> Issuer {
        Issuer::parse(self.realm(slug)["issuer"].as_str().unwrap()).unwrap()
    }

    fn https(&self) -> HttpsTransport {
        let pem = std::fs::read(self.dir.join("ca.crt")).unwrap();
        HttpsTransport::new(
            public_config(roots(&pem).unwrap()).unwrap(),
            DEFAULT_TIMEOUT,
        )
    }
}

/// Unix milliseconds of an RFC 9110 IMF-fixdate such as `Thu, 05 Nov 2026 04:42:06 GMT`.
fn imf_fixdate_ms(date: &str) -> u64 {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: Vec<&str> = date.split([' ', ':']).collect();
    let [_, day, month, year, hour, minute, second, "GMT"] = parts.as_slice() else {
        panic!("{date}");
    };
    let n = |t: &str| t.parse::<i64>().unwrap();
    let month = i64::try_from(MONTHS.iter().position(|m| m == month).unwrap()).unwrap() + 1;
    let y = if month <= 2 { n(year) - 1 } else { n(year) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + n(day) - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    let seconds = days * 86_400 + n(hour) * 3600 + n(minute) * 60 + n(second);
    u64::try_from(seconds).unwrap() * 1000
}

/// Access's time, from the `Date` of its answer at the start, moved on by the test's own clock:
/// what Access and Relay check `iat` against.
struct AccessTime {
    start_ms: u64,
    at: tokio::time::Instant,
}

impl Clock for AccessTime {
    fn now_ms(&self) -> u64 {
        self.start_ms + u64::try_from(self.at.elapsed().as_millis()).unwrap()
    }
}

/// Fresh `jti`s: the hash of a seed only this test run has and a counter.
struct Jti(AtomicU64, [u8; 32]);

impl Random for Jti {
    fn fill(&self, out: &mut [u8]) -> Result<(), AccessError> {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        let d = Sha256::new()
            .chain_update(self.1)
            .chain_update(n.to_be_bytes())
            .finalize();
        for (o, b) in out.iter_mut().zip(d.iter().cycle()) {
            *o = *b;
        }
        Ok(())
    }
}

type Tokens = ServiceTokens<HttpsTransport, AccessTime, Jti, TokenSigner, TokenSigner>;

/// Work's service tokens for Relay from the platform realm, with the keys of the token copy, and
/// the run's seed and the RFC 7638 thumbprint of the `DPoP` key.
async fn tokens(local: &Local, test: &str) -> (Tokens, [u8; 32], String) {
    let https = local.https();
    let issuer = local.issuer("platform");
    let answer = https
        .send(AccessRequest::get(
            format!("{}/.well-known/openid-configuration", issuer.as_str()),
            "application/json",
        ))
        .await
        .unwrap();
    let start_ms = imf_fixdate_ms(answer.header("date").unwrap());
    let seed: [u8; 32] = Sha256::new()
        .chain_update(start_ms.to_be_bytes())
        .chain_update(test.as_bytes())
        .finalize()
        .into();
    let keys = AccessKeys::load(&module(), TOKEN, &Secret::new(PIN.to_owned())).unwrap();
    let jkt = b64url(&thumbprint(&keys.dpop.public_key()));
    let tokens = ServiceTokens::new(
        https,
        AccessTime {
            start_ms,
            at: tokio::time::Instant::now(),
        },
        Jti(AtomicU64::new(0), seed),
        keys.client,
        keys.dpop,
        Target {
            client_id: local.client_of("work"),
            issuer,
            resource: local.client_of("relay"),
        },
    );
    (tokens, seed, jkt)
}

/// The token, once work-server's pairing gave Work its service Party in the platform realm.
async fn paired(tokens: &Tokens) -> String {
    let until = tokio::time::Instant::now() + PAIRING_WAIT;
    loop {
        match tokens.token().await {
            Ok(t) => return t.expose().to_owned(),
            Err(AccessError::Refused { code, .. })
                if code == "unauthorized_client" && tokio::time::Instant::now() < until =>
            {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => panic!("no service token for Relay: {e}"),
        }
    }
}

/// HTTPS to the local Relay; once cut, every call goes to a closed port of the loopback
/// address instead, as a Relay that is down.
struct RelayHttps {
    inner: HttpsTransport,
    cut: Arc<AtomicBool>,
}

impl Transport for &RelayHttps {
    async fn send(&self, request: Request) -> Result<Response, RelayError> {
        let method = match request.method {
            RelayMethod::Get => Method::Get,
            RelayMethod::Post => Method::Post,
            RelayMethod::Put => return Err(RelayError::Unreachable("PUT".to_owned())),
        };
        let url = if self.cut.load(Ordering::SeqCst) {
            request
                .url
                .replacen("https://relay", "https://127.0.0.1:1", 1)
        } else {
            request.url
        };
        let answer = self
            .inner
            .send(AccessRequest {
                method,
                url,
                headers: request.headers,
                body: request.body,
            })
            .await
            .map_err(|e| RelayError::Unreachable(e.to_string()))?;
        Ok(Response {
            status: answer.status,
            headers: answer.headers,
            body: answer.body,
        })
    }
}

fn relay_https(local: &Local) -> RelayHttps {
    RelayHttps {
        inner: local.https(),
        cut: Arc::default(),
    }
}

fn intent(seed: &[u8; 32], pos: u64, class: Class, approval: Option<String>) -> NotificationIntent {
    NotificationIntent::new(
        Committed {
            ledger: *seed,
            pos,
            record_id: [4; 32],
            recorded_at_ms: 1_793_000_000_000,
            traceparent: TRACE.to_owned(),
        },
        Spec {
            reason: "gate_waiting".to_owned(),
            class,
            item: format!("cnd_{}", hex(seed)),
            tenant: TenantId::new("tnt_local").unwrap(),
            realm: "acme".to_owned(),
            parties: vec!["AAECAwQFBgcICQoLDA0ODw".to_owned()],
            approval,
        },
    )
    .unwrap()
}

fn sub(seed: &[u8; 32]) -> String {
    format!("sub-{}", hex(&seed[..8]))
}

/// One raw `POST /v1/events` under Work's credential, for bodies Work itself never builds.
async fn post_raw(https: &RelayHttps, credential: &impl Credential, body: &Value) -> Response {
    let auth = credential.authorize("POST", RELAY_EVENTS).await.unwrap();
    let key = format!("wrk-test-{}", hex(&Sha256::digest(body.to_string())));
    let headers = [
        ("content-type", "application/json"),
        ("accept", "application/json"),
        ("relay-version", RELAY_VERSION),
        ("idempotency-key", key.as_str()),
        ("traceparent", TRACE),
        ("authorization", auth.authorization.as_str()),
        ("dpop", auth.dpop.as_str()),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_owned(), v.to_owned()))
    .collect();
    https
        .send(Request {
            method: RelayMethod::Post,
            url: RELAY_EVENTS.to_owned(),
            headers,
            body: body.to_string().into_bytes(),
        })
        .await
        .unwrap()
}

/// `GET /v1/events/{id}` under Work's credential: the event as Relay keeps it.
async fn stored_event(https: &RelayHttps, credential: &impl Credential, id: &str) -> Response {
    let url = format!("{RELAY_EVENTS}/{id}");
    let auth = credential.authorize("GET", &url).await.unwrap();
    let headers = [
        ("accept", "application/json"),
        ("relay-version", RELAY_VERSION),
        ("traceparent", TRACE),
        ("authorization", auth.authorization.as_str()),
        ("dpop", auth.dpop.as_str()),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_owned(), v.to_owned()))
    .collect();
    https
        .send(Request {
            method: RelayMethod::Get,
            url,
            headers,
            body: Vec::new(),
        })
        .await
        .unwrap()
}

fn raw_event(seed: &[u8; 32], interruption: &str, href: &str) -> Value {
    json!({
        "workflow": "work-action-required",
        "to": [{"id": sub(seed)}],
        "data": {"reason": "gate_waiting"},
        "dedup_key": format!("wrk-test-{}-{interruption}", hex(seed)),
        "interruption": interruption,
        "links": [{"rel": "primary", "href": href}],
    })
}

fn code(answer: &Response) -> String {
    serde_json::from_slice::<Value>(&answer.body).unwrap()["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

// T-99
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment with work-server paired"]
async fn t_99_the_platform_realm_gives_work_a_dpop_token_for_relay_that_only_names_work() {
    let local = Local::open();
    let (tokens, _seed, jkt) = tokens(&local, "token").await;
    let token = paired(&tokens).await;
    let part = |n: usize| -> Value {
        serde_json::from_slice(&from_b64url(token.split('.').nth(n).unwrap()).unwrap()).unwrap()
    };
    let header = part(0);
    assert_eq!(header["typ"], "at+jwt", "{header}");
    let claims = part(1);
    assert_eq!(claims["iss"], local.issuer("platform").as_str(), "{claims}");
    assert_eq!(claims["aud"], local.client_of("relay"), "{claims}");
    assert_eq!(claims["client_id"], local.client_of("work"), "{claims}");
    assert_eq!(
        claims["access_tenant"],
        local.realm("platform")["tenant"],
        "{claims}"
    );
    assert_eq!(claims["cnf"]["jkt"], jkt, "{claims}");
    assert!(claims.get("authorization_details").is_none(), "{claims}");
    assert!(claims.get("scope").is_none(), "{claims}");
    let life = claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap();
    assert!(life <= 300, "{claims}");
    let again = tokens.token().await.unwrap();
    assert_eq!(again.expose(), token);
}

// T-99 E-83
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment with work-server paired"]
async fn t_99_relay_takes_work_s_events_with_their_interruption_and_links() {
    let local = Local::open();
    let (tokens, seed, _jkt) = tokens(&local, "events").await;
    paired(&tokens).await;
    let https = relay_https(&local);
    let relay = Relay::new(&https, RelayCredential(tokens), RELAY_EVENTS).unwrap();
    let installation = Installation::parse(INSTALLATION).unwrap();
    let approval = format!("{}/approve", local.issuer("acme").as_str());
    for (pos, class, approval, interruption, links) in [
        (1, Class::Blocking, Some(approval), "time-sensitive", 2),
        (2, Class::Informational, None, "passive", 1),
    ] {
        let i = intent(&seed, pos, class, approval);
        let request = EventRequest::new(&i, &[sub(&seed)], &installation).unwrap();
        let body: Value = serde_json::from_slice(&request.body().unwrap()).unwrap();
        assert_eq!(body["interruption"], interruption);
        assert_eq!(body["links"].as_array().unwrap().len(), links);
        let accepted = relay.send(&request, TRACE).await.unwrap();
        assert!(accepted.event_id.starts_with("evt_"), "{accepted:?}");
        assert_eq!(accepted.notifications, 1);
        let again = relay.send(&request, TRACE).await.unwrap();
        assert_eq!(again.event_id, accepted.event_id);
    }
}

// T-99 X-25
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment with work-server paired"]
async fn t_99_relay_keeps_the_item_and_the_correlation_id_of_work_s_event() {
    let local = Local::open();
    let (tokens, seed, _jkt) = tokens(&local, "item").await;
    paired(&tokens).await;
    let (reader, _seed, _jkt) = self::tokens(&local, "item-read").await;
    let https = relay_https(&local);
    let relay = Relay::new(&https, RelayCredential(tokens), RELAY_EVENTS).unwrap();
    let installation = Installation::parse(INSTALLATION).unwrap();
    let i = intent(&seed, 6, Class::Informational, None);
    let request = EventRequest::new(&i, &[sub(&seed)], &installation).unwrap();
    let item = json!({
        "ref": format!("cnd_{}", hex(&seed)),
        "version": "6",
        "digest": format!("sha256:{}", hex(&[4; 32])),
    });
    let sent: Value = serde_json::from_slice(&request.body().unwrap()).unwrap();
    assert_eq!(sent["item"], item);
    assert_eq!(sent["correlation_id"], hex(&[4; 32]));
    let accepted = relay.send(&request, TRACE).await.unwrap();
    assert!(accepted.event_id.starts_with("evt_"), "{accepted:?}");
    let answer = stored_event(&https, &RelayCredential(reader), &accepted.event_id).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let kept: Value = serde_json::from_slice(&answer.body).unwrap();
    assert_eq!(kept["id"], accepted.event_id.as_str(), "{kept}");
    assert_eq!(kept["item"], item, "{kept}");
    assert_eq!(kept["correlation_id"], hex(&[4; 32]), "{kept}");
    assert_eq!(kept["dedup_key"], i.key().as_str(), "{kept}");
}

// T-99 E-83
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment with work-server paired"]
async fn t_99_work_never_sends_critical_and_relay_lowers_a_critical_event_at_send_time() {
    let local = Local::open();
    let (tokens, seed, _jkt) = tokens(&local, "critical").await;
    paired(&tokens).await;
    let installation = Installation::parse(INSTALLATION).unwrap();
    for class in [Class::Blocking, Class::Informational] {
        let request =
            EventRequest::new(&intent(&seed, 3, class, None), &[sub(&seed)], &installation)
                .unwrap();
        let body: Value = serde_json::from_slice(&request.body().unwrap()).unwrap();
        assert_ne!(body["interruption"], "critical");
        assert_ne!(body["interruption"], "active");
    }
    let https = relay_https(&local);
    let credential = RelayCredential(tokens);
    let answer = post_raw(
        &https,
        &credential,
        &raw_event(&seed, "critical", &installation.open("cnd_x")),
    )
    .await;
    assert_eq!(
        answer.status,
        202,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

// T-99 E-83
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment with work-server paired"]
async fn t_99_relay_refuses_a_link_that_is_not_https_and_work_never_builds_one() {
    let local = Local::open();
    let (tokens, seed, _jkt) = tokens(&local, "link").await;
    paired(&tokens).await;
    let installation = Installation::parse(INSTALLATION).unwrap();
    let plain = intent(
        &seed,
        4,
        Class::Blocking,
        Some("http://access-server/approve".to_owned()),
    );
    assert_eq!(
        EventRequest::new(&plain, &[sub(&seed)], &installation).unwrap_err(),
        RequestError::Link
    );
    let https = relay_https(&local);
    let credential = RelayCredential(tokens);
    let answer = post_raw(
        &https,
        &credential,
        &raw_event(&seed, "passive", "http://work-server/open/cnd_x"),
    )
    .await;
    assert_eq!(
        answer.status,
        422,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(code(&answer), "link_scheme_not_allowed");
}

struct Directory;

impl Recipients for Directory {
    fn subs(
        &self,
        _tenant: &TenantId,
        _realm: &str,
        _client_id: &str,
        parties: &[String],
    ) -> impl Future<Output = Result<BTreeMap<String, Option<String>>, Unresolvable>> + Send {
        std::future::ready(Ok(parties
            .iter()
            .map(|p| (p.clone(), Some(format!("sub-{p}"))))
            .collect()))
    }
}

#[derive(Default)]
struct Outbox {
    pending: Mutex<Vec<NotificationIntent>>,
    settled: Mutex<Vec<(IdempotencyKey, Settlement)>>,
}

impl Intents for &Outbox {
    fn pending(
        &self,
        _limit: u32,
    ) -> impl Future<Output = Result<Vec<NotificationIntent>, OutboxError>> + Send {
        std::future::ready(Ok(self.pending.lock().unwrap().clone()))
    }

    fn settle(
        &self,
        key: &IdempotencyKey,
        settlement: Settlement,
    ) -> impl Future<Output = Result<(), OutboxError>> + Send {
        self.pending.lock().unwrap().retain(|i| i.key() != key);
        self.settled.lock().unwrap().push((key.clone(), settlement));
        std::future::ready(Ok(()))
    }
}

// T-28 MD-3 E-38
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment with work-server paired"]
async fn t_28_an_intent_waits_while_relay_is_down_and_a_later_pass_delivers_it() {
    let local = Local::open();
    let (tokens, seed, _jkt) = tokens(&local, "outbox").await;
    paired(&tokens).await;
    let https = RelayHttps {
        inner: local.https(),
        cut: Arc::new(AtomicBool::new(true)),
    };
    let outbox = Outbox::default();
    let waiting = intent(&seed, 5, Class::Blocking, None);
    outbox.pending.lock().unwrap().push(waiting.clone());
    let deliverer = Deliverer::new(
        Relay::new(&https, RelayCredential(tokens), RELAY_EVENTS).unwrap(),
        Directory,
        &outbox,
        Installation::parse(INSTALLATION).unwrap(),
        &local.client_of("relay"),
    );
    let down = deliverer.run_once(10).await.unwrap();
    assert_eq!(down.waiting, 1);
    assert!(outbox.settled.lock().unwrap().is_empty());
    https.cut.store(false, Ordering::SeqCst);
    let up = deliverer.run_once(10).await.unwrap();
    assert_eq!(up.delivered, 1, "{up:?}");
    assert!(outbox.pending.lock().unwrap().is_empty());
    let settled = outbox.settled.lock().unwrap();
    assert_eq!(&settled[0].0, waiting.key());
    assert!(
        matches!(&settled[0].1.outcome, Outcome::Delivered(a) if a.notifications == 1),
        "{:?}",
        settled[0].1
    );
}
