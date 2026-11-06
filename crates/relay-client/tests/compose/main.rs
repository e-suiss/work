//! The Relay client against the real Relay of the local environment (T-99, T-28, MD-3): Relay's discovery at `https://relay` names the Access client of Relay's own registration in the local Access, the events capability and the dated version Work speaks, and an intent waits in the outbox while Relay cannot be reached and is sent again by a later pass once it can. These tests need `just dev`; `just test-compose` runs them with `WORK_ACCESS_LOCAL` naming the directory `just dev-access` fills with Access's local CA, which issued Relay's certificate too, and `bootstrap.json`, and with `relay` resolving to the loopback address.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use work_proto::id::TenantId;
use work_relay_client::RELAY_VERSION;
use work_relay_client::app::{Deliverer, Relay};
use work_relay_client::domain::answer::RelayError;
use work_relay_client::domain::intent::{
    Class, Committed, IdempotencyKey, NotificationIntent, Spec,
};
use work_relay_client::domain::request::Installation;
use work_relay_client::ports::{
    Credential, Intents, OutboxError, Recipients, Request, Response, Settlement, Transport,
    Unresolvable,
};

const RELAY: &str = "https://relay";
const ACCESS_ISSUER: &str = "https://access-server:8443/realms/platform";
const REGION: &str = "eu";
const BOUND: Duration = Duration::from_secs(5);

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

    fn tls(&self) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        let pem = std::fs::read(self.dir.join("ca.crt")).unwrap();
        for c in CertificateDer::pem_slice_iter(&pem) {
            roots.add(c.unwrap()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }
}

/// HTTPS to the local Relay: one HTTP/1.1 connection per call over TLS 1.3; once cut, every
/// call goes to a closed port of the loopback address instead, as a Relay that is down.
struct Https {
    tls: Arc<ClientConfig>,
    cut: Arc<AtomicBool>,
    answered: Arc<AtomicBool>,
}

impl Https {
    async fn exchange(
        &self,
        method: http::Method,
        url: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<Response, RelayError> {
        let failed = |e: &dyn std::fmt::Display| RelayError::Unreachable(e.to_string());
        let rest = url.strip_prefix("https://").unwrap();
        let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let port = if self.cut.load(Ordering::SeqCst) {
            1
        } else {
            443
        };
        let address = if port == 1 { "127.0.0.1" } else { host };
        let tcp = timeout(BOUND, TcpStream::connect((address, port)))
            .await
            .map_err(|e| failed(&e))?
            .map_err(|e| failed(&e))?;
        let name = ServerName::try_from(host.to_owned()).unwrap();
        let stream = timeout(
            BOUND,
            TlsConnector::from(Arc::clone(&self.tls)).connect(name, tcp),
        )
        .await
        .map_err(|e| failed(&e))?
        .map_err(|e| failed(&e))?;
        let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| failed(&e))?;
        let driver = tokio::spawn(conn);
        let mut builder = http::Request::builder()
            .method(method)
            .uri(if path.is_empty() { "/" } else { path })
            .header("host", host);
        for (n, v) in headers {
            builder = builder.header(n.as_str(), v.as_str());
        }
        let response = timeout(
            BOUND,
            sender.send_request(builder.body(Full::new(Bytes::from(body))).unwrap()),
        )
        .await
        .map_err(|e| failed(&e))?
        .map_err(|e| failed(&e))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(n, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (n.as_str().to_owned(), v.to_owned()))
            })
            .collect();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| failed(&e))?
            .to_bytes()
            .to_vec();
        driver.abort();
        self.answered.store(true, Ordering::SeqCst);
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

impl Transport for &Https {
    async fn post(&self, request: Request) -> Result<Response, RelayError> {
        self.exchange(
            http::Method::POST,
            &request.url,
            &request.headers,
            request.body,
        )
        .await
    }
}

/// A credential Relay has no API client trace for.
struct Untraced;

impl Credential for Untraced {
    fn bearer(&self) -> impl Future<Output = Result<String, RelayError>> + Send {
        std::future::ready(Ok("untraced".to_owned()))
    }
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
    settled: Mutex<Vec<IdempotencyKey>>,
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
        _settlement: Settlement,
    ) -> impl Future<Output = Result<(), OutboxError>> + Send {
        self.pending.lock().unwrap().retain(|i| i.key() != key);
        self.settled.lock().unwrap().push(key.clone());
        std::future::ready(Ok(()))
    }
}

// T-28 MD-3 E-38
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_28_an_intent_waits_in_the_outbox_while_relay_is_down_and_a_later_pass_reaches_relay() {
    let local = Local::open();
    let cut = Arc::new(AtomicBool::new(true));
    let answered = Arc::new(AtomicBool::new(false));
    let https = Https {
        tls: local.tls(),
        cut: Arc::clone(&cut),
        answered: Arc::clone(&answered),
    };
    let outbox = Outbox::default();
    let intent = NotificationIntent::new(
        Committed {
            ledger: [3; 32],
            pos: 1,
            record_id: [4; 32],
            recorded_at_ms: 1_793_000_000_000,
            traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_owned(),
        },
        Spec {
            reason: "gate_waiting".to_owned(),
            class: Class::Blocking,
            item: format!("cnd_{}", "ab".repeat(32)),
            tenant: TenantId::new("tnt_local").unwrap(),
            realm: "acme".to_owned(),
            parties: vec!["AAECAwQFBgcICQoLDA0ODw".to_owned()],
            approval: None,
        },
    )
    .unwrap();
    outbox.pending.lock().unwrap().push(intent.clone());
    let deliverer = Deliverer::new(
        Relay::new(&https, Untraced, &format!("{RELAY}/v1/events")).unwrap(),
        Directory,
        &outbox,
        Installation::parse("https://work-server:8443").unwrap(),
        &local.client_of("relay"),
    );
    let down = deliverer.run_once(10).await.unwrap();
    assert_eq!(down.waiting, 1);
    assert!(!answered.load(Ordering::SeqCst));
    assert!(outbox.settled.lock().unwrap().is_empty());
    assert_eq!(outbox.pending.lock().unwrap().len(), 1);
    cut.store(false, Ordering::SeqCst);
    deliverer.run_once(10).await.unwrap();
    assert!(answered.load(Ordering::SeqCst));
}

/// Relay's discovery as Work reads it. `just test-compose` leaves these out while Relay answers
/// every request that reached it through a TLS terminator `400 malformed_request`.
mod relay_tls {
    use super::*;

    // T-99
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a Relay that serves its API over TLS"]
    async fn t_99_relay_publishes_its_access_client_the_events_capability_and_work_s_version() {
        let local = Local::open();
        let https = Https {
            tls: local.tls(),
            cut: Arc::default(),
            answered: Arc::default(),
        };
        let answer = https
            .exchange(
                http::Method::GET,
                &format!("{RELAY}/.well-known/relay-configuration"),
                &[("accept".to_owned(), "application/json".to_owned())],
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(answer.status, 200);
        let doc: Value = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(doc["issuer"], RELAY, "{doc}");
        assert_eq!(doc["api_base"], format!("{RELAY}/v1"));
        assert_eq!(doc["region"], REGION);
        assert_eq!(doc["access_issuer"], ACCESS_ISSUER);
        assert_eq!(doc["access_client_id"], local.client_of("relay"));
        assert_ne!(local.client_of("relay"), local.client_of("work"));
        assert_eq!(doc["events_endpoint"], format!("{RELAY}/v1/events"));
        let has =
            |field: &str, value: &str| doc[field].as_array().unwrap().iter().any(|v| v == value);
        assert!(has("capabilities", "urn:suiss:relay:events:1"), "{doc}");
        assert!(has("contract_versions_supported", RELAY_VERSION), "{doc}");
    }
}
