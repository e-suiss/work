//! The Access client against the real Access of the local environment (T-96, T-101, P-116, T-28): discovery of the platform and `acme` realms at their path-form issuers, Work's PEP key born in its token with the certificate Access issued for its CSR, over mutual TLS for the tenant list and snapshot, the bootstrap's sample eligibility check and a refused one, a realm's token keys, the realms a caller's token may come from, a Party and its pairwise `sub` resolved both ways, and what the client does once Access cannot be reached (E-7); the signed key lookup is in `signed`, which `just test-compose-signed` runs once Access's new domains sign. These tests need `just dev`; `just test-compose` runs them with `WORK_ACCESS_LOCAL` naming the directory `just dev-access` fills with Access's local CA, Work's PEP certificate, `bootstrap.json` and a copy of the `work-dev` token, `SOFTHSM2_CONF` naming that copy, and `access-server` resolving to the loopback address.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use suiss_crypto::secret::Secret;
use work_access_client::adapters::{
    DEFAULT_TIMEOUT, HttpsTransport, PEP_LABEL, PepCredential, public_config,
};
use work_access_client::app::{
    Client, DIRECTORY_MAX_AGE_MS, DISCOVERY_INTERVAL_MS, Looked, REALM_KEYS_MAX_AGE_MS,
};
use work_access_client::domain::discovery::{
    Endpoint, Issuer, REFRESH_GRACE_MS, SUISS_CONFIGURATION, SuissConfiguration,
};
use work_access_client::domain::eligibility::EligibilityRequest;
use work_access_client::domain::keys::{AsOf, DomainId, KernelId, KeyState, Kid};
use work_access_client::domain::subjects::Direction;
use work_access_client::domain::token::{
    TokenRefusal, TokenRules, unverified, verify_access_token,
};
use work_access_client::domain::{AccessError, ProblemError, b64url, fixed_b64url};
use work_access_client::ports::{Clock, Request, Response, Transport};
use work_proto::id::TenantId;

const ACCESS: &str = "https://access-server:8443";
const REGION: &str = "eu";
const TOKEN: &str = "work-dev";
const PIN: &str = "1234";
const DAY_MS: u64 = 86_400_000;
const JSON: &str = "application/json";

struct At(u64);

impl Clock for At {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

/// A clock the test moves.
struct Moving(Arc<AtomicU64>);

impl Clock for Moving {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A closed port on the loopback address: what a client of an Access that is down reaches.
const CLOSED: &str = "https://127.0.0.1:1";

/// The transport to the local Access, which the test can cut: once cut, every call goes to
/// [`CLOSED`] instead.
struct Severable {
    inner: HttpsTransport,
    cut: Arc<AtomicBool>,
}

impl Transport for Severable {
    async fn send(&self, mut request: Request) -> Result<Response, AccessError> {
        if self.cut.load(Ordering::SeqCst) {
            request.url = request.url.replacen(ACCESS, CLOSED, 1);
        }
        self.inner.send(request).await
    }
}

fn module() -> PathBuf {
    std::env::var_os("PKCS11_MODULE").map_or_else(
        || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from,
    )
}

fn der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    STANDARD.decode(body).unwrap()
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

    fn tenant(&self, slug: &str) -> TenantId {
        TenantId::new(self.realm(slug)["tenant"].as_str().unwrap()).unwrap()
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        let ca = std::fs::read_to_string(self.dir.join("ca.crt")).unwrap();
        roots.add(CertificateDer::from(der(&ca))).unwrap();
        roots
    }

    /// Work's PEP key, born in the `work-dev` token, with the certificate Access's local CA
    /// issued for its CSR, which `work-access-pep` put beside it (T-101 item 2, T-56).
    fn pep(&self) -> PepCredential {
        let pep =
            PepCredential::load(&module(), TOKEN, &Secret::new(PIN.to_owned()), PEP_LABEL).unwrap();
        let issued = der(&std::fs::read_to_string(self.dir.join("work-pep.crt")).unwrap());
        let x5t: [u8; 32] = Sha256::digest(&issued).into();
        assert_eq!(pep.x5t_s256(), b64url(&x5t));
        pep
    }

    fn domain(&self, slug: &str) -> DomainId {
        DomainId(fixed_b64url(self.realm(slug)["domain"].as_str().unwrap()).unwrap())
    }

    fn root(&self) -> (KernelId, Kid) {
        let root = &self.bootstrap["root"];
        (
            KernelId::parse(root["party"].as_str().unwrap()).unwrap(),
            Kid::parse(root["kid"].as_str().unwrap()).unwrap(),
        )
    }

    /// Access's time, from the `Date` of its answer: what it checks validity windows against.
    async fn access_now_ms(&self, pep: &PepCredential) -> u64 {
        let answer = self
            .transport(pep)
            .send(Request::get(
                self.issuer("acme").well_known(SUISS_CONFIGURATION),
                JSON,
            ))
            .await
            .unwrap();
        imf_fixdate_ms(answer.header("date").unwrap())
    }

    /// The bootstrap's sample eligibility check, with an intent valid for a minute around
    /// Access's now.
    async fn sample(&self, pep: &PepCredential) -> (KernelId, Map<String, Value>) {
        let sample = &self.bootstrap["sample"];
        assert_eq!(sample["realm"], "acme");
        let now = self.access_now_ms(pep).await;
        let set = json!({
            "domain": sample["domain"],
            "intent": {
                "action": sample["action"],
                "resources": [sample["resource"]],
                "validity": { "from": now - 60_000, "until": now + 60_000 },
            },
            "basis": sample["basis"],
            "capacity": "own",
        });
        (
            KernelId::parse(sample["subject"].as_str().unwrap()).unwrap(),
            set.as_object().unwrap().clone(),
        )
    }

    fn transport(&self, pep: &PepCredential) -> HttpsTransport {
        HttpsTransport::new(pep.client_config(self.roots()).unwrap(), DEFAULT_TIMEOUT)
    }

    fn client(&self, pep: &PepCredential, slug: &str) -> Client<HttpsTransport, At> {
        Client::new(
            self.transport(pep),
            At(pep.not_after_ms() - DAY_MS),
            self.issuer(slug),
            REGION,
            pep.not_after_ms(),
        )
    }
}

// T-96
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_96_discovery_reads_the_platform_and_acme_realms_at_their_path_issuers() {
    let local = Local::open();
    let pep = local.pep();
    for slug in ["platform", "acme"] {
        let issuer = local.issuer(slug);
        assert_eq!(issuer.as_str(), format!("{ACCESS}/realms/{slug}"));
        assert_eq!(
            issuer.well_known(SUISS_CONFIGURATION),
            format!("{ACCESS}/.well-known/suiss-configuration/realms/{slug}")
        );
        let doc = local.client(&pep, slug).discover().await.unwrap();
        assert_eq!(doc.issuer, issuer);
        assert_eq!(doc.region, REGION);
        for endpoint in [
            Endpoint::KeyLookup,
            Endpoint::KeyBatch,
            Endpoint::Eligibility,
            Endpoint::TenantSnapshot,
            Endpoint::Exercise,
            Endpoint::SubjectResolution,
        ] {
            let template = doc.endpoints.get(endpoint).unwrap();
            assert!(template.as_str().starts_with(ACCESS), "{endpoint:?}");
        }
        let appended = local.realm(slug)["discovery"].as_str().unwrap().to_owned();
        let answer = local
            .transport(&pep)
            .send(Request::get(appended, JSON))
            .await
            .unwrap();
        assert_eq!(
            SuissConfiguration::from_json(answer.ok().unwrap(), &issuer).unwrap(),
            doc
        );
    }
}

// T-101 T-56
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_101_the_pep_key_born_in_the_token_carries_the_certificate_access_issued_for_its_csr() {
    let local = Local::open();
    let pep = local.pep();
    let left = pep.expiry_seconds(local.access_now_ms(&pep).await);
    assert!(left > 300 * 86_400 && left <= 366 * 86_400, "{left}");
    let client = local.client(&pep, "platform");
    client.discover().await.unwrap();
    assert_ne!(client.tenants(None).await.unwrap().tenants.len(), 0);
}

// T-101
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_101_the_pep_certificate_lists_the_tenants_and_reads_their_snapshots() {
    let local = Local::open();
    let pep = local.pep();
    let client = local.client(&pep, "platform");
    let doc = client.discover().await.unwrap();
    let mut listed = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = client.tenants(cursor.as_deref()).await.unwrap();
        listed.extend(page.tenants);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    for slug in ["platform", "acme"] {
        let tenant = local.tenant(slug);
        assert!(tenant.as_str().starts_with("tnt_"), "{slug}");
        let snapshot = client.tenant(&tenant).await.unwrap();
        assert_eq!(snapshot.tenant, tenant);
        assert_eq!(snapshot.region, REGION);
        assert!(listed.contains(&snapshot), "{slug}");
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let anonymous = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(local.roots())
        .with_no_client_auth();
    let url = doc
        .endpoints
        .get(Endpoint::TenantSnapshot)
        .unwrap()
        .expand(local.tenant("acme").as_str());
    let answer = HttpsTransport::new(Arc::new(anonymous), DEFAULT_TIMEOUT)
        .send(Request::get(url, JSON))
        .await
        .unwrap();
    assert!(matches!(
        answer.ok(),
        Err(AccessError::Refused { status: 401, .. })
    ));
}

// P-116
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn p_116_the_realm_token_keys_come_from_the_realm_jwks() {
    let local = Local::open();
    let pep = local.pep();
    for slug in ["platform", "acme"] {
        let client = local.client(&pep, slug);
        let keys = client
            .realm_keys(&local.issuer(slug), &[0; 32])
            .await
            .unwrap();
        assert_ne!(keys.keys.len(), 0, "{slug}");
    }
}

// E-38 T-28 SEC-8 MD-3 T-96
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn e_38_without_access_consequential_calls_fail_closed_and_reads_last_only_their_bound() {
    let local = Local::open();
    let pep = local.pep();
    let issuer = local.issuer("acme");
    let cut = Arc::new(AtomicBool::new(false));
    let now = Arc::new(AtomicU64::new(pep.not_after_ms() - DAY_MS));
    let client = Client::new(
        Severable {
            inner: local.transport(&pep),
            cut: Arc::clone(&cut),
        },
        Moving(Arc::clone(&now)),
        issuer.clone(),
        REGION,
        pep.not_after_ms(),
    );
    client.discover().await.unwrap();
    let keys = client.realm_keys(&issuer, &[0; 32]).await.unwrap();
    let kid = *keys.keys.keys().next().unwrap();
    let request = EligibilityRequest::new(KernelId([1; 16]), serde_json::Map::new(), None).unwrap();

    cut.store(true, Ordering::SeqCst);
    let cached = client.realm_keys(&issuer, &kid).await.unwrap();
    assert_eq!(
        cached.keys.keys().collect::<Vec<_>>(),
        keys.keys.keys().collect::<Vec<_>>()
    );
    for refused in [
        client.eligibility(&request).await.map(|_| ()),
        client
            .keys(DomainId([1; 32]), &[Kid([2; 32])], &AsOf::Head)
            .await
            .map(|_| ()),
        client.tenants(None).await.map(|_| ()),
        client.discover().await.map(|_| ()),
    ] {
        let error = refused.unwrap_err();
        assert!(
            matches!(error, AccessError::Transport(_) | AccessError::Timeout),
            "{error:?}"
        );
        assert_eq!(error.code(), "authority_unverifiable");
    }
    now.fetch_add(REALM_KEYS_MAX_AGE_MS, Ordering::SeqCst);
    assert!(client.realm_keys(&issuer, &kid).await.is_err());

    now.fetch_add(DISCOVERY_INTERVAL_MS + REFRESH_GRACE_MS, Ordering::SeqCst);
    cut.store(false, Ordering::SeqCst);
    assert_eq!(client.eligibility(&request).await, Err(AccessError::Stale));
    client.discover().await.unwrap();
    let answered = client.eligibility(&request).await;
    assert!(
        !matches!(
            answered,
            Err(AccessError::Stale | AccessError::Transport(_) | AccessError::Timeout)
        ),
        "{answered:?}"
    );
}

// T-101
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_101_the_bootstrap_sample_is_eligible() {
    let local = Local::open();
    let pep = local.pep();
    let client = local.client(&pep, "acme");
    client.discover().await.unwrap();
    let (subject, set) = local.sample(&pep).await;
    let request = EligibilityRequest::new(subject, set.clone(), None).unwrap();
    let answer = client.eligibility(&request).await.unwrap();
    assert!(answer.eligible);
    assert_ne!(answer.consistency_token.as_str(), "");
    let stranger = EligibilityRequest::new(KernelId([0x5a; 16]), set, None).unwrap();
    assert!(!client.eligibility(&stranger).await.unwrap().eligible);
}

// T-101
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_101_a_broken_set_is_refused_with_the_pointer_of_what_it_names() {
    let local = Local::open();
    let pep = local.pep();
    let client = local.client(&pep, "acme");
    client.discover().await.unwrap();
    let (subject, mut set) = local.sample(&pep).await;
    set.insert("basis".to_owned(), json!("none"));
    let request = EligibilityRequest::new(subject, set, None).unwrap();
    let refused = client.eligibility(&request).await.unwrap_err();
    let AccessError::Refused {
        status: 400,
        errors,
        ..
    } = &refused
    else {
        panic!("{refused:?}");
    };
    assert!(
        errors.contains(&ProblemError {
            pointer: Some("#/set/basis".to_owned()),
            code: "basis".to_owned(),
        }),
        "{refused:?}"
    );
    assert!(!refused.is_temporary());
    assert_eq!(refused.code(), "authority_unverifiable");
}

/// The signed key lookup (T-101 item 4), after `wait_until_access_signs_key_lookups`, which
/// waits while the lookup answers `503` `signer-no-key`.
mod signed {
    use work_access_client::domain::approval::{ApprovalRequest, State};
    use work_access_client::domain::exercise::{ExerciseId, Intent};

    use super::{AccessError, AsOf, Duration, Endpoint, KeyState, Kid, Local, Looked};

    const POLL: Duration = Duration::from_secs(30);

    fn wait_s() -> u64 {
        std::env::var("WORK_ACCESS_SIGNED_WAIT_S")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }

    // T-101 T-28
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its domains signing"]
    async fn wait_until_access_signs_key_lookups() {
        let local = Local::open();
        let pep = local.pep();
        let (_, root) = local.root();
        let polls = wait_s() / POLL.as_secs();
        for slug in ["platform", "acme"] {
            let client = local.client(&pep, slug);
            client.discover().await.unwrap();
            let mut polled = 0;
            loop {
                match client.keys(local.domain(slug), &[root], &AsOf::Head).await {
                    Err(AccessError::Unavailable { reason: Some(r) })
                        if r == "signer-no-key" && polled < polls =>
                    {
                        polled += 1;
                        tokio::time::sleep(POLL).await;
                    }
                    answered => {
                        answered.unwrap();
                        break;
                    }
                }
            }
        }
    }

    // T-101
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its domains signing"]
    async fn t_101_the_bootstrap_root_key_is_looked_up_and_verified_in_each_realm_domain() {
        let local = Local::open();
        let pep = local.pep();
        let (party, root) = local.root();
        let stranger = Kid([7; 32]);
        for slug in ["platform", "acme"] {
            let domain = local.domain(slug);
            let batch = local.client(&pep, slug);
            batch.discover().await.unwrap();
            let both = batch
                .keys(domain, &[root, stranger], &AsOf::Head)
                .await
                .unwrap();
            let [Looked::Known(key), Looked::Unknown(unknown)] = both.as_slice() else {
                panic!("{slug}: {both:?}");
            };
            assert_eq!(key.key.kid, root);
            assert_eq!(key.key.party, party);
            assert_eq!(key.key.state, KeyState::Active);
            assert_ne!(key.evidence.sign1.len(), 0);
            assert_ne!(key.evidence.excerpt.len(), 0);
            assert_eq!(*unknown, stranger);
            let single = local.client(&pep, slug);
            single.discover().await.unwrap();
            let one = single.keys(domain, &[root], &AsOf::Head).await.unwrap();
            let [Looked::Known(alone)] = one.as_slice() else {
                panic!("{slug}: {one:?}");
            };
            assert_eq!(alone.key, key.key);
        }
    }

    // P-12 MD-7 T-101
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its domains signing"]
    async fn p_12_the_signed_party_lookup_binds_the_test_user_and_leaves_a_stranger_out() {
        use work_access_client::domain::keys::{ActorKind, KernelId};
        use work_access_client::ports::PartyKinds as _;

        let local = Local::open();
        let pep = local.pep();
        let user =
            KernelId::parse(local.bootstrap["test_user"]["party"].as_str().unwrap()).unwrap();
        let (root, _) = local.root();
        let stranger = KernelId([7; 16]);
        let domain = local.domain("acme");
        let client = local.client(&pep, "acme");
        client.discover().await.unwrap();
        let both = client.kinds(domain, &[user, stranger, root]).await.unwrap();
        assert_eq!(both.get(&user), Some(&ActorKind::Human), "{both:?}");
        assert!(both.contains_key(&root), "{both:?}");
        assert!(!both.contains_key(&stranger), "{both:?}");
        let alone = client.kinds(domain, &[user]).await.unwrap();
        assert_eq!(alone.get(&user), Some(&ActorKind::Human));
        assert_eq!(
            client.kinds(domain, &[stranger]).await.unwrap(),
            std::collections::BTreeMap::new()
        );
        let entries = client.parties(domain, &[user], &AsOf::Head).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].ended.is_none());
    }

    // T-101 E-17 P-13
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its domains signing"]
    async fn t_101_an_exercise_access_never_allowed_is_no_authority_and_work_approves_nothing() {
        let local = Local::open();
        let pep = local.pep();
        let client = local.client(&pep, "acme");
        client.discover().await.unwrap();
        let intent = Intent {
            digest: [0x1e; 32],
            namespace: "work".to_owned(),
            action: "commit".to_owned(),
            major: 1,
            resources: Vec::new(),
            valid_from_ms: 0,
            valid_until_ms: u64::MAX,
        };
        let unknown = ExerciseId([0x5e; 32]);
        let domain = local.domain("acme");
        for agency in [false, true] {
            let refused = if agency {
                client
                    .exercise_agency(domain, &unknown, &intent, "cli_work")
                    .await
            } else {
                client.exercise(domain, &unknown, &intent, "cli_work").await
            };
            let Err(AccessError::Refused { status: 404, .. }) = &refused else {
                panic!("{refused:?}");
            };
        }
        let state = State::new("work-test").unwrap();
        let request = ApprovalRequest::Digest([0x2e; 32]);
        let url = client
            .approval_url(
                client.issuer(),
                &request,
                "https://work.example/v1/access/approval",
                &state,
            )
            .await;
        match url {
            Err(AccessError::Unserved(Endpoint::Approval)) => {}
            Ok(url) => assert!(url.contains("request="), "{url}"),
            other => panic!("{other:?}"),
        }
    }
}

/// The stream upkeep against the real Access (T-103 item 7): the platform stream is disabled
/// the only way Access offers, `DELETE` by the client that owns it, here with Work's own client
/// assertion key from the token copy, acting as the operator would; Work itself never deletes a
/// stream. The CI job then restarts `work-server` and checks that it opened the stream again.
/// `just test-compose-upkeep` runs this after `just test-compose`.
mod upkeep {
    use std::sync::atomic::AtomicU64;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::ServerName;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use work_access_client::adapters::{AccessKeys, TokenSigner, public_config};
    use work_access_client::app::platform::Platform;
    use work_access_client::domain::discovery::Endpoints;
    use work_access_client::domain::streams::{Stream, StreamStatus};
    use work_access_client::ports::Random;

    use sha2::Digest as _;

    use super::{
        AccessError, At, DEFAULT_TIMEOUT, Endpoint, HttpsTransport, Local, Ordering, PIN, Secret,
        Sha256, TOKEN, Value, module,
    };

    const RECEIVER: &str = "https://work-server:8443/v1/inbound/events";

    /// Fresh `jti`s: the hash of Access's time at the start and a counter.
    pub(super) struct Jti(AtomicU64, u64);

    impl Random for Jti {
        fn fill(&self, out: &mut [u8]) -> Result<(), AccessError> {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            let mut h = Sha256::new();
            h.update(self.1.to_be_bytes());
            h.update(n.to_be_bytes());
            let d = h.finalize();
            for (o, b) in out.iter_mut().zip(d.iter().cycle()) {
                *o = *b;
            }
            Ok(())
        }
    }

    /// `method url` with `bearer` and a JSON `body` when given; the status.
    pub(super) async fn send(
        method: &str,
        url: &str,
        bearer: &str,
        body: Option<&Value>,
        local: &Local,
    ) -> u16 {
        let rest = url.strip_prefix("https://").unwrap();
        let slash = rest.find('/').unwrap();
        let (authority, path) = rest.split_at(slash);
        let (host, port) = authority
            .rsplit_once(':')
            .map_or((authority, 443), |(h, p)| (h, p.parse::<u16>().unwrap()));
        let tcp = TcpStream::connect((host, port)).await.unwrap();
        let tls = TlsConnector::from(public_config(local.roots()).unwrap())
            .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
            .await
            .unwrap();
        let (mut send, connection) = http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(connection);
        let mut request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", authority)
            .header("authorization", bearer);
        let bytes = match body {
            Some(b) => {
                request = request.header("content-type", "application/json");
                Bytes::from(b.to_string())
            }
            None => Bytes::new(),
        };
        let request = request.body(Full::new(bytes)).unwrap();
        send.send_request(request).await.unwrap().status().as_u16()
    }

    /// Work's platform client with its own client assertion key from the token copy, the
    /// served endpoints, and the stream work-server's pairing opened.
    pub(super) async fn owner(
        local: &Local,
    ) -> (
        Platform<HttpsTransport, At, Jti, TokenSigner>,
        Endpoints,
        Stream,
    ) {
        let pep = local.pep();
        let now = local.access_now_ms(&pep).await;
        let discovery = local.client(&pep, "platform");
        discovery.discover().await.unwrap();
        let endpoints = discovery.served().unwrap();
        let keys = AccessKeys::load(&module(), TOKEN, &Secret::new(PIN.to_owned())).unwrap();
        let client_id = local.bootstrap["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["product"] == "work")
            .unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let platform = Platform::new(
            HttpsTransport::new(public_config(local.roots()).unwrap(), DEFAULT_TIMEOUT),
            At(now),
            Jti(AtomicU64::new(0), now),
            keys.client,
            &client_id,
            &local.issuer("platform"),
        );
        let streams = platform.streams(&endpoints).await.unwrap();
        let live = streams
            .into_iter()
            .find(|s| s.pushes_to(RECEIVER) && s.status != StreamStatus::Disabled)
            .expect("work-server's pairing opened the stream");
        (platform, endpoints, live)
    }

    // T-103 T-102
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with work-server paired"]
    async fn t_103_the_owner_disables_the_platform_stream_for_work_to_reopen() {
        let local = Local::open();
        let (platform, endpoints, live) = owner(&local).await;
        assert_eq!(live.status, StreamStatus::Enabled);
        let base = endpoints.get(Endpoint::PlatformStreams).unwrap().expand("");
        let bearer = format!("Bearer {}", platform.assertion().unwrap());
        let url = format!("{base}/{}", live.id);
        assert_eq!(send("DELETE", &url, &bearer, None, &local).await, 204);
        let after = platform.stream(&endpoints, &live.id).await.unwrap();
        assert!(
            after
                .as_ref()
                .is_none_or(|s| s.status == StreamStatus::Disabled),
            "{after:?}"
        );
    }
}

/// The platform stream's status as its owner sets it (T-102 item 7, T-103): paused, which
/// work-server reports as an operator signal with `work_access_event_stream_up` 0 after its next
/// pairing step, and enabled again. The CI compose job runs each by name and restarts work-server
/// after it.
mod status {
    use work_access_client::domain::streams::StreamStatus;

    use super::upkeep::{owner, send};
    use super::{Endpoint, Local, json};

    async fn set(status: StreamStatus) {
        let local = Local::open();
        let (platform, endpoints, live) = owner(&local).await;
        let base = endpoints.get(Endpoint::PlatformStreams).unwrap().expand("");
        let bearer = format!("Bearer {}", platform.assertion().unwrap());
        let body = json!({"stream_id": live.id, "status": status.as_str()});
        let url = format!("{base}/{}/status", live.id);
        assert_eq!(send("POST", &url, &bearer, Some(&body), &local).await, 200);
        let after = platform.stream(&endpoints, &live.id).await.unwrap();
        assert_eq!(after.map(|s| s.status), Some(status));
    }

    // T-102 T-103
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with work-server paired"]
    async fn t_102_the_owner_pauses_the_platform_stream() {
        set(StreamStatus::Paused).await;
    }

    // T-102 T-103
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with work-server paired"]
    async fn t_102_the_owner_enables_the_platform_stream_again() {
        set(StreamStatus::Enabled).await;
    }
}

// T-96 E-7 C-9 P-116
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_96_a_caller_token_comes_only_from_a_live_realm_and_verifies_only_under_its_keys() {
    let local = Local::open();
    let pep = local.pep();
    let client = local.client(&pep, "platform");
    client.discover().await.unwrap();
    for slug in ["platform", "acme"] {
        let issuer = local.issuer(slug);
        let realm = client.realm_of(issuer.as_str()).await.unwrap().unwrap();
        assert_eq!(realm.tenant, local.tenant(slug), "{slug}");
        assert_eq!(realm.realm, local.realm(slug)["realm"].as_str().unwrap());
        assert_eq!(realm.slug, slug);
    }
    let nowhere = format!("{ACCESS}/realms/nowhere");
    assert_eq!(client.realm_of(&nowhere).await.unwrap(), None);

    let header = b64url(
        format!(
            r#"{{"alg":"Ed25519","kid":"{}","typ":"at+jwt"}}"#,
            b64url(&[9; 32])
        )
        .as_bytes(),
    );
    let issuer = local.issuer("acme");
    let claims = format!(r#"{{"iss":"{}","aud":"cli_work"}}"#, issuer.as_str());
    let token = format!(
        "{header}.{}.{}",
        b64url(claims.as_bytes()),
        b64url(&[1; 64])
    );
    let (iss, kid) = unverified(&token).unwrap();
    assert_eq!(iss, issuer.as_str());
    let keys = client.realm_keys(&issuer, &kid).await.unwrap();
    assert!(!keys.keys.is_empty());
    let rules = TokenRules {
        issuer: issuer.as_str(),
        audience: "cli_work",
        now_ms: pep.not_after_ms() - DAY_MS,
    };
    assert_eq!(
        verify_access_token(&token, &keys, &rules),
        Err(TokenRefusal::UnknownKid)
    );
}

// T-101 E-7 C-9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_101_a_party_and_its_pairwise_sub_resolve_both_ways() {
    let local = Local::open();
    let pep = local.pep();
    let client = local.client(&pep, "platform");
    client.discover().await.unwrap();
    let platform = client
        .realm_of(local.issuer("platform").as_str())
        .await
        .unwrap()
        .unwrap();
    let client_id = local.bootstrap["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["product"] == "work")
        .unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let root = local.bootstrap["root"]["party"]
        .as_str()
        .unwrap()
        .to_owned();
    let stranger = b64url(&[7; 32]);
    let resolve = |direction, values: Vec<String>| {
        let (tenant, realm, client_id) = (&platform.tenant, &platform.realm, &client_id);
        let client = &client;
        async move {
            client
                .resolve(tenant, realm, client_id, direction, &values)
                .await
                .unwrap()
        }
    };
    let unknown = resolve(Direction::Subs, vec![stranger.clone()]).await;
    assert_eq!(unknown.get(&stranger), Some(&None));
    let forward = resolve(Direction::Parties, vec![root.clone()]).await;
    let Some(Some(sub)) = forward.get(&root).cloned() else {
        assert_eq!(forward.get(&root), Some(&None));
        return;
    };
    assert_eq!(sub.len(), 43);
    let back = resolve(Direction::Subs, vec![sub.clone(), stranger.clone()]).await;
    assert_eq!(back.get(&sub), Some(&Some(root.clone())));
    assert_eq!(back.get(&stranger), Some(&None));
    let again = resolve(Direction::Parties, vec![root.clone()]).await;
    assert_eq!(again.get(&root), Some(&Some(sub)));
}

// E-38 T-28 SEC-8 E-7
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn e_38_without_access_the_known_realms_last_only_their_bound() {
    let local = Local::open();
    let pep = local.pep();
    let cut = Arc::new(AtomicBool::new(false));
    let now = Arc::new(AtomicU64::new(pep.not_after_ms() - DAY_MS));
    let client = Client::new(
        Severable {
            inner: local.transport(&pep),
            cut: Arc::clone(&cut),
        },
        Moving(Arc::clone(&now)),
        local.issuer("platform"),
        REGION,
        pep.not_after_ms(),
    );
    client.discover().await.unwrap();
    let acme = local.issuer("acme");
    assert!(client.realm_of(acme.as_str()).await.unwrap().is_some());
    cut.store(true, Ordering::SeqCst);
    assert!(client.realm_of(acme.as_str()).await.unwrap().is_some());
    now.fetch_add(DIRECTORY_MAX_AGE_MS, Ordering::SeqCst);
    let error = client.realm_of(acme.as_str()).await.unwrap_err();
    assert_eq!(error.code(), "authority_unverifiable");
}

/// Relay found through Access. `just test-compose` leaves these out while Relay answers every
/// request that reached it through a TLS terminator `400 malformed_request`.
mod relay_tls {
    use super::*;

    // T-99 T-96 E-2
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a Relay that serves its API over TLS"]
    async fn t_99_relay_is_found_through_access_and_names_its_own_access_client() {
        let local = Local::open();
        let pep = local.pep();
        let client = local.client(&pep, "platform");
        let doc = client.discover().await.unwrap();
        assert_eq!(doc.relay.as_str(), "https://relay");
        let relay = HttpsTransport::new(public_config(local.roots()).unwrap(), DEFAULT_TIMEOUT);
        let found = client.relay(&relay, "2026-11-01").await.unwrap();
        assert_eq!(found.issuer, doc.relay);
        assert_eq!(found.api_base, "https://relay/v1");
        assert_eq!(found.events_endpoint, "https://relay/v1/events");
        let client_of = |product: &str| {
            local.bootstrap["clients"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["product"] == product)
                .map(|c| c["client_id"].as_str().unwrap().to_owned())
                .unwrap()
        };
        assert_eq!(found.access_client_id, client_of("relay"));
        assert_ne!(found.access_client_id, client_of("work"));
        assert!(found.capabilities.contains("urn:suiss:relay:events:1"));
        assert_eq!(
            client.relay(&relay, "2026-10-01").await.unwrap_err(),
            AccessError::ContractVersion("2026-10-01".to_owned())
        );
    }
}
