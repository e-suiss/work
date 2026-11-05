//! The Access client against the real Access of the local environment (T-96, T-101, P-116, T-28): discovery of the platform and `acme` realms at their path-form issuers, Work's PEP key born in its token with the certificate Access issued for its CSR, over mutual TLS for the tenant list and snapshot, the bootstrap's sample eligibility check and a refused one, a realm's token keys, and what the client does once Access cannot be reached; the signed key lookup is in `signed`, which `just test-compose-signed` runs once Access's new domains sign. These tests need `just dev`; `just test-compose` runs them with `WORK_ACCESS_LOCAL` naming the directory `just dev-access` fills with Access's local CA, Work's PEP certificate, `bootstrap.json` and a copy of the `work-dev` token, `SOFTHSM2_CONF` naming that copy, and `access-server` resolving to the loopback address.

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
use work_access_client::adapters::{DEFAULT_TIMEOUT, HttpsTransport, PEP_LABEL, PepCredential};
use work_access_client::app::{Client, DISCOVERY_INTERVAL_MS, Looked, REALM_KEYS_MAX_AGE_MS};
use work_access_client::domain::discovery::{
    Endpoint, Issuer, REFRESH_GRACE_MS, SUISS_CONFIGURATION, SuissConfiguration,
};
use work_access_client::domain::eligibility::EligibilityRequest;
use work_access_client::domain::keys::{AsOf, DomainId, KernelId, KeyState, Kid};
use work_access_client::domain::{AccessError, ProblemError, b64url, fixed_b64url};
use work_access_client::ports::{Clock, Request, Response, Transport};
use work_proto::id::TenantId;

const ACCESS: &str = "https://access-server:8443";
const REGION: &str = "local";
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

/// Wall time, Unix milliseconds: the eligibility intent's validity is checked against Access's
/// clock, which is the host's.
#[allow(clippy::disallowed_methods, reason = "test code")]
fn wall_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
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
        PepCredential::load(&module(), TOKEN, &Secret::new(PIN.to_owned()), PEP_LABEL).unwrap()
    }

    fn issued(&self) -> Vec<u8> {
        der(&std::fs::read_to_string(self.dir.join("work-pep.crt")).unwrap())
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

    /// The bootstrap's sample eligibility check, with an intent valid for a minute around now.
    fn sample(&self) -> (KernelId, Map<String, Value>) {
        let sample = &self.bootstrap["sample"];
        assert_eq!(sample["realm"], "acme");
        let now = wall_ms();
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
    let issued = local.issued();
    let x5t: [u8; 32] = Sha256::digest(&issued).into();
    assert_eq!(pep.x5t_s256(), b64url(&x5t));
    let left = pep.expiry_seconds(wall_ms());
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
    let (subject, set) = local.sample();
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
    let (subject, mut set) = local.sample();
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

/// The signed key lookup (T-101 item 4). A new domain's first operational key signs only once it
/// has been published for its lead (about 65 minutes); until then the lookup answers `503`
/// `signer-no-key`, so these run in the nightly job after
/// `wait_until_access_signs_key_lookups`.
mod signed {
    use super::{AccessError, AsOf, Duration, KeyState, Kid, Local, Looked};

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
}
