//! The Access client against the real Access of the local environment (T-96, T-101, P-116): discovery of the platform and `acme` realms at their path-form issuers, the PEP certificate over mutual TLS for the tenant list and snapshot, the verified key lookup of the bootstrap's root, the eligibility check and a realm's token keys. These tests need `just dev`; `just test-compose` runs them with `WORK_ACCESS_LOCAL` naming the directory `just dev-access` fills with Access's local CA, its PEP certificate and key and `bootstrap.json`, and with `access-server` resolving to the loopback address.

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
use std::process::Command;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::object::{Attribute, CertificateType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use suiss_crypto::secret::Secret;
use work_access_client::adapters::{DEFAULT_TIMEOUT, HttpsTransport, PEP_LABEL, PepCredential};
use work_access_client::app::{Client, Looked};
use work_access_client::domain::discovery::{
    Endpoint, Issuer, SUISS_CONFIGURATION, SuissConfiguration,
};
use work_access_client::domain::eligibility::EligibilityRequest;
use work_access_client::domain::keys::{AsOf, DomainId, KernelId, KeyState, Kid};
use work_access_client::domain::{AccessError, fixed_b64url};
use work_access_client::ports::{Clock, Request, Transport};
use work_proto::id::TenantId;

const ACCESS: &str = "https://access-server:8443";
const REGION: &str = "local";
const PIN: &str = "4711";
const DAY_MS: u64 = 86_400_000;
const JSON: &str = "application/json";

struct At(u64);

impl Clock for At {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

fn module() -> PathBuf {
    std::env::var_os("PKCS11_MODULE").map_or_else(
        || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from,
    )
}

fn softhsm(args: &[&str]) {
    let out = Command::new("softhsm2-util").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "softhsm2-util: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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

/// One DER element: its content, its own bytes and what follows it.
fn split(input: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let first = input[1];
    let (len, head) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        let len = input[2..2 + n]
            .iter()
            .fold(0, |acc, b| acc * 256 + usize::from(*b));
        (len, 2 + n)
    };
    (
        &input[head..head + len],
        &input[..head + len],
        &input[head + len..],
    )
}

/// The DER subject name of a certificate.
fn subject(certificate: &[u8]) -> Vec<u8> {
    let (body, _, _) = split(certificate);
    let (tbs, _, _) = split(body);
    let mut at = tbs;
    if at[0] == 0xa0 {
        at = split(at).2;
    }
    for _ in 0..4 {
        at = split(at).2;
    }
    split(at).1.to_vec()
}

fn import_certificate(token: &str, certificate: &[u8]) {
    let ctx = Pkcs11::new(module()).unwrap();
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => panic!("{e}"),
    }
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| {
            ctx.get_token_info(*s)
                .is_ok_and(|i| i.label().trim_end() == token)
        })
        .unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::from(PIN.to_owned())))
        .unwrap();
    session
        .create_object(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Label(PEP_LABEL.as_bytes().to_vec()),
            Attribute::Subject(subject(certificate)),
            Attribute::Value(certificate.to_vec()),
        ])
        .unwrap();
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

    fn domain(&self, slug: &str) -> DomainId {
        DomainId(fixed_b64url(self.realm(slug)["domain"].as_str().unwrap()).unwrap())
    }

    fn tenant(&self, slug: &str) -> TenantId {
        TenantId::new(self.realm(slug)["tenant"].as_str().unwrap()).unwrap()
    }

    fn root(&self) -> (KernelId, Kid) {
        let root = &self.bootstrap["root"];
        (
            KernelId(fixed_b64url(root["party"].as_str().unwrap()).unwrap()),
            Kid(fixed_b64url(root["kid"].as_str().unwrap()).unwrap()),
        )
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        let ca = std::fs::read_to_string(self.dir.join("ca.crt")).unwrap();
        roots.add(CertificateDer::from(der(&ca))).unwrap();
        roots
    }

    /// Access's PEP key and certificate, in a token of this test's own.
    fn pep(&self) -> PepCredential {
        let label = format!("access-pep-{}", std::process::id());
        softhsm(&[
            "--init-token",
            "--free",
            "--label",
            &label,
            "--so-pin",
            "12345678",
            "--pin",
            PIN,
        ]);
        let key = self.dir.join("pep.key");
        softhsm(&[
            "--import",
            key.to_str().unwrap(),
            "--token",
            &label,
            "--label",
            PEP_LABEL,
            "--id",
            "01",
            "--pin",
            PIN,
        ]);
        let certificate = std::fs::read_to_string(self.dir.join("pep.crt")).unwrap();
        import_certificate(&label, &der(&certificate));
        PepCredential::load(&module(), &label, &Secret::new(PIN.to_owned()), PEP_LABEL).unwrap()
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

// T-101
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
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
        assert!(!key.evidence.sign1.is_empty());
        assert!(!key.evidence.excerpt.is_empty());
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

// T-101
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn t_101_the_eligibility_check_answers_with_a_consistency_token() {
    let local = Local::open();
    let pep = local.pep();
    let client = local.client(&pep, "acme");
    client.discover().await.unwrap();
    let (party, _) = local.root();
    let set = json!({
        "domain": URL_SAFE_NO_PAD.encode(local.domain("acme").0),
        "intent": {
            "action": {
                "namespace": "work",
                "name": "approve",
                "major": 1,
                "schema": URL_SAFE_NO_PAD.encode([4; 32]),
            },
            "resources": [{ "namespace": "work", "path": ["gate-1"] }],
            "validity": { "from": 0, "until": 4_000_000_000_000_u64 },
        },
        "basis": {
            "holding": {
                "grant": URL_SAFE_NO_PAD.encode([6; 16]),
                "holder": party.text(),
                "since": 1,
            },
        },
        "capacity": "own",
    });
    let request = EligibilityRequest::new(party, set.as_object().unwrap().clone(), None).unwrap();
    let answer = client.eligibility(&request).await.unwrap();
    assert!(!answer.consistency_token.as_str().is_empty());
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
        assert!(!keys.keys.is_empty(), "{slug}");
    }
}
