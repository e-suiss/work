//! The outside of the Access client: the PEP credential, a TLS client certificate whose private key never leaves the PKCS#11 token and whose certificate is a token object of the same label (T-101 item 2, T-56), and the HTTPS transport that presents it to `/access/v1` and the ADP over TLS 1.3, one HTTP/1.1 connection per call, every step under a bound (T-32 rule 7).

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::sign::{CertifiedKey, Signer as TlsSigner, SigningKey, SingleCertAndKey};
use rustls::{ClientConfig, RootCertStore, SignatureAlgorithm, SignatureScheme};
use sha2::{Digest as _, Sha256};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::Signer as _;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::domain::x509::{ecdsa_der, read, spki_of};
use crate::domain::{AccessError, b64url};
use crate::ports::{Method, Request, Response, Transport};

/// The token label of the PEP key and certificate (T-101 item 2).
pub const PEP_LABEL: &str = "work-access-pep";

/// Default bound of one call (T-32 rule 7).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest answer body read (PD).
pub const MAX_BODY: usize = 1_048_576;

fn store_error(e: &impl std::fmt::Display) -> AccessError {
    AccessError::KeyStore(e.to_string())
}

fn failed(e: &impl std::fmt::Display) -> AccessError {
    AccessError::Transport(e.to_string())
}

struct TokenKey {
    signer: Arc<Mutex<HsmSigner>>,
    scheme: SignatureScheme,
    algorithm: SignatureAlgorithm,
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenKey")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl SigningKey for TokenKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn TlsSigner>> {
        if !offered.contains(&self.scheme) {
            return None;
        }
        Some(Box::new(TokenSigning {
            signer: self.signer.clone(),
            scheme: self.scheme,
        }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

struct TokenSigning {
    signer: Arc<Mutex<HsmSigner>>,
    scheme: SignatureScheme,
}

impl std::fmt::Debug for TokenSigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSigning")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl TlsSigner for TokenSigning {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let raw = self
            .signer
            .lock()
            .map_err(|_| rustls::Error::General("token key poisoned".to_owned()))?
            .sign(message)
            .map_err(|_| rustls::Error::General("token key refused".to_owned()))?;
        if self.scheme == SignatureScheme::ED25519 {
            Ok(raw)
        } else {
            ecdsa_der(&raw).ok_or_else(|| rustls::Error::General("token key refused".to_owned()))
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// The PEP credential Access names the caller by, `x5t#S256` of its certificate (T-101 item 2).
pub struct PepCredential {
    certified: Arc<CertifiedKey>,
    not_after_ms: u64,
    x5t: [u8; 32],
}

impl std::fmt::Debug for PepCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PepCredential")
            .field("x5t#S256", &b64url(&self.x5t))
            .field("not_after_ms", &self.not_after_ms)
            .finish_non_exhaustive()
    }
}

/// The DER of the X.509 certificate object labelled `label` in the token.
fn token_certificate(
    module: &Path,
    token: &str,
    pin: &Secret<String>,
    label: &str,
) -> Result<Vec<u8>, AccessError> {
    let ctx = Pkcs11::new(module).map_err(|e| store_error(&e))?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(store_error(&e)),
    }
    let slot = ctx
        .get_slots_with_token()
        .map_err(|e| store_error(&e))?
        .into_iter()
        .find(|s| {
            ctx.get_token_info(*s)
                .is_ok_and(|i| i.label().trim_end() == token)
        })
        .ok_or_else(|| AccessError::KeyStore(format!("token {token}")))?;
    let session = ctx.open_ro_session(slot).map_err(|e| store_error(&e))?;
    match session.login(UserType::User, Some(&AuthPin::from(pin.expose().clone()))) {
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => return Err(store_error(&e)),
    }
    let found = session
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .map_err(|e| store_error(&e))?;
    let [one] = found.as_slice() else {
        return Err(AccessError::Certificate("one certificate object per label"));
    };
    session
        .get_attributes(*one, &[AttributeType::Value])
        .map_err(|e| store_error(&e))?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Value(v) => Some(v),
            _ => None,
        })
        .ok_or(AccessError::Certificate("certificate value"))
}

impl PepCredential {
    /// Loads the key and the certificate labelled `label` from the token: the certificate must
    /// be of that key. Nothing of it comes from the configuration (E-3, T-96 item 5).
    ///
    /// # Errors
    /// [`AccessError::KeyStore`] or [`AccessError::Certificate`].
    pub fn load(
        module: &Path,
        token: &str,
        pin: &Secret<String>,
        label: &str,
    ) -> Result<Self, AccessError> {
        let store = KeyStore::open(module, token, pin).map_err(|e| store_error(&e))?;
        let signer = store.signer(label).map_err(|e| store_error(&e))?;
        let der = token_certificate(module, token, pin, label)?;
        let facts = read(&der)?;
        let key = signer.public_key();
        if spki_of(&key).as_deref() != Some(facts.spki.as_slice()) {
            return Err(AccessError::Certificate("not of the token key"));
        }
        let (scheme, algorithm) = match key {
            PublicKey::Ed25519(_) => (SignatureScheme::ED25519, SignatureAlgorithm::ED25519),
            PublicKey::P256(_) => (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureAlgorithm::ECDSA,
            ),
            PublicKey::MlDsa(..) => return Err(AccessError::Certificate("key type")),
        };
        let x5t: [u8; 32] = Sha256::digest(&der).into();
        let signing = TokenKey {
            signer: Arc::new(Mutex::new(signer)),
            scheme,
            algorithm,
        };
        Ok(Self {
            certified: Arc::new(CertifiedKey::new(
                vec![CertificateDer::from(der)],
                Arc::new(signing),
            )),
            not_after_ms: facts.not_after_ms,
            x5t,
        })
    }

    /// The certificate's `notAfter`, Unix milliseconds.
    #[must_use]
    pub const fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    /// Seconds left at `now_ms`, for `work_access_pep_certificate_expiry_seconds`; zero once
    /// expired.
    #[must_use]
    pub fn expiry_seconds(&self, now_ms: u64) -> u64 {
        self.not_after_ms
            .saturating_sub(now_ms)
            .checked_div(1000)
            .unwrap_or_default()
    }

    /// Refuses a consequential action once the certificate has expired (T-101 item 2, T-28).
    ///
    /// # Errors
    /// [`AccessError::Expired`].
    pub const fn check(&self, now_ms: u64) -> Result<(), AccessError> {
        if now_ms > self.not_after_ms {
            Err(AccessError::Expired)
        } else {
            Ok(())
        }
    }

    /// `x5t#S256`, the name Access gives the PEP.
    #[must_use]
    pub fn x5t_s256(&self) -> String {
        b64url(&self.x5t)
    }

    /// The TLS key, signing inside the token.
    #[must_use]
    pub fn signing_key(&self) -> Arc<dyn SigningKey> {
        self.certified.key.clone()
    }

    /// TLS 1.3 settings that trust `roots` and present this certificate.
    ///
    /// # Errors
    /// [`AccessError::Transport`].
    pub fn client_config(&self, roots: RootCertStore) -> Result<Arc<ClientConfig>, AccessError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| failed(&e))?
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(self.certified.clone())));
        Ok(Arc::new(config))
    }
}

/// The roots of a PEM file that the server certificates of Access and Relay verify against.
///
/// # Errors
/// [`AccessError::Certificate`] for a file without certificates or with one that does not parse.
pub fn roots(pem: &[u8]) -> Result<RootCertStore, AccessError> {
    let mut store = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(pem) {
        let certificate = certificate.map_err(|_| AccessError::Certificate("roots"))?;
        store
            .add(certificate)
            .map_err(|_| AccessError::Certificate("roots"))?;
    }
    if store.is_empty() {
        return Err(AccessError::Certificate("roots"));
    }
    Ok(store)
}

/// TLS 1.3 settings that trust `roots` and present no certificate, for the public discovery
/// documents (T-96 item 2).
///
/// # Errors
/// [`AccessError::Transport`].
pub fn public_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, AccessError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| failed(&e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

struct Target {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

fn target(url: &str) -> Result<Target, AccessError> {
    let bad = || AccessError::Transport("not an https URL".to_owned());
    let rest = url.strip_prefix("https://").ok_or_else(bad)?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => rest.split_at_checked(i).ok_or_else(bad)?,
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains(['@', '[']) {
        return Err(bad());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad())?),
        None => (authority, 443),
    };
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    Ok(Target {
        host: host.to_owned(),
        port,
        authority: authority.to_owned(),
        path,
    })
}

/// The HTTPS transport: TLS 1.3 under the given settings, one connection per call.
#[derive(Clone)]
pub struct HttpsTransport {
    tls: Arc<ClientConfig>,
    bound: Duration,
}

impl std::fmt::Debug for HttpsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsTransport")
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

impl HttpsTransport {
    /// A transport over `tls` whose every call ends within `bound`.
    #[must_use]
    pub const fn new(tls: Arc<ClientConfig>, bound: Duration) -> Self {
        Self { tls, bound }
    }

    async fn exchange(&self, request: Request) -> Result<Response, AccessError> {
        let t = target(&request.url)?;
        let tcp = timeout(self.bound, TcpStream::connect((t.host.as_str(), t.port)))
            .await
            .map_err(|_| AccessError::Timeout)?
            .map_err(|e| failed(&e))?;
        let name = ServerName::try_from(t.host.clone()).map_err(|e| failed(&e))?;
        let stream = timeout(
            self.bound,
            TlsConnector::from(self.tls.clone()).connect(name, tcp),
        )
        .await
        .map_err(|_| AccessError::Timeout)?
        .map_err(|e| failed(&e))?;
        let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| failed(&e))?;
        let driver = tokio::spawn(conn);
        let method = match request.method {
            Method::Get => http::Method::GET,
            Method::Post => http::Method::POST,
        };
        let mut builder = http::Request::builder()
            .method(method)
            .uri(t.path)
            .header("host", t.authority);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let outgoing = builder
            .body(Full::new(Bytes::from(request.body)))
            .map_err(|e| failed(&e))?;
        let answer = async {
            let response = sender
                .send_request(outgoing)
                .await
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
            let body = Limited::new(response.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|e| failed(&e))?
                .to_bytes()
                .to_vec();
            Ok(Response {
                status,
                headers,
                body,
            })
        }
        .await;
        driver.abort();
        answer
    }
}

impl Transport for HttpsTransport {
    async fn send(&self, request: Request) -> Result<Response, AccessError> {
        timeout(self.bound, self.exchange(request))
            .await
            .map_err(|_| AccessError::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use suiss_crypto::sig::{PureBackend, ed25519};

    use super::*;
    use crate::app::Client;
    use crate::domain::discovery::Issuer;
    use crate::domain::eligibility::EligibilityRequest;
    use crate::domain::keys::tests::{module, pin, token};
    use crate::domain::keys::{AsOf, DomainId, KernelId, Kid};
    use crate::domain::x509::tests::{certificate, name};
    use crate::ports::Clock;

    const NOW: u64 = 1_793_793_600_000;

    struct At(u64);

    impl Clock for At {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    fn import(label: &str, der: &[u8]) {
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
                    .is_ok_and(|i| i.label().trim_end() == label)
            })
            .unwrap();
        let session = ctx.open_rw_session(slot).unwrap();
        match session.login(UserType::User, Some(&AuthPin::from(pin().expose().clone()))) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => panic!("{e}"),
        }
        session
            .create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Token(true),
                Attribute::Label(PEP_LABEL.as_bytes().to_vec()),
                Attribute::Subject(name(PEP_LABEL)),
                Attribute::Value(der.to_vec()),
            ])
            .unwrap();
    }

    /// A PEP key generated in a fresh token and a certificate of `spki_key`'s key until
    /// `not_after`, signed by the token key, as a token object of the PEP label.
    fn pep(test: &str, not_after: &str, other_key: bool) -> (String, Vec<u8>, PublicKey) {
        let (label, store) = token(test);
        let signer = store.generate_ed25519(PEP_LABEL).unwrap();
        let spki_key = if other_key {
            store.generate_ed25519("other").unwrap().public_key()
        } else {
            signer.public_key()
        };
        let der = certificate(&spki_of(&spki_key).unwrap(), not_after, |tbs| {
            signer.sign(tbs).unwrap()
        });
        import(&label, &der);
        (label, der, signer.public_key())
    }

    // T-101
    #[test]
    fn t_101_the_pep_certificate_and_its_key_come_from_the_token() {
        let (label, der, key) = pep("pep", "491231235959Z", false);
        let credential = PepCredential::load(&module(), &label, &pin(), PEP_LABEL).unwrap();
        let x5t: [u8; 32] = Sha256::digest(&der).into();
        assert_eq!(credential.x5t_s256(), b64url(&x5t));
        assert!(!format!("{credential:?}").contains("PRIVATE"));
        let signing = credential
            .signing_key()
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ])
            .unwrap();
        assert_eq!(signing.scheme(), SignatureScheme::ED25519);
        let signature = signing.sign(b"tls 1.3 certificate verify").unwrap();
        let PublicKey::Ed25519(pk) = key else {
            panic!("an Ed25519 key");
        };
        ed25519(&PureBackend, &pk, b"tls 1.3 certificate verify", &signature).unwrap();
        assert!(
            credential
                .signing_key()
                .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .is_none()
        );
        assert!(credential.client_config(RootCertStore::empty()).is_ok());
    }

    // T-101
    #[test]
    fn t_101_a_certificate_of_another_key_is_refused() {
        let (label, _, _) = pep("pep-other", "491231235959Z", true);
        assert_eq!(
            PepCredential::load(&module(), &label, &pin(), PEP_LABEL).unwrap_err(),
            AccessError::Certificate("not of the token key")
        );
    }

    // T-101
    #[test]
    fn t_101_an_expired_pep_certificate_refuses_consequential_actions() {
        let (label, _, _) = pep("pep-expired", "261104115959Z", false);
        let credential = PepCredential::load(&module(), &label, &pin(), PEP_LABEL).unwrap();
        assert_eq!(credential.check(NOW), Err(AccessError::Expired));
        assert_eq!(credential.expiry_seconds(NOW), 0);
        assert_eq!(credential.expiry_seconds(NOW.saturating_sub(10_000)), 9);
        let transport = HttpsTransport::new(
            credential.client_config(RootCertStore::empty()).unwrap(),
            DEFAULT_TIMEOUT,
        );
        let client = Client::new(
            transport,
            At(NOW),
            Issuer::parse("https://acme.id.example").unwrap(),
            "eu-central",
            credential.not_after_ms(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let keys = runtime.block_on(client.keys(DomainId([1; 32]), &[Kid([2; 32])], &AsOf::Head));
        assert_eq!(keys, Err(AccessError::Expired));
        let request =
            EligibilityRequest::new(KernelId([3; 16]), serde_json::Map::new(), None).unwrap();
        assert_eq!(
            runtime.block_on(client.eligibility(&request)),
            Err(AccessError::Expired)
        );
        assert_eq!(credential.check(NOW.saturating_sub(1000)), Ok(()));
    }

    // T-96
    #[test]
    fn t_96_the_server_certificates_verify_against_the_roots_of_one_pem_file() {
        let pem = include_bytes!("../../../deploy/compose/nts/pki/root.pem");
        let store = roots(pem).unwrap();
        assert_eq!(store.len(), 1);
        assert!(public_config(store).is_ok());
        assert_eq!(roots(b"").unwrap_err(), AccessError::Certificate("roots"));
        assert_eq!(
            roots(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").unwrap_err(),
            AccessError::Certificate("roots")
        );
    }

    // T-101
    #[test]
    fn t_101_calls_go_to_https_urls_only() {
        let t = target("https://access.example:8443/access/v1/keys/a?domain=x").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("access.example", 8443));
        assert_eq!(t.path, "/access/v1/keys/a?domain=x");
        let t = target("https://access.example").unwrap();
        assert_eq!((t.port, t.path.as_str()), (443, "/"));
        assert!(target("http://access.example/").is_err());
        assert!(target("https://u@access.example/").is_err());
    }
}
