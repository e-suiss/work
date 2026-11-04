//! An Access realm for tests (P-116, T-56): the realm's token key in a `SoftHSM` token of the test's own, its key set as the realm JWKS gives it, and the `auth_context` artifacts it signs, among them the one the golden ledger's human records carry, bound to each record's identifier.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use suiss_crypto::cose::{Algorithm, KeySet, PublicKey};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::{Digest, context_digest, sha256};
use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer as _, sign_sign1};

use crate::TestkitError;

/// The realm issuer of the golden human author (`party:acme:alice`).
pub const ISSUER: &str = "https://acme.suiss.example";

/// The `auth_time` of the golden context, before the golden ledger's first record.
pub const AUTH_TIME: u64 = 1_792_109_000_000;

/// An admission time after [`AUTH_TIME`], the golden ledger's first `recorded_at`.
pub const ADMITTED_AT: u64 = 1_792_109_100_000;

/// The content type of the artifact's `COSE_Sign1` (Access OP-149 m.8).
pub const ARTIFACT_CONTENT_TYPE: &str = "application/access-auth-context+cbor";

/// The content type a record binds the artifact to (P-116 item 2).
pub const RECORD_CONTENT_TYPE: &str = "application/work-record+cbor";

/// The context label of Access's `digest`.
pub const DIGEST_LABEL: &str = "suiss/auth-context/v1";

const PIN: &str = "4711";

static NEXT: AtomicU32 = AtomicU32::new(0);

static INIT: Mutex<()> = Mutex::new(());

fn module() -> PathBuf {
    std::env::var_os("PKCS11_MODULE").map_or_else(
        || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from,
    )
}

fn hsm(e: impl std::fmt::Display) -> TestkitError {
    TestkitError::Hsm(e.to_string())
}

fn label(s: &str) -> Value {
    Digest(sha256(format!("work-vector:{s}").as_bytes())).to_value()
}

/// The golden human context payload: `aal2`, no step-up, bound to `content` when given as a
/// content type and the 32 bytes it binds.
#[must_use]
pub fn payload(content: Option<(&str, [u8; 32])>) -> Value {
    let mut m = vec![
        (Value::text("v"), Value::Unsigned(1)),
        (Value::text("realm"), Value::text(ISSUER)),
        (Value::text("session_ref"), label("access:session:alice")),
        (Value::text("aal"), Value::text("aal2")),
        (
            Value::text("assurance_flags"),
            Value::Array(
                ["human_presence", "phishing_resistant", "uv"]
                    .into_iter()
                    .map(Value::text)
                    .collect(),
            ),
        ),
        (Value::text("auth_time"), Value::Unsigned(AUTH_TIME)),
        (Value::text("ais_digest"), label("access:ais:alice")),
    ];
    if let Some((content_type, digest)) = content {
        m.push((Value::text("content_type"), Value::text(content_type)));
        m.push((Value::text("content_digest"), Digest(digest).to_value()));
    }
    Value::Map(m)
}

/// The golden context of the record whose identifier is `record`.
#[must_use]
pub fn record_payload(record: [u8; 32]) -> Value {
    payload(Some((RECORD_CONTENT_TYPE, record)))
}

/// `SHA-256("suiss/auth-context/v1" ‖ 0x00 ‖ dCBOR(payload))`.
///
/// # Errors
/// [`TestkitError::Hsm`] when the payload does not encode.
pub fn digest(payload: &Value) -> Result<[u8; 32], TestkitError> {
    Ok(context_digest(DIGEST_LABEL, &encode(payload)?).0)
}

fn encode(v: &Value) -> Result<Vec<u8>, TestkitError> {
    dcbor::encode(v, Limits::CEILING).map_err(hsm)
}

/// The RFC 7638 thumbprint of an Ed25519 key.
#[must_use]
pub fn thumbprint(x: &[u8; 32]) -> [u8; 32] {
    let json = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(x)
    );
    sha256(json.as_bytes())
}

/// A signed artifact and Access's `digest` of its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    /// The tagged `COSE_Sign1`.
    pub cose: Vec<u8>,
    /// Access's `digest`.
    pub digest: [u8; 32],
}

/// A realm whose token key lives in a fresh `SoftHSM` token.
pub struct Realm {
    store: Arc<KeyStore>,
    signer: HsmSigner,
    kid: [u8; 32],
    keys: KeySet,
}

impl std::fmt::Debug for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Realm")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Makes a new `SoftHSM` token named after `test` and gives its label; `SoftHSM` finds only the
/// tokens made before a process first opens one, so a test that opens several tokens makes them
/// all first.
///
/// # Errors
/// [`TestkitError::Hsm`] when the token cannot be made.
pub fn token(test: &str) -> Result<String, TestkitError> {
    let label = format!(
        "realm-{test}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let _one = INIT.lock().map_err(hsm)?;
    let init = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            &label,
            "--so-pin",
            "12345678",
            "--pin",
            PIN,
        ])
        .output()
        .map_err(hsm)?;
    if init.status.success() {
        Ok(label)
    } else {
        Err(TestkitError::Hsm(
            String::from_utf8_lossy(&init.stderr).into_owned(),
        ))
    }
}

impl Realm {
    /// A realm with an Ed25519 token key in a new token named after `test`.
    ///
    /// # Errors
    /// [`TestkitError::Hsm`] when the token or the key cannot be made.
    pub fn open(test: &str) -> Result<Self, TestkitError> {
        Self::in_token(&token(test)?)
    }

    /// A realm with an Ed25519 token key in the token labelled `label`, made by [`token`].
    ///
    /// # Errors
    /// [`TestkitError::Hsm`] when the token cannot be opened or the key cannot be made.
    pub fn in_token(label: &str) -> Result<Self, TestkitError> {
        let store = {
            let _one = INIT.lock().map_err(hsm)?;
            KeyStore::open(&module(), label, &Secret::new(PIN.to_owned())).map_err(hsm)?
        };
        Self::with_key(Arc::new(store), "realm-token")
    }

    fn with_key(store: Arc<KeyStore>, label: &str) -> Result<Self, TestkitError> {
        let signer = store.generate_ed25519(label).map_err(hsm)?;
        let PublicKey::Ed25519(x) = signer.public_key() else {
            return Err(TestkitError::Hsm("not an Ed25519 key".to_owned()));
        };
        let kid = thumbprint(&x);
        let mut keys = KeySet {
            allowed: BTreeSet::from([Algorithm::Ed25519, Algorithm::Esp256]),
            ..KeySet::default()
        };
        keys.insert(kid, PublicKey::Ed25519(x)).map_err(hsm)?;
        Ok(Self {
            store,
            signer,
            kid,
            keys,
        })
    }

    /// Another realm whose key, labelled `label`, lives in the same token: a key the first
    /// realm's JWKS does not name.
    ///
    /// # Errors
    /// [`TestkitError::Hsm`] when the key cannot be made.
    pub fn another(&self, label: &str) -> Result<Self, TestkitError> {
        Self::with_key(Arc::clone(&self.store), label)
    }

    /// The realm key set, as the realm JWKS gives it.
    #[must_use]
    pub fn keys(&self) -> &KeySet {
        &self.keys
    }

    /// The `kid` of the token key.
    #[must_use]
    pub fn kid(&self) -> [u8; 32] {
        self.kid
    }

    /// `payload_bytes` signed as Access signs an artifact, under `content_type`.
    ///
    /// # Errors
    /// [`TestkitError::Hsm`] when the token does not sign.
    pub fn sign_as(
        &self,
        content_type: &str,
        payload_bytes: &[u8],
    ) -> Result<Vec<u8>, TestkitError> {
        sign_sign1(&self.signer, self.kid, content_type, payload_bytes).map_err(hsm)
    }

    /// The artifact of `payload`.
    ///
    /// # Errors
    /// [`TestkitError::Hsm`] when it does not encode or sign.
    pub fn artifact(&self, payload: &Value) -> Result<Artifact, TestkitError> {
        let bytes = encode(payload)?;
        Ok(Artifact {
            cose: self.sign_as(ARTIFACT_CONTENT_TYPE, &bytes)?,
            digest: context_digest(DIGEST_LABEL, &bytes).0,
        })
    }

    /// The golden artifact of the record whose identifier is `record`.
    ///
    /// # Errors
    /// As [`Realm::artifact`].
    pub fn for_record(&self, record: [u8; 32]) -> Result<Artifact, TestkitError> {
        self.artifact(&record_payload(record))
    }
}

/// The paired realms of the golden tenant: [`ISSUER`].
#[must_use]
pub fn paired() -> BTreeSet<String> {
    BTreeSet::from([ISSUER.to_owned()])
}
