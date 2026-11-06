//! The caller of a request named from a real Access user token (T-104, C-9, E-7, T-97, P-56): the `acme` test user signs in through Access's real authorization code flow with PKCE, a `DPoP` key born in Work's token copy and `resource` naming Work's `client_id`; the token Access's own headless client got names Work too and stays bound to that client's key; the caller is named to the test user's Party, and `work-server` serves its reads for that caller only. `just test-compose-signed` runs them after `signed::wait_until_access_signs_tokens`, with `WORK_ACCESS_LOCAL` naming the directory `just dev-access` filled and `SOFTHSM2_CONF` naming its token copy; `retired` runs around retiring Work's client, at the end of the CI compose job.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unused_self,
    reason = "test code"
)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
use suiss_crypto::secret::Secret;
use suiss_crypto::sig::{P256_HALF_N, P256_N};
use suiss_crypto::signer::Signer as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use work_access_client::adapters::{
    DEFAULT_TIMEOUT, HttpsTransport, PEP_LABEL, PepCredential, public_config,
};
use work_access_client::app::Client;
use work_access_client::domain::discovery::{Issuer, SUISS_CONFIGURATION};
use work_access_client::domain::metadata::thumbprint;
use work_access_client::domain::subjects::Direction;
use work_access_client::domain::token::token_hash;
use work_access_client::domain::{b64url, from_b64url};
use work_access_client::ports::Clock;
use work_kernel::id::{Digest, LedgerId, WorkId};
use work_proto::id::ExternalId as _;

const REGION: &str = "eu";
const TOKEN: &str = "work-dev";
const PIN: &str = "1234";
const WORK: &str = "http://127.0.0.1:8190";
const DPOP_LABEL: &str = "work-test-user-dpop";
const ACCESS_TOKEN: &str = "access-server";
const ACCESS_PIN_FILE: &str = "access-hsm-pin";
const PASSKEY_LABEL: &str = "access/bootstrap/test-user-passkey";
const RETIRED_TOKEN: &str = "retired-token";
const POLL: Duration = Duration::from_secs(30);

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

fn der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    STANDARD.decode(body).unwrap()
}

/// Unix seconds of an RFC 9110 IMF-fixdate such as `Thu, 05 Nov 2026 04:42:06 GMT`.
fn imf_fixdate_s(date: &str) -> u64 {
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
    u64::try_from(days * 86_400 + n(hour) * 3600 + n(minute) * 60 + n(second)).unwrap()
}

/// One HTTP answer.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.status, self.text())
    }
}

async fn exchange<I>(io: I, request: http::Request<Full<Bytes>>) -> Answer
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut send, connection) = http1::handshake(TokioIo::new(io)).await.unwrap();
    tokio::spawn(connection);
    let response = send.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_owned(),
                v.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        headers,
        body: body.to_vec(),
    }
}

/// What `just dev-access` copied out of the local Access, and the test's `DPoP` key.
struct Local {
    dir: PathBuf,
    bootstrap: Value,
    seed: u64,
    fresh: AtomicU64,
}

impl Local {
    fn open() -> Self {
        let dir = PathBuf::from(
            std::env::var_os("WORK_ACCESS_LOCAL")
                .expect("WORK_ACCESS_LOCAL names the directory `just dev-access` fills"),
        );
        let bootstrap =
            serde_json::from_slice(&std::fs::read(dir.join("bootstrap.json")).unwrap()).unwrap();
        let seed = std::process::id().into();
        Self {
            dir,
            bootstrap,
            seed,
            fresh: AtomicU64::new(0),
        }
    }

    fn realm(&self, slug: &str) -> &Value {
        self.bootstrap["realms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["slug"] == slug)
            .unwrap()
    }

    fn issuer(&self, slug: &str) -> String {
        self.realm(slug)["issuer"].as_str().unwrap().to_owned()
    }

    fn work_client(&self) -> String {
        self.bootstrap["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["product"] == "work")
            .unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn user(&self, key: &str) -> String {
        self.bootstrap["test_user"][key]
            .as_str()
            .unwrap_or_else(|| panic!("test_user.{key}"))
            .to_owned()
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        let ca = std::fs::read_to_string(self.dir.join("ca.crt")).unwrap();
        roots.add(CertificateDer::from(der(&ca))).unwrap();
        roots
    }

    fn pep(&self) -> PepCredential {
        PepCredential::load(&module(), TOKEN, &Secret::new(PIN.to_owned()), PEP_LABEL).unwrap()
    }

    /// The test user's software passkey (Access A23): the Ed25519 key the bootstrap registered,
    /// in the copy of Access's token `just dev-access` made (T-56).
    fn passkey(&self) -> HsmSigner {
        let pin = std::fs::read_to_string(self.dir.join(ACCESS_PIN_FILE)).unwrap();
        KeyStore::open(&module(), ACCESS_TOKEN, &Secret::new(pin.trim().to_owned()))
            .unwrap()
            .signer(PASSKEY_LABEL)
            .unwrap()
    }

    /// The `WebAuthn` assertion of the passkey over the challenge of the login `step`'s
    /// `passkey_get` node, as the realm's software authenticator answers it (W3C `WebAuthn`
    /// Level 3 sections 6.1, 7.2): user present and verified, no counter.
    fn passkey_assertion(&self, issuer: &str, step: &Value) -> Value {
        let options = step["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["type"] == "passkey_get")
            .unwrap_or_else(|| panic!("{step}"))["options"]
            .clone();
        let challenge = options["challenge"].as_str().unwrap();
        let authority = issuer
            .strip_prefix("https://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        let host = authority.split(':').next().unwrap();
        let key = self.passkey();
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": format!("https://{authority}"),
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes();
        let mut authenticator_data = Sha256::digest(host.as_bytes()).to_vec();
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature = key.sign(&message).unwrap();
        let id = b64url(&thumbprint(&key.public_key()));
        json!({
            "id": id, "rawId": id, "type": "public-key",
            "response": {
                "clientDataJSON": b64url(&client_data),
                "authenticatorData": b64url(&authenticator_data),
                "signature": b64url(&signature),
            },
            "clientExtensionResults": {},
        })
    }

    /// The test's `DPoP` key, born in the token copy the first time and kept there (T-56).
    fn dpop(&self) -> HsmSigner {
        let store = KeyStore::open(&module(), TOKEN, &Secret::new(PIN.to_owned())).unwrap();
        store
            .signer(DPOP_LABEL)
            .or_else(|_| store.generate_p256(DPOP_LABEL))
            .unwrap()
    }

    /// An RFC 9562 version 7 UUID of `ms` no other call of this process sees, for an
    /// `Idempotency-Key`.
    fn uuid7(&self, ms: u64) -> String {
        let mut b = [0_u8; 16];
        b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
        b[6..].copy_from_slice(&from_b64url(&self.random()).unwrap()[..10]);
        b[6] = (b[6] & 0x0f) | 0x70;
        b[8] = (b[8] & 0x3f) | 0x80;
        let hex: String = b.iter().fold(String::new(), |mut out, x| {
            let _ = write!(out, "{x:02x}");
            out
        });
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    }

    /// 32 bytes no other call of this process sees, base64url.
    fn random(&self) -> String {
        let n = self.fresh.fetch_add(1, Ordering::SeqCst);
        let mut h = Sha256::new();
        h.update(self.seed.to_be_bytes());
        h.update(n.to_be_bytes());
        h.update(self.dir.as_os_str().as_encoded_bytes());
        b64url(&h.finalize())
    }

    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, Vec<u8>)>,
    ) -> Answer {
        let (https, rest) = match url.strip_prefix("https://") {
            Some(rest) => (true, rest),
            None => (false, url.strip_prefix("http://").unwrap()),
        };
        let slash = rest.find('/').unwrap_or(rest.len());
        let (authority, path) = rest.split_at(slash);
        let (host, port) = authority.rsplit_once(':').map_or_else(
            || (authority, if https { 443 } else { 80 }),
            |(h, p)| (h, p.parse::<u16>().unwrap()),
        );
        let mut request = http::Request::builder()
            .method(method)
            .uri(if path.is_empty() { "/" } else { path })
            .header("host", authority);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let bytes = match body {
            Some((content_type, bytes)) => {
                request = request.header("content-type", content_type);
                bytes
            }
            None => Vec::new(),
        };
        let request = request.body(Full::new(Bytes::from(bytes))).unwrap();
        let tcp = TcpStream::connect((host, port)).await.unwrap();
        if https {
            let tls = TlsConnector::from(public_config(self.roots()).unwrap())
                .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
                .await
                .unwrap();
            exchange(tls, request).await
        } else {
            exchange(tcp, request).await
        }
    }

    /// Access's time, Unix seconds, from the `Date` of its answer.
    async fn access_now_s(&self) -> u64 {
        let issuer = Issuer::parse(&self.issuer("acme")).unwrap();
        let answer = self
            .send("GET", &issuer.well_known(SUISS_CONFIGURATION), &[], None)
            .await;
        imf_fixdate_s(answer.header("date").unwrap())
    }

    /// A `DPoP` proof for `method url` by `key`, with `nonce` and `ath` of `token` when given
    /// (RFC 9449 section 4.2).
    async fn proof(
        &self,
        key: &HsmSigner,
        method: &str,
        url: &str,
        nonce: Option<&str>,
        token: Option<&str>,
    ) -> String {
        let mut claims = json!({
            "jti": self.random(),
            "htm": method,
            "htu": url,
            "iat": self.access_now_s().await,
        });
        if let Some(n) = nonce {
            claims["nonce"] = json!(n);
        }
        if let Some(t) = token {
            claims["ath"] = json!(token_hash(t));
        }
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk(&key.public_key())});
        jws(key, &header, &claims)
    }

    /// The Access client of the platform realm over Work's PEP certificate, at Access's now.
    async fn client(&self) -> Arc<Client<HttpsTransport, At>> {
        let pep = self.pep();
        let now = self.access_now_s().await * 1000;
        let client = Client::new(
            HttpsTransport::new(pep.client_config(self.roots()).unwrap(), DEFAULT_TIMEOUT),
            At(now),
            Issuer::parse(&self.issuer("platform")).unwrap(),
            REGION,
            pep.not_after_ms(),
        );
        client.discover().await.unwrap();
        Arc::new(client)
    }

    /// The Party Access resolves `token`'s pairwise `sub` to, asked directly (T-104): the test
    /// user's, `test_user.party`.
    async fn party_of(&self, token: &str) -> String {
        let claims = payload(token);
        let access = self.client().await;
        let realm = access
            .realm_of(claims["iss"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        let sub = claims["sub"].as_str().unwrap().to_owned();
        let found = access
            .resolve(
                &realm.tenant,
                &realm.realm,
                claims["client_id"].as_str().unwrap(),
                Direction::Subs,
                std::slice::from_ref(&sub),
            )
            .await
            .unwrap();
        let party = found
            .get(&sub)
            .cloned()
            .flatten()
            .expect("Access binds the test user to a Party");
        assert_eq!(party, self.user("party"));
        party
    }

    /// The test user's sign-in (RFC 6749 section 4.1, RFC 7636, RFC 9449, RFC 8707): `/authorize`
    /// sends the browser to the hosted login, whose JSON steps sign the user in, and the code is
    /// exchanged at `/token` with the PKCE verifier and a proof of `key`; the token is for
    /// Work's `client_id`.
    async fn login(&self, key: &HsmSigner) -> Result<Value, Answer> {
        self.session(key, false).await.map(|(tokens, _)| tokens)
    }

    /// The sign-in of [`Local::login`], with the password and the passkey as its second factor
    /// or, `passkey_first`, with the passkey alone (AAL2), and the realm session's cookies.
    async fn session(&self, key: &HsmSigner, passkey_first: bool) -> Result<(Value, Jar), Answer> {
        let issuer = self.issuer("acme");
        let client_id = self.user("client_id");
        let redirect = self.user("redirect_uri");
        let resource = self.work_client();
        let verifier = self.random();
        let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
        let state = self.random();
        let jkt = b64url(&thumbprint(&key.public_key()));
        let authorize = format!(
            "{issuer}/authorize?{}",
            form(&[
                ("client_id", &client_id),
                ("redirect_uri", &redirect),
                ("response_type", "code"),
                ("scope", "openid"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("state", &state),
                ("nonce", &self.random()),
                ("dpop_jkt", &jkt),
                ("resource", &resource),
            ])
        );
        let first = self.send("GET", &authorize, &[], None).await;
        let to_login = located(&first)?;
        let return_to = query(&to_login, "return_to").ok_or(first)?;
        let mut jar = Jar::default();
        let flows = format!("{issuer}/v1/login/flows");
        let started = self.post_json(&flows, &mut jar, None).await;
        if started.status != 201 {
            return Err(started);
        }
        let identified = self
            .post_json(
                &format!("{issuer}{}", started.json()["action"].as_str().unwrap_or_default()),
                &mut jar,
                Some(json!({"method": "identifier", "fields": {"identifier": self.user("identifier")}})),
            )
            .await;
        if identified.status != 200 || identified.json()["step"] != "authenticate" {
            return Err(identified);
        }
        let password = std::env::var("ACCESS_LOCAL_TEST_PASSWORD")
            .unwrap_or_else(|_| "local-only-not-a-secret".to_owned());
        let first = if passkey_first {
            let assertion = self.passkey_assertion(&issuer, &identified.json());
            json!({"method": "passkey", "fields": {"passkey_credential": assertion.to_string()}})
        } else {
            json!({"method": "password", "fields": {"password": password}})
        };
        let mut signed_in = self
            .post_json(
                &format!(
                    "{issuer}{}",
                    identified.json()["action"].as_str().unwrap_or_default()
                ),
                &mut jar,
                Some(first),
            )
            .await;
        if signed_in.status == 200 && signed_in.json()["step"] == "second_factor" {
            let step = signed_in.json();
            let assertion = self.passkey_assertion(&issuer, &step);
            signed_in = self
                .post_json(
                    &format!("{issuer}{}", step["action"].as_str().unwrap_or_default()),
                    &mut jar,
                    Some(json!({
                        "method": "passkey",
                        "fields": {"passkey_credential": assertion.to_string()},
                    })),
                )
                .await;
        }
        if signed_in.status != 200 || signed_in.json()["step"] != "complete" {
            return Err(signed_in);
        }
        let origin = issuer.split("/realms/").next().unwrap();
        let cookies = jar.header();
        let back = self
            .send(
                "GET",
                &format!("{origin}{return_to}"),
                &[("cookie", &cookies)],
                None,
            )
            .await;
        let redirected = located(&back)?;
        if !redirected.starts_with(&redirect)
            || query(&redirected, "state").as_deref() != Some(state.as_str())
            || query(&redirected, "iss").as_deref() != Some(issuer.as_str())
        {
            return Err(back);
        }
        let code = query(&redirected, "code").ok_or(back)?;
        let token_url = format!("{issuer}/token");
        let body = form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("code", &code),
            ("redirect_uri", &redirect),
            ("code_verifier", &verifier),
            ("resource", &resource),
        ]);
        let mut nonce: Option<String> = None;
        loop {
            let proof = self
                .proof(key, "POST", &token_url, nonce.as_deref(), None)
                .await;
            let answer = self
                .send(
                    "POST",
                    &token_url,
                    &[("dpop", &proof)],
                    Some((
                        "application/x-www-form-urlencoded",
                        body.clone().into_bytes(),
                    )),
                )
                .await;
            if answer.status == 200 {
                return Ok((answer.json(), jar));
            }
            match answer.header("dpop-nonce") {
                Some(n) if nonce.is_none() && answer.json()["error"] == "use_dpop_nonce" => {
                    nonce = Some(n.to_owned());
                }
                _ => return Err(answer),
            }
        }
    }

    async fn post_json(&self, url: &str, jar: &mut Jar, body: Option<Value>) -> Answer {
        let key = self.random();
        let cookies = jar.header();
        let mut headers = vec![("idempotency-key", key.as_str())];
        if !cookies.is_empty() {
            headers.push(("cookie", cookies.as_str()));
        }
        let bytes = body.as_ref().map_or_else(String::new, ToString::to_string);
        let answer = self
            .send(
                "POST",
                url,
                &headers,
                Some(("application/json", bytes.into_bytes())),
            )
            .await;
        jar.take(&answer);
        answer
    }

    /// The access token of a sign-in that succeeds, once Access's sign-in throttle lets it.
    async fn token(&self, key: &HsmSigner) -> String {
        let mut tokens = self.login(key).await;
        for _ in 0..6 {
            match &tokens {
                Err(answer) if answer.status == 429 => {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    tokens = self.login(key).await;
                }
                _ => break,
            }
        }
        let tokens = tokens.unwrap();
        assert_eq!(tokens["token_type"], "DPoP", "{tokens}");
        tokens["access_token"].as_str().unwrap().to_owned()
    }

    /// `GET` of `path` on `work-server` with `token` and a fresh proof of `key`.
    async fn read(&self, key: &HsmSigner, path: &str, token: &str) -> Answer {
        let url = format!("{WORK}{path}");
        let proof = self.proof(key, "GET", &url, None, Some(token)).await;
        let authorization = format!("DPoP {token}");
        self.send(
            "GET",
            &url,
            &[("authorization", &authorization), ("dpop", &proof)],
            None,
        )
        .await
    }
}

/// `sig` with its S in the lower half of the group order (CR-9).
fn low_s(mut sig: Vec<u8>) -> Vec<u8> {
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if s.as_slice() > P256_HALF_N.as_slice() {
        let mut out = [0_u8; 32];
        let mut borrow = 0_u16;
        for i in (0..32).rev() {
            let d = u16::from(P256_N[i])
                .wrapping_add(256)
                .wrapping_sub(u16::from(s[i]))
                .wrapping_sub(borrow);
            out[i] = d.to_le_bytes()[0];
            borrow = u16::from(d < 256);
        }
        sig[32..].copy_from_slice(&out);
    }
    sig
}

fn jws(key: &HsmSigner, header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    let sig = low_s(key.sign(input.as_bytes()).unwrap());
    format!("{input}.{}", b64url(&sig))
}

fn jwk(key: &PublicKey) -> Value {
    let PublicKey::P256(sec1) = key else {
        panic!("the DPoP key is P-256");
    };
    json!({"kty": "EC", "crv": "P-256", "x": b64url(&sec1[1..33]), "y": b64url(&sec1[33..65])})
}

/// The claims of a compact JWT, unverified.
fn payload(jwt: &str) -> Value {
    let part = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&from_b64url(part).unwrap()).unwrap()
}

fn names(aud: &Value, client_id: &str) -> bool {
    match aud {
        Value::String(a) => a == client_id,
        Value::Array(all) => all.iter().any(|a| a == client_id),
        _ => false,
    }
}

fn encode(s: &str, out: &mut String) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (k, v) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        encode(k, &mut out);
        out.push('=');
        encode(v, &mut out);
    }
    out
}

fn decode(s: &str) -> Option<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                out.push(u8::from_str_radix(s.get(i + 1..i + 3)?, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn query(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| decode(v))
}

/// The `Location` of a `303` that carries no OAuth `error`.
fn located(answer: &Answer) -> Result<String, Answer> {
    match answer.header("location") {
        Some(l) if answer.status == 303 && query(l, "error").is_none() => Ok(l.to_owned()),
        _ => Err(Answer {
            status: answer.status,
            headers: answer.headers.clone(),
            body: answer.body.clone(),
        }),
    }
}

/// A browser's cookies, name by name.
#[derive(Default)]
struct Jar(Vec<(String, String)>);

impl Jar {
    fn take(&mut self, answer: &Answer) {
        for c in answer.all("set-cookie") {
            let Some((name, value)) = c.split(';').next().and_then(|nv| nv.split_once('=')) else {
                continue;
            };
            self.0.retain(|(n, _)| n != name);
            if !c.to_ascii_lowercase().contains("max-age=0") {
                self.0.push((name.to_owned(), value.to_owned()));
            }
        }
    }

    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// What `work-server` answers a named caller's read or write of a ledger it does not hold
/// (T-104): `404 not_found`.
const UNSEEN: (u16, &str) = (404, "https://suiss.app/ns/work/problems/not_found");

fn ledger_path() -> (String, String) {
    let ledger = LedgerId(Digest::sha256([0x4c; 32])).to_external();
    let work = WorkId::from_bytes([0x57; 16]).to_external();
    (
        format!("/v1/ledgers/{ledger}/works/{work}"),
        format!("/v1/ledgers/{ledger}/changes"),
    )
}

/// What needs Access's new realms to sign tokens (T-104, T-97).
mod signed {
    use std::sync::Arc;

    use serde_json::{Value, json};
    use suiss_crypto::signer::Signer as _;
    use work_access_client::app::Looked;
    use work_access_client::domain::b64url;
    use work_access_client::domain::keys::{AsOf, DomainId, KernelId, Kid};
    use work_access_client::domain::metadata::thumbprint;
    use work_access_client::domain::subjects::Direction;
    use work_proto::id::TenantId;
    use work_query::app::caller::Authenticator;
    use work_query::domain::caller::{CallerRefusal, Presented};
    use work_query::domain::writes::{actor_type, signer};

    use super::{Local, POLL, UNSEEN, WORK, ledger_path, names, payload};

    fn wait_s() -> u64 {
        std::env::var("WORK_ACCESS_SIGNED_WAIT_S")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }

    // T-104 T-28
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment"]
    async fn wait_until_access_signs_tokens() {
        let local = Local::open();
        let key = local.dpop();
        let polls = wait_s() / POLL.as_secs();
        let mut polled = 0;
        loop {
            match local.login(&key).await {
                Ok(_) => break,
                Err(answer) if answer.status == 503 && polled < polls => {
                    polled += 1;
                    tokio::time::sleep(POLL).await;
                }
                Err(answer) => panic!("{answer:?}"),
            }
        }
    }

    // T-104 C-9 E-7 P-116
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its realms signing"]
    async fn t_104_a_real_user_token_names_the_test_user_by_its_party() {
        let local = Local::open();
        let key = local.dpop();
        let token = local.token(&key).await;
        let claims = payload(&token);
        let work = local.work_client();
        assert_eq!(claims["iss"], local.issuer("acme"));
        assert!(names(&claims["aud"], &work), "{claims}");
        assert_eq!(claims["cnf"]["jkt"], b64url(&thumbprint(&key.public_key())));
        let access = local.client().await;
        let auth = Authenticator::new(Arc::clone(&access), Some(work));
        let url = format!("{WORK}{}", ledger_path().0);
        let proof = local.proof(&key, "GET", &url, None, Some(&token)).await;
        let authorization = format!("DPoP {token}");
        let presented = Presented {
            authorization: Some(&authorization),
            dpop: Some(&proof),
            method: "GET",
            url: &url,
        };
        let party = local.party_of(&token).await;
        let caller = auth.caller(presented).await.unwrap();
        let acme = local.realm("acme");
        assert_eq!(
            caller.tenant,
            TenantId::new(acme["tenant"].as_str().unwrap()).unwrap()
        );
        assert_eq!(caller.realm, acme["realm"].as_str().unwrap());
        assert_eq!(caller.issuer, local.issuer("acme"));
        assert_eq!(caller.client_id, local.user("client_id"));
        assert_eq!(b64url(&caller.party_id), party);
        assert_eq!(caller.party.as_str(), party);
        let back = access
            .resolve(
                &caller.tenant,
                &caller.realm,
                &caller.client_id,
                Direction::Parties,
                std::slice::from_ref(&party),
            )
            .await
            .unwrap();
        assert_eq!(
            back.get(&party),
            Some(&claims["sub"].as_str().map(str::to_owned))
        );
        let again = auth.caller(presented).await;
        assert!(
            matches!(again, Err(CallerRefusal::Unauthenticated(_))),
            "{again:?}"
        );
    }

    // T-97 P-56 C-9 SEC-18 E-7
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its realms signing"]
    async fn t_97_work_server_names_the_test_user_and_answers_only_what_it_may_see() {
        let local = Local::open();
        let key = local.dpop();
        let token = local.token(&key).await;
        local.party_of(&token).await;
        let (status, problem) = UNSEEN;
        let (work, changes) = ledger_path();
        let anonymous = local.send("GET", &format!("{WORK}{work}"), &[], None).await;
        assert_eq!(anonymous.status, 401, "{anonymous:?}");
        assert!(
            anonymous
                .header("www-authenticate")
                .is_some_and(|c| c.starts_with("DPoP"))
        );
        let authorization = format!("DPoP {token}");
        let unproved = local
            .send(
                "GET",
                &format!("{WORK}{work}"),
                &[("authorization", &authorization)],
                None,
            )
            .await;
        assert_eq!(unproved.status, 401, "{unproved:?}");
        for path in [&work, &changes] {
            let named = local.read(&key, path, &token).await;
            assert_eq!(named.status, status, "{path}: {named:?}");
            assert_eq!(named.json()["type"], problem, "{named:?}");
        }
        let url = format!("{WORK}{work}");
        let proof = local.proof(&key, "GET", &url, None, Some(&token)).await;
        let headers = [("authorization", authorization.as_str()), ("dpop", &proof)];
        assert_eq!(local.send("GET", &url, &headers, None).await.status, status);
        let replayed = local.send("GET", &url, &headers, None).await;
        assert_eq!(replayed.status, 401, "{replayed:?}");
    }

    /// The golden promise's tagged `COSE_Sign1`: a record the write path decodes, so a named
    /// caller reaches the ledger check.
    pub(super) fn golden_promise() -> String {
        const COSE: &str = include_str!("../../../../conformance/vectors/records/cose-sign1.json");
        let cose: Value = serde_json::from_str(COSE).unwrap();
        let hex = cose["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "cose-sign1/declaration-promise-for-principal")
            .unwrap()["cose_hex"]
            .as_str()
            .unwrap();
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        b64url(&bytes)
    }

    // E-17 MD-4 T-28 C-9 SEC-18 P-13
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its realms signing"]
    async fn e_17_work_server_writes_a_declaration_only_for_a_named_caller() {
        let local = Local::open();
        let key = local.dpop();
        let token = local.token(&key).await;
        local.party_of(&token).await;
        let path = format!(
            "{}/declarations",
            ledger_path().1.trim_end_matches("/changes")
        );
        let url = format!("{WORK}{path}");
        let body = serde_json::to_vec(&json!({
            "record": golden_promise(),
            "authority": {"exercise": b64url(&[0x5e; 32]), "intent": b64url(b"intent")},
            "actor_types": {"author": "agent", "on_behalf_of": ["organization"]},
        }))
        .unwrap();
        let uuid7 = "01890a5d-ac96-774b-bcce-b302099a8057";
        let headers = [("idempotency-key", uuid7), ("if-match", "\"0\"")];
        let anonymous = local
            .send(
                "POST",
                &url,
                &headers,
                Some(("application/json", body.clone())),
            )
            .await;
        assert_eq!(anonymous.status, 401, "{anonymous:?}");
        assert!(
            anonymous
                .header("www-authenticate")
                .is_some_and(|c| c.starts_with("DPoP"))
        );
        let proof = local.proof(&key, "POST", &url, None, Some(&token)).await;
        let authorization = format!("DPoP {token}");
        let mut named = headers.to_vec();
        named.push(("authorization", authorization.as_str()));
        named.push(("dpop", proof.as_str()));
        let answer = local
            .send("POST", &url, &named, Some(("application/json", body)))
            .await;
        let (status, problem) = UNSEEN;
        assert_eq!(answer.status, status, "{answer:?}");
        assert_eq!(answer.json()["type"], problem, "{answer:?}");
    }

    // P-12 MD-7 INV-18 P-105 T-101
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its realms signing"]
    async fn p_12_a_real_key_signs_for_its_party_with_the_actor_kind_access_recorded() {
        let local = Local::open();
        let root = &local.bootstrap["root"];
        let party = KernelId::parse(root["party"].as_str().unwrap()).unwrap();
        let kid = Kid::parse(root["kid"].as_str().unwrap()).unwrap();
        let domain = DomainId(
            work_access_client::domain::fixed_b64url(
                local.realm("acme")["domain"].as_str().unwrap(),
            )
            .unwrap(),
        );
        let access = local.client().await;
        let looked = access.keys(domain, &[kid], &AsOf::Head).await.unwrap();
        let [Looked::Known(found)] = looked.as_slice() else {
            panic!("{looked:?}");
        };
        let signer = signer(Some(&found.key));
        let (named, actor) = signer.party.unwrap();
        assert_eq!(named.as_str(), b64url(&party.0));
        assert_eq!(actor, actor_type(found.key.actor_kind));
        assert_eq!(signer.keys.keys.len(), 1);
        assert!(signer.keys.keys.contains_key(&kid.0));
    }

    // T-104 C-9 E-7
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment, its realms signing and the login of Access's client"]
    async fn t_104_the_token_of_access_s_own_client_names_work_and_stays_bound_to_its_key() {
        let local = Local::open();
        let tool: Value =
            serde_json::from_slice(&std::fs::read(local.dir.join("tool-login.json")).unwrap())
                .unwrap();
        assert_eq!(tool["token_type"], "DPoP", "{tool}");
        assert_eq!(tool["instance"], json!(local.user("instance")), "{tool}");
        let token = tool["access_token"].as_str().unwrap();
        let claims = payload(token);
        assert!(names(&claims["aud"], &local.work_client()), "{claims}");
        assert_eq!(claims["cnf"]["jkt"], tool["dpop_jkt"]);
        let key = local.dpop();
        assert_ne!(
            tool["dpop_jkt"],
            json!(b64url(&thumbprint(&key.public_key())))
        );
        let foreign = local.read(&key, &ledger_path().0, token).await;
        assert_eq!(foreign.status, 401, "{foreign:?}");
    }
}

/// Around retiring Work's platform client, the last step of the CI compose job (T-102 item 5,
/// T-28): before it the test user is named by its Party, and once
/// `api_client.disabled` arrived no caller is.
mod retired {
    use super::{Local, RETIRED_TOKEN, UNSEEN, ledger_path};

    // T-102 T-97
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment and its realms signing"]
    async fn t_102_before_work_s_client_is_retired_the_test_user_is_named() {
        let local = Local::open();
        let key = local.dpop();
        let token = local.token(&key).await;
        local.party_of(&token).await;
        let named = local.read(&key, &ledger_path().0, &token).await;
        assert_eq!(named.status, UNSEEN.0, "{named:?}");
        std::fs::write(local.dir.join(RETIRED_TOKEN), &token).unwrap();
    }

    // T-102 T-28
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with Work's client retired"]
    async fn t_102_once_work_s_client_is_disabled_no_caller_is_named() {
        let local = Local::open();
        let key = local.dpop();
        let token = std::fs::read_to_string(local.dir.join(RETIRED_TOKEN)).unwrap();
        let refused = local.read(&key, &ledger_path().0, &token).await;
        assert_eq!(refused.status, 503, "{refused:?}");
        assert_eq!(
            refused.json()["type"],
            "https://suiss.app/ns/work/problems/authority_unverifiable",
            "{refused:?}"
        );
    }
}

/// The commitment write against the real Access (E-17, P-13, T-101, SEC-36, WD-124, WD-125): a
/// ledger opens in `work-server`'s cell; the test user asks `work-server`'s
/// `POST /v1/authority-requests` with the `work:commit` intent Work's client builds and an AIS of
/// the user's own device key, Work's PEP commits it at the ADP and answers `REQUIRE_ACTION` with
/// the typed authority request; the CI job has Access's `approve` tool approve that request with
/// the user's passkey; the user asks again with the contribution and Work's PEP answers the
/// allowed Exercise with its verified receipt.
/// `work-server` then refuses a tampered intent and a capacity the Exercise does not carry,
/// writes the user's unsigned Declaration under the user's AAL2 `auth_context`, keeps the
/// receipt the record's `authority` names, and marks the record once Access declares the user's
/// Party compromised.
mod commit {
    use std::time::Duration;

    use serde_json::{Value, json};
    use suiss_crypto::cose::PublicKey;
    use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
    use suiss_crypto::digest::sha256;
    use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
    use suiss_crypto::secret::Secret;
    use suiss_crypto::signer::{Signer as _, sign_sign1};
    use work_access_client::domain::adp::{self, Action, Holding, Statement};
    use work_access_client::domain::exercise::{
        Capacity as Held, ExerciseId, Intent, VerifiedExercise,
    };
    use work_access_client::domain::keys::{DomainId, KernelId};
    use work_access_client::domain::metadata::thumbprint;
    use work_access_client::domain::{b64url, fixed_b64url, from_b64url};
    use work_kernel::codec::{Decoded, decode_record, record_id};
    use work_kernel::id::{Digest, LedgerId};
    use work_kernel::record::Record;
    use work_kernel::rules::RuleSet;
    use work_ledger::{GenesisInput, SystemRng, genesis};
    use work_proto::id::ExternalId as _;
    use work_query::domain::authority::approval_state;
    use work_store::{
        AccessPool, CellId, Durability, ExportLog, NewApprovalState, ReceivedRole, SequencerPool,
        WindowHit,
    };

    use super::{ACCESS_PIN_FILE, ACCESS_TOKEN, Answer, Jar, Local, WORK, module};

    const LEDGER_FILE: &str = "commit-ledger";
    const STATE_FILE: &str = "commit-state.json";
    const REQUEST_FILE: &str = "commit-request.json";
    const APPROVED_FILE: &str = "approved.json";
    const EXERCISE_FILE: &str = "commit-exercise.json";
    const WRITTEN_FILE: &str = "commit-written.json";
    const SEQUENCER: &str = "postgres://work_sequencer:local-only-not-a-secret@127.0.0.1:5442/work";
    const APP: &str = "postgres://work_app:local-only-not-a-secret@127.0.0.1:5442/work";
    const ACCESS_DB: &str = "postgres://work_access:local-only-not-a-secret@127.0.0.1:5442/work";
    const POP_TYPE: &str = "application/access-instance-pop";
    const RETURN: &str = "/v1/access/approval";
    const DEVICE_LABEL: &str = "access/bootstrap/test-user-device";
    const RECORD_TYPE: &str = "application/work-record+cbor";
    const AIS_TYPE: &str = "application/access-ais+cbor";
    const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
    const REASON: &str = "Work compose test: commit into the test ledger";

    fn ledger(local: &Local) -> String {
        std::fs::read_to_string(local.dir.join(LEDGER_FILE))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn read(local: &Local, name: &str) -> Value {
        serde_json::from_slice(&std::fs::read(local.dir.join(name)).unwrap()).unwrap()
    }

    fn write(local: &Local, name: &str, value: &Value) {
        std::fs::write(local.dir.join(name), value.to_string()).unwrap();
    }

    fn allowed(local: &Local) -> &Value {
        &local.bootstrap["test_user"]["allowed"]
    }

    fn text<'a>(v: &'a Value, name: &str) -> &'a str {
        v[name].as_str().unwrap_or_else(|| panic!("{name}: {v}"))
    }

    fn id(v: &Value, name: &str) -> [u8; 16] {
        fixed_b64url(text(v, name)).unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    /// A deterministic CBOR map of `entries`, keys in encoded order.
    fn map(entries: Vec<(&str, Cbor)>) -> Cbor {
        let mut keyed: Vec<(Vec<u8>, (Cbor, Cbor))> = entries
            .into_iter()
            .map(|(k, v)| {
                let key = Cbor::text(k);
                (dcbor::encode(&key, Limits::CEILING).unwrap(), (key, v))
            })
            .collect();
        keyed.sort_by(|x, y| x.0.cmp(&y.0));
        Cbor::Map(keyed.into_iter().map(|(_, kv)| kv).collect())
    }

    /// The canonical `IntentEnvelope` of `work:commit` over the resource `namespace`/`id`, valid
    /// around Access's now (Access `intent.cddl`).
    fn intent(namespace: &str, id: &str, now_ms: u64) -> Vec<u8> {
        let action = map(vec![
            ("namespace", Cbor::text("work")),
            ("name", Cbor::text("commit")),
            ("major", Cbor::Unsigned(1)),
            ("schema", suiss_crypto::digest::Digest([0; 32]).to_value()),
        ]);
        let resource = map(vec![
            ("namespace", Cbor::text(namespace)),
            ("path", Cbor::Array(vec![Cbor::text(id)])),
            ("incarnation", Cbor::Unsigned(0)),
        ]);
        let envelope = map(vec![
            ("action", action),
            ("resources", Cbor::Array(vec![resource])),
            (
                "validity",
                Cbor::Array(vec![
                    Cbor::Unsigned(now_ms.saturating_sub(60_000)),
                    Cbor::Unsigned(now_ms.saturating_add(600_000)),
                ]),
            ),
        ]);
        dcbor::encode(&envelope, Limits::CEILING).unwrap()
    }

    /// The test user's `work:commit` intent over the ledger, as Work's client builds it for the
    /// ADP and as the `approve` tool is given it.
    struct Commit {
        json: Value,
        bytes: Vec<u8>,
        digest: [u8; 32],
    }

    /// The intent `test_user.allowed` names over `led`, valid around `now_ms`, with the sample
    /// catalog's parameters: the ledger and a `declaration` digest (E-45 names no parameter),
    /// built by Work's client.
    fn commit_intent(local: &Local, led: &str, now_ms: u64, declaration: &[u8]) -> Commit {
        let a = allowed(local);
        let action = &a["action"];
        assert_eq!(text(&a["resource"], "namespace"), adp::LEDGER_RESOURCE);
        let named = Action {
            namespace: text(action, "namespace").to_owned(),
            name: text(action, "name").to_owned(),
            major: action["major"].as_u64().unwrap(),
            schema: fixed_b64url(text(action, "schema")).unwrap(),
        };
        let bytes = adp::commit_intent(&named, led, declaration, now_ms - 60_000, now_ms + 600_000)
            .unwrap();
        let digest = Intent::from_bytes(&bytes).unwrap().digest;
        assert_eq!(adp::intent_digest_of(&bytes).unwrap(), digest);
        Commit {
            json: adp::intent_json(&bytes).unwrap(),
            bytes,
            digest,
        }
    }

    /// The intent of the commit the first authority request opened.
    fn opened(local: &Local) -> (Commit, Vec<u8>) {
        let state = read(local, STATE_FILE);
        let commit = commit_intent(
            local,
            &ledger(local),
            state["now"].as_u64().unwrap(),
            &from_b64url(text(&state, "declaration")).unwrap(),
        );
        assert_eq!(commit.json, state["intent"]);
        (commit, from_b64url(text(&state, "nonce")).unwrap())
    }

    /// The test user's device Instance key, in the copy of Access's token (T-56).
    fn device(local: &Local) -> HsmSigner {
        let pin = std::fs::read_to_string(local.dir.join(ACCESS_PIN_FILE)).unwrap();
        KeyStore::open(&module(), ACCESS_TOKEN, &Secret::new(pin.trim().to_owned()))
            .unwrap()
            .signer(DEVICE_LABEL)
            .unwrap()
    }

    /// The `COSE_Key` of `key` as Access registers a device key (RFC 9052 section 7).
    fn cose_key(key: &PublicKey) -> Vec<u8> {
        let entries = match key {
            PublicKey::Ed25519(x) => vec![
                (Cbor::Unsigned(1), Cbor::Unsigned(1)),
                (Cbor::int(-1), Cbor::Unsigned(6)),
                (Cbor::int(-2), Cbor::Bytes(x.to_vec())),
            ],
            PublicKey::P256(sec1) => {
                let (x, y) = sec1[1..].split_at(32);
                vec![
                    (Cbor::Unsigned(1), Cbor::Unsigned(2)),
                    (Cbor::int(-1), Cbor::Unsigned(1)),
                    (Cbor::int(-2), Cbor::Bytes(x.to_vec())),
                    (Cbor::int(-3), Cbor::Bytes(y.to_vec())),
                ]
            }
            PublicKey::MlDsa(..) => panic!("a device key is Ed25519 or P-256"),
        };
        dcbor::encode(&Cbor::Map(entries), Limits::CEILING).unwrap()
    }

    /// Binds the realm session in `jar` to the test user's device Instance, as a known device
    /// signs in (Access OP-149 m.32, INV-13): a challenge from `POST /v1/me/instances/challenges`
    /// and the device key's `COSE_Sign1` over it at `POST /v1/me/instances/bindings`; the
    /// session's `auth_context` then names `test_user.instance`.
    async fn bind_device(local: &Local, jar: &mut Jar) {
        let issuer = local.issuer("acme");
        let challenge = local
            .post_json(&format!("{issuer}/v1/me/instances/challenges"), jar, None)
            .await;
        assert_eq!(challenge.status, 201, "{challenge:?}");
        let bytes = from_b64url(text(&challenge.json(), "challenge")).unwrap();
        assert_eq!(bytes.len(), 32);
        let device = device(local);
        let key = device.public_key();
        let pop = sign_sign1(&device, thumbprint(&key), POP_TYPE, &bytes).unwrap();
        let bound = local
            .post_json(
                &format!("{issuer}/v1/me/instances/bindings"),
                jar,
                Some(json!({
                    "challenge": b64url(&bytes),
                    "key": b64url(&cose_key(&key)),
                    "pop": b64url(&pop),
                })),
            )
            .await;
        assert_eq!(bound.status, 201, "{bound:?}");
        let bound = bound.json();
        assert_eq!(text(&bound, "instance"), local.user("instance"), "{bound}");
        assert_eq!(text(&bound, "party"), local.user("party"), "{bound}");
    }

    async fn access_pool() -> AccessPool {
        let pool = work_store::connect(ACCESS_DB, "work-compose-test", Duration::from_secs(30))
            .await
            .unwrap();
        AccessPool::new(pool).await.unwrap()
    }

    fn tenant(local: &Local) -> String {
        text(local.realm("acme"), "tenant").to_owned()
    }

    /// `GET /v1/access/approval?<query>` on `work-server` as the test user; the `DPoP` proof
    /// names the route without its query (RFC 9449 section 4.2).
    async fn approval_return(local: &Local, key: &HsmSigner, token: &str, query: &str) -> Answer {
        let url = format!("{WORK}{RETURN}");
        let proof = local.proof(key, "GET", &url, None, Some(token)).await;
        let authorization = format!("DPoP {token}");
        local
            .send(
                "GET",
                &format!("{url}?{query}"),
                &[
                    ("authorization", authorization.as_str()),
                    ("dpop", proof.as_str()),
                ],
                None,
            )
            .await
    }

    /// The test user's request at `work-server`'s `POST /v1/authority-requests` that Work's PEP
    /// commit `c` under `nonce`, with the Actor Intent Statement the test user's own device key
    /// signs, addressed to Work's PEP by its `x5t#S256`, and the approvals `contributions`
    /// (T-101 item 2, Access L1-ADP-5, L2-SIG-1).
    async fn authority(local: &Local, c: &Commit, nonce: &[u8], contributions: &[&str]) -> Value {
        let a = allowed(local);
        let holding = &a["basis"]["holding"];
        let basis = Holding {
            grant: KernelId(id(holding, "grant")),
            holder: KernelId(id(holding, "holder")),
            since: holding["since"].as_u64().unwrap(),
        };
        let domain = DomainId(fixed_b64url(text(a, "domain")).unwrap());
        let pep = local.pep().x5t_s256();
        let statement = Statement {
            domain: &domain,
            nonce,
            intent: &c.digest,
            pep: &pep,
            capacity: Held::Own,
            basis,
        };
        let device = device(local);
        let now = local.access_now_s().await * 1000;
        let ais = sign_sign1(
            &device,
            thumbprint(&device.public_key()),
            AIS_TYPE,
            &statement.to_sign(now).unwrap(),
        )
        .unwrap();
        let body = serde_json::to_vec(&json!({
            "ledger": ledger(local),
            "intent": b64url(&c.bytes),
            "nonce": b64url(nonce),
            "basis": {"holding": {
                "grant": text(holding, "grant"),
                "holder": text(holding, "holder"),
                "since": basis.since.to_string(),
            }},
            "ais": b64url(&ais),
            "proofs": contributions.iter().map(|e| json!({"contribution": e})).collect::<Vec<_>>(),
            "reason": REASON,
        }))
        .unwrap();
        let key = local.dpop();
        let token = local.token(&key).await;
        let url = format!("{WORK}/v1/authority-requests");
        let proof = local.proof(&key, "POST", &url, None, Some(&token)).await;
        let authorization = format!("DPoP {token}");
        let idempotency = local.uuid7(now);
        let answer = local
            .send(
                "POST",
                &url,
                &[
                    ("idempotency-key", idempotency.as_str()),
                    ("authorization", authorization.as_str()),
                    ("dpop", proof.as_str()),
                ],
                Some(("application/json", body)),
            )
            .await;
        assert_eq!(answer.status, 200, "{answer:?}");
        answer.json()
    }

    /// The Exercise `exercise` as `work-server` reads it: asked of Access, its receipt verified
    /// for the intent and addressed to Work's PEP (T-101 item 7).
    async fn verified(local: &Local, exercise: &str, c: &Commit) -> VerifiedExercise {
        let domain = DomainId(fixed_b64url(text(allowed(local), "domain")).unwrap());
        let intent = Intent::from_bytes(&c.bytes).unwrap();
        let id = ExerciseId::parse(exercise).unwrap();
        let audience = local.pep().x5t_s256();
        let mut last = None;
        for _ in 0..30 {
            let access = local.client().await;
            match access.exercise(domain, &id, &intent, &audience).await {
                Ok(v) => return v,
                Err(e) => last = Some(e),
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        panic!("{last:?}");
    }

    /// The golden promise rewritten as the test user's own unsigned Declaration in `led`: the
    /// user is the author, the capacity is `own` or, given, `FOR(p)` on behalf of `p`, and the
    /// `authority` names the receipt's SHA-256 (P-13, P-21).
    fn record(local: &Local, led: &str, receipt: &[u8], on_behalf_of: Option<&str>) -> Vec<u8> {
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let golden = records["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "record/declaration-promise-for-principal")
            .unwrap();
        let Cbor::Map(fields) =
            dcbor::decode(&unhex(text(golden, "hex")), Limits::CEILING).unwrap()
        else {
            panic!("a record");
        };
        let digest = |b: [u8; 32]| Cbor::Array(vec![Cbor::int(-16), Cbor::Bytes(b.to_vec())]);
        let replaced = [
            "ledger",
            "author",
            "capacity",
            "authority",
            "on_behalf_of",
            "producer",
            "correlation",
        ];
        let kept: Vec<(String, Cbor)> = fields
            .into_iter()
            .filter_map(|(k, v)| match k {
                Cbor::Text(k) if !replaced.contains(&k.as_str()) => Some((k, v)),
                _ => None,
            })
            .collect();
        let mut entries: Vec<(&str, Cbor)> =
            kept.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let ledger = *LedgerId::parse_external(led).unwrap().0.as_bytes();
        entries.push(("ledger", digest(ledger)));
        entries.push(("author", Cbor::text(&local.user("party"))));
        entries.push((
            "authority",
            map(vec![
                ("proof", Cbor::text("decision_receipt")),
                ("digest", digest(sha256(receipt))),
            ]),
        ));
        match on_behalf_of {
            None => entries.push(("capacity", Cbor::text("own"))),
            Some(p) => {
                entries.push((
                    "capacity",
                    Cbor::Array(vec![Cbor::text("for"), Cbor::text(p)]),
                ));
                entries.push(("on_behalf_of", Cbor::Array(vec![Cbor::text(p)])));
            }
        }
        dcbor::encode(&map(entries), Limits::CEILING).unwrap()
    }

    /// The Access `auth_context` artifact of the test user's session bound to `record`
    /// (Access OP-149 m.8, P-116).
    async fn auth_context(local: &Local, jar: &Jar, record: &[u8]) -> Value {
        let issuer = local.issuer("acme");
        let origin = issuer.split("/realms/").next().unwrap().to_owned();
        let body = json!({
            "content_type": RECORD_TYPE,
            "content_digest": b64url(record_id(record).0.as_bytes()),
        });
        let cookies = jar.header();
        let key = local.random();
        let answer = local
            .send(
                "POST",
                &format!("{issuer}/v1/me/auth-context"),
                &[
                    ("cookie", cookies.as_str()),
                    ("origin", origin.as_str()),
                    ("idempotency-key", key.as_str()),
                ],
                Some(("application/json", body.to_string().into_bytes())),
            )
            .await;
        assert_eq!(answer.status, 200, "{answer:?}");
        answer.json()
    }

    /// What a write of the test user under the allowed Exercise needs: an AAL2 session, its
    /// `DPoP` token, the Exercise and its receipt.
    struct Writer {
        key: HsmSigner,
        token: String,
        jar: Jar,
        led: String,
        commit: Commit,
        exercise: String,
        receipt: Vec<u8>,
    }

    impl Writer {
        async fn open(local: &Local) -> Self {
            let (commit, _) = opened(local);
            let exercise = text(&read(local, EXERCISE_FILE), "exercise").to_owned();
            let receipt = verified(local, &exercise, &commit).await.receipt;
            let key = local.dpop();
            let (tokens, mut jar) = local.session(&key, true).await.unwrap();
            assert_eq!(tokens["token_type"], "DPoP", "{tokens}");
            bind_device(local, &mut jar).await;
            Self {
                key,
                token: tokens["access_token"].as_str().unwrap().to_owned(),
                jar,
                led: ledger(local),
                commit,
                exercise,
                receipt,
            }
        }

        /// `POST /v1/ledgers/{led}/declarations` of `record` with its `auth_context`, under the
        /// Exercise and `envelope`.
        async fn declare(
            &self,
            local: &Local,
            record: &[u8],
            envelope: &[u8],
            on_behalf_of: &[&str],
        ) -> Answer {
            let ac = auth_context(local, &self.jar, record).await;
            let body = serde_json::to_vec(&json!({
                "record": b64url(record),
                "auth_context": {"artifact": ac["auth_context"], "digest": ac["digest"]},
                "authority": {"exercise": self.exercise, "intent": b64url(envelope)},
                "actor_types": {"author": "human", "on_behalf_of": on_behalf_of},
            }))
            .unwrap();
            let url = format!("{WORK}/v1/ledgers/{}/declarations", self.led);
            let proof = local
                .proof(&self.key, "POST", &url, None, Some(&self.token))
                .await;
            let authorization = format!("DPoP {}", self.token);
            let idempotency = local.uuid7(local.access_now_s().await * 1000);
            local
                .send(
                    "POST",
                    &url,
                    &[
                        ("idempotency-key", idempotency.as_str()),
                        ("if-match", "\"0\""),
                        ("authorization", authorization.as_str()),
                        ("dpop", proof.as_str()),
                    ],
                    Some(("application/json", body)),
                )
                .await
        }
    }

    fn store_ledger(led: &str) -> work_store::LedgerId {
        work_store::LedgerId::from_bytes(*LedgerId::parse_external(led).unwrap().0.as_bytes())
    }

    async fn export() -> ExportLog {
        let pool = work_store::connect(APP, "work-compose-test", Duration::from_secs(30))
            .await
            .unwrap();
        ExportLog::new(pool).await.unwrap()
    }

    // P-100 OP-9 E-17
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment"]
    async fn p_100_a_ledger_opens_in_work_server_s_cell_for_the_test_user_s_commit() {
        let local = Local::open();
        let pool = work_store::connect(SEQUENCER, "work-compose-test", Duration::from_secs(30))
            .await
            .unwrap();
        let sequencer = SequencerPool::new(pool).await.unwrap();
        let input = GenesisInput::fresh(
            &SystemRng,
            local.access_now_s().await * 1000,
            (1, 0),
            *RuleSet::V1_0.schema().as_bytes(),
        )
        .unwrap();
        let opened = genesis(&input, Durability::SingleNode).unwrap();
        sequencer
            .open_ledger(&opened, &CellId::new("local").unwrap())
            .await
            .unwrap();
        let id = LedgerId(Digest::sha256(*opened.ledger.as_bytes())).to_external();
        std::fs::write(local.dir.join(LEDGER_FILE), &id).unwrap();
    }

    /// The problem `work-server` answers the test user's write of the golden promise into the
    /// opened ledger under `exercise` and `envelope`.
    async fn refused(local: &Local, exercise: &str, envelope: &[u8], now: u64) -> Value {
        let led = ledger(local);
        let key = local.dpop();
        let token = local.token(&key).await;
        let url = format!("{WORK}/v1/ledgers/{led}/declarations");
        let body = serde_json::to_vec(&json!({
            "record": super::signed::golden_promise(),
            "authority": {"exercise": exercise, "intent": b64url(envelope)},
            "actor_types": {"author": "agent", "on_behalf_of": ["organization"]},
        }))
        .unwrap();
        let proof = local.proof(&key, "POST", &url, None, Some(&token)).await;
        let authorization = format!("DPoP {token}");
        let idempotency = local.uuid7(now);
        let answer = local
            .send(
                "POST",
                &url,
                &[
                    ("idempotency-key", idempotency.as_str()),
                    ("if-match", "\"0\""),
                    ("authorization", authorization.as_str()),
                    ("dpop", proof.as_str()),
                ],
                Some(("application/json", body)),
            )
            .await;
        denied(&answer)
    }

    fn denied(answer: &Answer) -> Value {
        assert_eq!(answer.status, 403, "{answer:?}");
        let problem = answer.json();
        assert_eq!(
            problem["type"], "https://suiss.app/ns/work/problems/access_denied",
            "{problem}"
        );
        problem
    }

    // E-17 E-45 P-13 T-28
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with the commit ledger opened"]
    async fn e_45_an_intent_that_names_no_work_ledger_writes_nothing() {
        let local = Local::open();
        let now = local.access_now_s().await * 1000;
        let led = ledger(&local);
        let problem = refused(
            &local,
            &b64url(&[0x5e; 32]),
            &intent("work", &led, now),
            now,
        )
        .await;
        assert_eq!(problem["code_detail"], "intent_resource", "{problem}");
    }

    // T-101 E-17 E-45 P-13
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with the commit ledger opened"]
    async fn t_101_work_s_pep_commits_the_test_user_s_intent_and_access_asks_for_approval() {
        let local = Local::open();
        let led = ledger(&local);
        let a = allowed(&local);
        assert_eq!(text(&a["resource"], "namespace"), "work.ledger");
        assert!(
            led.starts_with(text(&a["resource"], "path_prefix")),
            "{led}"
        );
        let now = local.access_now_s().await * 1000;
        let declaration = from_b64url(&local.random()).unwrap();
        let nonce = from_b64url(&local.random()).unwrap()[..16].to_vec();
        let c = commit_intent(&local, &led, now, &declaration);
        let asked = authority(&local, &c, &nonce, &[]).await;
        assert_eq!(asked["outcome"], "require_action", "{asked}");
        assert_eq!(asked["next"], "approve", "{asked}");
        assert!(asked.get("exercise").is_none(), "{asked}");
        let request = &asked["request"];
        assert_eq!(request["requester"], json!({"party": local.user("party")}));
        assert_eq!(request["action"], c.json["action"]);
        assert_eq!(request["resource"], c.json["resources"][0]);
        assert_eq!(request["params"], c.json["params"]);
        assert_eq!(request["capacity"], "own");
        assert_eq!(request["reason"], REASON);
        assert_eq!(
            request["require_action"],
            json!({
                "domain": text(a, "domain"),
                "nonce": b64url(&nonce),
                "intent": b64url(&c.digest),
            })
        );
        assert!(request["expires_at"].as_u64().unwrap() > now, "{request}");
        write(&local, REQUEST_FILE, request);
        write(
            &local,
            STATE_FILE,
            &json!({
                "now": now,
                "nonce": b64url(&nonce),
                "declaration": b64url(&declaration),
                "intent": c.json,
            }),
        );
    }

    // T-101 E-17 P-13 E-14
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with the test user's approval of Work's request"]
    async fn t_101_with_the_contribution_work_s_pep_gets_the_exercise_and_its_receipt() {
        let local = Local::open();
        let approved = read(&local, APPROVED_FILE);
        let contribution = text(&approved, "contribution");
        let (c, nonce) = opened(&local);
        let answer = authority(&local, &c, &nonce, &[contribution]).await;
        assert_eq!(answer["outcome"], "allow", "{answer}");
        assert!(answer.get("next").is_none(), "{answer}");
        let exercise = text(&answer, "exercise").to_owned();
        assert_ne!(
            from_b64url(text(&answer, "receipt")).unwrap(),
            Vec::<u8>::new()
        );
        let v = verified(&local, &exercise, &c).await;
        assert_eq!(v.intent, c.digest);
        assert_eq!(v.exercise.text(), exercise);
        assert!(matches!(v.capacity, Held::Own), "{:?}", v.capacity);
        assert_ne!(v.receipt, Vec::<u8>::new());
        write(&local, EXERCISE_FILE, &json!({"exercise": exercise}));
    }

    // E-17 P-13 T-101 T-28
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with the Exercise Work's PEP got"]
    async fn e_17_work_server_writes_nothing_for_an_intent_access_did_not_approve() {
        let local = Local::open();
        let w = Writer::open(&local).await;
        let tampered = intent("work.ledger", &w.led, local.access_now_s().await * 1000);
        assert_ne!(tampered, w.commit.bytes);
        let bytes = record(&local, &w.led, &w.receipt, None);
        let problem = denied(&w.declare(&local, &bytes, &tampered, &[]).await);
        assert_eq!(problem["code_detail"], "exercise-intent", "{problem}");
    }

    // P-13 E-13 SEC-4 T-101
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with the Exercise Work's PEP got"]
    async fn p_13_work_server_writes_nothing_for_a_capacity_the_exercise_does_not_carry() {
        let local = Local::open();
        let w = Writer::open(&local).await;
        let principal = text(&local.bootstrap["sample"], "subject").to_owned();
        let bytes = record(&local, &w.led, &w.receipt, Some(&principal));
        let problem = denied(&w.declare(&local, &bytes, &w.commit.bytes, &["human"]).await);
        assert_eq!(problem["code_detail"], "capacity_mismatch", "{problem}");
    }

    // E-17 P-13 P-21 P-116 T-90 T-101
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with the Exercise Work's PEP got"]
    async fn e_17_work_server_writes_the_declaration_access_approved_and_keeps_its_receipt() {
        let local = Local::open();
        let w = Writer::open(&local).await;
        let bytes = record(&local, &w.led, &w.receipt, None);
        let answer = w.declare(&local, &bytes, &w.commit.bytes, &[]).await;
        assert_eq!(answer.status, 201, "{answer:?}");
        let written = answer.json();
        let rec = record_id(&bytes);
        assert_eq!(written["ledger"], w.led.as_str());
        assert_eq!(written["record"], rec.to_external());
        assert_eq!(written["replayed"], false);
        let pos: u64 = text(&written, "pos").parse().unwrap();
        let entries = export()
            .await
            .entries(&store_ledger(&w.led), pos, 1)
            .await
            .unwrap();
        let [entry] = entries.as_slice() else {
            panic!("{entries:?}");
        };
        assert_eq!(entry.pos, pos);
        assert_eq!(entry.record_bytes, bytes);
        let proof: Vec<&[u8]> = entry
            .received
            .iter()
            .filter(|r| r.role == ReceivedRole::AuthorityProof)
            .map(|r| r.bytes.as_slice())
            .collect();
        assert_eq!(proof, vec![w.receipt.as_slice()]);
        let Decoded::Record(stored) = decode_record(&entry.record_bytes).unwrap() else {
            panic!("a record");
        };
        let authority = stored.core().authority.unwrap();
        assert_eq!(*authority.digest.as_bytes(), sha256(&w.receipt));
        assert!(matches!(*stored, Record::Declaration(_)));
        let path = format!(
            "/v1/ledgers/{}/records/{}/evidence",
            w.led,
            rec.to_external()
        );
        let evidence = local.read(&w.key, &path, &w.token).await;
        assert_eq!(evidence.status, 200, "{evidence:?}");
        let evidence = evidence.json();
        assert!(evidence.get("author_signature").is_none(), "{evidence}");
        assert!(evidence["auth_context"]["digest"].is_string(), "{evidence}");
        assert_eq!(evidence["compromise_window"], json!([]), "{evidence}");
        write(
            &local,
            WRITTEN_FILE,
            &json!({"record": rec.to_external(), "pos": pos}),
        );
    }

    // SEC-36 C-4 T-102
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with the test user's Party compromised"]
    async fn sec_36_the_test_user_s_record_shows_the_compromise_window_of_its_party() {
        let local = Local::open();
        let written = read(&local, WRITTEN_FILE);
        let rec = text(&written, "record").to_owned();
        let pos = written["pos"].as_u64().unwrap();
        let led = ledger(&local);
        let key = local.dpop();
        let token = local.token(&key).await;
        let path = format!("/v1/ledgers/{led}/records/{rec}/evidence");
        let mut evidence = Value::Null;
        for _ in 0..60 {
            let answer = local.read(&key, &path, &token).await;
            assert_eq!(answer.status, 200, "{answer:?}");
            evidence = answer.json();
            if evidence["compromise_window"]
                .as_array()
                .is_some_and(|w| !w.is_empty())
            {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let windows = evidence["compromise_window"].as_array().unwrap();
        assert_eq!(windows.len(), 1, "{evidence}");
        let after = export()
            .await
            .entries(&store_ledger(&led), pos + 1, 16)
            .await
            .unwrap();
        let [notice] = after.as_slice() else {
            panic!("{after:?}");
        };
        let Decoded::Record(claim) = decode_record(&notice.record_bytes).unwrap() else {
            panic!("a record");
        };
        assert!(matches!(*claim, Record::Claim(_)));
        assert_eq!(
            windows[0]["notice"],
            record_id(&notice.record_bytes).to_external()
        );
        let instance = fixed_b64url::<16>(&local.user("instance")).unwrap();
        let ledger = *LedgerId::parse_external(&led).unwrap().0.as_bytes();
        let until = local.access_now_s().await * 1000 + 86_400_000;
        let by_instance = access_pool()
            .await
            .window_ledgers(
                &tenant(&local),
                &[],
                &[instance],
                &b64url(&[0; 16]),
                0,
                until,
            )
            .await
            .unwrap();
        assert!(
            by_instance.contains(&WindowHit {
                ledger,
                kid: None,
                instance: Some(instance),
            }),
            "{by_instance:?}"
        );
    }

    // T-101 E-17
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with the test user's approval of Work's request"]
    async fn e_17_the_approval_return_hands_back_the_contribution_access_confirmed_once() {
        let local = Local::open();
        let approved = read(&local, APPROVED_FILE);
        let contribution = text(&approved, "contribution").to_owned();
        let render = text(&approved, "render_digest").to_owned();
        let digest = sha256(&std::fs::read(local.dir.join(REQUEST_FILE)).unwrap());
        let party = local.user("party");
        let state = approval_state(&party, &digest);
        let led = ledger(&local);
        let now = local.access_now_s().await * 1000;
        let access = access_pool().await;
        let tenant = tenant(&local);
        let issued = NewApprovalState {
            state: &state,
            tenant: &tenant,
            party: fixed_b64url(&party).unwrap(),
            digest,
            ledger: *LedgerId::parse_external(&led).unwrap().0.as_bytes(),
            issued_at_ms: now,
            expires_at_ms: now + 3_600_000,
        };
        assert!(access.issue_approval_state(&issued).await.unwrap());
        assert!(!access.issue_approval_state(&issued).await.unwrap());
        let key = local.dpop();
        let token = local.token(&key).await;
        let query = format!("exercise={contribution}&render_digest={render}&state={state}");
        let back = approval_return(&local, &key, &token, &query).await;
        assert_eq!(back.status, 200, "{back:?}");
        assert_eq!(
            back.json(),
            json!({
                "ledger": led,
                "contribution": contribution,
                "render_digest": render,
                "next": "commit",
            })
        );
        let row = access.approval_state(&state).await.unwrap().unwrap();
        assert!(row.used_at_ms.is_some(), "{row:?}");
        let again = approval_return(&local, &key, &token, &query).await;
        assert_eq!(denied(&again)["code_detail"], "state_used");
        let unknown = format!(
            "exercise={contribution}&render_digest={render}&state={}",
            local.random()
        );
        let unknown = approval_return(&local, &key, &token, &unknown).await;
        assert_eq!(denied(&unknown)["code_detail"], "state_unknown");
        let unsent =
            approval_return(&local, &key, &token, &format!("exercise={contribution}")).await;
        assert_eq!(unsent.status, 400, "{unsent:?}");
    }
}
