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

const REGION: &str = "local";
const TOKEN: &str = "work-dev";
const PIN: &str = "1234";
const WORK: &str = "http://127.0.0.1:8190";
const DPOP_LABEL: &str = "work-test-user-dpop";
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
        let signed_in = self
            .post_json(
                &format!(
                    "{issuer}{}",
                    identified.json()["action"].as_str().unwrap_or_default()
                ),
                &mut jar,
                Some(json!({"method": "password", "fields": {"password": password}})),
            )
            .await;
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
                return Ok(answer.json());
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

    /// The access token of a sign-in that succeeds.
    async fn token(&self, key: &HsmSigner) -> String {
        let tokens = self.login(key).await.unwrap();
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

/// The commitment write against the real Access (E-17, P-13, WD-124, WD-125): a ledger opens in
/// `work-server`'s cell, the CI job asks Access's `approve` tool for an allowed `work:commit`
/// Exercise of the test user over it, and `work-server` writes the Declaration only for the
/// intent Access approved, verified online.
mod commit {
    use std::time::Duration;

    use serde_json::{Value, json};
    use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
    use work_access_client::domain::b64url;
    use work_kernel::id::{Digest, LedgerId};
    use work_kernel::rules::RuleSet;
    use work_ledger::{GenesisInput, SystemRng, genesis};
    use work_proto::id::ExternalId as _;
    use work_store::{CellId, Durability, SequencerPool};

    use super::{Local, WORK};

    const LEDGER_FILE: &str = "commit-ledger";
    const APPROVED_FILE: &str = "approved.json";
    const SEQUENCER: &str = "postgres://work_sequencer:local-only-not-a-secret@127.0.0.1:5442/work";

    fn ledger(local: &Local) -> String {
        std::fs::read_to_string(local.dir.join(LEDGER_FILE))
            .unwrap()
            .trim()
            .to_owned()
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

    // E-17 P-13 T-101 T-28
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the local environment with an Exercise the approve tool got"]
    async fn e_17_work_server_writes_nothing_for_an_intent_access_did_not_approve() {
        let local = Local::open();
        let approved: Value =
            serde_json::from_slice(&std::fs::read(local.dir.join(APPROVED_FILE)).unwrap()).unwrap();
        assert_eq!(approved["receipt"]["verified"], true, "{approved}");
        let exercise = approved["exercise"].as_str().unwrap();
        let led = ledger(&local);
        let now = local.access_now_s().await * 1000;
        let key = local.dpop();
        let token = local.token(&key).await;
        let url = format!("{WORK}/v1/ledgers/{led}/declarations");
        let tampered = intent("work.ledger", &led, now);
        let outside = intent("work", &led, now);
        for (envelope, detail) in [(tampered, "exercise-intent"), (outside, "intent_resource")] {
            let body = serde_json::to_vec(&json!({
                "record": super::signed::golden_promise(),
                "authority": {"exercise": exercise, "intent": b64url(&envelope)},
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
            assert_eq!(answer.status, 403, "{detail}: {answer:?}");
            let problem = answer.json();
            assert_eq!(
                problem["type"], "https://suiss.app/ns/work/problems/access_denied",
                "{problem}"
            );
            assert_eq!(problem["code_detail"], detail, "{problem}");
        }
    }
}
