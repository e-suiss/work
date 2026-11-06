//! Work's service token for another platform product (T-99 item 4; Access A28 (a)): [`ServiceTokens`] asks the platform realm's token endpoint once, with a fresh client assertion of `work-access-client` and a `DPoP` proof of `work-access-dpop`, sends the proof again with the endpoint's nonce when it asks for one, keeps the token until shortly before it ends, and gives every call to the product the `Authorization: DPoP` value with a fresh proof of its own.

use std::sync::Mutex;

use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::signer::Signer;

use crate::domain::assertion::{Claims, compact};
use crate::domain::discovery::Issuer;
use crate::domain::service::{
    NONCE_ERROR, NONCE_HEADER, Proof, ServiceToken, refusal, token_body, token_url,
};
use crate::domain::{AccessError, b64url};
use crate::ports::{Clock, Method, Random, Request, Transport};

const JSON: &str = "application/json";
const FORM: &str = "application/x-www-form-urlencoded";

/// The two headers of one call to the product.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopHeaders {
    /// `DPoP <token>`.
    pub authorization: String,
    /// The proof of this call.
    pub dpop: String,
}

impl std::fmt::Debug for DpopHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopHeaders").finish_non_exhaustive()
    }
}

/// The service tokens of Work's platform client for one product.
pub struct ServiceTokens<T, C, R, K, D> {
    transport: T,
    clock: C,
    random: R,
    client: K,
    dpop: D,
    kid: String,
    client_id: String,
    issuer: Issuer,
    resource: String,
    cached: Mutex<Option<ServiceToken>>,
}

impl<T, C, R, K, D> std::fmt::Debug for ServiceTokens<T, C, R, K, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceTokens")
            .field("client_id", &self.client_id)
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

/// Where the tokens come from and what they are for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// `WORK_ACCESS_CLIENT_ID`.
    pub client_id: String,
    /// The platform realm, `[suiss] access`.
    pub issuer: Issuer,
    /// The product's Access `client_id`, the token's `aud`.
    pub resource: String,
}

impl<T: Transport, C: Clock, R: Random, K: Signer + Send + Sync, D: Signer + Send + Sync>
    ServiceTokens<T, C, R, K, D>
{
    /// Tokens of `target`, with `client` signing the assertions and `dpop` the proofs.
    #[must_use]
    pub fn new(transport: T, clock: C, random: R, client: K, dpop: D, target: Target) -> Self {
        let kid = b64url(&thumbprint(&client.public_key()));
        Self {
            transport,
            clock,
            random,
            client,
            dpop,
            kid,
            client_id: target.client_id,
            issuer: target.issuer,
            resource: target.resource,
            cached: Mutex::new(None),
        }
    }

    fn jti(&self) -> Result<[u8; 32], AccessError> {
        let mut jti = [0_u8; 32];
        self.random.fill(&mut jti)?;
        Ok(jti)
    }

    fn sign(key: &impl Signer, input: &str) -> Result<String, AccessError> {
        let signature = key
            .sign(input.as_bytes())
            .map_err(|e| AccessError::KeyStore(e.to_string()))?;
        compact(input, &signature)
    }

    fn assertion(&self) -> Result<String, AccessError> {
        let input = Claims {
            kid: &self.kid,
            client_id: &self.client_id,
            audience: self.issuer.as_str(),
            jti: self.jti()?,
            now_ms: self.clock.now_ms(),
        }
        .signing_input()?;
        Self::sign(&self.client, &input)
    }

    /// A fresh proof for `method` to `url`, with `token` when the call presents one.
    ///
    /// # Errors
    /// [`AccessError::KeyStore`].
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        nonce: Option<&str>,
        token: Option<&str>,
    ) -> Result<String, AccessError> {
        let key = self.dpop.public_key();
        let input = Proof {
            key: &key,
            method,
            url,
            jti: self.jti()?,
            now_ms: self.clock.now_ms(),
            nonce,
            token,
        }
        .signing_input()?;
        Self::sign(&self.dpop, &input)
    }

    async fn ask(&self) -> Result<ServiceToken, AccessError> {
        let url = token_url(&self.issuer);
        let mut nonce: Option<String> = None;
        loop {
            let request = Request {
                method: Method::Post,
                url: url.clone(),
                headers: vec![
                    ("accept".to_owned(), JSON.to_owned()),
                    ("content-type".to_owned(), FORM.to_owned()),
                    (
                        "dpop".to_owned(),
                        self.proof("POST", &url, nonce.as_deref(), None)?,
                    ),
                ],
                body: token_body(&self.assertion()?, &self.resource),
            };
            let answer = self.transport.send(request).await?;
            if answer.status == 200 {
                return ServiceToken::from_json(&answer.body, self.clock.now_ms());
            }
            let refused = refusal(answer.status, &answer.body);
            let asks = matches!(&refused, AccessError::Refused { code, .. } if code == NONCE_ERROR);
            match answer.header(NONCE_HEADER) {
                Some(fresh) if asks && nonce.is_none() => nonce = Some(fresh.to_owned()),
                _ => return Err(refused),
            }
        }
    }

    /// The token, from the cache while it is fresh.
    ///
    /// # Errors
    /// [`AccessError`] of the token endpoint.
    pub async fn token(&self) -> Result<ServiceToken, AccessError> {
        let now = self.clock.now_ms();
        let hit = self.cached()?.as_ref().filter(|t| t.fresh(now)).cloned();
        if let Some(t) = hit {
            return Ok(t);
        }
        let fresh = self.ask().await?;
        *self.cached()? = Some(fresh.clone());
        Ok(fresh)
    }

    fn cached(&self) -> Result<std::sync::MutexGuard<'_, Option<ServiceToken>>, AccessError> {
        self.cached
            .lock()
            .map_err(|_| AccessError::KeyStore("token cache poisoned".to_owned()))
    }

    /// Drops the cached token, after the product refused it.
    ///
    /// # Errors
    /// [`AccessError::KeyStore`] for a poisoned cache.
    pub fn forget(&self) -> Result<(), AccessError> {
        *self.cached()? = None;
        Ok(())
    }

    /// The headers of one `method` call to `url` at the product.
    ///
    /// # Errors
    /// [`AccessError`] of the token endpoint or the key store.
    pub async fn authorize(&self, method: &str, url: &str) -> Result<DpopHeaders, AccessError> {
        let token = self.token().await?;
        let dpop = self.proof(method, url, None, Some(token.expose()))?;
        let mut authorization = String::from("DPoP ");
        authorization.push_str(token.expose());
        Ok(DpopHeaders {
            authorization,
            dpop,
        })
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test code")]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

    use suiss_crypto::cose::{Algorithm, PublicKey};
    use suiss_crypto::signer::SignError;

    use super::*;
    use crate::domain::from_b64url;
    use crate::ports::Response;

    struct Key(u8);

    impl Signer for Key {
        fn algorithm(&self) -> Algorithm {
            Algorithm::Es256
        }

        fn public_key(&self) -> PublicKey {
            let mut sec1 = vec![4];
            sec1.extend([self.0; 64]);
            PublicKey::P256(sec1)
        }

        fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SignError> {
            Ok(vec![self.0; 64])
        }
    }

    struct Now(AtomicU64);

    impl Clock for &Now {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct Counter(AtomicU8);

    impl Random for Counter {
        fn fill(&self, out: &mut [u8]) -> Result<(), AccessError> {
            out.fill(self.0.fetch_add(1, Ordering::Relaxed));
            Ok(())
        }
    }

    #[derive(Default)]
    struct Endpoint {
        sent: Mutex<Vec<Request>>,
        answers: Mutex<VecDeque<Response>>,
    }

    impl Transport for &Endpoint {
        async fn send(&self, request: Request) -> Result<Response, AccessError> {
            self.sent.lock().unwrap().push(request);
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| AccessError::Transport("closed".to_owned()))
        }
    }

    fn answer(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        Response {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn token(at: &str) -> Response {
        answer(
            200,
            &[],
            &format!(r#"{{"access_token":"{at}","token_type":"DPoP","expires_in":300}}"#),
        )
    }

    fn nonce() -> Response {
        answer(
            400,
            &[("DPoP-Nonce", "n-1")],
            r#"{"error":"use_dpop_nonce"}"#,
        )
    }

    fn claims(jwt: &str, n: usize) -> serde_json::Value {
        serde_json::from_slice(&from_b64url(jwt.split('.').nth(n).unwrap()).unwrap()).unwrap()
    }

    fn tokens<'a>(
        endpoint: &'a Endpoint,
        now: &'a Now,
    ) -> ServiceTokens<&'a Endpoint, &'a Now, Counter, Key, Key> {
        ServiceTokens::new(
            endpoint,
            now,
            Counter(AtomicU8::new(1)),
            Key(1),
            Key(2),
            Target {
                client_id: "cli_work".to_owned(),
                issuer: Issuer::parse("https://access.example/realms/platform").unwrap(),
                resource: "app_relay".to_owned(),
            },
        )
    }

    fn header<'a>(r: &'a Request, name: &str) -> &'a str {
        r.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .unwrap()
    }

    // T-99
    #[tokio::test]
    async fn t_99_the_token_request_sends_the_nonce_once_access_asks_for_it() {
        let endpoint = Endpoint::default();
        endpoint
            .answers
            .lock()
            .unwrap()
            .extend([nonce(), token("at-1")]);
        let now = Now(AtomicU64::new(1_793_793_600_000));
        let t = tokens(&endpoint, &now);
        let h = t
            .authorize("POST", "https://relay/v1/events")
            .await
            .unwrap();
        assert_eq!(h.authorization, "DPoP at-1");
        let sent = endpoint.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        for r in &*sent {
            assert_eq!(r.url, "https://access.example/realms/platform/token");
            assert_eq!(header(r, "content-type"), FORM);
            let body = String::from_utf8(r.body.clone()).unwrap();
            assert!(body.starts_with("grant_type=client_credentials&"));
            assert!(body.ends_with("&resource=app_relay"));
        }
        let first = claims(header(&sent[0], "dpop"), 1);
        let second = claims(header(&sent[1], "dpop"), 1);
        assert!(first.get("nonce").is_none());
        assert_eq!(second["nonce"], "n-1");
        assert_eq!(
            second["htu"],
            "https://access.example/realms/platform/token"
        );
        assert!(second.get("ath").is_none());
        assert_ne!(first["jti"], second["jti"]);
        let key = claims(header(&sent[0], "dpop"), 0);
        assert_eq!(key["jwk"]["x"], b64url(&[2; 32]));
        let call = claims(&h.dpop, 1);
        assert_eq!(call["htm"], "POST");
        assert_eq!(call["htu"], "https://relay/v1/events");
        assert_eq!(call["ath"], crate::domain::service::ath("at-1"));
        assert!(call.get("nonce").is_none());
    }

    // T-99
    #[tokio::test]
    async fn t_99_the_token_is_kept_until_shortly_before_it_ends_and_each_call_has_its_own_proof() {
        let endpoint = Endpoint::default();
        endpoint
            .answers
            .lock()
            .unwrap()
            .extend([token("at-1"), token("at-2")]);
        let now = Now(AtomicU64::new(1_793_793_600_000));
        let t = tokens(&endpoint, &now);
        let a = t
            .authorize("POST", "https://relay/v1/events")
            .await
            .unwrap();
        now.0.fetch_add(239_000, Ordering::SeqCst);
        let b = t
            .authorize("POST", "https://relay/v1/events")
            .await
            .unwrap();
        assert_eq!(a.authorization, b.authorization);
        assert_ne!(claims(&a.dpop, 1)["jti"], claims(&b.dpop, 1)["jti"]);
        assert_eq!(endpoint.sent.lock().unwrap().len(), 1);
        now.0.fetch_add(1_000, Ordering::SeqCst);
        let c = t
            .authorize("POST", "https://relay/v1/events")
            .await
            .unwrap();
        assert_eq!(c.authorization, "DPoP at-2");
        t.forget().unwrap();
        assert!(
            t.authorize("POST", "https://relay/v1/events")
                .await
                .is_err()
        );
        assert!(!format!("{c:?}").contains("at-2"));
        assert!(!format!("{t:?}").contains("at-2"));
    }

    // T-99 T-28
    #[tokio::test]
    async fn t_99_a_refused_token_request_is_not_asked_again_with_another_nonce() {
        let endpoint = Endpoint::default();
        endpoint.answers.lock().unwrap().extend([
            nonce(),
            nonce(),
            answer(400, &[], r#"{"error":"invalid_target"}"#),
        ]);
        let now = Now(AtomicU64::new(1_793_793_600_000));
        let t = tokens(&endpoint, &now);
        let e = t.token().await.unwrap_err();
        assert!(
            matches!(&e, AccessError::Refused { status: 400, code, .. } if code == NONCE_ERROR)
        );
        assert_eq!(endpoint.sent.lock().unwrap().len(), 2);
        let e = t.token().await.unwrap_err();
        assert!(
            matches!(&e, AccessError::Refused { status: 400, code, .. } if code == "invalid_target")
        );
    }
}
