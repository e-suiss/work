//! Who the executor is and how it calls Work (T-105 item 2, T-101, T-56, E-45, P-13): Access v0.7.4 has no executor registration and no per-job token (Access B21), so the executor connects with a service Party credential: its product's OAuth client (`private_key_jwt`, `DPoP`, both keys in the PKCS#11 token) asks the platform realm for a token whose `resource` is Work, and its service Instance key signs its records and its Actor Intent Statements. Every consequential write first asks Work's PEP, `POST /v1/authority-requests`, to commit the intent of the record's Access action; only an allowed Exercise with its receipt is written under. Whatever Access or Work refuses is handed back as a [`Refusal`] naming the exact problem, never retried as if it were allowed.

use std::path::Path;
use std::sync::RwLock;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::{Value, json};
use suiss_crypto::digest::sha256;
use suiss_crypto::pkcs11::KeyStore;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer as _, sign_sign1};
use work_access_client::adapters::{
    DEFAULT_TIMEOUT, HttpsTransport, TokenSigner, public_config, roots,
};
use work_access_client::app::Client;
use work_access_client::app::platform::{Platform, sign_challenge};
use work_access_client::app::service::{ServiceTokens, Target};
use work_access_client::domain::adp::{Action, Holding, Statement, commit_intent};
use work_access_client::domain::discovery::Issuer;
use work_access_client::domain::exercise::{Capacity, Intent};
use work_access_client::domain::keys::{DomainId, KernelId};
use work_access_client::domain::metadata::thumbprint;
use work_access_client::domain::pairing::{RealmChange, Target as Realm, plan_challenges};
use work_access_client::domain::{AccessError, b64url, fixed_b64url, from_b64url};
use work_access_client::ports::Clock as _;
use work_proto::id::TenantId;

use crate::clock::{Os, Wall};
use crate::config::Config;
use crate::web::{Answer, Http};

/// The content type of an Actor Intent Statement (Access L2-SIG-1).
const AIS_TYPE: &str = "application/access-ais+cbor";

/// How long the intent of one write is valid around now.
const INTENT_BEFORE_MS: u64 = 60_000;
const INTENT_AFTER_MS: u64 = 600_000;

/// Why something the executor asked for was not given; logged with every field, never taken
/// for an allowed answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The executor cannot ask at all: `no_holding`, `domain_unknown`, `party_unknown`, …
    Local(&'static str),
    /// Access refused or could not give a token or a pairing.
    Access(String),
    /// Work answered an RFC 9457 problem.
    Problem {
        /// The status.
        status: u16,
        /// `code`.
        code: String,
        /// `code_detail`.
        code_detail: String,
        /// `reason`, joined with `:`.
        reason: String,
    },
    /// Access asks for more before it allows: Work's `next`.
    Pending(String),
    /// No answer came.
    Transport(String),
}

impl Refusal {
    /// Logs the refusal of `element` for `commitment` at `stage`, with every field.
    pub(crate) fn log(&self, stage: &str, element: &str, commitment: &str) {
        match self {
            Self::Problem {
                status,
                code,
                code_detail,
                reason,
            } => tracing::warn!(
                event = "executor.refused",
                stage,
                element,
                commitment,
                status,
                code = code.as_str(),
                code_detail = code_detail.as_str(),
                reason = reason.as_str(),
                "Work refused"
            ),
            Self::Local(code) => tracing::warn!(
                event = "executor.refused",
                stage,
                element,
                commitment,
                code,
                "the executor cannot ask"
            ),
            Self::Access(error) => tracing::warn!(
                event = "executor.refused",
                stage,
                element,
                commitment,
                code = "access",
                error = error.as_str(),
                "Access refused"
            ),
            Self::Pending(next) => tracing::warn!(
                event = "executor.refused",
                stage,
                element,
                commitment,
                code = "require_action",
                next = next.as_str(),
                "Access asks for more before it allows"
            ),
            Self::Transport(error) => tracing::warn!(
                event = "executor.unreachable",
                stage,
                element,
                commitment,
                error = error.as_str(),
                "no answer"
            ),
        }
    }
}

/// The refusal an answer carries, from its problem document.
pub(crate) fn problem(answer: &Answer) -> Refusal {
    let doc: Value = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
    let text = |name: &str| {
        doc.get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let reason = doc
        .get("reason")
        .and_then(Value::as_array)
        .map(|r| {
            r.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_default();
    Refusal::Problem {
        status: answer.status,
        code: text("code"),
        code_detail: text("code_detail"),
        reason,
    }
}

fn access(error: &AccessError) -> Refusal {
    Refusal::Access(error.to_string())
}

/// The allowed Exercise a write is written under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Exercise {
    /// The `ExerciseID` text.
    pub(crate) exercise: String,
    /// The receipt as Access signed it.
    pub(crate) receipt: Vec<u8>,
    /// The intent envelope it was allowed for.
    pub(crate) intent: Vec<u8>,
}

#[derive(Deserialize)]
struct Decision {
    outcome: String,
    #[serde(default)]
    exercise: Option<String>,
    #[serde(default)]
    receipt: Option<String>,
    #[serde(default)]
    next: Option<String>,
}

/// What Work answered an authority request.
pub(crate) fn decision(answer: &Answer, intent: Vec<u8>) -> Result<Exercise, Refusal> {
    if answer.status != 200 {
        return Err(problem(answer));
    }
    let d: Decision =
        serde_json::from_slice(&answer.body).map_err(|_| Refusal::Local("decision"))?;
    match (d.outcome.as_str(), d.exercise, d.receipt) {
        ("allow", Some(exercise), Some(receipt)) => Ok(Exercise {
            exercise,
            receipt: from_b64url(&receipt).map_err(|_| Refusal::Local("receipt"))?,
            intent,
        }),
        _ => Err(Refusal::Pending(d.next.unwrap_or(d.outcome))),
    }
}

/// The `x5t#S256` of the first certificate of a PEM file (RFC 8705 section 3.1).
pub(crate) fn x5t_s256(pem: &str) -> Option<String> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = STANDARD.decode(body.trim()).ok()?;
    (!der.is_empty()).then(|| b64url(&sha256(&der)))
}

fn read_trimmed(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|t| t.trim().to_owned())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The `client_id` of `product` in Access's bootstrap summary.
pub(crate) fn client_of(bootstrap: &Value, product: &str) -> Option<String> {
    bootstrap
        .get("clients")?
        .as_array()?
        .iter()
        .find(|c| c.get("product").and_then(Value::as_str) == Some(product))?
        .get("client_id")?
        .as_str()
        .map(str::to_owned)
}

/// The tenant of the realm `slug` in Access's bootstrap summary.
pub(crate) fn tenant_of(bootstrap: &Value, slug: &str) -> Option<String> {
    bootstrap
        .get("realms")?
        .as_array()?
        .iter()
        .find(|r| r.get("slug").and_then(Value::as_str) == Some(slug))?
        .get("tenant")?
        .as_str()
        .map(str::to_owned)
}

/// The executor's `client_id`, Work's `client_id` and the tenant it pairs with, if any.
fn ids(config: &Config) -> Result<(String, String, Option<String>), String> {
    let a = &config.access;
    let bootstrap = match &a.bootstrap_file {
        Some(path) => Some(
            serde_json::from_str::<Value>(&read_trimmed(path)?)
                .map_err(|e| format!("{}: {e}", path.display()))?,
        ),
        None => None,
    };
    let from_bootstrap = |product: &str| {
        bootstrap
            .as_ref()
            .and_then(|b| client_of(b, product))
            .ok_or_else(|| format!("no {product} client in the bootstrap summary"))
    };
    let client_id = match (&a.client_id, &a.client_id_file, &a.product) {
        (Some(id), _, _) => id.clone(),
        (None, Some(path), _) => read_trimmed(path)?,
        (None, None, Some(product)) => from_bootstrap(product)?,
        (None, None, None) => return Err("no client_id".to_owned()),
    };
    let resource = match (&a.resource, &a.resource_file) {
        (Some(id), _) => id.clone(),
        (None, Some(path)) => read_trimmed(path)?,
        (None, None) => from_bootstrap("work")?,
    };
    let tenant = match (&a.pair_tenant, &a.pair_realm) {
        (Some(t), _) => Some(t.clone()),
        (None, Some(slug)) => Some(
            bootstrap
                .as_ref()
                .and_then(|b| tenant_of(b, slug))
                .ok_or_else(|| format!("no realm {slug} in the bootstrap summary"))?,
        ),
        (None, None) => None,
    };
    Ok((client_id, resource, tenant))
}

/// The executor's identity: its OAuth client, its service Instance key and, once known, its
/// Party and governing domain.
pub(crate) struct Identity {
    tokens: ServiceTokens<HttpsTransport, Wall, Os, TokenSigner, TokenSigner>,
    platform: Platform<HttpsTransport, Wall, Os, TokenSigner>,
    https: HttpsTransport,
    service: TokenSigner,
    issuer: Issuer,
    region: String,
    pep: String,
    tenant: Option<String>,
    party: RwLock<Option<String>>,
    domain: RwLock<Option<[u8; 32]>>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("issuer", &self.issuer.as_str())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Loads the keys from the token and the client ids, roots and PEP certificate from the
    /// configuration.
    pub(crate) fn load(config: &Config) -> Result<Self, String> {
        let pin = read_trimmed(&config.pkcs11.pin_file)?;
        let store = KeyStore::open(
            &config.pkcs11.module,
            &config.pkcs11.token,
            &Secret::new(pin),
        )
        .map_err(|e| format!("token: {e}"))?;
        let key = |label: &str| {
            store
                .signer(label)
                .map(TokenSigner::of)
                .map_err(|e| format!("{label}: {e}"))
        };
        let pem = std::fs::read(&config.access.tls_roots)
            .map_err(|e| format!("{}: {e}", config.access.tls_roots.display()))?;
        let tls =
            public_config(roots(&pem).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let https = HttpsTransport::new(tls, DEFAULT_TIMEOUT);
        let issuer = Issuer::parse(&config.access.issuer).map_err(|e| e.to_string())?;
        let (client_id, resource, tenant) = ids(config)?;
        let pep = x5t_s256(&read_trimmed(&config.work.pep_certificate)?)
            .ok_or_else(|| "work.pep_certificate is not a PEM certificate".to_owned())?;
        let domain = config
            .authority
            .domain
            .as_deref()
            .map(fixed_b64url::<32>)
            .transpose()
            .map_err(|_| "authority.domain is not 32 bytes of base64url".to_owned())?;
        let tokens = ServiceTokens::new(
            https.clone(),
            Wall,
            Os,
            key(&config.pkcs11.client_key)?,
            key(&config.pkcs11.dpop_key)?,
            Target {
                client_id: client_id.clone(),
                issuer: issuer.clone(),
                resource,
            },
        );
        let platform = Platform::new(
            https.clone(),
            Wall,
            Os,
            key(&config.pkcs11.client_key)?,
            &client_id,
            &issuer,
        );
        Ok(Self {
            tokens,
            platform,
            https,
            service: key(&config.pkcs11.service_key)?,
            issuer,
            region: config.access.region.clone(),
            pep,
            tenant,
            party: RwLock::new(config.executor.party.clone()),
            domain: RwLock::new(domain),
        })
    }

    /// The tenant the executor's product pairs with, if it pairs.
    pub(crate) fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    /// The executor's Party, once known.
    pub(crate) fn party(&self) -> Option<String> {
        self.party.read().ok().and_then(|p| p.clone())
    }

    fn domain(&self) -> Option<[u8; 32]> {
        self.domain.read().ok().and_then(|d| *d)
    }

    fn keep(&self, party: Option<[u8; 16]>, domain: Option<[u8; 32]>) {
        if let (Some(p), Ok(mut kept)) = (party, self.party.write()) {
            *kept = Some(b64url(&p));
        }
        if let (Some(d), Ok(mut kept)) = (domain, self.domain.write()) {
            *kept = Some(d);
        }
    }

    /// The service key, which signs the executor's records.
    pub(crate) const fn service(&self) -> &TokenSigner {
        &self.service
    }

    /// Pairs the executor's product with every live realm of `tenant` the way a product pairs
    /// (T-103 item 2), which opens its service Party there, and keeps the Party and the
    /// governing domain the answer names.
    pub(crate) async fn pair(&self, tenant: &str) -> Result<(), Refusal> {
        let tenant = TenantId::new(tenant).ok_or(Refusal::Local("tenant"))?;
        let client = Client::new(
            self.https.clone(),
            Wall,
            self.issuer.clone(),
            &self.region,
            0,
        );
        client.discover().await.map_err(|e| access(&e))?;
        let endpoints = client.served().map_err(|e| access(&e))?;
        let challenges = self
            .platform
            .challenges(&endpoints, &tenant)
            .await
            .map_err(|e| access(&e))?;
        let plan = plan_challenges(&challenges, &self.service.public_key(), Wall.now_ms());
        for change in &plan.changes {
            if let RealmChange::Unpaired { domain, party, .. } = change {
                self.keep(Some(*party), Some(*domain));
            }
        }
        for target in &challenges.targets {
            if let Realm::Paired(p) = target {
                self.keep(Some(p.party), None);
            }
        }
        if let Some((_, code)) = plan.refused.first() {
            return Err(Refusal::Access(format!("pairing refused: {code}")));
        }
        let signed = plan
            .sign
            .into_iter()
            .map(|(realm, challenge, statements)| {
                sign_challenge(&self.service, realm, challenge, &statements)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| access(&e))?;
        if signed.is_empty() {
            return Ok(());
        }
        let paired = self
            .platform
            .pair(&endpoints, &tenant, &signed)
            .await
            .map_err(|e| access(&e))?;
        for target in &paired.targets {
            if let Realm::Paired(p) = target {
                self.keep(Some(p.party), None);
            }
        }
        Ok(())
    }

    /// The `Authorization` and `DPoP` headers of one call to `url`, its query left out of the
    /// proof (RFC 9449 section 4.2).
    async fn headers(&self, method: &str, url: &str) -> Result<(String, String), Refusal> {
        let htu = url.split('?').next().unwrap_or(url);
        let h = self
            .tokens
            .authorize(method, htu)
            .await
            .map_err(|e| access(&e))?;
        Ok((h.authorization, h.dpop))
    }

    /// Drops the token Work refused.
    fn forget(&self) {
        if let Err(error) = self.tokens.forget() {
            tracing::warn!(event = "executor.token_kept", %error, "the refused token stays cached");
        }
    }
}

/// Work's API as the executor calls it.
#[derive(Debug)]
pub(crate) struct Work {
    http: Http,
    api: String,
    ledger: String,
    authority: crate::config::Authority,
    actor_type: String,
}

/// One consequential write: the record, its openings, the Access action and the route.
pub(crate) struct Write<'a> {
    /// The path under the API base.
    pub(crate) path: String,
    /// The Access action, such as `write`.
    pub(crate) action: &'static str,
    /// The digest the intent names as its `declaration` parameter.
    pub(crate) declaration: [u8; 32],
    /// The record builder, given the receipt digest.
    pub(crate) record: &'a (dyn Fn(&[u8; 32]) -> Result<(Vec<u8>, Vec<Value>), String> + Sync),
    /// The `If-Match` read from this path, if any.
    pub(crate) version_of: Option<String>,
}

impl Work {
    /// Work's API over `http`, in the configured ledger.
    pub(crate) fn new(http: Http, config: &Config) -> Self {
        Self {
            http,
            api: config.work.api.clone(),
            ledger: config.work.ledger.clone(),
            authority: config.authority.clone(),
            actor_type: config.executor.actor_type.clone(),
        }
    }

    /// The ledger, `led_…`.
    pub(crate) fn ledger(&self) -> &str {
        &self.ledger
    }

    /// One call with the executor's token; a `401` drops the token and asks once more.
    pub(crate) async fn call(
        &self,
        identity: &Identity,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
        bound: Duration,
    ) -> Result<Answer, Refusal> {
        let url = format!("{}{path}", self.api);
        let mut asked = 0_u8;
        loop {
            let (authorization, dpop) = identity.headers(method, &url).await?;
            let mut all: Vec<(&str, &str)> = vec![
                ("authorization", authorization.as_str()),
                ("dpop", dpop.as_str()),
                ("accept", "application/json"),
            ];
            all.extend_from_slice(headers);
            let answer = self
                .http
                .send(method, &url, &all, body.clone(), bound)
                .await
                .map_err(|e| Refusal::Transport(e.to_string()))?;
            if answer.status == 401 && asked == 0 {
                identity.forget();
                asked = 1;
                continue;
            }
            return Ok(answer);
        }
    }

    fn holding(&self, party: &str) -> Result<Holding, Refusal> {
        let a = &self.authority;
        let (Some(grant), Some(since)) = (a.grant.as_deref(), a.since) else {
            return Err(Refusal::Local("no_holding"));
        };
        let id = |t: &str| fixed_b64url::<16>(t).map(KernelId);
        Ok(Holding {
            grant: id(grant).map_err(|_| Refusal::Local("holding"))?,
            holder: id(a.holder.as_deref().unwrap_or(party))
                .map_err(|_| Refusal::Local("holding"))?,
            since,
        })
    }

    /// Asks Work's PEP to commit the intent of `action` on the ledger (E-45, T-101 item 2):
    /// the executor's service Instance states the commit to Work's PEP in its governing domain.
    pub(crate) async fn exercise(
        &self,
        identity: &Identity,
        action: &str,
        declaration: &[u8; 32],
    ) -> Result<Exercise, Refusal> {
        let party = identity.party().ok_or(Refusal::Local("party_unknown"))?;
        let basis = self.holding(&party)?;
        let domain = identity.domain().ok_or(Refusal::Local("domain_unknown"))?;
        let schema = match self.authority.action_schema.as_deref() {
            Some(t) => fixed_b64url::<32>(t).map_err(|_| Refusal::Local("action_schema"))?,
            None => [0; 32],
        };
        let now = Wall.now_ms();
        let intent = commit_intent(
            &Action {
                namespace: "work".to_owned(),
                name: action.to_owned(),
                major: 1,
                schema,
            },
            &self.ledger,
            declaration,
            now.saturating_sub(INTENT_BEFORE_MS),
            now.saturating_add(INTENT_AFTER_MS),
        )
        .map_err(|e| access(&e))?;
        let digest = Intent::from_bytes(&intent).map_err(|e| access(&e))?.digest;
        let nonce: [u8; 16] = Os.bytes().map_err(|e| access(&e))?;
        let statement = Statement {
            domain: &DomainId(domain),
            nonce: &nonce,
            intent: &digest,
            pep: &identity.pep,
            capacity: Capacity::Own,
            basis,
        };
        let payload = statement.to_sign(now).map_err(|e| access(&e))?;
        let key = identity.service();
        let ais = sign_sign1(key, thumbprint(&key.public_key()), AIS_TYPE, &payload)
            .map_err(|e| Refusal::Access(e.to_string()))?;
        let body = json!({
            "ledger": self.ledger,
            "intent": b64url(&intent),
            "nonce": b64url(&nonce),
            "basis": {"holding": {
                "grant": basis.grant.text(),
                "holder": basis.holder.text(),
                "since": basis.since.to_string(),
            }},
            "ais": b64url(&ais),
            "reason": format!("work-executor writes its work:{action} record"),
        });
        let key = Os.uuid7(now).map_err(|e| access(&e))?;
        let answer = self
            .call(
                identity,
                "POST",
                "/v1/authority-requests",
                &[("idempotency-key", key.as_str())],
                Some(body.to_string().into_bytes()),
                Duration::from_secs(30),
            )
            .await?;
        decision(&answer, intent)
    }

    /// The strong `ETag` of `path`, `"0"` when it has none.
    async fn version(&self, identity: &Identity, path: &str) -> String {
        match self
            .call(identity, "GET", path, &[], None, Duration::from_secs(10))
            .await
        {
            Ok(a) if a.status == 200 => a.header("etag").unwrap_or("\"0\"").to_owned(),
            _ => "\"0\"".to_owned(),
        }
    }

    /// Writes one record: the Exercise of its action first, then the signed record with its
    /// openings under it. Answers the written `rec_…`.
    pub(crate) async fn write(
        &self,
        identity: &Identity,
        write: &Write<'_>,
    ) -> Result<String, Refusal> {
        let exercise = self
            .exercise(identity, write.action, &write.declaration)
            .await?;
        let (record, openings) =
            (write.record)(&sha256(&exercise.receipt)).map_err(|_| Refusal::Local("record"))?;
        let body = json!({
            "record": b64url(&record),
            "authority": {"exercise": exercise.exercise, "intent": b64url(&exercise.intent)},
            "actor_types": {"author": self.actor_type},
            "body": openings,
        });
        let if_match = match &write.version_of {
            Some(path) => self.version(identity, path).await,
            None => "\"0\"".to_owned(),
        };
        let key = Os.uuid7(Wall.now_ms()).map_err(|e| access(&e))?;
        let answer = self
            .call(
                identity,
                "POST",
                &write.path,
                &[
                    ("idempotency-key", key.as_str()),
                    ("if-match", if_match.as_str()),
                ],
                Some(body.to_string().into_bytes()),
                Duration::from_secs(30),
            )
            .await?;
        if answer.status != 201 {
            return Err(problem(&answer));
        }
        let written: Value = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
        Ok(written
            .get("record")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &Value) -> Answer {
        Answer {
            status,
            headers: Vec::new(),
            body: body.to_string().into_bytes(),
        }
    }

    // T-105 T-98 P-13
    #[test]
    fn t_105_a_refusal_keeps_the_exact_problem_work_answered() {
        let denied = answer(
            403,
            &json!({"type": "https://suiss.app/ns/work/problems/access_denied", "status": 403,
                "code": "access_denied", "code_detail": "intent_action"}),
        );
        assert_eq!(
            problem(&denied),
            Refusal::Problem {
                status: 403,
                code: "access_denied".to_owned(),
                code_detail: "intent_action".to_owned(),
                reason: String::new(),
            }
        );
        let rejected = answer(
            422,
            &json!({"code": "record_rejected", "reason": ["control", "not_executor"]}),
        );
        assert!(matches!(
            problem(&rejected),
            Refusal::Problem { ref reason, .. } if reason == "control:not_executor"
        ));
        assert_eq!(decision(&denied, Vec::new()), Err(problem(&denied)));
        let pending = answer(
            200,
            &json!({"outcome": "require_action", "next": "approve"}),
        );
        assert_eq!(
            decision(&pending, Vec::new()),
            Err(Refusal::Pending("approve".to_owned()))
        );
        let allowed = answer(
            200,
            &json!({"outcome": "allow", "exercise": "AQ", "receipt": b64url(b"receipt")}),
        );
        let exercise = decision(&allowed, b"intent".to_vec()).unwrap();
        assert_eq!(exercise.receipt, b"receipt");
        assert_eq!(exercise.intent, b"intent");
    }

    // T-105 T-101
    #[test]
    fn t_105_the_client_ids_and_the_pep_come_from_what_the_environment_holds() {
        let bootstrap = json!({"clients": [
            {"product": "work", "client_id": "app_work"},
            {"product": "one", "client_id": "app_one"},
        ]});
        assert_eq!(client_of(&bootstrap, "one").as_deref(), Some("app_one"));
        assert_eq!(client_of(&bootstrap, "relay"), None);
        let realms = json!({"realms": [{"slug": "platform", "tenant": "tnt_p"}]});
        assert_eq!(tenant_of(&realms, "platform").as_deref(), Some("tnt_p"));
        assert_eq!(tenant_of(&realms, "acme"), None);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(b"certificate")
        );
        assert_eq!(x5t_s256(&pem), Some(b64url(&sha256(b"certificate"))));
        assert_eq!(x5t_s256("no certificate"), None);
    }
}
