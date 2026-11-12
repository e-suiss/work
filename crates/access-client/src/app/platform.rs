//! The platform routes and Work's pairing step (T-101 item 8, T-103): every request carries a fresh client assertion as `Authorization: Bearer` and nothing else, no TLS client certificate and no `DPoP`. [`run`] is the one code path of start-up, the hourly reconciliation, `tenant.created` and `work-cli access pair`: it maps the organizations each tenant's snapshot lists (E-3), stores each tenant's live realms and retires the others, asks for challenges where a realm is not paired under the service key, checks and signs them, sends every signed target in one request, retries once with a new challenge, counts failed runs, and keeps Work's SSF push stream open.

use std::collections::BTreeSet;

use access_kernel::ais::CONTENT_TYPE as AIS_CONTENT_TYPE;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::signer::{Signer, sign_sign1};
use work_proto::id::TenantId;

use crate::app::Client;
use crate::domain::assertion::{Claims, compact};
use crate::domain::discovery::{Endpoint, Endpoints, Issuer, percent};
use crate::domain::organizations::{
    OrganizationChange, OrganizationId, OrganizationOutcome, unlisted,
};
use crate::domain::pairing::{
    Answer, MAX_TARGETS, PairState, Plan, RealmChange, RealmId, STALLED_RUNS, Signed, Statements,
    StoredRealm, Unsignable, needs_pairing, pairing_body, plan_challenges, plan_result, retryable,
    snapshot_changes,
};
use crate::domain::streams::{self, Stream, StreamCheck, StreamStatus};
use crate::domain::tenants::TenantSnapshot;
use crate::domain::{AccessError, b64url};
use crate::ports::{Clock, PairingStore, Random, Request, Response, StoredStream, Transport};

const JSON: &str = "application/json";

/// The client of the platform routes, authenticated by `work-access-client`.
pub struct Platform<T, C, R, K> {
    transport: T,
    clock: C,
    random: R,
    key: K,
    kid: String,
    client_id: String,
    audience: String,
}

impl<T, C, R, K> std::fmt::Debug for Platform<T, C, R, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Platform")
            .field("client_id", &self.client_id)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// What opening a stream gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opened {
    /// The new stream.
    Stream(Stream),
    /// `409 stream-exists`: a live stream to the receiver is there already.
    Exists,
}

impl<T: Transport, C: Clock, R: Random, K: Signer + Send + Sync> Platform<T, C, R, K> {
    /// The client `client_id` of the platform realm `audience`, signing with `key`.
    #[must_use]
    pub fn new(
        transport: T,
        clock: C,
        random: R,
        key: K,
        client_id: &str,
        audience: &Issuer,
    ) -> Self {
        let kid = b64url(&thumbprint(&key.public_key()));
        Self {
            transport,
            clock,
            random,
            key,
            kid,
            client_id: client_id.to_owned(),
            audience: audience.as_str().to_owned(),
        }
    }

    /// Now, Unix milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// A fresh client assertion (T-101 item 8): a new `jti` from the RNG port, signed now.
    ///
    /// # Errors
    /// [`AccessError::KeyStore`].
    pub fn assertion(&self) -> Result<String, AccessError> {
        let mut jti = [0_u8; 32];
        self.random.fill(&mut jti)?;
        let input = Claims {
            kid: &self.kid,
            client_id: &self.client_id,
            audience: &self.audience,
            jti,
            now_ms: self.clock.now_ms(),
        }
        .signing_input()?;
        let signature = self
            .key
            .sign(input.as_bytes())
            .map_err(|e| AccessError::KeyStore(e.to_string()))?;
        compact(&input, &signature)
    }

    async fn send(&self, request: Request) -> Result<Response, AccessError> {
        let bearer = format!("Bearer {}", self.assertion()?);
        self.transport
            .send(request.with("authorization", &bearer))
            .await
    }

    /// `POST <pairing_challenges>` without a body: every live realm of `tenant`.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn challenges(
        &self,
        endpoints: &Endpoints,
        tenant: &TenantId,
    ) -> Result<Answer, AccessError> {
        let url = endpoints
            .get(Endpoint::PairingChallenges)?
            .expand(tenant.as_str());
        let answer = self.send(Request::post(url, JSON, Vec::new())).await?;
        Answer::from_json(answer.created()?, tenant.as_str())
    }

    /// `POST <pairing>` with up to [`MAX_TARGETS`] signed targets.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn pair(
        &self,
        endpoints: &Endpoints,
        tenant: &TenantId,
        signed: &[Signed],
    ) -> Result<Answer, AccessError> {
        let url = endpoints.get(Endpoint::Pairing)?.expand(tenant.as_str());
        let answer = self
            .send(Request::post(url, JSON, pairing_body(signed)?))
            .await?;
        Answer::from_json(answer.ok()?, tenant.as_str())
    }

    /// `GET <platform_streams>`.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn streams(&self, endpoints: &Endpoints) -> Result<Vec<Stream>, AccessError> {
        let url = endpoints.get(Endpoint::PlatformStreams)?.expand("");
        let answer = self.send(Request::get(url, JSON)).await?;
        Stream::list_from_json(answer.ok()?)
    }

    /// `GET <platform_streams>/{id}`; `None` for `404 no-such-stream`.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn stream(
        &self,
        endpoints: &Endpoints,
        id: &str,
    ) -> Result<Option<Stream>, AccessError> {
        let base = endpoints.get(Endpoint::PlatformStreams)?.expand("");
        let answer = self
            .send(Request::get(format!("{base}/{}", percent(id)), JSON))
            .await?;
        match answer.ok() {
            Ok(body) => Stream::from_json(body).map(Some),
            Err(AccessError::Refused {
                status: 404, code, ..
            }) if code == "no-such-stream" => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `POST <platform_streams>`: a push stream to `receiver` for Work's `client_id` asking for
    /// `events`.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn open_stream(
        &self,
        endpoints: &Endpoints,
        receiver: &str,
        events: &[String],
    ) -> Result<Opened, AccessError> {
        let url = endpoints.get(Endpoint::PlatformStreams)?.expand("");
        let body = streams::create_body(receiver, &self.client_id, events);
        let answer = self.send(Request::post(url, JSON, body)).await?;
        match answer.created() {
            Ok(body) => Stream::from_json(body).map(Opened::Stream),
            Err(AccessError::Refused {
                status: 409, code, ..
            }) if code == "stream-exists" => Ok(Opened::Exists),
            Err(e) => Err(e),
        }
    }
}

/// The AIS of one challenge: tagged `COSE_Sign1` by the service key, `alg` from the key, `kid`
/// its RFC 7638 thumbprint, content type `application/access-ais+cbor` (T-103 item 3).
///
/// # Errors
/// [`AccessError::KeyStore`].
pub fn sign_challenge<V: Signer>(
    service: &V,
    realm: RealmId,
    challenge: [u8; 32],
    statements: &Statements,
) -> Result<Signed, AccessError> {
    let kid = thumbprint(&service.public_key());
    let one = |payload: &Vec<u8>| {
        sign_sign1(service, kid, AIS_CONTENT_TYPE, payload)
            .map_err(|e| AccessError::KeyStore(e.to_string()))
    };
    Ok(Signed {
        realm,
        challenge,
        ais: one(&statements.instance_create)?,
        register_ais: statements.party_register.as_ref().map(one).transpose()?,
    })
}

/// Which tenants a step looks at (T-103 item 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Start-up and the hourly run: tenants with a live realm not paired under the service key.
    Due,
    /// `work-cli access pair`: every active tenant, at once.
    All,
    /// `tenant.created` and `work-cli access pair --tenant`: this tenant, at once.
    Tenant(TenantId),
}

/// What a step tells the operator and the tenant administrator (T-103 items 2, 4, 6, 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// A challenge was not signed.
    Unsignable {
        /// The tenant.
        tenant: TenantId,
        /// The realm.
        realm: RealmId,
        /// Why.
        reason: Unsignable,
    },
    /// The authority plane refused the realm; the tenant administrator sees "realm not paired
    /// with Work" under the slug.
    Refused {
        /// The tenant.
        tenant: TenantId,
        /// The realm.
        realm: RealmId,
        /// The realm's slug.
        slug: String,
        /// Access's code.
        code: String,
    },
    /// A realm refused before is paired; its attention item closes.
    Cleared {
        /// The tenant.
        tenant: TenantId,
        /// The realm.
        realm: RealmId,
        /// The realm's slug.
        slug: String,
    },
    /// [`STALLED_RUNS`] or more runs in a row did not pair the realm.
    Unpaired {
        /// The tenant.
        tenant: TenantId,
        /// The realm.
        realm: RealmId,
        /// Failed runs in a row.
        runs: u64,
    },
    /// A call or the store failed.
    Failed {
        /// The tenant, when the failure is one tenant's.
        tenant: Option<TenantId>,
        /// What failed.
        error: AccessError,
    },
    /// The tenant snapshot lists an organization Work had not mapped; it is mapped now (E-3).
    OrganizationMapped {
        /// The tenant.
        tenant: TenantId,
        /// The organization.
        organization: OrganizationId,
    },
    /// A mapped organization the tenant snapshot's list no longer names; the row stays.
    OrganizationUnlisted {
        /// The tenant.
        tenant: TenantId,
        /// The organization.
        organization: OrganizationId,
    },
    /// Work opened its stream again.
    StreamRecreated {
        /// The new stream.
        stream: String,
    },
    /// The stream is paused or unreachable.
    StreamDown {
        /// The stream.
        stream: String,
        /// Its status.
        status: StreamStatus,
    },
}

impl Signal {
    /// The log event name.
    #[must_use]
    pub const fn event(&self) -> &'static str {
        match self {
            Self::Unsignable { .. } => "access.pairing_unsignable",
            Self::Refused { .. } => "access.realm_refused",
            Self::Cleared { .. } => "access.realm_paired_again",
            Self::Unpaired { .. } => "access.realm_unpaired",
            Self::Failed { .. } => "access.pairing_failed",
            Self::OrganizationMapped { .. } => "access.organization_mapped",
            Self::OrganizationUnlisted { .. } => "access.organization_unlisted",
            Self::StreamRecreated { .. } => "access.event_stream_recreated",
            Self::StreamDown { .. } => "access.event_stream_down",
        }
    }
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsignable {
                tenant,
                realm,
                reason,
            } => write!(
                f,
                "{} realm {}: challenge not signed ({})",
                tenant.as_str(),
                realm.as_str(),
                reason.code()
            ),
            Self::Refused {
                tenant,
                realm,
                slug,
                code,
            } => write!(
                f,
                "{} realm {slug} ({}): not paired with Work, {code}",
                tenant.as_str(),
                realm.as_str()
            ),
            Self::Cleared {
                tenant,
                realm,
                slug,
            } => write!(
                f,
                "{} realm {slug} ({}): paired",
                tenant.as_str(),
                realm.as_str()
            ),
            Self::Unpaired {
                tenant,
                realm,
                runs,
            } => write!(
                f,
                "{} realm {}: {runs} runs in a row without pairing",
                tenant.as_str(),
                realm.as_str()
            ),
            Self::Failed {
                tenant: Some(t),
                error,
            } => write!(f, "{}: {error}", t.as_str()),
            Self::Failed {
                tenant: None,
                error,
            } => write!(f, "{error}"),
            Self::OrganizationMapped {
                tenant,
                organization,
            } => write!(
                f,
                "{} organization {} mapped",
                tenant.as_str(),
                organization.as_str()
            ),
            Self::OrganizationUnlisted {
                tenant,
                organization,
            } => write!(
                f,
                "{} organization {} is no longer listed by Access",
                tenant.as_str(),
                organization.as_str()
            ),
            Self::StreamRecreated { stream } => write!(f, "event stream {stream} opened again"),
            Self::StreamDown { stream, status } => {
                write!(f, "event stream {stream} is {}", status.as_str())
            }
        }
    }
}

/// What one step did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Active tenants of Work's region looked at.
    pub tenants: usize,
    /// Realms that ended paired in this step.
    pub paired: usize,
    /// Organizations the snapshots listed that this step mapped (E-3).
    pub organizations: usize,
    /// The signals, in order.
    pub signals: Vec<Signal>,
    /// `work_access_unpaired_realms`, when the store answered.
    pub unpaired_realms: Option<u64>,
    /// `work_access_event_stream_recreated_total`, when the stream row was written.
    pub recreated: Option<u64>,
    /// `work_access_event_stream_up`.
    pub stream_up: bool,
}

/// What a step needs besides the two clients: Work's realm table, the service key in the token
/// and the `suiss_event_receiver` the stream pushes to.
#[derive(Debug)]
pub struct Step<'a, S, V> {
    /// Work's realm table.
    pub store: &'a S,
    /// `work-access-service`.
    pub service: &'a V,
    /// `<installation URI>/v1/inbound/events`.
    pub receiver: &'a str,
}

#[derive(Default)]
struct Attempt {
    failed: BTreeSet<RealmId>,
    paired: BTreeSet<RealmId>,
    stream: Option<String>,
}

fn slug_of(snapshot: &TenantSnapshot, realm: &RealmId) -> String {
    snapshot
        .realms
        .iter()
        .find(|r| r.id == *realm)
        .map_or_else(|| realm.as_str().to_owned(), |r| r.slug.clone())
}

async fn apply_plan<S: PairingStore>(
    store: &S,
    snapshot: &TenantSnapshot,
    stored: &[StoredRealm],
    plan: &Plan,
    now: u64,
    out: &mut Attempt,
    signals: &mut Vec<Signal>,
) -> Result<(), AccessError> {
    let tenant = &snapshot.tenant;
    for change in &plan.changes {
        match change {
            RealmChange::Failed { realm } => {
                out.failed.insert(realm.clone());
            }
            RealmChange::Paired { realm, .. } => {
                store.apply(tenant, change, now).await?;
                out.failed.remove(realm);
                let first = out.paired.insert(realm.clone());
                let was_refused = stored
                    .iter()
                    .any(|s| s.realm == *realm && s.state == PairState::Refused);
                if first && was_refused {
                    signals.push(Signal::Cleared {
                        tenant: tenant.clone(),
                        realm: realm.clone(),
                        slug: slug_of(snapshot, realm),
                    });
                }
            }
            _ => {
                store.apply(tenant, change, now).await?;
            }
        }
    }
    for (realm, code) in &plan.refused {
        signals.push(Signal::Refused {
            tenant: tenant.clone(),
            realm: realm.clone(),
            slug: slug_of(snapshot, realm),
            code: code.clone(),
        });
    }
    for (realm, reason) in &plan.unsignable {
        signals.push(Signal::Unsignable {
            tenant: tenant.clone(),
            realm: realm.clone(),
            reason: *reason,
        });
    }
    Ok(())
}

async fn attempt<P, D, R, K, S, V>(
    platform: &Platform<P, D, R, K>,
    step: &Step<'_, S, V>,
    endpoints: &Endpoints,
    snapshot: &TenantSnapshot,
    stored: &[StoredRealm],
    out: &mut Attempt,
    signals: &mut Vec<Signal>,
) -> Result<(), AccessError>
where
    P: Transport,
    D: Clock,
    R: Random,
    K: Signer + Send + Sync,
    S: PairingStore,
    V: Signer + Send + Sync,
{
    let tenant = &snapshot.tenant;
    let challenges = platform.challenges(endpoints, tenant).await?;
    let now = platform.now_ms();
    let plan = plan_challenges(&challenges, &step.service.public_key(), now);
    apply_plan(step.store, snapshot, stored, &plan, now, out, signals).await?;
    let signed = plan
        .sign
        .into_iter()
        .map(|(realm, challenge, statements)| {
            sign_challenge(step.service, realm, challenge, &statements)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for chunk in signed.chunks(MAX_TARGETS) {
        let result = platform.pair(endpoints, tenant, chunk).await?;
        let answered: Vec<RealmId> = chunk.iter().map(|s| s.realm.clone()).collect();
        let plan = plan_result(&result, &answered);
        apply_plan(
            step.store,
            snapshot,
            stored,
            &plan,
            platform.now_ms(),
            out,
            signals,
        )
        .await?;
        if result.event_stream.is_some() {
            out.stream = result.event_stream;
        }
    }
    Ok(())
}

async fn count_failures<S: PairingStore>(
    store: &S,
    tenant: &TenantId,
    failed: &BTreeSet<RealmId>,
    now: u64,
    signals: &mut Vec<Signal>,
) -> Result<(), AccessError> {
    for realm in failed {
        let change = RealmChange::Failed {
            realm: realm.clone(),
        };
        if let Some(runs) = store.apply(tenant, &change, now).await?
            && runs >= STALLED_RUNS
        {
            signals.push(Signal::Unpaired {
                tenant: tenant.clone(),
                realm: realm.clone(),
                runs,
            });
        }
    }
    Ok(())
}

/// Maps every organization `snapshot` lists and reports the mapped ones a list no longer
/// names (E-3, T-96 item 4).
pub(crate) async fn organization_step<S: PairingStore>(
    store: &S,
    snapshot: &TenantSnapshot,
    now: u64,
    report: &mut Report,
) -> Result<(), AccessError> {
    let tenant = &snapshot.tenant;
    for organization in &snapshot.organizations {
        let change = OrganizationChange::Listed {
            organization: organization.clone(),
        };
        if store.map_organization(tenant, &change, now).await? == OrganizationOutcome::Mapped {
            report.organizations = report.organizations.saturating_add(1);
            report.signals.push(Signal::OrganizationMapped {
                tenant: tenant.clone(),
                organization: organization.clone(),
            });
        }
    }
    if snapshot.organizations.is_empty() {
        return Ok(());
    }
    let known = store.organizations(tenant).await?;
    for organization in unlisted(&known, &snapshot.organizations) {
        report.signals.push(Signal::OrganizationUnlisted {
            tenant: tenant.clone(),
            organization,
        });
    }
    Ok(())
}

async fn tenant_step<P, D, R, K, S, V>(
    platform: &Platform<P, D, R, K>,
    step: &Step<'_, S, V>,
    endpoints: &Endpoints,
    snapshot: &TenantSnapshot,
    force: bool,
    report: &mut Report,
) -> Result<Option<String>, AccessError>
where
    P: Transport,
    D: Clock,
    R: Random,
    K: Signer + Send + Sync,
    S: PairingStore,
    V: Signer + Send + Sync,
{
    let tenant = &snapshot.tenant;
    let now = platform.now_ms();
    organization_step(step.store, snapshot, now, report).await?;
    for change in snapshot_changes(&snapshot.realms) {
        step.store.apply(tenant, &change, now).await?;
    }
    let stored = step.store.realms(tenant).await?;
    let live: Vec<RealmId> = snapshot.realms.iter().map(|r| r.id.clone()).collect();
    let kid = thumbprint(&step.service.public_key());
    if live.is_empty() || !(force || needs_pairing(&live, &stored, &kid)) {
        return Ok(None);
    }
    let mut out = Attempt::default();
    let mut outcome = attempt(
        platform,
        step,
        endpoints,
        snapshot,
        &stored,
        &mut out,
        &mut report.signals,
    )
    .await;
    if outcome.as_ref().is_err_and(retryable) {
        out.failed.clear();
        outcome = attempt(
            platform,
            step,
            endpoints,
            snapshot,
            &stored,
            &mut out,
            &mut report.signals,
        )
        .await;
    }
    let mut failed = out.failed;
    if outcome.is_err() {
        let held: BTreeSet<&RealmId> = stored
            .iter()
            .filter(|s| s.state == PairState::Paired && s.kid == Some(kid))
            .map(|s| &s.realm)
            .collect();
        failed.extend(
            live.iter()
                .filter(|r| !held.contains(r) && !out.paired.contains(*r))
                .cloned(),
        );
    }
    count_failures(
        step.store,
        tenant,
        &failed,
        platform.now_ms(),
        &mut report.signals,
    )
    .await?;
    report.paired = report.paired.saturating_add(out.paired.len());
    outcome.map(|()| out.stream)
}

async fn record<S: PairingStore>(
    store: &S,
    found: Option<&Stream>,
    recreated: bool,
    now: u64,
) -> Result<StoredStream, AccessError> {
    store
        .record_stream(
            found.map(|s| s.id.as_str()),
            found.map(|s| s.status),
            recreated,
            now,
        )
        .await
}

async fn stream_step<P, D, R, K, S, V>(
    platform: &Platform<P, D, R, K>,
    step: &Step<'_, S, V>,
    endpoints: &Endpoints,
    seen: Option<&str>,
    signals: &mut Vec<Signal>,
) -> Result<StoredStream, AccessError>
where
    P: Transport,
    D: Clock,
    R: Random,
    K: Signer + Send + Sync,
    S: PairingStore,
    V: Signer + Send + Sync,
{
    let receiver = step.receiver;
    let known = step.store.stream().await?.and_then(|s| s.id);
    let id = match (seen, known) {
        (Some(s), Some(k)) if s != k => None,
        (Some(s), _) => Some(s.to_owned()),
        (None, k) => k,
    };
    let found = if let Some(id) = &id {
        platform.stream(endpoints, id).await?
    } else {
        let list = platform.streams(endpoints).await?;
        streams::live(&list, receiver).cloned()
    };
    let now = platform.now_ms();
    match streams::check(found.as_ref()) {
        StreamCheck::Up => record(step.store, found.as_ref(), false, now).await,
        StreamCheck::Down(status) => {
            if let Some(s) = &found {
                signals.push(Signal::StreamDown {
                    stream: s.id.clone(),
                    status,
                });
            }
            record(step.store, found.as_ref(), false, now).await
        }
        StreamCheck::Reopen => {
            let mut known = platform.streams(endpoints).await?;
            known.extend(found);
            let events = streams::events(&known);
            if let Opened::Stream(s) = platform.open_stream(endpoints, receiver, &events).await? {
                signals.push(Signal::StreamRecreated {
                    stream: s.id.clone(),
                });
                record(step.store, Some(&s), true, platform.now_ms()).await
            } else {
                let list = platform.streams(endpoints).await?;
                record(
                    step.store,
                    streams::live(&list, receiver),
                    false,
                    platform.now_ms(),
                )
                .await
            }
        }
    }
}

/// One pairing step over `scope` (T-103 items 1–7): discovery, the tenants, each tenant's
/// pairing, the event stream and the gauges. A failure of one tenant does not stop the others;
/// every failure is a [`Signal::Failed`].
pub async fn run<T, C, P, D, R, K, S, V>(
    client: &Client<T, C>,
    platform: &Platform<P, D, R, K>,
    step: &Step<'_, S, V>,
    scope: &Scope,
) -> Report
where
    T: Transport,
    C: Clock,
    P: Transport,
    D: Clock,
    R: Random,
    K: Signer + Send + Sync,
    S: PairingStore,
    V: Signer + Send + Sync,
{
    let mut report = Report::default();
    let endpoints = match client.discover().await {
        Ok(doc) => doc.endpoints,
        Err(error) => {
            report.signals.push(Signal::Failed {
                tenant: None,
                error,
            });
            return report;
        }
    };
    let tenants = if let Scope::Tenant(t) = scope {
        client.tenant(t).await.map(|s| vec![s])
    } else {
        client.all_tenants().await
    };
    let mut seen: Option<String> = None;
    match tenants {
        Ok(list) => {
            for snapshot in list.iter().filter(|s| s.pairable(client.region())) {
                report.tenants = report.tenants.saturating_add(1);
                let force = !matches!(scope, Scope::Due);
                match tenant_step(platform, step, &endpoints, snapshot, force, &mut report).await {
                    Ok(Some(stream)) => seen = Some(stream),
                    Ok(None) => {}
                    Err(error) => report.signals.push(Signal::Failed {
                        tenant: Some(snapshot.tenant.clone()),
                        error,
                    }),
                }
            }
        }
        Err(error) => report.signals.push(Signal::Failed {
            tenant: None,
            error,
        }),
    }
    match stream_step(
        platform,
        step,
        &endpoints,
        seen.as_deref(),
        &mut report.signals,
    )
    .await
    {
        Ok(row) => {
            report.stream_up = row.status == Some(StreamStatus::Enabled);
            report.recreated = Some(row.recreated);
        }
        Err(error) => report.signals.push(Signal::Failed {
            tenant: None,
            error,
        }),
    }
    match step.store.stalled(STALLED_RUNS).await {
        Ok(n) => report.unpaired_realms = Some(n),
        Err(error) => report.signals.push(Signal::Failed {
            tenant: None,
            error,
        }),
    }
    report
}
