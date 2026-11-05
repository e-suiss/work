//! The Access client's use cases: discovery at start and on refresh (T-96 item 2), Relay's discovery document (T-99 item 1), Domain Metadata kept per domain, verified and cached key lookups (T-101 item 4), the eligibility check (T-101 item 5), the realm token keys an `auth_context` artifact verifies under (P-116), tenant snapshots and the reconciliation job (T-96 item 4), and the platform routes with Work's pairing and event stream upkeep (T-103) in [`platform`], and the Access intake of Work's event entry (T-102) in [`events`]. Every consequential call is refused fail-closed while the PEP certificate has expired or the endpoint it needs is not served (T-28).

pub mod events;
pub mod platform;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use suiss_crypto::cose::KeySet;

use work_proto::id::TenantId;

use crate::domain::cache::{CachePolicy, CachedKey, KeyCache};
use crate::domain::directory::{KnownRealm, by_issuer, page_realms};
use crate::domain::discovery::{
    AuthzenConfiguration, Endpoint, Endpoints, Issuer, SUISS_CONFIGURATION, SuissConfiguration,
    fresh, percent,
};
use crate::domain::eligibility::{Eligibility, EligibilityRequest};
use crate::domain::keys::{
    ACCEPT_COSE, AsOf, DomainId, EXCERPT_HEADER, KeyAnswer, Kid, MAX_KIDS, batch_body,
    etag_position, verify_answer,
};
use crate::domain::metadata::{DomainMetadata, unverified_payload, verify_metadata};
use crate::domain::realm::{OPENID_CONFIGURATION, jwks_uri, realm_keys};
use crate::domain::relay::RelayConfiguration;
use crate::domain::subjects::{
    self, CACHE_ENTRIES, Direction, MAX_SUBJECTS, Resolution, SubjectCache,
};
use crate::domain::tenants::{MAX_PAGES, TenantChange, TenantPage, TenantSnapshot, list_url, plan};
use crate::domain::{AccessError, b64url, from_b64url};
use crate::ports::{Clock, Request, Response, TenantMap, Transport};

/// How often discovery is read again (T-96 item 2).
pub const DISCOVERY_INTERVAL_MS: u64 = 5 * 60 * 1000;

/// How long verified Domain Metadata is kept before it is read again, Access's `max-age`.
pub const METADATA_MAX_AGE_MS: u64 = 5 * 60 * 1000;

/// How long a realm's token keys are kept before they are read again, unless an artifact names a
/// key they do not hold (P-116 item 4).
pub const REALM_KEYS_MAX_AGE_MS: u64 = 5 * 60 * 1000;

/// How long the realms read from the tenant list name callers before the list is read again
/// (PD): a new tenant's callers wait at most this long, and a realm that left the list is
/// refused at most this late.
pub const DIRECTORY_MAX_AGE_MS: u64 = 5 * 60 * 1000;

const JSON: &str = "application/json";

struct Trusted {
    metadata: DomainMetadata,
    signed: Option<Endpoints>,
    read_at_ms: u64,
}

#[derive(Default)]
struct State {
    configuration: Option<SuissConfiguration>,
    discovered: Option<(u64, u64)>,
    domains: BTreeMap<DomainId, Trusted>,
    cache: KeyCache,
    realms: BTreeMap<Issuer, (KeySet, u64)>,
    event_reread_ms: Option<u64>,
    disabled: bool,
    directory: Option<(BTreeMap<String, KnownRealm>, u64)>,
    subjects: SubjectCache,
}

/// A key the client looked up: verified, from the cache or a fresh answer, or unknown to Access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Looked {
    /// The key with the answer it came from.
    Known(Box<CachedKey>),
    /// Access does not know the kid at the point asked.
    Unknown(Kid),
}

/// The client of one Access issuer.
pub struct Client<T, C> {
    transport: T,
    clock: C,
    issuer: Issuer,
    region: String,
    pep_not_after_ms: u64,
    state: Mutex<State>,
}

impl<T, C> std::fmt::Debug for Client<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("issuer", &self.issuer)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

fn poisoned() -> AccessError {
    AccessError::Transport("client state poisoned".to_owned())
}

impl<T: Transport, C: Clock> Client<T, C> {
    /// A client of `issuer` in Work's `region`, over `transport`, whose PEP certificate ends at
    /// `pep_not_after_ms`.
    #[must_use]
    pub fn new(
        transport: T,
        clock: C,
        issuer: Issuer,
        region: &str,
        pep_not_after_ms: u64,
    ) -> Self {
        Self {
            transport,
            clock,
            issuer,
            region: region.to_owned(),
            pep_not_after_ms,
            state: Mutex::new(State {
                subjects: SubjectCache::new(CACHE_ENTRIES),
                ..State::default()
            }),
        }
    }

    /// Now on the client's clock, Unix milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn state(&self) -> Result<MutexGuard<'_, State>, AccessError> {
        self.state.lock().map_err(|_| poisoned())
    }

    async fn get(&self, url: String, accept: &str) -> Result<Response, AccessError> {
        self.transport.send(Request::get(url, accept)).await
    }

    fn consequential(&self) -> Result<(), AccessError> {
        let now = self.clock.now_ms();
        if now > self.pep_not_after_ms {
            return Err(AccessError::Expired);
        }
        let state = self.state()?;
        if state.disabled {
            return Err(AccessError::Disabled);
        }
        fresh(state.discovered, now)
    }

    /// Now on the client's clock, Unix milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Refuses every later consequential action: Access disabled Work's own client
    /// (`api_client.disabled`, T-102 item 5, T-28).
    ///
    /// # Errors
    /// [`AccessError::Transport`] when the client state is poisoned.
    pub fn disable(&self) -> Result<(), AccessError> {
        self.state()?.disabled = true;
        Ok(())
    }

    /// Drops every cached key of `domain` at once (T-102 item 5, E-14).
    ///
    /// # Errors
    /// [`AccessError::Transport`] when the client state is poisoned.
    pub fn forget_domain(&self, domain: DomainId) -> Result<(), AccessError> {
        self.state()?.cache.forget_domain(domain);
        Ok(())
    }

    /// How many keys the cache holds.
    ///
    /// # Errors
    /// [`AccessError::Transport`] when the client state is poisoned.
    pub fn cached_keys(&self) -> Result<usize, AccessError> {
        Ok(self.state()?.cache.len())
    }

    /// The platform realm keys a pushed SET signed under `kid` verifies with (T-102 item 3):
    /// the realm JWKS of `[suiss] access`, read again for a `kid` it does not hold at most once
    /// per [`DISCOVERY_INTERVAL_MS`], so that SETs naming unknown keys cannot make Work read
    /// Access's JWKS on every request.
    ///
    /// # Errors
    /// [`AccessError`]; the SET is not accepted.
    pub async fn event_keys(&self, kid: &[u8; 32]) -> Result<KeySet, AccessError> {
        let now = self.clock.now_ms();
        {
            let state = self.state()?;
            if let Some((keys, read_at)) = state.realms.get(&self.issuer)
                && now.saturating_sub(*read_at) < REALM_KEYS_MAX_AGE_MS
                && (keys.keys.contains_key(kid)
                    || state
                        .event_reread_ms
                        .is_some_and(|at| now.saturating_sub(at) < DISCOVERY_INTERVAL_MS))
            {
                return Ok(keys.clone());
            }
        }
        let issuer = self.issuer.clone();
        let keys = self.realm_keys(&issuer, kid).await?;
        if !keys.keys.contains_key(kid) {
            self.state()?.event_reread_ms = Some(now);
        }
        Ok(keys)
    }

    /// Puts a key set for the platform realm as read at `read_at_ms`, for tests that hand the
    /// intake a known JWKS.
    #[cfg(test)]
    pub(crate) fn put_event_keys(&self, keys: KeySet, read_at_ms: u64) {
        if let Ok(mut state) = self.state() {
            state.realms.insert(self.issuer.clone(), (keys, read_at_ms));
        }
    }

    /// Puts a verified key answer in the cache, for tests.
    #[cfg(test)]
    pub(crate) fn put_key(&self, answer: &KeyAnswer, as_of: &AsOf, now_ms: u64) {
        if let Ok(mut state) = self.state() {
            state.cache.put(
                answer,
                as_of,
                CachePolicy::parse(Some("max-age=300")),
                now_ms,
            );
        }
    }

    /// The endpoints the last discovery read.
    ///
    /// # Errors
    /// [`AccessError::Unserved`] before discovery.
    pub fn served(&self) -> Result<Endpoints, AccessError> {
        self.endpoints()
    }

    /// Work's region (E-4).
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The Access issuer, `[suiss] access`.
    #[must_use]
    pub const fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    fn endpoints(&self) -> Result<Endpoints, AccessError> {
        self.state()?
            .configuration
            .as_ref()
            .map(|c| c.endpoints.clone())
            .ok_or(AccessError::Unserved(Endpoint::Adp))
    }

    /// Reads the Suiss configuration and the `AuthZEN` document and checks what start needs; the
    /// document is kept for every later call and carries consequential actions for as long as
    /// Access's `max-age` allows (T-96 item 2, Access OP-149 m.2). A failed refresh keeps the
    /// last document.
    ///
    /// # Errors
    /// [`AccessError`]; at start each refuses start.
    pub async fn discover(&self) -> Result<SuissConfiguration, AccessError> {
        let read_at = self.clock.now_ms();
        let answer = self
            .get(self.issuer.well_known(SUISS_CONFIGURATION), JSON)
            .await?;
        let doc = SuissConfiguration::from_json(answer.ok()?, &self.issuer)?;
        let max_age = CachePolicy::parse(answer.header("cache-control"))
            .max_age_ms
            .unwrap_or(DISCOVERY_INTERVAL_MS);
        let adp = doc.endpoints.get(Endpoint::Adp)?.as_str().to_owned();
        let authzen = AuthzenConfiguration::from_json(self.get(adp, JSON).await?.ok()?)?;
        doc.check_start(&authzen, &self.region)?;
        let mut state = self.state()?;
        state.configuration = Some(doc.clone());
        state.discovered = Some((read_at, max_age));
        Ok(doc)
    }

    /// Drops every cached key `kid` of `domain` at once, as an `instance-terminated` event asks;
    /// the next admission looks the key up again (T-102 item 5, E-14).
    ///
    /// # Errors
    /// [`AccessError::Transport`] when the client state is poisoned.
    pub fn forget(&self, domain: DomainId, kid: Kid) -> Result<(), AccessError> {
        self.state()?.cache.forget(domain, kid);
        Ok(())
    }

    /// Reads Relay's discovery document at the `suiss_relay` discovery named, over
    /// `relay_transport`, for
    /// the dated `contract_version` (T-99 items 1, 2).
    ///
    /// # Errors
    /// [`AccessError`]; at start each refuses start.
    pub async fn relay(
        &self,
        relay_transport: &impl Transport,
        contract_version: &str,
    ) -> Result<RelayConfiguration, AccessError> {
        let base = self
            .state()?
            .configuration
            .as_ref()
            .map(|c| c.relay.clone())
            .ok_or(AccessError::Unserved(Endpoint::Adp))?;
        let request = Request::get(RelayConfiguration::url(&base), JSON)
            .with("relay-version", contract_version);
        let answer = relay_transport.send(request).await?;
        RelayConfiguration::from_json(
            answer.ok()?,
            &base,
            &self.issuer,
            &self.region,
            contract_version,
        )
    }

    /// The domain's Domain Metadata: read from the domain's `AuthZEN` document, verified against
    /// the binding keys of the metadata accepted before for the domain, or, the first time,
    /// against its own binding keys; kept for [`METADATA_MAX_AGE_MS`].
    async fn metadata(
        &self,
        domain: DomainId,
    ) -> Result<(DomainMetadata, Option<Endpoints>), AccessError> {
        let now = self.clock.now_ms();
        let previous = {
            let state = self.state()?;
            match state.domains.get(&domain) {
                Some(t) if now.saturating_sub(t.read_at_ms) < METADATA_MAX_AGE_MS => {
                    return Ok((t.metadata.clone(), t.signed.clone()));
                }
                Some(t) => Some(t.metadata.binding_set()),
                None => None,
            }
        };
        let adp = self.endpoints()?.get(Endpoint::Adp)?.as_str().to_owned();
        let answer = self.get(format!("{adp}/{}", domain.text()), JSON).await?;
        let signed = AuthzenConfiguration::from_json(answer.ok()?)?
            .signed_metadata
            .ok_or(AccessError::Metadata("absent"))?;
        let trusted = match previous {
            Some(set) => set,
            None => DomainMetadata::from_bytes(
                &unverified_payload(&signed).map_err(|e| AccessError::Metadata(e.code()))?,
            )
            .map_err(|e| AccessError::Metadata(e.code()))?
            .binding_set(),
        };
        let metadata =
            verify_metadata(&signed, &trusted).map_err(|e| AccessError::Metadata(e.code()))?;
        if metadata.domain != domain.0 {
            return Err(AccessError::Metadata("domain-mismatch"));
        }
        let signed_discovery = metadata
            .discovery
            .as_deref()
            .map(Endpoints::from_signed)
            .transpose()?;
        self.state()?.domains.insert(
            domain,
            Trusted {
                metadata: metadata.clone(),
                signed: signed_discovery.clone(),
                read_at_ms: now,
            },
        );
        Ok((metadata, signed_discovery))
    }

    /// The keys `kids` of `domain` at `as_of`: fresh cached entries, the rest asked from Access
    /// in batches of at most [`MAX_KIDS`], each answer verified before use (T-101 item 4).
    ///
    /// # Errors
    /// [`AccessError`]; the action that needs the keys is refused.
    pub async fn keys(
        &self,
        domain: DomainId,
        kids: &[Kid],
        as_of: &AsOf,
    ) -> Result<Vec<Looked>, AccessError> {
        self.consequential()?;
        let now = self.clock.now_ms();
        let mut found: BTreeMap<Kid, Looked> = BTreeMap::new();
        {
            let state = self.state()?;
            for kid in kids {
                if let Some(c) = state.cache.get(domain, *kid, as_of, now) {
                    found.insert(*kid, Looked::Known(Box::new(c.clone())));
                }
            }
        }
        let missing: Vec<Kid> = kids
            .iter()
            .filter(|k| !found.contains_key(k))
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for chunk in missing.chunks(MAX_KIDS) {
            let (answer, policy) = self.lookup(domain, chunk, as_of).await?;
            for key in &answer.keys {
                let cached = CachedKey::of(key.clone(), &answer);
                found.insert(key.kid, Looked::Known(Box::new(cached)));
            }
            for kid in &answer.unknown {
                found.insert(*kid, Looked::Unknown(*kid));
            }
            self.state()?.cache.put(&answer, as_of, policy, now);
        }
        kids.iter()
            .map(|k| found.get(k).cloned().ok_or(AccessError::Answer("kids")))
            .collect()
    }

    async fn lookup(
        &self,
        domain: DomainId,
        kids: &[Kid],
        as_of: &AsOf,
    ) -> Result<(KeyAnswer, CachePolicy), AccessError> {
        let (metadata, signed) = self.metadata(domain).await?;
        let endpoints = self.endpoints()?;
        let request = if let [kid] = kids {
            let template = endpoints.agreed(Endpoint::KeyLookup, signed.as_ref())?;
            let mut url = format!(
                "{}?domain={}",
                template.expand(&kid.text()),
                percent(&domain.text())
            );
            if let Some(t) = as_of.text() {
                url = format!("{url}&as_of={}", percent(&t));
            }
            Request::get(url, ACCEPT_COSE)
        } else {
            let template = endpoints.agreed(Endpoint::KeyBatch, signed.as_ref())?;
            Request::post(
                template.expand(""),
                ACCEPT_COSE,
                batch_body(&domain, kids, as_of)?,
            )
        };
        let answer = self.transport.send(request).await?;
        let body = answer.ok()?;
        if !answer
            .header("content-type")
            .is_some_and(|c| c.to_ascii_lowercase().starts_with(ACCEPT_COSE))
        {
            return Err(AccessError::Answer("content-type"));
        }
        let excerpt = from_b64url(
            answer
                .header(EXCERPT_HEADER)
                .ok_or(AccessError::Answer("excerpt"))?,
        )
        .map_err(|_| AccessError::Answer("excerpt"))?;
        let verified = verify_answer(
            &metadata,
            &domain,
            kids,
            body,
            &excerpt,
            etag_position(answer.header("etag")),
        )?;
        Ok((verified, CachePolicy::parse(answer.header("cache-control"))))
    }

    /// Asks whether a subject is in a set at the moment of approval; Access records nothing and
    /// the answer is never cached (T-101 item 5).
    ///
    /// # Errors
    /// [`AccessError`]; the approval is refused.
    pub async fn eligibility(
        &self,
        request: &EligibilityRequest,
    ) -> Result<Eligibility, AccessError> {
        self.consequential()?;
        let url = self.endpoints()?.get(Endpoint::Eligibility)?.expand("");
        let answer = self
            .transport
            .send(Request::post(url, JSON, request.body()))
            .await?;
        Eligibility::from_json(answer.ok()?)
    }

    /// The token keys of `realm` that verify an `auth_context` artifact signed under `kid`
    /// (P-116 item 4): the realm JWKS its OIDC discovery document names, kept for
    /// [`REALM_KEYS_MAX_AGE_MS`] and read again sooner when it does not hold `kid`.
    ///
    /// # Errors
    /// [`AccessError`]; the record is refused.
    pub async fn realm_keys(&self, realm: &Issuer, kid: &[u8; 32]) -> Result<KeySet, AccessError> {
        let now = self.clock.now_ms();
        let cached = self
            .state()?
            .realms
            .get(realm)
            .filter(|(keys, read_at)| {
                now.saturating_sub(*read_at) < REALM_KEYS_MAX_AGE_MS && keys.keys.contains_key(kid)
            })
            .map(|(keys, _)| keys.clone());
        if let Some(keys) = cached {
            return Ok(keys);
        }
        let configuration = self
            .get(realm.well_known(OPENID_CONFIGURATION), JSON)
            .await?;
        let uri = jwks_uri(configuration.ok()?, realm)?;
        let keys = realm_keys(self.get(uri, JSON).await?.ok()?)?;
        self.state()?
            .realms
            .insert(realm.clone(), (keys.clone(), now));
        Ok(keys)
    }

    /// The realm whose issuer is `issuer` among the live realms of the active tenants of Work's
    /// region (T-96 item 4, P-116 item 4): read from the tenant list over the PEP certificate and
    /// kept for [`DIRECTORY_MAX_AGE_MS`]; `None` when no such realm names callers.
    ///
    /// # Errors
    /// [`AccessError`]; the caller is not authenticated.
    pub async fn realm_of(&self, issuer: &str) -> Result<Option<KnownRealm>, AccessError> {
        let now = self.clock.now_ms();
        let cached = self
            .state()?
            .directory
            .as_ref()
            .filter(|(_, read_at)| now.saturating_sub(*read_at) < DIRECTORY_MAX_AGE_MS)
            .map(|(realms, _)| realms.get(issuer).cloned());
        if let Some(found) = cached {
            return Ok(found);
        }
        let endpoints = self.endpoints()?;
        let template = endpoints.get(Endpoint::TenantSnapshot)?;
        let mut realms = Vec::new();
        let mut cursors = BTreeSet::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let url = list_url(template, cursor.as_deref())?;
            let (page, next) = page_realms(self.get(url, JSON).await?.ok()?, &self.region)?;
            realms.extend(page);
            match next {
                None => {
                    let directory = by_issuer(realms);
                    let found = directory.get(issuer).cloned();
                    self.state()?.directory = Some((directory, now));
                    return Ok(found);
                }
                Some(next) if !cursors.insert(next.clone()) => {
                    return Err(AccessError::Answer("cursor"));
                }
                Some(next) => cursor = Some(next),
            }
        }
        Err(AccessError::Answer("pages"))
    }

    /// Resolves `values` of `direction` for the pairwise sector `client_id` in `realm` of
    /// `tenant` (T-101 item 2; Access OP-149 m.19 (g)): cached values first, the rest asked of
    /// Access over the PEP certificate in calls of at most [`MAX_SUBJECTS`]. Every value maps to
    /// its counterpart, `None` when Access does not know it; only resolved pairs are cached.
    ///
    /// # Errors
    /// [`AccessError`]; nothing is resolved.
    pub async fn resolve(
        &self,
        tenant: &TenantId,
        realm: &str,
        client_id: &str,
        direction: Direction,
        values: &[String],
    ) -> Result<BTreeMap<String, Option<String>>, AccessError> {
        let mut out = BTreeMap::new();
        let mut missing: Vec<String> = Vec::new();
        {
            let mut state = self.state()?;
            for value in values {
                if out.contains_key(value) || missing.contains(value) {
                    continue;
                }
                match state
                    .subjects
                    .get(tenant, realm, client_id, direction, value)
                {
                    Some(found) => {
                        out.insert(value.clone(), Some(found));
                    }
                    None => missing.push(value.clone()),
                }
            }
        }
        if missing.is_empty() {
            return Ok(out);
        }
        let url = self
            .endpoints()?
            .get(Endpoint::SubjectResolution)?
            .expand(tenant.as_str());
        for chunk in missing.chunks(MAX_SUBJECTS) {
            let body = subjects::body(realm, client_id, direction, chunk)?;
            let answer = self
                .transport
                .send(Request::post(url.clone(), JSON, body))
                .await?;
            let resolution =
                Resolution::from_json(answer.ok()?, realm, client_id, direction, chunk)?;
            self.state()?
                .subjects
                .keep(tenant, realm, client_id, &resolution);
            for (party, sub) in &resolution.pairs {
                let (asked, counterpart) = match direction {
                    Direction::Parties => (b64url(party), sub.clone()),
                    Direction::Subs => (sub.clone(), b64url(party)),
                };
                out.insert(asked, Some(counterpart));
            }
            for unknown in resolution.unknown {
                out.insert(unknown, None);
            }
        }
        Ok(out)
    }

    /// One tenant's snapshot.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn tenant(&self, tenant: &TenantId) -> Result<TenantSnapshot, AccessError> {
        let url = self
            .endpoints()?
            .get(Endpoint::TenantSnapshot)?
            .expand(tenant.as_str());
        TenantSnapshot::from_json(self.get(url, JSON).await?.ok()?)
    }

    /// One page of the tenant list.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn tenants(&self, cursor: Option<&str>) -> Result<TenantPage, AccessError> {
        let url = list_url(self.endpoints()?.get(Endpoint::TenantSnapshot)?, cursor)?;
        TenantPage::from_json(self.get(url, JSON).await?.ok()?)
    }

    /// One reconciliation run, at start and every hour (T-96 item 4): reads the whole tenant
    /// list, then applies to `map` what [`plan`] finds. A list that does not end, or repeats a
    /// cursor, applies nothing.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn reconcile(&self, map: &impl TenantMap) -> Result<Vec<TenantChange>, AccessError> {
        let seen = self.all_tenants().await?;
        let changes = plan(&map.known().await?, &seen, &self.region);
        for change in &changes {
            map.apply(change.clone()).await?;
        }
        Ok(changes)
    }

    /// The whole tenant list. A list that does not end, or repeats a cursor, is refused.
    ///
    /// # Errors
    /// [`AccessError`].
    pub async fn all_tenants(&self) -> Result<Vec<TenantSnapshot>, AccessError> {
        let mut seen = Vec::new();
        let mut cursors = BTreeSet::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let page = self.tenants(cursor.as_deref()).await?;
            seen.extend(page.tenants);
            match page.next_cursor {
                None => return Ok(seen),
                Some(next) if !cursors.insert(next.clone()) => {
                    return Err(AccessError::Answer("cursor"));
                }
                Some(next) => cursor = Some(next),
            }
        }
        Err(AccessError::Answer("pages"))
    }
}
