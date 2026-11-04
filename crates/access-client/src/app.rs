//! The Access client's use cases: discovery at start and on refresh (T-96 item 2), Relay's discovery document (T-99 item 1), Domain Metadata kept per domain, verified and cached key lookups (T-101 item 4), the eligibility check (T-101 item 5), tenant snapshots and the reconciliation job (T-96 item 4). Every consequential call is refused fail-closed while the PEP certificate has expired or the endpoint it needs is not served (T-28).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use work_proto::id::TenantId;

use crate::domain::cache::{CachePolicy, CachedKey, KeyCache};
use crate::domain::discovery::{
    AuthzenConfiguration, Endpoint, Endpoints, Issuer, SUISS_CONFIGURATION, SuissConfiguration,
    percent,
};
use crate::domain::eligibility::{Eligibility, EligibilityRequest};
use crate::domain::keys::{
    ACCEPT_COSE, AsOf, DomainId, EXCERPT_HEADER, KeyAnswer, Kid, MAX_KIDS, batch_body,
    etag_position, verify_answer,
};
use crate::domain::metadata::{DomainMetadata, unverified_payload, verify_metadata};
use crate::domain::relay::RelayConfiguration;
use crate::domain::tenants::{MAX_PAGES, TenantChange, TenantPage, TenantSnapshot, list_url, plan};
use crate::domain::{AccessError, from_b64url};
use crate::ports::{Clock, Request, Response, TenantMap, Transport};

/// How often discovery is read again (T-96 item 2).
pub const DISCOVERY_INTERVAL_MS: u64 = 5 * 60 * 1000;

/// How long verified Domain Metadata is kept before it is read again, Access's `max-age`.
pub const METADATA_MAX_AGE_MS: u64 = 5 * 60 * 1000;

const JSON: &str = "application/json";

struct Trusted {
    metadata: DomainMetadata,
    signed: Option<Endpoints>,
    read_at_ms: u64,
}

#[derive(Default)]
struct State {
    configuration: Option<SuissConfiguration>,
    domains: BTreeMap<DomainId, Trusted>,
    cache: KeyCache,
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
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> Result<MutexGuard<'_, State>, AccessError> {
        self.state.lock().map_err(|_| poisoned())
    }

    async fn get(&self, url: String, accept: &str) -> Result<Response, AccessError> {
        self.transport.send(Request::get(url, accept)).await
    }

    fn consequential(&self) -> Result<(), AccessError> {
        if self.clock.now_ms() > self.pep_not_after_ms {
            return Err(AccessError::Expired);
        }
        Ok(())
    }

    fn endpoints(&self) -> Result<Endpoints, AccessError> {
        self.state()?
            .configuration
            .as_ref()
            .map(|c| c.endpoints.clone())
            .ok_or(AccessError::Unserved(Endpoint::Adp))
    }

    /// Reads the Suiss configuration and the AuthZEN document and checks what start needs; the
    /// document is kept for every later call (T-96 item 2, Access OP-149 m.2).
    ///
    /// # Errors
    /// [`AccessError`]; at start each refuses start.
    pub async fn discover(&self) -> Result<SuissConfiguration, AccessError> {
        let answer = self
            .get(self.issuer.well_known(SUISS_CONFIGURATION), JSON)
            .await?;
        let doc = SuissConfiguration::from_json(answer.ok()?, &self.issuer)?;
        let adp = doc.endpoints.get(Endpoint::Adp)?.as_str().to_owned();
        let authzen = AuthzenConfiguration::from_json(self.get(adp, JSON).await?.ok()?)?;
        doc.check_start(&authzen, &self.region)?;
        self.state()?.configuration = Some(doc.clone());
        Ok(doc)
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

    /// The domain's Domain Metadata: read from the domain's AuthZEN document, verified against
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
        let request = match kids {
            [kid] => {
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
            }
            _ => {
                let template = endpoints.agreed(Endpoint::KeyBatch, signed.as_ref())?;
                Request::post(
                    template.expand(""),
                    ACCEPT_COSE,
                    batch_body(&domain, kids, as_of)?,
                )
            }
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
        let mut seen = Vec::new();
        let mut cursors = BTreeSet::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let page = self.tenants(cursor.as_deref()).await?;
            seen.extend(page.tenants);
            match page.next_cursor {
                None => {
                    let changes = plan(&map.known().await?, &seen, &self.region);
                    for change in &changes {
                        map.apply(change.clone()).await?;
                    }
                    return Ok(changes);
                }
                Some(next) if !cursors.insert(next.clone()) => {
                    return Err(AccessError::Answer("cursor"));
                }
                Some(next) => cursor = Some(next),
            }
        }
        Err(AccessError::Answer("pages"))
    }
}
