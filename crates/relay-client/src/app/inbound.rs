//! Work's entry for Relay's events (T-100, P-114): a delivery is taken only with the Suiss webhook profile headers, a timestamp within the tolerance and a `v1a` signature under a product event key of the `jwks_uri` of Relay's last checked discovery document; the key set is kept for the discovery interval, and when no key verifies it is read once more, at most once per interval. Then the `source` must be the discovery `issuer` and `accesstenant` a paired tenant. A first arrival writes its `(tenant, source, id)` row and is attributed: a time or delivery event to the tenant's Work service Party, an answer to the Party Access names for the responder's `sub` in Relay's sector, anything else to nobody. An accepted or repeated event is answered `204`, an unauthenticated one `401`, one of an unpaired tenant `404`, and while Relay's discovery, its keys, the pairing, Access or the rows do not answer `503`, so that Relay delivers again. No answer is a record: writing one waits for the Declaration it rests on.

use std::sync::{Mutex, MutexGuard};

use sha2::{Digest as _, Sha256};
use work_proto::id::TenantId;

use crate::RELAY_VERSION;
use crate::domain::answer::{RelayError, problem};
use crate::domain::inbound::{
    Attribution, Event, KeySet, Kind, Refusal, Unattributable, Webhook, timely,
};
use crate::ports::{
    Arrival, Attributed, Clock, Discovered, Discovery, Method, Request, Responders, Seen, Tenants,
    Transport,
};

/// How long a key set is used before it is read again, and the least time between two reads
/// made because no key verified (T-100 item 4): the discovery interval.
pub const KEYS_INTERVAL_MS: u64 = 300_000;

/// A first arrival, with whose record it may become.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taken {
    /// The event.
    pub event: Event,
    /// The attribution.
    pub attribution: Attribution,
}

/// What became of one delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A first arrival.
    Accepted(Box<Taken>),
    /// An event seen before.
    Repeat {
        /// The tenant.
        tenant: TenantId,
        /// The event id.
        id: String,
    },
    /// An event of a tenant Work has not paired with.
    Unpaired {
        /// The tenant.
        tenant: TenantId,
        /// The event type.
        name: String,
    },
    /// An event that is not taken.
    Refused(Refusal),
    /// Something did not answer; Relay delivers again.
    Unavailable(String),
}

impl Outcome {
    /// The HTTP status (T-100 item 1).
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::Accepted(_) | Self::Repeat { .. } => 204,
            Self::Unpaired { .. } => 404,
            Self::Refused(refusal) => refusal.status(),
            Self::Unavailable(_) => 503,
        }
    }

    /// Whose record a first arrival may become; `None` for every other outcome.
    #[must_use]
    pub fn attribution(&self) -> Option<&Attribution> {
        match self {
            Self::Accepted(taken) => Some(&taken.attribution),
            _ => None,
        }
    }

    /// The log event.
    #[must_use]
    pub const fn event(&self) -> &'static str {
        match self {
            Self::Accepted(_) => "relay.event_accepted",
            Self::Repeat { .. } => "relay.event_repeated",
            Self::Unpaired { .. } => "relay.event_unpaired",
            Self::Refused(_) => "relay.event_refused",
            Self::Unavailable(_) => "relay.event_unavailable",
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted(taken) => write!(
                f,
                "{} {} of {} ({})",
                taken.event.name,
                taken.event.id,
                taken.event.tenant.as_str(),
                taken.attribution.code()
            ),
            Self::Repeat { tenant, id } => write!(f, "{id} of {} seen before", tenant.as_str()),
            Self::Unpaired { tenant, name } => {
                write!(f, "{name} of unpaired tenant {}", tenant.as_str())
            }
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::Unavailable(detail) => write!(f, "{detail}"),
        }
    }
}

#[derive(Debug, Default)]
struct Cache {
    keys: KeySet,
    uri: String,
    read_at_ms: Option<u64>,
    reread_at_ms: Option<u64>,
}

/// What the entry is built over.
#[derive(Debug)]
pub struct Parts<D, T, P, S, R, C, E> {
    /// Relay's last checked discovery document.
    pub discovery: D,
    /// The exchange the key set is read over.
    pub transport: T,
    /// Work's tenant pairing.
    pub tenants: P,
    /// The deduplication rows.
    pub seen: S,
    /// The Party of a responder.
    pub responders: R,
    /// Time.
    pub clock: C,
    /// What an attributed event does.
    pub effects: E,
}

/// The entry for Relay's events.
#[derive(Debug)]
pub struct Intake<D, T, P, S, R, C, E> {
    parts: Parts<D, T, P, S, R, C, E>,
    cache: Mutex<Cache>,
}

impl<D, T, P, S, R, C, E> Intake<D, T, P, S, R, C, E>
where
    D: Discovery,
    T: Transport,
    P: Tenants,
    S: Seen,
    R: Responders,
    C: Clock,
    E: Attributed,
{
    /// The entry over `parts`, with no key read yet.
    #[must_use]
    pub fn new(parts: Parts<D, T, P, S, R, C, E>) -> Self {
        Self {
            parts,
            cache: Mutex::default(),
        }
    }

    fn cache(&self) -> MutexGuard<'_, Cache> {
        match self.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    async fn fetch(&self, uri: &str) -> Result<KeySet, RelayError> {
        let headers = [
            ("accept", "application/json"),
            ("relay-version", RELAY_VERSION),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .collect();
        let answer = self
            .parts
            .transport
            .send(Request {
                method: Method::Get,
                url: uri.to_owned(),
                headers,
                body: Vec::new(),
            })
            .await?;
        if answer.status != 200 {
            return Err(problem(
                answer.status,
                &answer.body,
                answer.header("retry-after"),
            ));
        }
        KeySet::from_jwks(&answer.body).map_err(|_| RelayError::Answer("jwks"))
    }

    /// The key set of `uri` and whether this call read it: the kept one while it is younger than
    /// [`KEYS_INTERVAL_MS`], else a new read, and the kept one again when that read fails.
    async fn keys(&self, uri: &str, now: u64) -> Result<(KeySet, bool), RelayError> {
        let kept = {
            let cache = self.cache();
            match cache.read_at_ms {
                Some(at) if cache.uri == uri => {
                    if now.saturating_sub(at) < KEYS_INTERVAL_MS {
                        return Ok((cache.keys.clone(), false));
                    }
                    Some(cache.keys.clone())
                }
                _ => None,
            }
        };
        match self.fetch(uri).await {
            Ok(keys) => {
                let mut cache = self.cache();
                cache.keys = keys.clone();
                uri.clone_into(&mut cache.uri);
                cache.read_at_ms = Some(now);
                Ok((keys, true))
            }
            Err(error) => kept.map(|keys| (keys, false)).ok_or(error),
        }
    }

    /// The key set read once more because no key verified, unless such a read was made within
    /// [`KEYS_INTERVAL_MS`].
    async fn reread(&self, uri: &str, now: u64) -> Option<KeySet> {
        {
            let mut cache = self.cache();
            if cache
                .reread_at_ms
                .is_some_and(|at| now.saturating_sub(at) < KEYS_INTERVAL_MS)
            {
                return None;
            }
            cache.reread_at_ms = Some(now);
        }
        let keys = self.fetch(uri).await.ok()?;
        let mut cache = self.cache();
        cache.keys = keys.clone();
        uri.clone_into(&mut cache.uri);
        cache.read_at_ms = Some(now);
        Some(keys)
    }

    async fn verified(
        &self,
        doc: &Discovered,
        webhook: &Webhook,
        body: &[u8],
    ) -> Result<(), Outcome> {
        let now = self.parts.clock.now_ms();
        timely(webhook, now).map_err(Outcome::Refused)?;
        let (keys, read_now) = self
            .keys(&doc.jwks_uri, now)
            .await
            .map_err(|e| Outcome::Unavailable(e.to_string()))?;
        if keys.verifies(webhook, body) {
            return Ok(());
        }
        if !read_now
            && let Some(keys) = self.reread(&doc.jwks_uri, now).await
            && keys.verifies(webhook, body)
        {
            return Ok(());
        }
        Err(Outcome::Refused(Refusal::Signature))
    }

    async fn attribution(&self, doc: &Discovered, event: &Event) -> Result<Attribution, Outcome> {
        let answer = match &event.kind {
            Kind::Automation => return Ok(Attribution::ServiceParty),
            Kind::Engagement | Kind::Other => return Ok(Attribution::Nothing),
            Kind::Response(Err(why)) => return Ok(Attribution::Unattributed(*why)),
            Kind::Response(Ok(answer)) => answer,
        };
        let party = self
            .parts
            .responders
            .party(&event.tenant, &doc.access_client_id, &answer.sub)
            .await
            .map_err(|e| Outcome::Unavailable(e.to_string()))?;
        Ok(party.map_or(
            Attribution::Unattributed(Unattributable::Unresolved),
            |party| Attribution::Responder {
                party,
                answer: answer.clone(),
            },
        ))
    }

    async fn taken(&self, webhook: Option<&Webhook>, body: &[u8]) -> Result<Outcome, Outcome> {
        let doc = self
            .parts
            .discovery
            .current()
            .ok_or_else(|| Outcome::Unavailable("Relay's discovery is not read".to_owned()))?;
        let webhook = webhook.ok_or(Outcome::Refused(Refusal::Headers))?;
        self.verified(&doc, webhook, body).await?;
        let event = Event::read(body, webhook, &doc.issuer).map_err(Outcome::Refused)?;
        let unavailable = |e: crate::ports::Unavailable| Outcome::Unavailable(e.0);
        if !self
            .parts
            .tenants
            .paired(&event.tenant)
            .await
            .map_err(unavailable)?
        {
            return Ok(Outcome::Unpaired {
                tenant: event.tenant,
                name: event.name,
            });
        }
        let attribution = self.attribution(&doc, &event).await?;
        let arrival = Arrival {
            tenant: &event.tenant,
            source: &event.source,
            id: &event.id,
            digest: Sha256::digest(body).into(),
            at_ms: self.parts.clock.now_ms(),
        };
        if !self.parts.seen.note(&arrival).await.map_err(unavailable)? {
            return Ok(Outcome::Repeat {
                tenant: event.tenant,
                id: event.id,
            });
        }
        self.parts.effects.attributed(&event, &attribution);
        Ok(Outcome::Accepted(Box::new(Taken { event, attribution })))
    }

    /// Takes one delivery: its profile headers, when the request carried all three, and its body
    /// as received.
    pub async fn receive(&self, webhook: Option<&Webhook>, body: &[u8]) -> Outcome {
        match self.taken(webhook, body).await {
            Ok(outcome) | Err(outcome) => outcome,
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test code")]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;
    use crate::domain::inbound::tests::{ISSUER, NOW_MS, body, jwks, key, resolved, signed};
    use crate::domain::inbound::{Evidence, RESPONSE_TYPE};
    use crate::ports::{Response, Unavailable};

    const JWKS_URI: &str = "https://relay.example/.well-known/relay-jwks.json";

    #[derive(Default)]
    struct World {
        discovered: bool,
        published: Mutex<Option<Vec<u8>>>,
        reads: AtomicU64,
        now_ms: AtomicU64,
        paired: bool,
        rows: Mutex<BTreeSet<(String, String, String)>>,
        rows_down: bool,
        party: Option<Option<String>>,
        attributed: Mutex<Vec<(String, Attribution)>>,
    }

    impl World {
        fn with(keys: &[&SigningKey]) -> Self {
            Self {
                discovered: true,
                published: Mutex::new(Some(jwks(keys))),
                now_ms: AtomicU64::new(NOW_MS),
                paired: true,
                party: Some(Some("AAECAwQFBgcICQoLDA0ODw".to_owned())),
                ..Self::default()
            }
        }

        fn now_holds(&self, keys: &[&SigningKey]) {
            *self.published.lock().unwrap() = Some(jwks(keys));
        }

        fn intake(&self) -> Intake<&Self, &Self, &Self, &Self, &Self, &Self, &Self> {
            Intake::new(Parts {
                discovery: self,
                transport: self,
                tenants: self,
                seen: self,
                responders: self,
                clock: self,
                effects: self,
            })
        }
    }

    impl Discovery for &World {
        fn current(&self) -> Option<Discovered> {
            self.discovered.then(|| Discovered {
                issuer: ISSUER.to_owned(),
                jwks_uri: JWKS_URI.to_owned(),
                access_client_id: "app_relay".to_owned(),
            })
        }
    }

    impl Transport for &World {
        fn send(
            &self,
            request: Request,
        ) -> impl Future<Output = Result<Response, RelayError>> + Send {
            assert_eq!(request.method, Method::Get);
            assert_eq!(request.url, JWKS_URI);
            assert_eq!(request.header("authorization"), None);
            self.reads.fetch_add(1, Ordering::SeqCst);
            std::future::ready(self.published.lock().unwrap().clone().map_or_else(
                || Err(RelayError::Unreachable("closed".to_owned())),
                |body| {
                    Ok(Response {
                        status: 200,
                        headers: Vec::new(),
                        body,
                    })
                },
            ))
        }
    }

    impl Tenants for &World {
        fn paired(
            &self,
            tenant: &TenantId,
        ) -> impl Future<Output = Result<bool, Unavailable>> + Send {
            std::future::ready(Ok(self.paired && tenant.as_str() == "tnt_acme"))
        }
    }

    impl Seen for &World {
        fn note(
            &self,
            arrival: &Arrival<'_>,
        ) -> impl Future<Output = Result<bool, Unavailable>> + Send {
            let row = (
                arrival.tenant.as_str().to_owned(),
                arrival.source.to_owned(),
                arrival.id.to_owned(),
            );
            std::future::ready(if self.rows_down {
                Err(Unavailable("rows".to_owned()))
            } else {
                Ok(self.rows.lock().unwrap().insert(row))
            })
        }
    }

    impl Responders for &World {
        fn party(
            &self,
            _tenant: &TenantId,
            client_id: &str,
            sub: &str,
        ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send {
            assert_eq!(client_id, "app_relay");
            assert_eq!(sub, "sub-1");
            std::future::ready(
                self.party
                    .clone()
                    .ok_or_else(|| Unavailable("access".to_owned())),
            )
        }
    }

    impl Clock for &World {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::SeqCst)
        }
    }

    impl Attributed for &World {
        fn attributed(&self, event: &Event, attribution: &Attribution) {
            self.attributed
                .lock()
                .unwrap()
                .push((event.id.clone(), attribution.clone()));
        }
    }

    fn delivery(k: &SigningKey, name: &str, id: &str) -> (Webhook, Vec<u8>) {
        let body = body(name, id, &json!({}));
        (signed(&[k], id, NOW_MS, &body), body)
    }

    // T-100 P-35
    #[tokio::test]
    async fn t_100_a_verified_event_is_recorded_once_per_tenant_source_and_id() {
        let k = key(7);
        let world = World::with(&[&k]);
        let intake = world.intake();
        let (webhook, body) = delivery(&k, "notification.delivered", "evt_1");
        let first = intake.receive(Some(&webhook), &body).await;
        assert_eq!(first.status(), 204, "{first}");
        assert_eq!(first.attribution(), Some(&Attribution::ServiceParty));
        let again = intake.receive(Some(&webhook), &body).await;
        assert_eq!(again.status(), 204);
        assert!(matches!(&again, Outcome::Repeat { id, .. } if id == "evt_1"));
        let (other, other_body) = delivery(&k, "notification.delivered", "evt_2");
        assert!(matches!(
            intake.receive(Some(&other), &other_body).await,
            Outcome::Accepted(_)
        ));
        assert_eq!(
            *world.rows.lock().unwrap(),
            BTreeSet::from([
                ("tnt_acme".to_owned(), ISSUER.to_owned(), "evt_1".to_owned()),
                ("tnt_acme".to_owned(), ISSUER.to_owned(), "evt_2".to_owned()),
            ])
        );
        assert_eq!(world.attributed.lock().unwrap().len(), 2);
        assert_eq!(world.reads.load(Ordering::SeqCst), 1);
    }

    // P-114 T-100
    #[tokio::test]
    async fn p_114_an_unsigned_relay_event_becomes_no_record() {
        let k = key(7);
        let world = World::with(&[&k]);
        let intake = world.intake();
        let (webhook, body) = delivery(&k, "waitpoint.expired", "evt_1");
        let unsigned = intake.receive(None, &body).await;
        assert_eq!(unsigned, Outcome::Refused(Refusal::Headers));
        assert_eq!(unsigned.status(), 401);
        let mut tampered = body.clone();
        tampered.push(b'\n');
        let outcome = intake.receive(Some(&webhook), &tampered).await;
        assert_eq!(outcome, Outcome::Refused(Refusal::Signature));
        assert_eq!(outcome.status(), 401);
        let stranger = signed(&[&key(9)], "evt_1", NOW_MS, &body);
        assert_eq!(
            intake.receive(Some(&stranger), &body).await,
            Outcome::Refused(Refusal::Signature)
        );
        let stale = signed(&[&k], "evt_1", NOW_MS - 301_000, &body);
        assert_eq!(
            intake.receive(Some(&stale), &body).await,
            Outcome::Refused(Refusal::Timestamp)
        );
        assert!(world.rows.lock().unwrap().is_empty());
        assert!(world.attributed.lock().unwrap().is_empty());
    }

    // T-100
    #[tokio::test]
    async fn t_100_a_rotated_key_is_found_after_one_jwks_refresh() {
        let (old, new) = (key(7), key(8));
        let world = World::with(&[&old]);
        let intake = world.intake();
        let (w1, b1) = delivery(&old, "waitpoint.expired", "evt_1");
        assert_eq!(intake.receive(Some(&w1), &b1).await.status(), 204);
        assert_eq!(world.reads.load(Ordering::SeqCst), 1);
        world.now_holds(&[&old, &new]);
        world.now_ms.fetch_add(1_000, Ordering::SeqCst);
        let b2 = body("waitpoint.expired", "evt_2", &json!({}));
        let w2 = signed(&[&new], "evt_2", NOW_MS + 1_000, &b2);
        assert_eq!(intake.receive(Some(&w2), &b2).await.status(), 204);
        assert_eq!(world.reads.load(Ordering::SeqCst), 2);
        let b3 = body("waitpoint.expired", "evt_3", &json!({}));
        let w3 = signed(&[&key(9)], "evt_3", NOW_MS + 1_000, &b3);
        assert_eq!(
            intake.receive(Some(&w3), &b3).await,
            Outcome::Refused(Refusal::Signature)
        );
        assert_eq!(world.reads.load(Ordering::SeqCst), 2);
        world.now_holds(&[&new, &key(9)]);
        assert_eq!(
            intake.receive(Some(&w3), &b3).await,
            Outcome::Refused(Refusal::Signature)
        );
        assert_eq!(world.reads.load(Ordering::SeqCst), 2);
        world.now_ms.fetch_add(KEYS_INTERVAL_MS, Ordering::SeqCst);
        let later = NOW_MS + 1_000 + KEYS_INTERVAL_MS;
        let w4 = signed(&[&key(9)], "evt_3", later, &b3);
        assert_eq!(intake.receive(Some(&w4), &b3).await.status(), 204);
        assert_eq!(world.reads.load(Ordering::SeqCst), 3);
        let b5 = body("waitpoint.expired", "evt_5", &json!({}));
        let w5 = signed(&[&old], "evt_5", later, &b5);
        assert_eq!(
            intake.receive(Some(&w5), &b5).await,
            Outcome::Refused(Refusal::Signature)
        );
    }

    // T-100 T-28
    #[tokio::test]
    async fn t_100_an_event_is_asked_for_again_while_relay_s_keys_or_the_rows_do_not_answer() {
        let k = key(7);
        let (webhook, body) = delivery(&k, "waitpoint.expired", "evt_1");
        let undiscovered = World {
            discovered: false,
            ..World::with(&[&k])
        };
        assert_eq!(
            undiscovered
                .intake()
                .receive(Some(&webhook), &body)
                .await
                .status(),
            503
        );
        let keyless = World::with(&[&k]);
        *keyless.published.lock().unwrap() = None;
        assert_eq!(
            keyless
                .intake()
                .receive(Some(&webhook), &body)
                .await
                .status(),
            503
        );
        let rowless = World {
            rows_down: true,
            ..World::with(&[&k])
        };
        assert_eq!(
            rowless
                .intake()
                .receive(Some(&webhook), &body)
                .await
                .status(),
            503
        );
        assert!(rowless.attributed.lock().unwrap().is_empty());
        let world = World::with(&[&k]);
        let intake = world.intake();
        assert_eq!(intake.receive(Some(&webhook), &body).await.status(), 204);
        *world.published.lock().unwrap() = None;
        world.now_ms.fetch_add(KEYS_INTERVAL_MS, Ordering::SeqCst);
        let b2 = body_at("evt_2");
        let w2 = signed(&[&k], "evt_2", NOW_MS + KEYS_INTERVAL_MS, &b2);
        assert_eq!(intake.receive(Some(&w2), &b2).await.status(), 204);
    }

    fn body_at(id: &str) -> Vec<u8> {
        body("waitpoint.expired", id, &json!({}))
    }

    // T-100 T-96
    #[tokio::test]
    async fn t_100_an_event_of_an_unpaired_tenant_is_only_a_log_line() {
        let k = key(7);
        let world = World {
            paired: false,
            ..World::with(&[&k])
        };
        let (webhook, body) = delivery(&k, "notification.failed", "evt_1");
        let outcome = world.intake().receive(Some(&webhook), &body).await;
        assert_eq!(outcome.status(), 404);
        assert!(matches!(outcome, Outcome::Unpaired { .. }));
        assert!(world.rows.lock().unwrap().is_empty());
        assert!(world.attributed.lock().unwrap().is_empty());
    }

    // P-114 T-100
    #[tokio::test]
    async fn p_114_a_resolved_waitpoint_belongs_to_the_party_of_its_responder() {
        let k = key(7);
        let world = World::with(&[&k]);
        let intake = world.intake();
        let send = |id: &'static str, level: &'static str| {
            let body = body(RESPONSE_TYPE, id, &resolved(level));
            (signed(&[&k], id, NOW_MS, &body), body)
        };
        let (w, b) = send("evt_1", "relay_session");
        let accepted = intake.receive(Some(&w), &b).await;
        let Some(Attribution::Responder { party, answer }) = accepted.attribution() else {
            panic!("the responder: {accepted}");
        };
        assert_eq!(party, "AAECAwQFBgcICQoLDA0ODw");
        assert!(matches!(answer.evidence, Evidence::RelaySession { .. }));
        let (w, b) = send("evt_2", "channel_claim");
        assert_eq!(
            intake.receive(Some(&w), &b).await.attribution(),
            Some(&Attribution::Unattributed(Unattributable::ChannelClaim))
        );
        let unknown = World {
            party: Some(None),
            ..World::with(&[&k])
        };
        let (w, b) = send("evt_3", "access_aas_ref");
        assert_eq!(
            unknown.intake().receive(Some(&w), &b).await.attribution(),
            Some(&Attribution::Unattributed(Unattributable::Unresolved))
        );
        let down = World {
            party: None,
            ..World::with(&[&k])
        };
        assert_eq!(down.intake().receive(Some(&w), &b).await.status(), 503);
        assert!(down.rows.lock().unwrap().is_empty());
    }

    // P-114 E-22 T-100
    #[tokio::test]
    async fn p_114_relay_is_the_author_of_nothing() {
        let k = key(7);
        let world = World::with(&[&k]);
        let intake = world.intake();
        for (n, name) in [
            "notification.seen",
            "notification.read",
            "notification.clicked",
            "notification.archived",
            "waitpoint.created",
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("evt_{n}");
            let (w, b) = delivery(&k, name, &id);
            assert_eq!(
                intake.receive(Some(&w), &b).await.attribution(),
                Some(&Attribution::Nothing),
                "{name}"
            );
        }
        assert_eq!(world.rows.lock().unwrap().len(), 5);
        for (_, attribution) in world.attributed.lock().unwrap().iter() {
            assert_eq!(attribution.code(), "nothing");
        }
    }
}
