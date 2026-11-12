//! The Relay client and the delivery of intents (T-99, T-17, T-28, E-18): [`Relay`] sends one event to the events endpoint Relay's discovery names, or a batch to `<events>/batch`, each with `Relay-Version`, Work's Access service token as `DPoP` with a fresh proof of the call, the intent's idempotency key and the `traceparent` of the committing request; [`Deliverer`] takes the pending intents of the outbox oldest first, resolves their Parties to pairwise `sub`s in Relay's sector, sends nothing to a Party that does not resolve, and settles each intent Relay takes or refuses. While Relay or Access cannot answer the intent stays in the outbox, the pass stops, and a later pass sends it again with the same key; no normative outcome waits on Relay (MD-3 item 6).

pub mod inbound;
pub mod waits;

use crate::RELAY_VERSION;
use crate::domain::answer::{Accepted, RelayError, RowOutcome, accepted, batch, problem};
use crate::domain::intent::{IdempotencyKey, NotificationIntent};
use crate::domain::request::{EventRequest, Installation, RequestError, batch_body, is_https};
use crate::ports::{
    Credential, Intents, Method, OutboxError, Outcome, Recipients, Request, Settlement, Transport,
    Unresolvable,
};

/// The endpoints of the capabilities Relay's discovery offers beyond events (T-99 item 3): each
/// is there only while Relay serves every operation of its capability.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Offered {
    /// `waitpoints_endpoint`, with `urn:suiss:relay:waitpoint:1`.
    pub waitpoints: Option<String>,
    /// `escalation_policies_endpoint`, with `urn:suiss:relay:escalation:1`.
    pub escalation_policies: Option<String>,
    /// `agents_endpoint`, with `urn:suiss:relay:agent_ceiling:1`.
    pub agents: Option<String>,
}

/// The client of one Relay installation's events endpoint.
#[derive(Debug)]
pub struct Relay<T, K> {
    transport: T,
    credential: K,
    events: String,
    offered: Offered,
}

impl<T: Transport, K: Credential> Relay<T, K> {
    /// The client of `events_endpoint`, from Relay's discovery.
    ///
    /// # Errors
    /// [`RequestError::Link`] for an endpoint that is not `https`.
    pub fn new(transport: T, credential: K, events_endpoint: &str) -> Result<Self, RequestError> {
        if !is_https(events_endpoint) {
            return Err(RequestError::Link);
        }
        Ok(Self {
            transport,
            credential,
            events: events_endpoint.trim_end_matches('/').to_owned(),
            offered: Offered::default(),
        })
    }

    /// The same client with the endpoints Relay's discovery offers now; one that is not `https`
    /// counts as not offered.
    #[must_use]
    pub fn offering(mut self, offered: Offered) -> Self {
        let checked = |endpoint: Option<String>| {
            endpoint
                .filter(|e| is_https(e))
                .map(|e| e.trim_end_matches('/').to_owned())
        };
        self.offered = Offered {
            waitpoints: checked(offered.waitpoints),
            escalation_policies: checked(offered.escalation_policies),
            agents: checked(offered.agents),
        };
        self
    }

    async fn post(
        &self,
        url: String,
        body: Vec<u8>,
        key: &IdempotencyKey,
        traceparent: &str,
    ) -> Result<crate::ports::Response, RelayError> {
        self.call(Method::Post, url, body, key, traceparent).await
    }

    async fn call(
        &self,
        method: Method,
        url: String,
        body: Vec<u8>,
        key: &IdempotencyKey,
        traceparent: &str,
    ) -> Result<crate::ports::Response, RelayError> {
        let auth = self.credential.authorize(method.as_str(), &url).await?;
        let headers = [
            ("content-type", "application/json"),
            ("accept", "application/json"),
            ("relay-version", RELAY_VERSION),
            ("idempotency-key", key.as_str()),
            ("traceparent", traceparent),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .chain([
            ("authorization".to_owned(), auth.authorization),
            ("dpop".to_owned(), auth.dpop),
        ])
        .collect();
        let answer = self
            .transport
            .send(Request {
                method,
                url,
                headers,
                body,
            })
            .await?;
        if answer.status == 401 {
            self.credential.rejected();
        }
        Ok(answer)
    }

    /// `POST /v1/events`.
    ///
    /// # Errors
    /// [`RelayError`].
    pub async fn send(
        &self,
        event: &EventRequest,
        traceparent: &str,
    ) -> Result<Accepted, RelayError> {
        let body = event.body().map_err(|_| RelayError::Answer("request"))?;
        let answer = self
            .post(self.events.clone(), body, event.key(), traceparent)
            .await?;
        if answer.status == 202 {
            accepted(&answer.body)
        } else {
            Err(problem(
                answer.status,
                &answer.body,
                answer.header("retry-after"),
            ))
        }
    }

    /// `POST /v1/events/batch` with one key for the whole batch; the outcome of every row in
    /// the order sent.
    ///
    /// # Errors
    /// [`RelayError`] for the whole request.
    pub async fn send_batch(
        &self,
        rows: &[EventRequest],
        traceparent: &str,
    ) -> Result<Vec<RowOutcome>, RelayError> {
        let keys: Vec<&IdempotencyKey> = rows.iter().map(EventRequest::key).collect();
        let key = IdempotencyKey::of_batch(&keys);
        let body = batch_body(rows).map_err(|_| RelayError::Answer("request"))?;
        let answer = self
            .post(format!("{}/batch", self.events), body, &key, traceparent)
            .await?;
        match answer.status {
            202 | 207 => batch(&answer.body, rows.len()),
            422 => batch(&answer.body, rows.len()).map_err(|_| problem(422, &answer.body, None)),
            status => Err(problem(status, &answer.body, answer.header("retry-after"))),
        }
    }
}

/// What one pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// Intents Relay took.
    pub delivered: u32,
    /// Intents Relay refused or that could not be built.
    pub refused: u32,
    /// Intents none of whose recipients resolved.
    pub unresolved: u32,
    /// Intents left in the outbox for a later pass.
    pub waiting: u32,
}

enum Wait {
    Relay(RelayError),
    Access(Unresolvable),
}

impl Wait {
    fn code(&self) -> &str {
        match self {
            Self::Relay(e) => e.code(),
            Self::Access(_) => "recipients_unresolvable",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Relay(e) => e.to_string(),
            Self::Access(e) => e.to_string(),
        }
    }
}

/// The delivery of the outbox's intents to Relay.
#[derive(Debug)]
pub struct Deliverer<T, K, R, I> {
    relay: Relay<T, K>,
    recipients: R,
    intents: I,
    installation: Installation,
    sector: String,
}

impl<T: Transport, K: Credential, R: Recipients, I: Intents> Deliverer<T, K, R, I> {
    /// Delivers through `relay`, resolving recipients in Relay's sector `access_client_id`
    /// (Relay's discovery) and linking items below `installation`.
    #[must_use]
    pub fn new(
        relay: Relay<T, K>,
        recipients: R,
        intents: I,
        installation: Installation,
        access_client_id: &str,
    ) -> Self {
        Self {
            relay,
            recipients,
            intents,
            installation,
            sector: access_client_id.to_owned(),
        }
    }

    async fn settlement(&self, intent: &NotificationIntent) -> Result<Settlement, Wait> {
        let spec = intent.spec();
        let found = self
            .recipients
            .subs(&spec.tenant, &spec.realm, &self.sector, &spec.parties)
            .await
            .map_err(Wait::Access)?;
        let mut subs = Vec::new();
        let mut unresolved = Vec::new();
        for party in &spec.parties {
            match found.get(party) {
                Some(Some(sub)) => subs.push(sub.clone()),
                _ => unresolved.push(party.clone()),
            }
        }
        if subs.is_empty() {
            return Ok(Settlement {
                outcome: Outcome::NoRecipient,
                unresolved,
            });
        }
        let request = match EventRequest::new(intent, &subs, &self.installation) {
            Ok(r) => r,
            Err(e) => {
                return Ok(Settlement {
                    outcome: Outcome::Invalid(e),
                    unresolved,
                });
            }
        };
        let outcome = match self
            .relay
            .send(&request, &intent.committed().traceparent)
            .await
        {
            Ok(a) => Outcome::Delivered(a),
            Err(e) if e.is_temporary() => return Err(Wait::Relay(e)),
            Err(e) => Outcome::Refused(e),
        };
        Ok(Settlement {
            outcome,
            unresolved,
        })
    }

    /// One pass over up to `limit` pending intents. The first one that must wait stops the
    /// pass; it and the rest stay pending.
    ///
    /// # Errors
    /// [`OutboxError`].
    pub async fn run_once(&self, limit: u32) -> Result<Pass, OutboxError> {
        let pending = self.intents.pending(limit).await?;
        let mut pass = Pass::default();
        let mut stopped = false;
        for intent in &pending {
            if stopped {
                pass.waiting = pass.waiting.saturating_add(1);
                continue;
            }
            match self.settlement(intent).await {
                Ok(settlement) => {
                    let counter = match &settlement.outcome {
                        Outcome::Delivered(_) => &mut pass.delivered,
                        Outcome::Refused(_) | Outcome::Invalid(_) => &mut pass.refused,
                        Outcome::NoRecipient => &mut pass.unresolved,
                    };
                    *counter = counter.saturating_add(1);
                    if !settlement.unresolved.is_empty() {
                        tracing::warn!(
                            event = "relay.recipient_unresolved",
                            key = intent.key().as_str(),
                            unresolved = settlement.unresolved.len(),
                            "recipients Access does not know get no notification"
                        );
                    }
                    self.intents.settle(intent.key(), settlement).await?;
                }
                Err(wait) => {
                    tracing::warn!(
                        event = "relay.waiting",
                        key = intent.key().as_str(),
                        code = wait.code(),
                        detail = %wait.detail(),
                        "the intent stays in the outbox"
                    );
                    stopped = true;
                    pass.waiting = pass.waiting.saturating_add(1);
                }
            }
        }
        Ok(pass)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use work_proto::id::TenantId;

    use super::*;
    use crate::domain::intent::Spec;
    use crate::domain::intent::tests::{TRACE, committed, spec};
    use crate::ports::{Authorization, Response};

    #[derive(Default)]
    pub(crate) struct Wire {
        pub(crate) sent: Mutex<Vec<Request>>,
        answers: Mutex<VecDeque<Result<Response, RelayError>>>,
    }

    impl Wire {
        pub(crate) fn answering(answers: Vec<Result<Response, RelayError>>) -> Self {
            Self {
                sent: Mutex::default(),
                answers: Mutex::new(answers.into()),
            }
        }
    }

    impl Transport for &Wire {
        fn send(
            &self,
            request: Request,
        ) -> impl Future<Output = Result<Response, RelayError>> + Send {
            self.sent.lock().unwrap().push(request);
            std::future::ready(
                self.answers
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Err(RelayError::Unreachable("closed".to_owned()))),
            )
        }
    }

    pub(crate) struct Token;

    impl Credential for Token {
        fn authorize(
            &self,
            method: &str,
            url: &str,
        ) -> impl Future<Output = Result<Authorization, RelayError>> + Send {
            std::future::ready(Ok(Authorization {
                authorization: "DPoP at".to_owned(),
                dpop: format!("proof {method} {url}"),
            }))
        }
    }

    struct Counting(AtomicU32);

    impl Credential for &Counting {
        fn authorize(
            &self,
            _method: &str,
            _url: &str,
        ) -> impl Future<Output = Result<Authorization, RelayError>> + Send {
            std::future::ready(Ok(Authorization {
                authorization: "DPoP at".to_owned(),
                dpop: "proof".to_owned(),
            }))
        }

        fn rejected(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Directory(Option<BTreeMap<String, Option<String>>>);

    impl Recipients for Directory {
        fn subs(
            &self,
            _tenant: &TenantId,
            _realm: &str,
            client_id: &str,
            parties: &[String],
        ) -> impl Future<Output = Result<BTreeMap<String, Option<String>>, Unresolvable>> + Send
        {
            assert_eq!(client_id, "app_relay");
            std::future::ready(
                self.0
                    .clone()
                    .ok_or_else(|| Unresolvable("503".to_owned()))
                    .map(|known| {
                        parties
                            .iter()
                            .map(|p| (p.clone(), known.get(p).cloned().flatten()))
                            .collect()
                    }),
            )
        }
    }

    #[derive(Default)]
    struct Outbox {
        pending: Mutex<Vec<NotificationIntent>>,
        settled: Mutex<Vec<(IdempotencyKey, Settlement)>>,
    }

    impl Intents for &Outbox {
        fn pending(
            &self,
            limit: u32,
        ) -> impl Future<Output = Result<Vec<NotificationIntent>, OutboxError>> + Send {
            let all = self.pending.lock().unwrap().clone();
            std::future::ready(Ok(all
                .into_iter()
                .take(usize::try_from(limit).unwrap())
                .collect()))
        }

        fn settle(
            &self,
            key: &IdempotencyKey,
            settlement: Settlement,
        ) -> impl Future<Output = Result<(), OutboxError>> + Send {
            self.pending.lock().unwrap().retain(|i| i.key() != key);
            self.settled.lock().unwrap().push((key.clone(), settlement));
            std::future::ready(Ok(()))
        }
    }

    fn intent(pos: u64, spec: Spec) -> NotificationIntent {
        let mut c = committed();
        c.pos = pos;
        NotificationIntent::new(c, spec).unwrap()
    }

    fn accepted_body() -> Response {
        Response {
            status: 202,
            headers: Vec::new(),
            body: serde_json::json!({
                "object": "event", "id": "evt_1", "workflow": {"key": "work-action-required", "version": 1},
                "status": "accepted", "recipient_count": 1,
                "notifications": [{"recipient_id": "rcp_1", "notification_id": "ntf_1"}],
                "created_at": "2026-11-06T10:00:00Z"
            })
            .to_string()
            .into_bytes(),
        }
    }

    pub(crate) fn refusal(status: u16, code: &str, retryable: bool) -> Response {
        Response {
            status,
            headers: vec![("Retry-After".to_owned(), "3".to_owned())],
            body: serde_json::json!({"type": "t", "title": "t", "status": status, "code": code, "retryable": retryable})
                .to_string()
                .into_bytes(),
        }
    }

    fn known() -> Directory {
        Directory(Some(BTreeMap::from([(
            spec().parties[0].clone(),
            Some("pairwise-1".to_owned()),
        )])))
    }

    fn deliverer<'a>(
        wire: &'a Wire,
        directory: Directory,
        outbox: &'a Outbox,
    ) -> Deliverer<&'a Wire, Token, Directory, &'a Outbox> {
        let relay = Relay::new(wire, Token, "https://relay.example/v1/events").unwrap();
        Deliverer::new(
            relay,
            directory,
            outbox,
            Installation::parse("https://work.example").unwrap(),
            "app_relay",
        )
    }

    // T-99 P-42 T-12
    #[tokio::test]
    async fn t_99_an_event_carries_the_version_the_token_the_key_and_the_trace() {
        let wire = Wire::answering(vec![Ok(accepted_body())]);
        let relay = Relay::new(&wire, Token, "https://relay.example/v1/events").unwrap();
        let i = intent(1, spec());
        let request = EventRequest::new(
            &i,
            &["s".to_owned()],
            &Installation::parse("https://work.example").unwrap(),
        )
        .unwrap();
        let a = relay.send(&request, TRACE).await.unwrap();
        assert_eq!(a.event_id, "evt_1");
        let sent = wire.sent.lock().unwrap();
        let r = &sent[0];
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.url, "https://relay.example/v1/events");
        assert_eq!(r.header("relay-version"), Some(RELAY_VERSION));
        assert_eq!(r.header("authorization"), Some("DPoP at"));
        assert_eq!(
            r.header("dpop"),
            Some("proof POST https://relay.example/v1/events")
        );
        assert_eq!(r.header("idempotency-key"), Some(i.key().as_str()));
        assert_eq!(r.header("traceparent"), Some(TRACE));
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.body, request.body().unwrap());
        assert!(Relay::new(&wire, Token, "http://relay.example/v1/events").is_err());
    }

    // T-99 T-28
    #[tokio::test]
    async fn t_99_a_token_relay_does_not_take_is_dropped_before_the_next_call() {
        let wire = Wire::answering(vec![
            Ok(refusal(401, "auth_invalid_token", false)),
            Ok(accepted_body()),
        ]);
        let counting = Counting(AtomicU32::new(0));
        let relay = Relay::new(&wire, &counting, "https://relay.example/v1/events").unwrap();
        let i = intent(1, spec());
        let request = EventRequest::new(
            &i,
            &["s".to_owned()],
            &Installation::parse("https://work.example").unwrap(),
        )
        .unwrap();
        assert!(
            relay
                .send(&request, TRACE)
                .await
                .unwrap_err()
                .is_temporary()
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 1);
        relay.send(&request, TRACE).await.unwrap();
        assert_eq!(counting.0.load(Ordering::SeqCst), 1);
    }

    // T-99
    #[tokio::test]
    async fn t_99_a_batch_goes_to_the_batch_endpoint_under_one_key() {
        let event = serde_json::from_slice::<serde_json::Value>(&accepted_body().body).unwrap();
        let result = serde_json::json!({"object": "batch_result", "summary": {}, "results": [
            {"index": 0, "status": "accepted", "event": event},
            {"index": 1, "status": "rejected", "error": {"status": 422, "code": "recipient_not_found", "retryable": false}}
        ]});
        let wire = Wire::answering(vec![Ok(Response {
            status: 207,
            headers: Vec::new(),
            body: result.to_string().into_bytes(),
        })]);
        let relay = Relay::new(&wire, Token, "https://relay.example/v1/events").unwrap();
        let installation = Installation::parse("https://work.example").unwrap();
        let rows: Vec<EventRequest> = [1, 2]
            .into_iter()
            .map(|pos| {
                EventRequest::new(&intent(pos, spec()), &["s".to_owned()], &installation)
                    .unwrap()
                    .row()
            })
            .collect();
        let outcomes = relay.send_batch(&rows, TRACE).await.unwrap();
        assert!(outcomes[0].is_ok());
        assert!(!outcomes[1].as_ref().unwrap_err().is_temporary());
        let sent = wire.sent.lock().unwrap();
        assert_eq!(sent[0].url, "https://relay.example/v1/events/batch");
        assert_eq!(
            sent[0].header("dpop"),
            Some("proof POST https://relay.example/v1/events/batch")
        );
        let keys: Vec<&IdempotencyKey> = rows.iter().map(EventRequest::key).collect();
        assert_eq!(
            sent[0].header("idempotency-key"),
            Some(IdempotencyKey::of_batch(&keys).as_str())
        );
    }

    // T-28 E-38 MD-3
    #[tokio::test]
    async fn t_28_an_unreachable_relay_keeps_the_intent_and_a_later_pass_sends_it_with_the_same_key()
     {
        let outbox = Outbox::default();
        outbox
            .pending
            .lock()
            .unwrap()
            .extend([intent(1, spec()), intent(2, spec())]);
        let down = Wire::default();
        let pass = deliverer(&down, known(), &outbox)
            .run_once(10)
            .await
            .unwrap();
        assert_eq!(
            pass,
            Pass {
                waiting: 2,
                ..Pass::default()
            }
        );
        assert_eq!(down.sent.lock().unwrap().len(), 1);
        assert!(outbox.settled.lock().unwrap().is_empty());
        let busy = Wire::answering(vec![Ok(refusal(503, "service_unavailable", true))]);
        let pass = deliverer(&busy, known(), &outbox)
            .run_once(10)
            .await
            .unwrap();
        assert_eq!(pass.waiting, 2);
        let up = Wire::answering(vec![Ok(accepted_body()), Ok(accepted_body())]);
        let pass = deliverer(&up, known(), &outbox).run_once(10).await.unwrap();
        assert_eq!(
            pass,
            Pass {
                delivered: 2,
                ..Pass::default()
            }
        );
        let first = down.sent.lock().unwrap()[0]
            .header("idempotency-key")
            .map(str::to_owned);
        assert_eq!(
            up.sent.lock().unwrap()[0]
                .header("idempotency-key")
                .map(str::to_owned),
            first
        );
        assert!(outbox.pending.lock().unwrap().is_empty());
    }

    // T-28 E-38
    #[tokio::test]
    async fn t_28_an_access_outage_or_a_refused_token_keeps_the_intent() {
        let outbox = Outbox::default();
        outbox.pending.lock().unwrap().push(intent(1, spec()));
        let wire = Wire::default();
        let pass = deliverer(&wire, Directory(None), &outbox)
            .run_once(10)
            .await
            .unwrap();
        assert_eq!(pass.waiting, 1);
        assert!(wire.sent.lock().unwrap().is_empty());
        let wire = Wire::answering(vec![Ok(refusal(401, "auth_invalid_token", false))]);
        let pass = deliverer(&wire, known(), &outbox)
            .run_once(10)
            .await
            .unwrap();
        assert_eq!(pass.waiting, 1);
        assert!(outbox.settled.lock().unwrap().is_empty());
    }

    // T-99 T-28
    #[tokio::test]
    async fn t_99_a_refused_event_leaves_the_outbox_with_its_code() {
        let outbox = Outbox::default();
        outbox.pending.lock().unwrap().push(intent(1, spec()));
        let wire = Wire::answering(vec![Ok(refusal(422, "link_scheme_not_allowed", false))]);
        let pass = deliverer(&wire, known(), &outbox)
            .run_once(10)
            .await
            .unwrap();
        assert_eq!(
            pass,
            Pass {
                refused: 1,
                ..Pass::default()
            }
        );
        let settled = outbox.settled.lock().unwrap();
        assert!(matches!(
            &settled[0].1.outcome,
            Outcome::Refused(RelayError::Refused { status: 422, code }) if code == "link_scheme_not_allowed"
        ));
    }

    // T-99
    #[tokio::test]
    async fn t_99_an_unresolved_party_gets_no_notification() {
        let outbox = Outbox::default();
        let mut two = spec();
        two.parties.push("unknown-party".to_owned());
        outbox.pending.lock().unwrap().extend([
            intent(1, two),
            intent(
                2,
                Spec {
                    parties: vec!["unknown-party".to_owned()],
                    ..spec()
                },
            ),
        ]);
        let wire = Wire::answering(vec![Ok(accepted_body())]);
        let pass = deliverer(&wire, known(), &outbox)
            .run_once(10)
            .await
            .unwrap();
        assert_eq!(
            pass,
            Pass {
                delivered: 1,
                unresolved: 1,
                ..Pass::default()
            }
        );
        let sent = wire.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap();
        assert_eq!(body["to"], serde_json::json!([{"id": "pairwise-1"}]));
        let settled = outbox.settled.lock().unwrap();
        assert_eq!(settled[0].1.unresolved, ["unknown-party"]);
        assert_eq!(settled[1].1.outcome, Outcome::NoRecipient);
    }

    // INV-30 E-5 MD-2
    #[tokio::test]
    async fn inv_30_work_reaches_relay_only_through_the_events_endpoint_its_discovery_names() {
        let outbox = Outbox::default();
        outbox.pending.lock().unwrap().push(intent(1, spec()));
        let wire = Wire::answering(vec![Ok(accepted_body())]);
        deliverer(&wire, known(), &outbox)
            .run_once(10)
            .await
            .unwrap();
        let sent = wire.sent.lock().unwrap();
        assert!(
            sent.iter()
                .all(|r| r.url == "https://relay.example/v1/events")
        );
        let names: Vec<&str> = sent[0].headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "content-type",
                "accept",
                "relay-version",
                "idempotency-key",
                "traceparent",
                "authorization",
                "dpop"
            ]
        );
    }
}
