//! Relay's side of the event entry (T-100, P-114): a request of the CloudEvents media type goes to the Relay intake, every other one to the Access receiver. The intake reads Relay's product event keys over the roots Relay's discovery is read over, from the `jwks_uri` of the discovery document the process last read and checked; a tenant is paired when one of its realms is, the deduplication rows are the ones Access events use, and a responder's `sub` is asked of Access in every paired realm of the tenant, in Relay's sector. What an event is attributed to is a log event: no record is written for a Relay event before the Declaration it would rest on exists. While ledger time is unavailable nothing is verified and Relay is asked to deliver again.

use std::sync::{Arc, RwLock};

use axum::body::Bytes;
use work_access_client::adapters::HttpsTransport;
use work_access_client::domain::AccessError;
use work_access_client::domain::pairing::PairState;
use work_access_client::domain::subjects::Subject;
use work_access_client::ports::{
    Arrival as AccessArrival, InboundLog as _, Method as AccessMethod, PairingStore as _,
    Request as AccessRequest, Transport as _,
};
use work_http::inbound::{Answer, Answering, Receiver, WebhookHeaders};
use work_ledger::time::{LedgerTime, ProcessMonotonic};
use work_proto::id::TenantId;
use work_reconciler::adapters::{PgInbound, PgPairing};
use work_relay_client::app::inbound::{Intake, Outcome, Parts};
use work_relay_client::domain::answer::RelayError;
use work_relay_client::domain::inbound::{Attribution, CONTENT_TYPE, Event, Webhook};
use work_relay_client::ports::{
    Arrival, Attributed, Clock, Discovered, Discovery, Method, Request, Responders, Response, Seen,
    Tenants, Transport, Unavailable,
};

use crate::inbound::AccessReceiver;
use crate::startup::{AccessClient, AccessClock};

/// Relay's discovery document as the process last read and checked it.
#[derive(Clone, Debug, Default)]
pub(crate) struct RelayDocument(Arc<RwLock<Option<Discovered>>>);

impl RelayDocument {
    /// Keeps `document` as the last one read.
    pub(crate) fn keep(&self, document: Discovered) {
        match self.0.write() {
            Ok(mut kept) => *kept = Some(document),
            Err(poisoned) => *poisoned.into_inner() = Some(document),
        }
    }
}

impl Discovery for RelayDocument {
    fn current(&self) -> Option<Discovered> {
        match self.0.read() {
            Ok(kept) => kept.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// The exchange Relay's key set is read over: a `GET` without a credential.
#[derive(Clone)]
pub(crate) struct KeySetHttps(pub(crate) HttpsTransport);

impl Transport for KeySetHttps {
    async fn send(&self, request: Request) -> Result<Response, RelayError> {
        if request.method != Method::Get {
            return Err(RelayError::Unreachable(
                "the key set exchange only reads".to_owned(),
            ));
        }
        let answer = self
            .0
            .send(AccessRequest {
                method: AccessMethod::Get,
                url: request.url,
                headers: request.headers,
                body: Vec::new(),
            })
            .await
            .map_err(|e| RelayError::Unreachable(e.to_string()))?;
        Ok(Response {
            status: answer.status,
            headers: answer.headers,
            body: answer.body,
        })
    }
}

fn unavailable(error: &AccessError) -> Unavailable {
    Unavailable(error.to_string())
}

/// A tenant is paired once one of its realms is (T-96 item 4).
#[derive(Clone)]
pub(crate) struct Paired(pub(crate) PgPairing);

impl Tenants for Paired {
    async fn paired(&self, tenant: &TenantId) -> Result<bool, Unavailable> {
        let realms = self.0.realms(tenant).await.map_err(|e| unavailable(&e))?;
        Ok(realms.iter().any(|r| r.state == PairState::Paired))
    }
}

/// The `work.inbound_seen` rows, shared with Access events.
#[derive(Clone)]
pub(crate) struct Rows(pub(crate) PgInbound);

impl Seen for Rows {
    async fn note(&self, arrival: &Arrival<'_>) -> Result<bool, Unavailable> {
        self.0
            .note(&AccessArrival {
                tenant: arrival.tenant,
                source: arrival.source,
                id: arrival.id,
                digest: arrival.digest,
                at_ms: arrival.at_ms,
            })
            .await
            .map_err(|e| unavailable(&e))
    }
}

/// The Party of a responder's `sub`, asked of Access in every paired realm of the tenant.
#[derive(Clone)]
pub(crate) struct PartyOf {
    pub(crate) client: Arc<AccessClient>,
    pub(crate) realms: PgPairing,
}

impl Responders for PartyOf {
    async fn party(
        &self,
        tenant: &TenantId,
        client_id: &str,
        sub: &str,
    ) -> Result<Option<String>, Unavailable> {
        let realms = self
            .realms
            .realms(tenant)
            .await
            .map_err(|e| unavailable(&e))?;
        for realm in realms.iter().filter(|r| r.state == PairState::Paired) {
            match self
                .client
                .subject(tenant, realm.realm.as_str(), client_id, sub)
                .await
            {
                Ok(Some(Subject::Party(party))) => return Ok(Some(party)),
                Err(error) if error.is_temporary() => return Err(unavailable(&error)),
                Ok(_) | Err(_) => {}
            }
        }
        Ok(None)
    }
}

impl Clock for AccessClock {
    fn now_ms(&self) -> u64 {
        self.0.read().unwrap_or(u64::MAX)
    }
}

/// What an attributed Relay event does in this process: a log event that names the event and
/// whose record it may become, never the responder.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Logged;

impl Attributed for Logged {
    fn attributed(&self, event: &Event, attribution: &Attribution) {
        if let Attribution::Unattributed(why) = attribution {
            tracing::warn!(
                event = "relay.response_unattributed",
                tenant = event.tenant.as_str(),
                name = event.name.as_str(),
                id = event.id.as_str(),
                reason = why.code(),
                "a Relay answer nobody is the author of; no record"
            );
        } else {
            tracing::info!(
                event = "relay.event_attributed",
                tenant = event.tenant.as_str(),
                name = event.name.as_str(),
                id = event.id.as_str(),
                correlation = event.correlation_id.as_deref().unwrap_or_default(),
                attribution = attribution.code(),
                "Relay event attributed"
            );
        }
    }
}

/// The Relay intake of this process.
pub(crate) type RelayIntake =
    Intake<RelayDocument, KeySetHttps, Paired, Rows, PartyOf, AccessClock, Logged>;

/// The intake over the process's adapters.
pub(crate) fn intake(
    document: RelayDocument,
    transport: HttpsTransport,
    client: Arc<AccessClient>,
    realms: PgPairing,
    log: PgInbound,
    time: LedgerTime<ProcessMonotonic>,
) -> RelayIntake {
    Intake::new(Parts {
        discovery: document,
        transport: KeySetHttps(transport),
        tenants: Paired(realms.clone()),
        seen: Rows(log),
        responders: PartyOf { client, realms },
        clock: AccessClock(time),
        effects: Logged,
    })
}

/// Whether `content_type` is the media type of a Relay event, whatever its parameters.
pub(crate) fn is_relay(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|t| t.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case(CONTENT_TYPE))
}

/// The profile headers of a delivery, when the request carried all three.
pub(crate) fn webhook(headers: WebhookHeaders) -> Option<Webhook> {
    Some(Webhook {
        id: headers.id?,
        timestamp: headers.timestamp?,
        signature: headers.signature?,
    })
}

fn logged(outcome: &Outcome) {
    match outcome {
        Outcome::Accepted { .. } | Outcome::Repeat { .. } | Outcome::Unpaired { .. } => {
            tracing::info!(event = outcome.event(), %outcome, "Relay event");
        }
        _ => tracing::warn!(event = outcome.event(), %outcome, "Relay event not taken"),
    }
}

/// The receiver behind the route: Relay's events by their media type, everything else Access's.
pub(crate) struct EntryReceiver {
    pub(crate) access: AccessReceiver,
    pub(crate) relay: Arc<RelayIntake>,
    pub(crate) time: LedgerTime<ProcessMonotonic>,
}

impl Receiver for EntryReceiver {
    fn receive(&self, content_type: Option<String>, body: Bytes) -> Answering {
        self.receive_signed(content_type, WebhookHeaders::default(), body)
    }

    fn receive_signed(
        &self,
        content_type: Option<String>,
        headers: WebhookHeaders,
        body: Bytes,
    ) -> Answering {
        if !is_relay(content_type.as_deref()) {
            return self.access.receive(content_type, body);
        }
        let relay = Arc::clone(&self.relay);
        let time = self.time.clone();
        Box::pin(async move {
            if time.read().is_err() {
                tracing::warn!(
                    event = "relay.event_unverifiable",
                    "no ledger time; the event is asked again"
                );
                return Answer {
                    status: 503,
                    body: Vec::new(),
                };
            }
            let outcome = relay.receive(webhook(headers).as_ref(), &body).await;
            logged(&outcome);
            Answer {
                status: outcome.status(),
                body: Vec::new(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-100 T-102
    #[test]
    fn t_100_the_cloudevents_media_type_alone_selects_the_relay_intake() {
        for relay in [
            "application/cloudevents+json",
            "Application/CloudEvents+JSON",
            "application/cloudevents+json; charset=utf-8",
        ] {
            assert!(is_relay(Some(relay)), "{relay}");
        }
        for other in [
            "application/secevent+jwt",
            "application/json",
            "application/cloudevents-batch+json",
            "",
        ] {
            assert!(!is_relay(Some(other)), "{other}");
        }
        assert!(!is_relay(None));
    }

    // T-100 P-36
    #[test]
    fn t_100_a_delivery_without_one_profile_header_carries_no_signature() {
        let all = WebhookHeaders {
            id: Some("evt_1".to_owned()),
            timestamp: Some("1793000000".to_owned()),
            signature: Some("v1a,AAAA".to_owned()),
        };
        assert_eq!(
            webhook(all.clone()),
            Some(Webhook {
                id: "evt_1".to_owned(),
                timestamp: "1793000000".to_owned(),
                signature: "v1a,AAAA".to_owned(),
            })
        );
        for missing in [
            WebhookHeaders {
                id: None,
                ..all.clone()
            },
            WebhookHeaders {
                timestamp: None,
                ..all.clone()
            },
            WebhookHeaders {
                signature: None,
                ..all
            },
        ] {
            assert_eq!(webhook(missing), None);
        }
    }

    // T-100
    #[test]
    fn t_100_the_last_checked_discovery_document_names_the_keys_and_the_source() {
        let document = RelayDocument::default();
        assert_eq!(document.current(), None);
        let first = Discovered {
            issuer: "https://relay.example".to_owned(),
            jwks_uri: "https://relay.example/.well-known/relay-jwks.json".to_owned(),
            access_client_id: "app_relay".to_owned(),
        };
        document.keep(first.clone());
        assert_eq!(document.current(), Some(first.clone()));
        let next = Discovered {
            access_client_id: "app_relay_2".to_owned(),
            ..first
        };
        document.keep(next.clone());
        assert_eq!(document.current(), Some(next));
    }
}
