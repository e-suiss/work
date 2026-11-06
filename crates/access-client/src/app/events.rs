//! Work's event entry for Access (T-102): the `Content-Type` picks the verifier, an Access SET is verified under the platform realm JWKS and its claims, an event of a tenant Work has not paired with is only logged (`tenant.created` and Work's own `api_client` events excepted), every other one writes its `(access_tenant, iss, jti)` deduplication row and, the first time only, has its effect. The answer follows RFC 8935: `202` for an accepted or repeated event, `400` with `{err, description}` for a refusal; `415` for another media type and `503` while the keys cannot be read, so that Access delivers again.

use sha2::{Digest as _, Sha256};
use work_proto::id::TenantId;

use crate::app::Client;
use crate::domain::AccessError;
use crate::domain::events::{
    ClientChange, Event, Expected, Refusal, Set, Signal, Verifier, claims, parse, verifier,
};
use crate::domain::pairing::PairState;
use crate::ports::{Arrival, Clock, Effects, InboundLog, PairingStore, Transport};

/// What the entry did with one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Verified, recorded once and acted on.
    Accepted {
        /// The tenant.
        tenant: TenantId,
        /// The event name.
        name: String,
        /// The `jti`.
        jti: String,
    },
    /// Verified, seen before: nothing happened again.
    Repeat {
        /// The tenant.
        tenant: TenantId,
        /// The `jti`.
        jti: String,
    },
    /// Verified, but Work has no paired realm of the tenant: only logged; the reconciliation
    /// catches up.
    Unpaired {
        /// The tenant.
        tenant: TenantId,
        /// The event name.
        name: String,
    },
    /// Refused; only a log line.
    Refused(Refusal),
    /// Neither an Access SET nor a Relay event.
    Unsupported,
    /// A Relay event: Relay intake is not built yet, so Relay delivers it again later.
    RelayNotYet,
    /// The keys or the store could not be read; Access delivers again.
    Unavailable(AccessError),
}

impl Outcome {
    /// The HTTP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::Accepted { .. } | Self::Repeat { .. } | Self::Unpaired { .. } => 202,
            Self::Refused(_) => 400,
            Self::Unsupported => 415,
            Self::RelayNotYet | Self::Unavailable(_) => 503,
        }
    }

    /// The response body: the RFC 8935 error of a refusal, nothing otherwise.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        match self {
            Self::Refused(r) => r.body(),
            _ => Vec::new(),
        }
    }

    /// The log event name.
    #[must_use]
    pub const fn event(&self) -> &'static str {
        match self {
            Self::Accepted { .. } => "access.event_accepted",
            Self::Repeat { .. } => "access.event_repeated",
            Self::Unpaired { .. } => "access.event_of_unpaired_tenant",
            Self::Refused(_) => "access.event_refused",
            Self::Unsupported => "inbound.unsupported_media_type",
            Self::RelayNotYet => "inbound.relay_not_served",
            Self::Unavailable(_) => "access.event_unverifiable",
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted { tenant, name, jti } => {
                write!(f, "{name} of {} accepted ({jti})", tenant.as_str())
            }
            Self::Repeat { tenant, jti } => {
                write!(f, "{jti} of {} seen before", tenant.as_str())
            }
            Self::Unpaired { tenant, name } => {
                write!(f, "{name} of unpaired tenant {}", tenant.as_str())
            }
            Self::Refused(r) => write!(f, "{r}"),
            Self::Unsupported => write!(f, "unsupported media type"),
            Self::RelayNotYet => write!(f, "Relay events are not received yet"),
            Self::Unavailable(e) => write!(f, "{e}"),
        }
    }
}

/// The entry over Work's Access client, its realm table and deduplication rows, and what an
/// event does.
#[derive(Debug)]
pub struct Intake<'a, T, C, S, L, E> {
    /// The client of `[suiss] access`.
    pub client: &'a Client<T, C>,
    /// `WORK_ACCESS_CLIENT_ID`, the `aud` of every SET.
    pub client_id: &'a str,
    /// Work's realm table.
    pub realms: &'a S,
    /// The deduplication rows.
    pub log: &'a L,
    /// The effects.
    pub effects: &'a E,
}

/// Whether an event is taken without a paired realm of its tenant: `tenant.created` starts the
/// pairing, and `api_client` events are about Work's own client in the platform tenant.
const fn without_pairing(event: &Event) -> bool {
    matches!(event, Event::TenantCreated | Event::ApiClient { .. })
}

impl<T, C, S, L, E> Intake<'_, T, C, S, L, E>
where
    T: Transport,
    C: Clock,
    S: PairingStore,
    L: InboundLog,
    E: Effects,
{
    /// Takes one request of `content_type` with `body`.
    pub async fn receive(&self, content_type: Option<&str>, body: &[u8]) -> Outcome {
        match verifier(content_type) {
            Verifier::Access => self.access(body).await,
            Verifier::Relay => Outcome::RelayNotYet,
            Verifier::Unsupported => Outcome::Unsupported,
        }
    }

    async fn verify(&self, body: &[u8]) -> Result<Set, Outcome> {
        let set = parse(body).map_err(Outcome::Refused)?;
        let keys = self
            .client
            .event_keys(&set.kid)
            .await
            .map_err(Outcome::Unavailable)?;
        let payload = set.verify(&keys).map_err(Outcome::Refused)?;
        let expected = Expected {
            issuer: self.client.issuer().as_str(),
            audience: self.client_id,
            now_ms: self.client.now_ms(),
        };
        claims(payload, &expected).map_err(Outcome::Refused)
    }

    async fn access(&self, body: &[u8]) -> Outcome {
        let set = match self.verify(body).await {
            Ok(set) => set,
            Err(outcome) => return outcome,
        };
        if !without_pairing(&set.event) {
            match self.realms.realms(&set.tenant).await {
                Ok(realms) if realms.iter().any(|r| r.state == PairState::Paired) => {}
                Ok(_) => {
                    return Outcome::Unpaired {
                        name: set.event.name().to_owned(),
                        tenant: set.tenant,
                    };
                }
                Err(e) => return Outcome::Unavailable(e),
            }
        }
        let arrival = Arrival {
            tenant: &set.tenant,
            source: &set.iss,
            id: &set.jti,
            digest: Sha256::digest(body).into(),
            at_ms: self.client.now_ms(),
        };
        match self.log.note(&arrival).await {
            Ok(true) => {}
            Ok(false) => {
                return Outcome::Repeat {
                    tenant: set.tenant,
                    jti: set.jti,
                };
            }
            Err(e) => return Outcome::Unavailable(e),
        }
        self.apply(&set);
        Outcome::Accepted {
            name: set.event.name().to_owned(),
            tenant: set.tenant,
            jti: set.jti,
        }
    }

    fn apply(&self, set: &Set) {
        let e = self.effects;
        match &set.event {
            Event::Revocation { domain, .. } | Event::InstanceTerminated { domain } => {
                e.forget_domain(*domain);
            }
            Event::Compromised {
                domain,
                party,
                window: Some(window),
                ..
            } => {
                e.forget_domain(*domain);
                e.signal(&Signal::Compromised {
                    tenant: set.tenant.clone(),
                    domain: *domain,
                    party: party.clone(),
                    window: *window,
                });
            }
            Event::Compromised {
                party,
                window: None,
                ..
            } => e.signal(&Signal::CompromiseUnprocessed {
                tenant: set.tenant.clone(),
                party: party.clone(),
            }),
            Event::PartyDisabled { domain, party } => {
                e.forget_domain(*domain);
                e.signal(&Signal::PartyDisabled {
                    tenant: set.tenant.clone(),
                    party: party.clone(),
                });
            }
            Event::TenantCreated => e.pair(&set.tenant),
            Event::ApiClient { change, client_id } if client_id == self.client_id => match change {
                ClientChange::Created => {}
                ClientChange::Updated => e.signal(&Signal::ClientUpdated {
                    client_id: client_id.clone(),
                }),
                ClientChange::Disabled => {
                    e.disable_client();
                    e.signal(&Signal::ClientDisabled {
                        client_id: client_id.clone(),
                    });
                }
            },
            Event::ApiClient { .. } | Event::Organization(_) | Event::Unknown(_) => {}
        }
    }
}

#[cfg(test)]
mod tests;
