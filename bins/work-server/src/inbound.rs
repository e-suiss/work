//! The event entry of the process (T-102): `POST /v1/inbound/events` on its own TLS 1.3 listener, whose key signs inside the `[access]` token (T-56), handed to the Access intake over the process's Access client, Work's realm table and the tenant scoped deduplication rows; `tenant.created` runs the pairing step for its tenant, revocations and terminations drop the domain's cached keys at once, a compromise with its window has its SEC-36 notice written into every ledger of the tenant that holds a record of the window (WD-123), Work's own disabled client fails every consequential action closed, and every signal is a log event. While ledger time is unavailable nothing is verified and Access is asked to deliver again.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use work_access_client::adapters::TokenSigner;
use work_access_client::app::events::{Intake, Outcome};
use work_access_client::app::platform::Scope;
use work_access_client::domain::b64url;
use work_access_client::domain::events::{Compromise, Signal};
use work_access_client::domain::keys::DomainId;
use work_access_client::ports::Effects;
use work_http::inbound::{Answer, Answering, Receiver};
use work_proto::id::TenantId;
use work_query::app::notices::{Noticed, Notices};
use work_reconciler::adapters::{PgInbound, PgPairing};

use crate::pairing::Pairer;
use crate::startup::AccessClient;

/// The longest TLS handshake the listener waits for.
const HANDSHAKE: Duration = Duration::from_secs(5);

/// What an accepted event does in this process.
#[derive(Clone)]
struct ProcessEffects {
    client: Arc<AccessClient>,
    pairer: Pairer,
    notices: Option<Arc<Notices<TokenSigner>>>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _written = write!(s, "{b:02x}");
        s
    })
}

impl Effects for ProcessEffects {
    fn pair(&self, tenant: &TenantId) {
        let pairer = self.pairer.clone();
        let scope = Scope::Tenant(tenant.clone());
        tokio::spawn(async move { pairer.run(&scope).await });
    }

    fn forget_domain(&self, domain: DomainId) {
        if let Err(error) = self.client.forget_domain(domain) {
            tracing::error!(event = "access.cache_not_dropped", %error, "key cache not dropped");
        }
    }

    fn disable_client(&self) {
        if let Err(error) = self.client.disable() {
            tracing::error!(event = "access.client_not_disabled", %error, "client not disabled");
        }
    }

    fn signal(&self, signal: &Signal) {
        tracing::warn!(event = signal.event(), %signal, "Access event signal");
    }

    fn compromised(&self, compromise: &Compromise) {
        let Some(notices) = self.notices.clone() else {
            tracing::error!(
                event = "access.compromise_notice_failed",
                tenant = compromise.tenant.as_str(),
                jti = compromise.jti.as_str(),
                error = "no service key",
                "SEC-36 notice not written"
            );
            return;
        };
        let compromise = compromise.clone();
        tokio::spawn(async move {
            match notices.write(&compromise).await {
                Ok(done) => {
                    for noticed in done {
                        match noticed {
                            Noticed::Written(ledger, pos) => tracing::warn!(
                                event = "access.compromise_notice_written",
                                tenant = compromise.tenant.as_str(),
                                ledger = hex(&ledger),
                                pos,
                                jti = compromise.jti.as_str(),
                                event_digest = b64url(&compromise.event_digest),
                                "SEC-36 compromise window notice written"
                            ),
                            Noticed::Present(ledger) => tracing::info!(
                                event = "access.compromise_notice_present",
                                tenant = compromise.tenant.as_str(),
                                ledger = hex(&ledger),
                                jti = compromise.jti.as_str(),
                                "SEC-36 compromise window notice already written"
                            ),
                        }
                    }
                }
                Err(error) => tracing::error!(
                    event = "access.compromise_notice_failed",
                    tenant = compromise.tenant.as_str(),
                    jti = compromise.jti.as_str(),
                    %error,
                    "SEC-36 notice not written"
                ),
            }
        });
    }
}

/// The receiver behind the route.
pub(crate) struct AccessReceiver {
    effects: ProcessEffects,
    realms: PgPairing,
    log: PgInbound,
    client_id: Arc<dyn Fn() -> String + Send + Sync>,
}

impl AccessReceiver {
    pub(crate) fn new(
        client: Arc<AccessClient>,
        pairer: Pairer,
        log: PgInbound,
        client_id: Arc<dyn Fn() -> String + Send + Sync>,
        notices: Option<Arc<Notices<TokenSigner>>>,
    ) -> Self {
        Self {
            realms: pairer.store.clone(),
            effects: ProcessEffects {
                client,
                pairer,
                notices,
            },
            log,
            client_id,
        }
    }
}

fn logged(outcome: &Outcome) {
    match outcome {
        Outcome::Accepted { .. } | Outcome::Repeat { .. } | Outcome::Unpaired { .. } => {
            tracing::info!(event = outcome.event(), %outcome, "inbound event");
        }
        _ => tracing::warn!(event = outcome.event(), %outcome, "inbound event not taken"),
    }
}

impl Receiver for AccessReceiver {
    fn receive(&self, content_type: Option<String>, body: Bytes) -> Answering {
        let effects = self.effects.clone();
        let realms = self.realms.clone();
        let log = self.log.clone();
        let client_id = (self.client_id)();
        Box::pin(async move {
            if effects.pairer.clock.read().is_err() {
                tracing::warn!(
                    event = "access.event_unverifiable",
                    "no ledger time; the event is asked again"
                );
                return Answer {
                    status: 503,
                    body: Vec::new(),
                };
            }
            let outcome = Intake {
                client: effects.client.as_ref(),
                client_id: &client_id,
                realms: &realms,
                log: &log,
                effects: &effects,
            }
            .receive(content_type.as_deref(), &body)
            .await;
            logged(&outcome);
            Answer {
                status: outcome.status(),
                body: outcome.body(),
            }
        })
    }
}

/// A TCP listener that completes the TLS handshake of each connection before axum sees it; a
/// failed or slow handshake drops only that connection.
pub(crate) struct TlsListener {
    tcp: TcpListener,
    tls: TlsAcceptor,
}

impl TlsListener {
    pub(crate) async fn bind(addr: SocketAddr, tls: Arc<ServerConfig>) -> std::io::Result<Self> {
        Ok(Self {
            tcp: TcpListener::bind(addr).await?,
            tls: TlsAcceptor::from(tls),
        })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, peer) = match self.tcp.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(event = "inbound.accept_failed", %error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            match tokio::time::timeout(HANDSHAKE, self.tls.accept(tcp)).await {
                Ok(Ok(stream)) => return (stream, peer),
                Ok(Err(error)) => {
                    tracing::warn!(event = "inbound.handshake_failed", %peer, %error, "TLS handshake failed");
                }
                Err(_) => {
                    tracing::warn!(event = "inbound.handshake_failed", %peer, "TLS handshake timed out");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}
