//! The Roughtime client over UDP (OP-42 item 3): one request per query with a fresh nonce from
//! the process random source, the answer verified by the shared wire module and turned into the
//! interval the bound check uses.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::time::adapters::ProcessMonotonic;
use crate::time::domain::RoughtimeAnswer;
use crate::time::ports::{Monotonic, QueryError, RoughtimeQuery};
use crate::time::wire::{self, Version};

/// Upper bound on one Roughtime exchange (T-32 rule 7).
pub const ROUGHTIME_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_RESPONSE: usize = 1472;

/// A configured Roughtime server (OP-43 item 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoughtimeServer {
    /// `host:port`.
    pub address: String,
    /// The server's long-term Ed25519 public key.
    pub public_key: [u8; 32],
    /// The version it speaks.
    pub version: Version,
}

/// The Roughtime port over the configured servers.
#[derive(Debug, Clone)]
pub struct RoughtimeUdp {
    servers: Vec<RoughtimeServer>,
    mono: Arc<ProcessMonotonic>,
}

impl RoughtimeUdp {
    /// A client for `servers`, timing round trips on `mono`.
    #[must_use]
    pub const fn new(servers: Vec<RoughtimeServer>, mono: Arc<ProcessMonotonic>) -> Self {
        Self { servers, mono }
    }

    async fn exchange(&self, server: &RoughtimeServer) -> Result<RoughtimeAnswer, QueryError> {
        let fail = |what: &str, e: &dyn std::fmt::Display| QueryError(format!("{what}: {e}"));
        let mut challenge = [0_u8; 32];
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(&mut challenge)
            .map_err(|_| QueryError("nonce: no randomness".to_owned()))?;
        let request = wire::request(server.version, &challenge, &server.public_key)
            .map_err(|e| fail("request", &e))?;
        let peer = tokio::net::lookup_host(server.address.as_str())
            .await
            .map_err(|e| fail("resolve", &e))?
            .next()
            .ok_or_else(|| QueryError(format!("resolve: no address for {}", server.address)))?;
        let local: SocketAddr = if peer.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(local).await.map_err(|e| fail("bind", &e))?;
        socket
            .connect(peer)
            .await
            .map_err(|e| fail("connect", &e))?;
        let sent = self.mono.now_ms();
        socket.send(&request).await.map_err(|e| fail("send", &e))?;
        let mut buf = vec![0_u8; MAX_RESPONSE];
        let n = socket
            .recv(&mut buf)
            .await
            .map_err(|e| fail("receive", &e))?;
        let received = self.mono.now_ms();
        let packet = buf.get(..n).unwrap_or_default();
        let verified = wire::verify(server.version, &server.public_key, &request, packet)
            .map_err(|e| fail("verify", &e))?;
        Ok(RoughtimeAnswer {
            midpoint_ms: verified.midpoint_s.saturating_mul(1_000),
            radius_ms: u64::from(verified.radius_s).saturating_mul(1_000),
            rtt_ms: received.saturating_sub(sent),
            mono_ms: received,
        })
    }
}

impl RoughtimeQuery for RoughtimeUdp {
    fn servers(&self) -> usize {
        self.servers.len()
    }

    async fn query(&self, server: usize) -> Result<RoughtimeAnswer, QueryError> {
        let config = self
            .servers
            .get(server)
            .ok_or_else(|| QueryError(format!("no Roughtime server {server}")))?;
        timeout(ROUGHTIME_TIMEOUT, self.exchange(config))
            .await
            .map_err(|_| QueryError(format!("no answer within {ROUGHTIME_TIMEOUT:?}")))?
    }
}
