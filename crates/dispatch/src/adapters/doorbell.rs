//! Adapters of the executor doorbell (E-39, T-105): [`PgDoorbells`], the delivery rows of the canonical store over a pool logged in as `work_publisher`, each call in a transaction of its own (T-32 rule 4); and [`HttpRing`], an HTTP/1.1 client that POSTs the doorbell to an `http` or, with the operator's roots, an `https` webhook, every exchange under a timeout (T-32 rule 7).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, header};
use http_body_util::Full;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use work_store::{ExecutorDelivery, LedgerId, PublisherPool, StoreError};

use crate::domain::doorbell::RingError;
use crate::ports::{DoorbellQueue, Ring};

/// The delivery rows over a pool logged in as `work_publisher`.
#[derive(Debug, Clone)]
pub struct PgDoorbells {
    pool: PublisherPool,
}

impl PgDoorbells {
    /// Over `pool`.
    #[must_use]
    pub const fn new(pool: PublisherPool) -> Self {
        Self { pool }
    }
}

impl DoorbellQueue for PgDoorbells {
    async fn ledgers(
        &self,
        after: Option<&LedgerId>,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<LedgerId>, StoreError> {
        self.pool.doorbell_ledgers(after, now_ms, limit).await
    }

    async fn due(
        &self,
        ledger: &LedgerId,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<ExecutorDelivery>, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let rows = tx.doorbells_due(now_ms, limit).await?;
        tx.commit().await?;
        Ok(rows)
    }

    async fn settled(
        &self,
        ledger: &LedgerId,
        seq: u64,
        rung: bool,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let done = tx.doorbell_settled(seq, rung, at_ms).await?;
        tx.commit().await?;
        Ok(done)
    }

    async fn retry(
        &self,
        ledger: &LedgerId,
        seq: u64,
        error: &str,
        next_attempt_ms: u64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin(ledger).await?;
        let done = tx.doorbell_retry(seq, error, next_attempt_ms).await?;
        tx.commit().await?;
        Ok(done)
    }
}

/// A webhook URL taken apart: `http(s)://host[:port][/path]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Webhook {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

impl Webhook {
    /// The parts of `url`.
    ///
    /// # Errors
    /// [`RingError::Url`] for a URL that is not `http(s)://host[:port][/path]` without user
    /// information, query or fragment.
    pub fn parse(url: &str) -> Result<Self, RingError> {
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(RingError::Url);
        };
        if rest.contains(['?', '#', '@']) {
            return Err(RingError::Url);
        }
        let (authority, path) = rest
            .split_once('/')
            .map_or((rest, "/".to_owned()), |(a, p)| (a, format!("/{p}")));
        let default = if tls { 443 } else { 80 };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().map_err(|_| RingError::Url)?),
            None => (authority, default),
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(RingError::Url);
        }
        Ok(Self {
            tls,
            host: host.to_owned(),
            port,
            path,
        })
    }

    /// Whether it is an `https` webhook.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.tls
    }

    fn host_header(&self) -> String {
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// The doorbell client: `https` webhooks verify against the operator's roots, and each
/// exchange is bounded by `limit`.
#[derive(Clone)]
pub struct HttpRing<C> {
    tls: Option<Arc<ClientConfig>>,
    limit: Duration,
    clock: C,
}

impl<C> std::fmt::Debug for HttpRing<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRing")
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl<C> HttpRing<C> {
    /// A client verifying `https` webhooks against `tls`, each exchange bounded by `limit`,
    /// reading time from `clock`.
    #[must_use]
    pub const fn new(tls: Option<Arc<ClientConfig>>, limit: Duration, clock: C) -> Self {
        Self { tls, limit, clock }
    }
}

async fn post<S>(stream: S, request: Request<Full<Bytes>>) -> Result<(), RingError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| RingError::Unreachable)?;
    let driver = tokio::spawn(conn);
    let answered = sender
        .send_request(request)
        .await
        .map_err(|_| RingError::Unreachable);
    driver.abort();
    let status = answered?.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(RingError::Status(status.as_u16()))
    }
}

impl<C: Fn() -> u64 + Send + Sync> HttpRing<C> {
    async fn exchange(&self, hook: &Webhook, body: &str) -> Result<(), RingError> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(hook.path.as_str())
            .header(header::HOST, hook.host_header())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_owned())))
            .map_err(|_| RingError::Url)?;
        let tcp = timeout(
            self.limit,
            TcpStream::connect((hook.host.as_str(), hook.port)),
        )
        .await
        .map_err(|_| RingError::Timeout)?
        .map_err(|_| RingError::Unreachable)?;
        if !hook.tls {
            return post(tcp, request).await;
        }
        let tls = self.tls.clone().ok_or(RingError::Url)?;
        let name = ServerName::try_from(hook.host.clone()).map_err(|_| RingError::Url)?;
        let stream = timeout(self.limit, TlsConnector::from(tls).connect(name, tcp))
            .await
            .map_err(|_| RingError::Timeout)?
            .map_err(|_| RingError::Unreachable)?;
        post(stream, request).await
    }
}

impl<C: Fn() -> u64 + Send + Sync> Ring for HttpRing<C> {
    fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    async fn ring(&self, url: &str, body: &str) -> Result<(), RingError> {
        let hook = Webhook::parse(url)?;
        timeout(self.limit, self.exchange(&hook, body))
            .await
            .map_err(|_| RingError::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // E-39
    #[test]
    fn e_39_a_webhook_url_is_http_or_https_without_credentials_query_or_fragment() {
        let hook = Webhook::parse("https://agent.example:8443/hooks/work").unwrap();
        assert!(hook.tls);
        assert_eq!(hook.port, 8443);
        assert_eq!(hook.path, "/hooks/work");
        assert_eq!(hook.host_header(), "agent.example:8443");
        let plain = Webhook::parse("http://robot").unwrap();
        assert_eq!((plain.port, plain.path.as_str()), (80, "/"));
        for bad in [
            "ftp://x/",
            "https://user@x/",
            "https://x/?a=1",
            "https://x/#f",
            "https:///p",
            "https://x:port/",
        ] {
            assert_eq!(Webhook::parse(bad), Err(RingError::Url), "{bad}");
        }
    }
}
