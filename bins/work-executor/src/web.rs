//! The executor's exchange with Work's API (T-105): one HTTP/1.1 call per request over plain TCP for an `http://` base, as the local environment serves Work, or TLS 1.3 over the configured roots for an `https://` one, each bounded in time and size.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// The longest a connection or a TLS handshake may take.
const CONNECT: Duration = Duration::from_secs(10);

/// The largest answer read.
const MAX_BODY: usize = 4_194_304;

/// One answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Answer {
    /// The status.
    pub(crate) status: u16,
    /// The headers, lower-case names.
    pub(crate) headers: Vec<(String, String)>,
    /// The body.
    pub(crate) body: Vec<u8>,
}

impl Answer {
    /// The first value of header `name`.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Why no answer came.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpError {
    /// The URL is not one the executor calls.
    #[error("not an http or https URL")]
    Url,
    /// The call did not end within its bound.
    #[error("timeout")]
    Timeout,
    /// The connection or the exchange failed.
    #[error("exchange: {0}")]
    Exchange(String),
}

fn failed(e: &impl std::fmt::Display) -> HttpError {
    HttpError::Exchange(e.to_string())
}

/// Where one call goes.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    tls: bool,
    host: String,
    port: u16,
    authority: String,
    path: String,
}

fn target(url: &str) -> Result<Target, HttpError> {
    let (tls, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (None, Some(rest)) => (false, rest),
        (None, None) => return Err(HttpError::Url),
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => rest.split_at_checked(i).ok_or(HttpError::Url)?,
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains(['@', '[']) {
        return Err(HttpError::Url);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| HttpError::Url)?),
        None => (authority, if tls { 443 } else { 80 }),
    };
    Ok(Target {
        tls,
        host: host.to_owned(),
        port,
        authority: authority.to_owned(),
        path: if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        },
    })
}

/// The exchange.
#[derive(Clone)]
pub(crate) struct Http {
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http").finish_non_exhaustive()
    }
}

async fn exchange<I>(io: I, request: http::Request<Full<Bytes>>) -> Result<Answer, HttpError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| failed(&e))?;
    let driver = tokio::spawn(connection);
    let answer = async {
        let response = sender.send_request(request).await.map_err(|e| failed(&e))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(n, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (n.as_str().to_owned(), v.to_owned()))
            })
            .collect();
        let body = Limited::new(response.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| failed(&e))?
            .to_bytes()
            .to_vec();
        Ok(Answer {
            status,
            headers,
            body,
        })
    }
    .await;
    driver.abort();
    answer
}

impl Http {
    /// An exchange whose TLS calls trust what `tls` trusts.
    pub(crate) const fn new(tls: Arc<ClientConfig>) -> Self {
        Self { tls }
    }

    async fn call(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<Answer, HttpError> {
        let t = target(url)?;
        let mut builder = http::Request::builder()
            .method(method)
            .uri(t.path.as_str())
            .header("host", t.authority.as_str());
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| failed(&e))?;
        let tcp = timeout(CONNECT, TcpStream::connect((t.host.as_str(), t.port)))
            .await
            .map_err(|_| HttpError::Timeout)?
            .map_err(|e| failed(&e))?;
        if t.tls {
            let name = ServerName::try_from(t.host.clone()).map_err(|e| failed(&e))?;
            let stream = timeout(
                CONNECT,
                TlsConnector::from(Arc::clone(&self.tls)).connect(name, tcp),
            )
            .await
            .map_err(|_| HttpError::Timeout)?
            .map_err(|e| failed(&e))?;
            exchange(stream, request).await
        } else {
            exchange(tcp, request).await
        }
    }

    /// Sends `method url` with `headers` and a JSON `body`, within `bound`.
    pub(crate) async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
        bound: Duration,
    ) -> Result<Answer, HttpError> {
        timeout(bound, self.call(method, url, headers, body))
            .await
            .map_err(|_| HttpError::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-105
    #[test]
    fn t_105_work_is_called_over_http_or_https_only() {
        let plain = target("http://work-server:8090/v1/ledgers/led_a?after=0").unwrap();
        assert!(!plain.tls);
        assert_eq!(plain.port, 8090);
        assert_eq!(plain.path, "/v1/ledgers/led_a?after=0");
        let tls = target("https://work.localhost").unwrap();
        assert!(tls.tls);
        assert_eq!(tls.port, 443);
        assert_eq!(tls.path, "/");
        assert!(target("ftp://work").is_err());
        assert!(target("http://user@work/").is_err());
        assert!(target("http://work:x/").is_err());
    }
}
