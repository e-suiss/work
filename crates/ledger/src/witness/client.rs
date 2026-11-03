//! The C2SP `tlog-witness` client (§18 OP-33 item 1, OP-46 item 10): `POST <prefix>/add-checkpoint`
//! with the size the witness holds, the consistency proof from it and the log-signed checkpoint,
//! over HTTP/1.1 with TLS for an `https` witness, every exchange under one time limit; the answer
//! is typed by the status the protocol gives it, and an answer above 64 KiB is not read.

use std::io::BufRead;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use suiss_crypto::note::base64_encode;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// Upper bound on one exchange with a witness, as on the time sources (OP-44 item 4).
pub const DEFAULT_WITNESS_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_ANSWER: usize = 64 * 1024;

const SIZE_TYPE: &str = "text/x.tlog.size";

/// What a witness answered (C2SP `tlog-witness`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessAnswer {
    /// 200: its cosignature lines over the checkpoint, each ending in a newline.
    Cosigned(String),
    /// 409: the old size is not the size it holds, which it names.
    Conflict(u64),
    /// 404: it does not know the checkpoint's origin.
    UnknownLog,
    /// 403: no signature of a log key it trusts for the origin verified.
    Forbidden,
    /// 422: the proof does not lead from the tree it holds, or it holds another root at the
    /// same size: a split view of the log (SEC-32).
    Inconsistent,
    /// 400: the request is malformed or its old size is above the checkpoint's.
    BadRequest,
}

/// Why a witness gave no answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessCallError {
    /// The URL is not `http(s)://host[:port][/prefix]`.
    #[error("witness url must be http(s)://host[:port][/prefix]")]
    Url,
    /// An `https` witness without TLS settings, or roots that do not load.
    #[error("witness TLS settings are missing or do not load")]
    Tls,
    /// No answer within the limit.
    #[error("witness did not answer in time")]
    Timeout,
    /// The connection could not be made or broke off.
    #[error("witness unreachable: {0}")]
    Transport(String),
    /// A status the protocol does not give.
    #[error("witness answered status {0}")]
    Status(u16),
    /// An answer that is not what its status requires.
    #[error("witness answer is malformed")]
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    tls: bool,
    host: String,
    port: u16,
    prefix: String,
}

fn endpoint(url: &str) -> Result<Endpoint, WitnessCallError> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(WitnessCallError::Url);
    };
    if !rest.bytes().all(|b| b.is_ascii_graphic()) || rest.contains(['?', '#', '@', '[']) {
        return Err(WitnessCallError::Url);
    }
    let (authority, path) = rest
        .find('/')
        .and_then(|at| rest.split_at_checked(at))
        .unwrap_or((rest, ""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| WitnessCallError::Url)?),
        None => (authority, if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(WitnessCallError::Url);
    }
    Ok(Endpoint {
        tls,
        host: host.to_owned(),
        port,
        prefix: path.trim_end_matches('/').to_owned(),
    })
}

/// The `add-checkpoint` body: the old size, one base64 proof line per hash, an empty line and
/// the checkpoint note.
pub(crate) fn request_body(old: u64, proof: &[[u8; 32]], note: &str) -> String {
    let mut body = format!("old {old}\n");
    for hash in proof {
        body.push_str(&base64_encode(hash));
        body.push('\n');
    }
    body.push('\n');
    body.push_str(note);
    body
}

fn cosignature_lines(body: &[u8]) -> Result<String, WitnessCallError> {
    let text = std::str::from_utf8(body).map_err(|_| WitnessCallError::Malformed)?;
    let lines_ok = text
        .split_terminator('\n')
        .all(|line| line.starts_with("\u{2014} "));
    if text.is_empty() || !text.ends_with('\n') || !lines_ok {
        return Err(WitnessCallError::Malformed);
    }
    Ok(text.to_owned())
}

fn size_line(body: &[u8]) -> Result<u64, WitnessCallError> {
    let text = std::str::from_utf8(body).map_err(|_| WitnessCallError::Malformed)?;
    let digits = text.strip_suffix('\n').ok_or(WitnessCallError::Malformed)?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        return Err(WitnessCallError::Malformed);
    }
    digits.parse().map_err(|_| WitnessCallError::Malformed)
}

/// The answer a status, content type and body make (C2SP `tlog-witness`).
pub(crate) fn answer(
    status: StatusCode,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<WitnessAnswer, WitnessCallError> {
    match status {
        StatusCode::OK => cosignature_lines(body).map(WitnessAnswer::Cosigned),
        StatusCode::CONFLICT => {
            let media = content_type
                .and_then(|t| t.split(';').next())
                .map(str::trim);
            if media != Some(SIZE_TYPE) {
                return Err(WitnessCallError::Malformed);
            }
            size_line(body).map(WitnessAnswer::Conflict)
        }
        StatusCode::NOT_FOUND => Ok(WitnessAnswer::UnknownLog),
        StatusCode::FORBIDDEN => Ok(WitnessAnswer::Forbidden),
        StatusCode::UNPROCESSABLE_ENTITY => Ok(WitnessAnswer::Inconsistent),
        StatusCode::BAD_REQUEST => Ok(WitnessAnswer::BadRequest),
        other => Err(WitnessCallError::Status(other.as_u16())),
    }
}

/// TLS settings for `https` witnesses that trust exactly the certificates in the PEM `roots`.
///
/// # Errors
/// [`WitnessCallError::Tls`] when no certificate loads.
pub fn witness_tls(roots: &mut dyn BufRead) -> Result<Arc<ClientConfig>, WitnessCallError> {
    let mut store = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(roots) {
        let cert = cert.map_err(|_| WitnessCallError::Tls)?;
        store.add(cert).map_err(|_| WitnessCallError::Tls)?;
    }
    if store.is_empty() {
        return Err(WitnessCallError::Tls);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| WitnessCallError::Tls)?
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn transport(e: &dyn std::fmt::Display) -> WitnessCallError {
    WitnessCallError::Transport(e.to_string())
}

async fn send<S>(
    stream: S,
    request: Request<Full<Bytes>>,
) -> Result<WitnessAnswer, WitnessCallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| transport(&e))?;
    let driver = tokio::spawn(conn);
    let answered = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| transport(&e))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|_| WitnessCallError::Malformed)?
            .to_bytes();
        answer(status, content_type.as_deref(), &body)
    }
    .await;
    driver.abort();
    answered
}

/// A client of one witness's submission prefix.
#[derive(Clone)]
pub struct WitnessClient {
    endpoint: Endpoint,
    tls: Option<Arc<ClientConfig>>,
    limit: Duration,
}

impl std::fmt::Debug for WitnessClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessClient")
            .field("endpoint", &self.endpoint)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl WitnessClient {
    /// A client of the witness at `url`, `http://host[:port][/prefix]` or `https://…` with
    /// `tls`, each exchange bounded by `limit`.
    ///
    /// # Errors
    /// [`WitnessCallError::Url`] for a malformed URL, [`WitnessCallError::Tls`] for an `https`
    /// URL without `tls`.
    pub fn new(
        url: &str,
        tls: Option<Arc<ClientConfig>>,
        limit: Duration,
    ) -> Result<Self, WitnessCallError> {
        let endpoint = endpoint(url)?;
        if endpoint.tls && tls.is_none() {
            return Err(WitnessCallError::Tls);
        }
        Ok(Self {
            endpoint,
            tls,
            limit,
        })
    }

    fn host_header(&self) -> String {
        let default = if self.endpoint.tls { 443 } else { 80 };
        if self.endpoint.port == default {
            self.endpoint.host.clone()
        } else {
            format!("{}:{}", self.endpoint.host, self.endpoint.port)
        }
    }

    /// Sends `note`, a checkpoint the log signed, from the size `old` the witness holds with
    /// `proof` from it.
    ///
    /// # Errors
    /// [`WitnessCallError`] when no answer of the protocol came.
    pub async fn add_checkpoint(
        &self,
        old: u64,
        proof: &[[u8; 32]],
        note: &str,
    ) -> Result<WitnessAnswer, WitnessCallError> {
        let body = request_body(old, proof, note);
        timeout(self.limit, self.exchange(body))
            .await
            .map_err(|_| WitnessCallError::Timeout)?
    }

    async fn exchange(&self, body: String) -> Result<WitnessAnswer, WitnessCallError> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/add-checkpoint", self.endpoint.prefix))
            .header(header::HOST, self.host_header())
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| WitnessCallError::Url)?;
        let address = (self.endpoint.host.as_str(), self.endpoint.port);
        let tcp = timeout(self.limit, TcpStream::connect(address))
            .await
            .map_err(|_| WitnessCallError::Timeout)?
            .map_err(|e| transport(&e))?;
        if !self.endpoint.tls {
            return send(tcp, request).await;
        }
        let tls = self.tls.clone().ok_or(WitnessCallError::Tls)?;
        let name = ServerName::try_from(self.endpoint.host.clone())
            .map_err(|_| WitnessCallError::Url)?;
        let stream = timeout(self.limit, TlsConnector::from(tls).connect(name, tcp))
            .await
            .map_err(|_| WitnessCallError::Timeout)?
            .map_err(|e| transport(&e))?;
        send(stream, request).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-33 OP-46
    #[test]
    fn op_33_the_add_checkpoint_body_is_old_size_proof_lines_and_the_note() {
        let note = "o\n2\nAAAA\n\n\u{2014} log abc\n";
        assert_eq!(request_body(0, &[], note), format!("old 0\n\n{note}"));
        let body = request_body(3, &[[0; 32], [0xff; 32]], note);
        assert_eq!(
            body,
            format!(
                "old 3\n{}\n{}\n\n{note}",
                base64_encode(&[0; 32]),
                base64_encode(&[0xff; 32])
            )
        );
    }

    // OP-33 OP-46 SEC-32
    #[test]
    fn op_46_witness_answers_are_typed_by_their_status() {
        let line = "\u{2014} witness.example AAAA\n";
        assert_eq!(
            answer(StatusCode::OK, None, line.as_bytes()),
            Ok(WitnessAnswer::Cosigned(line.to_owned()))
        );
        for bad in ["", "\u{2014} w A", "\u{2014} w A\n\n", "w A\n"] {
            assert_eq!(
                answer(StatusCode::OK, None, bad.as_bytes()),
                Err(WitnessCallError::Malformed),
                "{bad:?}"
            );
        }
        assert_eq!(
            answer(StatusCode::CONFLICT, Some(SIZE_TYPE), b"7\n"),
            Ok(WitnessAnswer::Conflict(7))
        );
        assert_eq!(
            answer(StatusCode::CONFLICT, Some("text/x.tlog.size; x=1"), b"0\n"),
            Ok(WitnessAnswer::Conflict(0))
        );
        for (media, body) in [
            (Some("text/plain"), "7\n"),
            (None, "7\n"),
            (Some(SIZE_TYPE), "07\n"),
            (Some(SIZE_TYPE), "7"),
            (Some(SIZE_TYPE), "-1\n"),
        ] {
            assert_eq!(
                answer(StatusCode::CONFLICT, media, body.as_bytes()),
                Err(WitnessCallError::Malformed),
                "{media:?} {body:?}"
            );
        }
        assert_eq!(
            answer(StatusCode::NOT_FOUND, None, b""),
            Ok(WitnessAnswer::UnknownLog)
        );
        assert_eq!(
            answer(StatusCode::FORBIDDEN, None, b""),
            Ok(WitnessAnswer::Forbidden)
        );
        assert_eq!(
            answer(StatusCode::UNPROCESSABLE_ENTITY, None, b""),
            Ok(WitnessAnswer::Inconsistent)
        );
        assert_eq!(
            answer(StatusCode::BAD_REQUEST, None, b""),
            Ok(WitnessAnswer::BadRequest)
        );
        assert_eq!(
            answer(StatusCode::SERVICE_UNAVAILABLE, None, b""),
            Err(WitnessCallError::Status(503))
        );
    }

    // OP-33 T-32
    #[test]
    fn op_33_a_witness_is_named_by_an_http_url_and_https_needs_tls() {
        let e = endpoint("http://witness:7380").unwrap();
        assert_eq!(
            (e.tls, e.host.as_str(), e.port, e.prefix.as_str()),
            (false, "witness", 7380, "")
        );
        let e = endpoint("https://w.example/tlog/").unwrap();
        assert_eq!(
            (e.tls, e.host.as_str(), e.port, e.prefix.as_str()),
            (true, "w.example", 443, "/tlog")
        );
        for bad in [
            "witness:7380",
            "ftp://w",
            "http://",
            "http://:80",
            "http://w:x",
            "http://u@w",
            "http://w/a b",
            "http://w?q",
            "http://[::1]:80",
        ] {
            assert_eq!(endpoint(bad), Err(WitnessCallError::Url), "{bad}");
        }
        assert_eq!(
            WitnessClient::new("https://w.example", None, DEFAULT_WITNESS_TIMEOUT).err(),
            Some(WitnessCallError::Tls)
        );
        let client = WitnessClient::new("http://w:80", None, DEFAULT_WITNESS_TIMEOUT).unwrap();
        assert_eq!(client.host_header(), "w");
        assert_eq!(
            witness_tls(&mut "".as_bytes()).err(),
            Some(WitnessCallError::Tls)
        );
    }
}
