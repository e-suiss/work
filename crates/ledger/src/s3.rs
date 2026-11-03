//! The S3-compatible object store client shared by the body store, the WORM replica and the cold
//! archive (§17 T-20, T-32 rule 8, §18 OP-2, OP-33 item 3, OP-35): path-style requests signed
//! with AWS Signature Version 4 over HTTP/1.1, every header sent being signed, TLS for `https`
//! endpoints. The request time comes from the caller's clock; every call runs under a timeout.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hmac::{Hmac, KeyInit as _, Mac as _};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use sha2::{Digest as _, Sha256};
use suiss_crypto::secret::Secret;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::body::hex;

/// Default bound of one object store call (T-32 rule 7).
const DEFAULT_S3_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the object store is and how to sign for it.
pub struct S3Config {
    /// `http://host:port` or `https://host[:port]`, without a path.
    pub endpoint: String,
    /// The signing region.
    pub region: String,
    /// The bucket, `[a-z0-9.-]{3,63}`.
    pub bucket: String,
    /// The access key id.
    pub key_id: String,
    /// The secret access key.
    pub secret: Secret<String>,
    /// TLS settings of an `https` endpoint.
    pub tls: Option<Arc<ClientConfig>>,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

/// Why an object store call did not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum S3Error {
    /// The configuration, the connection or the request failed.
    #[error("{0}")]
    Failed(String),
    /// A call ran past its bound.
    #[error("call timed out")]
    Timeout,
}

/// TLS settings that trust exactly the certificates in `pem` (T-32 rule 8).
///
/// # Errors
/// [`S3Error::Failed`] when `pem` holds no certificate or one that does not parse.
pub fn tls_trusting(pem: &[u8]) -> Result<Arc<ClientConfig>, S3Error> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|e| S3Error::Failed(format!("certificate: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| S3Error::Failed(format!("certificate: {e}")))?;
    }
    if roots.is_empty() {
        return Err(S3Error::Failed(
            "the PEM holds zero certificates".to_owned(),
        ));
    }
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| S3Error::Failed(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug, Clone)]
struct Endpoint {
    tls: bool,
    host: String,
    port: u16,
}

fn endpoint(url: &str) -> Result<Endpoint, S3Error> {
    let bad = || S3Error::Failed("endpoint must be http(s)://host[:port]".to_owned());
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(bad());
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err(bad());
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad())?),
        None => (rest, if tls { 443 } else { 80 }),
    };
    Ok(Endpoint {
        tls,
        host: host.to_owned(),
        port,
    })
}

fn bucket_ok(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
}

/// Whether `k` is an object key this client sends unescaped.
pub(crate) fn key_ok(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 512
        && !k.starts_with('/')
        && !k.contains("//")
        && k.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'/' | b'_' | b'.' | b'-')
        })
}

type HmacSha256 = Hmac<Sha256>;

fn failed(e: &impl std::fmt::Display) -> S3Error {
    S3Error::Failed(e.to_string())
}

/// One request over `stream`, one HTTP/1.1 connection per request; the caller bounds the call.
async fn send<S>(stream: S, request: Request<Full<Bytes>>) -> Result<(StatusCode, Vec<u8>), S3Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| failed(&e))?;
    let driver = tokio::spawn(conn);
    let answer = async {
        let response = sender.send_request(request).await.map_err(|e| failed(&e))?;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| failed(&e))?
            .to_bytes();
        Ok((status, bytes.to_vec()))
    }
    .await;
    driver.abort();
    answer
}

fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, S3Error> {
    let mut m = HmacSha256::new_from_slice(key).map_err(|e| failed(&e))?;
    m.update(data);
    Ok(m.finalize().into_bytes().to_vec())
}

pub(crate) fn sha_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` of Unix milliseconds `ms`, UTC.
pub(crate) fn stamp(ms: u64) -> (String, String) {
    let (y, m, d, hh, mm, ss) = utc(ms);
    let date = format!("{y:04}{m:02}{d:02}");
    let time = format!("{date}T{hh:02}{mm:02}{ss:02}Z");
    (date, time)
}

/// `YYYY-MM-DDTHH:MM:SSZ` of Unix milliseconds `ms`, UTC.
pub(crate) fn rfc3339(ms: u64) -> String {
    let (y, m, d, hh, mm, ss) = utc(ms);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn utc(ms: u64) -> (u64, u64, u64, u64, u64, u64) {
    let secs = ms / 1000;
    let rem = secs % 86_400;
    let (y, m, d) = civil(secs / 86_400);
    (y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// The proleptic Gregorian date of `days` since 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let d = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(u64::from(m <= 2));
    (y, m, d)
}

/// The `SigV4` signing key of `secret` for `date`, `region` and `service`.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Result<Vec<u8>, S3Error> {
    let mut key = b"AWS4".to_vec();
    key.extend_from_slice(secret.as_bytes());
    let k = mac(&key, date.as_bytes())?;
    let k = mac(&k, region.as_bytes())?;
    let k = mac(&k, service.as_bytes())?;
    mac(&k, b"aws4_request")
}

/// What one request signs.
struct Canonical<'a> {
    method: &'a Method,
    path: &'a str,
    query: &'a str,
    /// Lowercase names, sorted, each name sent once.
    headers: &'a [(String, String)],
    payload: &'a str,
}

/// The `Authorization` value of `request` at `time` (`YYYYMMDDTHHMMSSZ`) on `date`.
fn authorization(
    key_id: &str,
    secret: &str,
    region: &str,
    request: &Canonical<'_>,
    date: &str,
    time: &str,
) -> Result<String, S3Error> {
    let scope = format!("{date}/{region}/s3/aws4_request");
    let mut lines = String::new();
    for (name, value) in request.headers {
        lines.push_str(name);
        lines.push(':');
        lines.push_str(value.trim());
        lines.push('\n');
    }
    let signed = request
        .headers
        .iter()
        .map(|(n, _)| n.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{lines}\n{signed}\n{}",
        request.method, request.path, request.query, request.payload
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{time}\n{scope}\n{}",
        sha_hex(canonical.as_bytes())
    );
    let k = signing_key(secret, date, region, "s3")?;
    let signature = hex(&mac(&k, to_sign.as_bytes())?);
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed}, Signature={signature}"
    ))
}

/// A signed S3 client of one bucket.
pub(crate) struct S3Client {
    endpoint: Endpoint,
    config: S3Config,
    limit: Duration,
}

impl std::fmt::Debug for S3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Client")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl S3Client {
    /// The client of the store `config` names.
    pub(crate) fn new(config: S3Config) -> Result<Self, S3Error> {
        let endpoint = endpoint(&config.endpoint)?;
        if !bucket_ok(&config.bucket) {
            return Err(S3Error::Failed("malformed bucket name".to_owned()));
        }
        if endpoint.tls && config.tls.is_none() {
            return Err(S3Error::Failed(
                "an https endpoint needs TLS settings".to_owned(),
            ));
        }
        Ok(Self {
            endpoint,
            config,
            limit: DEFAULT_S3_TIMEOUT,
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

    /// `/<bucket>`.
    pub(crate) fn bucket_path(&self) -> String {
        format!("/{}", self.config.bucket)
    }

    /// `/<bucket>/<key>` for a well-formed `key`.
    pub(crate) fn object_path(&self, key: &str) -> Result<String, S3Error> {
        if !key_ok(key) {
            return Err(S3Error::Failed("malformed object key".to_owned()));
        }
        Ok(format!("/{}/{key}", self.config.bucket))
    }

    async fn exchange(
        &self,
        method: Method,
        path: &str,
        query: &str,
        extra: &[(&str, String)],
        body: Vec<u8>,
        now_ms: u64,
    ) -> Result<(StatusCode, Vec<u8>), S3Error> {
        let payload = sha_hex(&body);
        let (date, time) = stamp(now_ms);
        let mut headers: Vec<(String, String)> = vec![
            ("host".to_owned(), self.host_header()),
            ("x-amz-content-sha256".to_owned(), payload.clone()),
            ("x-amz-date".to_owned(), time.clone()),
        ];
        headers.extend(
            extra
                .iter()
                .map(|(n, v)| (n.to_ascii_lowercase(), v.clone())),
        );
        headers.sort();
        let auth = authorization(
            &self.config.key_id,
            self.config.secret.expose(),
            &self.config.region,
            &Canonical {
                method: &method,
                path,
                query,
                headers: &headers,
                payload: &payload,
            },
            &date,
            &time,
        )?;
        let uri = if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        };
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in &headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder
            .header("authorization", auth)
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| failed(&e))?;
        let address = (self.endpoint.host.as_str(), self.endpoint.port);
        let tcp = timeout(self.limit, TcpStream::connect(address))
            .await
            .map_err(|_| S3Error::Timeout)?
            .map_err(|e| failed(&e))?;
        if !self.endpoint.tls {
            return send(tcp, request).await;
        }
        let tls =
            self.config.tls.clone().ok_or_else(|| {
                S3Error::Failed("an https endpoint needs TLS settings".to_owned())
            })?;
        let name = ServerName::try_from(self.endpoint.host.clone()).map_err(|e| failed(&e))?;
        let stream = timeout(self.limit, TlsConnector::from(tls).connect(name, tcp))
            .await
            .map_err(|_| S3Error::Timeout)?
            .map_err(|e| failed(&e))?;
        send(stream, request).await
    }

    /// One signed request: `query` is the canonical query string (`name=value`, sorted), and
    /// every header in `extra` is signed too.
    pub(crate) async fn call(
        &self,
        method: Method,
        path: &str,
        query: &str,
        extra: &[(&str, String)],
        body: Vec<u8>,
        now_ms: u64,
    ) -> Result<(StatusCode, Vec<u8>), S3Error> {
        timeout(
            self.limit,
            self.exchange(method, path, query, extra, body, now_ms),
        )
        .await
        .map_err(|_| S3Error::Timeout)?
    }

    /// Creates the bucket with `extra` headers; an existing bucket of this owner is not an
    /// error.
    pub(crate) async fn ensure_bucket(
        &self,
        extra: &[(&str, String)],
        now_ms: u64,
    ) -> Result<(), S3Error> {
        let path = self.bucket_path();
        let (status, _) = self
            .call(Method::PUT, &path, "", extra, Vec::new(), now_ms)
            .await?;
        if status.is_success() || status == StatusCode::CONFLICT {
            Ok(())
        } else {
            Err(S3Error::Failed(format!("create bucket: {status}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-20 OP-2
    #[test]
    fn t_20_the_object_store_endpoint_and_names_are_checked() {
        assert!(endpoint("http://127.0.0.1:7070").is_ok_and(|e| !e.tls && e.port == 7070));
        assert!(endpoint("https://s3.example").is_ok_and(|e| e.tls && e.port == 443));
        for bad in [
            "ftp://x",
            "http://",
            "http://x/y",
            "http://u@x",
            "http://x:port",
        ] {
            assert!(endpoint(bad).is_err(), "{bad}");
        }
        assert!(bucket_ok("work-bodies"));
        assert!(!bucket_ok("Work"));
        assert!(key_ok("ab/cd"));
        assert!(!key_ok("../x?y"));
        assert!(!key_ok("/ab"));
        assert!(!key_ok("ab//cd"));
        assert!(tls_trusting(b"").is_err());
    }

    // T-20
    #[test]
    fn t_20_request_time_is_the_utc_date_of_the_clock() {
        assert_eq!(
            stamp(1_440_938_160_000),
            ("20150830".to_owned(), "20150830T123600Z".to_owned())
        );
        assert_eq!(stamp(0).1, "19700101T000000Z");
        assert_eq!(stamp(951_782_400_000).0, "20000229");
        assert_eq!(rfc3339(1_440_938_160_999), "2015-08-30T12:36:00Z");
    }

    // T-20
    #[test]
    fn t_20_requests_are_signed_with_signature_version_4() {
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        )
        .unwrap();
        assert_eq!(
            hex(&key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
        let empty = sha_hex(b"");
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let headers = [
            (
                "host".to_owned(),
                "examplebucket.s3.amazonaws.com".to_owned(),
            ),
            ("range".to_owned(), "bytes=0-9".to_owned()),
            ("x-amz-content-sha256".to_owned(), empty.clone()),
            ("x-amz-date".to_owned(), "20130524T000000Z".to_owned()),
        ];
        let auth = authorization(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            &Canonical {
                method: &Method::GET,
                path: "/test.txt",
                query: "",
                headers: &headers,
                payload: &empty,
            },
            "20130524",
            "20130524T000000Z",
        )
        .unwrap();
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        let client = S3Client::new(S3Config {
            endpoint: "http://127.0.0.1:7070".to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "work-bodies".to_owned(),
            key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            secret: Secret::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned()),
            tls: None,
        })
        .unwrap();
        assert_eq!(client.host_header(), "127.0.0.1:7070");
        assert_eq!(client.object_path("ab/cd").unwrap(), "/work-bodies/ab/cd");
        assert!(client.object_path("Ab").is_err());
    }
}
