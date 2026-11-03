//! The S3-compatible object store adapter (§17 T-20, T-32 rule 8, OP-2): path-style `PUT` and
//! `GET` of ciphertexts by their content address, signed with AWS Signature Version 4 over
//! HTTP/1.1, TLS for `https` endpoints. The request time comes from the caller's clock; every
//! call runs under a timeout.

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
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use super::{BodyError, DEFAULT_CALL_TIMEOUT, ObjectStore, hex};

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

#[derive(Debug, Clone)]
struct Endpoint {
    tls: bool,
    host: String,
    port: u16,
}

fn endpoint(url: &str) -> Result<Endpoint, BodyError> {
    let bad = || BodyError::Object("endpoint must be http(s)://host[:port]".to_owned());
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

fn key_ok(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 512
        && k.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'/' | b'_' | b'.' | b'-')
        })
}

/// An S3-compatible object store (T-20).
pub struct S3Store {
    endpoint: Endpoint,
    config: S3Config,
    limit: Duration,
}

impl std::fmt::Debug for S3Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Store")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

type HmacSha256 = Hmac<Sha256>;

fn io(e: &std::io::Error) -> BodyError {
    BodyError::Object(e.to_string())
}

fn http(e: &hyper::Error) -> BodyError {
    BodyError::Object(e.to_string())
}

/// One request over `stream`, one HTTP/1.1 connection per request; the caller bounds the call.
async fn send<S>(
    stream: S,
    request: Request<Full<Bytes>>,
) -> Result<(StatusCode, Vec<u8>), BodyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| http(&e))?;
    let driver = tokio::spawn(conn);
    let answer = async {
        let response = sender.send_request(request).await.map_err(|e| http(&e))?;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| http(&e))?
            .to_bytes();
        Ok((status, bytes.to_vec()))
    }
    .await;
    driver.abort();
    answer
}

fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, BodyError> {
    let mut m = HmacSha256::new_from_slice(key).map_err(|_| BodyError::Corrupt)?;
    m.update(data);
    Ok(m.finalize().into_bytes().to_vec())
}

fn sha_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` of Unix milliseconds `ms`, UTC.
fn stamp(ms: u64) -> (String, String) {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil(days);
    let date = format!("{y:04}{m:02}{d:02}");
    let time = format!(
        "{date}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );
    (date, time)
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
fn signing_key(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, BodyError> {
    let mut key = b"AWS4".to_vec();
    key.extend_from_slice(secret.as_bytes());
    let k = mac(&key, date.as_bytes())?;
    let k = mac(&k, region.as_bytes())?;
    let k = mac(&k, service.as_bytes())?;
    mac(&k, b"aws4_request")
}

impl S3Store {
    /// The store `config` names.
    ///
    /// # Errors
    /// [`BodyError::Object`] for a malformed endpoint or bucket, or an `https` endpoint without
    /// TLS settings.
    pub fn new(config: S3Config) -> Result<Self, BodyError> {
        let endpoint = endpoint(&config.endpoint)?;
        if !bucket_ok(&config.bucket) {
            return Err(BodyError::Object("malformed bucket name".to_owned()));
        }
        if endpoint.tls && config.tls.is_none() {
            return Err(BodyError::Object(
                "an https endpoint needs TLS settings".to_owned(),
            ));
        }
        Ok(Self {
            endpoint,
            config,
            limit: DEFAULT_CALL_TIMEOUT,
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

    fn authorization(
        &self,
        method: &Method,
        path: &str,
        host: &str,
        payload: &str,
        now_ms: u64,
    ) -> Result<(String, String), BodyError> {
        let (date, time) = stamp(now_ms);
        let scope = format!("{date}/{}/s3/aws4_request", self.config.region);
        let signed = "host;x-amz-content-sha256;x-amz-date";
        let canonical = format!(
            "{method}\n{path}\n\nhost:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{time}\n\n{signed}\n{payload}"
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{time}\n{scope}\n{}",
            sha_hex(canonical.as_bytes())
        );
        let k = signing_key(
            self.config.secret.expose(),
            &date,
            &self.config.region,
            "s3",
        )?;
        let signature = hex(&mac(&k, to_sign.as_bytes())?);
        Ok((
            time,
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
                self.config.key_id
            ),
        ))
    }

    async fn exchange(
        &self,
        method: Method,
        path: String,
        body: Vec<u8>,
        now_ms: u64,
    ) -> Result<(StatusCode, Vec<u8>), BodyError> {
        let host = self.host_header();
        let payload = sha_hex(&body);
        let (time, auth) = self.authorization(&method, &path, &host, &payload, now_ms)?;
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host)
            .header("x-amz-content-sha256", payload)
            .header("x-amz-date", time)
            .header("authorization", auth)
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| BodyError::Object(e.to_string()))?;
        let address = (self.endpoint.host.as_str(), self.endpoint.port);
        let tcp = timeout(self.limit, TcpStream::connect(address))
            .await
            .map_err(|_| BodyError::Timeout)?
            .map_err(|e| io(&e))?;
        if !self.endpoint.tls {
            return send(tcp, request).await;
        }
        let tls = self.config.tls.clone().ok_or(BodyError::Corrupt)?;
        let name = ServerName::try_from(self.endpoint.host.clone())
            .map_err(|e| BodyError::Object(e.to_string()))?;
        let stream = timeout(self.limit, TlsConnector::from(tls).connect(name, tcp))
            .await
            .map_err(|_| BodyError::Timeout)?
            .map_err(|e| io(&e))?;
        send(stream, request).await
    }

    async fn call(
        &self,
        method: Method,
        path: String,
        body: Vec<u8>,
        now_ms: u64,
    ) -> Result<(StatusCode, Vec<u8>), BodyError> {
        timeout(self.limit, self.exchange(method, path, body, now_ms))
            .await
            .map_err(|_| BodyError::Timeout)?
    }

    /// Creates the bucket; an existing bucket of this owner is not an error.
    ///
    /// # Errors
    /// [`BodyError::Object`] for any other answer.
    pub async fn ensure_bucket(&self, now_ms: u64) -> Result<(), BodyError> {
        let path = format!("/{}", self.config.bucket);
        let (status, _) = self.call(Method::PUT, path, Vec::new(), now_ms).await?;
        if status.is_success() || status == StatusCode::CONFLICT {
            Ok(())
        } else {
            Err(BodyError::Object(format!("create bucket: {status}")))
        }
    }

    fn path(&self, key: &str) -> Result<String, BodyError> {
        if !key_ok(key) {
            return Err(BodyError::Object("malformed object key".to_owned()));
        }
        Ok(format!("/{}/{key}", self.config.bucket))
    }
}

impl ObjectStore for S3Store {
    async fn put(&self, key: &str, bytes: Vec<u8>, now_ms: u64) -> Result<(), BodyError> {
        let path = self.path(key)?;
        let (status, _) = self.call(Method::PUT, path, bytes, now_ms).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(BodyError::Object(format!("put: {status}")))
        }
    }

    async fn get(&self, key: &str, now_ms: u64) -> Result<Vec<u8>, BodyError> {
        let path = self.path(key)?;
        let (status, bytes) = self.call(Method::GET, path, Vec::new(), now_ms).await?;
        if status.is_success() {
            Ok(bytes)
        } else {
            Err(BodyError::Object(format!("get: {status}")))
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
        assert_eq!(
            sha_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let store = S3Store::new(S3Config {
            endpoint: "http://127.0.0.1:7070".to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "work-bodies".to_owned(),
            key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            secret: Secret::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned()),
            tls: None,
        })
        .unwrap();
        let (time, auth) = store
            .authorization(
                &Method::GET,
                "/work-bodies/ab/cd",
                &store.host_header(),
                &sha_hex(b""),
                1_369_353_600_000,
            )
            .unwrap();
        assert_eq!(time, "20130524T000000Z");
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="
        ));
        assert_eq!(store.host_header(), "127.0.0.1:7070");
    }
}
