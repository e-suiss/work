//! Work's one event entry, `POST /v1/inbound/events` (T-102 item 2, T-100 item 1): the route reads at most [`MAX_EVENT_BYTES`] and hands the `Content-Type`, the Suiss webhook profile headers (P-36) and the bytes as received to the [`Receiver`], which picks the verifier and answers. It is a receiver for Access's SSF push (RFC 8935) and Relay's events, not an operation of the REST family: its answers are the receivers' own, and it carries no caller identity, since the signature of each event is its authentication.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

/// The path of the entry.
pub const PATH: &str = "/v1/inbound/events";

/// The largest event body the route reads.
pub const MAX_EVENT_BYTES: usize = 65_536;

/// What a receiver answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The body; a non-empty one is `application/json`.
    pub body: Vec<u8>,
}

/// A boxed answer future.
pub type Answering = Pin<Box<dyn Future<Output = Answer> + Send>>;

/// The header that names a delivery of the Suiss webhook profile.
pub const WEBHOOK_ID: &str = "webhook-id";

/// The header with the Unix seconds a delivery was signed at.
pub const WEBHOOK_TIMESTAMP: &str = "webhook-timestamp";

/// The header with the signatures of a delivery.
pub const WEBHOOK_SIGNATURE: &str = "webhook-signature";

/// The Suiss webhook profile headers of a request as received (P-36, T-100 item 4): each is
/// `None` when the request does not carry it once as visible ASCII.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WebhookHeaders {
    /// `webhook-id`.
    pub id: Option<String>,
    /// `webhook-timestamp`.
    pub timestamp: Option<String>,
    /// `webhook-signature`.
    pub signature: Option<String>,
}

/// What takes an event: the `Content-Type` alone picks its verifier.
pub trait Receiver: Send + Sync + 'static {
    /// Takes one event.
    fn receive(&self, content_type: Option<String>, body: Bytes) -> Answering;

    /// Takes one event with the webhook profile headers of its request; a receiver whose events
    /// carry their own signature takes it as [`Receiver::receive`].
    fn receive_signed(
        &self,
        content_type: Option<String>,
        headers: WebhookHeaders,
        body: Bytes,
    ) -> Answering {
        drop(headers);
        self.receive(content_type, body)
    }
}

fn once(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then(|| value.to_owned())
}

fn answer(a: Answer) -> Response {
    let status = StatusCode::from_u16(a.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if a.body.is_empty() {
        return status.into_response();
    }
    let json = HeaderValue::from_static("application/json");
    (status, [(header::CONTENT_TYPE, json)], a.body).into_response()
}

fn too_large() -> Response {
    let body = br#"{"err":"invalid_request","description":"the event is too large"}"#;
    answer(Answer {
        status: 413,
        body: body.to_vec(),
    })
}

async fn events(State(receiver): State<Arc<dyn Receiver>>, request: Request) -> Response {
    let (parts, body): (_, Body) = request.into_parts();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_EVENT_BYTES)
    {
        return too_large();
    }
    let headers = WebhookHeaders {
        id: once(&parts.headers, WEBHOOK_ID),
        timestamp: once(&parts.headers, WEBHOOK_TIMESTAMP),
        signature: once(&parts.headers, WEBHOOK_SIGNATURE),
    };
    let Ok(bytes) = to_bytes(body, MAX_EVENT_BYTES).await else {
        return too_large();
    };
    answer(receiver.receive_signed(content_type, headers, bytes).await)
}

/// The entry alone, for the listener it is served on.
pub fn router(receiver: Arc<dyn Receiver>) -> Router {
    Router::new()
        .route(PATH, post(events))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(receiver)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::http::Method;
    use tower_service::Service as _;

    use super::*;

    #[derive(Default)]
    struct Seen(Mutex<Vec<(Option<String>, Vec<u8>)>>);

    impl Receiver for Seen {
        fn receive(&self, content_type: Option<String>, body: Bytes) -> Answering {
            self.0.lock().unwrap().push((content_type, body.to_vec()));
            Box::pin(async {
                Answer {
                    status: 202,
                    body: Vec::new(),
                }
            })
        }
    }

    fn post_request(path: &str, content_type: &str, body: Vec<u8>) -> Request {
        let mut request = Request::new(Body::from(body));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = path.parse().unwrap();
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
        request
    }

    // T-102
    #[tokio::test]
    async fn t_102_the_entry_hands_the_media_type_and_bytes_as_received() {
        let seen = Arc::new(Seen::default());
        let mut router = super::router(seen.clone());
        let response = router
            .call(post_request(
                PATH,
                "application/secevent+jwt",
                b"a.b.c".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            seen.0.lock().unwrap().as_slice(),
            [(
                Some("application/secevent+jwt".to_owned()),
                b"a.b.c".to_vec()
            )]
        );
        let large = vec![b'a'; MAX_EVENT_BYTES.saturating_add(1)];
        let response = router
            .call(post_request(PATH, "application/secevent+jwt", large))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let response = router
            .call(post_request(
                "/v1/problems/busy",
                "application/json",
                Vec::new(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let mut get = Request::new(Body::empty());
        *get.uri_mut() = PATH.parse().unwrap();
        let response = router.call(get).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(seen.0.lock().unwrap().len(), 1);
    }

    #[derive(Default)]
    struct Signed(Mutex<Vec<(WebhookHeaders, Vec<u8>)>>);

    impl Receiver for Signed {
        fn receive(&self, _content_type: Option<String>, _body: Bytes) -> Answering {
            Box::pin(async {
                Answer {
                    status: 401,
                    body: Vec::new(),
                }
            })
        }

        fn receive_signed(
            &self,
            _content_type: Option<String>,
            headers: WebhookHeaders,
            body: Bytes,
        ) -> Answering {
            self.0.lock().unwrap().push((headers, body.to_vec()));
            Box::pin(async {
                Answer {
                    status: 204,
                    body: Vec::new(),
                }
            })
        }
    }

    // T-100 P-36
    #[tokio::test]
    async fn t_100_the_entry_hands_the_webhook_profile_headers_as_received() {
        let seen = Arc::new(Signed::default());
        let mut router = super::router(seen.clone());
        let mut signed = post_request(PATH, "application/cloudevents+json", b"{}".to_vec());
        for (name, value) in [
            (WEBHOOK_ID, "evt_1"),
            (WEBHOOK_TIMESTAMP, "1793000000"),
            (WEBHOOK_SIGNATURE, "v1a,AAAA v1a,BBBB"),
        ] {
            signed
                .headers_mut()
                .insert(name, HeaderValue::from_static(value));
        }
        let response = router.call(signed).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let mut twice = post_request(PATH, "application/cloudevents+json", b"{}".to_vec());
        twice
            .headers_mut()
            .append(WEBHOOK_ID, HeaderValue::from_static("evt_1"));
        twice
            .headers_mut()
            .append(WEBHOOK_ID, HeaderValue::from_static("evt_2"));
        router.call(twice).await.unwrap();
        let bare = post_request(PATH, "application/cloudevents+json", b"{}".to_vec());
        router.call(bare).await.unwrap();
        let seen = seen.0.lock().unwrap();
        assert_eq!(
            seen[0],
            (
                WebhookHeaders {
                    id: Some("evt_1".to_owned()),
                    timestamp: Some("1793000000".to_owned()),
                    signature: Some("v1a,AAAA v1a,BBBB".to_owned()),
                },
                b"{}".to_vec()
            )
        );
        assert_eq!(seen[1].0, WebhookHeaders::default());
        assert_eq!(seen[2].0, WebhookHeaders::default());
    }
}
