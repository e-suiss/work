//! The doorbell listener (E-39, RC-42): Work's delivery worker POSTs a content-free `{"ledger", "cursor"}` to the executor's URL after a committed delivery; the bell only wakes the pull loop, which then pulls with its own token, so nothing the bell says is taken as a delivery.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use serde::Deserialize;
use tokio::sync::Notify;

/// What the bell carries; read only to refuse a body that is not the bell.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bell {
    /// The ledger, `led_…`.
    pub(crate) ledger: String,
    /// The sequence number of the delivery, decimal.
    pub(crate) cursor: String,
}

/// Whether `body` is a doorbell for `ledger`.
pub(crate) fn rings(body: &[u8], ledger: &str) -> bool {
    serde_json::from_slice::<Bell>(body).is_ok_and(|b| {
        b.ledger == ledger && !b.cursor.is_empty() && b.cursor.bytes().all(|c| c.is_ascii_digit())
    })
}

#[derive(Clone)]
struct Bells {
    notify: Arc<Notify>,
    ledger: String,
}

async fn ring(State(bells): State<Bells>, body: axum::body::Bytes) -> StatusCode {
    if rings(&body, &bells.ledger) {
        bells.notify.notify_one();
        StatusCode::NO_CONTENT
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// Serves the bell on `listen` for `ledger` until the process ends.
pub(crate) async fn serve(
    listen: &str,
    ledger: String,
    notify: Arc<Notify>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let app = Router::new()
        .route("/", post(ring))
        .route("/doorbell", post(ring))
        .with_state(Bells { notify, ledger });
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // E-39 RC-42 T-105
    #[test]
    fn e_39_the_doorbell_is_content_free_and_only_wakes_the_pull() {
        assert!(rings(br#"{"ledger":"led_a","cursor":"17"}"#, "led_a"));
        assert!(!rings(br#"{"ledger":"led_b","cursor":"17"}"#, "led_a"));
        assert!(!rings(br#"{"ledger":"led_a","cursor":"x"}"#, "led_a"));
        assert!(!rings(
            br#"{"ledger":"led_a","cursor":"1","body":"oA"}"#,
            "led_a"
        ));
        assert!(!rings(b"not json", "led_a"));
    }
}
