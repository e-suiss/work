//! Work's SSF push stream (T-103 item 7, T-102 note, Access OP-149 m.17 (e), m.19 (f)): a stream as `platform_streams` shows it, the request that opens it again with every event the stream supports, and what Work does about each status. Work never deletes a stream.

use serde::Deserialize;

use crate::domain::AccessError;
use crate::domain::pairing::is_uuid;

/// The SSF push delivery method (RFC 8935).
pub const PUSH_METHOD: &str = "urn:ietf:rfc:8935";

/// Every event Access's catalog names, asked for when no stream is left to read its
/// `events_supported` from (`platform-streams.json` example).
pub const CATALOG: [&str; 15] = [
    "urn:suiss:access:event:api_client.created",
    "urn:suiss:access:event:api_client.disabled",
    "urn:suiss:access:event:api_client.updated",
    "urn:suiss:access:event:authority-expired",
    "urn:suiss:access:event:authority-narrowed",
    "urn:suiss:access:event:authority-revoked",
    "urn:suiss:access:event:instance-terminated",
    "urn:suiss:access:event:mandate-ended",
    "urn:suiss:access:event:organization.created",
    "urn:suiss:access:event:organization.updated",
    "urn:suiss:access:event:party.compromised",
    "urn:suiss:access:event:party.disabled",
    "urn:suiss:access:event:projection-invalidated",
    "urn:suiss:access:event:revalidation-required",
    "urn:suiss:access:event:tenant.created",
];

/// A stream's status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamStatus {
    /// Delivering.
    Enabled,
    /// Paused; there is no resume endpoint.
    Paused,
    /// Disabled.
    Disabled,
    /// Access stopped delivering after its retries.
    Unreachable,
}

impl StreamStatus {
    /// Access's spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Disabled => "disabled",
            Self::Unreachable => "unreachable",
        }
    }

    fn parse(text: &str) -> Result<Self, AccessError> {
        [
            Self::Enabled,
            Self::Paused,
            Self::Disabled,
            Self::Unreachable,
        ]
        .into_iter()
        .find(|s| s.as_str() == text)
        .ok_or(AccessError::Answer("stream status"))
    }
}

#[derive(Deserialize)]
struct DeliveryWire {
    method: String,
    endpoint_url: Option<String>,
}

#[derive(Deserialize)]
struct StreamWire {
    stream_id: String,
    #[serde(default)]
    events_supported: Vec<String>,
    delivery: DeliveryWire,
    status: String,
}

#[derive(Deserialize)]
struct StreamsWire {
    streams: Vec<StreamWire>,
}

/// One stream of Work's client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    /// The stream id, a canonical lower-case UUID.
    pub id: String,
    /// The status.
    pub status: StreamStatus,
    /// `delivery.method`.
    pub method: String,
    /// `delivery.endpoint_url`.
    pub endpoint: Option<String>,
    /// Every event the transmitter supports.
    pub events_supported: Vec<String>,
}

fn stream(w: StreamWire) -> Result<Stream, AccessError> {
    if !is_uuid(&w.stream_id) {
        return Err(AccessError::Answer("stream_id"));
    }
    Ok(Stream {
        id: w.stream_id,
        status: StreamStatus::parse(&w.status)?,
        method: w.delivery.method,
        endpoint: w.delivery.endpoint_url,
        events_supported: w.events_supported,
    })
}

impl Stream {
    /// Reads one stream.
    ///
    /// # Errors
    /// [`AccessError::Answer`].
    pub fn from_json(body: &[u8]) -> Result<Self, AccessError> {
        stream(serde_json::from_slice(body).map_err(|_| AccessError::Answer("stream"))?)
    }

    /// Reads `GET <platform_streams>`, live first.
    ///
    /// # Errors
    /// [`AccessError::Answer`].
    pub fn list_from_json(body: &[u8]) -> Result<Vec<Self>, AccessError> {
        let w: StreamsWire =
            serde_json::from_slice(body).map_err(|_| AccessError::Answer("streams"))?;
        w.streams.into_iter().map(stream).collect()
    }

    /// Whether it pushes to `receiver`.
    #[must_use]
    pub fn pushes_to(&self, receiver: &str) -> bool {
        self.method == PUSH_METHOD && self.endpoint.as_deref() == Some(receiver)
    }
}

/// The live stream that pushes to `receiver`, the one Work adopts: enabled first, then any
/// other that is not disabled.
#[must_use]
pub fn live<'a>(streams: &'a [Stream], receiver: &str) -> Option<&'a Stream> {
    let pushing = || streams.iter().filter(|s| s.pushes_to(receiver));
    pushing()
        .find(|s| s.status == StreamStatus::Enabled)
        .or_else(|| pushing().find(|s| s.status != StreamStatus::Disabled))
}

/// The events a new stream asks for: what a known stream supports, else Access's catalog.
#[must_use]
pub fn events(streams: &[Stream]) -> Vec<String> {
    streams
        .iter()
        .find(|s| !s.events_supported.is_empty())
        .map_or_else(
            || CATALOG.iter().map(|e| (*e).to_owned()).collect(),
            |s| s.events_supported.clone(),
        )
}

/// The `POST <platform_streams>` body that opens a push stream to `receiver` for `audience`,
/// Work's `client_id`.
#[must_use]
pub fn create_body(receiver: &str, audience: &str, events: &[String]) -> Vec<u8> {
    serde_json::json!({
        "delivery": {"method": PUSH_METHOD, "endpoint_url": receiver},
        "aud": audience,
        "events_requested": events,
    })
    .to_string()
    .into_bytes()
}

/// What Work does about the stream it read (T-103 item 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamCheck {
    /// Enabled; nothing to do.
    Up,
    /// Paused or unreachable: only an operator signal, `work_access_event_stream_up` is 0.
    Down(StreamStatus),
    /// Missing or disabled: Work opens it again.
    Reopen,
}

/// The check of `found`, `None` when Access answered `404 no-such-stream`.
#[must_use]
pub fn check(found: Option<&Stream>) -> StreamCheck {
    match found.map(|s| s.status) {
        Some(StreamStatus::Enabled) => StreamCheck::Up,
        Some(s @ (StreamStatus::Paused | StreamStatus::Unreachable)) => StreamCheck::Down(s),
        Some(StreamStatus::Disabled) | None => StreamCheck::Reopen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str =
        include_str!("../../../../conformance/vectors/access/platform-streams.json");

    // T-103
    #[test]
    fn t_103_a_disabled_stream_is_recreated() {
        let list = Stream::list_from_json(EXAMPLE.as_bytes()).unwrap();
        let mut s = list[0].clone();
        assert_eq!(check(Some(&s)), StreamCheck::Up);
        s.status = StreamStatus::Disabled;
        assert_eq!(check(Some(&s)), StreamCheck::Reopen);
        assert_eq!(check(None), StreamCheck::Reopen);
        s.status = StreamStatus::Paused;
        assert_eq!(check(Some(&s)), StreamCheck::Down(StreamStatus::Paused));
        s.status = StreamStatus::Unreachable;
        assert_eq!(
            check(Some(&s)),
            StreamCheck::Down(StreamStatus::Unreachable)
        );
        let body: serde_json::Value = serde_json::from_slice(&create_body(
            "https://work.example/ssf",
            "cli_w",
            &events(&list),
        ))
        .unwrap();
        assert_eq!(body["delivery"]["method"], PUSH_METHOD);
        assert_eq!(body["delivery"]["endpoint_url"], "https://work.example/ssf");
        assert_eq!(body["aud"], "cli_w");
        assert_eq!(body["events_requested"].as_array().unwrap().len(), 15);
        assert_eq!(events(&[]), CATALOG.map(str::to_owned).to_vec());
    }

    // T-103
    #[test]
    fn t_103_stream_exists_adopts_the_live_stream() {
        let mut list = Stream::list_from_json(EXAMPLE.as_bytes()).unwrap();
        let receiver = "https://work.example/ssf";
        assert_eq!(
            live(&list, receiver).map(|s| s.id.as_str()),
            Some("6f1c2a4e-9b0d-4c3e-8a71-2d5f0e9b4c11")
        );
        assert_eq!(live(&list, "https://other.example/ssf"), None);
        let mut disabled = list[0].clone();
        disabled.id = "6f1c2a4e-9b0d-4c3e-8a71-2d5f0e9b4c00".to_owned();
        disabled.status = StreamStatus::Disabled;
        list.insert(0, disabled);
        list[1].status = StreamStatus::Paused;
        assert_eq!(
            live(&list, receiver).map(|s| s.id.as_str()),
            Some("6f1c2a4e-9b0d-4c3e-8a71-2d5f0e9b4c11")
        );
        list[1].status = StreamStatus::Disabled;
        assert_eq!(live(&list, receiver), None);
        assert!(Stream::from_json(br#"{"stream_id": "x", "delivery": {"method": "urn:ietf:rfc:8935"}, "status": "enabled"}"#).is_err());
        assert!(Stream::from_json(br#"{"stream_id": "6f1c2a4e-9b0d-4c3e-8a71-2d5f0e9b4c11", "delivery": {"method": "urn:ietf:rfc:8935"}, "status": "gone"}"#).is_err());
    }
}
