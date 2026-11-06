//! The Relay event request Work sends (T-99 items 5–7, 10, E-15, Relay E-83): the workflow of the intent's class, the recipients as their pairwise Access `sub`s in Relay's sector, the reason code as the only data, the idempotency key as `dedup_key`, `interruption` from the class (blocking is `time-sensitive`, information `passive`; Work has no `active` or `critical`), and the links: always `primary`, the item's page below Work's installation URI, and `access_approval` at an authority gate; every link is absolute `https` and no `rel` repeats. Fields Relay does not serve yet (`item`, `correlation_id`, Relay A7) and anything of the record's content are never written.

use serde::Serialize;

use crate::domain::intent::{Class, IdempotencyKey, NotificationIntent};

/// The longest link Relay takes.
pub const MAX_HREF: usize = 2048;

/// The workflow of a blocking notification.
pub const BLOCKING_WORKFLOW: &str = "work-action-required";

/// The workflow of an informational notification.
pub const INFORMATIONAL_WORKFLOW: &str = "work-information";

/// The interruption level of a notification (T-99 item 6, Relay CH-65): only the two levels Work
/// sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Interruption {
    /// Blocking notifications.
    TimeSensitive,
    /// Informational notifications.
    Passive,
}

impl Class {
    /// The interruption level of the class (T-99 item 6).
    #[must_use]
    pub const fn interruption(self) -> Interruption {
        match self {
            Self::Blocking => Interruption::TimeSensitive,
            Self::Informational => Interruption::Passive,
        }
    }

    /// The Relay workflow of the class.
    #[must_use]
    pub const fn workflow(self) -> &'static str {
        match self {
            Self::Blocking => BLOCKING_WORKFLOW,
            Self::Informational => INFORMATIONAL_WORKFLOW,
        }
    }
}

/// Why a request cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The installation URI is not an `https` origin.
    #[error("the installation URI is not an https origin")]
    Installation,
    /// A link is not an absolute `https` URI within [`MAX_HREF`].
    #[error("a link is not an absolute https URI")]
    Link,
    /// No recipient resolved.
    #[error("no recipient")]
    Recipients,
}

/// Work's installation URI (P-98): an `https` origin without a trailing slash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installation(String);

impl Installation {
    /// Checks `uri`.
    ///
    /// # Errors
    /// [`RequestError::Installation`].
    pub fn parse(uri: &str) -> Result<Self, RequestError> {
        let host = uri
            .strip_prefix("https://")
            .ok_or(RequestError::Installation)?;
        let clean = !host.is_empty()
            && host.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
            });
        if clean {
            Ok(Self(uri.to_owned()))
        } else {
            Err(RequestError::Installation)
        }
    }

    /// The page of `item` (T-99 item 7).
    #[must_use]
    pub fn open(&self, item: &str) -> String {
        format!("{}/open/{item}", self.0)
    }
}

/// A link relation Work sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rel {
    /// The item's page.
    Primary,
    /// The Access approval page of an authority gate.
    AccessApproval,
}

/// A link of the notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    rel: Rel,
    href: String,
}

/// Whether `href` is an absolute `https` URI Relay takes.
#[must_use]
pub fn is_https(href: &str) -> bool {
    href.len() <= MAX_HREF
        && href
            .strip_prefix("https://")
            .and_then(|rest| rest.split(['/', '?', '#']).next())
            .is_some_and(|host| !host.is_empty())
        && href.bytes().all(|b| b.is_ascii_graphic())
}

impl Link {
    /// A link of `rel` to `href`.
    ///
    /// # Errors
    /// [`RequestError::Link`].
    pub fn new(rel: Rel, href: String) -> Result<Self, RequestError> {
        if is_https(&href) {
            Ok(Self { rel, href })
        } else {
            Err(RequestError::Link)
        }
    }

    /// The relation.
    #[must_use]
    pub const fn rel(&self) -> Rel {
        self.rel
    }

    /// The target.
    #[must_use]
    pub fn href(&self) -> &str {
        &self.href
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Recipient {
    id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Data {
    reason: String,
}

/// The body of one event, `POST /v1/events` (Relay `EventRequest`), or one row of a batch
/// (`BatchEventRequest`, with `ref`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EventRequest {
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    row: Option<String>,
    workflow: &'static str,
    to: Vec<Recipient>,
    data: Data,
    dedup_key: String,
    interruption: Interruption,
    links: Vec<Link>,
    #[serde(skip)]
    key: IdempotencyKey,
}

impl EventRequest {
    /// The request of `intent` to `subs`, the resolved recipients, with the item's page below
    /// `installation`.
    ///
    /// # Errors
    /// [`RequestError`].
    pub fn new(
        intent: &NotificationIntent,
        subs: &[String],
        installation: &Installation,
    ) -> Result<Self, RequestError> {
        if subs.is_empty() {
            return Err(RequestError::Recipients);
        }
        let spec = intent.spec();
        let mut links = vec![Link::new(Rel::Primary, installation.open(&spec.item))?];
        if let Some(approval) = &spec.approval {
            links.push(Link::new(Rel::AccessApproval, approval.clone())?);
        }
        Ok(Self {
            row: None,
            workflow: spec.class.workflow(),
            to: subs.iter().map(|s| Recipient { id: s.clone() }).collect(),
            data: Data {
                reason: spec.reason.clone(),
            },
            dedup_key: intent.key().as_str().to_owned(),
            interruption: spec.class.interruption(),
            links,
            key: intent.key().clone(),
        })
    }

    /// The request as a batch row, its `ref` the idempotency key.
    #[must_use]
    pub fn row(mut self) -> Self {
        self.row = Some(self.key.as_str().to_owned());
        self
    }

    /// The idempotency key.
    #[must_use]
    pub const fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    /// The links.
    #[must_use]
    pub fn links(&self) -> &[Link] {
        &self.links
    }

    /// The JSON body.
    ///
    /// # Errors
    /// [`serde_json::Error`], which a request of these fields never gives.
    pub fn body(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// The body of `POST /v1/events/batch` (Relay `BatchRequest`).
///
/// # Errors
/// [`serde_json::Error`].
pub fn batch_body(rows: &[EventRequest]) -> Result<Vec<u8>, serde_json::Error> {
    #[derive(Serialize)]
    struct Batch<'a> {
        events: &'a [EventRequest],
    }
    serde_json::to_vec(&Batch { events: rows })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::domain::intent::tests::{committed, spec};
    use crate::domain::intent::{Spec, hex};

    fn installation() -> Installation {
        Installation::parse("https://work.example").unwrap()
    }

    fn json(request: &EventRequest) -> Value {
        serde_json::from_slice(&request.body().unwrap()).unwrap()
    }

    fn intent(spec: Spec) -> NotificationIntent {
        NotificationIntent::new(committed(), spec).unwrap()
    }

    // T-99 ST-40
    #[test]
    fn t_99_blocking_is_time_sensitive_and_information_is_passive() {
        let subs = ["sub-1".to_owned()];
        let blocking = EventRequest::new(&intent(spec()), &subs, &installation()).unwrap();
        assert_eq!(json(&blocking)["interruption"], "time-sensitive");
        assert_eq!(json(&blocking)["workflow"], BLOCKING_WORKFLOW);
        let info = Spec {
            class: Class::Informational,
            ..spec()
        };
        let info = EventRequest::new(&intent(info), &subs, &installation()).unwrap();
        assert_eq!(json(&info)["interruption"], "passive");
        assert_eq!(json(&info)["workflow"], INFORMATIONAL_WORKFLOW);
        for class in [Class::Blocking, Class::Informational] {
            let level = serde_json::to_value(class.interruption()).unwrap();
            assert!(level != "critical" && level != "active", "{level}");
        }
    }

    // T-99 X-17
    #[test]
    fn t_99_every_notification_carries_the_primary_link_to_the_item_page() {
        let item = format!("cnd_{}", "ab".repeat(32));
        let request =
            EventRequest::new(&intent(spec()), &["s".to_owned()], &installation()).unwrap();
        assert_eq!(
            json(&request)["links"],
            serde_json::json!([{"rel": "primary", "href": format!("https://work.example/open/{item}")}])
        );
        let gate = Spec {
            approval: Some("https://acme.id.example/v1/approve?request=r".to_owned()),
            ..spec()
        };
        let request = EventRequest::new(&intent(gate), &["s".to_owned()], &installation()).unwrap();
        let rels: Vec<Rel> = request.links().iter().map(Link::rel).collect();
        assert_eq!(rels, [Rel::Primary, Rel::AccessApproval]);
        assert_eq!(json(&request)["links"][1]["rel"], "access_approval");
    }

    // T-99 E-26
    #[test]
    fn t_99_a_link_that_is_not_absolute_https_is_never_sent() {
        for href in [
            "http://acme.id.example/v1/approve",
            "acme://open",
            "/open/x",
            "https://",
            "https:///path",
            "https://acme.example/a b",
        ] {
            assert_eq!(
                Link::new(Rel::AccessApproval, href.to_owned()),
                Err(RequestError::Link),
                "{href}"
            );
        }
        let long = format!("https://a.example/{}", "x".repeat(MAX_HREF));
        assert_eq!(Link::new(Rel::Primary, long), Err(RequestError::Link));
        let gate = Spec {
            approval: Some("http://acme.id.example/v1/approve".to_owned()),
            ..spec()
        };
        assert_eq!(
            EventRequest::new(&intent(gate), &["s".to_owned()], &installation()),
            Err(RequestError::Link)
        );
        assert_eq!(
            Installation::parse("http://work.example"),
            Err(RequestError::Installation)
        );
        assert_eq!(
            Installation::parse("https://work.example/"),
            Err(RequestError::Installation)
        );
    }

    // T-99
    #[test]
    fn t_99_recipients_are_access_subjects() {
        let subs = ["pairwise-1".to_owned(), "pairwise-2".to_owned()];
        let request = EventRequest::new(&intent(spec()), &subs, &installation()).unwrap();
        assert_eq!(
            json(&request)["to"],
            serde_json::json!([{"id": "pairwise-1"}, {"id": "pairwise-2"}])
        );
        assert_eq!(
            EventRequest::new(&intent(spec()), &[], &installation()),
            Err(RequestError::Recipients)
        );
    }

    // E-15 T-99
    #[test]
    fn e_15_the_event_carries_no_record_content_and_no_field_relay_does_not_serve() {
        let gate = Spec {
            approval: Some("https://acme.id.example/v1/approve?request=r".to_owned()),
            ..spec()
        };
        let i = intent(gate);
        let request = EventRequest::new(&i, &["s".to_owned()], &installation()).unwrap();
        let body = json(&request);
        let mut keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "data",
                "dedup_key",
                "interruption",
                "links",
                "to",
                "workflow"
            ]
        );
        assert_eq!(body["data"], serde_json::json!({"reason": "gate_waiting"}));
        assert_eq!(body["dedup_key"], i.key().as_str());
        let text = String::from_utf8(request.body().unwrap()).unwrap();
        for secret in [
            hex(&i.committed().record_id),
            hex(&i.committed().ledger),
            i.spec().parties[0].clone(),
            i.spec().tenant.as_str().to_owned(),
            i.committed().traceparent.clone(),
        ] {
            assert!(!text.contains(&secret), "{secret} in {text}");
        }
        assert!(!text.contains("correlation_id") && !text.contains("\"item\""));
        let row = request.clone().row();
        assert_eq!(json(&row)["ref"], i.key().as_str());
        let batch: Value = serde_json::from_slice(&batch_body(&[row]).unwrap()).unwrap();
        assert_eq!(batch["events"][0]["workflow"], BLOCKING_WORKFLOW);
    }
}
