//! Relay's events at Work's entry (T-100 items 4–6, P-114, P-36; Relay E-84 … E-89): the Suiss webhook profile headers, whose `v1a` Ed25519 signatures over `id.timestamp.body` are tried under every product event key of Relay's `jwks_uri` while an HMAC `v1` entry counts for nothing; the CloudEvents envelope, whose `source` must be the discovery `issuer` and whose `accesstenant` names the tenant; and what an event may become. A time or delivery event is written only by the tenant's Work service Party and only with a prior Declaration; a `waitpoint.resolved` answer belongs to its responder alone, and only with an Access context (`relay_session`, `access_aas_ref`); an engagement event, a `waitpoint.created` or an unknown type becomes nothing. Relay is never an author.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Deserialize;
use suiss_crypto::sig::{PureBackend, ed25519};
use work_proto::id::TenantId;

/// The media type of a Relay event (T-100 item 1).
pub const CONTENT_TYPE: &str = "application/cloudevents+json";

/// How far `webhook-timestamp` may lie from now, seconds (P-36).
pub const TOLERANCE_S: u64 = 300;

/// The most keys read from a key set: a rotation holds two.
pub const MAX_KEYS: usize = 8;

/// The prefix of an Ed25519 entry of `webhook-signature`.
const V1A: &str = "v1a,";

/// The Suiss webhook profile headers of one delivery (P-36).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Webhook {
    /// `webhook-id`.
    pub id: String,
    /// `webhook-timestamp`, Unix seconds.
    pub timestamp: String,
    /// `webhook-signature`, entries separated by spaces.
    pub signature: String,
}

/// Why an event is not taken; it becomes no record and is only a log line (P-114 item 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// A profile header is missing or empty.
    #[error("a webhook profile header is missing")]
    Headers,
    /// `webhook-timestamp` is not Unix seconds within the tolerance.
    #[error("the webhook timestamp is outside the tolerance")]
    Timestamp,
    /// No `v1a` signature verifies under a key of the key set.
    #[error("the signature verifies under none of the product event keys")]
    Signature,
    /// `source` is not Relay's issuer.
    #[error("the source is not the Relay issuer")]
    Source,
    /// The body is not a CloudEvents 1.0 event whose `id` is `webhook-id`.
    #[error("the body is not the CloudEvents event the headers name")]
    Envelope,
    /// `accesstenant` is missing or not an Access tenant id.
    #[error("the event does not name its Access tenant")]
    Tenant,
}

impl Refusal {
    /// The answer: `401` while the event is not authenticated, `400` for an authenticated one
    /// Work cannot read (T-100 item 1).
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Headers | Self::Timestamp | Self::Signature | Self::Source => 401,
            Self::Envelope | Self::Tenant => 400,
        }
    }

    /// The stable code of the log line.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Headers => "headers",
            Self::Timestamp => "timestamp",
            Self::Signature => "signature",
            Self::Source => "source",
            Self::Envelope => "envelope",
            Self::Tenant => "tenant",
        }
    }
}

/// The key set document is not a JWK set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the product event key set is not a JWK set of Ed25519 keys")]
pub struct KeysError;

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default, rename = "use")]
    usage: Option<String>,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// The product event keys of Relay's `jwks_uri` (Relay E-89): `kty: OKP`, `crv: Ed25519`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeySet(Vec<[u8; 32]>);

impl KeySet {
    /// Reads the key set document; keys of another kind or use are left out.
    ///
    /// # Errors
    /// [`KeysError`] for a document that is not a JWK set, an Ed25519 key without its 32 bytes,
    /// or more than [`MAX_KEYS`] keys.
    pub fn from_jwks(body: &[u8]) -> Result<Self, KeysError> {
        let set: Jwks = serde_json::from_slice(body).map_err(|_| KeysError)?;
        let mut keys = Vec::new();
        for jwk in set.keys {
            let signs = jwk.usage.as_deref().is_none_or(|u| u == "sig");
            if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") || !signs {
                continue;
            }
            let x = jwk.x.ok_or(KeysError)?;
            let bytes = URL_SAFE_NO_PAD.decode(x).map_err(|_| KeysError)?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| KeysError)?;
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        if keys.len() > MAX_KEYS {
            return Err(KeysError);
        }
        Ok(Self(keys))
    }

    /// How many keys the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether one `v1a` entry of the signature header verifies `body` under one key of the set
    /// (T-100 item 4): during a rotation the header carries two signatures and the set two keys.
    #[must_use]
    pub fn verifies(&self, webhook: &Webhook, body: &[u8]) -> bool {
        let mut message = Vec::with_capacity(
            webhook
                .id
                .len()
                .saturating_add(webhook.timestamp.len())
                .saturating_add(body.len())
                .saturating_add(2),
        );
        message.extend_from_slice(webhook.id.as_bytes());
        message.push(b'.');
        message.extend_from_slice(webhook.timestamp.as_bytes());
        message.push(b'.');
        message.extend_from_slice(body);
        webhook
            .signature
            .split(' ')
            .filter_map(|entry| entry.strip_prefix(V1A))
            .filter_map(|text| STANDARD.decode(text).ok())
            .any(|signature| {
                self.0
                    .iter()
                    .any(|key| ed25519(&PureBackend, key, &message, &signature).is_ok())
            })
    }
}

/// Checks the profile headers before any key is tried: all three present, and the timestamp
/// within [`TOLERANCE_S`] of `now_ms`.
///
/// # Errors
/// [`Refusal::Headers`], [`Refusal::Timestamp`].
pub fn timely(webhook: &Webhook, now_ms: u64) -> Result<(), Refusal> {
    if webhook.id.is_empty() || webhook.timestamp.is_empty() || webhook.signature.is_empty() {
        return Err(Refusal::Headers);
    }
    let digits =
        webhook.timestamp.len() <= 12 && webhook.timestamp.bytes().all(|b| b.is_ascii_digit());
    let at_s: u64 = webhook
        .timestamp
        .parse()
        .ok()
        .filter(|_| digits)
        .ok_or(Refusal::Timestamp)?;
    if at_s.abs_diff(now_ms / 1000) > TOLERANCE_S {
        return Err(Refusal::Timestamp);
    }
    Ok(())
}

/// The Access context Relay verified a responder under (Relay E-86, WD-103 item 9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// `relay_session`: Relay's session object, the record's `auth_context`.
    RelaySession {
        /// The assurance level copied from the Access token.
        aal: String,
        /// When the responder authenticated, RFC 3339.
        auth_time: String,
        /// The digest of the subscriber token's `jti`.
        subscriber_token_digest: String,
    },
    /// `access_aas_ref`: the Access decision the record rests on.
    AccessDecision(String),
}

/// Why an answer is nobody's record (P-114 item 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unattributable {
    /// `channel_claim`: the channel alone says who answered.
    ChannelClaim,
    /// The responder is not a subscriber with an Access `sub`.
    Responder,
    /// The Access context or the response digest is missing.
    Context,
    /// Access knows no Party for the responder's `sub`.
    Unresolved,
}

impl Unattributable {
    /// The stable code of the attention signal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ChannelClaim => "channel_claim",
            Self::Responder => "responder",
            Self::Context => "context",
            Self::Unresolved => "unresolved",
        }
    }
}

/// A `waitpoint.resolved` answer with an Access context (T-100 item 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The waitpoint, `wp_…`: the value is read there and never from the event.
    pub waitpoint_id: String,
    /// The responder's pairwise Access `sub` in Relay's sector.
    pub sub: String,
    /// The context.
    pub evidence: Evidence,
    /// `sha256:` digest of the RFC 8785 form of the response value.
    pub response_digest: String,
}

/// What an event of a type may become (T-100 item 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A time or delivery event: a record of the tenant's Work service Party, only with a prior
    /// Declaration as its basis (P-114 item 2).
    Automation,
    /// A responder's answer (P-114 item 3).
    Response(Result<Answer, Unattributable>),
    /// `seen`, `read`, `archived`, `clicked`: never a record and never an acknowledgement.
    Engagement,
    /// Anything else: only its deduplication row.
    Other,
}

/// The event types of P-114 item 2.
pub const AUTOMATION_TYPES: [&str; 9] = [
    "agent.ceiling_exceeded",
    "delivery.status_changed",
    "notification.delivered",
    "notification.expired",
    "notification.failed",
    "waitpoint.cancelled",
    "waitpoint.escalated",
    "waitpoint.expired",
    "waitpoint.stalled",
];

/// The engagement event types.
pub const ENGAGEMENT_TYPES: [&str; 4] = [
    "notification.archived",
    "notification.clicked",
    "notification.read",
    "notification.seen",
];

/// The type of a responder's answer.
pub const RESPONSE_TYPE: &str = "waitpoint.resolved";

#[derive(Deserialize)]
struct SessionWire {
    aal: String,
    auth_time: String,
    subscriber_token_digest: String,
}

#[derive(Deserialize)]
struct ResponderWire {
    kind: String,
    #[serde(default)]
    external_id: Option<String>,
}

#[derive(Deserialize)]
struct AnswerWire {
    waitpoint_id: String,
    #[serde(default)]
    responder: Option<ResponderWire>,
    #[serde(default)]
    evidence_level: Option<String>,
    #[serde(default)]
    response_digest: Option<String>,
    #[serde(default)]
    session: Option<SessionWire>,
    #[serde(default)]
    access_decision_ref: Option<String>,
}

fn is_sha256(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn answer(data: Option<serde_json::Value>) -> Result<Answer, Unattributable> {
    let wire: AnswerWire = data
        .and_then(|d| serde_json::from_value(d).ok())
        .ok_or(Unattributable::Context)?;
    let sub = wire
        .responder
        .filter(|r| r.kind == "subscriber")
        .and_then(|r| r.external_id)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or(Unattributable::Responder)?;
    let evidence = match wire.evidence_level.as_deref() {
        Some("relay_session") => {
            let s = wire.session.ok_or(Unattributable::Context)?;
            if s.aal.is_empty() || s.auth_time.is_empty() || !is_sha256(&s.subscriber_token_digest)
            {
                return Err(Unattributable::Context);
            }
            Evidence::RelaySession {
                aal: s.aal,
                auth_time: s.auth_time,
                subscriber_token_digest: s.subscriber_token_digest,
            }
        }
        Some("access_aas_ref") => Evidence::AccessDecision(
            wire.access_decision_ref
                .filter(|r| !r.is_empty() && r.len() <= 256)
                .ok_or(Unattributable::Context)?,
        ),
        Some("channel_claim") => return Err(Unattributable::ChannelClaim),
        _ => return Err(Unattributable::Context),
    };
    let response_digest = wire
        .response_digest
        .filter(|d| is_sha256(d))
        .ok_or(Unattributable::Context)?;
    Ok(Answer {
        waitpoint_id: wire.waitpoint_id,
        sub,
        evidence,
        response_digest,
    })
}

#[derive(Deserialize)]
struct Envelope {
    specversion: String,
    id: String,
    source: String,
    #[serde(rename = "type")]
    name: String,
    #[serde(default)]
    accesstenant: Option<String>,
    #[serde(default)]
    accessorganization: Option<String>,
    #[serde(default)]
    correlationid: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

/// A Relay event whose signature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// `id`, equal to `webhook-id`: with the tenant and the source its deduplication key.
    pub id: String,
    /// `source`: Relay's issuer.
    pub source: String,
    /// `type`.
    pub name: String,
    /// `accesstenant`.
    pub tenant: TenantId,
    /// `accessorganization`, when the event has one.
    pub organization: Option<String>,
    /// `correlationid`: the id of the record Work sent with the intent (T-99 item 7).
    pub correlation_id: Option<String>,
    /// What it may become.
    pub kind: Kind,
}

impl Event {
    /// Reads the body of a delivery whose signature verified (T-100 item 4): a CloudEvents 1.0
    /// event whose `id` is `webhook-id`, whose `source` is `issuer` and which names its tenant.
    ///
    /// # Errors
    /// [`Refusal::Envelope`], [`Refusal::Source`], [`Refusal::Tenant`].
    pub fn read(body: &[u8], webhook: &Webhook, issuer: &str) -> Result<Self, Refusal> {
        let e: Envelope = serde_json::from_slice(body).map_err(|_| Refusal::Envelope)?;
        if e.specversion != "1.0" || e.id != webhook.id || e.id.len() > 512 || e.name.is_empty() {
            return Err(Refusal::Envelope);
        }
        if e.source != issuer {
            return Err(Refusal::Source);
        }
        let tenant = e
            .accesstenant
            .filter(|t| t.len() <= 256)
            .and_then(|t| TenantId::new(&t))
            .ok_or(Refusal::Tenant)?;
        let kind = if e.name == RESPONSE_TYPE {
            Kind::Response(answer(e.data))
        } else if AUTOMATION_TYPES.contains(&e.name.as_str()) {
            Kind::Automation
        } else if ENGAGEMENT_TYPES.contains(&e.name.as_str()) {
            Kind::Engagement
        } else {
            Kind::Other
        };
        Ok(Self {
            id: e.id,
            source: e.source,
            name: e.name,
            tenant,
            organization: e.accessorganization,
            correlation_id: e.correlationid,
            kind,
        })
    }
}

/// Whose record an event may become (P-114): never Relay's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// The tenant's Work service Party (`origin = automation`), and only with a prior Declaration
    /// as the basis; without one nothing is written (P-114 item 2).
    ServiceParty,
    /// The responder's Party, as an `observation` Claim with the context as `auth_context`
    /// (P-114 item 3).
    Responder {
        /// The responder's base64url `PartyID`.
        party: String,
        /// The answer.
        answer: Answer,
    },
    /// An answer nobody is the author of: no record, an attention signal.
    Unattributed(Unattributable),
    /// No record: an engagement event, `waitpoint.created` or an unknown type.
    Nothing,
}

impl Attribution {
    /// The stable code of the log line.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ServiceParty => "service_party",
            Self::Responder { .. } => "responder",
            Self::Unattributed(_) => "unattributed",
            Self::Nothing => "nothing",
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test code")]
pub(crate) mod tests {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::ed25519::signature::Signer as _;
    use serde_json::json;

    use super::*;

    pub(crate) const ISSUER: &str = "https://relay.example";
    pub(crate) const NOW_MS: u64 = 1_793_000_000_000;

    pub(crate) fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn jwks(keys: &[&SigningKey]) -> Vec<u8> {
        let keys: Vec<serde_json::Value> = keys
            .iter()
            .map(|k| {
                json!({
                    "kty": "OKP", "crv": "Ed25519", "use": "sig", "kid": "k",
                    "x": URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes()),
                })
            })
            .collect();
        json!({ "keys": keys }).to_string().into_bytes()
    }

    pub(crate) fn body(name: &str, id: &str, data: &serde_json::Value) -> Vec<u8> {
        json!({
            "specversion": "1.0", "id": id, "source": ISSUER, "type": name,
            "time": "2026-11-12T10:00:00Z", "datacontenttype": "application/json",
            "accesstenant": "tnt_acme", "correlationid": "ab".repeat(32), "data": data,
        })
        .to_string()
        .into_bytes()
    }

    pub(crate) fn signed(keys: &[&SigningKey], id: &str, at_ms: u64, body: &[u8]) -> Webhook {
        let timestamp = (at_ms / 1000).to_string();
        let mut message = format!("{id}.{timestamp}.").into_bytes();
        message.extend_from_slice(body);
        let signature = keys
            .iter()
            .map(|k| format!("v1a,{}", STANDARD.encode(k.sign(&message).to_bytes())))
            .collect::<Vec<_>>()
            .join(" ");
        Webhook {
            id: id.to_owned(),
            timestamp,
            signature,
        }
    }

    pub(crate) fn resolved(level: &str) -> serde_json::Value {
        json!({
            "waitpoint_id": "wp_01", "kind": "question",
            "responder": {"recipient_id": "rcp_1", "kind": "subscriber", "external_id": "sub-1"},
            "evidence_level": level,
            "response_digest": format!("sha256:{}", "cd".repeat(32)),
            "session": {
                "aal": "aal2", "auth_time": "2026-11-12T09:59:00Z",
                "subscriber_token_digest": format!("sha256:{}", "ef".repeat(32)),
            },
            "access_decision_ref": "dec_1",
        })
    }

    // T-100 P-36
    #[test]
    fn t_100_a_relay_event_signed_by_a_jwks_key_is_accepted() {
        let k = key(7);
        let set = KeySet::from_jwks(&jwks(&[&k])).unwrap();
        assert_eq!(set.len(), 1);
        let body = body("notification.delivered", "evt_1", &json!({}));
        let webhook = signed(&[&k], "evt_1", NOW_MS, &body);
        assert_eq!(timely(&webhook, NOW_MS), Ok(()));
        assert!(set.verifies(&webhook, &body));
        let event = Event::read(&body, &webhook, ISSUER).unwrap();
        assert_eq!(event.tenant.as_str(), "tnt_acme");
        assert_eq!(event.kind, Kind::Automation);
        assert_eq!(event.correlation_id, Some("ab".repeat(32)));
    }

    // T-100 P-114
    #[test]
    fn t_100_a_tampered_body_or_signature_verifies_under_no_key() {
        let k = key(7);
        let set = KeySet::from_jwks(&jwks(&[&k])).unwrap();
        let body = body("notification.delivered", "evt_1", &json!({}));
        let webhook = signed(&[&k], "evt_1", NOW_MS, &body);
        let mut other = body.clone();
        other.push(b' ');
        assert!(!set.verifies(&webhook, &other));
        let moved = Webhook {
            id: "evt_2".to_owned(),
            ..webhook.clone()
        };
        assert!(!set.verifies(&moved, &body));
        let later = Webhook {
            timestamp: (NOW_MS / 1000 + 1).to_string(),
            ..webhook.clone()
        };
        assert!(!set.verifies(&later, &body));
        let stranger = signed(&[&key(8)], "evt_1", NOW_MS, &body);
        assert!(!set.verifies(&stranger, &body));
        assert!(!KeySet::default().verifies(&webhook, &body));
    }

    // T-100 T-102
    #[test]
    fn t_100_an_hmac_entry_is_never_a_signature() {
        let k = key(7);
        let set = KeySet::from_jwks(&jwks(&[&k])).unwrap();
        let body = body("notification.delivered", "evt_1", &json!({}));
        let webhook = signed(&[&k], "evt_1", NOW_MS, &body);
        let raw = webhook.signature.strip_prefix("v1a,").unwrap().to_owned();
        for signature in [format!("v1,{raw}"), raw.clone(), format!("v1a,{raw}x")] {
            let w = Webhook {
                signature,
                ..webhook.clone()
            };
            assert!(!set.verifies(&w, &body), "{w:?}");
        }
        let both = Webhook {
            signature: format!("v1,AAAA v1a,{raw}"),
            ..webhook
        };
        assert!(set.verifies(&both, &body));
    }

    // T-100
    #[test]
    fn t_100_during_a_rotation_either_key_of_the_set_verifies() {
        let (old, new) = (key(7), key(8));
        let body = body("waitpoint.expired", "evt_1", &json!({}));
        let two = signed(&[&old, &new], "evt_1", NOW_MS, &body);
        for held in [vec![&old], vec![&new], vec![&old, &new]] {
            assert!(
                KeySet::from_jwks(&jwks(&held))
                    .unwrap()
                    .verifies(&two, &body)
            );
        }
        let one = signed(&[&new], "evt_1", NOW_MS, &body);
        assert!(
            !KeySet::from_jwks(&jwks(&[&old]))
                .unwrap()
                .verifies(&one, &body)
        );
        assert!(
            KeySet::from_jwks(&jwks(&[&old, &new]))
                .unwrap()
                .verifies(&one, &body)
        );
    }

    // T-100
    #[test]
    fn t_100_the_key_set_holds_only_ed25519_signing_keys() {
        let k = key(7);
        let x = URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes());
        let mixed = json!({"keys": [
            {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"},
            {"kty": "OKP", "crv": "X25519", "x": x},
            {"kty": "OKP", "crv": "Ed25519", "use": "enc", "x": x},
            {"kty": "OKP", "crv": "Ed25519", "x": x},
            {"kty": "OKP", "crv": "Ed25519", "use": "sig", "x": x},
        ]});
        assert_eq!(
            KeySet::from_jwks(mixed.to_string().as_bytes())
                .unwrap()
                .len(),
            1
        );
        assert!(KeySet::from_jwks(br#"{"keys":[]}"#).unwrap().is_empty());
        for bad in [
            json!({"keys": [{"kty": "OKP", "crv": "Ed25519"}]}),
            json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "AA"}]}),
            json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "!!"}]}),
            json!({"key": []}),
        ] {
            assert_eq!(
                KeySet::from_jwks(bad.to_string().as_bytes()),
                Err(KeysError)
            );
        }
        let many: Vec<serde_json::Value> = (0..=u8::try_from(MAX_KEYS).unwrap())
            .map(|n| {
                let x = URL_SAFE_NO_PAD.encode(key(n + 1).verifying_key().to_bytes());
                json!({"kty": "OKP", "crv": "Ed25519", "x": x})
            })
            .collect();
        assert_eq!(
            KeySet::from_jwks(json!({ "keys": many }).to_string().as_bytes()),
            Err(KeysError)
        );
    }

    // T-100 P-36
    #[test]
    fn t_100_the_timestamp_lies_within_the_profile_tolerance() {
        let w = |timestamp: &str| Webhook {
            id: "evt_1".to_owned(),
            timestamp: timestamp.to_owned(),
            signature: "v1a,AA".to_owned(),
        };
        let now_s = NOW_MS / 1000;
        for inside in [now_s, now_s - TOLERANCE_S, now_s + TOLERANCE_S] {
            assert_eq!(timely(&w(&inside.to_string()), NOW_MS), Ok(()));
        }
        for outside in [now_s - TOLERANCE_S - 1, now_s + TOLERANCE_S + 1, 0] {
            assert_eq!(
                timely(&w(&outside.to_string()), NOW_MS),
                Err(Refusal::Timestamp)
            );
        }
        for bad in ["+1793000000", "1793000000.5", "now", "17930000000000000"] {
            assert_eq!(timely(&w(bad), NOW_MS), Err(Refusal::Timestamp), "{bad}");
        }
        assert_eq!(timely(&w(""), NOW_MS), Err(Refusal::Headers));
        let unsigned = Webhook {
            signature: String::new(),
            ..w(&now_s.to_string())
        };
        assert_eq!(timely(&unsigned, NOW_MS), Err(Refusal::Headers));
        assert_eq!(Refusal::Headers.status(), 401);
        assert_eq!(Refusal::Timestamp.status(), 401);
        assert_eq!(Refusal::Signature.status(), 401);
    }

    // T-100 P-114
    #[test]
    fn t_100_an_event_whose_source_is_not_the_relay_issuer_becomes_no_record() {
        let k = key(7);
        let body = body("waitpoint.expired", "evt_1", &json!({}));
        let webhook = signed(&[&k], "evt_1", NOW_MS, &body);
        assert_eq!(
            Event::read(&body, &webhook, "https://other.example"),
            Err(Refusal::Source)
        );
        assert_eq!(
            Event::read(&body, &webhook, "https://relay.example/"),
            Err(Refusal::Source)
        );
        assert_eq!(Refusal::Source.status(), 401);
        assert!(Event::read(&body, &webhook, ISSUER).is_ok());
    }

    // T-100 P-35
    #[test]
    fn t_100_the_event_names_its_tenant_and_the_id_its_headers_carry() {
        let webhook = Webhook {
            id: "evt_1".to_owned(),
            timestamp: "1".to_owned(),
            signature: "v1a,AA".to_owned(),
        };
        let other_id = body("waitpoint.expired", "evt_2", &json!({}));
        assert_eq!(
            Event::read(&other_id, &webhook, ISSUER),
            Err(Refusal::Envelope)
        );
        let event = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut v: serde_json::Value =
                serde_json::from_slice(&body("waitpoint.expired", "evt_1", &json!({}))).unwrap();
            change(&mut v);
            Event::read(v.to_string().as_bytes(), &webhook, ISSUER)
        };
        assert_eq!(
            event(&|v| v["specversion"] = json!("0.3")),
            Err(Refusal::Envelope)
        );
        assert_eq!(
            event(&|v| {
                v.as_object_mut().unwrap().remove("accesstenant");
            }),
            Err(Refusal::Tenant)
        );
        assert_eq!(
            event(&|v| v["accesstenant"] = json!("")),
            Err(Refusal::Tenant)
        );
        assert_eq!(
            Event::read(b"not json", &webhook, ISSUER),
            Err(Refusal::Envelope)
        );
        assert_eq!(Refusal::Envelope.status(), 400);
        let with_org = event(&|v| v["accessorganization"] = json!("org_1")).unwrap();
        assert_eq!(with_org.organization.as_deref(), Some("org_1"));
        assert_eq!(event(&|_| ()).unwrap().organization, None);
    }

    // T-100 P-114 E-22
    #[test]
    fn t_100_engagement_events_write_no_record() {
        let webhook = Webhook {
            id: "evt_1".to_owned(),
            timestamp: "1".to_owned(),
            signature: "v1a,AA".to_owned(),
        };
        let kind = |name: &str| {
            Event::read(&body(name, "evt_1", &json!({})), &webhook, ISSUER)
                .unwrap()
                .kind
        };
        for name in ENGAGEMENT_TYPES {
            assert_eq!(kind(name), Kind::Engagement, "{name}");
        }
        for name in AUTOMATION_TYPES {
            assert_eq!(kind(name), Kind::Automation, "{name}");
        }
        for name in [
            "waitpoint.created",
            "waitpoint.response_rejected",
            "campaign.completed",
            "notification.acknowledged",
        ] {
            assert_eq!(kind(name), Kind::Other, "{name}");
        }
    }

    // T-100 P-114
    #[test]
    fn t_100_a_channel_claim_response_is_not_attributed() {
        let webhook = Webhook {
            id: "evt_1".to_owned(),
            timestamp: "1".to_owned(),
            signature: "v1a,AA".to_owned(),
        };
        let kind = |data: &serde_json::Value| {
            Event::read(&body(RESPONSE_TYPE, "evt_1", data), &webhook, ISSUER)
                .unwrap()
                .kind
        };
        assert_eq!(
            kind(&resolved("channel_claim")),
            Kind::Response(Err(Unattributable::ChannelClaim))
        );
        let Kind::Response(Ok(session)) = kind(&resolved("relay_session")) else {
            panic!("a relay_session answer");
        };
        assert_eq!(session.sub, "sub-1");
        assert_eq!(session.waitpoint_id, "wp_01");
        assert!(matches!(
            session.evidence,
            Evidence::RelaySession { ref aal, .. } if aal == "aal2"
        ));
        let Kind::Response(Ok(decision)) = kind(&resolved("access_aas_ref")) else {
            panic!("an access_aas_ref answer");
        };
        assert_eq!(
            decision.evidence,
            Evidence::AccessDecision("dec_1".to_owned())
        );
        let mut agent = resolved("relay_session");
        agent["responder"]["kind"] = json!("agent");
        assert_eq!(kind(&agent), Kind::Response(Err(Unattributable::Responder)));
        let mut bare = resolved("relay_session");
        bare.as_object_mut().unwrap().remove("session");
        assert_eq!(kind(&bare), Kind::Response(Err(Unattributable::Context)));
        let mut unknown = resolved("relay_session");
        unknown["evidence_level"] = json!("word_of_mouth");
        assert_eq!(kind(&unknown), Kind::Response(Err(Unattributable::Context)));
    }

    // T-100
    #[test]
    fn t_100_a_response_carries_the_digest_its_value_must_match() {
        let webhook = Webhook {
            id: "evt_1".to_owned(),
            timestamp: "1".to_owned(),
            signature: "v1a,AA".to_owned(),
        };
        let kind = |data: &serde_json::Value| {
            Event::read(&body(RESPONSE_TYPE, "evt_1", data), &webhook, ISSUER)
                .unwrap()
                .kind
        };
        let Kind::Response(Ok(answer)) = kind(&resolved("relay_session")) else {
            panic!("a relay_session answer");
        };
        assert_eq!(
            answer.response_digest,
            format!("sha256:{}", "cd".repeat(32))
        );
        for bad in [
            json!("sha256:CD"),
            json!(format!("sha1:{}", "cd".repeat(32))),
            json!(null),
        ] {
            let mut data = resolved("relay_session");
            data["response_digest"] = bad;
            assert_eq!(kind(&data), Kind::Response(Err(Unattributable::Context)));
        }
        let text = body(RESPONSE_TYPE, "evt_1", &resolved("relay_session"));
        assert!(!String::from_utf8(text).unwrap().contains("\"value\""));
    }
}
