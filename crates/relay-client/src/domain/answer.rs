//! What Relay answers (T-28, T-99, Relay API-37): `202` with the accepted event, or for a batch the result of every row, or an RFC 9457 problem. A failure that is not the event's own is temporary and the intent stays in the outbox to be sent again with the same key: Relay unreachable, a `5xx`, `408`, `429`, any problem Relay marks `retryable`, a credential Relay does not take (`401`, or `403` with an `auth_` code), which is about Work's Access token and not the event, and a capability Relay's discovery does not offer now (T-99 item 3). Every other problem is a refusal of the event and permanent.

use serde::Deserialize;

/// The reason an intent waits for a capability Relay does not offer (T-99 item 3).
pub const CAPABILITY_MISSING: &str = "relay_capability_missing";

/// Why a Relay call did not deliver.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// Relay could not be reached or did not answer in time.
    #[error("relay unreachable: {0}")]
    Unreachable(String),
    /// Relay answered that it cannot take the call now.
    #[error("relay unavailable: {status} {code}")]
    Unavailable {
        /// HTTP status.
        status: u16,
        /// The problem code, `unknown` without one.
        code: String,
        /// `Retry-After`, seconds.
        retry_after_s: Option<u64>,
    },
    /// Relay does not take Work's credential.
    #[error("relay refused the credential: {status} {code}")]
    Unauthenticated {
        /// HTTP status.
        status: u16,
        /// The problem code.
        code: String,
    },
    /// Relay refused the event.
    #[error("relay refused the event: {status} {code}")]
    Refused {
        /// HTTP status.
        status: u16,
        /// The problem code.
        code: String,
    },
    /// Work holds no credential for Relay now.
    #[error("no credential for relay: {0}")]
    Credential(String),
    /// Relay's discovery does not offer the capability the call needs; there is no other way
    /// (T-99 item 3, E-2).
    #[error("relay does not offer {0}")]
    CapabilityMissing(&'static str),
    /// A `2xx` whose body is not what the contract says.
    #[error("relay answer: {0}")]
    Answer(&'static str),
}

impl RelayError {
    /// Whether the intent stays in the outbox and is sent again (T-28).
    #[must_use]
    pub const fn is_temporary(&self) -> bool {
        !matches!(self, Self::Refused { .. })
    }

    /// The stable code, for the log and the attention signal.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Unreachable(_) => "relay_unreachable",
            Self::Credential(_) => "relay_credential_missing",
            Self::CapabilityMissing(_) => CAPABILITY_MISSING,
            Self::Answer(_) => "relay_answer",
            Self::Unavailable { code, .. }
            | Self::Unauthenticated { code, .. }
            | Self::Refused { code, .. } => code,
        }
    }
}

#[derive(Deserialize)]
struct Problem {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    retryable: Option<bool>,
}

/// The error of a non-`2xx` answer of `status` with `body` and `Retry-After`.
#[must_use]
pub fn problem(status: u16, body: &[u8], retry_after: Option<&str>) -> RelayError {
    let p: Option<Problem> = serde_json::from_slice(body).ok();
    let retryable = p.as_ref().and_then(|p| p.retryable).unwrap_or(false);
    let code = p
        .and_then(|p| p.code)
        .filter(|c| {
            !c.is_empty()
                && c.len() <= 64
                && c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let auth = status == 401 || (status == 403 && code.starts_with("auth_"));
    if auth {
        RelayError::Unauthenticated { status, code }
    } else if status >= 500 || matches!(status, 408 | 429) || retryable {
        RelayError::Unavailable {
            status,
            code,
            retry_after_s: retry_after.and_then(|v| v.trim().parse().ok()),
        }
    } else {
        RelayError::Refused { status, code }
    }
}

/// An accepted event (Relay `EventAccepted`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The `evt_` id.
    pub event_id: String,
    /// How many notifications it opened.
    pub notifications: usize,
}

#[derive(Deserialize)]
struct EventWire {
    object: String,
    id: String,
    status: String,
    notifications: Vec<serde_json::Value>,
}

impl EventWire {
    fn checked(self) -> Result<Accepted, RelayError> {
        if self.object == "event" && self.status == "accepted" && !self.id.is_empty() {
            Ok(Accepted {
                event_id: self.id,
                notifications: self.notifications.len(),
            })
        } else {
            Err(RelayError::Answer("event"))
        }
    }
}

/// The accepted event of a `202` to `POST /v1/events`.
///
/// # Errors
/// [`RelayError::Answer`].
pub fn accepted(body: &[u8]) -> Result<Accepted, RelayError> {
    serde_json::from_slice::<EventWire>(body)
        .map_err(|_| RelayError::Answer("event"))?
        .checked()
}

#[derive(Deserialize)]
struct RowWire {
    index: usize,
    status: String,
    #[serde(default)]
    event: Option<EventWire>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct BatchWire {
    object: String,
    results: Vec<RowWire>,
}

/// The outcome of one batch row, in the order the rows were sent.
pub type RowOutcome = Result<Accepted, RelayError>;

/// The rows of a `202`, `207` or `422` batch result for `rows` rows sent.
///
/// # Errors
/// [`RelayError::Answer`] for a result that does not answer every row once.
pub fn batch(body: &[u8], rows: usize) -> Result<Vec<RowOutcome>, RelayError> {
    let wire: BatchWire =
        serde_json::from_slice(body).map_err(|_| RelayError::Answer("batch_result"))?;
    if wire.object != "batch_result" || wire.results.len() != rows {
        return Err(RelayError::Answer("batch_result"));
    }
    let mut out: Vec<Option<RowOutcome>> = vec![None; rows];
    for row in wire.results {
        let outcome = match (row.status.as_str(), row.event, row.error) {
            ("accepted", Some(event), _) => event.checked(),
            ("rejected", _, Some(error)) => {
                let status = error
                    .get("status")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|s| u16::try_from(s).ok())
                    .unwrap_or(422);
                let bytes = serde_json::to_vec(&error).unwrap_or_default();
                Err(problem(status, &bytes, None))
            }
            _ => return Err(RelayError::Answer("batch_result")),
        };
        let Some(slot) = out.get_mut(row.index) else {
            return Err(RelayError::Answer("batch_result"));
        };
        if slot.is_some() {
            return Err(RelayError::Answer("batch_result"));
        }
        *slot = Some(outcome);
    }
    out.into_iter()
        .map(|o| o.ok_or(RelayError::Answer("batch_result")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(code: &str, retryable: bool) -> Vec<u8> {
        serde_json::json!({
            "type": format!("https://relay.example/v1/errors/{code}"),
            "title": "t",
            "status": 422,
            "code": code,
            "retryable": retryable
        })
        .to_string()
        .into_bytes()
    }

    // T-28 T-99
    #[test]
    fn t_28_an_outage_is_temporary_and_a_refusal_is_permanent() {
        assert!(RelayError::Unreachable("connect".to_owned()).is_temporary());
        let busy = problem(503, &body("service_unavailable", true), Some("7"));
        assert_eq!(
            busy,
            RelayError::Unavailable {
                status: 503,
                code: "service_unavailable".to_owned(),
                retry_after_s: Some(7)
            }
        );
        assert!(busy.is_temporary());
        assert!(problem(429, &body("rate_limited", true), None).is_temporary());
        assert!(problem(502, b"<html>", None).is_temporary());
        assert!(problem(409, &body("idempotency_in_progress", true), None).is_temporary());
        let token = problem(401, &body("auth_invalid_token", false), None);
        assert!(matches!(
            token,
            RelayError::Unauthenticated { status: 401, .. }
        ));
        assert!(token.is_temporary());
        assert!(problem(403, &body("auth_tenant_suspended", false), None).is_temporary());
        let critical = problem(422, &body("critical_not_granted", false), None);
        assert_eq!(
            critical,
            RelayError::Refused {
                status: 422,
                code: "critical_not_granted".to_owned()
            }
        );
        assert!(!critical.is_temporary());
        assert_eq!(critical.code(), "critical_not_granted");
        let scheme = problem(422, &body("link_scheme_not_allowed", false), None);
        assert!(!scheme.is_temporary());
        assert_eq!(
            problem(400, b"not json", None),
            RelayError::Refused {
                status: 400,
                code: "unknown".to_owned()
            }
        );
    }

    // T-99
    #[test]
    fn t_99_an_accepted_event_and_a_batch_answer_every_row() {
        let event = serde_json::json!({
            "object": "event", "id": "evt_1", "workflow": {"key": "work-information", "version": 1},
            "status": "accepted", "recipient_count": 1,
            "notifications": [{"recipient_id": "rcp_1", "notification_id": "ntf_1"}],
            "created_at": "2026-11-06T10:00:00Z"
        });
        assert_eq!(
            accepted(event.to_string().as_bytes()).unwrap(),
            Accepted {
                event_id: "evt_1".to_owned(),
                notifications: 1
            }
        );
        assert_eq!(accepted(b"{}"), Err(RelayError::Answer("event")));
        let result = serde_json::json!({
            "object": "batch_result",
            "summary": {},
            "results": [
                {"index": 1, "status": "rejected", "error": {"status": 422, "code": "link_scheme_not_allowed", "retryable": false}},
                {"index": 0, "status": "accepted", "event": event}
            ]
        });
        let rows = batch(result.to_string().as_bytes(), 2).unwrap();
        assert_eq!(rows[0].as_ref().unwrap().event_id, "evt_1");
        assert_eq!(
            rows[1].as_ref().unwrap_err().code(),
            "link_scheme_not_allowed"
        );
        assert_eq!(
            batch(result.to_string().as_bytes(), 3),
            Err(RelayError::Answer("batch_result"))
        );
    }
}
