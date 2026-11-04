//! The single-subject eligibility check (T-101 item 5; Access OP-149 m.10, m.15 (a)): `{subject, set, as_of?}` to `{eligible, consistency_token}`. The call records nothing in Access and is never cached; the token enters the record's `authority` basis (P-13).

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::domain::AccessError;
use crate::domain::keys::KernelId;

/// Members an ADP `check` carries that the eligibility `set` must not (Access OP-149 m.15 (a)).
pub const NOT_IN_SET: [&str; 5] = ["mode", "nonce", "payload", "exercise", "ais"];

/// An opaque Access consistency token: the head an answer was read at.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsistencyToken(String);

impl ConsistencyToken {
    /// Wraps a non-empty token.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        (!text.is_empty()).then(|| Self(text.to_owned()))
    }

    /// The token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ConsistencyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsistencyToken")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// One eligibility question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligibilityRequest {
    subject: KernelId,
    set: Map<String, Value>,
    as_of: Option<ConsistencyToken>,
}

impl EligibilityRequest {
    /// Whether `subject`, a `PartyID`, is in the set the ADP `check` context `set` describes,
    /// answered at or after `as_of`.
    ///
    /// # Errors
    /// [`AccessError::Answer`] when `set` names a member a `check` alone carries.
    pub fn new(
        subject: KernelId,
        set: Map<String, Value>,
        as_of: Option<ConsistencyToken>,
    ) -> Result<Self, AccessError> {
        if NOT_IN_SET.iter().any(|m| set.contains_key(*m)) {
            return Err(AccessError::Answer("set"));
        }
        Ok(Self {
            subject,
            set,
            as_of,
        })
    }

    /// The JSON body.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut body = Map::new();
        body.insert("subject".to_owned(), self.subject.text().into());
        body.insert("set".to_owned(), Value::Object(self.set.clone()));
        if let Some(t) = &self.as_of {
            body.insert("as_of".to_owned(), t.as_str().into());
        }
        serde_json::to_vec(&Value::Object(body)).unwrap_or_default()
    }
}

#[derive(Deserialize)]
struct Wire {
    eligible: bool,
    consistency_token: String,
}

/// The answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eligibility {
    /// Whether the subject is in the set.
    pub eligible: bool,
    /// The head it was read at; it enters the record's `authority` basis.
    pub consistency_token: ConsistencyToken,
}

impl Eligibility {
    /// Reads the answer.
    ///
    /// # Errors
    /// [`AccessError::Answer`].
    pub fn from_json(body: &[u8]) -> Result<Self, AccessError> {
        let wire: Wire =
            serde_json::from_slice(body).map_err(|_| AccessError::Answer("eligibility"))?;
        Ok(Self {
            eligible: wire.eligible,
            consistency_token: ConsistencyToken::new(&wire.consistency_token)
                .ok_or(AccessError::Answer("consistency_token"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> Map<String, Value> {
        serde_json::json!({"domain": "sha-256:AQ", "intent": "approve", "basis": [], "capacity": "self", "proofs": []})
            .as_object()
            .unwrap()
            .clone()
    }

    // T-101
    #[test]
    fn t_101_the_eligibility_request_is_a_check_context_without_mode_or_nonce() {
        let subject = KernelId([4; 16]);
        let request =
            EligibilityRequest::new(subject, set(), ConsistencyToken::new("ct1")).unwrap();
        let body: Value = serde_json::from_slice(&request.body()).unwrap();
        assert_eq!(body["subject"], subject.text());
        assert_eq!(body["set"]["intent"], "approve");
        assert_eq!(body["as_of"], "ct1");
        for member in NOT_IN_SET {
            let mut s = set();
            s.insert(member.to_owned(), Value::Null);
            assert!(
                EligibilityRequest::new(subject, s, None).is_err(),
                "{member}"
            );
        }
    }

    // T-101
    #[test]
    fn t_101_the_answer_carries_a_consistency_token() {
        let a =
            Eligibility::from_json(br#"{"eligible": true, "consistency_token": "abc"}"#).unwrap();
        assert!(a.eligible);
        assert_eq!(a.consistency_token.as_str(), "abc");
        assert!(Eligibility::from_json(br#"{"eligible": true}"#).is_err());
        assert!(Eligibility::from_json(br#"{"eligible": true, "consistency_token": ""}"#).is_err());
        assert!(!format!("{:?}", a.consistency_token).contains("abc"));
    }
}
