//! Waitpoints, escalation policies and ceiling decisions as Relay takes them (T-99 items 3, 8, 9; Relay E-82): a waitpoint matches on the Condition's external id as its `correlation_key`, carries the id of the record that opened the Condition as `correlation_id` and names its responders by their pairwise Access `sub`s; an escalation policy is written once under the key `wrk-` and the id of its policy record and referenced by that key, each tier with `repeat = 0`, since Work repeats a chain with a new waitpoint; a declaration Relay's bounds do not hold (1 to 10 tiers, each at least `PT1M` after the one before, tier responders among the waitpoint's) is refused as `escalation_policy_unsupported` before anything is sent. Relay pins the policy when the waitpoint opens, so a membership change cancels the waitpoint and opens a new one for the same Condition with the tiers still to come. A ceiling decision names the `agent.ceiling_exceeded` event it answers and the Declaration that decided.

use serde::Serialize;
use work_proto::id::{Prefix, parse};

use crate::domain::intent::hex;

/// The capability of the waitpoint operations.
pub const WAITPOINT_CAPABILITY: &str = "urn:suiss:relay:waitpoint:1";

/// The capability of the escalation policy operations.
pub const ESCALATION_CAPABILITY: &str = "urn:suiss:relay:escalation:1";

/// The capability of the ceiling decision operations.
pub const AGENT_CEILING_CAPABILITY: &str = "urn:suiss:relay:agent_ceiling:1";

/// The most tiers of a policy.
pub const MAX_TIERS: usize = 10;

/// The least time between two tiers, seconds: `PT1M`.
pub const MIN_AFTER_S: u64 = 60;

/// The most responders of a waitpoint or a tier.
pub const MAX_RESPONDERS: usize = 50;

/// The prefix of a policy key.
pub const POLICY_PREFIX: &str = "wrk-";

/// The problem code of a declaration outside Relay's bounds (T-98 item 6).
pub const POLICY_UNSUPPORTED: &str = "escalation_policy_unsupported";

/// Why an escalation policy declaration is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Fewer than one or more than [`MAX_TIERS`] tiers.
    #[error("an escalation policy has 1 to {MAX_TIERS} tiers")]
    Tiers,
    /// A tier less than [`MIN_AFTER_S`] seconds after the one before.
    #[error("a tier follows the one before by at least PT1M")]
    After,
    /// A tier invites a responder the waitpoint does not name, or more than [`MAX_RESPONDERS`].
    #[error("a tier invites only responders of the waitpoint")]
    Responders,
}

impl PolicyError {
    /// The problem code: one for every bound.
    #[must_use]
    pub const fn code(self) -> &'static str {
        POLICY_UNSUPPORTED
    }
}

/// One tier of a chain (ST-43).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tier {
    /// Seconds after the tier before, or after the opening for the first.
    pub after_s: u64,
    /// The pairwise `sub`s invited at this tier.
    pub add_responders: Vec<String>,
    /// Whether a tier nobody of which can be reached is skipped.
    pub skip_if_empty: bool,
}

#[derive(Serialize)]
struct ResponderWire<'a> {
    kind: &'static str,
    id: &'a str,
}

fn subscribers(subs: &[String]) -> Vec<ResponderWire<'_>> {
    subs.iter()
        .map(|id| ResponderWire {
            kind: "subscriber",
            id,
        })
        .collect()
}

#[derive(Serialize)]
struct TierWire<'a> {
    after: String,
    add_responders: Vec<ResponderWire<'a>>,
    repeat: u8,
    skip_if_empty: bool,
}

/// An escalation policy within Relay's bounds, under its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalationPolicy {
    key: String,
    tiers: Vec<Tier>,
}

/// The key of the policy the record `record_id` declares.
#[must_use]
pub fn policy_key(record_id: &[u8; 32]) -> String {
    format!("{POLICY_PREFIX}{}", hex(record_id))
}

impl EscalationPolicy {
    /// The policy the record `record_id` declares with `tiers`, for a waitpoint of `responders`.
    ///
    /// # Errors
    /// [`PolicyError`].
    pub fn new(
        record_id: &[u8; 32],
        tiers: Vec<Tier>,
        responders: &[String],
    ) -> Result<Self, PolicyError> {
        if tiers.is_empty() || tiers.len() > MAX_TIERS {
            return Err(PolicyError::Tiers);
        }
        for tier in &tiers {
            if tier.after_s < MIN_AFTER_S {
                return Err(PolicyError::After);
            }
            if tier.add_responders.len() > MAX_RESPONDERS
                || tier.add_responders.iter().any(|r| !responders.contains(r))
            {
                return Err(PolicyError::Responders);
            }
        }
        Ok(Self {
            key: policy_key(record_id),
            tiers,
        })
    }

    /// The key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The tiers.
    #[must_use]
    pub fn tiers(&self) -> &[Tier] {
        &self.tiers
    }

    /// The tiers still to come `elapsed_s` seconds after the waitpoint opened, as the policy the
    /// record `record_id` declares for the waitpoint that replaces it (T-99 item 8, ST-45): the
    /// first of them waits out what is left of its time, and at least [`MIN_AFTER_S`]. `None`
    /// once every tier has passed.
    #[must_use]
    pub fn remaining(&self, record_id: &[u8; 32], elapsed_s: u64) -> Option<Self> {
        let mut due_s = 0_u64;
        let mut left = Vec::new();
        for tier in &self.tiers {
            due_s = due_s.saturating_add(tier.after_s);
            if !left.is_empty() {
                left.push(tier.clone());
            } else if due_s > elapsed_s {
                left.push(Tier {
                    after_s: due_s.saturating_sub(elapsed_s).max(MIN_AFTER_S),
                    ..tier.clone()
                });
            }
        }
        (!left.is_empty()).then(|| Self {
            key: policy_key(record_id),
            tiers: left,
        })
    }

    /// The body of `PUT /v1/escalation_policies/{key}` (Relay `EscalationPolicyWrite`).
    ///
    /// # Errors
    /// [`serde_json::Error`], which a policy of these fields never gives.
    pub fn body(&self) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        struct Write<'a> {
            tiers: Vec<TierWire<'a>>,
        }
        serde_json::to_vec(&Write {
            tiers: self
                .tiers
                .iter()
                .map(|t| TierWire {
                    after: format!("PT{}S", t.after_s),
                    add_responders: subscribers(&t.add_responders),
                    repeat: 0,
                    skip_if_empty: t.skip_if_empty,
                })
                .collect(),
        })
    }
}

/// What a waitpoint waits for, in Relay's words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitpointKind {
    /// An answer to a question.
    Question,
    /// A review.
    Review,
    /// An event.
    Event,
}

/// Why a waitpoint cannot be asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WaitpointError {
    /// The correlation key is not a Condition id.
    #[error("the correlation key is not a condition id")]
    Condition,
    /// The matched type is not an event name.
    #[error("the matched type is not an event name")]
    EventType,
    /// No responder resolved, or more than [`MAX_RESPONDERS`].
    #[error("responders: one to {MAX_RESPONDERS}")]
    Responders,
}

/// What Work asks a waitpoint for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitpointSpec {
    /// What it waits for.
    pub kind: WaitpointKind,
    /// The event type it matches, `noun.verb_past`.
    pub event_type: String,
    /// The Condition's external id, `cnd_…`: the correlation key.
    pub condition: String,
    /// The id of the record that opened the Condition: the correlation id.
    pub opened_by: [u8; 32],
    /// The responders' pairwise `sub`s in Relay's sector.
    pub responders: Vec<String>,
    /// The deadline, Unix milliseconds.
    pub expires_at_ms: u64,
    /// The key of its escalation policy.
    pub policy: Option<String>,
}

fn is_event_name(text: &str) -> bool {
    let part = |p: &str| {
        let mut bytes = p.bytes();
        matches!(bytes.next(), Some(b'a'..=b'z'))
            && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
    };
    text.len() <= 128 && text.contains('.') && text.split('.').all(part)
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

/// `YYYY-MM-DDTHH:MM:SSZ` of Unix milliseconds `ms`, UTC (Relay `Timestamp`).
#[must_use]
pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1000;
    let rem = secs % 86_400;
    let (y, m, d) = civil(secs / 86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[derive(Serialize)]
struct MatchWire<'a> {
    #[serde(rename = "type")]
    event_type: &'a str,
    correlation_key: &'a str,
}

#[derive(Serialize)]
struct PolicyRef<'a> {
    key: &'a str,
}

#[derive(Serialize)]
struct CreateWire<'a> {
    kind: WaitpointKind,
    #[serde(rename = "match")]
    matching: MatchWire<'a>,
    responders: Vec<ResponderWire<'a>>,
    expires_at: String,
    correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    escalation_policy: Option<PolicyRef<'a>>,
}

/// A checked waitpoint request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitpointCreate(WaitpointSpec);

impl WaitpointCreate {
    /// Checks `spec`; repeated responders count once.
    ///
    /// # Errors
    /// [`WaitpointError`].
    pub fn new(mut spec: WaitpointSpec) -> Result<Self, WaitpointError> {
        if parse(Prefix::Condition, &spec.condition).is_err() {
            return Err(WaitpointError::Condition);
        }
        if !is_event_name(&spec.event_type) {
            return Err(WaitpointError::EventType);
        }
        let mut seen = std::collections::BTreeSet::new();
        spec.responders.retain(|r| seen.insert(r.clone()));
        if spec.responders.is_empty() || spec.responders.len() > MAX_RESPONDERS {
            return Err(WaitpointError::Responders);
        }
        Ok(Self(spec))
    }

    /// What it asks for.
    #[must_use]
    pub const fn spec(&self) -> &WaitpointSpec {
        &self.0
    }

    /// The same waitpoint under another policy, for the one that replaces it.
    #[must_use]
    pub fn with_policy(mut self, policy: Option<&EscalationPolicy>) -> Self {
        self.0.policy = policy.map(|p| p.key().to_owned());
        self
    }

    /// The body of `POST /v1/waitpoints` (Relay `WaitpointCreate`).
    ///
    /// # Errors
    /// [`serde_json::Error`], which a request of these fields never gives.
    pub fn body(&self) -> Result<Vec<u8>, serde_json::Error> {
        let s = &self.0;
        serde_json::to_vec(&CreateWire {
            kind: s.kind,
            matching: MatchWire {
                event_type: &s.event_type,
                correlation_key: &s.condition,
            },
            responders: subscribers(&s.responders),
            expires_at: rfc3339(s.expires_at_ms),
            correlation_id: hex(&s.opened_by),
            escalation_policy: s.policy.as_deref().map(|key| PolicyRef { key }),
        })
    }
}

/// The body of `POST /v1/waitpoints/{id}/cancel` (Relay `WaitpointCancel`): `reason` is a code.
///
/// # Errors
/// [`serde_json::Error`].
pub fn cancel_body(reason: &str) -> Result<Vec<u8>, serde_json::Error> {
    #[derive(Serialize)]
    struct Cancel<'a> {
        reason: &'a str,
    }
    serde_json::to_vec(&Cancel { reason })
}

/// The owner's decision on an agent's held notifications (E-23).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Send everything held.
    SendAll,
    /// Cancel what is held.
    Cancel,
    /// Stop the agent.
    Stop,
}

/// The body of `POST /v1/agents/{agent_id}/ceiling_decisions` (Relay `CeilingDecisionCreate`):
/// the decision, the `id` of the `agent.ceiling_exceeded` event it answers and the id of the
/// Declaration that decided.
///
/// # Errors
/// [`serde_json::Error`].
pub fn decision_body(
    decision: Decision,
    ceiling_event_id: &str,
    declaration: &[u8; 32],
) -> Result<Vec<u8>, serde_json::Error> {
    #[derive(Serialize)]
    struct Create<'a> {
        decision: Decision,
        ceiling_event_id: &'a str,
        decision_ref: String,
    }
    serde_json::to_vec(&Create {
        decision,
        ceiling_event_id,
        decision_ref: hex(declaration),
    })
}

/// The body of `POST /v1/agents/{agent_id}/resume` (Relay `AgentResume`): the id of the record
/// that lifts the stop.
///
/// # Errors
/// [`serde_json::Error`].
pub fn resume_body(lifting: &[u8; 32]) -> Result<Vec<u8>, serde_json::Error> {
    #[derive(Serialize)]
    struct Resume {
        decision_ref: String,
    }
    serde_json::to_vec(&Resume {
        decision_ref: hex(lifting),
    })
}

fn is_relay_id(id: &str, prefix: &str) -> bool {
    let crockford = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'h' | b'j' | b'k' | b'm' | b'n' | b'p'..=b't' | b'v'..=b'z');
    id.strip_prefix(prefix)
        .is_some_and(|body| body.len() == 26 && body.bytes().all(crockford))
}

/// A Relay waitpoint id, `wp_…`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitpointId(String);

impl WaitpointId {
    /// Checks `id`.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        is_relay_id(id, "wp_").then(|| Self(id.to_owned()))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Relay agent recipient id, `agt_…`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentId(String);

impl AgentId {
    /// Checks `id`.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        is_relay_id(id, "agt_").then(|| Self(id.to_owned()))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test code")]
pub(crate) mod tests {
    use serde_json::{Value, json};

    use super::*;

    pub(crate) fn subs() -> Vec<String> {
        vec!["sub-1".to_owned(), "sub-2".to_owned()]
    }

    pub(crate) fn tier(after_s: u64, add: &[&str]) -> Tier {
        Tier {
            after_s,
            add_responders: add.iter().map(|s| (*s).to_owned()).collect(),
            skip_if_empty: true,
        }
    }

    pub(crate) fn spec() -> WaitpointSpec {
        WaitpointSpec {
            kind: WaitpointKind::Question,
            event_type: "condition.answered".to_owned(),
            condition: format!("cnd_{}", "ab".repeat(32)),
            opened_by: [9; 32],
            responders: subs(),
            expires_at_ms: 1_793_000_000_000,
            policy: None,
        }
    }

    fn json_of(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).unwrap()
    }

    // T-99 ST-43
    #[test]
    fn t_99_an_escalation_policy_outside_relay_limits_is_refused() {
        let id = [5; 32];
        assert_eq!(
            EscalationPolicy::new(&id, Vec::new(), &subs()),
            Err(PolicyError::Tiers)
        );
        let eleven = vec![tier(60, &[]); MAX_TIERS + 1];
        assert_eq!(
            EscalationPolicy::new(&id, eleven, &subs()),
            Err(PolicyError::Tiers)
        );
        assert_eq!(
            EscalationPolicy::new(&id, vec![tier(59, &[])], &subs()),
            Err(PolicyError::After)
        );
        assert_eq!(
            EscalationPolicy::new(&id, vec![tier(60, &["sub-9"])], &subs()),
            Err(PolicyError::Responders)
        );
        for e in [
            PolicyError::Tiers,
            PolicyError::After,
            PolicyError::Responders,
        ] {
            assert_eq!(e.code(), "escalation_policy_unsupported");
        }
        let ten = vec![tier(60, &["sub-2"]); MAX_TIERS];
        assert!(EscalationPolicy::new(&id, ten, &subs()).is_ok());
    }

    // T-99 ST-43
    #[test]
    fn t_99_a_policy_is_written_under_its_record_key_with_no_repeat() {
        let policy = EscalationPolicy::new(
            &[5; 32],
            vec![tier(900, &["sub-2"]), tier(3600, &[])],
            &subs(),
        )
        .unwrap();
        assert_eq!(policy.key(), format!("wrk-{}", "05".repeat(32)));
        assert!(policy.key().len() <= 100);
        assert_eq!(
            json_of(&policy.body().unwrap()),
            json!({"tiers": [
                {"after": "PT900S", "add_responders": [{"kind": "subscriber", "id": "sub-2"}],
                 "repeat": 0, "skip_if_empty": true},
                {"after": "PT3600S", "add_responders": [], "repeat": 0, "skip_if_empty": true},
            ]})
        );
        let other = EscalationPolicy::new(&[6; 32], vec![tier(900, &[])], &subs()).unwrap();
        assert_ne!(other.key(), policy.key());
    }

    // T-99 ST-45
    #[test]
    fn t_99_the_tiers_still_to_come_start_from_the_time_already_waited() {
        let policy = EscalationPolicy::new(
            &[5; 32],
            vec![tier(600, &[]), tier(600, &["sub-2"]), tier(1200, &[])],
            &subs(),
        )
        .unwrap();
        let after = |elapsed: u64| -> Option<Vec<u64>> {
            policy
                .remaining(&[6; 32], elapsed)
                .map(|p| p.tiers().iter().map(|t| t.after_s).collect())
        };
        assert_eq!(after(0), Some(vec![600, 600, 1200]));
        assert_eq!(after(100), Some(vec![500, 600, 1200]));
        assert_eq!(after(600), Some(vec![600, 1200]));
        assert_eq!(after(1190), Some(vec![60, 1200]));
        assert_eq!(after(1300), Some(vec![1100]));
        assert_eq!(after(2400), None);
        let left = policy.remaining(&[6; 32], 700).unwrap();
        assert_eq!(left.key(), format!("wrk-{}", "06".repeat(32)));
        assert_eq!(left.tiers()[0].add_responders, ["sub-2"]);
    }

    // T-99 E-15
    #[test]
    fn t_99_a_waitpoint_matches_the_condition_and_names_its_opening_record() {
        let policy = EscalationPolicy::new(&[5; 32], vec![tier(900, &[])], &subs()).unwrap();
        let create = WaitpointCreate::new(spec())
            .unwrap()
            .with_policy(Some(&policy));
        assert_eq!(
            json_of(&create.body().unwrap()),
            json!({
                "kind": "question",
                "match": {"type": "condition.answered", "correlation_key": format!("cnd_{}", "ab".repeat(32))},
                "responders": [{"kind": "subscriber", "id": "sub-1"}, {"kind": "subscriber", "id": "sub-2"}],
                "expires_at": "2026-10-26T07:33:20Z",
                "correlation_id": "09".repeat(32),
                "escalation_policy": {"key": policy.key()},
            })
        );
        let plain = WaitpointCreate::new(spec()).unwrap();
        assert!(
            json_of(&plain.body().unwrap())
                .get("escalation_policy")
                .is_none()
        );
        let bad = |change: &dyn Fn(&mut WaitpointSpec)| {
            let mut s = spec();
            change(&mut s);
            WaitpointCreate::new(s).unwrap_err()
        };
        assert_eq!(
            bad(&|s| s.condition = format!("wrk_{}", "ab".repeat(32))),
            WaitpointError::Condition
        );
        assert_eq!(
            bad(&|s| s.event_type = "answered".to_owned()),
            WaitpointError::EventType
        );
        assert_eq!(bad(&|s| s.responders.clear()), WaitpointError::Responders);
        let twice = WaitpointSpec {
            responders: vec!["s".to_owned(), "s".to_owned()],
            ..spec()
        };
        assert_eq!(
            WaitpointCreate::new(twice).unwrap().spec().responders,
            ["s"]
        );
    }

    // T-99
    #[test]
    fn t_99_a_deadline_is_an_rfc_3339_utc_timestamp() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_793_000_000_999), "2026-10-26T07:33:20Z");
        assert_eq!(rfc3339(1_798_761_599_000), "2026-12-31T23:59:59Z");
    }

    // T-99 E-23
    #[test]
    fn t_99_a_ceiling_decision_names_its_event_and_its_declaration() {
        assert_eq!(
            json_of(&decision_body(Decision::SendAll, "evt_1", &[3; 32]).unwrap()),
            json!({"decision": "send_all", "ceiling_event_id": "evt_1", "decision_ref": "03".repeat(32)})
        );
        for (decision, word) in [(Decision::Cancel, "cancel"), (Decision::Stop, "stop")] {
            let body = json_of(&decision_body(decision, "evt_1", &[3; 32]).unwrap());
            assert_eq!(body["decision"], word);
        }
        assert_eq!(
            json_of(&resume_body(&[4; 32]).unwrap()),
            json!({"decision_ref": "04".repeat(32)})
        );
        assert_eq!(
            json_of(&cancel_body("membership_changed").unwrap()),
            json!({"reason": "membership_changed"})
        );
        assert!(AgentId::parse("agt_01jc8z3k5m7p9r1t3v5x7z9b2d").is_some());
        assert!(WaitpointId::parse("wp_01jc8z3k5m7p9r1t3v5x7z9b2d").is_some());
        for bad in [
            "agt_",
            "wp_01jc8z3k5m7p9r1t3v5x7z9b2d",
            "agt_01JC8Z3K5M7P9R1T3V5X7Z9B2D",
            "agt_../../v1/events/batch/xyz",
        ] {
            assert_eq!(AgentId::parse(bad), None, "{bad}");
        }
        assert_eq!(WaitpointId::parse("wp_01jc8z3k5m7p9r1t3v5x7z9b2/"), None);
    }
}
