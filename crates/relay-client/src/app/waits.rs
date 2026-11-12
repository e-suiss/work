//! Waitpoints, escalation policies and ceiling decisions over the Relay client (T-99 items 3, 8, 9, 10; Relay E-82): each call goes to the endpoint Relay's discovery offers with its capability and, while Relay does not offer it, is not sent at all and stays in the outbox as `relay_capability_missing`, as during a Relay outage; there is no timer of Work's own and no other way (E-2). A policy record is written once, without `If-Match`, and a policy Relay already holds under the key counts as written. A waitpoint is replaced in one job, in order and under the step keys of the job's key: the policy of the tiers still to come, the cancellation, the new waitpoint for the same Condition.

use serde::Deserialize;

use crate::app::Relay;
use crate::domain::answer::{RelayError, problem};
use crate::domain::intent::IdempotencyKey;
use crate::domain::waitpoint::{
    AGENT_CEILING_CAPABILITY, AgentId, Decision, ESCALATION_CAPABILITY, EscalationPolicy,
    WAITPOINT_CAPABILITY, WaitpointCreate, WaitpointId, cancel_body, decision_body, resume_body,
};
use crate::ports::{Credential, Method, Response, Transport};

/// The status of a policy write that names no version although the key holds one: the policy
/// record was written before.
const POLICY_HELD: u16 = 428;

#[derive(Deserialize)]
struct WaitpointWire {
    object: String,
    id: String,
}

fn offered<'a>(
    endpoint: Option<&'a String>,
    capability: &'static str,
) -> Result<&'a str, RelayError> {
    endpoint
        .map(String::as_str)
        .ok_or(RelayError::CapabilityMissing(capability))
}

fn refused(answer: &Response) -> RelayError {
    problem(answer.status, &answer.body, answer.header("retry-after"))
}

fn encoded(body: Result<Vec<u8>, serde_json::Error>) -> Result<Vec<u8>, RelayError> {
    body.map_err(|_| RelayError::Answer("request"))
}

impl<T: Transport, K: Credential> Relay<T, K> {
    /// `PUT /v1/escalation_policies/{key}`: writes the policy record once (T-99 item 8).
    ///
    /// # Errors
    /// [`RelayError`]; [`RelayError::CapabilityMissing`] while Relay does not offer escalation.
    pub async fn put_policy(
        &self,
        policy: &EscalationPolicy,
        key: &IdempotencyKey,
        traceparent: &str,
    ) -> Result<(), RelayError> {
        let base = offered(
            self.offered.escalation_policies.as_ref(),
            ESCALATION_CAPABILITY,
        )?;
        let url = format!("{base}/{}", policy.key());
        let body = encoded(policy.body())?;
        let answer = self.call(Method::Put, url, body, key, traceparent).await?;
        match answer.status {
            200 | 201 | POLICY_HELD => Ok(()),
            _ => Err(refused(&answer)),
        }
    }

    /// `POST /v1/waitpoints`: opens the waitpoint and gives its id (T-99 item 8).
    ///
    /// # Errors
    /// [`RelayError`]; [`RelayError::CapabilityMissing`] while Relay does not offer waitpoints.
    pub async fn create_waitpoint(
        &self,
        create: &WaitpointCreate,
        key: &IdempotencyKey,
        traceparent: &str,
    ) -> Result<WaitpointId, RelayError> {
        let base = offered(self.offered.waitpoints.as_ref(), WAITPOINT_CAPABILITY)?;
        let body = encoded(create.body())?;
        let answer = self
            .call(Method::Post, base.to_owned(), body, key, traceparent)
            .await?;
        if answer.status != 201 {
            return Err(refused(&answer));
        }
        serde_json::from_slice::<WaitpointWire>(&answer.body)
            .ok()
            .filter(|w| w.object == "waitpoint")
            .and_then(|w| WaitpointId::parse(&w.id))
            .ok_or(RelayError::Answer("waitpoint"))
    }

    /// `POST /v1/waitpoints/{id}/cancel` with `reason`, a code.
    ///
    /// # Errors
    /// [`RelayError`]; [`RelayError::CapabilityMissing`] while Relay does not offer waitpoints.
    pub async fn cancel_waitpoint(
        &self,
        id: &WaitpointId,
        reason: &str,
        key: &IdempotencyKey,
        traceparent: &str,
    ) -> Result<(), RelayError> {
        let base = offered(self.offered.waitpoints.as_ref(), WAITPOINT_CAPABILITY)?;
        let url = format!("{base}/{}/cancel", id.as_str());
        let body = encoded(cancel_body(reason))?;
        let answer = self.call(Method::Post, url, body, key, traceparent).await?;
        if answer.status == 200 {
            Ok(())
        } else {
            Err(refused(&answer))
        }
    }

    /// Replaces the waitpoint `replaced` after a membership change (T-99 item 8, ST-45): Relay
    /// pins the policy when a waitpoint opens, so the policy of the tiers still to come is
    /// written, the old waitpoint is cancelled with `reason` and `create` opens the new one for
    /// the same Condition, in this order under the step keys of `key`. The first call that fails
    /// ends the job; a later run makes the same calls under the same keys.
    ///
    /// # Errors
    /// [`RelayError`] of the first call that fails; nothing is sent while Relay offers no
    /// waitpoints, or no escalation for a `policy`.
    pub async fn replace_waitpoint(
        &self,
        replaced: &WaitpointId,
        reason: &str,
        policy: Option<&EscalationPolicy>,
        create: &WaitpointCreate,
        key: &IdempotencyKey,
        traceparent: &str,
    ) -> Result<WaitpointId, RelayError> {
        offered(self.offered.waitpoints.as_ref(), WAITPOINT_CAPABILITY)?;
        if let Some(policy) = policy {
            self.put_policy(policy, &key.step("policy"), traceparent)
                .await?;
        }
        self.cancel_waitpoint(replaced, reason, &key.step("cancel"), traceparent)
            .await?;
        self.create_waitpoint(create, &key.step("create"), traceparent)
            .await
    }

    /// `POST /v1/agents/{agent_id}/ceiling_decisions`: the E-23 Declaration `declaration` on the
    /// `agent.ceiling_exceeded` event `ceiling_event_id` (T-99 item 9). A `409
    /// ceiling_decision_conflict` is a refusal: it takes nothing back in Work.
    ///
    /// # Errors
    /// [`RelayError`]; [`RelayError::CapabilityMissing`] while Relay does not offer the ceiling.
    pub async fn decide_ceiling(
        &self,
        agent: &AgentId,
        decision: Decision,
        ceiling_event_id: &str,
        declaration: &[u8; 32],
        key: &IdempotencyKey,
        traceparent: &str,
    ) -> Result<(), RelayError> {
        let base = offered(self.offered.agents.as_ref(), AGENT_CEILING_CAPABILITY)?;
        let url = format!("{base}/{}/ceiling_decisions", agent.as_str());
        let body = encoded(decision_body(decision, ceiling_event_id, declaration))?;
        let answer = self.call(Method::Post, url, body, key, traceparent).await?;
        if answer.status == 201 {
            Ok(())
        } else {
            Err(refused(&answer))
        }
    }

    /// `POST /v1/agents/{agent_id}/resume`: the record `lifting` lifts a stop (T-99 item 9).
    ///
    /// # Errors
    /// [`RelayError`]; [`RelayError::CapabilityMissing`] while Relay does not offer the ceiling.
    pub async fn resume_agent(
        &self,
        agent: &AgentId,
        lifting: &[u8; 32],
        key: &IdempotencyKey,
        traceparent: &str,
    ) -> Result<(), RelayError> {
        let base = offered(self.offered.agents.as_ref(), AGENT_CEILING_CAPABILITY)?;
        let url = format!("{base}/{}/resume", agent.as_str());
        let body = encoded(resume_body(lifting))?;
        let answer = self.call(Method::Post, url, body, key, traceparent).await?;
        if answer.status == 200 {
            Ok(())
        } else {
            Err(refused(&answer))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Offered;
    use crate::app::tests::{Token, Wire, refusal};
    use crate::domain::answer::CAPABILITY_MISSING;
    use crate::domain::intent::tests::TRACE;
    use crate::domain::waitpoint::tests::{spec, subs, tier};

    const EVENTS: &str = "https://relay.example/v1/events";
    const WP_OLD: &str = "wp_01jc8z3k5m7p9r1t3v5x7z9b2d";
    const WP_NEW: &str = "wp_01jc8z3k5m7p9r1t3v5x7z9b2e";
    const AGENT: &str = "agt_01jc8z3k5m7p9r1t3v5x7z9b2d";

    fn all() -> Offered {
        Offered {
            waitpoints: Some("https://relay.example/v1/waitpoints".to_owned()),
            escalation_policies: Some("https://relay.example/v1/escalation_policies".to_owned()),
            agents: Some("https://relay.example/v1/agents/".to_owned()),
        }
    }

    fn key() -> IdempotencyKey {
        IdempotencyKey::of(&[7; 32], 42, "gate_waiting")
    }

    fn answer(status: u16, body: &serde_json::Value) -> Result<Response, RelayError> {
        Ok(Response {
            status,
            headers: Vec::new(),
            body: body.to_string().into_bytes(),
        })
    }

    fn waitpoint(id: &str) -> Result<Response, RelayError> {
        answer(
            201,
            &serde_json::json!({"object": "waitpoint", "id": id, "state": "open"}),
        )
    }

    fn policy() -> EscalationPolicy {
        EscalationPolicy::new(&[5; 32], vec![tier(900, &["sub-2"])], &subs()).unwrap()
    }

    // T-99 T-28 E-2
    #[tokio::test]
    async fn t_99_a_missing_waitpoint_capability_keeps_the_request_in_the_outbox() {
        let wire = Wire::default();
        let relay = Relay::new(&wire, Token, EVENTS).unwrap();
        let create = WaitpointCreate::new(spec()).unwrap();
        let old = WaitpointId::parse(WP_OLD).unwrap();
        let agent = AgentId::parse(AGENT).unwrap();
        let errors = [
            relay
                .create_waitpoint(&create, &key(), TRACE)
                .await
                .unwrap_err(),
            relay
                .cancel_waitpoint(&old, "membership_changed", &key(), TRACE)
                .await
                .unwrap_err(),
            relay
                .put_policy(&policy(), &key(), TRACE)
                .await
                .unwrap_err(),
            relay
                .replace_waitpoint(&old, "membership_changed", None, &create, &key(), TRACE)
                .await
                .unwrap_err(),
            relay
                .decide_ceiling(&agent, Decision::Stop, "evt_1", &[3; 32], &key(), TRACE)
                .await
                .unwrap_err(),
            relay
                .resume_agent(&agent, &[4; 32], &key(), TRACE)
                .await
                .unwrap_err(),
        ];
        for error in &errors {
            assert!(error.is_temporary(), "{error}");
            assert_eq!(error.code(), CAPABILITY_MISSING);
        }
        assert_eq!(
            errors[0],
            RelayError::CapabilityMissing("urn:suiss:relay:waitpoint:1")
        );
        assert_eq!(
            errors[2],
            RelayError::CapabilityMissing("urn:suiss:relay:escalation:1")
        );
        assert_eq!(
            errors[4],
            RelayError::CapabilityMissing("urn:suiss:relay:agent_ceiling:1")
        );
        assert!(wire.sent.lock().unwrap().is_empty());
        let plain = Relay::new(&wire, Token, EVENTS).unwrap().offering(Offered {
            waitpoints: Some("http://relay.example/v1/waitpoints".to_owned()),
            ..Offered::default()
        });
        assert_eq!(
            plain.create_waitpoint(&create, &key(), TRACE).await,
            Err(RelayError::CapabilityMissing("urn:suiss:relay:waitpoint:1"))
        );
        assert!(wire.sent.lock().unwrap().is_empty());
    }

    // T-99 ST-43
    #[tokio::test]
    async fn t_99_a_waitpoint_and_its_policy_go_to_the_endpoints_discovery_offers() {
        let wire = Wire::answering(vec![
            answer(201, &serde_json::json!({"object": "escalation_policy"})),
            waitpoint(WP_OLD),
            answer(428, &serde_json::json!({"code": "precondition_required"})),
            Ok(refusal(422, "escalation_responder_outside_set", false)),
        ]);
        let relay = Relay::new(&wire, Token, EVENTS).unwrap().offering(all());
        let policy = policy();
        relay
            .put_policy(&policy, &key().step("policy"), TRACE)
            .await
            .unwrap();
        let create = WaitpointCreate::new(spec())
            .unwrap()
            .with_policy(Some(&policy));
        let id = relay
            .create_waitpoint(&create, &key(), TRACE)
            .await
            .unwrap();
        assert_eq!(id.as_str(), WP_OLD);
        relay
            .put_policy(&policy, &key().step("policy"), TRACE)
            .await
            .unwrap();
        let refused = relay
            .create_waitpoint(&create, &key(), TRACE)
            .await
            .unwrap_err();
        assert!(!refused.is_temporary());
        let sent = wire.sent.lock().unwrap();
        assert_eq!(sent[0].method, Method::Put);
        assert_eq!(
            sent[0].url,
            format!(
                "https://relay.example/v1/escalation_policies/{}",
                policy.key()
            )
        );
        assert_eq!(sent[0].header("if-match"), None);
        assert_eq!(sent[0].body, policy.body().unwrap());
        assert_eq!(sent[1].method, Method::Post);
        assert_eq!(sent[1].url, "https://relay.example/v1/waitpoints");
        assert_eq!(sent[1].header("idempotency-key"), Some(key().as_str()));
        assert_eq!(
            sent[1].header("dpop"),
            Some("proof POST https://relay.example/v1/waitpoints")
        );
        assert_eq!(sent[1].header("traceparent"), Some(TRACE));
        assert_eq!(sent[1].body, create.body().unwrap());
    }

    // T-99 ST-45
    #[tokio::test]
    async fn t_99_a_membership_change_replaces_the_waitpoint() {
        let wire = Wire::answering(vec![
            answer(201, &serde_json::json!({"object": "escalation_policy"})),
            answer(
                200,
                &serde_json::json!({"object": "waitpoint", "id": WP_OLD}),
            ),
            waitpoint(WP_NEW),
        ]);
        let relay = Relay::new(&wire, Token, EVENTS).unwrap().offering(all());
        let left = policy().remaining(&[6; 32], 300).unwrap();
        let create = WaitpointCreate::new(spec())
            .unwrap()
            .with_policy(Some(&left));
        let old = WaitpointId::parse(WP_OLD).unwrap();
        let new = relay
            .replace_waitpoint(
                &old,
                "membership_changed",
                Some(&left),
                &create,
                &key(),
                TRACE,
            )
            .await
            .unwrap();
        assert_eq!(new.as_str(), WP_NEW);
        let sent = wire.sent.lock().unwrap();
        let calls: Vec<(Method, &str)> = sent.iter().map(|r| (r.method, r.url.as_str())).collect();
        let policy_url = format!(
            "https://relay.example/v1/escalation_policies/{}",
            left.key()
        );
        assert_eq!(
            calls,
            [
                (Method::Put, policy_url.as_str()),
                (
                    Method::Post,
                    "https://relay.example/v1/waitpoints/wp_01jc8z3k5m7p9r1t3v5x7z9b2d/cancel"
                ),
                (Method::Post, "https://relay.example/v1/waitpoints"),
            ]
        );
        let keys: Vec<Option<&str>> = sent.iter().map(|r| r.header("idempotency-key")).collect();
        assert_eq!(
            keys,
            [
                Some(key().step("policy").as_str()),
                Some(key().step("cancel").as_str()),
                Some(key().step("create").as_str()),
            ]
        );
        let body: serde_json::Value = serde_json::from_slice(&sent[2].body).unwrap();
        assert_eq!(body["match"]["correlation_key"], spec().condition);
        assert_eq!(body["escalation_policy"]["key"], left.key());
        let tiers: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap();
        assert_eq!(tiers["tiers"][0]["after"], "PT600S");
        drop(sent);
        let down = Wire::answering(vec![Ok(refusal(503, "service_unavailable", true))]);
        let relay = Relay::new(&down, Token, EVENTS).unwrap().offering(all());
        let waiting = relay
            .replace_waitpoint(&old, "membership_changed", None, &create, &key(), TRACE)
            .await
            .unwrap_err();
        assert!(waiting.is_temporary());
        assert_eq!(down.sent.lock().unwrap().len(), 1);
    }

    // T-99 E-23
    #[tokio::test]
    async fn t_99_a_ceiling_decision_goes_to_the_agent_and_a_conflict_takes_nothing_back() {
        let wire = Wire::answering(vec![
            answer(201, &serde_json::json!({"object": "ceiling_decision"})),
            Ok(refusal(409, "ceiling_decision_conflict", false)),
            answer(200, &serde_json::json!({"object": "agent_state"})),
        ]);
        let relay = Relay::new(&wire, Token, EVENTS).unwrap().offering(all());
        let agent = AgentId::parse(AGENT).unwrap();
        relay
            .decide_ceiling(&agent, Decision::Stop, "evt_1", &[3; 32], &key(), TRACE)
            .await
            .unwrap();
        let conflict = relay
            .decide_ceiling(&agent, Decision::SendAll, "evt_1", &[3; 32], &key(), TRACE)
            .await
            .unwrap_err();
        assert_eq!(
            conflict,
            RelayError::Refused {
                status: 409,
                code: "ceiling_decision_conflict".to_owned()
            }
        );
        relay
            .resume_agent(&agent, &[4; 32], &key(), TRACE)
            .await
            .unwrap();
        let sent = wire.sent.lock().unwrap();
        assert_eq!(
            sent[0].url,
            format!("https://relay.example/v1/agents/{AGENT}/ceiling_decisions")
        );
        assert_eq!(
            sent[2].url,
            format!("https://relay.example/v1/agents/{AGENT}/resume")
        );
        let body: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap();
        assert_eq!(body["decision"], "stop");
        assert_eq!(body["decision_ref"], "03".repeat(32));
    }
}
