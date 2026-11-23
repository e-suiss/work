//! The pure side of the coordination contract (RC-36, RC-39, RC-42, RC-43, SEC-15): a pulled delivery decoded with the kernel's `work/control/1` readers, the answer to a delivered request decided from the declared capability, the configured answers and the step under way, and the contract bodies the executor writes.

use serde::Deserialize;
use work_access_client::domain::from_b64url;
use work_kernel::catalog::{ChangePolicy, HandoverReason, StopAnswer, StopType};
use work_kernel::control::body::{
    AttemptOutcome, Binding, Capability, CommitmentDelivery, ControlMode, ControlModeReport,
    ExecutionState, Handover, Heartbeat, Operation, ProgressEvent, ProgressReport, RequestDelivery,
    RequestKind, RequestResponse, SessionReport, StatusReport,
};
use work_kernel::id::Digest;

use crate::config::Responses;

/// One delivery as `GET …/executor/deliveries` answers it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct Wire {
    /// The sequence number, decimal.
    pub(crate) seq: String,
    /// `commitment` or `request`.
    pub(crate) kind: String,
    /// The commitment, `cmt_…`.
    pub(crate) commitment: String,
    /// The record that caused it, `rec_…`.
    pub(crate) record: String,
    /// The `work/control/1` body, unpadded base64url CBOR.
    pub(crate) body: String,
}

/// The answer of one pull.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct Pulled {
    /// The deliveries, oldest first.
    pub(crate) deliveries: Vec<Wire>,
    /// The cursor of the next pull.
    pub(crate) cursor: String,
}

/// What a delivery asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Delivered {
    /// The executor is given a commitment (RC-42, SEC-15).
    Commitment(CommitmentDelivery),
    /// A request about a commitment it runs (RC-36, RC-42).
    Request(RequestDelivery),
}

/// One decoded delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Delivery {
    /// Its sequence number.
    pub(crate) seq: u64,
    /// The commitment, `cmt_…`.
    pub(crate) commitment: String,
    /// What it asks.
    pub(crate) what: Delivered,
}

/// Why a delivery is not read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DeliveryError {
    /// The sequence number is not a decimal.
    #[error("seq")]
    Seq,
    /// The kind is neither `commitment` nor `request`.
    #[error("kind")]
    Kind,
    /// The body is not unpadded base64url.
    #[error("body")]
    Encoding,
    /// The body is not the contract body its kind names, by the member refused.
    #[error("definition:{0}")]
    Body(&'static str),
}

impl Wire {
    /// The delivery, its body read with the kernel's decoder (RC-42).
    pub(crate) fn decode(&self) -> Result<Delivery, DeliveryError> {
        let seq = self.seq.parse::<u64>().map_err(|_| DeliveryError::Seq)?;
        let bytes = from_b64url(&self.body).map_err(|_| DeliveryError::Encoding)?;
        let what = match self.kind.as_str() {
            "commitment" => Delivered::Commitment(
                CommitmentDelivery::decode(&bytes).map_err(|e| DeliveryError::Body(e.0))?,
            ),
            "request" => Delivered::Request(
                RequestDelivery::decode(&bytes).map_err(|e| DeliveryError::Body(e.0))?,
            ),
            _ => return Err(DeliveryError::Kind),
        };
        Ok(Delivery {
            seq,
            commitment: self.commitment.clone(),
            what,
        })
    }
}

/// What the executor does once it answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    /// Nothing changes.
    Nothing,
    /// Stop now.
    Stop,
    /// Stop once the step under way ends (RC-39, a non-cancellable step or a controlled stop).
    StopAfterStep,
    /// Pause until a resume.
    Pause,
    /// Go on after a pause or a stop lifted by `resume_after_stop`.
    Resume,
    /// A second driver takes control: the executor holds still (RC-33).
    TakeOver,
    /// Control comes back: a handover note and automatic mode (RC-34).
    ReturnControl,
}

/// The answer to one request and what follows from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Decision {
    /// The response body (RC-36, RC-42).
    pub(crate) response: RequestResponse,
    /// What the executor does.
    pub(crate) effect: Effect,
}

fn accepted(request: &RequestDelivery, answer: StopAnswer, effect: Effect) -> Decision {
    Decision {
        response: RequestResponse {
            request: request.record,
            answer,
            reason: None,
            applied_version: None,
        },
        effect,
    }
}

fn refused(request: &RequestDelivery, reason: &str) -> Decision {
    Decision {
        response: RequestResponse {
            request: request.record,
            answer: StopAnswer::Refuse,
            reason: Some(reason.to_owned()),
            applied_version: None,
        },
        effect: Effect::Nothing,
    }
}

/// The answer to `request` (RC-36, RC-39, RC-42): only what the capability declares is
/// accepted; a stop is answered as configured, and an immediate stop during a non-cancellable
/// step is answered `finish_then_stop`, since the executor's own safety authority is never
/// overridden and the stop applies after the step; a takeover is answered as configured; a
/// change is applied only under a declared change policy, with its version.
pub(crate) fn decide(
    request: &RequestDelivery,
    capability: &Capability,
    responses: &Responses,
    step: Option<&str>,
) -> Decision {
    let undeclared = "the executor does not declare this request in its capability";
    match request.kind {
        RequestKind::Stop => {
            let Some(stop_type) = request.stop_type else {
                return refused(request, undeclared);
            };
            if !capability.stop_types.contains(&stop_type) {
                return refused(request, undeclared);
            }
            let configured = if stop_type == StopType::Pause {
                responses.pause
            } else {
                responses.stop
            };
            let pinned = step.is_some_and(|s| capability.non_cancellable.iter().any(|n| n == s));
            match (configured, stop_type) {
                (StopAnswer::Refuse, _) => refused(request, &responses.reason),
                (_, StopType::Pause) => accepted(request, StopAnswer::Accept, Effect::Pause),
                (StopAnswer::Accept, StopType::Immediate) if !pinned => {
                    accepted(request, StopAnswer::Accept, Effect::Stop)
                }
                _ => accepted(request, StopAnswer::FinishThenStop, Effect::StopAfterStep),
            }
        }
        RequestKind::Takeover if !capability.supports(Operation::Takeover) => {
            refused(request, undeclared)
        }
        RequestKind::Takeover => match responses.takeover {
            StopAnswer::Refuse => refused(request, &responses.reason),
            _ => accepted(request, StopAnswer::Accept, Effect::TakeOver),
        },
        RequestKind::ReturnControl => accepted(request, StopAnswer::Accept, Effect::ReturnControl),
        RequestKind::Resume => accepted(request, StopAnswer::Accept, Effect::Resume),
        RequestKind::Start => accepted(request, StopAnswer::Accept, Effect::Nothing),
        RequestKind::BudgetExhausted => accepted(request, StopAnswer::Accept, Effect::Pause),
        RequestKind::Change => match request.change {
            Some((policy, version))
                if matches!(policy, ChangePolicy::Interrupt | ChangePolicy::Rollback)
                    && capability.change_policies.contains(&policy) =>
            {
                let mut decision = accepted(request, StopAnswer::Accept, Effect::Nothing);
                decision.response.applied_version = Some(version);
                decision
            }
            _ => refused(request, undeclared),
        },
    }
}

/// The session reference of attempt `attempt` of the commitment `commitment`.
pub(crate) fn session_ref(prefix: &str, commitment: &str, attempt: u32) -> String {
    format!("{prefix}{commitment}:{attempt}")
}

/// A status report (RC-38, RC-42).
pub(crate) fn status(
    state: ExecutionState,
    done: &str,
    need: &str,
    step: Option<&str>,
) -> StatusReport {
    StatusReport {
        status: state,
        done: done.to_owned(),
        need: need.to_owned(),
        step: step.map(str::to_owned),
    }
}

/// The action report of a `write` step, bound to the delivery's single-use authority context
/// and idempotency key (SEC-15), relying on the commitment version it was given.
pub(crate) fn action_report(
    delivery: &CommitmentDelivery,
    session: &str,
    summary: &str,
    external_idempotent: bool,
) -> ProgressReport {
    ProgressReport {
        event: ProgressEvent::Action,
        session: session.to_owned(),
        summary: summary.to_owned(),
        trace: None,
        relies_on: vec![delivery.version],
        binding: Some(Binding {
            authority_context: delivery.authority_context,
            idempotency_key: delivery.idempotency_key.clone(),
            external_idempotent,
        }),
    }
}

/// The error report of a `fail` step.
pub(crate) fn error_report(session: &str, reason: &str) -> ProgressReport {
    ProgressReport {
        event: ProgressEvent::Error,
        session: session.to_owned(),
        summary: reason.to_owned(),
        trace: None,
        relies_on: Vec::new(),
        binding: None,
    }
}

/// An open, closed or failed session (RC-43).
pub(crate) fn session(
    session: &str,
    commitment: Digest,
    attempt: u32,
    outcome: Option<(AttemptOutcome, Option<&str>)>,
) -> SessionReport {
    SessionReport {
        session: session.to_owned(),
        commitment,
        attempt,
        outcome: outcome.map(|(o, _)| o),
        reason: outcome.and_then(|(_, r)| r.map(str::to_owned)),
    }
}

/// A heartbeat; `departing` when the executor leaves on purpose (RC-42, ST-4).
pub(crate) fn heartbeat(session: &str, seq: u64, departing: bool) -> Heartbeat {
    Heartbeat {
        session: session.to_owned(),
        seq,
        departing,
    }
}

/// The control mode, under the lease `lease` while a second driver holds it (RC-32, RC-33).
pub(crate) const fn control_mode(mode: ControlMode, lease: Option<Digest>) -> ControlModeReport {
    ControlModeReport { mode, lease }
}

/// The handover note the executor writes when control comes back (RC-34, CM-45).
pub(crate) fn handover(delivery: &CommitmentDelivery, done: &str, next: &str) -> Handover {
    let or = |text: &str, empty: &str| {
        if text.is_empty() {
            empty.to_owned()
        } else {
            text.to_owned()
        }
    };
    Handover {
        reason: HandoverReason::ControlTransfer.wire_name().to_owned(),
        stateful: true,
        context: vec![delivery.version],
        summary: "control came back to the executor".to_owned(),
        done: or(done, "nothing yet"),
        changed: "the second driver's actions are theirs to report".to_owned(),
        open_questions: "none".to_owned(),
        next_steps: or(next, "the script is complete"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use work_kernel::control::body::Depth;

    use super::*;

    pub(crate) fn capability() -> Capability {
        Capability {
            operations: vec![
                Operation::Cancel,
                Operation::Takeover,
                Operation::PauseResume,
            ],
            stop_types: vec![
                StopType::Pause,
                StopType::Immediate,
                StopType::FinishThenStop,
            ],
            change_policies: vec![ChangePolicy::Interrupt],
            non_cancellable: vec!["deploy".to_owned()],
            safe_state: Some("idle".to_owned()),
            checkpoints: false,
            heartbeat: Some(1000),
            depth: Depth::Full,
        }
    }

    pub(crate) fn responses() -> Responses {
        Responses {
            stop: StopAnswer::Accept,
            pause: StopAnswer::Accept,
            takeover: StopAnswer::Accept,
            reason: "local policy".to_owned(),
        }
    }

    pub(crate) fn delivery() -> CommitmentDelivery {
        CommitmentDelivery {
            commitment: Digest::sha256([1; 32]),
            version: Digest::sha256([2; 32]),
            aim: None,
            criterion: None,
            budget: None,
            change_policy: ChangePolicy::Queue,
            context: Vec::new(),
            authority_context: Digest::sha256([3; 32]),
            idempotency_key: "cmt_x/rec_y".to_owned(),
        }
    }

    fn request(kind: RequestKind, stop_type: Option<StopType>) -> RequestDelivery {
        RequestDelivery {
            record: Digest::sha256([9; 32]),
            kind,
            stop_type,
            change: None,
        }
    }

    fn answer(d: &Decision) -> (StopAnswer, Effect) {
        (d.response.answer, d.effect)
    }

    // RC-36 RC-42 T-105
    #[test]
    fn rc_36_a_stop_is_accepted_finished_then_stopped_or_refused_with_its_reason() {
        let c = capability();
        let r = responses();
        let immediate = request(RequestKind::Stop, Some(StopType::Immediate));
        assert_eq!(
            answer(&decide(&immediate, &c, &r, Some("step-1"))),
            (StopAnswer::Accept, Effect::Stop)
        );
        let controlled = request(RequestKind::Stop, Some(StopType::FinishThenStop));
        assert_eq!(
            answer(&decide(&controlled, &c, &r, None)),
            (StopAnswer::FinishThenStop, Effect::StopAfterStep)
        );
        let pause = request(RequestKind::Stop, Some(StopType::Pause));
        assert_eq!(
            answer(&decide(&pause, &c, &r, None)),
            (StopAnswer::Accept, Effect::Pause)
        );
        let refusing = Responses {
            stop: StopAnswer::Refuse,
            ..responses()
        };
        let no = decide(&immediate, &c, &refusing, None);
        assert_eq!(answer(&no), (StopAnswer::Refuse, Effect::Nothing));
        assert_eq!(no.response.reason.as_deref(), Some("local policy"));
        assert_eq!(no.response.request, immediate.record);
        no.response.encode().unwrap();
        let finishing = Responses {
            stop: StopAnswer::FinishThenStop,
            ..responses()
        };
        assert_eq!(
            answer(&decide(&immediate, &c, &finishing, None)),
            (StopAnswer::FinishThenStop, Effect::StopAfterStep)
        );
    }

    // RC-39 RC-36
    #[test]
    fn rc_39_an_immediate_stop_during_a_non_cancellable_step_applies_after_the_step() {
        let immediate = request(RequestKind::Stop, Some(StopType::Immediate));
        let d = decide(&immediate, &capability(), &responses(), Some("deploy"));
        assert_eq!(
            answer(&d),
            (StopAnswer::FinishThenStop, Effect::StopAfterStep)
        );
        assert!(d.response.reason.is_none());
    }

    // RC-42 RC-36 RC-33
    #[test]
    fn rc_42_only_what_the_capability_declares_is_accepted() {
        let mut c = capability();
        c.stop_types = vec![StopType::Pause];
        c.operations = vec![Operation::PauseResume];
        let r = responses();
        let immediate = request(RequestKind::Stop, Some(StopType::Immediate));
        assert_eq!(
            answer(&decide(&immediate, &c, &r, None)),
            (StopAnswer::Refuse, Effect::Nothing)
        );
        let takeover = request(RequestKind::Takeover, None);
        assert_eq!(
            answer(&decide(&takeover, &c, &r, None)),
            (StopAnswer::Refuse, Effect::Nothing)
        );
        assert_eq!(
            answer(&decide(&takeover, &capability(), &r, None)),
            (StopAnswer::Accept, Effect::TakeOver)
        );
        let refusing = Responses {
            takeover: StopAnswer::Refuse,
            ..responses()
        };
        assert_eq!(
            answer(&decide(&takeover, &capability(), &refusing, None)),
            (StopAnswer::Refuse, Effect::Nothing)
        );
        let back = request(RequestKind::ReturnControl, None);
        assert_eq!(
            answer(&decide(&back, &c, &r, None)),
            (StopAnswer::Accept, Effect::ReturnControl)
        );
        let mut change = request(RequestKind::Change, None);
        change.change = Some((ChangePolicy::Interrupt, 4));
        let applied = decide(&change, &capability(), &r, None);
        assert_eq!(applied.response.applied_version, Some(4));
        change.change = Some((ChangePolicy::Rollback, 5));
        assert_eq!(
            answer(&decide(&change, &capability(), &r, None)),
            (StopAnswer::Refuse, Effect::Nothing)
        );
        let budget = request(RequestKind::BudgetExhausted, None);
        assert_eq!(
            answer(&decide(&budget, &c, &r, None)),
            (StopAnswer::Accept, Effect::Pause)
        );
    }

    // RC-42 T-105
    #[test]
    fn rc_42_a_delivery_is_read_with_the_kernel_decoders() {
        let body = delivery().encode().unwrap();
        let wire = Wire {
            seq: "17".to_owned(),
            kind: "commitment".to_owned(),
            commitment: "cmt_x".to_owned(),
            record: "rec_y".to_owned(),
            body: work_access_client::domain::b64url(&body),
        };
        let d = wire.decode().unwrap();
        assert_eq!(d.seq, 17);
        assert_eq!(d.what, Delivered::Commitment(delivery()));
        let stop = request(RequestKind::Stop, Some(StopType::Pause));
        let as_request = Wire {
            kind: "request".to_owned(),
            body: work_access_client::domain::b64url(&stop.encode().unwrap()),
            ..wire.clone()
        };
        assert_eq!(as_request.decode().unwrap().what, Delivered::Request(stop));
        let crossed = Wire {
            kind: "request".to_owned(),
            ..wire.clone()
        };
        assert!(matches!(crossed.decode(), Err(DeliveryError::Body(_))));
        let other = Wire {
            kind: "doorbell".to_owned(),
            ..wire.clone()
        };
        assert_eq!(other.decode(), Err(DeliveryError::Kind));
        let unpadded = Wire {
            body: "AA==".to_owned(),
            ..wire.clone()
        };
        assert_eq!(unpadded.decode(), Err(DeliveryError::Encoding));
        let seq = Wire {
            seq: "-1".to_owned(),
            ..wire
        };
        assert_eq!(seq.decode(), Err(DeliveryError::Seq));
        let pulled: Pulled = serde_json::from_str(
            r#"{"deliveries":[{"seq":"1","kind":"request","commitment":"cmt_a","record":"rec_b","body":"oA","at":"2026-11-23T10:00:00.000Z"}],"cursor":"1"}"#,
        )
        .unwrap();
        assert_eq!(pulled.cursor, "1");
        assert_eq!(pulled.deliveries.len(), 1);
    }

    // SEC-15 RC-42 RC-43
    #[test]
    fn sec_15_an_action_report_binds_the_delivery_s_context_to_its_key() {
        let d = delivery();
        let s = session_ref("urn:work-executor:session:", "cmt_x", 1);
        let report = action_report(&d, &s, "deployed", false);
        let binding = report.binding.clone().unwrap();
        assert_eq!(binding.authority_context, d.authority_context);
        assert_eq!(binding.idempotency_key, d.idempotency_key);
        assert_eq!(report.relies_on, vec![d.version]);
        let bytes = report.encode().unwrap();
        assert_eq!(ProgressReport::decode(&bytes).unwrap(), report);
        let error = error_report(&s, "the disk is full");
        assert!(error.binding.is_none());
        error.encode().unwrap();
        let open = session(&s, d.commitment, 1, None);
        open.encode().unwrap();
        let failed = super::session(
            &s,
            d.commitment,
            1,
            Some((AttemptOutcome::Failed, Some("the disk is full"))),
        );
        assert_eq!(failed.reason.as_deref(), Some("the disk is full"));
        failed.encode().unwrap();
        heartbeat(&s, 3, true).encode().unwrap();
        status(ExecutionState::Running, "", "", Some("deploy"))
            .encode()
            .unwrap();
        control_mode(ControlMode::Manual, Some(Digest::sha256([9; 32])))
            .encode()
            .unwrap();
        let note = handover(&d, "", "");
        assert_eq!(note.reason, "control_transfer");
        note.encode().unwrap();
    }
}
