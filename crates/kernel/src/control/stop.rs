//! Stop requests (RC-36 … RC-40, E-28): a stop is a request carrying its type (`immediate`, `finish_then_stop`, `pause`), the doer answers with a `stop_response` (`accept`, `finish_then_stop`, or `refuse` with its reason) and the request reads pending until then; request, answer, forced stop and the executor's "stopped" confirmation are separate records and only the executor's Claim shows a stop, otherwise the stop state is unknown; a refusal reaches the requester's and the principal's attention and an unanswered or refused request shows the principal the Access revocation path; a step the capability declares non-cancellable finishes before the stop applies; resuming takes its own `resume_after_stop` Declaration, never happens by itself, and a correction's version only grows.

use alloc::string::String;
use alloc::vec::Vec;

use crate::catalog::{DeclarationSubtype, StopAnswer, StopType};
use crate::control::axis::{Reported, latest};
use crate::control::body::{Capability, ExecutionState, StatusReport, parent_code};
use crate::id::{PartyRef, RecordId, Time};
use crate::reason::wire_enum;
use crate::record::{ParamScalar, ParamValue, Record};

fn subtype(record: &Record) -> Option<DeclarationSubtype> {
    match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str()),
        Record::Act(_) | Record::Claim(_) => None,
    }
}

fn code<'r>(record: &'r Record, name: &str) -> Option<&'r str> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Text(t)) => Some(parent_code(t)),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

/// The stop type of a `stop_request` Declaration (RC-36, P-85).
#[must_use]
pub fn stop_type_of(record: &Record) -> Option<StopType> {
    if subtype(record) != Some(DeclarationSubtype::StopRequest) {
        return None;
    }
    code(record, "stop_type").and_then(StopType::from_wire_name)
}

/// The answer of a `stop_response` Declaration (RC-36, P-84, P-85).
#[must_use]
pub fn answer_of(record: &Record) -> Option<StopAnswer> {
    if subtype(record) != Some(DeclarationSubtype::StopResponse) {
        return None;
    }
    code(record, "response").and_then(StopAnswer::from_wire_name)
}

fn has_note(record: &Record) -> bool {
    record
        .core()
        .body
        .iter()
        .flatten()
        .any(|b| b.part.as_str() == "note")
}

wire_enum! {
    /// Why a `stop_response` does not answer a stop request (RC-36, RC-38).
    ResponseRefusal {
        /// The record is not a `stop_response` Declaration.
        NotAResponse => "not_a_response",
        /// Only the doer answers.
        NotDoer => "not_doer",
        /// The basis does not cite exactly one stop request.
        Uncited => "uncited",
        /// A refusal carries its reason in the `note` body part.
        Unreasoned => "unreasoned",
    }
}

/// Checks a `stop_response` against the stop requests `requests` (RC-36, RC-38): written by the doer `executor`, citing one request in its basis, a refusal with its reason.
///
/// # Errors
/// The [`ResponseRefusal`].
pub fn check_response(
    record: &Record,
    requests: &[(RecordId, &Record)],
    executor: &PartyRef,
) -> Result<(), ResponseRefusal> {
    let answer = answer_of(record).ok_or(ResponseRefusal::NotAResponse)?;
    if &record.core().author != executor {
        return Err(ResponseRefusal::NotDoer);
    }
    let cited = requests
        .iter()
        .filter(|(id, r)| record.basis().contains(id) && stop_type_of(r).is_some())
        .count();
    if cited != 1 {
        return Err(ResponseRefusal::Uncited);
    }
    if answer == StopAnswer::Refuse && !has_note(record) {
        return Err(ResponseRefusal::Unreasoned);
    }
    Ok(())
}

wire_enum! {
    /// Why a `resume_after_stop` does not resume (RC-40).
    ResumeRefusal {
        /// The record is not a `resume_after_stop` Declaration.
        NotAResume => "not_a_resume",
        /// The basis cites no stop request.
        Uncited => "uncited",
    }
}

/// Checks a `resume_after_stop` Declaration (RC-40): it cites the stop request it lifts in its basis.
///
/// # Errors
/// The [`ResumeRefusal`].
pub fn check_resume(
    record: &Record,
    requests: &[(RecordId, &Record)],
) -> Result<(), ResumeRefusal> {
    if subtype(record) != Some(DeclarationSubtype::ResumeAfterStop) {
        return Err(ResumeRefusal::NotAResume);
    }
    let cited = requests
        .iter()
        .any(|(id, r)| record.basis().contains(id) && stop_type_of(r).is_some());
    if cited {
        Ok(())
    } else {
        Err(ResumeRefusal::Uncited)
    }
}

wire_enum! {
    /// Where a recorded forced stop comes from; Work only records it (RC-37).
    ForceSource {
        /// Access revoked the authority.
        AccessRevocation => "access_revocation",
        /// The executor or its policy enforcement point enforced it.
        Enforcement => "enforcement",
    }
}

wire_enum! {
    /// How the doer answered a stop request (RC-36).
    StopProgress {
        /// No answer yet.
        Pending => "pending",
        /// Accepted: stopped or stopping.
        Accepted => "accepted",
        /// The doer finishes, then stops.
        FinishingThenStop => "finishing_then_stop",
        /// Refused with a reason.
        Refused => "refused",
    }
}

wire_enum! {
    /// Whether the stop is confirmed; only the executor's Claim confirms it (RC-38).
    StopState {
        /// The executor confirmed it.
        Confirmed => "confirmed",
        /// No confirmation.
        Unknown => "unknown",
    }
}

/// When a stop applies (RC-39).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopTiming {
    /// At once.
    Now,
    /// After this non-cancellable step finishes.
    AfterStep(String),
}

/// When a stop applies while the executor runs `step` (RC-39): a step the capability declares non-cancellable finishes first, whatever the stop type.
#[must_use]
pub fn stop_timing(step: Option<&str>, capability: Option<&Capability>) -> StopTiming {
    match (step, capability) {
        (Some(s), Some(c)) if c.non_cancellable.iter().any(|n| n.as_str() == s) => {
            StopTiming::AfterStep(String::from(s))
        }
        _ => StopTiming::Now,
    }
}

/// One stop request as derived from its separate records (RC-36 … RC-40).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopView {
    /// The `stop_request` record.
    pub request: RecordId,
    /// Who asked.
    pub requester: PartyRef,
    /// The stop type.
    pub stop_type: StopType,
    /// The doer's answer.
    pub progress: StopProgress,
    /// The latest `stop_response` of the doer.
    pub response: Option<RecordId>,
    /// The executor's confirming status Claim.
    pub confirmation: Option<RecordId>,
    /// Confirmed only by that Claim.
    pub state: StopState,
    /// The first forced stop recorded after the request.
    pub forced: Option<RecordId>,
    /// When the stop applies.
    pub timing: StopTiming,
    /// Who must see a refusal: the requester and the principal.
    pub attention: Vec<PartyRef>,
    /// Whether the principal is shown the Access revocation path: the request is unanswered or refused and unconfirmed (E-28).
    pub revocation_path: bool,
    /// The `resume_after_stop` that lifts it.
    pub resumed: Option<RecordId>,
    /// The executor reported running after the confirmed stop without a `resume_after_stop` (RC-40).
    pub restarted_without_resume: bool,
}

/// The records and Claims stop requests are derived from.
#[derive(Clone, Copy, Debug)]
pub struct StopFacts<'a> {
    /// The Declarations of the execution in ledger order with their ledger times.
    pub records: &'a [(RecordId, Time, &'a Record)],
    /// The doer.
    pub executor: &'a PartyRef,
    /// The principal.
    pub principal: &'a PartyRef,
    /// The executor's capability declaration.
    pub capability: Option<&'a Capability>,
    /// The executor's status Claims.
    pub status: &'a [Reported<StatusReport>],
    /// Forced stops recorded from Access or the executor.
    pub forced: &'a [Reported<ForceSource>],
}

fn confirms(stop_type: StopType, state: ExecutionState) -> bool {
    match stop_type {
        StopType::Pause => matches!(state, ExecutionState::Paused | ExecutionState::Stopped),
        StopType::Immediate | StopType::FinishThenStop => state == ExecutionState::Stopped,
    }
}

/// Derives every stop request at `now` (RC-36 … RC-40, E-28).
#[must_use]
pub fn stops(facts: &StopFacts<'_>, now: Time) -> Vec<StopView> {
    let current = latest(facts.status, facts.executor, now);
    let step = current.and_then(|r| r.body.step.as_deref());
    let mut out = Vec::new();
    for (id, at, record) in facts.records {
        if *at > now {
            continue;
        }
        let Some(stop_type) = stop_type_of(record) else {
            continue;
        };
        let cites = |r: &Record| r.basis().contains(id);
        let response = facts.records.iter().rev().find(|(_, t, r)| {
            *t <= now && &r.core().author == facts.executor && cites(r) && answer_of(r).is_some()
        });
        let progress = match response.and_then(|(_, _, r)| answer_of(r)) {
            None => StopProgress::Pending,
            Some(StopAnswer::Accept) => StopProgress::Accepted,
            Some(StopAnswer::FinishThenStop) => StopProgress::FinishingThenStop,
            Some(StopAnswer::Refuse) => StopProgress::Refused,
        };
        let confirmation = facts.status.iter().find(|s| {
            &s.author == facts.executor
                && s.at >= *at
                && s.at <= now
                && confirms(stop_type, s.body.status)
        });
        let forced = facts
            .forced
            .iter()
            .find(|f| f.at >= *at && f.at <= now)
            .map(|f| f.record);
        let resumed = facts
            .records
            .iter()
            .find(|(_, t, r)| {
                *t <= now && subtype(r) == Some(DeclarationSubtype::ResumeAfterStop) && cites(r)
            })
            .map(|(rid, _, _)| *rid);
        let restarted_without_resume = resumed.is_none()
            && confirmation.is_some_and(|c| {
                facts.status.iter().any(|s| {
                    &s.author == facts.executor
                        && s.at >= c.at
                        && s.at <= now
                        && s.record != c.record
                        && s.body.status == ExecutionState::Running
                })
            });
        let requester = record.core().author.clone();
        let mut attention = Vec::new();
        if progress == StopProgress::Refused {
            attention.push(requester.clone());
            if facts.principal != &requester {
                attention.push(facts.principal.clone());
            }
        }
        out.push(StopView {
            request: *id,
            requester,
            stop_type,
            progress,
            response: response.map(|(rid, _, _)| *rid),
            confirmation: confirmation.map(|c| c.record),
            state: if confirmation.is_some() {
                StopState::Confirmed
            } else {
                StopState::Unknown
            },
            forced,
            timing: stop_timing(step, facts.capability),
            attention,
            revocation_path: confirmation.is_none()
                && matches!(progress, StopProgress::Pending | StopProgress::Refused),
            resumed,
            restarted_without_resume,
        });
    }
    out
}

wire_enum! {
    /// Why an operator correction is refused (RC-40).
    CorrectionRefusal {
        /// The version does not grow.
        NotMonotonic => "not_monotonic",
    }
}

/// Checks that a correction's version grows past the previous one (RC-40).
///
/// # Errors
/// [`CorrectionRefusal::NotMonotonic`].
pub fn check_correction(previous: Option<u64>, next: u64) -> Result<(), CorrectionRefusal> {
    if previous.is_some_and(|p| next <= p) || next == 0 {
        Err(CorrectionRefusal::NotMonotonic)
    } else {
        Ok(())
    }
}
