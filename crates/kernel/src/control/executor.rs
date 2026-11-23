//! The executor coordination contract (RC-41 … RC-43, SEC-15, OP-4): one executor, two contracts, and the Access executor service binds through the same Work contract as any customer executor, so only the executor assigned to the work counts and no identity has a privileged path; each contract element travels as a record of a fixed kind, capability, plan and act stay separate, an execution session is a first-class Reference whose attempts are grouped with their outcomes and reasons kept, a consequential execution binds a single-use authority context to one idempotency key, an external effect is claimed to happen once only when the external system honours the key, and a record is `acted upon` once the executor reports an Act relying on it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::catalog::ClaimSubtype;
use crate::control::axis::Reported;
use crate::control::body::{AttemptOutcome, ProgressEvent, ProgressReport, SessionReport};
use crate::id::{Digest, PartyRef, RecordId};
use crate::reason::wire_enum;
use crate::record::Kind;

/// The extension key of a capability declaration Claim (RC-42).
pub const CAPABILITY_EXT_KEY: &str = "https://suiss.app/ns/work/executor.capability/1";

/// The extension key of a status report Claim (RC-42).
pub const STATUS_EXT_KEY: &str = "https://suiss.app/ns/work/executor.status/1";

/// The extension key of a control mode Claim (RC-32, RC-42).
pub const CONTROL_MODE_EXT_KEY: &str = "https://suiss.app/ns/work/executor.control_mode/1";

/// The extension key of a heartbeat Claim (RC-42).
pub const HEARTBEAT_EXT_KEY: &str = "https://suiss.app/ns/work/executor.heartbeat/1";

/// The extension key of an act or claim report (RC-42).
pub const REPORT_EXT_KEY: &str = "https://suiss.app/ns/work/executor.report/1";

/// The extension key of an execution session Claim (RC-43).
pub const SESSION_EXT_KEY: &str = "https://suiss.app/ns/work/executor.session/1";

/// The body part every contract element travels in.
pub const CONTRACT_PART: &str = "definition";

/// The record kind and Claim subtype a report of `event` travels as (RC-42, RC-43, C-38): an action is an Act, a plan update an `assumption` Claim, everything else an `observation` Claim.
#[must_use]
pub const fn report_record(event: ProgressEvent) -> (Kind, Option<ClaimSubtype>) {
    match event {
        ProgressEvent::Action => (Kind::Act, None),
        ProgressEvent::PlanUpdate => (Kind::Claim, Some(ClaimSubtype::Assumption)),
        ProgressEvent::Question
        | ProgressEvent::Answer
        | ProgressEvent::Error
        | ProgressEvent::RationaleSummary => (Kind::Claim, Some(ClaimSubtype::Observation)),
    }
}

/// The reports that count: those by an executor assigned to the work, whoever runs it (RC-41).
#[must_use]
pub fn counted<'r, T>(reports: &'r [Reported<T>], executors: &[PartyRef]) -> Vec<&'r Reported<T>> {
    reports
        .iter()
        .filter(|r| executors.contains(&r.author))
        .collect()
}

/// One execution attempt of a commitment, grouped by its session Reference (RC-43).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// The session Reference.
    pub session: String,
    /// The attempt number.
    pub attempt: u32,
    /// How it ended, once it has.
    pub outcome: Option<AttemptOutcome>,
    /// Why it failed or was abandoned.
    pub reason: Option<String>,
    /// The session records, in ledger order.
    pub records: Vec<RecordId>,
}

/// The attempts of the commitment `commitment` from the executors' session Claims (RC-43, ST-5): one per session Reference in attempt order, the latest report of a session giving its outcome, every past attempt and its reason kept.
#[must_use]
pub fn attempts(
    commitment: &Digest,
    sessions: &[Reported<SessionReport>],
    executors: &[PartyRef],
) -> Vec<Attempt> {
    let mut out: Vec<Attempt> = Vec::new();
    for r in counted(sessions, executors) {
        if &r.body.commitment != commitment {
            continue;
        }
        if let Some(a) = out.iter_mut().find(|a| a.session == r.body.session) {
            a.records.push(r.record);
            if r.body.outcome.is_some() {
                a.outcome = r.body.outcome;
                a.reason.clone_from(&r.body.reason);
            }
        } else {
            out.push(Attempt {
                session: r.body.session.clone(),
                attempt: r.body.attempt,
                outcome: r.body.outcome,
                reason: r.body.reason.clone(),
                records: alloc::vec![r.record],
            });
        }
    }
    out.sort_by_key(|a| a.attempt);
    out
}

wire_enum! {
    /// How a consequential execution stands against the authority contexts already used (SEC-15).
    SingleUse {
        /// A context not used before.
        Fresh => "fresh",
        /// The same context with the same key: a replay of the same execution, with no new effect.
        Replay => "replay",
    }
}

wire_enum! {
    /// Why a consequential execution is refused (SEC-15).
    SingleUseRefusal {
        /// The authority context was used with another idempotency key.
        ContextReused => "context_reused",
        /// The idempotency key was used with another authority context.
        KeyReused => "key_reused",
    }
}

/// One binding of an authority context to an idempotency key (SEC-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Use<'a> {
    /// The single-use authority context.
    pub context: &'a Digest,
    /// The idempotency key.
    pub key: &'a str,
}

/// Checks a consequential execution against the bindings already used (SEC-15): an authority context binds exactly one idempotency key and a key exactly one context.
///
/// # Errors
/// The [`SingleUseRefusal`].
pub fn check_single_use(used: &[Use<'_>], new: Use<'_>) -> Result<SingleUse, SingleUseRefusal> {
    for u in used {
        match (u.context == new.context, u.key == new.key) {
            (true, true) => return Ok(SingleUse::Replay),
            (true, false) => return Err(SingleUseRefusal::ContextReused),
            (false, true) => return Err(SingleUseRefusal::KeyReused),
            (false, false) => {}
        }
    }
    Ok(SingleUse::Fresh)
}

wire_enum! {
    /// What a report may claim about how often its external effect happened (SEC-15).
    EffectGuarantee {
        /// Once, because the external system honours the idempotency key.
        Once => "once",
        /// Not claimed: the external system does not honour the key.
        Unclaimed => "unclaimed",
    }
}

/// What an action report may claim about its external effect (SEC-15); a report that is not an action claims nothing.
#[must_use]
pub fn effect_guarantee(report: &ProgressReport) -> EffectGuarantee {
    match &report.binding {
        Some(b) if b.external_idempotent => EffectGuarantee::Once,
        Some(_) | None => EffectGuarantee::Unclaimed,
    }
}

/// The first Act report of an assigned executor relying on `record`, which makes it `acted upon` (OP-4).
#[must_use]
pub fn acted_upon(
    record: &RecordId,
    reports: &[Reported<ProgressReport>],
    executors: &[PartyRef],
) -> Option<RecordId> {
    counted(reports, executors)
        .into_iter()
        .find(|r| r.body.event == ProgressEvent::Action && r.body.relies_on.contains(&record.0))
        .map(|r| r.record)
}
