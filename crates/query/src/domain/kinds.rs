//! The record kinds a typed write names and the Access action each one takes (E-45 items 2 to 4, C-6, RC-17, RC-42, RC-48): a commitment operation, a responsibility operation, another core Declaration subtype, an executor report Claim by its extension key, another Claim, or an Act; a coordination gate decision and the Work service's own automation records take none, so a caller cannot write them.

use work_kernel::catalog::DeclarationSubtype;
use work_kernel::commitment::{Operation, condition_of};
use work_kernel::control::executor::{
    CAPABILITY_EXT_KEY, CONTROL_MODE_EXT_KEY, HEARTBEAT_EXT_KEY, REPORT_EXT_KEY, SESSION_EXT_KEY,
    STATUS_EXT_KEY,
};
use work_kernel::record::Record;
use work_kernel::responsibility::ResponsibilityOperation;

use crate::domain::commitments::action_of;

/// The extension key of a recorded forced stop, an `observation` Claim whose value is the deterministic CBOR text of its source, `access_revocation` or `enforcement` (RC-37, RC-38).
pub const FORCED_STOP_EXT_KEY: &str = "https://suiss.app/ns/work/executor.forced_stop/1";

/// The extension keys of the executor coordination Claims and of a recorded forced stop (RC-37, RC-42, RC-43).
pub const EXECUTOR_EXT_KEYS: [&str; 7] = [
    CAPABILITY_EXT_KEY,
    STATUS_EXT_KEY,
    CONTROL_MODE_EXT_KEY,
    HEARTBEAT_EXT_KEY,
    REPORT_EXT_KEY,
    SESSION_EXT_KEY,
    FORCED_STOP_EXT_KEY,
];

/// What a record is to a typed write (C-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A commitment operation (§9).
    Commitment(Operation),
    /// A responsibility operation (RC-17).
    Responsibility(ResponsibilityOperation),
    /// Any other core Declaration subtype.
    Declaration(DeclarationSubtype),
    /// A Claim carrying one executor coordination extension key (RC-42).
    Executor(&'static str),
    /// Any other Claim.
    Claim,
    /// An Act.
    Act,
}

/// The executor coordination extension key `record` carries, when it carries exactly one.
#[must_use]
pub fn executor_key(record: &Record) -> Option<&'static str> {
    let mut keys = record
        .core()
        .ext
        .iter()
        .flatten()
        .filter_map(|e| EXECUTOR_EXT_KEYS.into_iter().find(|k| *k == e.key.as_str()));
    let first = keys.next()?;
    keys.next().is_none().then_some(first)
}

/// What `record` is to a typed write.
#[must_use]
pub fn kind_of(record: &Record) -> Option<Kind> {
    match record {
        Record::Declaration(d) => {
            let subtype = DeclarationSubtype::from_uri(d.subtype.as_str())?;
            Some(
                Operation::of(subtype)
                    .map(Kind::Commitment)
                    .or_else(|| ResponsibilityOperation::of(subtype).map(Kind::Responsibility))
                    .unwrap_or(Kind::Declaration(subtype)),
            )
        }
        Record::Claim(_) => Some(executor_key(record).map_or(Kind::Claim, Kind::Executor)),
        Record::Act(_) => Some(Kind::Act),
    }
}

/// The Access action of a responsibility operation (E-45 item 2).
#[must_use]
pub const fn responsibility_action(operation: ResponsibilityOperation) -> &'static str {
    match operation {
        ResponsibilityOperation::Claim
        | ResponsibilityOperation::Unclaim
        | ResponsibilityOperation::RenewLease => "claim",
        ResponsibilityOperation::Forward
        | ResponsibilityOperation::Nominate
        | ResponsibilityOperation::Offer
        | ResponsibilityOperation::Reassign => "assign",
    }
}

/// The Access action of a core Declaration subtype that is neither a commitment nor a responsibility operation (E-45 items 2 and 4, RC-48); `None` for a coordination gate decision, which takes no action, and for one Work writes only as its own.
#[must_use]
pub const fn declaration_action(subtype: DeclarationSubtype) -> Option<&'static str> {
    Some(match subtype {
        DeclarationSubtype::QueueDefinition => "assign",
        DeclarationSubtype::OrgRule => "org_rule_set",
        DeclarationSubtype::Acknowledgement
        | DeclarationSubtype::OpenCondition
        | DeclarationSubtype::WithdrawCondition
        | DeclarationSubtype::AttentionRequest => "condition",
        DeclarationSubtype::StopRequest | DeclarationSubtype::ResumeAfterStop => "stop_request",
        DeclarationSubtype::StopResponse => "stop_respond",
        DeclarationSubtype::ControlLease
        | DeclarationSubtype::HandoffNote
        | DeclarationSubtype::ConflictResolution => "control",
        DeclarationSubtype::AutonomyPolicy
        | DeclarationSubtype::Waiver
        | DeclarationSubtype::ImplicitAcceptanceTerms => "autonomy_policy_set",
        DeclarationSubtype::PracticeAdoption => "practice_adopt",
        DeclarationSubtype::Disclosure => "disclose",
        DeclarationSubtype::Admission => "admit",
        DeclarationSubtype::Redact => "redact",
        DeclarationSubtype::Aim => "write",
        _ => return None,
    })
}

/// The Access action a caller's `record` takes (E-45 items 2 to 4): a clock, periodic or budget Condition is part of a commitment's terms and takes `work:commit` (WD-146), every Claim and Act `work:write`.
#[must_use]
pub fn record_action(record: &Record) -> Option<&'static str> {
    if condition_of(record).is_some() {
        return Some("commit");
    }
    match kind_of(record)? {
        Kind::Commitment(op) => action_of(op),
        Kind::Responsibility(op) => Some(responsibility_action(op)),
        Kind::Declaration(subtype) => declaration_action(subtype),
        Kind::Executor(_) | Kind::Claim | Kind::Act => Some("write"),
    }
}

#[cfg(test)]
mod tests;
