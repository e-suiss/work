//! The record kinds a typed write names and the Access action each one takes (E-45 items 2 to 4, C-6, RC-17, RC-42, RC-48): a commitment operation, a responsibility operation, another core Declaration subtype, an executor report Claim by its extension key, another Claim, or an Act; a coordination gate decision and the Work service's own automation records take none, so a caller cannot write them.

use suiss_crypto::dcbor::{self, Limits, Value};
use work_kernel::catalog::DeclarationSubtype;
use work_kernel::codec::{Decoded, decode_record};
use work_kernel::commitment::{Operation, condition_of};
use work_kernel::control::executor::{
    CAPABILITY_EXT_KEY, CONTROL_MODE_EXT_KEY, HEARTBEAT_EXT_KEY, REPORT_EXT_KEY, SESSION_EXT_KEY,
    STATUS_EXT_KEY,
};
use work_kernel::cose::parse_container;
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

/// The extension key of an agent ceiling decision (E-23): an `acknowledgement` carrying it decides on an `agent.ceiling_exceeded` event.
pub const CEILING_EXT_KEY: &str = "https://suiss.app/ns/work/agent-ceiling-decision/1";

/// The Access action of an agent ceiling decision (E-23, E-45).
pub const CEILING_ACTION: &str = "agent_ceiling_decide";

/// Longest Relay event id a decision names, in bytes.
pub const MAX_CEILING_EVENT: usize = 512;

/// Longest agent id a decision names, in bytes.
pub const MAX_CEILING_AGENT: usize = 256;

/// What Work decides on an agent's notification ceiling (E-23, Relay AG-49).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeilingChoice {
    /// Send everything Relay holds.
    SendAll,
    /// Cancel what Relay holds.
    Cancel,
    /// Stop the agent.
    Stop,
}

impl CeilingChoice {
    /// Every choice.
    pub const ALL: [Self; 3] = [Self::SendAll, Self::Cancel, Self::Stop];

    /// The wire name, as Relay's `decision` spells it.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SendAll => "send_all",
            Self::Cancel => "cancel",
            Self::Stop => "stop",
        }
    }

    /// The choice of `name`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.wire_name() == name)
    }
}

/// An agent ceiling decision read from its record (E-23).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeilingDecision {
    /// The decision.
    pub decision: CeilingChoice,
    /// The `id` of the `agent.ceiling_exceeded` event it answers.
    pub event: String,
    /// The agent, `agt_…`.
    pub agent: String,
}

fn bounded_text(entries: &[(Value, Value)], name: &str, most: usize) -> Option<String> {
    entries.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(k), Value::Text(t)) if k == name && !t.is_empty() && t.len() <= most => {
            Some(t.clone())
        }
        _ => None,
    })
}

/// The ceiling decision `record` is: a core `acknowledgement` carrying exactly one [`CEILING_EXT_KEY`] extension, not critical, whose value is the map `{decision, event, agent}` and nothing else (E-23).
#[must_use]
pub fn ceiling_decision(record: &Record) -> Option<CeilingDecision> {
    let Record::Declaration(d) = record else {
        return None;
    };
    if DeclarationSubtype::from_uri(d.subtype.as_str()) != Some(DeclarationSubtype::Acknowledgement)
    {
        return None;
    }
    let core = record.core();
    if core
        .critical
        .iter()
        .flatten()
        .any(|k| k.as_str() == CEILING_EXT_KEY)
    {
        return None;
    }
    let mut found = core
        .ext
        .iter()
        .flatten()
        .filter(|e| e.key.as_str() == CEILING_EXT_KEY);
    let ext = found.next()?;
    if found.next().is_some() {
        return None;
    }
    let Ok(Value::Map(entries)) = dcbor::decode(&ext.value.0, Limits::CEILING) else {
        return None;
    };
    let known = ["decision", "event", "agent"];
    if entries.len() != known.len()
        || !entries
            .iter()
            .all(|(k, _)| matches!(k, Value::Text(t) if known.contains(&t.as_str())))
    {
        return None;
    }
    Some(CeilingDecision {
        decision: CeilingChoice::from_wire_name(&bounded_text(&entries, "decision", 16)?)?,
        event: bounded_text(&entries, "event", MAX_CEILING_EVENT)?,
        agent: bounded_text(&entries, "agent", MAX_CEILING_AGENT)?,
    })
}

/// The ceiling decision a write carries: `record` is the `SignedRecord` bytes of an `unsigned` record or the tagged `COSE_Sign1` of a signed one (E-23).
#[must_use]
pub fn carried_ceiling(record: &[u8], unsigned: bool) -> Option<CeilingDecision> {
    let payload = if unsigned {
        record.to_vec()
    } else {
        parse_container(record).ok()?.payload?
    };
    match decode_record(&payload).ok()? {
        Decoded::Record(r) => ceiling_decision(&r),
        Decoded::UnknownProtocol(_) => None,
    }
}

/// The Access action a caller's `record` takes (E-45 items 2 to 4): a clock, periodic or budget Condition is part of a commitment's terms and takes `work:commit` (WD-146), an agent ceiling decision `work:agent_ceiling_decide` (E-23), every Claim and Act `work:write`.
#[must_use]
pub fn record_action(record: &Record) -> Option<&'static str> {
    if condition_of(record).is_some() {
        return Some("commit");
    }
    if ceiling_decision(record).is_some() {
        return Some(CEILING_ACTION);
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
