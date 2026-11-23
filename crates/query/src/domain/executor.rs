//! The executor coordination rules a write applies besides the kernel's (RC-41, RC-42, RC-43, T-105, E-39, SEC-15, OP-4): a record names its commitment through what it continues, cites or references; only the obligor in force is the executor and only its reports count; each contract element travels as a record of its fixed kind with its `work/control/1` body in the `definition` part; a record that binds the commitment to an obligor Party delivers it the commitment, and a stop request, a control lease, a resume after a stop and a correction deliver it a request; an action report binds its authority context to one idempotency key.

use std::collections::BTreeMap;

use work_kernel::catalog::{ChangePolicy, ClaimSubtype, DeclarationSubtype};
use work_kernel::commitment::CommitmentView;
use work_kernel::control::body::{
    Capability, CommitmentDelivery, ControlBodyError, ControlLease, ControlModeReport, Handover,
    Heartbeat, ProgressReport, RequestDelivery, RequestKind, RequestResponse, SessionReport,
    StatusReport,
};
use work_kernel::control::executor::{
    CAPABILITY_EXT_KEY, CONTROL_MODE_EXT_KEY, HEARTBEAT_EXT_KEY, REPORT_EXT_KEY, SESSION_EXT_KEY,
    STATUS_EXT_KEY, report_record,
};
use work_kernel::control::stop::{answer_of, stop_type_of};
use work_kernel::id::{PartyRef, RecordId};
use work_kernel::ontology::Obligor;
use work_kernel::record::{ClaimType, Record};
use work_kernel::relation::{ReferenceTarget, Relation};
use work_proto::id::{CommitmentId, ExternalId as _};

use crate::domain::kinds::{Kind, kind_of};

/// The most context references a commitment delivery carries (RC-42, E-39).
pub const MAX_CONTEXT: usize = 256;

/// The records `record` points at: those it continues, those it cites and those it references.
fn targets(record: &Record) -> Vec<RecordId> {
    let mut out: Vec<RecordId> = record.supersedes().copied().collect();
    out.extend(record.basis().iter().copied());
    out.extend(
        record
            .core()
            .relations
            .iter()
            .flatten()
            .filter_map(|r| match r {
                Relation::References {
                    target: ReferenceTarget::Record(target),
                    ..
                } => Some(*target),
                _ => None,
            }),
    );
    out
}

/// The commitment, by its `request`, that `record` names among `views`: one it continues, cites
/// or references, or one a record it cites or references names that way.
#[must_use]
pub fn named(
    views: &[CommitmentView],
    records: &BTreeMap<RecordId, &Record>,
    record: &Record,
) -> Option<RecordId> {
    let direct = |r: &Record| {
        targets(r)
            .into_iter()
            .find_map(|t| views.iter().find(|v| v.continues(&t)).map(|v| v.root))
    };
    direct(record).or_else(|| {
        targets(record)
            .into_iter()
            .filter_map(|t| records.get(&t))
            .find_map(|r| direct(r))
    })
}

/// The executor of `view`: the obligor in force when it is a Party (RC-41).
#[must_use]
pub const fn executor_of(view: &CommitmentView) -> Option<&PartyRef> {
    match &view.obligor {
        Obligor::Party(p) => Some(p),
        Obligor::Queue(_) => None,
    }
}

/// The contract element a record carries (RC-42, RC-43).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Element {
    /// A capability declaration Claim.
    Capability,
    /// A status report Claim.
    Status,
    /// A control mode Claim.
    ControlMode,
    /// A heartbeat Claim.
    Heartbeat,
    /// An execution session Claim.
    Session,
    /// An act or claim report.
    Report,
    /// A `stop_response` Declaration.
    StopResponse,
    /// A `handoff_note` Declaration written on the executor contract.
    Handover,
    /// An `observation` Claim answering a request that is not a stop, written on the executor
    /// contract.
    RequestResponse,
}

fn carries(record: &Record, key: &str) -> bool {
    record
        .core()
        .ext
        .iter()
        .flatten()
        .any(|e| e.key.as_str() == key)
}

/// The element `record` carries: every executor Claim, an Act carrying the report extension key
/// and a `stop_response` wherever they are written; a `handoff_note` and an `observation`
/// Claim only on the executor contract (`contract`).
#[must_use]
pub fn element_of(record: &Record, contract: bool) -> Option<Element> {
    match kind_of(record)? {
        Kind::Executor(key) => Some(match key {
            CAPABILITY_EXT_KEY => Element::Capability,
            STATUS_EXT_KEY => Element::Status,
            CONTROL_MODE_EXT_KEY => Element::ControlMode,
            HEARTBEAT_EXT_KEY => Element::Heartbeat,
            SESSION_EXT_KEY => Element::Session,
            _ => Element::Report,
        }),
        Kind::Act if carries(record, REPORT_EXT_KEY) => Some(Element::Report),
        Kind::Declaration(DeclarationSubtype::StopResponse) => Some(Element::StopResponse),
        Kind::Declaration(DeclarationSubtype::HandoffNote) if contract => Some(Element::Handover),
        Kind::Claim
            if contract
                && matches!(record, Record::Claim(c) if c.subtype == ClaimType::Core(ClaimSubtype::Observation)) =>
        {
            Some(Element::RequestResponse)
        }
        _ => None,
    }
}

/// Why an executor write is refused, each as its `422 record_rejected` reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorRefusal {
    /// The author is not the executor assigned to the work (RC-41).
    NotExecutor,
    /// The record names no commitment, or another one than the route.
    Commitment,
    /// The `definition` body does not decode, naming the member.
    Definition(&'static str),
    /// A `control` rule refused it: a stop response or a single-use binding.
    Control(&'static str),
}

impl ExecutorRefusal {
    /// The reason, `<family>:<code>`.
    #[must_use]
    pub fn reason(self) -> String {
        match self {
            Self::NotExecutor => "control:not_executor".to_owned(),
            Self::Commitment => "control:commitment".to_owned(),
            Self::Definition(member) => format!("definition:{member}"),
            Self::Control(code) => format!("control:{code}"),
        }
    }
}

fn body<T>(
    definition: Option<&[u8]>,
    decode: impl Fn(&[u8]) -> Result<T, ControlBodyError>,
) -> Result<T, ExecutorRefusal> {
    let bytes = definition.ok_or(ExecutorRefusal::Definition("body"))?;
    decode(bytes).map_err(|e| ExecutorRefusal::Definition(e.0))
}

/// The action report's binding and the records it relies on, the only element a write keeps
/// beside its record (SEC-15, OP-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionBinding {
    /// The single-use authority context.
    pub authority: [u8; 32],
    /// The idempotency key.
    pub key: String,
    /// The records relied on, ascending.
    pub relies_on: Vec<[u8; 32]>,
}

/// Checks the `definition` body `definition` of `element` carried by `record` on the
/// commitment `commitment` (RC-42, RC-43): it decodes as the element's `work/control/1` rule,
/// a report travels as the record kind its event takes, a session names the commitment, and a
/// response names the request it cites; a `stop_response` may carry its answer as a body, which
/// then agrees with its parameters. An action report gives its binding.
///
/// # Errors
/// [`ExecutorRefusal::Definition`] naming the member.
pub fn check_body(
    element: Element,
    record: &Record,
    commitment: &RecordId,
    definition: Option<&[u8]>,
) -> Result<Option<ActionBinding>, ExecutorRefusal> {
    match element {
        Element::Capability => body(definition, Capability::decode).map(|_| None),
        Element::Status => body(definition, StatusReport::decode).map(|_| None),
        Element::ControlMode => body(definition, ControlModeReport::decode).map(|_| None),
        Element::Heartbeat => body(definition, Heartbeat::decode).map(|_| None),
        Element::Handover => body(definition, Handover::decode).map(|_| None),
        Element::Session => {
            let session = body(definition, SessionReport::decode)?;
            if session.commitment != commitment.0 {
                return Err(ExecutorRefusal::Definition("commitment"));
            }
            Ok(None)
        }
        Element::Report => {
            let report = body(definition, ProgressReport::decode)?;
            let (kind, subtype) = report_record(report.event);
            let fits = record.kind() == kind
                && match (record, subtype) {
                    (Record::Claim(c), Some(s)) => c.subtype == ClaimType::Core(s),
                    (Record::Act(_), None) => true,
                    _ => false,
                };
            if !fits {
                return Err(ExecutorRefusal::Definition("event"));
            }
            Ok(report.binding.map(|b| ActionBinding {
                authority: *b.authority_context.as_bytes(),
                key: b.idempotency_key,
                relies_on: report.relies_on.iter().map(|d| *d.as_bytes()).collect(),
            }))
        }
        Element::RequestResponse => {
            let response = body(definition, RequestResponse::decode)?;
            if !record.basis().contains(&RecordId(response.request)) {
                return Err(ExecutorRefusal::Definition("request"));
            }
            Ok(None)
        }
        Element::StopResponse => {
            let Some(bytes) = definition else {
                return Ok(None);
            };
            let response =
                RequestResponse::decode(bytes).map_err(|e| ExecutorRefusal::Definition(e.0))?;
            if !record.basis().contains(&RecordId(response.request)) {
                return Err(ExecutorRefusal::Definition("request"));
            }
            if answer_of(record) != Some(response.answer) {
                return Err(ExecutorRefusal::Definition("answer"));
            }
            Ok(None)
        }
    }
}

/// The request a Declaration delivers to the executor (RC-36, RC-33, RC-40, RC-42): a stop
/// with its type, a control lease grant as a takeover and its release as a return of control,
/// a resume after a stop; `definition` is the record's opened `definition` part. A record whose
/// parameters or body do not say what it asks delivers nothing.
#[must_use]
pub fn request_of(
    record: &Record,
    id: RecordId,
    definition: Option<&[u8]>,
) -> Option<RequestDelivery> {
    let Kind::Declaration(subtype) = kind_of(record)? else {
        return None;
    };
    let (kind, stop_type) = match subtype {
        DeclarationSubtype::StopRequest => (RequestKind::Stop, Some(stop_type_of(record)?)),
        DeclarationSubtype::ControlLease => match ControlLease::decode(definition?).ok()? {
            ControlLease::Grant { .. } => (RequestKind::Takeover, None),
            ControlLease::Release { .. } => (RequestKind::ReturnControl, None),
        },
        DeclarationSubtype::ResumeAfterStop => (RequestKind::Resume, None),
        _ => return None,
    };
    Some(RequestDelivery {
        record: id.0,
        kind,
        stop_type,
        change: None,
    })
}

/// The change a record delivers when it raises the instruction version of a commitment whose
/// change policy is a correction (RC-40, CM-56, CM-57); a `queue` or `reject` policy waits for
/// the executor to read the commitment.
#[must_use]
pub fn change_of(
    before: &CommitmentView,
    after: &CommitmentView,
    id: RecordId,
) -> Option<RequestDelivery> {
    let policy = after.terms.change_policy;
    if after.instruction_version <= before.instruction_version
        || !matches!(policy, ChangePolicy::Interrupt | ChangePolicy::Rollback)
    {
        return None;
    }
    Some(RequestDelivery {
        record: id.0,
        kind: RequestKind::Change,
        stop_type: None,
        change: Some((policy, u64::from(after.instruction_version))),
    })
}

/// The Party record `id` binds the commitment to, when the fold with it applied holds the work
/// by `id` and did not before (RC-42, RC-18, CM-44): a promise, a conditional promise, an
/// accepted counter-offer, a `claim`, an answered offer or an accepted delegation.
#[must_use]
pub fn bound_to<'v>(
    before: &CommitmentView,
    after: &'v CommitmentView,
    id: RecordId,
) -> Option<&'v PartyRef> {
    let hold = after.allocation.hold.as_ref().filter(|h| h.record == id)?;
    let held_before = before
        .allocation
        .hold
        .as_ref()
        .is_some_and(|h| h.record == id);
    (!held_before).then_some(&hold.party)
}

/// The idempotency key of the execution a binding record starts (SEC-15): `<cmt_…>/<rec_…>`.
#[must_use]
pub fn execution_key(commitment: RecordId, binding: RecordId) -> String {
    format!(
        "{}/{}",
        CommitmentId(commitment).to_external(),
        binding.to_external()
    )
}

/// The commitment Work delivers to the executor the record `id` binds `after` to (RC-42,
/// SEC-15, E-39): its `request`, the binding record as its version, its Aim, budget and change
/// policy, the records the binding and the request cite as its context and nothing else, the
/// digest of the Access decision receipt kept beside the binding record as its single-use
/// authority context, and the execution's idempotency key.
#[must_use]
pub fn commitment_delivery(
    after: &CommitmentView,
    id: RecordId,
    authority: [u8; 32],
    budget: Option<RecordId>,
    cited: &[RecordId],
) -> CommitmentDelivery {
    let mut context: Vec<_> = cited
        .iter()
        .filter(|c| **c != after.root && **c != id)
        .map(|c| c.0)
        .collect();
    context.sort_unstable();
    context.dedup();
    context.truncate(MAX_CONTEXT);
    CommitmentDelivery {
        commitment: after.root.0,
        version: id.0,
        aim: after.aim.map(|a| a.0),
        criterion: None,
        budget: budget.map(|b| b.0),
        change_policy: after.terms.change_policy,
        context,
        authority_context: work_kernel::id::Digest::sha256(authority),
        idempotency_key: execution_key(after.root, id),
    }
}

#[cfg(test)]
mod tests;
