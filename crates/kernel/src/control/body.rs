//! The `work/control/1` bodies (RC-27, RC-33, RC-42, RC-43): the autonomy policy, the control lease and every element of the executor coordination contract of `conformance/cddl/work-control.cddl`, read and written as deterministic CBOR, each refusal naming the member it refused.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::catalog::{ChangePolicy, HandoverReason, StopAnswer, StopType};
use crate::id::{Digest, PartyRef, Time, canonical_text_cmp};
use crate::reason::wire_enum;
use crate::uri::{ExternalRef, TypeUri};

/// The contract name of the bodies.
pub const CONTRACT: &str = "work/control/1";

/// The CDDL of the bodies, byte for byte `conformance/cddl/work-control.cddl`.
pub const CDDL: &str = r#"; RC-27 RC-28 RC-29 RC-49

autonomy-policy = {
  version: uint .ge 1,
  ? rule_set: digest,
  ? bulk_threshold: uint .ge 1,
  ? near_boundary: 1..1000,
  ? notify: true,
  ? suggest: true,
  ? expanded_actions: [1*64 action],
  ? expansion: true,
}

action = tstr .size (1..256)

; RC-33 RC-34

control-lease = lease-grant / lease-release

lease-grant = {
  driver: party,
  environment: tstr .size (1..256),
  from: epoch-ms,
  until: epoch-ms,
  reason: tstr .size (1..1024),
}

lease-release = {
  lease: digest,
  released: epoch-ms,
}

; RC-32 RC-34 RC-39 RC-42 RC-43

capability = {
  ? operations: [1*3 operation],
  ? stop_types: [1*3 stop-type],
  ? change_policies: [1*2 correction],
  ? non_cancellable: [1*64 step],
  ? safe_state: tstr .size (1..256),
  checkpoints: bool,
  ? heartbeat: uint .ge 1,
  depth: depth,
}

operation = "pause_resume" / "cancel" / "takeover"
depth = "full" / "traffic_light" / "read_only"
correction = "interrupt" / "rollback"
step = tstr .size (1..256)

; RC-42 SEC-15

commitment-delivery = {
  commitment: digest,
  version: digest,
  ? aim: digest,
  ? criterion: type-uri,
  ? budget: digest,
  change_policy: "queue" / "reject" / correction,
  ? context: [1*256 digest],
  authority_context: digest,
  idempotency_key: idempotency-key,
}

idempotency-key = tstr .size (1..255)

; RC-36 RC-40 RC-42

request = stop-delivery / control-delivery / change-delivery

stop-delivery = {
  record: digest,
  kind: "stop",
  stop_type: stop-type,
}

control-delivery = {
  record: digest,
  kind: "start" / "resume" / "takeover" / "return_control" / "budget_exhausted",
}

change-delivery = {
  record: digest,
  kind: "change",
  change_policy: correction,
  change_version: uint .ge 1,
}

request-response = accepted-response / refused-response

accepted-response = {
  request: digest,
  answer: "accept" / "finish_then_stop",
  ? applied_version: uint .ge 1,
}

refused-response = {
  request: digest,
  answer: "refuse",
  reason: tstr .size (1..1024),
}

; RC-42 RC-43 SEC-15 OP-4

report = action-report / claim-report

action-report = {
  event: "action",
  session: session-ref,
  summary: summary,
  ? trace: external-ref,
  ? relies_on: [1*256 digest],
  authority_context: digest,
  idempotency_key: idempotency-key,
  external_idempotent: bool,
}

claim-report = {
  event: "question" / "answer" / "error" / "plan_update" / "rationale_summary",
  session: session-ref,
  summary: summary,
  ? trace: external-ref,
  ? relies_on: [1*256 digest],
}

summary = tstr .size (1..4096)

; RC-38 RC-42

status-report = {
  status: "running" / "paused" / "stopped" / "failed" / "completed",
  done: tstr .size (0..4096),
  need: tstr .size (0..4096),
  ? step: step,
}

; RC-32 RC-33 RC-42

control-mode = {
  mode: "automatic" / "intervened" / "manual",
  ? lease: digest,
}

; RC-34 RC-42 CM-45

handover = {
  handover_reason: handover-reason,
  stateful: bool,
  ? context: [1*256 digest],
  summary: summary,
  done: summary,
  changed: summary,
  open_questions: summary,
  next_steps: summary,
}

handover-reason = "capacity" / "competence" / "escalation" / "departure" / "control_transfer" / "other"
                / tstr .regexp "(capacity|competence|escalation|departure|control_transfer|other):https://[a-z0-9.-]+(:[0-9]+)?/[!-~]*"

; RC-42 RC-43 ST-4

heartbeat = {
  session: session-ref,
  seq: uint,
  ? departing: true,
}

; RC-43

session = open-session / closed-session / failed-session

open-session = {
  session: session-ref,
  commitment: digest,
  attempt: uint .ge 1,
}

closed-session = {
  session: session-ref,
  commitment: digest,
  attempt: uint .ge 1,
  outcome: "succeeded",
}

failed-session = {
  session: session-ref,
  commitment: digest,
  attempt: uint .ge 1,
  outcome: "failed" / "abandoned",
  reason: tstr .size (1..1024),
}

stop-type = "immediate" / "finish_then_stop" / "pause"
digest = [-16, bstr .size 32]
party = tstr .size (1..255)
epoch-ms = uint
type-uri = tstr .regexp "https://[a-z0-9.-]+(:[0-9]+)?/[!-~]*"
external-ref = tstr .regexp "[a-z][a-z0-9+.-]*:[!-~]+"
session-ref = external-ref
"#;

/// Why a value is not a `work/control/1` body, naming the member it refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlBodyError(pub &'static str);

impl core::fmt::Display for ControlBodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not a control body: {}", self.0)
    }
}

impl core::error::Error for ControlBodyError {}

type Read<T> = Result<T, ControlBodyError>;

fn decode_value(bytes: &[u8]) -> Read<Value> {
    dcbor::decode(bytes, Limits::CEILING).map_err(|_| ControlBodyError("cbor"))
}

fn encode_value(value: &Value) -> Read<Vec<u8>> {
    dcbor::encode(value, Limits::CEILING).map_err(|_| ControlBodyError("encoding"))
}

fn members(value: &Value, allowed: &[&str]) -> Read<()> {
    let Value::Map(entries) = value else {
        return Err(ControlBodyError("body"));
    };
    for (k, _) in entries {
        if !matches!(k, Value::Text(t) if allowed.contains(&t.as_str())) {
            return Err(ControlBodyError("member"));
        }
    }
    Ok(())
}

fn uint(value: &Value, key: &'static str) -> Read<u64> {
    match value.get(key) {
        Some(Value::Unsigned(u)) => Ok(*u),
        _ => Err(ControlBodyError(key)),
    }
}

fn opt_uint(value: &Value, key: &'static str) -> Read<Option<u64>> {
    match value.get(key) {
        None => Ok(None),
        Some(Value::Unsigned(u)) => Ok(Some(*u)),
        Some(_) => Err(ControlBodyError(key)),
    }
}

fn positive(value: &Value, key: &'static str) -> Read<Option<u64>> {
    match opt_uint(value, key)? {
        Some(0) => Err(ControlBodyError(key)),
        other => Ok(other),
    }
}

fn sized(value: &Value, key: &'static str, min: usize, max: usize) -> Read<String> {
    match value.get(key) {
        Some(Value::Text(t)) if t.len() >= min && t.len() <= max => Ok(t.clone()),
        _ => Err(ControlBodyError(key)),
    }
}

fn text(value: &Value, key: &'static str, max: usize) -> Read<String> {
    sized(value, key, 1, max)
}

fn opt_text(value: &Value, key: &'static str, max: usize) -> Read<Option<String>> {
    match value.get(key) {
        None => Ok(None),
        Some(_) => text(value, key, max).map(Some),
    }
}

fn boolean(value: &Value, key: &'static str) -> Read<bool> {
    match value.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(ControlBodyError(key)),
    }
}

fn flag(value: &Value, key: &'static str) -> Read<bool> {
    match value.get(key) {
        None => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(_) => Err(ControlBodyError(key)),
    }
}

fn digest_of(item: &Value) -> Option<Digest> {
    match item {
        Value::Array(pair) => match pair.as_slice() {
            [alg, Value::Bytes(d)] if alg.as_i64() == Some(-16) => {
                <[u8; 32]>::try_from(d.as_slice()).ok().map(Digest::sha256)
            }
            _ => None,
        },
        _ => None,
    }
}

fn digest(value: &Value, key: &'static str) -> Read<Digest> {
    value
        .get(key)
        .and_then(digest_of)
        .ok_or(ControlBodyError(key))
}

fn opt_digest(value: &Value, key: &'static str) -> Read<Option<Digest>> {
    match value.get(key) {
        None => Ok(None),
        Some(item) => digest_of(item).map(Some).ok_or(ControlBodyError(key)),
    }
}

fn digests(value: &Value, key: &'static str) -> Read<Vec<Digest>> {
    let Some(found) = value.get(key) else {
        return Ok(Vec::new());
    };
    let Value::Array(list) = found else {
        return Err(ControlBodyError(key));
    };
    if list.is_empty() {
        return Err(ControlBodyError(key));
    }
    let mut out: Vec<Digest> = Vec::with_capacity(list.len());
    for item in list {
        let d = digest_of(item).ok_or(ControlBodyError(key))?;
        if out.last().is_some_and(|last| *last >= d) {
            return Err(ControlBodyError(key));
        }
        out.push(d);
    }
    Ok(out)
}

fn names<T>(
    value: &Value,
    key: &'static str,
    most: usize,
    parse: impl Fn(&str) -> Option<T>,
) -> Read<Vec<T>> {
    let Some(found) = value.get(key) else {
        return Ok(Vec::new());
    };
    let Value::Array(list) = found else {
        return Err(ControlBodyError(key));
    };
    if list.is_empty() || list.len() > most {
        return Err(ControlBodyError(key));
    }
    let mut seen: Vec<&str> = Vec::with_capacity(list.len());
    let mut out: Vec<T> = Vec::with_capacity(list.len());
    for item in list {
        let Value::Text(t) = item else {
            return Err(ControlBodyError(key));
        };
        if seen
            .last()
            .is_some_and(|last| canonical_text_cmp(last, t.as_str()) != Ordering::Less)
        {
            return Err(ControlBodyError(key));
        }
        out.push(parse(t.as_str()).ok_or(ControlBodyError(key))?);
        seen.push(t.as_str());
    }
    Ok(out)
}

fn step_name(t: &str) -> Option<String> {
    (!t.is_empty() && t.len() <= MAX_NAME).then(|| String::from(t))
}

fn digest_value(d: &Digest) -> Value {
    Value::Array(alloc::vec![
        Value::int(-16),
        Value::Bytes(d.as_bytes().to_vec())
    ])
}

fn digest_list(list: &[Digest]) -> Value {
    Value::Array(list.iter().map(digest_value).collect())
}

fn text_list<'a>(list: impl Iterator<Item = &'a str>) -> Value {
    Value::Array(list.map(Value::text).collect())
}

fn entry(key: &str, value: Value) -> (Value, Value) {
    (Value::text(key), value)
}

fn push_list(entries: &mut Vec<(Value, Value)>, key: &str, list: Value) {
    if matches!(&list, Value::Array(items) if !items.is_empty()) {
        entries.push(entry(key, list));
    }
}

fn push_text(entries: &mut Vec<(Value, Value)>, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        entries.push(entry(key, Value::text(v)));
    }
}

fn push_digest(entries: &mut Vec<(Value, Value)>, key: &str, value: Option<&Digest>) {
    if let Some(v) = value {
        entries.push(entry(key, digest_value(v)));
    }
}

fn push_flag(entries: &mut Vec<(Value, Value)>, key: &str, on: bool) {
    if on {
        entries.push(entry(key, Value::Bool(true)));
    }
}

fn type_uri_text(value: &Value, key: &'static str) -> Read<Option<String>> {
    match value.get(key) {
        None => Ok(None),
        Some(Value::Text(t)) if TypeUri::parse(t).is_some() => Ok(Some(t.clone())),
        Some(_) => Err(ControlBodyError(key)),
    }
}

fn external_ref(value: &Value, key: &'static str) -> Read<String> {
    match value.get(key) {
        Some(Value::Text(t)) if ExternalRef::parse(t).is_some() => Ok(t.clone()),
        _ => Err(ControlBodyError(key)),
    }
}

fn opt_external_ref(value: &Value, key: &'static str) -> Read<Option<String>> {
    match value.get(key) {
        None => Ok(None),
        Some(_) => external_ref(value, key).map(Some),
    }
}

fn wire<T>(value: &Value, key: &'static str, parse: impl Fn(&str) -> Option<T>) -> Read<T> {
    match value.get(key) {
        Some(Value::Text(t)) => parse(t.as_str()).ok_or(ControlBodyError(key)),
        _ => Err(ControlBodyError(key)),
    }
}

/// The base code of a catalog code that may carry a namespaced sub-code (P-71): `base` or `base:https://…`.
#[must_use]
pub fn parent_code(text: &str) -> &str {
    match text.split_once(':') {
        Some((code, sub)) if TypeUri::parse(sub).is_some() => code,
        _ => text,
    }
}

macro_rules! codec {
    ($t:ty) => {
        impl $t {
            /// Reads deterministic CBOR bytes of the body.
            ///
            /// # Errors
            /// [`ControlBodyError`] naming the member that does not fit.
            pub fn decode(bytes: &[u8]) -> Result<Self, ControlBodyError> {
                Self::from_value(&decode_value(bytes)?)
            }

            /// The deterministic CBOR bytes of the body.
            ///
            /// # Errors
            /// [`ControlBodyError`] for a body `from_value` would refuse.
            pub fn encode(&self) -> Result<Vec<u8>, ControlBodyError> {
                let value = self.to_value();
                Self::from_value(&value)?;
                encode_value(&value)
            }
        }
    };
}

/// Longest name of an action, step, environment or safe state, in bytes.
pub const MAX_NAME: usize = 256;

/// Longest free text of a reason, in bytes.
pub const MAX_REASON: usize = 1024;

/// Longest free text of a summary or report part, in bytes.
pub const MAX_TEXT: usize = 4096;

/// Most actions one autonomy policy expands.
pub const MAX_EXPANDED: usize = 64;

/// Most non-cancellable steps one capability declares.
pub const MAX_STEPS: usize = 64;

/// The default bulk threshold: an action touching more objects is bulk (RC-49).
pub const DEFAULT_BULK_THRESHOLD: u64 = 10;

/// The default nearness to an Access numeric limit, in permille (RC-49).
pub const DEFAULT_NEAR_BOUNDARY: u16 = 800;

/// A principal's autonomy policy, the body of an `autonomy_policy` Declaration (RC-27, RC-28, RC-29, RC-49).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutonomyPolicy {
    /// The policy version, at least 1.
    pub version: u32,
    /// The restriction rule set the policy is evaluated with, by digest (RC-27).
    pub rule_set: Option<Digest>,
    /// The bulk threshold; absent is [`DEFAULT_BULK_THRESHOLD`].
    pub bulk_threshold: Option<u64>,
    /// The nearness to an Access numeric limit in permille, 1 to 1000; absent is [`DEFAULT_NEAR_BOUNDARY`].
    pub near_boundary: Option<u16>,
    /// The principal wants a notification for every action that proceeds.
    pub notify: bool,
    /// Every agent action is a suggestion first (RC-28).
    pub suggest: bool,
    /// Actions whose irreversible or binding default gate the principal lifts, ascending (RC-29).
    pub expanded_actions: Vec<String>,
    /// The policy widens the default and needs the principal's own Declaration (RC-29, RC-49).
    pub expansion: bool,
}

impl AutonomyPolicy {
    /// The bulk threshold in force.
    #[must_use]
    pub fn bulk(&self) -> u64 {
        self.bulk_threshold.unwrap_or(DEFAULT_BULK_THRESHOLD)
    }

    /// The nearness in force, in permille.
    #[must_use]
    pub fn near(&self) -> u16 {
        self.near_boundary.unwrap_or(DEFAULT_NEAR_BOUNDARY)
    }

    /// Whether any value is wider than the default (RC-49).
    #[must_use]
    pub fn widens(&self) -> bool {
        self.bulk() > DEFAULT_BULK_THRESHOLD
            || self.near() > DEFAULT_NEAR_BOUNDARY
            || !self.expanded_actions.is_empty()
    }

    /// Checks `value` against the `autonomy-policy` rule; a wider value needs `expansion` and an expansion must widen something.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        members(
            value,
            &[
                "version",
                "rule_set",
                "bulk_threshold",
                "near_boundary",
                "notify",
                "suggest",
                "expanded_actions",
                "expansion",
            ],
        )?;
        let version = u32::try_from(uint(value, "version")?)
            .ok()
            .filter(|v| *v >= 1)
            .ok_or(ControlBodyError("version"))?;
        let near_boundary = match opt_uint(value, "near_boundary")? {
            None => None,
            Some(n) => Some(
                u16::try_from(n)
                    .ok()
                    .filter(|n| (1..=1000).contains(n))
                    .ok_or(ControlBodyError("near_boundary"))?,
            ),
        };
        let policy = Self {
            version,
            rule_set: opt_digest(value, "rule_set")?,
            bulk_threshold: positive(value, "bulk_threshold")?,
            near_boundary,
            notify: flag(value, "notify")?,
            suggest: flag(value, "suggest")?,
            expanded_actions: names(value, "expanded_actions", MAX_EXPANDED, step_name)?,
            expansion: flag(value, "expansion")?,
        };
        if policy.widens() != policy.expansion {
            return Err(ControlBodyError("expansion"));
        }
        Ok(policy)
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![entry("version", Value::Unsigned(u64::from(self.version)))];
        push_digest(&mut entries, "rule_set", self.rule_set.as_ref());
        if let Some(b) = self.bulk_threshold {
            entries.push(entry("bulk_threshold", Value::Unsigned(b)));
        }
        if let Some(n) = self.near_boundary {
            entries.push(entry("near_boundary", Value::Unsigned(u64::from(n))));
        }
        push_flag(&mut entries, "notify", self.notify);
        push_flag(&mut entries, "suggest", self.suggest);
        push_list(
            &mut entries,
            "expanded_actions",
            text_list(self.expanded_actions.iter().map(String::as_str)),
        );
        push_flag(&mut entries, "expansion", self.expansion);
        Value::Map(entries)
    }
}

codec!(AutonomyPolicy);

/// A control lease, the body of a `control_lease` Declaration: a grant to a second driver or its release (RC-33, RC-34).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlLease {
    /// A second driver takes control of an execution environment for a bounded time.
    Grant {
        /// Who drives.
        driver: PartyRef,
        /// The execution environment: a browser session, a terminal, a robot arm.
        environment: String,
        /// When the lease starts.
        from: Time,
        /// When the lease ends; later than `from`.
        until: Time,
        /// Why control is taken.
        reason: String,
    },
    /// The driver gives control back.
    Release {
        /// The `control_lease` grant record released.
        lease: Digest,
        /// When control was given back.
        released: Time,
    },
}

impl ControlLease {
    /// Checks `value` against the `control-lease` rule; a grant ends after it starts.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        if value.get("released").is_some() || value.get("lease").is_some() {
            members(value, &["lease", "released"])?;
            return Ok(Self::Release {
                lease: digest(value, "lease")?,
                released: Time(uint(value, "released")?),
            });
        }
        members(value, &["driver", "environment", "from", "until", "reason"])?;
        let driver = match value.get("driver") {
            Some(Value::Text(t)) => PartyRef::new(t).ok_or(ControlBodyError("driver"))?,
            _ => return Err(ControlBodyError("driver")),
        };
        let from = Time(uint(value, "from")?);
        let until = Time(uint(value, "until")?);
        if until <= from {
            return Err(ControlBodyError("until"));
        }
        Ok(Self::Grant {
            driver,
            environment: text(value, "environment", MAX_NAME)?,
            from,
            until,
            reason: text(value, "reason", MAX_REASON)?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Grant {
                driver,
                environment,
                from,
                until,
                reason,
            } => Value::Map(alloc::vec![
                entry("driver", Value::text(driver.as_str())),
                entry("environment", Value::text(environment)),
                entry("from", Value::Unsigned(from.0)),
                entry("until", Value::Unsigned(until.0)),
                entry("reason", Value::text(reason)),
            ]),
            Self::Release { lease, released } => Value::Map(alloc::vec![
                entry("lease", digest_value(lease)),
                entry("released", Value::Unsigned(released.0)),
            ]),
        }
    }
}

codec!(ControlLease);

wire_enum! {
    /// The control operations an executor can declare (RC-42).
    Operation {
        /// Pause and resume.
        PauseResume => "pause_resume",
        /// Cancel.
        Cancel => "cancel",
        /// Take over.
        Takeover => "takeover",
    }
}

wire_enum! {
    /// How deeply an executor integrates (RC-43).
    Depth {
        /// Full control: every element of the contract.
        Full => "full",
        /// Traffic light: start permission, stop and resume; the executor plans by itself.
        TrafficLight => "traffic_light",
        /// Read only: Work watches the reports and delivers no request.
        ReadOnly => "read_only",
    }
}

/// An executor's control capability declaration, the body of an `observation` Claim; the interface offers only what it declares (RC-3, RC-32, RC-39, RC-42, RC-43).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    /// Supported operations, ascending.
    pub operations: Vec<Operation>,
    /// Supported stop types, ascending.
    pub stop_types: Vec<StopType>,
    /// Supported change policies, only `interrupt` and `rollback`, ascending.
    pub change_policies: Vec<ChangePolicy>,
    /// Steps a cancellation never interrupts; a stop applies after the step (RC-39).
    pub non_cancellable: Vec<String>,
    /// The declared safe state, if one is reachable.
    pub safe_state: Option<String>,
    /// Whether the executor supports checkpoints.
    pub checkpoints: bool,
    /// The heartbeat interval in milliseconds; absent is no liveness expectation (ST-4).
    pub heartbeat: Option<u64>,
    /// The integration depth.
    pub depth: Depth,
}

impl Capability {
    /// Whether the executor declares `operation`.
    #[must_use]
    pub fn supports(&self, operation: Operation) -> bool {
        self.operations.contains(&operation)
    }

    /// Checks `value` against the `capability` rule: a pause stop needs `pause_resume`, any other stop needs `cancel`, a traffic light executor declares no takeover and no change policy, and a read only executor declares no operation.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        members(
            value,
            &[
                "operations",
                "stop_types",
                "change_policies",
                "non_cancellable",
                "safe_state",
                "checkpoints",
                "heartbeat",
                "depth",
            ],
        )?;
        let capability = Self {
            operations: names(value, "operations", 3, Operation::from_wire_name)?,
            stop_types: names(value, "stop_types", 3, StopType::from_wire_name)?,
            change_policies: names(value, "change_policies", 2, |t| {
                ChangePolicy::from_wire_name(t)
                    .filter(|p| matches!(p, ChangePolicy::Interrupt | ChangePolicy::Rollback))
            })?,
            non_cancellable: names(value, "non_cancellable", MAX_STEPS, step_name)?,
            safe_state: opt_text(value, "safe_state", MAX_NAME)?,
            checkpoints: boolean(value, "checkpoints")?,
            heartbeat: positive(value, "heartbeat")?,
            depth: wire(value, "depth", Depth::from_wire_name)?,
        };
        let stops_ok = capability.stop_types.iter().all(|s| match s {
            StopType::Pause => capability.supports(Operation::PauseResume),
            StopType::Immediate | StopType::FinishThenStop => {
                capability.supports(Operation::Cancel)
            }
        });
        if !stops_ok {
            return Err(ControlBodyError("stop_types"));
        }
        let depth_ok = match capability.depth {
            Depth::Full => true,
            Depth::TrafficLight => {
                !capability.supports(Operation::Takeover) && capability.change_policies.is_empty()
            }
            Depth::ReadOnly => {
                capability.operations.is_empty()
                    && capability.stop_types.is_empty()
                    && capability.change_policies.is_empty()
            }
        };
        if !depth_ok {
            return Err(ControlBodyError("depth"));
        }
        Ok(capability)
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = Vec::new();
        push_list(
            &mut entries,
            "operations",
            text_list(self.operations.iter().map(|o| o.wire_name())),
        );
        push_list(
            &mut entries,
            "stop_types",
            text_list(self.stop_types.iter().map(|s| s.wire_name())),
        );
        push_list(
            &mut entries,
            "change_policies",
            text_list(self.change_policies.iter().map(|c| c.wire_name())),
        );
        push_list(
            &mut entries,
            "non_cancellable",
            text_list(self.non_cancellable.iter().map(String::as_str)),
        );
        push_text(&mut entries, "safe_state", self.safe_state.as_deref());
        entries.push(entry("checkpoints", Value::Bool(self.checkpoints)));
        if let Some(h) = self.heartbeat {
            entries.push(entry("heartbeat", Value::Unsigned(h)));
        }
        entries.push(entry("depth", Value::text(self.depth.wire_name())));
        Value::Map(entries)
    }
}

codec!(Capability);

/// The commitment Work delivers to the executor it is given to (the RC-42 table's first element), bound to a single-use authority context and an idempotency key (RC-42, SEC-15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentDelivery {
    /// The commitment's `request` record.
    pub commitment: Digest,
    /// The commitment version: the head record of its chain.
    pub version: Digest,
    /// The Aim the commitment serves.
    pub aim: Option<Digest>,
    /// The acceptance criterion URI.
    pub criterion: Option<String>,
    /// The budget Condition record.
    pub budget: Option<Digest>,
    /// The change policy.
    pub change_policy: ChangePolicy,
    /// Context references, ascending; context is referenced, never copied.
    pub context: Vec<Digest>,
    /// The single-use authority context (SEC-15).
    pub authority_context: Digest,
    /// The idempotency key the execution is bound to (SEC-15).
    pub idempotency_key: String,
}

impl CommitmentDelivery {
    /// Checks `value` against the `commitment-delivery` rule.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        members(
            value,
            &[
                "commitment",
                "version",
                "aim",
                "criterion",
                "budget",
                "change_policy",
                "context",
                "authority_context",
                "idempotency_key",
            ],
        )?;
        Ok(Self {
            commitment: digest(value, "commitment")?,
            version: digest(value, "version")?,
            aim: opt_digest(value, "aim")?,
            criterion: type_uri_text(value, "criterion")?,
            budget: opt_digest(value, "budget")?,
            change_policy: wire(value, "change_policy", ChangePolicy::from_wire_name)?,
            context: digests(value, "context")?,
            authority_context: digest(value, "authority_context")?,
            idempotency_key: text(value, "idempotency_key", 255)?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            entry("commitment", digest_value(&self.commitment)),
            entry("version", digest_value(&self.version)),
        ];
        push_digest(&mut entries, "aim", self.aim.as_ref());
        push_text(&mut entries, "criterion", self.criterion.as_deref());
        push_digest(&mut entries, "budget", self.budget.as_ref());
        entries.push(entry(
            "change_policy",
            Value::text(self.change_policy.wire_name()),
        ));
        push_list(&mut entries, "context", digest_list(&self.context));
        entries.push(entry(
            "authority_context",
            digest_value(&self.authority_context),
        ));
        entries.push(entry("idempotency_key", Value::text(&self.idempotency_key)));
        Value::Map(entries)
    }
}

codec!(CommitmentDelivery);

wire_enum! {
    /// What Work asks an executor to do (RC-42).
    RequestKind {
        /// Start permission.
        Start => "start",
        /// Stop, with its stop type (RC-36).
        Stop => "stop",
        /// Resume a paused execution, or a stopped one after `resume_after_stop` (RC-40).
        Resume => "resume",
        /// Take over control (RC-33).
        Takeover => "takeover",
        /// Give control back (RC-33).
        ReturnControl => "return_control",
        /// A change, with its policy and version.
        Change => "change",
        /// The budget is exhausted.
        BudgetExhausted => "budget_exhausted",
    }
}

/// A request Work delivers to an executor (RC-36, RC-40, RC-42).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestDelivery {
    /// The Work record that carries the request.
    pub record: Digest,
    /// What is asked.
    pub kind: RequestKind,
    /// The stop type, exactly for `stop`.
    pub stop_type: Option<StopType>,
    /// The change policy and the monotonic change version, exactly for `change`.
    pub change: Option<(ChangePolicy, u64)>,
}

impl RequestDelivery {
    /// Checks `value` against the `request` rule.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        let kind = wire(value, "kind", RequestKind::from_wire_name)?;
        let record = digest(value, "record")?;
        match kind {
            RequestKind::Stop => {
                members(value, &["record", "kind", "stop_type"])?;
                Ok(Self {
                    record,
                    kind,
                    stop_type: Some(wire(value, "stop_type", StopType::from_wire_name)?),
                    change: None,
                })
            }
            RequestKind::Change => {
                members(
                    value,
                    &["record", "kind", "change_policy", "change_version"],
                )?;
                let policy = wire(value, "change_policy", ChangePolicy::from_wire_name)?;
                if !matches!(policy, ChangePolicy::Interrupt | ChangePolicy::Rollback) {
                    return Err(ControlBodyError("change_policy"));
                }
                let version =
                    positive(value, "change_version")?.ok_or(ControlBodyError("change_version"))?;
                Ok(Self {
                    record,
                    kind,
                    stop_type: None,
                    change: Some((policy, version)),
                })
            }
            RequestKind::Start
            | RequestKind::Resume
            | RequestKind::Takeover
            | RequestKind::ReturnControl
            | RequestKind::BudgetExhausted => {
                members(value, &["record", "kind"])?;
                Ok(Self {
                    record,
                    kind,
                    stop_type: None,
                    change: None,
                })
            }
        }
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            entry("record", digest_value(&self.record)),
            entry("kind", Value::text(self.kind.wire_name())),
        ];
        if let Some(s) = self.stop_type {
            entries.push(entry("stop_type", Value::text(s.wire_name())));
        }
        if let Some((policy, version)) = self.change {
            entries.push(entry("change_policy", Value::text(policy.wire_name())));
            entries.push(entry("change_version", Value::Unsigned(version)));
        }
        Value::Map(entries)
    }
}

codec!(RequestDelivery);

/// An executor's answer to a delivered request; a refusal carries its reason (RC-36, RC-42).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestResponse {
    /// The Work record of the request answered.
    pub request: Digest,
    /// The answer.
    pub answer: StopAnswer,
    /// Why the request is refused, exactly for `refuse`.
    pub reason: Option<String>,
    /// The change version applied.
    pub applied_version: Option<u64>,
}

impl RequestResponse {
    /// Checks `value` against the `request-response` rule.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        let answer = wire(value, "answer", StopAnswer::from_wire_name)?;
        let request = digest(value, "request")?;
        if answer == StopAnswer::Refuse {
            members(value, &["request", "answer", "reason"])?;
            return Ok(Self {
                request,
                answer,
                reason: Some(text(value, "reason", MAX_REASON)?),
                applied_version: None,
            });
        }
        members(value, &["request", "answer", "applied_version"])?;
        Ok(Self {
            request,
            answer,
            reason: None,
            applied_version: positive(value, "applied_version")?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            entry("request", digest_value(&self.request)),
            entry("answer", Value::text(self.answer.wire_name())),
        ];
        push_text(&mut entries, "reason", self.reason.as_deref());
        if let Some(v) = self.applied_version {
            entries.push(entry("applied_version", Value::Unsigned(v)));
        }
        Value::Map(entries)
    }
}

codec!(RequestResponse);

wire_enum! {
    /// The progress event kinds of an executor report (RC-42).
    ProgressEvent {
        /// An external action, reported as an Act.
        Action => "action",
        /// A question.
        Question => "question",
        /// An answer.
        Answer => "answer",
        /// An error.
        Error => "error",
        /// A plan update, an `assumption` Claim (RC-43).
        PlanUpdate => "plan_update",
        /// A rationale summary; the raw chain of thought is never sent.
        RationaleSummary => "rationale_summary",
    }
}

/// The single-use authority context and idempotency key an action report is bound to (SEC-15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The single-use authority context.
    pub authority_context: Digest,
    /// The idempotency key.
    pub idempotency_key: String,
    /// Whether the external system honours the key, which alone lets a report claim the effect happened once.
    pub external_idempotent: bool,
}

/// An executor's act or claim report (RC-42, RC-43, OP-4); the raw trace is only a reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressReport {
    /// The event kind.
    pub event: ProgressEvent,
    /// The execution session reference.
    pub session: String,
    /// The summary.
    pub summary: String,
    /// The raw trace, as an external reference only.
    pub trace: Option<String>,
    /// The Work records the report relies on, ascending.
    pub relies_on: Vec<Digest>,
    /// The binding, exactly for `action`.
    pub binding: Option<Binding>,
}

impl ProgressReport {
    /// Checks `value` against the `report` rule: an action carries its binding and nothing else does.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        let event = wire(value, "event", ProgressEvent::from_wire_name)?;
        let binding = if event == ProgressEvent::Action {
            members(
                value,
                &[
                    "event",
                    "session",
                    "summary",
                    "trace",
                    "relies_on",
                    "authority_context",
                    "idempotency_key",
                    "external_idempotent",
                ],
            )?;
            Some(Binding {
                authority_context: digest(value, "authority_context")?,
                idempotency_key: text(value, "idempotency_key", 255)?,
                external_idempotent: boolean(value, "external_idempotent")?,
            })
        } else {
            members(
                value,
                &["event", "session", "summary", "trace", "relies_on"],
            )?;
            None
        };
        Ok(Self {
            event,
            session: external_ref(value, "session")?,
            summary: text(value, "summary", MAX_TEXT)?,
            trace: opt_external_ref(value, "trace")?,
            relies_on: digests(value, "relies_on")?,
            binding,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            entry("event", Value::text(self.event.wire_name())),
            entry("session", Value::text(&self.session)),
            entry("summary", Value::text(&self.summary)),
        ];
        push_text(&mut entries, "trace", self.trace.as_deref());
        push_list(&mut entries, "relies_on", digest_list(&self.relies_on));
        if let Some(b) = &self.binding {
            entries.push(entry(
                "authority_context",
                digest_value(&b.authority_context),
            ));
            entries.push(entry("idempotency_key", Value::text(&b.idempotency_key)));
            entries.push(entry(
                "external_idempotent",
                Value::Bool(b.external_idempotent),
            ));
        }
        Value::Map(entries)
    }
}

codec!(ProgressReport);

wire_enum! {
    /// What an executor reports of the execution (RC-38, RC-42).
    ExecutionState {
        /// Running.
        Running => "running",
        /// Paused.
        Paused => "paused",
        /// Stopped; the only source of "stopped" (RC-38).
        Stopped => "stopped",
        /// Failed.
        Failed => "failed",
        /// Completed.
        Completed => "completed",
    }
}

impl ExecutionState {
    /// Whether the execution has ended.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed | Self::Completed)
    }
}

/// The minimal status report, the same for agents and machines: status, what was done, what is needed (RC-42).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    /// The execution state.
    pub status: ExecutionState,
    /// What was done.
    pub done: String,
    /// What is needed.
    pub need: String,
    /// The step under way.
    pub step: Option<String>,
}

impl StatusReport {
    /// Checks `value` against the `status-report` rule.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        members(value, &["status", "done", "need", "step"])?;
        Ok(Self {
            status: wire(value, "status", ExecutionState::from_wire_name)?,
            done: sized(value, "done", 0, MAX_TEXT)?,
            need: sized(value, "need", 0, MAX_TEXT)?,
            step: opt_text(value, "step", MAX_NAME)?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            entry("status", Value::text(self.status.wire_name())),
            entry("done", Value::text(&self.done)),
            entry("need", Value::text(&self.need)),
        ];
        push_text(&mut entries, "step", self.step.as_deref());
        Value::Map(entries)
    }
}

codec!(StatusReport);

wire_enum! {
    /// The control mode an executor claims (RC-32).
    ControlMode {
        /// Automatic.
        Automatic => "automatic",
        /// Intervened.
        Intervened => "intervened",
        /// Manual.
        Manual => "manual",
    }
}

/// An executor's control mode Claim with the lease it runs under (RC-32, RC-33, RC-42).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlModeReport {
    /// The mode.
    pub mode: ControlMode,
    /// The `control_lease` grant record in force.
    pub lease: Option<Digest>,
}

impl ControlModeReport {
    /// Checks `value` against the `control-mode` rule.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        members(value, &["mode", "lease"])?;
        Ok(Self {
            mode: wire(value, "mode", ControlMode::from_wire_name)?,
            lease: opt_digest(value, "lease")?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![entry("mode", Value::text(self.mode.wire_name()))];
        push_digest(&mut entries, "lease", self.lease.as_ref());
        Value::Map(entries)
    }
}

codec!(ControlModeReport);

/// A handover note in the §9.11 schema, written by whoever gives control back (RC-34, CM-45).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handover {
    /// The reason code, optionally with a namespaced sub-code.
    pub reason: String,
    /// Whether progress and context are carried over.
    pub stateful: bool,
    /// Context references, ascending.
    pub context: Vec<Digest>,
    /// The current state of the work.
    pub summary: String,
    /// What was done or tried.
    pub done: String,
    /// What changed.
    pub changed: String,
    /// Open questions.
    pub open_questions: String,
    /// What comes next.
    pub next_steps: String,
}

impl Handover {
    /// Checks `value` against the `handover` rule.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        members(
            value,
            &[
                "handover_reason",
                "stateful",
                "context",
                "summary",
                "done",
                "changed",
                "open_questions",
                "next_steps",
            ],
        )?;
        let reason = text(value, "handover_reason", MAX_REASON)?;
        if HandoverReason::from_wire_name(parent_code(&reason)).is_none() {
            return Err(ControlBodyError("handover_reason"));
        }
        Ok(Self {
            reason,
            stateful: boolean(value, "stateful")?,
            context: digests(value, "context")?,
            summary: text(value, "summary", MAX_TEXT)?,
            done: text(value, "done", MAX_TEXT)?,
            changed: text(value, "changed", MAX_TEXT)?,
            open_questions: text(value, "open_questions", MAX_TEXT)?,
            next_steps: text(value, "next_steps", MAX_TEXT)?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            entry("handover_reason", Value::text(&self.reason)),
            entry("stateful", Value::Bool(self.stateful)),
        ];
        push_list(&mut entries, "context", digest_list(&self.context));
        entries.push(entry("summary", Value::text(&self.summary)));
        entries.push(entry("done", Value::text(&self.done)));
        entries.push(entry("changed", Value::text(&self.changed)));
        entries.push(entry("open_questions", Value::text(&self.open_questions)));
        entries.push(entry("next_steps", Value::text(&self.next_steps)));
        Value::Map(entries)
    }
}

codec!(Handover);

/// A liveness heartbeat; `departing` is a graceful departure, not a loss (RC-42, ST-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heartbeat {
    /// The execution session reference.
    pub session: String,
    /// The sequence number.
    pub seq: u64,
    /// The executor is leaving on purpose.
    pub departing: bool,
}

impl Heartbeat {
    /// Checks `value` against the `heartbeat` rule.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        members(value, &["session", "seq", "departing"])?;
        Ok(Self {
            session: external_ref(value, "session")?,
            seq: uint(value, "seq")?,
            departing: flag(value, "departing")?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            entry("session", Value::text(&self.session)),
            entry("seq", Value::Unsigned(self.seq)),
        ];
        push_flag(&mut entries, "departing", self.departing);
        Value::Map(entries)
    }
}

codec!(Heartbeat);

wire_enum! {
    /// How an execution attempt ended (RC-43).
    AttemptOutcome {
        /// Succeeded.
        Succeeded => "succeeded",
        /// Failed.
        Failed => "failed",
        /// Abandoned.
        Abandoned => "abandoned",
    }
}

/// An execution session report: a first-class Reference grouping one attempt of a commitment (RC-43, ST-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionReport {
    /// The execution session reference.
    pub session: String,
    /// The commitment's `request` record.
    pub commitment: Digest,
    /// The attempt number, from 1.
    pub attempt: u32,
    /// How the attempt ended, once it has.
    pub outcome: Option<AttemptOutcome>,
    /// Why it failed or was abandoned.
    pub reason: Option<String>,
}

impl SessionReport {
    /// Checks `value` against the `session` rule: a failed or abandoned attempt keeps its reason.
    ///
    /// # Errors
    /// [`ControlBodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Read<Self> {
        let outcome = match value.get("outcome") {
            None => None,
            Some(_) => Some(wire(value, "outcome", AttemptOutcome::from_wire_name)?),
        };
        let reason = match outcome {
            Some(AttemptOutcome::Failed | AttemptOutcome::Abandoned) => {
                members(
                    value,
                    &["session", "commitment", "attempt", "outcome", "reason"],
                )?;
                Some(text(value, "reason", MAX_REASON)?)
            }
            Some(AttemptOutcome::Succeeded) => {
                members(value, &["session", "commitment", "attempt", "outcome"])?;
                None
            }
            None => {
                members(value, &["session", "commitment", "attempt"])?;
                None
            }
        };
        let attempt = u32::try_from(uint(value, "attempt")?)
            .ok()
            .filter(|a| *a >= 1)
            .ok_or(ControlBodyError("attempt"))?;
        Ok(Self {
            session: external_ref(value, "session")?,
            commitment: digest(value, "commitment")?,
            attempt,
            outcome,
            reason,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            entry("session", Value::text(&self.session)),
            entry("commitment", digest_value(&self.commitment)),
            entry("attempt", Value::Unsigned(u64::from(self.attempt))),
        ];
        if let Some(o) = self.outcome {
            entries.push(entry("outcome", Value::text(o.wire_name())));
        }
        push_text(&mut entries, "reason", self.reason.as_deref());
        Value::Map(entries)
    }
}

codec!(SessionReport);
