//! The commitment clock (CM-50, CM-51, CM-52, CM-53): a clock is the time Condition of a commitment with a target, a duration, an optional business calendar, warning tiers, a breach line, declared pause conditions and start and stop events; its state is a projection over the clock events of the records, the evaluation time and the supplied tzdb zones, never stored and recomputable from history, a new definition version applies forward only, and the clock pauses only on a declared pause condition with an addressed waiting party, never on an attention mute; a periodic update commitment derives its expected report times from a recurrence rule and a tolerance, and a report that does not arrive within the tolerance is a breach signal.

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;

use crate::calendar::{CalendarError, Counting, LocalDateTime, WorkCalendar};
use crate::commitment_time::{
    self, BodyError, members, push_warnings, text, uint, uint_or_zero, version, warnings,
};
use crate::id::{PartyRef, Time};
use crate::rrule::{Rule, RuleError};
use crate::tz::Zone;

/// Most pause conditions of one clock.
pub const MAX_PAUSE: usize = 16;

/// Most start or stop events of one clock.
pub const MAX_EVENTS: usize = 8;

/// Longest pause reason or event name, in bytes.
pub const MAX_NAME: usize = 256;

/// What a clock times (CM-50); the start and the finish deadline are separate targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Until the first answer.
    Response,
    /// Until someone takes the work up and starts it.
    Start,
    /// Until the work is finished.
    Finish,
}

impl Target {
    const fn name(self) -> &'static str {
        match self {
            Self::Response => "response",
            Self::Start => "start",
            Self::Finish => "finish",
        }
    }

    fn read(text: &str) -> Option<Self> {
        match text {
            "response" => Some(Self::Response),
            "start" => Some(Self::Start),
            "finish" => Some(Self::Finish),
            _ => None,
        }
    }
}

/// The commitment role a pause condition waits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The creditor.
    Creditor,
    /// The obligor.
    Obligor,
    /// The accepting Party.
    Acceptor,
    /// A third party.
    ThirdParty,
}

impl Role {
    const fn name(self) -> &'static str {
        match self {
            Self::Creditor => "creditor",
            Self::Obligor => "obligor",
            Self::Acceptor => "acceptor",
            Self::ThirdParty => "third_party",
        }
    }

    fn read(text: &str) -> Option<Self> {
        match text {
            "creditor" => Some(Self::Creditor),
            "obligor" => Some(Self::Obligor),
            "acceptor" => Some(Self::Acceptor),
            "third_party" => Some(Self::ThirdParty),
            _ => None,
        }
    }
}

/// A declared pause condition: the wait reason and the role waited on (CM-52).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PauseCondition {
    /// The wait reason code.
    pub reason: String,
    /// The role the wait must address.
    pub awaited: Role,
}

/// A clock definition body (CM-50).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockDefinition {
    /// The definition version; a change is a higher version that applies forward (CM-51).
    pub version: u32,
    /// The target.
    pub target: Target,
    /// The target duration in counted milliseconds, at least 1.
    pub duration: u64,
    /// The business calendar; continuous time without one.
    pub calendar: Option<WorkCalendar>,
    /// Warning tiers in permille of the duration, ascending.
    pub warnings: Vec<u16>,
    /// Counted milliseconds after the duration until the breach; 0 breaches at the duration.
    pub grace: u64,
    /// Declared pause conditions.
    pub pause: Vec<PauseCondition>,
    /// The record events that start the clock.
    pub start: Vec<String>,
    /// The record events that stop it as met.
    pub stop: Vec<String>,
}

fn names(value: &Value, key: &'static str) -> Result<Vec<String>, BodyError> {
    match value.get(key) {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_EVENTS => items
            .iter()
            .map(|item| match item {
                Value::Text(t) if !t.is_empty() && t.len() <= MAX_NAME => Ok(t.clone()),
                _ => Err(BodyError(key)),
            })
            .collect(),
        _ => Err(BodyError(key)),
    }
}

fn pause_conditions(value: &Value) -> Result<Vec<PauseCondition>, BodyError> {
    let Some(found) = value.get("pause") else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = found else {
        return Err(BodyError("pause"));
    };
    if items.is_empty() || items.len() > MAX_PAUSE {
        return Err(BodyError("pause"));
    }
    items
        .iter()
        .map(|item| {
            members(item, &["reason", "awaited"]).map_err(|_| BodyError("pause"))?;
            let reason = text(item, "reason", MAX_NAME).map_err(|_| BodyError("pause"))?;
            let awaited = text(item, "awaited", MAX_NAME)
                .ok()
                .and_then(Role::read)
                .ok_or(BodyError("pause"))?;
            Ok(PauseCondition {
                reason: String::from(reason),
                awaited,
            })
        })
        .collect()
}

fn text_array(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::text(s)).collect())
}

impl ClockDefinition {
    /// Checks `value` against the `clock` rule.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Result<Self, BodyError> {
        members(
            value,
            &[
                "version", "target", "duration", "calendar", "warnings", "grace", "pause", "start",
                "stop",
            ],
        )?;
        let version = version(value)?;
        let target = text(value, "target", MAX_NAME)
            .ok()
            .and_then(Target::read)
            .ok_or(BodyError("target"))?;
        let duration = uint(value, "duration")?;
        if duration == 0 {
            return Err(BodyError("duration"));
        }
        let calendar = match value.get("calendar") {
            None => None,
            Some(c) => Some(WorkCalendar::from_value(c)?),
        };
        let grace = uint_or_zero(value, "grace")?;
        if value.get("grace").is_some() && grace == 0 {
            return Err(BodyError("grace"));
        }
        Ok(Self {
            version,
            target,
            duration,
            calendar,
            warnings: warnings(value)?,
            grace,
            pause: pause_conditions(value)?,
            start: names(value, "start")?,
            stop: names(value, "stop")?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            (
                Value::text("version"),
                Value::Unsigned(u64::from(self.version))
            ),
            (Value::text("target"), Value::text(self.target.name())),
            (Value::text("duration"), Value::Unsigned(self.duration)),
        ];
        if let Some(c) = &self.calendar {
            entries.push((Value::text("calendar"), c.to_value()));
        }
        push_warnings(&mut entries, &self.warnings);
        if self.grace > 0 {
            entries.push((Value::text("grace"), Value::Unsigned(self.grace)));
        }
        if !self.pause.is_empty() {
            let pause = self
                .pause
                .iter()
                .map(|p| {
                    Value::Map(alloc::vec![
                        (Value::text("reason"), Value::text(&p.reason)),
                        (Value::text("awaited"), Value::text(p.awaited.name())),
                    ])
                })
                .collect();
            entries.push((Value::text("pause"), Value::Array(pause)));
        }
        entries.push((Value::text("start"), text_array(&self.start)));
        entries.push((Value::text("stop"), text_array(&self.stop)));
        Value::Map(entries)
    }

    /// Reads deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        Self::from_value(&commitment_time::decode(bytes)?)
    }

    /// The deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`BodyError`] for a body [`ClockDefinition::from_value`] would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, BodyError> {
        let value = self.to_value();
        Self::from_value(&value)?;
        commitment_time::encode(&value)
    }

    fn lines(&self) -> Result<Vec<(Tier, u64)>, ClockError> {
        let mut out = Vec::with_capacity(self.warnings.len().saturating_add(1));
        for permille in &self.warnings {
            let line = u128::from(self.duration)
                .checked_mul(u128::from(*permille))
                .and_then(|v| v.checked_div(1_000))
                .and_then(|v| u64::try_from(v).ok())
                .ok_or(ClockError::Overflow)?;
            out.push((Tier::Warning(*permille), line));
        }
        let breach = self
            .duration
            .checked_add(self.grace)
            .ok_or(ClockError::Overflow)?;
        out.push((Tier::Breach, breach));
        Ok(out)
    }
}

/// A wait recorded on the commitment while its clock may run (CM-52).
#[derive(Clone, Copy, Debug)]
pub struct Wait<'a> {
    /// The wait reason code.
    pub reason: &'a str,
    /// The Party waited on, when the wait addresses one.
    pub awaited: Option<&'a PartyRef>,
    /// The commitment role of the Party waited on.
    pub awaited_role: Option<Role>,
    /// The author of the wait.
    pub author: &'a PartyRef,
    /// What is waited for.
    pub subject: &'a str,
}

/// A clock event the records of a commitment yield, in ledger order.
#[derive(Clone, Copy, Debug)]
pub enum ClockEvent<'a> {
    /// A declared start event.
    Started,
    /// A declared stop event: the target is met.
    Stopped,
    /// A wait opened.
    WaitOpened(Wait<'a>),
    /// The open wait closed.
    WaitClosed,
    /// An attention item of the commitment was muted (ST-35); it never pauses the clock.
    Muted,
    /// A new definition version took effect.
    Redefined(&'a ClockDefinition),
}

/// A clock event at its ledger time.
#[derive(Clone, Copy, Debug)]
pub struct Timed<'a> {
    /// The ledger time of the record.
    pub at: Time,
    /// The event.
    pub event: ClockEvent<'a>,
}

/// Why a wait does not pause the clock (CM-52).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseRefusal {
    /// The definition declares no pause condition for the reason and the role waited on.
    Undeclared,
    /// The wait addresses no Party.
    Unaddressed,
    /// The author waits on itself: a one-sided pause.
    SelfAddressed,
    /// The wait does not say what is waited for.
    NoSubject,
}

/// A warning tier or the breach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// A warning tier in permille of the duration.
    Warning(u16),
    /// The breach line.
    Breach,
}

/// A tier the clock reached, under the definition version in effect then; never rewritten (CM-51).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reached {
    /// The tier.
    pub tier: Tier,
    /// When it was reached.
    pub at: Time,
    /// The definition version in effect.
    pub version: u32,
}

/// The run state of a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockState {
    /// No start event yet.
    NotStarted,
    /// Counting.
    Running,
    /// Paused by a valid wait.
    Paused,
    /// Stopped by a stop event.
    Met,
}

/// Why a clock cannot be projected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    /// The events are not in ledger time order.
    Order,
    /// A redefinition does not raise the version (CM-51).
    Version,
    /// Counted time cannot be computed.
    Calendar(CalendarError),
    /// The recurrence rule cannot be expanded.
    Rule(RuleError),
    /// Arithmetic left the integer range.
    Overflow,
}

impl core::fmt::Display for ClockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Order => f.write_str("clock events out of order"),
            Self::Version => f.write_str("a clock redefinition must raise the version"),
            Self::Calendar(e) => write!(f, "clock: {e}"),
            Self::Rule(e) => write!(f, "clock: {e}"),
            Self::Overflow => f.write_str("clock arithmetic overflow"),
        }
    }
}

impl core::error::Error for ClockError {}

impl From<CalendarError> for ClockError {
    fn from(e: CalendarError) -> Self {
        Self::Calendar(e)
    }
}

/// The projected clock (CM-51); never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockView {
    /// The run state.
    pub state: ClockState,
    /// The definition version in effect.
    pub version: u32,
    /// Counted milliseconds so far.
    pub elapsed: u64,
    /// Counted milliseconds left of the duration under the definition in effect.
    pub remaining: u64,
    /// The highest warning tier reached under any version.
    pub warning: Option<u16>,
    /// When the breach line was first reached, under any version.
    pub breached: Option<Time>,
    /// Every tier reached, in order.
    pub reached: Vec<Reached>,
    /// When the valid wait that pauses the clock opened.
    pub paused_since: Option<Time>,
    /// When a stop event met the target.
    pub met_at: Option<Time>,
    /// Waits that did not pause the clock, with their time.
    pub refused: Vec<(Time, PauseRefusal)>,
    /// When the next tier is reached if nothing else happens; only while running.
    pub next_change: Option<Time>,
    /// The tzdb version of the calendar zone counted in.
    pub tzdb: Option<String>,
}

struct Projector<'a> {
    def: &'a ClockDefinition,
    state: ClockState,
    cursor: Time,
    elapsed: u64,
    reached: Vec<Reached>,
    paused_since: Option<Time>,
    met_at: Option<Time>,
    refused: Vec<(Time, PauseRefusal)>,
}

impl<'a> Projector<'a> {
    fn is_reached(&self, tier: Tier) -> bool {
        self.reached.iter().any(|r| r.tier == tier)
    }

    fn run_to(&mut self, to: Time, zones: &[Zone]) -> Result<(), ClockError> {
        if self.state == ClockState::Running && to > self.cursor {
            let counting = Counting::of(self.def.calendar.as_ref(), zones)?;
            let end = self
                .elapsed
                .checked_add(counting.elapsed(self.cursor, to)?)
                .ok_or(ClockError::Overflow)?;
            for (tier, line) in self.def.lines()? {
                if line <= end && !self.is_reached(tier) {
                    let need = line.saturating_sub(self.elapsed);
                    let at = counting.advance(self.cursor, need)?.min(to);
                    self.reached.push(Reached {
                        tier,
                        at,
                        version: self.def.version,
                    });
                }
            }
            self.elapsed = end;
        }
        self.cursor = self.cursor.max(to);
        Ok(())
    }

    fn check(&self, wait: &Wait<'_>) -> Result<(), PauseRefusal> {
        let declared = self
            .def
            .pause
            .iter()
            .any(|p| p.reason == wait.reason && Some(p.awaited) == wait.awaited_role);
        if !declared {
            return Err(PauseRefusal::Undeclared);
        }
        let Some(awaited) = wait.awaited else {
            return Err(PauseRefusal::Unaddressed);
        };
        if awaited == wait.author {
            return Err(PauseRefusal::SelfAddressed);
        }
        if wait.subject.is_empty() {
            return Err(PauseRefusal::NoSubject);
        }
        Ok(())
    }

    fn apply(&mut self, at: Time, event: ClockEvent<'a>) -> Result<(), ClockError> {
        match event {
            ClockEvent::Started if self.state == ClockState::NotStarted => {
                self.state = ClockState::Running;
            }
            ClockEvent::Stopped
                if matches!(self.state, ClockState::Running | ClockState::Paused) =>
            {
                self.state = ClockState::Met;
                self.met_at = Some(at);
                self.paused_since = None;
            }
            ClockEvent::WaitOpened(wait) => match self.check(&wait) {
                Err(refusal) => self.refused.push((at, refusal)),
                Ok(()) if self.state == ClockState::Running => {
                    self.state = ClockState::Paused;
                    self.paused_since = Some(at);
                }
                Ok(()) => {}
            },
            ClockEvent::WaitClosed if self.state == ClockState::Paused => {
                self.state = ClockState::Running;
                self.paused_since = None;
            }
            ClockEvent::Redefined(next) => {
                if next.version <= self.def.version {
                    return Err(ClockError::Version);
                }
                self.def = next;
                for (tier, line) in self.def.lines()? {
                    if line <= self.elapsed && !self.is_reached(tier) {
                        self.reached.push(Reached {
                            tier,
                            at,
                            version: next.version,
                        });
                    }
                }
            }
            ClockEvent::Started
            | ClockEvent::Stopped
            | ClockEvent::WaitClosed
            | ClockEvent::Muted => {}
        }
        Ok(())
    }

    fn view(self, zones: &[Zone]) -> Result<ClockView, ClockError> {
        let counting = Counting::of(self.def.calendar.as_ref(), zones)?;
        let next_line = self
            .def
            .lines()?
            .into_iter()
            .filter(|(tier, line)| !self.is_reached(*tier) && *line > self.elapsed)
            .map(|(_, line)| line)
            .min();
        let next_change = match (self.state, next_line) {
            (ClockState::Running, Some(line)) => {
                Some(counting.advance(self.cursor, line.saturating_sub(self.elapsed))?)
            }
            _ => None,
        };
        let warning = self
            .reached
            .iter()
            .filter_map(|r| match r.tier {
                Tier::Warning(p) => Some(p),
                Tier::Breach => None,
            })
            .max();
        let breached = self
            .reached
            .iter()
            .find(|r| r.tier == Tier::Breach)
            .map(|r| r.at);
        Ok(ClockView {
            state: self.state,
            version: self.def.version,
            elapsed: self.elapsed,
            remaining: self.def.duration.saturating_sub(self.elapsed),
            warning,
            breached,
            reached: self.reached,
            paused_since: self.paused_since,
            met_at: self.met_at,
            refused: self.refused,
            next_change,
            tzdb: counting.zone().map(|z| String::from(z.version())),
        })
    }
}

/// Projects a clock at `now` from its initial definition and the clock events of the commitment's records, counted over the supplied tzdb zones (CM-51); events after `now` are not yet in effect, a redefinition applies from its time on without rewriting the tiers already reached, and a wait pauses only when [`PauseRefusal`] does not apply (CM-52).
///
/// # Errors
/// [`ClockError`] for events out of order, a redefinition that does not raise the version, a calendar zone missing from `zones` and overflow.
pub fn project<'a>(
    initial: &'a ClockDefinition,
    events: &[Timed<'a>],
    zones: &[Zone],
    now: Time,
) -> Result<ClockView, ClockError> {
    let mut p = Projector {
        def: initial,
        state: ClockState::NotStarted,
        cursor: Time(0),
        elapsed: 0,
        reached: Vec::new(),
        paused_since: None,
        met_at: None,
        refused: Vec::new(),
    };
    let mut last = Time(0);
    for e in events {
        if e.at < last {
            return Err(ClockError::Order);
        }
        last = e.at;
        if e.at > now {
            break;
        }
        p.run_to(e.at, zones)?;
        p.apply(e.at, e.event)?;
    }
    p.run_to(now, zones)?;
    p.view(zones)
}

/// A periodic update definition body (CM-53, CM-64).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodicDefinition {
    /// The definition version.
    pub version: u32,
    /// The recurrence rule as written.
    pub rule_text: String,
    /// The parsed rule.
    pub rule: Rule,
    /// The local `DTSTART`.
    pub dtstart: LocalDateTime,
    /// The IANA zone of `dtstart`, the creditor's or the definition's.
    pub zone: String,
    /// How far from an expected time a report still counts, in milliseconds.
    pub tolerance: u64,
    /// The report schema; the default status, done and needed schema when absent.
    pub schema: Option<String>,
}

/// One expected report of a periodic update commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Due {
    /// The expected time.
    pub expected: Time,
    /// The last time a report still counts.
    pub deadline: Time,
    /// The report Claim that met it.
    pub report: Option<Time>,
    /// Whether the deadline passed without a report: a breach signal.
    pub missed: bool,
}

/// The projected periodic update commitment; never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodicView {
    /// The expected reports up to the evaluation time.
    pub due: Vec<Due>,
    /// How many of them were missed.
    pub missed: usize,
    /// The deadline of the next report not yet in.
    pub next_deadline: Option<Time>,
    /// The tzdb version of the zone.
    pub tzdb: String,
}

impl PeriodicDefinition {
    /// Checks `value` against the `periodic` rule, including the recurrence rule subset.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Result<Self, BodyError> {
        members(
            value,
            &["version", "rule", "dtstart", "zone", "tolerance", "schema"],
        )?;
        let version = version(value)?;
        let rule_text = text(value, "rule", crate::rrule::MAX_TEXT)?;
        let rule = Rule::parse(rule_text).map_err(|_| BodyError("rule"))?;
        let dtstart = text(value, "dtstart", 15)
            .ok()
            .and_then(LocalDateTime::parse_basic)
            .ok_or(BodyError("dtstart"))?;
        let schema = match value.get("schema") {
            None => None,
            Some(_) => Some(String::from(text(value, "schema", MAX_NAME)?)),
        };
        Ok(Self {
            version,
            rule_text: String::from(rule_text),
            rule,
            dtstart,
            zone: String::from(text(value, "zone", crate::tz::MAX_NAME)?),
            tolerance: uint(value, "tolerance")?,
            schema,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            (
                Value::text("version"),
                Value::Unsigned(u64::from(self.version))
            ),
            (Value::text("rule"), Value::text(&self.rule_text)),
            (Value::text("dtstart"), Value::Text(self.dtstart.to_basic())),
            (Value::text("zone"), Value::text(&self.zone)),
            (Value::text("tolerance"), Value::Unsigned(self.tolerance)),
        ];
        if let Some(s) = &self.schema {
            entries.push((Value::text("schema"), Value::text(s)));
        }
        Value::Map(entries)
    }

    /// Reads deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        Self::from_value(&commitment_time::decode(bytes)?)
    }

    /// The deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`BodyError`] for a body [`PeriodicDefinition::from_value`] would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, BodyError> {
        let value = self.to_value();
        Self::from_value(&value)?;
        commitment_time::encode(&value)
    }

    /// Projects the commitment at `now`: the expected report times from `opened` up to `now` or its close, each met by the first unused report Claim time within the tolerance either side, and missed once its deadline passed without one (CM-53).
    ///
    /// # Errors
    /// [`ClockError`] when the zone is not among `zones`, more than `max` reports are expected, or the rule cannot be expanded.
    pub fn project(
        &self,
        zones: &[Zone],
        reports: &[Time],
        opened: Time,
        closed: Option<Time>,
        now: Time,
        max: usize,
    ) -> Result<PeriodicView, ClockError> {
        let zone = zones
            .iter()
            .find(|z| z.name() == self.zone)
            .ok_or(ClockError::Calendar(CalendarError::Zone))?;
        let end = closed.map_or(now, |c| c.min(now));
        let horizon = Time(end.0.checked_add(1).ok_or(ClockError::Overflow)?);
        let limit = max.checked_add(1).ok_or(ClockError::Overflow)?;
        let expected = self
            .rule
            .occurrences(self.dtstart, zone, opened, horizon, limit)
            .map_err(ClockError::Rule)?;
        if expected.len() > max {
            return Err(ClockError::Overflow);
        }
        let mut sorted = reports.to_vec();
        sorted.sort_unstable();
        let mut used = alloc::vec![false; sorted.len()];
        let mut due = Vec::with_capacity(expected.len());
        for at in expected {
            let low = at.0.saturating_sub(self.tolerance);
            let deadline = Time(at.0.saturating_add(self.tolerance));
            let found = sorted
                .iter()
                .enumerate()
                .find(|(i, r)| used.get(*i) == Some(&false) && low <= r.0 && **r <= deadline);
            let report = found.map(|(i, r)| {
                if let Some(slot) = used.get_mut(i) {
                    *slot = true;
                }
                *r
            });
            due.push(Due {
                expected: at,
                deadline,
                report,
                missed: report.is_none() && now > deadline,
            });
        }
        let pending = due
            .iter()
            .find(|d| d.report.is_none() && !d.missed)
            .map(|d| d.deadline);
        let next_deadline = match pending {
            Some(d) => Some(d),
            None if closed.is_none_or(|c| now < c) => self
                .rule
                .occurrences(
                    self.dtstart,
                    zone,
                    horizon,
                    closed.unwrap_or(Time(u64::MAX)),
                    1,
                )
                .map_err(ClockError::Rule)?
                .first()
                .map(|t| Time(t.0.saturating_add(self.tolerance))),
            None => None,
        };
        Ok(PeriodicView {
            missed: due.iter().filter(|d| d.missed).count(),
            due,
            next_deadline,
            tzdb: String::from(zone.version()),
        })
    }
}
