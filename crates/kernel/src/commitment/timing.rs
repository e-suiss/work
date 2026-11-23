//! The time Conditions of a commitment (CM-47, CM-48, CM-49, CM-50, CM-51, CM-53, CM-63, CM-64, WD-146): its clocks, periodic update and budget are Condition records the `request` lists in `conditions`, each holding its `work/commitment-time/1` definition in the `definition` body part and changed only by a later Condition record that supersedes it and applies forward; the records of the commitment map to clock events here and nowhere else, consumption and report Claims count when they reference the budget Condition or the commitment's `request` and come from the commitment's obligor, and every projection is recomputed from the records, the opened definitions, the supplied tzdb zones and the evaluation time, never stored.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use super::operation::Operation;
use super::support::{SupportCause, SupportSignal};
use super::view::{ActiveEndCause, CommitmentView, StepOutcome};
use crate::budget::{self, Amount, Budget, BudgetError, BudgetView, Consumption};
use crate::catalog::{ClaimSubtype, DeclarationSubtype};
use crate::clock::{
    self, ClockDefinition, ClockError, ClockEvent, ClockView, PeriodicDefinition, PeriodicView,
    Target, Timed,
};
use crate::commitment_time::{BodyError, DEFINITION_PART, TimeCondition};
use crate::derive::{Entry, Ingest};
use crate::id::{PartyRef, RecordId, Time};
use crate::ontology::Obligor;
use crate::record::{ClaimType, ParamScalar, ParamValue, Record};
use crate::relation::{DerivedTarget, ReferenceTarget, Relation};
use crate::tz::Zone;

/// The extension key of a periodic report `observation` Claim (CM-53, WD-146).
pub const REPORT_EXT_KEY: &str = "https://suiss.app/ns/work/periodic.report/1";

/// The body parts of a periodic report under the default schema: the status, the progress the obligor reports and what it needs (CM-53).
pub const REPORT_PARTS: [&str; 3] = ["status", "done", "need"];

/// Most expected reports one periodic projection holds.
pub const MAX_DUE: usize = 10_000;

/// Deepest sub-commitment level a budget rolls up from (CM-48).
pub const MAX_DEPTH: usize = 16;

/// The clock event names a definition may declare for each target, as `(start, stop)` (WD-146 item 4): the response clock starts at the `request` and stops at the first answer; the start clock starts at the binding and stops at the obligor's first Act or `state`; the finish clock starts at the binding and stops at acceptance or a terminal outcome; a `reject` never restarts a clock.
#[must_use]
pub const fn clock_events(target: Target) -> (&'static [&'static str], &'static [&'static str]) {
    match target {
        Target::Response => (
            &["request"],
            &["promise", "promise_conditional", "decline", "counter"],
        ),
        Target::Start => (&["promise", "accept_counter"], &["act", "state"]),
        Target::Finish => (&["promise", "accept_counter"], &["accept", "terminal"]),
    }
}

/// A decoded definition of a clock, periodic or budget Condition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Definition {
    /// A clock definition (CM-50).
    Clock(ClockDefinition),
    /// A periodic update definition (CM-53).
    Periodic(PeriodicDefinition),
    /// A budget (CM-48).
    Budget(Budget),
}

impl Definition {
    /// The Condition type it belongs to.
    #[must_use]
    pub const fn condition(&self) -> TimeCondition {
        match self {
            Self::Clock(_) => TimeCondition::Clock,
            Self::Periodic(_) => TimeCondition::Periodic,
            Self::Budget(_) => TimeCondition::Budget,
        }
    }

    /// Reads the `definition` part of a Condition of `condition`: a clock may declare only the event names of its target (WD-146 item 4).
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn decode(condition: TimeCondition, bytes: &[u8]) -> Result<Self, BodyError> {
        match condition {
            TimeCondition::Clock => {
                let def = ClockDefinition::decode(bytes)?;
                let (start, stop) = clock_events(def.target);
                if !def.start.iter().all(|n| start.contains(&n.as_str())) {
                    return Err(BodyError("start"));
                }
                if !def.stop.iter().all(|n| stop.contains(&n.as_str())) {
                    return Err(BodyError("stop"));
                }
                Ok(Self::Clock(def))
            }
            TimeCondition::Periodic => PeriodicDefinition::decode(bytes).map(Self::Periodic),
            TimeCondition::Budget => Budget::decode(bytes).map(Self::Budget),
        }
    }

    fn version(&self) -> Option<u32> {
        match self {
            Self::Clock(c) => Some(c.version),
            Self::Periodic(p) => Some(p.version),
            Self::Budget(_) => None,
        }
    }

    /// Checks that `self` may supersede `previous` (CM-51): the same Condition type, a clock of the same target, a budget of the same measure, and a higher version for a clock or a periodic update.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not continue `previous`.
    pub fn continues(&self, previous: &Self) -> Result<(), BodyError> {
        match (previous, self) {
            (Self::Clock(a), Self::Clock(b)) if a.target != b.target => Err(BodyError("target")),
            (Self::Budget(a), Self::Budget(b)) if a.measure != b.measure => {
                Err(BodyError("measure"))
            }
            (a, b) if a.condition() != b.condition() => Err(BodyError("body")),
            (a, b) => match (a.version(), b.version()) {
                (Some(old), Some(new)) if new <= old => Err(BodyError("version")),
                _ => Ok(()),
            },
        }
    }

    /// The tzdb zone the definition counts in, if any.
    #[must_use]
    pub fn zone(&self) -> Option<&str> {
        match self {
            Self::Clock(c) => c.calendar.as_ref().map(|k| k.zone.as_str()),
            Self::Periodic(p) => Some(p.zone.as_str()),
            Self::Budget(_) => None,
        }
    }
}

/// The time Condition type of a record: an `open_condition` declaring a clock, periodic or budget `condition_type`.
#[must_use]
pub fn condition_of(record: &Record) -> Option<TimeCondition> {
    let Record::Declaration(d) = record else {
        return None;
    };
    if DeclarationSubtype::from_uri(d.subtype.as_str()) != Some(DeclarationSubtype::OpenCondition) {
        return None;
    }
    match record.param("condition_type")? {
        ParamValue::Scalar(ParamScalar::Text(t)) => TimeCondition::from_uri(t),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

/// The opened `definition` parts the caller supplies, by Condition record.
pub trait Definitions {
    /// The content of the record's `definition` part, if it opened.
    fn definition(&self, record: &RecordId) -> Option<&[u8]>;
}

impl Definitions for alloc::collections::BTreeMap<RecordId, Vec<u8>> {
    fn definition(&self, record: &RecordId) -> Option<&[u8]> {
        self.get(record).map(Vec::as_slice)
    }
}

/// What a time projection reads besides the commitment.
#[derive(Clone, Copy)]
pub struct TimeInputs<'a> {
    /// The ledger's entries in order, as the commitments were derived from.
    pub entries: &'a [Entry<'a>],
    /// Every commitment of the ledger, for the sub-commitments of a budget.
    pub views: &'a [CommitmentView],
    /// The opened `definition` parts.
    pub definitions: &'a dyn Definitions,
    /// The tzdb zones the definitions count in.
    pub zones: &'a [Zone],
    /// The evaluation time.
    pub now: Time,
}

/// One version of a time Condition: its record, its ledger time and its definition.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Version {
    record: RecordId,
    at: Time,
    definition: Definition,
}

/// A time Condition's chain of versions, from the record the `request` lists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Chain {
    versions: Vec<Version>,
    ignored: Vec<RecordId>,
}

fn chain_of(condition: RecordId, kind: TimeCondition, inputs: &TimeInputs<'_>) -> Option<Chain> {
    let mut members: BTreeSet<RecordId> = BTreeSet::new();
    let mut out = Chain::default();
    for e in admitted(inputs) {
        let id = e.id();
        let continues = id == condition
            || (!members.is_empty() && e.record().supersedes().any(|t| members.contains(t)));
        if !continues || condition_of(e.record()) != Some(kind) {
            continue;
        }
        members.insert(id);
        let decoded = inputs
            .definitions
            .definition(&id)
            .and_then(|b| Definition::decode(kind, b).ok());
        let accepted = match (&decoded, out.versions.last()) {
            (Some(next), Some(last)) => next.continues(&last.definition).is_ok(),
            (Some(_), None) => true,
            (None, _) => false,
        };
        match decoded {
            Some(definition) if accepted => out.versions.push(Version {
                record: id,
                at: e.recorded_at(),
                definition,
            }),
            _ if id == condition => return None,
            _ => out.ignored.push(id),
        }
    }
    (!out.versions.is_empty()).then_some(out)
}

fn admitted<'a>(inputs: &TimeInputs<'a>) -> impl Iterator<Item = &'a Entry<'a>> + use<'a> {
    let entries: &'a [Entry<'a>] = inputs.entries;
    entries.iter().filter(|e| e.ingest() == Ingest::Admitted)
}

/// The obligors whose records and Claims count for the commitment: the obligor in force and those it was delegated away from.
fn executors(view: &CommitmentView) -> Vec<PartyRef> {
    let mut out: Vec<PartyRef> = Vec::new();
    if let Obligor::Party(p) = &view.obligor {
        out.push(p.clone());
    }
    for end in &view.active_ends {
        if end.cause == ActiveEndCause::Delegated && !out.contains(&end.obligor) {
            out.push(end.obligor.clone());
        }
    }
    out
}

fn targets(record: &Record) -> impl Iterator<Item = RecordId> + '_ {
    record
        .core()
        .relations
        .iter()
        .flatten()
        .filter_map(|r| match r {
            Relation::Serves { target, .. }
            | Relation::References {
                target: ReferenceTarget::Record(target),
                ..
            }
            | Relation::DerivedFrom {
                target: DerivedTarget::Record(target),
                ..
            } => Some(*target),
            _ => None,
        })
}

fn references(record: &Record) -> impl Iterator<Item = RecordId> + '_ {
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
        })
}

const fn terminal(op: Operation) -> bool {
    matches!(
        op,
        Operation::Decline
            | Operation::Cancel
            | Operation::Release
            | Operation::Expire
            | Operation::AdministrativeClose
            | Operation::DeclareObsolete
            | Operation::RevokeRequest
    )
}

/// The clock event names one entry of the ledger gives the commitment `view` (WD-146 item 4): `request` for its opening, the wire name of every applied operation and `terminal` beside a terminal outcome, and `act` for an Act of an obligor that serves, references or derives from one of its records.
#[must_use]
pub fn event_names(view: &CommitmentView, entry: &Entry<'_>) -> Vec<&'static str> {
    let id = entry.id();
    if id == view.root {
        return alloc::vec!["request"];
    }
    if let Some(step) = view.steps.iter().find(|s| s.record == id) {
        if step.outcome != StepOutcome::Applied {
            return Vec::new();
        }
        let mut out = alloc::vec![step.operation.wire_name()];
        if terminal(step.operation) {
            out.push("terminal");
        }
        return out;
    }
    let record = entry.record();
    let own = |t: RecordId| t == view.root || view.steps.iter().any(|s| s.record == t);
    if matches!(record, Record::Act(_))
        && executors(view).contains(&record.core().author)
        && targets(record).any(own)
    {
        return alloc::vec!["act"];
    }
    Vec::new()
}

/// A projected clock of the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockProjection {
    /// The Condition record the `request` lists.
    pub condition: RecordId,
    /// The version in effect.
    pub definition: RecordId,
    /// The target.
    pub target: Target,
    /// The projection.
    pub view: Result<ClockView, ClockError>,
    /// Later Condition records whose definition did not open or did not continue the chain.
    pub ignored: Vec<RecordId>,
}

/// A projected periodic update of the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodicProjection {
    /// The Condition record the `request` lists.
    pub condition: RecordId,
    /// The version in effect.
    pub definition: RecordId,
    /// The projection.
    pub view: Result<PeriodicView, ClockError>,
    /// The report Claims counted.
    pub reports: usize,
    /// Report Claims not counted: from a Party that is not its obligor, or without the default parts.
    pub ignored_reports: usize,
    /// Later Condition records whose definition did not open or did not continue the chain.
    pub ignored: Vec<RecordId>,
}

/// A projected budget of the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetProjection {
    /// The Condition record the `request` lists.
    pub condition: RecordId,
    /// The version in effect.
    pub definition: RecordId,
    /// The budget in effect.
    pub budget: Budget,
    /// The projection.
    pub view: Result<BudgetView, BudgetError>,
    /// Later Condition records whose definition did not open or did not continue the chain.
    pub ignored: Vec<RecordId>,
}

/// Every time Condition of one commitment, projected; never stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimeProjection {
    /// The clocks.
    pub clocks: Vec<ClockProjection>,
    /// The periodic updates.
    pub periodic: Vec<PeriodicProjection>,
    /// The budgets.
    pub budgets: Vec<BudgetProjection>,
    /// Listed time Conditions whose first definition did not open.
    pub undefined: Vec<RecordId>,
}

impl TimeProjection {
    /// Whether a budget is exhausted, which hands the next move to the accountable Party (CM-49).
    #[must_use]
    pub fn budget_exhausted(&self) -> bool {
        self.budgets
            .iter()
            .any(|b| b.view.as_ref().is_ok_and(|v| v.exhausted))
    }
}

fn time_conditions(
    view: &CommitmentView,
    inputs: &TimeInputs<'_>,
) -> Vec<(RecordId, TimeCondition)> {
    view.conditions
        .iter()
        .filter_map(|c| {
            inputs
                .entries
                .iter()
                .find(|e| e.id() == *c)
                .and_then(|e| condition_of(e.record()))
                .map(|k| (*c, k))
        })
        .collect()
}

fn clock_projection(
    view: &CommitmentView,
    c: RecordId,
    chain: &Chain,
    inputs: &TimeInputs<'_>,
) -> Option<ClockProjection> {
    let defs: Vec<(RecordId, Time, &ClockDefinition)> = chain
        .versions
        .iter()
        .filter_map(|v| match &v.definition {
            Definition::Clock(d) => Some((v.record, v.at, d)),
            _ => None,
        })
        .collect();
    let (_, _, initial) = *defs.first()?;
    let mut current = initial;
    let mut events: Vec<Timed<'_>> = Vec::new();
    for e in admitted(inputs) {
        let at = e.recorded_at();
        if let Some(&(_, _, next)) = defs.iter().skip(1).find(|(r, _, _)| *r == e.id()) {
            current = next;
            events.push(Timed {
                at,
                event: ClockEvent::Redefined(next),
            });
            continue;
        }
        let names = event_names(view, e);
        if names
            .iter()
            .any(|n| current.start.iter().any(|s| s.as_str() == *n))
        {
            events.push(Timed {
                at,
                event: ClockEvent::Started,
            });
        }
        if names
            .iter()
            .any(|n| current.stop.iter().any(|s| s.as_str() == *n))
        {
            events.push(Timed {
                at,
                event: ClockEvent::Stopped,
            });
        }
    }
    let (last, _, _) = *defs.last()?;
    Some(ClockProjection {
        condition: c,
        definition: last,
        target: current.target,
        view: clock::project(initial, &events, inputs.zones, inputs.now),
        ignored: chain.ignored.clone(),
    })
}

fn first_time(view: &CommitmentView, inputs: &TimeInputs<'_>, names: &[&str]) -> Option<Time> {
    admitted(inputs)
        .find(|e| event_names(view, e).iter().any(|n| names.contains(n)))
        .map(Entry::recorded_at)
}

fn claims_of<'a>(
    inputs: &TimeInputs<'a>,
    key: &'static str,
) -> impl Iterator<Item = (&'a Entry<'a>, &'a [u8])> + use<'a> {
    admitted(inputs).filter_map(move |e| match e.record() {
        Record::Claim(c) if c.subtype == ClaimType::Core(ClaimSubtype::Observation) => c
            .core
            .ext
            .iter()
            .flatten()
            .find(|x| x.key.as_str() == key)
            .map(|x| (e, x.value.0.as_slice())),
        _ => None,
    })
}

fn has_parts(record: &Record) -> bool {
    REPORT_PARTS.iter().all(|p| {
        record
            .core()
            .body
            .iter()
            .flatten()
            .any(|b| b.part.as_str() == *p)
    })
}

fn periodic_projection(
    view: &CommitmentView,
    c: RecordId,
    chain: &Chain,
    inputs: &TimeInputs<'_>,
) -> Option<PeriodicProjection> {
    let defs: Vec<(RecordId, Time, &PeriodicDefinition)> = chain
        .versions
        .iter()
        .filter_map(|v| match &v.definition {
            Definition::Periodic(d) => Some((v.record, v.at, d)),
            _ => None,
        })
        .collect();
    let (last, _, latest) = *defs.last()?;
    let executors = executors(view);
    let mut reports: Vec<Time> = Vec::new();
    let mut ignored_reports: usize = 0;
    for (e, _) in claims_of(inputs, REPORT_EXT_KEY) {
        if !references(e.record()).any(|t| t == view.root) {
            continue;
        }
        let counted = executors.contains(&e.record().core().author)
            && (latest.schema.is_some() || has_parts(e.record()));
        if counted {
            reports.push(e.recorded_at());
        } else {
            ignored_reports = ignored_reports.saturating_add(1);
        }
    }
    let bound = first_time(view, inputs, &["promise", "accept_counter"]);
    let closed = first_time(view, inputs, &["accept", "terminal"]);
    let view_of = |bound: Time| -> Result<PeriodicView, ClockError> {
        let mut merged: Option<PeriodicView> = None;
        for (i, (_, at, def)) in defs.iter().enumerate() {
            let from = bound.max(*at);
            let until = defs.get(i.saturating_add(1)).map(|(_, next, _)| *next);
            let end = match (until, closed) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if end.is_some_and(|e| e <= from) {
                continue;
            }
            let part = def.project(inputs.zones, &reports, from, end, inputs.now, MAX_DUE)?;
            merged = Some(match merged {
                None => part,
                Some(mut acc) => {
                    acc.due.extend(part.due);
                    if acc.due.len() > MAX_DUE {
                        return Err(ClockError::Overflow);
                    }
                    acc.missed = acc.missed.saturating_add(part.missed);
                    acc.next_deadline = part.next_deadline;
                    acc.tzdb = part.tzdb;
                    acc
                }
            });
        }
        Ok(merged.unwrap_or(PeriodicView {
            due: Vec::new(),
            missed: 0,
            next_deadline: None,
            tzdb: zone_version(inputs.zones, &latest.zone),
        }))
    };
    let projected = match bound {
        Some(b) => view_of(b),
        None => Ok(PeriodicView {
            due: Vec::new(),
            missed: 0,
            next_deadline: None,
            tzdb: zone_version(inputs.zones, &latest.zone),
        }),
    };
    Some(PeriodicProjection {
        condition: c,
        definition: last,
        view: projected,
        reports: reports.len(),
        ignored_reports,
        ignored: chain.ignored.clone(),
    })
}

fn zone_version(zones: &[Zone], name: &str) -> String {
    zones
        .iter()
        .find(|z| z.name() == name)
        .map(|z| String::from(z.version()))
        .unwrap_or_default()
}

fn budget_of(
    view: &CommitmentView,
    inputs: &TimeInputs<'_>,
    depth: usize,
    seen: &mut BTreeSet<RecordId>,
) -> Vec<BudgetProjection> {
    if depth > MAX_DEPTH || !seen.insert(view.root) {
        return Vec::new();
    }
    let mut children: Vec<Amount> = Vec::new();
    for child in inputs
        .views
        .iter()
        .filter(|v| v.supports.contains(&view.root) && v.opening == StepOutcome::Applied)
    {
        for b in budget_of(child, inputs, depth.saturating_add(1), seen) {
            if let Ok(v) = b.view {
                children.push(Amount {
                    measure: b.budget.measure,
                    amount: v.consumed,
                });
            }
        }
    }
    let executors = executors(view);
    let mut out = Vec::new();
    for (c, kind) in time_conditions(view, inputs) {
        if kind != TimeCondition::Budget {
            continue;
        }
        let Some(chain) = chain_of(c, kind, inputs) else {
            continue;
        };
        let members: Vec<RecordId> = chain
            .versions
            .iter()
            .map(|v| v.record)
            .chain(chain.ignored.iter().copied())
            .collect();
        let Some(Version {
            record,
            definition: Definition::Budget(budget),
            ..
        }) = chain.versions.last()
        else {
            continue;
        };
        let consumption: Vec<Consumption<'_>> = claims_of(inputs, budget::CONSUMPTION_EXT_KEY)
            .filter(|(e, _)| references(e.record()).any(|t| members.contains(&t)))
            .filter(|(e, _)| e.recorded_at() <= inputs.now)
            .filter_map(|(e, bytes)| {
                Amount::decode(bytes).ok().map(|amount| Consumption {
                    source: &e.record().core().author,
                    amount,
                })
            })
            .collect();
        out.push(BudgetProjection {
            condition: c,
            definition: *record,
            budget: budget.clone(),
            view: budget.evaluate(&executors, &consumption, &children),
            ignored: chain.ignored.clone(),
        });
    }
    out
}

/// Projects every time Condition `view` lists at `inputs.now` (CM-48, CM-50, CM-51, CM-53): each Condition's chain of definitions from the opened `definition` parts, a later version applying from its ledger time on when it continues the chain; the clock events from the commitment's records; the periodic reports from the binding to acceptance or a terminal outcome; the budget from its consumption Claims and the totals of its sub-commitments.
#[must_use]
pub fn project(view: &CommitmentView, inputs: &TimeInputs<'_>) -> TimeProjection {
    let mut out = TimeProjection::default();
    for (c, kind) in time_conditions(view, inputs) {
        let Some(chain) = chain_of(c, kind, inputs) else {
            out.undefined.push(c);
            continue;
        };
        match kind {
            TimeCondition::Clock => out.clocks.extend(clock_projection(view, c, &chain, inputs)),
            TimeCondition::Periodic => {
                out.periodic
                    .extend(periodic_projection(view, c, &chain, inputs));
            }
            TimeCondition::Budget => {}
        }
    }
    out.budgets = budget_of(view, inputs, 0, &mut BTreeSet::new());
    out
}

/// The Condition records of `view` and of the commitments that support it, down to [`MAX_DEPTH`], whose `definition` part a projection reads, each with its ledger position.
#[must_use]
pub fn definition_records(view: &CommitmentView, inputs: &TimeInputs<'_>) -> Vec<(RecordId, u64)> {
    let mut roots: Vec<&CommitmentView> = alloc::vec![view];
    let mut seen: BTreeSet<RecordId> = BTreeSet::new();
    let mut conditions: BTreeSet<RecordId> = BTreeSet::new();
    let mut depth = 0;
    while !roots.is_empty() && depth <= MAX_DEPTH {
        let mut next = Vec::new();
        for v in roots {
            if !seen.insert(v.root) {
                continue;
            }
            for (c, _) in time_conditions(v, inputs) {
                conditions.insert(c);
            }
            next.extend(inputs.views.iter().filter(|c| c.supports.contains(&v.root)));
        }
        roots = next;
        depth = depth.saturating_add(1);
    }
    let mut members: BTreeSet<RecordId> = BTreeSet::new();
    let mut out = Vec::new();
    for e in admitted(inputs) {
        let id = e.id();
        let listed =
            conditions.contains(&id) || e.record().supersedes().any(|t| members.contains(t));
        let carries = e
            .record()
            .core()
            .body
            .iter()
            .flatten()
            .any(|b| b.part.as_str() == DEFINITION_PART);
        if listed && condition_of(e.record()).is_some() && carries {
            members.insert(id);
            out.push((id, e.position()));
        }
    }
    out
}

/// The tzdb zones the definitions in `inputs` name, each once in ascending order.
#[must_use]
pub fn zones_named(view: &CommitmentView, inputs: &TimeInputs<'_>) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for (id, _) in definition_records(view, inputs) {
        let kind = inputs
            .entries
            .iter()
            .find(|e| e.id() == id)
            .and_then(|e| condition_of(e.record()));
        let decoded = kind.and_then(|k| {
            inputs
                .definitions
                .definition(&id)
                .and_then(|b| Definition::decode(k, b).ok())
        });
        if let Some(zone) = decoded.as_ref().and_then(Definition::zone) {
            out.insert(String::from(zone));
        }
    }
    out.into_iter().collect()
}

/// The signals the clocks and periodic updates of the sub-commitments in `children` raise on `parent` (CM-47): a breached clock, else the highest warning tier reached, and a missed periodic report; each names the Condition record that raised it.
#[must_use]
pub fn clock_signals(
    parent: &CommitmentView,
    children: &[(&CommitmentView, &TimeProjection)],
) -> Vec<SupportSignal> {
    let notify = match &parent.obligor {
        Obligor::Party(p) => Some(p.clone()),
        Obligor::Queue(_) => None,
    };
    let mut out = Vec::new();
    for (child, time) in children
        .iter()
        .filter(|(c, _)| c.supports.contains(&parent.root))
    {
        for clock in &time.clocks {
            let Ok(v) = &clock.view else {
                continue;
            };
            let cause = if v.breached.is_some() {
                SupportCause::ClockBreach
            } else if v.warning.is_some() {
                SupportCause::ClockWarning
            } else {
                continue;
            };
            out.push(SupportSignal {
                parent: parent.root,
                child: child.root,
                cause,
                record: clock.condition,
                notify: notify.clone(),
            });
        }
        for periodic in &time.periodic {
            if periodic.view.as_ref().is_ok_and(|v| v.missed > 0) {
                out.push(SupportSignal {
                    parent: parent.root,
                    child: child.root,
                    cause: SupportCause::ReportMissed,
                    record: periodic.condition,
                    notify: notify.clone(),
                });
            }
        }
    }
    out
}
