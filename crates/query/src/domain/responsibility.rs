//! The responsibility of a commitment, a queue and a Party's workload as the kernel derives them from the records (RC-1…RC-25, RC-44, RC-48), and the ledger-state checks of the responsibility Declarations a caller writes: the actor types the derivation reads are those Access bound into the ledger's envelopes at admission, no Party is known disabled and no group membership is known, so a group resolves only to the organisation rule's fallback here; the organisation is the one the ledger's first organisation rule names, else its only organisation Party; nothing here decides a rule of the kernel and nothing is stored.

use std::collections::BTreeMap;

use work_kernel::catalog::DeclarationSubtype;
use work_kernel::codec::Decoded;
use work_kernel::commitment::{CommitmentView, Refusal, StepOutcome};
use work_kernel::derive::{Derivation, Entry};
use work_kernel::id::{LedgerId, PartyRef, RecordId, Time};
use work_kernel::ontology::Obligor;
use work_kernel::record::{ParamScalar, ParamValue, Record};
use work_kernel::relation::Relation;
use work_kernel::responsibility::{
    Accountability, AccountabilitySource, AllocationSignal, AllocationSignalKind, AllocationState,
    Candidates, ChainLink, Directory, HoldVia, LeaseStatus, OrgRule, OrgRuleVersion,
    PARTICIPATION_KEY, PingPong, QueueDefinition, QueueVersion, Regime, Resolution,
    ResponsibilityOperation, Waiver, WaiverScope, Workload, accountability, accountability_chain,
    allocation_signals, allocation_state, lease_status, org_rules, ping_pong, queue_accountability,
    queue_versions, workload,
};
use work_kernel::validate::{ActorType, ActorTypeSource};
use work_proto::id::PositionToken;

use crate::domain::commitments::{FoldError, Folded, facts};
use crate::domain::reads::ReadRefusal;

/// What Access said about Parties as the ledger keeps it: the actor type Access bound to each
/// author and `on_behalf_of` ring at admission, the latest one winning; no Party is known
/// disabled and no group or role membership is known (RC-1, RC-7, P-12).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LedgerDirectory {
    actors: BTreeMap<PartyRef, ActorType>,
}

impl LedgerDirectory {
    /// The actor types Access bound into the envelopes of `folded`.
    #[must_use]
    pub fn of(folded: &Folded) -> Self {
        let mut actors = BTreeMap::new();
        for entry in folded.verified() {
            let Decoded::Record(record) = entry.record() else {
                continue;
            };
            let types = &entry.envelope().actor_types;
            let core = record.core();
            let rings = core.on_behalf_of.iter().flatten().zip(&types.on_behalf_of);
            for (party, t) in core::iter::once((&core.author, &types.author)).chain(rings) {
                if t.source == ActorTypeSource::AccessBinding {
                    actors.insert(party.clone(), t.actor_type);
                }
            }
        }
        Self { actors }
    }

    /// A directory of the given actor types.
    #[must_use]
    pub const fn from_actors(actors: BTreeMap<PartyRef, ActorType>) -> Self {
        Self { actors }
    }
}

impl Directory for LedgerDirectory {
    fn actor(&self, party: &PartyRef) -> Option<ActorType> {
        self.actors.get(party).copied()
    }

    fn disabled(&self, _party: &PartyRef) -> bool {
        false
    }

    fn members(&self, _group: &str) -> Option<Vec<PartyRef>> {
        None
    }
}

/// The responsibility of one commitment at an evaluation time (RC-1…RC-25): the accountable
/// Party and its chain, the assignment state, the lease, the ping-pong count, the assignment
/// signals and the reason of each forwarding in its history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Responsibility {
    /// The single accountable Party; `None` only when it falls to an organisation the ledger
    /// does not name.
    pub accountability: Option<Accountability>,
    /// The accountability chain in the order the derivation walks it (RC-5).
    pub chain: Vec<ChainLink>,
    /// The assignment state (RC-15, RC-16).
    pub state: AllocationState,
    /// The ownership lease (RC-18).
    pub lease: LeaseStatus,
    /// The forwarding count and chain (RC-14).
    pub ping_pong: PingPong,
    /// The assignment signals for the queue owner (RC-13, RC-14, RC-18).
    pub signals: Vec<AllocationSignal>,
    /// The reason each forwarding of its history gives, by record (RC-19).
    pub reasons: BTreeMap<RecordId, String>,
}

/// One commitment of a queue and its assignment (RC-10, RC-15, RC-16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueItem {
    /// The commitment, by its `request`.
    pub commitment: RecordId,
    /// Its assignment state.
    pub state: AllocationState,
    /// The obligor holding it.
    pub holder: Option<PartyRef>,
    /// The Party its open offer names.
    pub offered: Option<PartyRef>,
    /// Since when it is pooled.
    pub pooled_since: Option<Time>,
    /// Its forwarding count.
    pub ping_pong: PingPong,
    /// Its lease.
    pub lease: LeaseStatus,
    /// Its assignment signals.
    pub signals: Vec<AllocationSignalKind>,
}

/// A queue as its records derive it (RC-10…RC-14, RC-24): every definition version, the
/// accountable Party, its open work and the candidates over its WIP limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueView {
    /// The queue, the root of its definition chain.
    pub queue: RecordId,
    /// Every version in ledger order; the last is in force.
    pub versions: Vec<QueueVersion>,
    /// The queue's accountable Party (RC-7, RC-12).
    pub accountability: Option<Accountability>,
    /// The open commitments that are in the queue or were taken from it.
    pub work: Vec<QueueItem>,
    /// The workload of each listed candidate over the WIP limit in force (RC-24).
    pub overloaded: Vec<Workload>,
}

/// A queue read (RC-10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueRead {
    /// The ledger.
    pub ledger: LedgerId,
    /// The queue.
    pub view: QueueView,
    /// The ledger time the read reflects.
    pub at_ms: u64,
    /// The position the read reflects.
    pub position: PositionToken,
}

/// One commitment a Party holds (RC-18, RC-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldWork {
    /// The commitment, by its `request`.
    pub commitment: RecordId,
    /// The queue it was taken from.
    pub queue: Option<RecordId>,
    /// How it was taken.
    pub via: HoldVia,
    /// Since when.
    pub since: Time,
}

/// A WIP limit a queue in force declares for a Party it lists (RC-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WipLimit {
    /// The queue.
    pub queue: RecordId,
    /// The limit.
    pub limit: u64,
    /// Whether the open workload passes it.
    pub overloaded: bool,
}

/// The open workload of one Party (RC-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadView {
    /// The counts; running executions are not derived here and count 0.
    pub workload: Workload,
    /// The open commitments it holds.
    pub held: Vec<HeldWork>,
    /// The WIP limits of the queues in force that list it.
    pub limits: Vec<WipLimit>,
}

/// A workload read (RC-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadRead {
    /// The ledger.
    pub ledger: LedgerId,
    /// The workload.
    pub view: WorkloadView,
    /// The ledger time the read reflects.
    pub at_ms: u64,
    /// The position the read reflects.
    pub position: PositionToken,
}

fn text<'r>(record: &'r Record, name: &str) -> Option<&'r str> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Text(t)) => Some(t.as_str()),
        _ => None,
    }
}

fn subtype(record: &Record) -> Option<DeclarationSubtype> {
    match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str()),
        Record::Act(_) | Record::Claim(_) => None,
    }
}

/// The responsibility inputs a ledger's records give: queue definition versions, organisation
/// rules, the directory, the organisation and the forwarding reasons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    queues: Vec<QueueVersion>,
    rules: Vec<OrgRuleVersion>,
    directory: LedgerDirectory,
    organization: Option<PartyRef>,
    reasons: BTreeMap<RecordId, String>,
}

impl Ledger {
    /// The inputs of `folded`, whose entries and derivation are given.
    #[must_use]
    pub fn of(folded: &Folded, entries: &[Entry<'_>], derivation: &Derivation) -> Self {
        Self::with_directory(entries, derivation, LedgerDirectory::of(folded))
    }

    /// The inputs of `entries` with the actor types of `directory`.
    #[must_use]
    pub fn with_directory(
        entries: &[Entry<'_>],
        derivation: &Derivation,
        directory: LedgerDirectory,
    ) -> Self {
        let rules = org_rules(entries, derivation);
        let organization = rules
            .first()
            .map(|r| r.rule.organization.clone())
            .or_else(|| {
                let mut orgs = directory
                    .actors
                    .iter()
                    .filter(|(_, a)| **a == ActorType::Organization);
                match (orgs.next(), orgs.next()) {
                    (Some((only, _)), None) => Some(only.clone()),
                    _ => None,
                }
            });
        let reasons = entries
            .iter()
            .filter(|e| subtype(e.record()) == Some(ResponsibilityOperation::Forward.subtype()))
            .filter_map(|e| text(e.record(), "reason").map(|r| (e.id(), r.to_owned())))
            .collect();
        Self {
            queues: queue_versions(entries, derivation),
            rules,
            directory,
            organization,
            reasons,
        }
    }

    /// The organisation of the ledger, when it names one.
    #[must_use]
    pub const fn organization(&self) -> Option<&PartyRef> {
        self.organization.as_ref()
    }

    /// Every queue definition version with normative effect, in ledger order.
    #[must_use]
    pub fn queues(&self) -> &[QueueVersion] {
        &self.queues
    }

    /// The organisation rules in force.
    #[must_use]
    pub fn rules(&self) -> &[OrgRuleVersion] {
        &self.rules
    }

    fn known(&self, source: AccountabilitySource, rule: Option<RecordId>) -> bool {
        self.organization.is_some() || source != AccountabilitySource::OrgRule || rule.is_some()
    }

    /// The responsibility of `view` at ledger time `now` (RC-1…RC-25): Access's candidate
    /// membership and the activity that renews a lease are not known here.
    #[must_use]
    pub fn commitment(&self, view: &CommitmentView, now: Time) -> Responsibility {
        let organization = self
            .organization
            .clone()
            .unwrap_or_else(|| view.obligee.clone());
        let derived = accountability(view, &organization, &self.rules, &self.directory);
        let chain = accountability_chain(view, &organization, &self.rules, &self.directory)
            .into_iter()
            .filter(|l| self.known(l.source, None))
            .collect();
        let reasons = view
            .allocation
            .history
            .iter()
            .filter_map(|e| self.reasons.get(&e.record).map(|r| (e.record, r.clone())))
            .collect();
        Responsibility {
            accountability: self.known(derived.source, derived.rule).then_some(derived),
            chain,
            state: allocation_state(view, now, None),
            lease: lease_status(view, now, &[]),
            ping_pong: ping_pong(view),
            signals: allocation_signals(view, now, &[], None),
            reasons,
        }
    }

    fn in_force(&self) -> BTreeMap<RecordId, &QueueVersion> {
        self.queues.iter().map(|v| (v.queue, v)).collect()
    }

    /// The queue `queue` as `party` may read it at ledger time `now` (RC-10…RC-14, RC-24): its
    /// owner, a Party its Party list admits, or a Party that wrote one of its versions.
    ///
    /// # Errors
    /// [`ReadRefusal::NotFound`] for no such queue or one `party` may not read.
    pub fn queue(
        &self,
        views: &[CommitmentView],
        queue: &RecordId,
        party: &PartyRef,
        now: Time,
    ) -> Result<QueueView, ReadRefusal> {
        let versions: Vec<QueueVersion> = self
            .queues
            .iter()
            .filter(|v| v.queue == *queue)
            .cloned()
            .collect();
        let current = versions.last().ok_or(ReadRefusal::NotFound)?;
        let reads = current.definition.owner == *party
            || current.definition.admits(party) == Some(true)
            || versions.iter().any(|v| v.author_chain.contains(party));
        if !reads {
            return Err(ReadRefusal::NotFound);
        }
        let organization = self
            .organization
            .clone()
            .unwrap_or_else(|| current.definition.owner.clone());
        let derived = queue_accountability(current, &organization, &self.rules, &self.directory);
        let work = views
            .iter()
            .filter(|v| {
                v.allocation.queue == Some(*queue)
                    && v.opening == StepOutcome::Applied
                    && !v.is_terminal()
            })
            .map(|v| QueueItem {
                commitment: v.root,
                state: allocation_state(v, now, None),
                holder: match &v.obligor {
                    Obligor::Party(p) => Some(p.clone()),
                    Obligor::Queue(_) => None,
                },
                offered: v.allocation.offer.as_ref().map(|o| o.to.clone()),
                pooled_since: v.allocation.pooled_since,
                ping_pong: ping_pong(v),
                lease: lease_status(v, now, &[]),
                signals: allocation_signals(v, now, &[], None)
                    .into_iter()
                    .map(|s| s.kind)
                    .collect(),
            })
            .collect();
        let overloaded = match (&current.definition.candidates, current.definition.wip_limit) {
            (Candidates::Parties(list), Some(limit)) => list
                .iter()
                .map(|p| workload(views, p, 0))
                .filter(|w| w.overloaded(Some(limit)))
                .collect(),
            _ => Vec::new(),
        };
        Ok(QueueView {
            queue: *queue,
            accountability: self.known(derived.source, derived.rule).then_some(derived),
            versions,
            work,
            overloaded,
        })
    }

    /// The open workload of `party` as `caller` may read it (RC-24): the Party itself, or the
    /// owner of a queue in force whose Party list admits it.
    ///
    /// # Errors
    /// [`ReadRefusal::NotFound`] for a caller that may not read it.
    pub fn workload(
        &self,
        views: &[CommitmentView],
        party: &PartyRef,
        caller: &PartyRef,
    ) -> Result<WorkloadView, ReadRefusal> {
        let in_force = self.in_force();
        let listing: Vec<&QueueVersion> = in_force
            .values()
            .copied()
            .filter(|v| v.definition.admits(party) == Some(true))
            .collect();
        if party != caller && !listing.iter().any(|v| v.definition.owner == *caller) {
            return Err(ReadRefusal::NotFound);
        }
        let counted = workload(views, party, 0);
        let held = views
            .iter()
            .filter(|v| !v.is_terminal() && matches!(&v.obligor, Obligor::Party(p) if p == party))
            .filter_map(|v| {
                v.allocation.hold.as_ref().map(|h| HeldWork {
                    commitment: v.root,
                    queue: v.allocation.queue,
                    via: h.via,
                    since: h.since,
                })
            })
            .collect();
        let limits = listing
            .iter()
            .filter_map(|v| {
                v.definition.wip_limit.map(|limit| WipLimit {
                    queue: v.queue,
                    limit,
                    overloaded: counted.overloaded(Some(limit)),
                })
            })
            .collect();
        Ok(WorkloadView {
            workload: counted,
            held,
            limits,
        })
    }
}

/// The queue `queue` of `folded` as `party` may read it (RC-10…RC-14, RC-24).
///
/// # Errors
/// [`ReadRefusal::NotFound`] for no such queue or one `party` may not read,
/// [`ReadRefusal::Unavailable`] when the ledger does not fold.
pub fn queue(
    folded: &Folded,
    queue: &RecordId,
    party: &PartyRef,
    position: PositionToken,
) -> Result<QueueRead, ReadRefusal> {
    let (entries, derivation, views) = folded
        .derive_all(&facts())
        .map_err(|_| ReadRefusal::Unavailable)?;
    let (_, at_ms) = folded.head();
    let view =
        Ledger::of(folded, &entries, &derivation).queue(&views, queue, party, Time(at_ms))?;
    Ok(QueueRead {
        ledger: *folded.ledger(),
        view,
        at_ms,
        position,
    })
}

/// The open workload of `party` in `folded` as `caller` may read it (RC-24).
///
/// # Errors
/// [`ReadRefusal::NotFound`] for a caller that may not read it,
/// [`ReadRefusal::Unavailable`] when the ledger does not fold.
pub fn party_workload(
    folded: &Folded,
    party: &PartyRef,
    caller: &PartyRef,
    position: PositionToken,
) -> Result<WorkloadRead, ReadRefusal> {
    let (entries, derivation, views) = folded
        .derive_all(&facts())
        .map_err(|_| ReadRefusal::Unavailable)?;
    let (_, at_ms) = folded.head();
    let view = Ledger::of(folded, &entries, &derivation).workload(&views, party, caller)?;
    Ok(WorkloadRead {
        ledger: *folded.ledger(),
        view,
        at_ms,
        position,
    })
}

fn engaged(record: &Record) -> Vec<&PartyRef> {
    record
        .core()
        .relations
        .iter()
        .flatten()
        .filter_map(|r| match r {
            Relation::EngagedIn { source, .. } => Some(source),
            _ => None,
        })
        .collect()
}

/// The Parties whose Access actor type the check of a responsibility Declaration reads: the
/// `accountable` Party of a `request` or `amend`, the owner of a queue definition, the
/// organisation, fallback and fixed resolutions of an organisation rule, and the Party a
/// participation policy is declared for (RC-6, RC-12, RC-44, RC-48).
#[must_use]
pub fn named_parties(record: &Record) -> Vec<PartyRef> {
    let mut out: Vec<PartyRef> = text(record, "accountable")
        .and_then(PartyRef::new)
        .into_iter()
        .collect();
    if let Some(q) = QueueDefinition::of(record) {
        out.push(q.owner);
    }
    if let Some(rule) = OrgRule::of(record) {
        out.push(rule.organization);
        out.push(rule.fallback);
        out.extend(rule.groups.into_iter().filter_map(|(_, r)| match r {
            Resolution::Party(p) => Some(p),
            Resolution::Role(_) => None,
        }));
    }
    if record.param(PARTICIPATION_KEY).is_some() {
        out.extend(engaged(record).into_iter().cloned());
    }
    out.sort();
    out.dedup();
    out
}

fn require(condition: bool, refusal: Refusal) -> Result<(), Refusal> {
    if condition { Ok(()) } else { Err(refusal) }
}

/// The ledger-state check of a responsibility Declaration a caller writes, before it is written
/// (RC-6, RC-9, RC-10, RC-12, RC-44, RC-48), by the Access actor types `actors` gives; a Party
/// Access does not type is not refused here, since the derivation passes over it:
/// - an `accountable` Party, a queue owner, an organisation rule's fallback and fixed
///   resolutions must be a Party the `default` regime ends in, a human or an organisation
///   (`not_accountable`);
/// - a new queue definition version must supersede the version in force of its chain, and an
///   organisation rule must start the only chain of its organisation or supersede that chain's
///   version in force, naming an organisation Party (`wrong_target`); a definition or rule the
///   kernel cannot read is `missing_content`;
/// - a waiver must narrow a waivable guarantee (`waiver_forbidden`) of a commitment of the
///   ledger (`wrong_target`);
/// - a participation policy goes beside exactly one `engaged_in` (`missing_content`) of an
///   agent (`wrong_target`).
///
/// # Errors
/// The [`Refusal`] of the first rule that fails.
pub fn check_against(
    record: &Record,
    id: RecordId,
    queues: &[QueueVersion],
    rules: &[OrgRuleVersion],
    views: &[CommitmentView],
    actors: &BTreeMap<PartyRef, ActorType>,
) -> Result<(), Refusal> {
    let ends = |p: &PartyRef| actors.get(p).is_none_or(|a| Regime::Default.ends_in(*a));
    if let Some(accountable) = text(record, "accountable").and_then(PartyRef::new) {
        require(ends(&accountable), Refusal::NotAccountable)?;
    }
    match subtype(record) {
        Some(DeclarationSubtype::QueueDefinition) => {
            let definition = QueueDefinition::of(record).ok_or(Refusal::MissingContent)?;
            require(ends(&definition.owner), Refusal::NotAccountable)?;
            if let Some(target) = record.supersedes().next() {
                let chain = queues
                    .iter()
                    .find(|v| v.version == *target)
                    .map(|v| v.queue)
                    .ok_or(Refusal::WrongTarget)?;
                let latest = queues.iter().rev().find(|v| v.queue == chain);
                require(
                    latest.is_some_and(|v| v.version == *target),
                    Refusal::WrongTarget,
                )?;
            }
        }
        Some(DeclarationSubtype::OrgRule) => {
            let rule = OrgRule::of(record).ok_or(Refusal::MissingContent)?;
            require(
                actors
                    .get(&rule.organization)
                    .is_none_or(|a| *a == ActorType::Organization),
                Refusal::WrongTarget,
            )?;
            require(ends(&rule.fallback), Refusal::NotAccountable)?;
            for (_, resolution) in &rule.groups {
                if let Resolution::Party(p) = resolution {
                    require(ends(p), Refusal::NotAccountable)?;
                }
            }
            let current = rules
                .iter()
                .find(|r| r.rule.organization == rule.organization);
            let continues = match (record.supersedes().next(), current) {
                (None, None) => true,
                (Some(target), Some(c)) => c.version == *target,
                (None, Some(_)) | (Some(_), None) => false,
            };
            require(continues, Refusal::WrongTarget)?;
        }
        Some(DeclarationSubtype::Waiver) => {
            let waiver = Waiver::of(record, id).ok_or(Refusal::WaiverForbidden)?;
            if let WaiverScope::Commitment(c) = waiver.scope {
                require(views.iter().any(|v| v.root == c), Refusal::WrongTarget)?;
            }
        }
        _ => {}
    }
    if record.param(PARTICIPATION_KEY).is_some() {
        let parties = engaged(record);
        let [agent] = parties.as_slice() else {
            return Err(Refusal::MissingContent);
        };
        require(
            actors.get(*agent).is_none_or(|a| *a == ActorType::Agent),
            Refusal::WrongTarget,
        )?;
    }
    Ok(())
}

/// Whether [`check_against`] reads the ledger's records for `record`: a queue definition, an
/// organisation rule or a waiver.
#[must_use]
pub fn reads_ledger(record: &Record) -> bool {
    matches!(
        subtype(record),
        Some(
            DeclarationSubtype::QueueDefinition
                | DeclarationSubtype::OrgRule
                | DeclarationSubtype::Waiver
        )
    )
}

/// Whether `record` carries anything [`check_against`] checks.
#[must_use]
pub fn checked(record: &Record) -> bool {
    reads_ledger(record)
        || record.param("accountable").is_some()
        || record.param(PARTICIPATION_KEY).is_some()
}

/// [`check_against`] over the records of `folded`; `None` for a record that reads no ledger
/// state.
///
/// # Errors
/// [`FoldError::Derive`] when the kernel refuses the sequence.
pub fn check_declaration(
    record: &Record,
    id: RecordId,
    folded: Option<&Folded>,
    actors: &BTreeMap<PartyRef, ActorType>,
) -> Result<Result<(), Refusal>, FoldError> {
    match folded {
        Some(folded) if reads_ledger(record) => {
            let (entries, derivation, views) = folded.derive_all(&facts())?;
            let queues = queue_versions(&entries, &derivation);
            let rules = org_rules(&entries, &derivation);
            Ok(check_against(record, id, &queues, &rules, &views, actors))
        }
        _ => Ok(check_against(record, id, &[], &[], &[], actors)),
    }
}

#[cfg(test)]
mod tests;
