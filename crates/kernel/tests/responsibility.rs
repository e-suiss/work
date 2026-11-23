//! Responsibility over typed records: the accountable Party and its chain, the organisation rule, queue definitions, the assignment axis and the responsibility operations folded into the commitment lifecycle, the lease, distribution decisions, workload, principal guarantees, participation and role labels.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code"
)]

use std::collections::BTreeMap;

use work_kernel::catalog::DeclarationSubtype;
use work_kernel::commitment::{
    AccessAnswer, ActiveEndCause, Caller, CommitmentState, CommitmentView, Facts, Mover, Operation,
    Policy, Proposed, Refusal, StepOutcome, Summary, allowed_responsibility, check_responsibility,
    derive_commitments, next_moves,
};
use work_kernel::derive::{
    AuthorityIssuer, BusinessCalendar, Derivation, DerivationInputs, Entry, Ingest, ProfileVersion,
    Restriction, TrustInputs, derive,
};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time, WorkId};
use work_kernel::limits::SemanticLimits;
use work_kernel::ontology::Obligor;
use work_kernel::reason::{EnvelopeField, Reason, Schema};
use work_kernel::record::{
    Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Claim, ClaimType,
    Declaration, Param, ParamScalar, ParamValue, PartName, ProtocolVersion, Record, RecordCore,
    VersionVector, Visibility,
};
use work_kernel::relation::Relation;
use work_kernel::responsibility::{
    AccountabilitySource, ActBy, AssignmentAct, AssignmentSignalKind, AssignmentState,
    CommitmentEffect, ControlSpan, Directory, DistributionMethod, ForwardTarget, HoldVia,
    InterventionMark, LeaseExpiry, LeaseStatus, ParticipationPolicy, PrincipalGuarantee,
    QueueDefinition, Regime, ResponsibilityOperation, SUGGESTED_PARTICIPATION, access_wait,
    accountability, assignment_signals, assignment_state, decisions, guarantees, in_force,
    interventions, lease_status, org_rules, participation, ping_pong, queue_accountability,
    queue_versions, resolve_group, rule_for, waivers, workload,
};
use work_kernel::rules::RuleSet;
use work_kernel::uri::TypeUri;
use work_kernel::validate::{
    ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin, Outcome, ValidationContext,
    validate,
};

const ALICE: &str = "party:acme:alice";
const BOB: &str = "party:acme:bob";
const CAROL: &str = "party:acme:carol";
const DAVE: &str = "party:acme:dave";
const OWNER: &str = "party:acme:desk-lead";
const ORG: &str = "party:acme:org";
const FALLBACK: &str = "party:acme:duty-manager";
const AGENT: &str = "party:acme:agent-procure-7";
const AGENT_2: &str = "party:acme:agent-review-2";
const SYS: &str = "party:acme:work-scheduler";
const CORE: &str = "https://suiss.app/ns/work/";

fn party(s: &str) -> PartyRef {
    PartyRef::new(s).unwrap()
}

fn id(n: usize) -> RecordId {
    let mut bytes = [0x6d_u8; 32];
    bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
    RecordId(Digest::sha256(bytes))
}

fn t(s: &str) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Text(s.to_owned()))
}

fn u(n: u64) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Uint(n))
}

fn d(r: RecordId) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Digest(r.0))
}

fn list(items: &[&str]) -> ParamValue {
    ParamValue::List(
        items
            .iter()
            .map(|s| ParamScalar::Text((*s).to_owned()))
            .collect(),
    )
}

fn digests(items: &[RecordId]) -> ParamValue {
    let mut sorted = items.to_vec();
    sorted.sort();
    ParamValue::List(sorted.iter().map(|r| ParamScalar::Digest(r.0)).collect())
}

fn work() -> WorkId {
    WorkId::from_bytes([0x42; 16])
}

fn core(author: &str, head: Option<RecordId>, params: &[(&str, ParamValue)]) -> RecordCore {
    let mut params: Vec<Param> = params
        .iter()
        .map(|(k, v)| Param {
            name: PartName::parse(k).unwrap(),
            value: v.clone(),
        })
        .collect();
    params.sort_by(|a, b| work_kernel::id::canonical_text_cmp(a.name.as_str(), b.name.as_str()));
    RecordCore {
        author: party(author),
        on_behalf_of: None,
        capacity: Some(Capacity::Own),
        basis: Some(vec![]),
        visibility: Visibility {
            see: Audience::Author,
            search_excluded: false,
            agent_context_excluded: false,
        },
        ledger: LedgerId(Digest::sha256([1; 32])),
        concerns: vec![],
        relations: head.map(|target| {
            vec![Relation::Supersedes {
                target,
                qualifier: None,
            }]
        }),
        authority: Some(AuthorityRef {
            proof: AuthorityProofKind::DecisionReceipt,
            digest: Digest::sha256([2; 32]),
        }),
        producer: None,
        correlation: None,
        evidence: None,
        body: None,
        params: (!params.is_empty()).then_some(params),
        versions: VersionVector {
            protocol: ProtocolVersion { major: 1, minor: 0 },
            schema: Digest::sha256([3; 32]),
            practices: None,
        },
        ext: None,
        critical: None,
    }
}

fn decl(author: &str, name: &str, head: Option<RecordId>, params: &[(&str, ParamValue)]) -> Record {
    Record::Declaration(Declaration {
        subtype: TypeUri::parse(&format!("{CORE}declaration/{name}")).unwrap(),
        occurred_at: None,
        core: core(author, head, params),
    })
}

fn observation(author: &str, params: &[(&str, ParamValue)]) -> Record {
    Record::Claim(Claim {
        subtype: ClaimType::from_uri(TypeUri::parse(&format!("{CORE}claim/observation")).unwrap()),
        occurred_at: Time(1),
        core: RecordCore {
            capacity: None,
            basis: None,
            authority: None,
            ..core(author, None, params)
        },
    })
}

fn core_mut(record: &mut Record) -> &mut RecordCore {
    match record {
        Record::Act(r) => &mut r.core,
        Record::Declaration(r) => &mut r.core,
        Record::Claim(r) => &mut r.core,
    }
}

fn with_basis(mut record: Record, basis: &[RecordId]) -> Record {
    let mut b = basis.to_vec();
    b.sort();
    core_mut(&mut record).basis = Some(b);
    record
}

fn with_note(mut record: Record) -> Record {
    core_mut(&mut record).body = Some(vec![BodyCommitment {
        part: PartName::parse("note").unwrap(),
        commit: Digest::sha256([4; 32]),
    }]);
    record
}

fn on_behalf(mut record: Record, chain: &[&str]) -> Record {
    let core = core_mut(&mut record);
    core.on_behalf_of = Some(chain.iter().copied().map(party).collect());
    core.capacity = Some(Capacity::For(party(chain[0])));
    record
}

fn engaging(mut record: Record, agent: &str, label: Option<&str>) -> Record {
    core_mut(&mut record)
        .relations
        .get_or_insert_with(Vec::new)
        .push(Relation::EngagedIn {
            source: party(agent),
            target: work(),
            qualifier: label.map(|l| TypeUri::parse(l).unwrap()),
        });
    record
}

fn actor_of(author: &str) -> ActorType {
    match author {
        AGENT | AGENT_2 => ActorType::Agent,
        ORG => ActorType::Organization,
        SYS => ActorType::System,
        _ => ActorType::Human,
    }
}

fn validated(record: &Record) -> Outcome {
    let entry = |p: &PartyRef| ActorTypeEntry {
        actor_type: actor_of(p.as_str()),
        source: ActorTypeSource::AccessBinding,
    };
    let core = record.core();
    let actors = ActorTypes {
        author: entry(&core.author),
        on_behalf_of: core.on_behalf_of.iter().flatten().map(entry).collect(),
        evidence: vec![],
    };
    validate(
        record,
        &ValidationContext {
            origin: Origin::Direct,
            actor_types: &actors,
            understood_extensions: &[],
            limits: SemanticLimits::DEFAULT,
            recorded_at: None,
        },
    )
}

struct Ledger {
    records: Vec<(RecordId, Record, ActorType, u64)>,
}

impl Ledger {
    fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    fn at(&mut self, record: Record, recorded_at: u64) -> RecordId {
        let rid = id(self.records.len() + 1);
        let actor = actor_of(record.core().author.as_str());
        self.records.push((rid, record, actor, recorded_at));
        rid
    }

    fn push(&mut self, record: Record) -> RecordId {
        let next = self.records.last().map_or(1000, |r| r.3 + 1000);
        self.at(record, next)
    }

    fn entries(&self) -> Vec<Entry<'_>> {
        self.records
            .iter()
            .zip(1_u64..)
            .map(|((rid, record, actor, at), position)| {
                Entry::unverified(
                    *rid,
                    record,
                    position,
                    Time(*at),
                    Ingest::Admitted,
                    Restriction::NoObjection,
                    AuthorityIssuer::Local,
                )
                .with_author(*actor, false)
            })
            .collect()
    }

    fn derivation(entries: &[Entry<'_>]) -> Derivation {
        let activations = [(0, RuleSet::V1_0.protocol())];
        let inputs = DerivationInputs {
            activations: &activations,
            profile: ProfileVersion(1),
            practices: &[],
            trust: TrustInputs {
                trusted_publishers: &[],
            },
            ledger_time: Time(u64::MAX / 2),
            calendar: BusinessCalendar::Continuous,
        };
        derive(entries, &inputs).unwrap()
    }

    fn view(&self, root: RecordId) -> CommitmentView {
        let entries = self.entries();
        let derivation = Self::derivation(&entries);
        let facts = Facts {
            conditions_met: &[],
            policy: Policy::default(),
            budget_exhausted: false,
        };
        derive_commitments(&entries, &derivation, &facts)
            .into_iter()
            .find(|v| v.root == root)
            .unwrap()
    }

    fn outcome(&self, root: RecordId, record: RecordId) -> StepOutcome {
        self.view(root)
            .assignment
            .history
            .iter()
            .find(|e| e.record == record)
            .unwrap()
            .outcome
    }

    fn records(&self) -> BTreeMap<RecordId, &Record> {
        self.records.iter().map(|r| (r.0, &r.1)).collect()
    }

    fn time(&self, record: RecordId) -> u64 {
        self.records.iter().find(|r| r.0 == record).unwrap().3
    }
}

struct Dir {
    disabled: Vec<&'static str>,
    roles: Vec<(&'static str, Vec<&'static str>)>,
}

impl Dir {
    fn new() -> Self {
        Self {
            disabled: Vec::new(),
            roles: Vec::new(),
        }
    }
}

impl Directory for Dir {
    fn actor(&self, p: &PartyRef) -> Option<ActorType> {
        Some(actor_of(p.as_str()))
    }

    fn disabled(&self, p: &PartyRef) -> bool {
        self.disabled.contains(&p.as_str())
    }

    fn members(&self, group: &str) -> Option<Vec<PartyRef>> {
        self.roles
            .iter()
            .find(|(g, _)| *g == group)
            .map(|(_, members)| members.iter().copied().map(party).collect())
    }
}

fn queue(ledger: &mut Ledger, extra: &[(&str, ParamValue)]) -> RecordId {
    let mut params = vec![("owner", t(OWNER)), ("candidates", list(&[BOB, CAROL]))];
    params.extend(extra.iter().cloned());
    ledger.push(decl(OWNER, "queue_definition", None, &params))
}

fn pooled(ledger: &mut Ledger, queue: RecordId) -> RecordId {
    ledger.push(decl(
        ALICE,
        "request",
        None,
        &[("queue", d(queue)), ("acceptor", t(ALICE))],
    ))
}

fn summary(view: &CommitmentView) -> Summary {
    view.summary()
}

fn proposed(record: &Record, access: AccessAnswer) -> Proposed<'_> {
    Proposed {
        id: id(9999),
        record,
        position: 9999,
        recorded_at: Time(9_999_000),
        author_actor: actor_of(record.core().author.as_str()),
        step_up: false,
        access,
        agent_side: false,
        control_supported: false,
    }
}

// RC-10 RC-11 RC-21
#[test]
fn rc_10_rc_11_a_queue_definition_is_a_versioned_declaration_with_pull_by_default() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[]);
    let record = &ledger.records[0].1;
    assert_eq!(validated(record), Outcome::Accepted);
    let definition = QueueDefinition::of(record).unwrap();
    assert_eq!(definition.distribution, DistributionMethod::Pull);
    assert_eq!(definition.admits(&party(BOB)), Some(true));
    assert_eq!(definition.admits(&party(DAVE)), Some(false));
    let v2 = ledger.push(decl(
        OWNER,
        "queue_definition",
        Some(q),
        &[
            ("owner", t(OWNER)),
            ("candidate_group", t("group:acme:legal")),
            ("distribution", t("push")),
        ],
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let versions = queue_versions(&entries, &derivation);
    assert_eq!(versions.len(), 2);
    assert!(versions.iter().all(|v| v.queue == q));
    assert_eq!(in_force(&versions, q, 2).unwrap().version, q);
    let latest = in_force(&versions, q, 3).unwrap();
    assert_eq!(latest.version, v2);
    assert_eq!(latest.definition.distribution, DistributionMethod::Push);
    assert_eq!(latest.definition.admits(&party(DAVE)), None);
    let both = decl(
        OWNER,
        "queue_definition",
        None,
        &[
            ("owner", t(OWNER)),
            ("candidates", list(&[BOB])),
            ("candidate_group", t("group:acme:legal")),
        ],
    );
    assert_eq!(
        validated(&both),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let half_lease = decl(
        OWNER,
        "queue_definition",
        None,
        &[
            ("owner", t(OWNER)),
            ("candidates", list(&[BOB])),
            ("lease", u(5)),
        ],
    );
    assert_eq!(
        validated(&half_lease),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
}

// RC-12
#[test]
fn rc_12_a_queue_without_an_owner_is_a_schema_error() {
    let ownerless = decl(
        OWNER,
        "queue_definition",
        None,
        &[("candidates", list(&[BOB]))],
    );
    assert_eq!(
        validated(&ownerless),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    assert!(QueueDefinition::of(&ownerless).is_none());
}

// RC-12 RC-7 RC-48
#[test]
fn rc_12_pooled_work_and_the_queue_are_the_owner_s_and_never_ownerless() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[]);
    let root = pooled(&mut ledger, q);
    let view = ledger.view(root);
    let org = party(ORG);
    let dir = Dir::new();
    let a = accountability(&view, &org, &[], &dir);
    assert_eq!(a.party, party(OWNER));
    assert_eq!(a.source, AccountabilitySource::QueueOwner);
    assert!(a.derived);
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let versions = queue_versions(&entries, &derivation);
    let owned = queue_accountability(&versions[0], &org, &[], &dir);
    assert_eq!(owned.party, party(OWNER));
    assert!(!owned.derived);
    let gone = Dir {
        disabled: vec![OWNER],
        roles: Vec::new(),
    };
    let fallen = queue_accountability(&versions[0], &org, &[], &gone);
    assert_eq!(fallen.party, org);
    assert!(fallen.unowned);
    assert_eq!(fallen.source, AccountabilitySource::OrgRule);
}

// RC-17
#[test]
fn rc_17_the_responsibility_set_is_closed_and_maps_to_the_commitment_axis() {
    assert_eq!(ResponsibilityOperation::CLOSED_SET.len(), 7);
    for op in ResponsibilityOperation::ALL {
        assert_eq!(ResponsibilityOperation::of(op.subtype()), Some(*op));
        assert_eq!(Operation::of(op.subtype()), None);
        assert!(!op.wire_name().contains('-'));
    }
    assert_eq!(
        ResponsibilityOperation::Claim.commitment_effect(),
        CommitmentEffect::Promise
    );
    assert_eq!(
        ResponsibilityOperation::Unclaim.commitment_effect(),
        CommitmentEffect::ReturnToRequested
    );
    for op in [
        ResponsibilityOperation::Forward,
        ResponsibilityOperation::Nominate,
        ResponsibilityOperation::Offer,
        ResponsibilityOperation::Reassign,
        ResponsibilityOperation::RenewLease,
    ] {
        assert_eq!(op.commitment_effect(), CommitmentEffect::Unchanged);
    }
    assert_eq!(
        ResponsibilityOperation::of(DeclarationSubtype::Release),
        None
    );
}

// RC-17 RC-15 RC-16
#[test]
fn rc_17_claim_promises_and_unclaim_returns_to_requested_without_a_release() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[]);
    let root = pooled(&mut ledger, q);
    let pool = ledger.view(root);
    assert_eq!(summary(&pool), Summary::Uniform(CommitmentState::Requested));
    assert_eq!(
        assignment_state(&pool, Time(0), None),
        AssignmentState::Pooled
    );
    let claim = ledger.push(decl(BOB, "claim", Some(root), &[]));
    let held = ledger.view(root);
    assert_eq!(summary(&held), Summary::Uniform(CommitmentState::Promised));
    assert_eq!(held.obligor, Obligor::Party(party(BOB)));
    assert_eq!(
        assignment_state(&held, Time(0), None),
        AssignmentState::Held
    );
    let taken = held.assignment.hold.as_ref().unwrap();
    assert_eq!((taken.via, taken.record), (HoldVia::Claim, claim));
    assert_eq!(held.steps.len(), 0);
    let unclaim = ledger.push(decl(BOB, "unclaim", Some(claim), &[]));
    let back = ledger.view(root);
    assert_eq!(summary(&back), Summary::Uniform(CommitmentState::Requested));
    assert_eq!(back.obligor, Obligor::Queue(q));
    assert_eq!(
        assignment_state(&back, Time(0), None),
        AssignmentState::Pooled
    );
    assert_eq!(back.active_ends.len(), 1);
    assert_eq!(back.active_ends[0].cause, ActiveEndCause::Unclaimed);
    assert_eq!(back.active_ends[0].obligor, party(BOB));
    assert!(!back.is_terminal());
    assert!(back.steps.iter().all(|s| s.operation != Operation::Release));
    assert!(back.continues(&unclaim));
    let again = ledger.push(decl(CAROL, "claim", Some(unclaim), &[]));
    assert_eq!(ledger.outcome(root, again), StepOutcome::Applied);
    assert_eq!(ledger.view(root).obligor, Obligor::Party(party(CAROL)));
}

// RC-11 RC-21 RC-17
#[test]
fn rc_11_claims_follow_the_candidates_the_exclusions_and_the_pull_method() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[("excluded", list(&[CAROL]))]);
    let root = pooled(&mut ledger, q);
    let outsider = ledger.push(decl(DAVE, "claim", Some(root), &[]));
    let excluded = ledger.push(decl(CAROL, "claim", Some(outsider), &[]));
    let promise = ledger.push(decl(DAVE, "promise", Some(excluded), &[]));
    assert_eq!(
        ledger.outcome(root, outsider),
        StepOutcome::Refused(Refusal::NotACandidate)
    );
    assert_eq!(
        ledger.outcome(root, excluded),
        StepOutcome::Refused(Refusal::NotACandidate)
    );
    assert_eq!(
        ledger.outcome(root, promise),
        StepOutcome::Refused(Refusal::NotACandidate)
    );
    assert_eq!(
        summary(&ledger.view(root)),
        Summary::Uniform(CommitmentState::Requested)
    );
    let mut push = Ledger::new();
    let q = queue(&mut push, &[("distribution", t("push"))]);
    let root = pooled(&mut push, q);
    let claim = push.push(decl(BOB, "claim", Some(root), &[]));
    assert_eq!(
        push.outcome(root, claim),
        StepOutcome::Refused(Refusal::PolicyMethod)
    );
}

// RC-17
#[test]
fn rc_17_an_offer_is_answered_by_section_9_and_a_nomination_binds_no_one() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[("distribution", t("push"))]);
    let root = pooled(&mut ledger, q);
    let nominate = ledger.push(decl(OWNER, "nominate", Some(root), &[("party", t(CAROL))]));
    let view = ledger.view(root);
    assert_eq!(view.obligor, Obligor::Queue(q));
    assert_eq!(view.assignment.nominations[0].party, party(CAROL));
    let offer = ledger.push(decl(OWNER, "offer", Some(nominate), &[("party", t(BOB))]));
    let offered = ledger.view(root);
    assert_eq!(
        assignment_state(&offered, Time(0), None),
        AssignmentState::Offered
    );
    let facts = Facts {
        conditions_met: &[],
        policy: Policy::default(),
        budget_exhausted: false,
    };
    assert_eq!(next_moves(&offered, &facts), vec![Mover::Party(party(BOB))]);
    let twice = ledger.push(decl(OWNER, "offer", Some(offer), &[("party", t(CAROL))]));
    assert_eq!(
        ledger.outcome(root, twice),
        StepOutcome::Refused(Refusal::AlreadyPending)
    );
    let declined = ledger.push(decl(
        BOB,
        "decline",
        Some(twice),
        &[("reason", t("no_capacity"))],
    ));
    let after = ledger.view(root);
    assert_eq!(
        summary(&after),
        Summary::Uniform(CommitmentState::Requested)
    );
    assert_eq!(
        assignment_state(&after, Time(0), None),
        AssignmentState::Pooled
    );
    let to_carol = ledger.push(decl(OWNER, "offer", Some(declined), &[("party", t(CAROL))]));
    ledger.push(decl(CAROL, "promise", Some(to_carol), &[]));
    let held = ledger.view(root);
    assert_eq!(held.obligor, Obligor::Party(party(CAROL)));
    assert_eq!(held.assignment.hold.as_ref().unwrap().via, HoldVia::Offer);
    assert!(held.assignment.offer.is_none());
    assert_eq!(held.assignment.offers.len(), 2);
}

// RC-17
#[test]
fn rc_17_reassign_keeps_the_obligor_until_the_delegation_is_accepted() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[]);
    let root = pooled(&mut ledger, q);
    let claim = ledger.push(decl(BOB, "claim", Some(root), &[]));
    let stranger = ledger.push(decl(DAVE, "reassign", Some(claim), &[("party", t(CAROL))]));
    assert_eq!(
        ledger.outcome(root, stranger),
        StepOutcome::Refused(Refusal::WrongRole)
    );
    let reassign = ledger.push(decl(
        OWNER,
        "reassign",
        Some(stranger),
        &[("party", t(CAROL))],
    ));
    let pending = ledger.view(root);
    assert_eq!(pending.obligor, Obligor::Party(party(BOB)));
    assert_eq!(
        pending.pending.delegation.as_ref().unwrap().record,
        reassign
    );
    ledger.push(decl(
        CAROL,
        "delegate",
        Some(reassign),
        &[("step", t("acceptance")), ("proposal", d(reassign))],
    ));
    let moved = ledger.view(root);
    assert_eq!(moved.obligor, Obligor::Party(party(CAROL)));
    assert_eq!(
        moved.assignment.hold.as_ref().unwrap().via,
        HoldVia::Delegation
    );
    assert_eq!(moved.active_ends[0].cause, ActiveEndCause::Delegated);
}

// RC-14
#[test]
fn rc_14_every_forwarding_counts_and_past_the_threshold_signals_the_owner() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[("ping_pong_threshold", u(1))]);
    let other = ledger.push(decl(
        OWNER,
        "queue_definition",
        None,
        &[
            ("owner", t(OWNER)),
            ("candidates", list(&[DAVE])),
            ("ping_pong_threshold", u(1)),
        ],
    ));
    let root = pooled(&mut ledger, q);
    let reasonless = decl(OWNER, "forward", Some(root), &[("queue", d(other))]);
    assert_eq!(
        validated(&reasonless),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let other_note = decl(
        OWNER,
        "forward",
        Some(root),
        &[("queue", d(other)), ("reason", t("other"))],
    );
    assert_eq!(
        validated(&other_note),
        Outcome::Rejected(Reason::Schema(Schema::RequiredField))
    );
    assert_eq!(validated(&with_note(other_note)), Outcome::Accepted);
    let first = ledger.push(decl(
        OWNER,
        "forward",
        Some(root),
        &[("queue", d(other)), ("reason", t("wrong_recipient"))],
    ));
    let moved = ledger.view(root);
    assert_eq!(moved.obligor, Obligor::Queue(other));
    assert_eq!(ping_pong(&moved).count, 1);
    assert!(!ping_pong(&moved).over);
    let second = ledger.push(decl(
        OWNER,
        "forward",
        Some(first),
        &[("candidates", list(&[BOB])), ("reason", t("expertise"))],
    ));
    let view = ledger.view(root);
    let count = ping_pong(&view);
    assert_eq!(count.count, 2);
    assert!(count.over);
    assert_eq!(
        count.chain,
        vec![
            ForwardTarget::Queue(other),
            ForwardTarget::Candidates(vec![party(BOB)])
        ]
    );
    let signals = assignment_signals(&view, Time(0), &[], None);
    assert!(
        signals
            .iter()
            .any(|s| s.kind == AssignmentSignalKind::PingPong && s.to == Some(party(OWNER)))
    );
    assert_eq!(summary(&view), Summary::Uniform(CommitmentState::Requested));
    let claim = ledger.push(decl(DAVE, "claim", Some(second), &[]));
    assert_eq!(
        ledger.outcome(root, claim),
        StepOutcome::Refused(Refusal::NotACandidate)
    );
}

// RC-18
#[test]
fn rc_18_a_lease_runs_out_and_the_work_service_returns_the_work() {
    let mut ledger = Ledger::new();
    let q = queue(
        &mut ledger,
        &[("lease", u(5000)), ("lease_expiry", t("return_to_pool"))],
    );
    let root = pooled(&mut ledger, q);
    let claim = ledger.push(decl(BOB, "claim", Some(root), &[]));
    let start = ledger.time(claim);
    let view = ledger.view(root);
    assert_eq!(
        lease_status(&view, Time(start + 1), &[]),
        LeaseStatus::Running(Time(start + 5000))
    );
    assert_eq!(
        lease_status(&view, Time(start + 6000), &[Time(start + 2000)]),
        LeaseStatus::Running(Time(start + 7000))
    );
    let early = ledger.push(with_basis(decl(SYS, "unclaim", Some(claim), &[]), &[claim]));
    assert_eq!(
        ledger.outcome(root, early),
        StepOutcome::Refused(Refusal::NotYetDue)
    );
    let renew = ledger.push(decl(BOB, "renew_lease", Some(early), &[]));
    let renewed = ledger.time(renew);
    let view = ledger.view(root);
    assert_eq!(
        lease_status(&view, Time(renewed + 5000), &[]),
        LeaseStatus::Expired {
            at: Time(renewed + 5000),
            expiry: LeaseExpiry::ReturnToPool
        }
    );
    let signals = assignment_signals(&view, Time(renewed + 5000), &[], None);
    assert!(
        signals
            .iter()
            .any(|s| s.kind == AssignmentSignalKind::LeaseExpired && s.unclaim_due)
    );
    let due = ledger.at(
        with_basis(decl(SYS, "unclaim", Some(renew), &[]), &[claim]),
        renewed + 5000,
    );
    assert_eq!(ledger.outcome(root, due), StepOutcome::Applied);
    let back = ledger.view(root);
    assert_eq!(back.obligor, Obligor::Queue(q));
    assert_eq!(
        lease_status(&back, Time(renewed + 9000), &[]),
        LeaseStatus::NoLease
    );
    let mut direct = Ledger::new();
    let root = direct.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(BOB)), ("acceptor", t(ALICE))],
    ));
    let promise = direct.push(decl(BOB, "promise", Some(root), &[]));
    let renew = direct.push(decl(BOB, "renew_lease", Some(promise), &[]));
    assert_eq!(
        direct.outcome(root, renew),
        StepOutcome::Refused(Refusal::NoLease)
    );
    assert_eq!(
        lease_status(&direct.view(root), Time(u64::MAX), &[]),
        LeaseStatus::NoLease
    );
}

// RC-18
#[test]
fn rc_18_a_kept_lease_only_signals_the_owner() {
    let mut ledger = Ledger::new();
    let q = queue(
        &mut ledger,
        &[("lease", u(1000)), ("lease_expiry", t("keep_and_signal"))],
    );
    let root = pooled(&mut ledger, q);
    let claim = ledger.push(decl(BOB, "claim", Some(root), &[]));
    let late = ledger.time(claim) + 3000;
    let unclaim = ledger.at(
        with_basis(decl(SYS, "unclaim", Some(claim), &[]), &[claim]),
        late,
    );
    assert_eq!(
        ledger.outcome(root, unclaim),
        StepOutcome::Refused(Refusal::PolicyMethod)
    );
    let view = ledger.view(root);
    let signals = assignment_signals(&view, Time(late), &[], None);
    assert!(
        signals
            .iter()
            .any(|s| s.kind == AssignmentSignalKind::LeaseExpired && !s.unclaim_due)
    );
    let renew = ledger.push(decl(BOB, "renew_lease", Some(unclaim), &[]));
    assert_eq!(ledger.outcome(root, renew), StepOutcome::Applied);
}

// RC-13 RC-15
#[test]
fn rc_13_nobody_took_it_after_the_start_deadline_or_without_candidates() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[("start_within", u(2000))]);
    let root = pooled(&mut ledger, q);
    let opened = ledger.time(root);
    let view = ledger.view(root);
    assert_eq!(
        assignment_state(&view, Time(opened + 1999), None),
        AssignmentState::Pooled
    );
    assert_eq!(
        assignment_state(&view, Time(opened + 2000), None),
        AssignmentState::FailedToAssign
    );
    assert_eq!(
        assignment_state(&view, Time(opened), Some(false)),
        AssignmentState::FailedToAssign
    );
    assert!(
        assignment_signals(&view, Time(opened + 2000), &[], None)
            .iter()
            .any(|s| s.kind == AssignmentSignalKind::FailedToAssign && s.to == Some(party(OWNER)))
    );
    ledger.push(decl(BOB, "claim", Some(root), &[]));
    let held = ledger.view(root);
    assert_eq!(
        assignment_state(&held, Time(opened + 9000), Some(false)),
        AssignmentState::Held
    );
    assert_eq!(summary(&held), Summary::Uniform(CommitmentState::Promised));
}

// RC-19
#[test]
fn rc_19_the_history_keeps_every_assignment_record_with_its_policy_version() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[]);
    let root = pooled(&mut ledger, q);
    let offer = ledger.push(decl(OWNER, "offer", Some(root), &[("party", t(BOB))]));
    let v2 = ledger.push(decl(
        OWNER,
        "queue_definition",
        Some(q),
        &[
            ("owner", t(OWNER)),
            ("candidates", list(&[BOB, CAROL, DAVE])),
        ],
    ));
    let refused = ledger.push(decl(ALICE, "claim", Some(offer), &[]));
    let claim = ledger.push(decl(DAVE, "claim", Some(refused), &[]));
    let view = ledger.view(root);
    let history: Vec<(RecordId, AssignmentAct, Option<RecordId>, StepOutcome)> = view
        .assignment
        .history
        .iter()
        .map(|e| (e.record, e.act, e.policy, e.outcome))
        .collect();
    assert_eq!(
        history,
        vec![
            (
                offer,
                AssignmentAct::Responsibility(ResponsibilityOperation::Offer),
                Some(q),
                StepOutcome::Applied
            ),
            (
                refused,
                AssignmentAct::Responsibility(ResponsibilityOperation::Claim),
                Some(v2),
                StepOutcome::Refused(Refusal::NotACandidate)
            ),
            (
                claim,
                AssignmentAct::Responsibility(ResponsibilityOperation::Claim),
                Some(v2),
                StepOutcome::Applied
            ),
        ]
    );
    assert_eq!(view.assignment.history[0].to, Some(party(BOB)));
    assert_eq!(view.assignment.history[2].by, party(DAVE));
}

// RC-20
#[test]
fn rc_20_assignment_grants_no_access_and_held_work_waits_for_it() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[]);
    let root = pooled(&mut ledger, q);
    let view = ledger.view(root);
    let claim = decl(BOB, "claim", Some(root), &[]);
    let records = ledger.records();
    assert_eq!(
        check_responsibility(&view, &proposed(&claim, AccessAnswer::Deny), &records),
        Err(Refusal::AccessDenied)
    );
    assert_eq!(
        check_responsibility(&view, &proposed(&claim, AccessAnswer::Require), &records),
        Err(Refusal::AccessPending)
    );
    assert_eq!(
        check_responsibility(&view, &proposed(&claim, AccessAnswer::Allow), &records),
        Ok(AssignmentAct::Responsibility(
            ResponsibilityOperation::Claim
        ))
    );
    ledger.push(claim);
    let held = ledger.view(root);
    let wait = access_wait(&held, AccessAnswer::Require).unwrap();
    assert_eq!(wait.party, party(BOB));
    assert!(access_wait(&held, AccessAnswer::Allow).is_none());
    assert!(access_wait(&view, AccessAnswer::Deny).is_none());
}

// RC-21 RC-22 RC-23
#[test]
fn rc_22_a_policy_offer_records_its_version_and_its_claim_inputs() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[("distribution", t("skill"))]);
    let skills = ledger.push(observation(BOB, &[]));
    let root = pooled(&mut ledger, q);
    let bare = ledger.push(decl(
        SYS,
        "offer",
        Some(root),
        &[("party", t(BOB)), ("policy", d(q))],
    ));
    let not_a_claim = ledger.push(decl(
        SYS,
        "offer",
        Some(bare),
        &[
            ("party", t(BOB)),
            ("policy", d(q)),
            ("inputs", digests(&[root])),
        ],
    ));
    let stale = ledger.push(decl(
        SYS,
        "offer",
        Some(not_a_claim),
        &[
            ("party", t(BOB)),
            ("policy", d(root)),
            ("inputs", digests(&[skills])),
        ],
    ));
    let offer = ledger.push(decl(
        SYS,
        "offer",
        Some(stale),
        &[
            ("party", t(BOB)),
            ("policy", d(q)),
            ("inputs", digests(&[skills])),
        ],
    ));
    assert_eq!(
        ledger.outcome(root, bare),
        StepOutcome::Refused(Refusal::MissingContent)
    );
    assert_eq!(
        ledger.outcome(root, not_a_claim),
        StepOutcome::Refused(Refusal::WrongTarget)
    );
    assert_eq!(
        ledger.outcome(root, stale),
        StepOutcome::Refused(Refusal::WrongTarget)
    );
    assert_eq!(ledger.outcome(root, offer), StepOutcome::Applied);
    let view = ledger.view(root);
    let made = decisions(&view);
    assert_eq!(made.len(), 1);
    assert_eq!(made[0].record, offer);
    assert_eq!(made[0].policy, Some(q));
    assert_eq!(made[0].method, Some(DistributionMethod::Skill));
    assert_eq!(made[0].inputs, vec![skills]);
    assert_eq!(made[0].offered, party(BOB));
    let inputs_without_policy = decl(
        OWNER,
        "offer",
        Some(root),
        &[("party", t(BOB)), ("inputs", digests(&[skills]))],
    );
    assert_eq!(
        validated(&inputs_without_policy),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
}

// RC-24
#[test]
fn rc_24_open_workload_is_derived_and_a_wip_limit_signals_overload() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[("wip_limit", u(1))]);
    let first = pooled(&mut ledger, q);
    let second = pooled(&mut ledger, q);
    let direct = ledger.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(BOB)), ("acceptor", t(ALICE))],
    ));
    ledger.push(decl(BOB, "claim", Some(first), &[]));
    ledger.push(decl(BOB, "claim", Some(second), &[]));
    ledger.push(decl(BOB, "promise", Some(direct), &[]));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let facts = Facts {
        conditions_met: &[],
        policy: Policy::default(),
        budget_exhausted: false,
    };
    let views = derive_commitments(&entries, &derivation, &facts);
    let load = workload(&views, &party(BOB), 1);
    assert_eq!((load.open, load.claimed, load.running), (3, 2, 1));
    assert!(load.overloaded(Some(1)));
    assert!(!load.overloaded(Some(3)));
    assert!(!load.overloaded(None));
    assert_eq!(workload(&views, &party(CAROL), 0).open, 0);
}

// RC-25 RC-21
#[test]
fn rc_25_a_bid_award_binds_and_is_withdrawn_only_by_revocation_or_cancellation() {
    let mut ledger = Ledger::new();
    let q = queue(&mut ledger, &[("distribution", t("bid"))]);
    let bid = ledger.push(observation(CAROL, &[]));
    let root = pooled(&mut ledger, q);
    let award = ledger.push(decl(
        OWNER,
        "offer",
        Some(root),
        &[
            ("party", t(CAROL)),
            ("policy", d(q)),
            ("inputs", digests(&[bid])),
        ],
    ));
    let promise = ledger.push(decl(CAROL, "promise", Some(award), &[]));
    let view = ledger.view(root);
    assert!(view.assignment.hold.as_ref().unwrap().binding);
    let unclaim = ledger.push(decl(CAROL, "unclaim", Some(promise), &[]));
    assert_eq!(
        ledger.outcome(root, unclaim),
        StepOutcome::Refused(Refusal::BindingAward)
    );
    ledger.push(decl(
        CAROL,
        "cancel",
        Some(unclaim),
        &[("reason", t("cannot_complete"))],
    ));
    assert_eq!(
        summary(&ledger.view(root)),
        Summary::Uniform(CommitmentState::Cancelled)
    );
}

// RC-1 RC-4 RC-5 RC-6
#[test]
fn rc_5_accountability_is_one_party_explicit_or_derived_and_marked_derived() {
    let org = party(ORG);
    let dir = Dir::new();
    let mut ledger = Ledger::new();
    let explicit = ledger.push(decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(AGENT)),
            ("acceptor", t(ALICE)),
            ("accountable", t(CAROL)),
        ],
    ));
    let a = accountability(&ledger.view(explicit), &org, &[], &dir);
    assert_eq!(a.party, party(CAROL));
    assert_eq!(a.source, AccountabilitySource::Explicit);
    assert!(!a.derived);
    let mut agent = Ledger::new();
    let root = agent.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(AGENT)), ("acceptor", t(ALICE))],
    ));
    let unbound = accountability(&agent.view(root), &org, &[], &dir);
    assert_eq!(unbound.party, party(ALICE));
    assert_eq!(unbound.source, AccountabilitySource::Requester);
    assert!(unbound.derived);
    agent.push(on_behalf(
        decl(AGENT_2, "promise", Some(root), &[]),
        &[AGENT, DAVE],
    ));
    let view = agent.view(root);
    assert_eq!(view.obligor, Obligor::Party(party(AGENT)));
    let bound = accountability(&view, &org, &[], &dir);
    assert_eq!(bound.party, party(DAVE));
    assert_eq!(bound.source, AccountabilitySource::OnBehalfOf);
    assert!(bound.derived);
    assert_ne!(bound.party, party(AGENT));
}

// RC-6 RC-48
#[test]
fn rc_6_the_regime_decides_the_end_and_an_agent_never_ends_the_chain() {
    let mut ledger = Ledger::new();
    let rule = ledger.push(decl(
        ALICE,
        "org_rule",
        None,
        &[("organization", t(ORG)), ("fallback", t(FALLBACK))],
    ));
    let root = ledger.push(decl(
        AGENT,
        "request",
        None,
        &[("obligor", t(AGENT)), ("acceptor", t(AGENT))],
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let rules = org_rules(&entries, &derivation);
    let org = party(ORG);
    let dir = Dir::new();
    let view = ledger.view(root);
    let a = accountability(&view, &org, &rules, &dir);
    assert_eq!(a.party, party(FALLBACK));
    assert_eq!(a.source, AccountabilitySource::OrgRule);
    assert_eq!(a.rule, Some(rule));
    assert!(a.derived);
    assert_eq!(accountability(&view, &org, &[], &dir).party, org);
    assert!(Regime::Default.ends_in(ActorType::Human));
    assert!(Regime::Default.ends_in(ActorType::Organization));
    for regime in Regime::ALL {
        assert!(!regime.ends_in(ActorType::Agent));
        assert!(!regime.ends_in(ActorType::System));
        assert!(!regime.ends_in(ActorType::Machine));
    }
    let mut strict = Ledger::new();
    let rule = strict.push(decl(
        ALICE,
        "org_rule",
        None,
        &[
            ("organization", t(ORG)),
            ("fallback", t(FALLBACK)),
            ("regime", t("organization")),
        ],
    ));
    let root = strict.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(BOB)), ("acceptor", t(ALICE))],
    ));
    strict.push(decl(BOB, "promise", Some(root), &[]));
    let entries = strict.entries();
    let derivation = Ledger::derivation(&entries);
    let rules = org_rules(&entries, &derivation);
    let a = accountability(&strict.view(root), &org, &rules, &dir);
    assert_eq!(a.party, org);
    assert_eq!(a.internal, Some(party(BOB)));
    assert_eq!(a.rule, Some(rule));
}

// RC-7 RC-48
#[test]
fn rc_7_a_disabled_party_falls_to_the_upper_accountable_or_the_fallback() {
    let mut ledger = Ledger::new();
    let rule = ledger.push(decl(
        ALICE,
        "org_rule",
        None,
        &[("organization", t(ORG)), ("fallback", t(FALLBACK))],
    ));
    let root = ledger.push(decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(AGENT)),
            ("acceptor", t(ALICE)),
            ("accountable", t(CAROL)),
        ],
    ));
    ledger.push(on_behalf(
        decl(AGENT_2, "promise", Some(root), &[]),
        &[AGENT, DAVE],
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let rules = org_rules(&entries, &derivation);
    let org = party(ORG);
    let view = ledger.view(root);
    let carol_gone = Dir {
        disabled: vec![CAROL],
        roles: Vec::new(),
    };
    let upper = accountability(&view, &org, &rules, &carol_gone);
    assert_eq!(upper.party, party(DAVE));
    assert!(upper.unowned);
    assert!(upper.derived);
    let all_gone = Dir {
        disabled: vec![CAROL, DAVE],
        roles: Vec::new(),
    };
    let fallen = accountability(&view, &org, &rules, &all_gone);
    assert_eq!(fallen.party, party(FALLBACK));
    assert_eq!(fallen.rule, Some(rule));
    assert!(fallen.unowned);
    assert_eq!(accountability(&view, &org, &[], &all_gone).party, org);
}

// RC-7 RC-5 RC-6
#[test]
fn rc_7_an_accountability_transfer_needs_the_new_party_s_acceptance() {
    let org = party(ORG);
    let dir = Dir::new();
    let mut ledger = Ledger::new();
    let root = ledger.push(decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(BOB)),
            ("acceptor", t(ALICE)),
            ("accountable", t(CAROL)),
        ],
    ));
    let transfer = ledger.push(decl(
        CAROL,
        "amend",
        Some(root),
        &[("accountable", t(DAVE))],
    ));
    let pending = ledger.view(root);
    let a = accountability(&pending, &org, &[], &dir);
    assert_eq!(a.party, party(CAROL));
    assert_eq!(a.transfer.as_ref().unwrap().to, party(DAVE));
    let wrong = ledger.push(decl(
        BOB,
        "acknowledgement",
        Some(transfer),
        &[("proposal", d(transfer))],
    ));
    let agent = ledger.push(decl(AGENT, "acknowledgement", Some(wrong), &[]));
    let accepted = ledger.push(decl(
        DAVE,
        "acknowledgement",
        Some(agent),
        &[("proposal", d(transfer))],
    ));
    assert_eq!(
        ledger.outcome(root, wrong),
        StepOutcome::Refused(Refusal::WrongRole)
    );
    assert_eq!(
        ledger.outcome(root, agent),
        StepOutcome::Refused(Refusal::NotAccountable)
    );
    assert_eq!(ledger.outcome(root, accepted), StepOutcome::Applied);
    let a = accountability(&ledger.view(root), &org, &[], &dir);
    assert_eq!(a.party, party(DAVE));
    assert_eq!(a.source, AccountabilitySource::Transferred);
    assert!(!a.derived);
    assert!(a.transfer.is_none());
    let mixed = decl(
        CAROL,
        "amend",
        Some(root),
        &[
            ("accountable", t(DAVE)),
            ("high_impact", ParamValue::Scalar(ParamScalar::Bool(true))),
        ],
    );
    assert_eq!(
        validated(&mixed),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let mut open = Ledger::new();
    let root = open.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(BOB)), ("acceptor", t(ALICE))],
    ));
    let taken = open.push(decl(CAROL, "acknowledgement", Some(root), &[]));
    assert_eq!(open.outcome(root, taken), StepOutcome::Applied);
    let a = accountability(&open.view(root), &org, &[], &dir);
    assert_eq!(
        (a.party, a.source),
        (party(CAROL), AccountabilitySource::TakenOver)
    );
}

// RC-1 RC-48
#[test]
fn rc_1_a_group_is_accountable_only_once_the_org_rule_resolves_it() {
    let mut ledger = Ledger::new();
    let rule = ledger.push(decl(
        ALICE,
        "org_rule",
        None,
        &[
            ("organization", t(ORG)),
            ("fallback", t(FALLBACK)),
            ("party_groups", list(&["group:acme:legal"])),
            ("parties", list(&[CAROL])),
            (
                "role_groups",
                list(&["group:acme:night", "group:acme:ward"]),
            ),
            (
                "roles",
                list(&["role:acme:night-lead", "role:acme:ward-leads"]),
            ),
        ],
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let rules = org_rules(&entries, &derivation);
    let org = party(ORG);
    let dir = Dir {
        disabled: Vec::new(),
        roles: vec![
            ("role:acme:night-lead", vec![DAVE]),
            ("role:acme:ward-leads", vec![BOB, CAROL]),
        ],
    };
    let current = rule_for(&rules, &org);
    let legal = resolve_group(current, &org, "group:acme:legal", &dir);
    assert_eq!(
        (legal.party.clone(), legal.resolved, legal.rule),
        (party(CAROL), true, Some(rule))
    );
    let night = resolve_group(current, &org, "group:acme:night", &dir);
    assert_eq!((night.party.clone(), night.resolved), (party(DAVE), true));
    let ward = resolve_group(current, &org, "group:acme:ward", &dir);
    assert_eq!(
        (ward.party.clone(), ward.resolved),
        (party(FALLBACK), false)
    );
    let unknown = resolve_group(current, &org, "group:acme:unknown", &dir);
    assert_eq!(unknown.party, party(FALLBACK));
    let none = resolve_group(None, &org, "group:acme:legal", &dir);
    assert_eq!((none.party, none.rule), (org.clone(), None));
    let root = ledger.push(decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(BOB)),
            ("acceptor", t(ALICE)),
            ("accountable_group", t("group:acme:legal")),
        ],
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let rules = org_rules(&entries, &derivation);
    let a = accountability(&ledger.view(root), &org, &rules, &dir);
    assert_eq!(
        (a.party, a.rule, a.derived),
        (party(CAROL), Some(rule), false)
    );
    let both = decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(BOB)),
            ("acceptor", t(ALICE)),
            ("accountable", t(CAROL)),
            ("accountable_group", t("group:acme:legal")),
        ],
    );
    assert_eq!(
        validated(&both),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
}

// RC-48
#[test]
fn rc_48_the_org_rule_is_a_versioned_declaration_with_a_mandatory_fallback() {
    assert_eq!(
        DeclarationSubtype::from_wire_name("org_rule"),
        Some(DeclarationSubtype::OrgRule)
    );
    let no_fallback = decl(ALICE, "org_rule", None, &[("organization", t(ORG))]);
    assert_eq!(
        validated(&no_fallback),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let unpaired = decl(
        ALICE,
        "org_rule",
        None,
        &[
            ("organization", t(ORG)),
            ("fallback", t(FALLBACK)),
            (
                "party_groups",
                list(&["group:acme:legal", "group:acme:tax"]),
            ),
            ("parties", list(&[CAROL])),
        ],
    );
    assert_eq!(
        validated(&unpaired),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let twice = decl(
        ALICE,
        "org_rule",
        None,
        &[
            ("organization", t(ORG)),
            ("fallback", t(FALLBACK)),
            ("party_groups", list(&["group:acme:legal"])),
            ("parties", list(&[CAROL])),
            ("role_groups", list(&["group:acme:legal"])),
            ("roles", list(&["role:acme:lead"])),
        ],
    );
    assert_eq!(
        validated(&twice),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let agent_end = decl(
        ALICE,
        "org_rule",
        None,
        &[
            ("organization", t(ORG)),
            ("fallback", t("https://agents.example/a")),
        ],
    );
    assert_eq!(
        validated(&agent_end),
        Outcome::Rejected(Reason::EnvelopeMismatch(EnvelopeField::ActorType))
    );
    let mut ledger = Ledger::new();
    let first = ledger.push(decl(
        ALICE,
        "org_rule",
        None,
        &[("organization", t(ORG)), ("fallback", t(FALLBACK))],
    ));
    assert_eq!(validated(&ledger.records[0].1), Outcome::Accepted);
    let second = ledger.push(decl(
        ALICE,
        "org_rule",
        Some(first),
        &[("organization", t(ORG)), ("fallback", t(DAVE))],
    ));
    ledger.push(decl(
        BOB,
        "org_rule",
        None,
        &[("organization", t(ORG)), ("fallback", t(BOB))],
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let rules = org_rules(&entries, &derivation);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].chain, first);
    assert_eq!(rules[0].version, second);
    assert_eq!(rules[0].rule.fallback, party(DAVE));
    assert_eq!(rules[0].rule.regime, Regime::Default);
}

// RC-8
#[test]
fn rc_8_the_intervener_answers_from_the_takeover_on_and_a_leaseless_coordinator_is_marked() {
    let lease = ControlSpan {
        record: id(1),
        party: party(CAROL),
        from: Time(5000),
        until: Some(Time(9000)),
    };
    let act = |n: usize, who: &str, at: u64| ActBy {
        record: id(n),
        party: party(who),
        at: Time(at),
    };
    let acts = [
        act(10, AGENT, 4000),
        act(11, CAROL, 4000),
        act(12, CAROL, 6000),
        act(13, CAROL, 9500),
        act(14, OWNER, 6000),
    ];
    let marks = interventions(&acts, &[lease], &[party(CAROL), party(OWNER)]);
    assert_eq!(
        marks,
        vec![
            (id(11), InterventionMark::OutsideCoordination),
            (id(12), InterventionMark::UnderLease),
            (id(13), InterventionMark::OutsideCoordination),
            (id(14), InterventionMark::OutsideCoordination),
        ]
    );
}

// RC-9
#[test]
fn rc_9_four_guarantees_are_never_waived_and_a_waiver_is_scoped_and_recorded() {
    let unwaivable = PrincipalGuarantee::ALL
        .iter()
        .filter(|g| !g.waivable())
        .count();
    assert_eq!((PrincipalGuarantee::ALL.len(), unwaivable), (7, 4));
    let oversight = decl(
        ALICE,
        "waiver",
        None,
        &[("guarantee", t("oversight")), ("commitment", d(id(1)))],
    );
    assert_eq!(
        validated(&oversight),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let unscoped = decl(ALICE, "waiver", None, &[("guarantee", t("advance_notice"))]);
    assert_eq!(
        validated(&unscoped),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let widening = decl(
        ALICE,
        "waiver",
        None,
        &[
            ("guarantee", t("advance_notice")),
            ("commitment", d(id(1))),
            ("authority", t("work:close")),
        ],
    );
    assert_eq!(
        validated(&widening),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let mut ledger = Ledger::new();
    let root = ledger.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(AGENT)), ("acceptor", t(ALICE))],
    ));
    let waiver = decl(
        ALICE,
        "waiver",
        None,
        &[
            ("guarantee", t("advance_notice")),
            ("commitment", d(root)),
            ("until", u(50_000)),
        ],
    );
    assert_eq!(validated(&waiver), Outcome::Accepted);
    ledger.push(waiver);
    ledger.push(decl(
        ALICE,
        "waiver",
        None,
        &[
            ("guarantee", t("immediate_notice")),
            ("work", ParamValue::Scalar(ParamScalar::WorkId(work()))),
        ],
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let found = waivers(&entries, &derivation);
    assert_eq!(found.len(), 2);
    let state = guarantees(
        &found,
        &party(ALICE),
        Some(root),
        Some(work()),
        Time(10_000),
    );
    let off: Vec<PrincipalGuarantee> = state
        .iter()
        .filter(|(_, on)| !on)
        .map(|(g, _)| *g)
        .collect();
    assert_eq!(
        off,
        vec![
            PrincipalGuarantee::AdvanceNotice,
            PrincipalGuarantee::ImmediateNotice
        ]
    );
    let later = guarantees(&found, &party(ALICE), Some(root), None, Time(60_000));
    assert!(later.iter().all(|(_, on)| *on));
    let other = guarantees(&found, &party(BOB), Some(root), Some(work()), Time(10_000));
    assert!(other.iter().all(|(_, on)| *on));
}

// RC-44
#[test]
fn rc_44_participation_is_an_engaged_in_parameter_and_only_a_principal_changes_it() {
    let label = engaging(
        observation(ALICE, &[("participation", t("proactive"))]),
        AGENT,
        None,
    );
    assert_eq!(validated(&label), Outcome::Accepted);
    let loose = observation(ALICE, &[("participation", t("proactive"))]);
    assert_eq!(
        validated(&loose),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let unknown = engaging(
        observation(ALICE, &[("participation", t("always"))]),
        AGENT,
        None,
    );
    assert_eq!(
        validated(&unknown),
        Outcome::Rejected(Reason::Schema(Schema::Params))
    );
    let mut ledger = Ledger::new();
    let added = ledger.push(engaging(
        observation(ALICE, &[("participation", t("proactive"))]),
        AGENT,
        None,
    ));
    ledger.push(engaging(
        observation(BOB, &[("participation", t("assigned_only"))]),
        AGENT,
        None,
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let principals = [party(CAROL)];
    let now = participation(&entries, &derivation, &party(AGENT), &work(), &principals).unwrap();
    assert_eq!(
        (now.policy, now.record),
        (ParticipationPolicy::Proactive, added)
    );
    drop(entries);
    let changed = ledger.push(engaging(
        observation(CAROL, &[("participation", t("on_call"))]),
        AGENT,
        None,
    ));
    let entries = ledger.entries();
    let derivation = Ledger::derivation(&entries);
    let now = participation(&entries, &derivation, &party(AGENT), &work(), &principals).unwrap();
    assert_eq!(
        (now.policy, now.record),
        (ParticipationPolicy::OnCall, changed)
    );
    assert!(participation(&entries, &derivation, &party(BOB), &work(), &principals).is_none());
    assert_eq!(SUGGESTED_PARTICIPATION, ParticipationPolicy::OnCall);
}

// RC-45
#[test]
fn rc_45_a_role_label_carries_no_authority_and_no_responsibility() {
    let labelled = decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(BOB)),
            ("acceptor", t(ALICE)),
            ("accountable", t("https://clinic.example/ns/role/attending")),
        ],
    );
    assert_eq!(
        validated(&labelled),
        Outcome::Rejected(Reason::EnvelopeMismatch(EnvelopeField::ActorType))
    );
    let mut ledger = Ledger::new();
    let root = ledger.push(engaging(
        decl(
            ALICE,
            "request",
            None,
            &[("obligor", t(BOB)), ("acceptor", t(ALICE))],
        ),
        CAROL,
        Some("https://clinic.example/ns/role/attending"),
    ));
    let view = ledger.view(root);
    let a = accountability(&view, &party(ORG), &[], &Dir::new());
    assert_eq!(a.party, party(ALICE));
    assert_ne!(view.obligor, Obligor::Party(party(CAROL)));
    assert_ne!(view.acceptor, party(CAROL));
}

// RC-17
#[test]
fn rc_17_allowed_responsibility_follows_roles_state_and_access() {
    let mut ledger = Ledger::new();
    let q = queue(
        &mut ledger,
        &[("lease", u(1000)), ("lease_expiry", t("keep_and_signal"))],
    );
    let root = pooled(&mut ledger, q);
    let view = ledger.view(root);
    let ops = |party: &PartyRef, view: &CommitmentView| -> Vec<ResponsibilityOperation> {
        let caller = Caller {
            party,
            actor: ActorType::Human,
            step_up: false,
        };
        allowed_responsibility(view, &caller, &|_| AccessAnswer::Allow)
            .into_iter()
            .map(|a| a.operation)
            .collect()
    };
    assert_eq!(
        ops(&party(BOB), &view),
        vec![ResponsibilityOperation::Claim]
    );
    assert_eq!(
        ops(&party(OWNER), &view),
        vec![
            ResponsibilityOperation::Forward,
            ResponsibilityOperation::Nominate,
            ResponsibilityOperation::Offer,
            ResponsibilityOperation::Reassign,
        ]
    );
    assert_eq!(ops(&party(DAVE), &view), Vec::new());
    ledger.push(decl(BOB, "claim", Some(root), &[]));
    let held = ledger.view(root);
    assert_eq!(
        ops(&party(BOB), &held),
        vec![
            ResponsibilityOperation::Unclaim,
            ResponsibilityOperation::RenewLease
        ]
    );
    let bob = party(BOB);
    let caller = Caller {
        party: &bob,
        actor: ActorType::Human,
        step_up: false,
    };
    let denied = allowed_responsibility(&held, &caller, &|_| AccessAnswer::Deny);
    assert!(
        denied
            .iter()
            .all(|a| a.missing == vec![work_kernel::commitment::Missing::AccessDenied])
    );
}
