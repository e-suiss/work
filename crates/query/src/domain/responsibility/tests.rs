use std::collections::BTreeMap;

use work_kernel::catalog::{ChangePolicy, CommitmentKind};
use work_kernel::commitment::{
    self, AccessAnswer, CommitmentState, CommitmentView, EvidenceRule, Facts, Item, Operation,
    Pending, Policy, Proposal, Proposed, Refusal, StepOutcome, Terms,
};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time, WorkId};
use work_kernel::ontology::Obligor;
use work_kernel::record::{
    Audience, AuthorityProofKind, AuthorityRef, Capacity, Claim, ClaimType, Declaration, Param,
    ParamScalar, ParamValue, PartName, ProtocolVersion, Record, RecordCore, VersionVector,
    Visibility,
};
use work_kernel::relation::Relation;
use work_kernel::responsibility::{
    AccountabilitySource, Accountable, Allocation, AllocationAct, AllocationEvent,
    AllocationSignalKind, AllocationState, Explicit, ForwardTarget, Forwarding, Hold, HoldVia,
    Lease, LeaseExpiry, LeaseStatus, OrgRule, OrgRuleVersion, QueueDefinition, QueueVersion,
};
use work_kernel::uri::TypeUri;
use work_kernel::validate::ActorType;

use super::*;
use crate::domain::commitments::{commitment_of, involves};
use crate::domain::kinds::{Kind, kind_of, record_action};

const ALICE: &str = "party:acme:alice";
const BOB: &str = "party:acme:bob";
const CAROL: &str = "party:acme:carol";
const DAVE: &str = "party:acme:dave";
const OWNER: &str = "party:acme:desk-lead";
const ORG: &str = "party:acme:org";
const AGENT: &str = "party:acme:agent-procure-7";
const CORE: &str = "https://suiss.app/ns/work/";

fn party(s: &str) -> PartyRef {
    PartyRef::new(s).unwrap()
}

fn id(n: u8) -> RecordId {
    RecordId(Digest::sha256([n; 32]))
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

fn engaging(author: &str, agents: &[&str]) -> Record {
    let mut core = RecordCore {
        capacity: None,
        basis: None,
        ..core(author, None, &[("participation", t("proactive"))])
    };
    core.relations = Some(
        agents
            .iter()
            .map(|a| Relation::EngagedIn {
                source: party(a),
                target: work(),
                qualifier: None,
            })
            .collect(),
    );
    Record::Claim(Claim {
        subtype: ClaimType::from_uri(TypeUri::parse(&format!("{CORE}claim/observation")).unwrap()),
        occurred_at: Time(1),
        core,
    })
}

fn actor_of(p: &str) -> ActorType {
    match p {
        AGENT => ActorType::Agent,
        ORG => ActorType::Organization,
        _ => ActorType::Human,
    }
}

fn actors() -> BTreeMap<PartyRef, ActorType> {
    [ALICE, BOB, CAROL, DAVE, OWNER, ORG, AGENT]
        .into_iter()
        .map(|p| (party(p), actor_of(p)))
        .collect()
}

fn queue_record(head: Option<RecordId>, extra: &[(&str, ParamValue)]) -> Record {
    let mut params = vec![("owner", t(OWNER)), ("candidates", list(&[BOB, CAROL]))];
    params.extend(extra.iter().cloned());
    decl(OWNER, "queue_definition", head, &params)
}

fn version(queue: RecordId, version: RecordId, position: u64, record: &Record) -> QueueVersion {
    QueueVersion {
        queue,
        version,
        position,
        author_chain: vec![party(OWNER)],
        definition: QueueDefinition::of(record).unwrap(),
    }
}

fn view(root: RecordId, obligor: Obligor, state: CommitmentState) -> CommitmentView {
    CommitmentView {
        root,
        opening: StepOutcome::Applied,
        obligee: party(ALICE),
        obligor,
        acceptor: party(ALICE),
        principal: Vec::new(),
        requester: vec![party(ALICE)],
        aim: None,
        conditions: Vec::new(),
        supports: Vec::new(),
        items: vec![Item {
            index: 0,
            state,
            closing: None,
        }],
        terms: Terms {
            kind: CommitmentKind::Standard,
            item_count: 1,
            due: None,
            respond_by: None,
            evidence: EvidenceRule::default(),
            high_impact: false,
            four_eyes_waived: false,
            change_policy: ChangePolicy::Queue,
            aggregation: None,
            undefined: Vec::new(),
        },
        offer_version: 0,
        instruction_version: 0,
        pending: Pending::default(),
        statement: None,
        implicit: None,
        precondition: None,
        deferral: None,
        rejections: 0,
        rejected: Vec::new(),
        disputes: Vec::new(),
        reopening: None,
        fulfilments: Vec::new(),
        notices: Vec::new(),
        handovers: Vec::new(),
        active_ends: Vec::new(),
        steps: Vec::new(),
        allocation: Allocation::default(),
        accountability: Accountable::default(),
    }
}

fn pooled(root: RecordId, queue: &QueueVersion) -> CommitmentView {
    let mut v = view(
        root,
        Obligor::Queue(queue.queue),
        CommitmentState::Requested,
    );
    v.allocation.queue = Some(queue.queue);
    v.allocation.definition = Some(queue.clone());
    v.allocation.pooled_since = Some(Time(1000));
    v
}

fn event(record: RecordId, by: &str, at: u64) -> AllocationEvent {
    AllocationEvent {
        record,
        act: AllocationAct::Responsibility(ResponsibilityOperation::Claim),
        by: party(by),
        to: None,
        at: Time(at),
        policy: None,
        outcome: StepOutcome::Applied,
    }
}

fn held(
    root: RecordId,
    queue: &QueueVersion,
    by: &str,
    claim: RecordId,
    at: u64,
) -> CommitmentView {
    let mut v = pooled(root, queue);
    v.obligor = Obligor::Party(party(by));
    v.items[0].state = CommitmentState::Promised;
    v.allocation.pooled_since = None;
    v.allocation.hold = Some(Hold {
        record: claim,
        party: party(by),
        since: Time(at),
        via: HoldVia::Claim,
        binding: false,
        renewed: Time(at),
        chain: vec![party(by)],
        lease: queue.definition.lease,
    });
    v.allocation.history.push(event(claim, by, at));
    v
}

fn ledger(queues: Vec<QueueVersion>, rules: Vec<OrgRuleVersion>) -> Ledger {
    Ledger::from_parts(
        queues,
        rules,
        LedgerDirectory::from_actors(actors()),
        BTreeMap::new(),
    )
}

fn proposed(record: &Record) -> Proposed<'_> {
    Proposed {
        id: id(99),
        record,
        position: 9999,
        recorded_at: Time(9_999_000),
        author_actor: actor_of(record.core().author.as_str()),
        step_up: false,
        access: AccessAnswer::Allow,
        agent_side: false,
        control_supported: false,
    }
}

fn no_records() -> BTreeMap<RecordId, &'static Record> {
    BTreeMap::new()
}

// RC-17 RC-19
#[test]
fn rc_17_a_record_continuing_a_claim_or_an_acknowledgement_finds_its_commitment() {
    let record = queue_record(None, &[]);
    let q = version(id(1), id(1), 1, &record);
    let (root, claim, ack) = (id(2), id(3), id(4));
    let mut taken = held(root, &q, BOB, claim, 3000);
    let mut acknowledged = event(ack, ALICE, 4000);
    acknowledged.act = AllocationAct::Acknowledgement;
    taken.allocation.history.push(acknowledged);
    let views = vec![taken];
    assert_eq!(commitment_of(&views, &claim).unwrap().root, root);
    assert_eq!(commitment_of(&views, &ack).unwrap().root, root);
    assert!(commitment_of(&views, &id(5)).is_none());
    let unclaim = decl(BOB, "unclaim", Some(ack), &[]);
    assert_eq!(
        commitment::check_responsibility(&views[0], &proposed(&unclaim), &no_records()),
        Ok(AllocationAct::Responsibility(
            ResponsibilityOperation::Unclaim
        ))
    );
}

// RC-11 P-56
#[test]
fn rc_11_pooled_work_is_read_by_the_queue_owner_and_its_listed_candidates_only() {
    let record = queue_record(None, &[("excluded", list(&[CAROL]))]);
    let q = version(id(1), id(1), 1, &record);
    let pool = pooled(id(2), &q);
    assert!(involves(&pool, &party(OWNER)));
    assert!(involves(&pool, &party(BOB)));
    assert!(!involves(&pool, &party(CAROL)));
    assert!(!involves(&pool, &party(DAVE)));
    let grouped = decl(
        OWNER,
        "queue_definition",
        None,
        &[
            ("owner", t(OWNER)),
            ("candidate_group", t("group:acme:legal")),
        ],
    );
    let g = version(id(6), id(6), 6, &grouped);
    let pool = pooled(id(7), &g);
    assert!(involves(&pool, &party(OWNER)));
    assert!(!involves(&pool, &party(BOB)));
    let taken = held(id(2), &q, BOB, id(3), 3000);
    assert!(involves(&taken, &party(BOB)));
    assert!(!involves(&taken, &party(OWNER)));
}

// RC-5 RC-1 RC-15 RC-16 RC-48
#[test]
fn rc_5_pooled_work_names_the_queue_owner_as_its_derived_accountable_and_its_chain() {
    let record = queue_record(None, &[]);
    let q = version(id(1), id(1), 1, &record);
    let ledger = ledger(vec![q.clone()], Vec::new());
    assert_eq!(ledger.organization(), Some(&party(ORG)));
    let pool = ledger.commitment(&pooled(id(2), &q), Time(2000));
    let a = pool.accountability.unwrap();
    assert_eq!(
        (a.party.as_str(), a.source, a.derived),
        (OWNER, AccountabilitySource::QueueOwner, true)
    );
    assert_eq!(
        pool.chain
            .iter()
            .map(|l| l.party.as_str())
            .collect::<Vec<_>>(),
        [OWNER, ALICE]
    );
    assert_eq!(pool.state, AllocationState::Pooled);
    assert_eq!(pool.lease, LeaseStatus::NoLease);
    let taken = ledger.commitment(&held(id(2), &q, BOB, id(3), 3000), Time(4000));
    assert_eq!(taken.state, AllocationState::Held);
    let a = taken.accountability.unwrap();
    assert_eq!(
        (a.party.as_str(), a.source),
        (BOB, AccountabilitySource::Obligor)
    );
}

// RC-1 RC-48
#[test]
fn rc_1_without_a_named_organisation_the_fallback_to_it_is_no_party() {
    let direct = view(
        id(2),
        Obligor::Party(party(BOB)),
        CommitmentState::Requested,
    );
    let only_agents = [(party(AGENT), ActorType::Agent)].into_iter().collect();
    let unnamed = Ledger::from_parts(
        Vec::new(),
        Vec::new(),
        LedgerDirectory::from_actors(only_agents),
        BTreeMap::new(),
    );
    assert_eq!(unnamed.organization(), None);
    let read = unnamed.commitment(&direct, Time(0));
    assert_eq!(read.accountability, None);
    assert!(
        read.chain
            .iter()
            .all(|l| l.source != AccountabilitySource::OrgRule)
    );
    let named = ledger(Vec::new(), Vec::new()).commitment(&direct, Time(0));
    assert_eq!(named.accountability.unwrap().party, party(ALICE));
}

// RC-14 RC-19
#[test]
fn rc_14_forwardings_keep_their_reason_and_raise_ping_pong_past_the_threshold() {
    let record = queue_record(None, &[("ping_pong_threshold", u(1))]);
    let q = version(id(1), id(1), 1, &record);
    let (first, second) = (id(3), id(4));
    let mut pool = pooled(id(2), &q);
    for (record, to, at) in [(first, DAVE, 3000), (second, BOB, 4000)] {
        pool.allocation.forwards.push(Forwarding {
            record,
            by: party(OWNER),
            target: ForwardTarget::Candidates(vec![party(to)]),
            at: Time(at),
        });
        let mut forwarded = event(record, OWNER, at);
        forwarded.act = AllocationAct::Responsibility(ResponsibilityOperation::Forward);
        pool.allocation.history.push(forwarded);
    }
    let reasons: BTreeMap<RecordId, String> = [
        (first, "expertise".to_owned()),
        (second, "capacity".to_owned()),
        (id(9), "other".to_owned()),
    ]
    .into_iter()
    .collect();
    let with_reasons = Ledger::from_parts(
        vec![q],
        Vec::new(),
        LedgerDirectory::from_actors(actors()),
        reasons,
    );
    let read = with_reasons.commitment(&pool, Time(5000));
    assert_eq!(read.ping_pong.count, 2);
    assert!(read.ping_pong.over);
    assert_eq!(
        read.ping_pong.chain[1],
        ForwardTarget::Candidates(vec![party(BOB)])
    );
    assert_eq!(read.reasons.len(), 2);
    assert_eq!(read.reasons[&first], "expertise");
    assert_eq!(read.reasons[&second], "capacity");
    assert!(
        read.signals
            .iter()
            .any(|s| s.kind == AllocationSignalKind::PingPong && s.to == Some(party(OWNER)))
    );
}

// RC-18
#[test]
fn rc_18_the_lease_runs_from_the_claim_and_its_expiry_returns_the_work_to_the_pool() {
    let record = queue_record(
        None,
        &[("lease", u(5000)), ("lease_expiry", t("return_to_pool"))],
    );
    let q = version(id(1), id(1), 1, &record);
    assert_eq!(
        q.definition.lease,
        Some(Lease {
            duration: 5000,
            expiry: LeaseExpiry::ReturnToPool,
        })
    );
    let ledger = ledger(vec![q.clone()], Vec::new());
    let taken = held(id(2), &q, BOB, id(3), 10_000);
    assert_eq!(
        ledger.commitment(&taken, Time(11_000)).lease,
        LeaseStatus::Running(Time(15_000))
    );
    let expired = ledger.commitment(&taken, Time(16_000));
    assert!(matches!(expired.lease, LeaseStatus::Expired { .. }));
    assert!(
        expired
            .signals
            .iter()
            .any(|s| s.kind == AllocationSignalKind::LeaseExpired && s.unclaim_due)
    );
}

// RC-10 RC-12 RC-13
#[test]
fn rc_10_a_queue_reads_its_versions_and_open_work_for_its_owner_and_candidates() {
    let q = id(1);
    let v1 = version(q, q, 1, &queue_record(None, &[]));
    let v2 = version(
        q,
        id(5),
        5,
        &queue_record(Some(q), &[("start_within", u(1))]),
    );
    let ledger = ledger(vec![v1, v2.clone()], Vec::new());
    let root = id(2);
    let views = vec![pooled(root, &v2)];
    let read = ledger.queue(&views, &q, &party(OWNER), Time(9000)).unwrap();
    assert_eq!(
        read.versions.iter().map(|v| v.version).collect::<Vec<_>>(),
        [q, id(5)]
    );
    assert_eq!(read.accountability.unwrap().party, party(OWNER));
    assert_eq!(read.work.len(), 1);
    assert_eq!(read.work[0].commitment, root);
    assert_eq!(read.work[0].state, AllocationState::FailedToAssign);
    assert_eq!(read.work[0].signals, [AllocationSignalKind::FailedToAssign]);
    assert!(ledger.queue(&views, &q, &party(BOB), Time(0)).is_ok());
    assert_eq!(
        ledger.queue(&views, &q, &party(DAVE), Time(0)),
        Err(ReadRefusal::NotFound)
    );
    assert_eq!(
        ledger.queue(&views, &root, &party(OWNER), Time(0)),
        Err(ReadRefusal::NotFound)
    );
}

// RC-24
#[test]
fn rc_24_the_workload_counts_held_work_against_the_wip_limits_that_list_the_party() {
    let record = queue_record(None, &[("wip_limit", u(1))]);
    let q = version(id(1), id(1), 1, &record);
    let ledger = ledger(vec![q.clone()], Vec::new());
    let one = vec![held(id(2), &q, BOB, id(3), 3000), pooled(id(4), &q)];
    let read = ledger.workload(&one, &party(BOB), &party(BOB)).unwrap();
    assert_eq!((read.workload.open, read.workload.claimed), (1, 1));
    assert_eq!(read.held[0].via, HoldVia::Claim);
    assert_eq!(read.held[0].queue, Some(id(1)));
    assert!(!read.limits[0].overloaded);
    let two = vec![
        held(id(2), &q, BOB, id(3), 3000),
        held(id(4), &q, BOB, id(5), 5000),
    ];
    let read = ledger.workload(&two, &party(BOB), &party(OWNER)).unwrap();
    assert_eq!(read.workload.open, 2);
    assert!(read.limits[0].overloaded);
    let over = ledger.queue(&two, &id(1), &party(OWNER), Time(0)).unwrap();
    assert_eq!(over.overloaded.len(), 1);
    assert_eq!(over.overloaded[0].party, party(BOB));
    assert_eq!(
        ledger.workload(&two, &party(BOB), &party(DAVE)),
        Err(ReadRefusal::NotFound)
    );
}

// RC-10 RC-12 RC-6
#[test]
fn rc_10_a_queue_version_supersedes_the_version_in_force_and_names_an_accountable_owner() {
    let q = id(1);
    let v1 = version(q, q, 1, &queue_record(None, &[]));
    let check = |record: &Record, queues: &[QueueVersion]| {
        check_against(record, id(99), queues, &[], &[], &actors())
    };
    let fresh = |head: Option<RecordId>, owner: &str| {
        decl(
            OWNER,
            "queue_definition",
            head,
            &[("owner", t(owner)), ("candidates", list(&[BOB]))],
        )
    };
    let one = [v1.clone()];
    assert_eq!(check(&fresh(Some(q), OWNER), &one), Ok(()));
    assert_eq!(
        check(&fresh(Some(q), AGENT), &one),
        Err(Refusal::NotAccountable)
    );
    let two = [v1, version(q, id(5), 5, &fresh(Some(q), OWNER))];
    assert_eq!(
        check(&fresh(Some(q), OWNER), &two),
        Err(Refusal::WrongTarget)
    );
    assert_eq!(check(&fresh(Some(id(5)), OWNER), &two), Ok(()));
    assert_eq!(
        check(&fresh(Some(id(7)), OWNER), &two),
        Err(Refusal::WrongTarget)
    );
    assert!(reads_ledger(&fresh(None, OWNER)));
    assert_eq!(named_parties(&fresh(None, OWNER)), [party(OWNER)]);
}

// RC-48 RC-6
#[test]
fn rc_48_an_organisation_has_one_rule_chain_with_an_accountable_fallback() {
    let rule = |head: Option<RecordId>, organization: &str, fallback: &str| {
        decl(
            OWNER,
            "org_rule",
            head,
            &[("organization", t(organization)), ("fallback", t(fallback))],
        )
    };
    let check = |record: &Record, rules: &[OrgRuleVersion]| {
        check_against(record, id(99), &[], rules, &[], &actors())
    };
    assert_eq!(check(&rule(None, ORG, OWNER), &[]), Ok(()));
    assert_eq!(
        check(&rule(None, ORG, AGENT), &[]),
        Err(Refusal::NotAccountable)
    );
    assert_eq!(
        check(&rule(None, OWNER, OWNER), &[]),
        Err(Refusal::WrongTarget)
    );
    let first = id(1);
    let current = [OrgRuleVersion {
        chain: first,
        version: first,
        rule: OrgRule::of(&rule(None, ORG, OWNER)).unwrap(),
    }];
    assert_eq!(
        check(&rule(None, ORG, BOB), &current),
        Err(Refusal::WrongTarget)
    );
    assert_eq!(check(&rule(Some(first), ORG, BOB), &current), Ok(()));
    assert_eq!(
        check(&rule(Some(id(2)), ORG, BOB), &current),
        Err(Refusal::WrongTarget)
    );
    assert_eq!(
        named_parties(&rule(None, ORG, BOB)),
        [party(BOB), party(ORG)]
    );
}

// RC-9 RC-44 RC-6
#[test]
fn rc_9_a_waiver_scopes_a_commitment_of_the_ledger_and_participation_names_one_agent() {
    let root = id(2);
    let views = [view(
        root,
        Obligor::Party(party(BOB)),
        CommitmentState::Promised,
    )];
    let check = |record: &Record| check_against(record, id(99), &[], &[], &views, &actors());
    let waiver = |c: RecordId, guarantee: &str| {
        decl(
            ALICE,
            "waiver",
            None,
            &[("guarantee", t(guarantee)), ("commitment", d(c))],
        )
    };
    assert_eq!(check(&waiver(root, "advance_notice")), Ok(()));
    assert_eq!(
        check(&waiver(id(77), "advance_notice")),
        Err(Refusal::WrongTarget)
    );
    assert_eq!(
        check(&waiver(root, "oversight")),
        Err(Refusal::WaiverForbidden)
    );
    assert_eq!(check(&engaging(ALICE, &[AGENT])), Ok(()));
    assert_eq!(check(&engaging(ALICE, &[BOB])), Err(Refusal::WrongTarget));
    assert_eq!(
        check(&engaging(ALICE, &[AGENT, BOB])),
        Err(Refusal::MissingContent)
    );
    assert_eq!(kind_of(&engaging(ALICE, &[AGENT])), Some(Kind::Claim));
    assert_eq!(record_action(&engaging(ALICE, &[AGENT])), Some("write"));
    let agent_accountable = decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(BOB)),
            ("acceptor", t(ALICE)),
            ("accountable", t(AGENT)),
        ],
    );
    assert!(checked(&agent_accountable));
    assert!(!reads_ledger(&agent_accountable));
    assert_eq!(check(&agent_accountable), Err(Refusal::NotAccountable));
}

// RC-7 RC-5 E-45
#[test]
fn rc_7_a_transfer_is_an_amend_through_the_commitment_route_and_its_acceptance_an_acknowledgement()
{
    let root = id(2);
    let mut direct = view(root, Obligor::Party(party(BOB)), CommitmentState::Promised);
    direct.accountability.explicit = Some(Explicit {
        party: party(CAROL),
        record: root,
        source: AccountabilitySource::Explicit,
    });
    let amend = decl(CAROL, "amend", Some(root), &[("accountable", t(DAVE))]);
    assert_eq!(kind_of(&amend), Some(Kind::Commitment(Operation::Amend)));
    assert_eq!(record_action(&amend), Some("commit"));
    let facts = Facts {
        conditions_met: &[],
        policy: Policy::default(),
        budget_exhausted: false,
    };
    assert_eq!(
        commitment::check(Some(&direct), &proposed(&amend), &no_records(), &facts),
        Ok(Operation::Amend)
    );
    let transfer = id(3);
    direct.accountability.transfer = Some(Proposal {
        record: transfer,
        to: party(DAVE),
    });
    let accept = decl(
        DAVE,
        "acknowledgement",
        Some(transfer),
        &[("proposal", d(transfer))],
    );
    assert_eq!(
        kind_of(&accept),
        Some(Kind::Declaration(DeclarationSubtype::Acknowledgement))
    );
    assert_eq!(record_action(&accept), Some("condition"));
    assert!(involves(&direct, &party(DAVE)));
    assert_eq!(
        commitment::check_responsibility(&direct, &proposed(&accept), &no_records()),
        Ok(AllocationAct::Acknowledgement)
    );
}
