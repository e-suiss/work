use std::collections::BTreeMap;

use work_kernel::commitment::{
    self, AccessAnswer, CommitmentView, Facts, Operation, Policy, Proposed, Refusal,
};
use work_kernel::derive::{
    AuthorityIssuer, BusinessCalendar, Derivation, DerivationInputs, Entry, Ingest, ProfileVersion,
    Restriction, TrustInputs, derive,
};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time, WorkId};
use work_kernel::record::{
    Audience, AuthorityProofKind, AuthorityRef, Capacity, Claim, ClaimType, Declaration, Param,
    ParamScalar, ParamValue, PartName, ProtocolVersion, Record, RecordCore, VersionVector,
    Visibility,
};
use work_kernel::relation::Relation;
use work_kernel::responsibility::{
    AccountabilitySource, AllocationAct, AllocationSignalKind, AllocationState, ForwardTarget,
    HoldVia, LeaseStatus,
};
use work_kernel::rules::RuleSet;
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

fn id(n: usize) -> RecordId {
    let mut bytes = [0x5d_u8; 32];
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

struct Book {
    records: Vec<(RecordId, Record, u64)>,
}

impl Book {
    fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    fn push(&mut self, record: Record) -> RecordId {
        let rid = id(self.records.len().saturating_add(1));
        let at = self.records.last().map_or(1000, |r| r.2.saturating_add(1000));
        self.records.push((rid, record, at));
        rid
    }

    fn entries(&self) -> Vec<Entry<'_>> {
        self.records
            .iter()
            .zip(1_u64..)
            .map(|((rid, record, at), position)| {
                Entry::unverified(
                    *rid,
                    record,
                    position,
                    Time(*at),
                    Ingest::Admitted,
                    Restriction::NoObjection,
                    AuthorityIssuer::Local,
                )
                .with_author(actor_of(record.core().author.as_str()), false)
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

    fn facts() -> Facts<'static> {
        Facts {
            conditions_met: &[],
            policy: Policy::default(),
            budget_exhausted: false,
        }
    }

    fn views(&self) -> Vec<CommitmentView> {
        let entries = self.entries();
        let derivation = Self::derivation(&entries);
        commitment::derive_commitments(&entries, &derivation, &Self::facts())
    }

    fn view(&self, root: RecordId) -> CommitmentView {
        self.views().into_iter().find(|v| v.root == root).unwrap()
    }

    fn ledger(&self) -> Ledger {
        let entries = self.entries();
        let derivation = Self::derivation(&entries);
        Ledger::with_directory(
            &entries,
            &derivation,
            LedgerDirectory::from_actors(actors()),
        )
    }

    fn time(&self, record: RecordId) -> u64 {
        self.records.iter().find(|r| r.0 == record).unwrap().2
    }

    fn check(&self, record: &Record) -> Result<(), Refusal> {
        let entries = self.entries();
        let derivation = Self::derivation(&entries);
        let ledger = self.ledger();
        check_against(
            record,
            id(9999),
            ledger.queues(),
            ledger.rules(),
            &commitment::derive_commitments(&entries, &derivation, &Self::facts()),
            &actors(),
        )
    }
}

fn queue(book: &mut Book, extra: &[(&str, ParamValue)]) -> RecordId {
    let mut params = vec![("owner", t(OWNER)), ("candidates", list(&[BOB, CAROL]))];
    params.extend(extra.iter().cloned());
    book.push(decl(OWNER, "queue_definition", None, &params))
}

fn pooled(book: &mut Book, queue: RecordId) -> RecordId {
    book.push(decl(
        ALICE,
        "request",
        None,
        &[("queue", d(queue)), ("acceptor", t(ALICE))],
    ))
}

fn proposed(record: &Record) -> Proposed<'_> {
    Proposed {
        id: id(9999),
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

// RC-17 RC-19
#[test]
fn rc_17_a_record_continuing_a_claim_or_an_acknowledgement_finds_its_commitment() {
    let mut book = Book::new();
    let q = queue(&mut book, &[]);
    let root = pooled(&mut book, q);
    let claim = book.push(decl(BOB, "claim", Some(root), &[]));
    let ack = book.push(decl(ALICE, "acknowledgement", Some(claim), &[]));
    let views = book.views();
    assert_eq!(commitment_of(&views, &claim).unwrap().root, root);
    assert_eq!(commitment_of(&views, &ack).unwrap().root, root);
    let unclaim = decl(BOB, "unclaim", Some(ack), &[]);
    let view = commitment_of(&views, &ack).unwrap();
    let entries = book.entries();
    let records: BTreeMap<RecordId, &Record> =
        entries.iter().map(|e| (e.id(), e.record())).collect();
    assert_eq!(
        commitment::check_responsibility(view, &proposed(&unclaim), &records),
        Ok(AllocationAct::Responsibility(
            ResponsibilityOperation::Unclaim
        ))
    );
}

// RC-11 P-56
#[test]
fn rc_11_pooled_work_is_read_by_the_queue_owner_and_its_listed_candidates_only() {
    let mut book = Book::new();
    let q = queue(&mut book, &[("excluded", list(&[CAROL]))]);
    let root = pooled(&mut book, q);
    let view = book.view(root);
    assert!(involves(&view, &party(OWNER)));
    assert!(involves(&view, &party(BOB)));
    assert!(!involves(&view, &party(CAROL)));
    assert!(!involves(&view, &party(DAVE)));
    let mut grouped = Book::new();
    let g = grouped.push(decl(
        OWNER,
        "queue_definition",
        None,
        &[
            ("owner", t(OWNER)),
            ("candidate_group", t("group:acme:legal")),
        ],
    ));
    let root = pooled(&mut grouped, g);
    let view = grouped.view(root);
    assert!(involves(&view, &party(OWNER)));
    assert!(!involves(&view, &party(BOB)));
}

// RC-5 RC-1 RC-15 RC-16 RC-48
#[test]
fn rc_5_pooled_work_names_the_queue_owner_as_its_derived_accountable_and_its_chain() {
    let mut book = Book::new();
    let q = queue(&mut book, &[]);
    let root = pooled(&mut book, q);
    let ledger = book.ledger();
    assert_eq!(ledger.organization(), Some(&party(ORG)));
    let pool = ledger.commitment(&book.view(root), Time(0));
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
    book.push(decl(BOB, "claim", Some(root), &[]));
    let held = book.ledger().commitment(&book.view(root), Time(0));
    assert_eq!(held.state, AllocationState::Held);
    let a = held.accountability.unwrap();
    assert_eq!(
        (a.party.as_str(), a.source),
        (BOB, AccountabilitySource::Obligor)
    );
}

// RC-1 RC-48
#[test]
fn rc_1_without_a_named_organisation_the_fallback_to_it_is_no_party() {
    let mut book = Book::new();
    let root = book.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(BOB)), ("acceptor", t(ALICE))],
    ));
    let entries = book.entries();
    let derivation = Book::derivation(&entries);
    let only_agents = [(party(AGENT), ActorType::Agent)].into_iter().collect();
    let ledger = Ledger::with_directory(
        &entries,
        &derivation,
        LedgerDirectory::from_actors(only_agents),
    );
    assert_eq!(ledger.organization(), None);
    let read = ledger.commitment(&book.view(root), Time(0));
    assert_eq!(read.accountability, None);
    assert!(
        read.chain
            .iter()
            .all(|l| l.source != AccountabilitySource::OrgRule)
    );
}

// RC-14 RC-19
#[test]
fn rc_14_forwardings_keep_their_reason_and_raise_ping_pong_past_the_threshold() {
    let mut book = Book::new();
    let q = queue(&mut book, &[("ping_pong_threshold", u(1))]);
    let root = pooled(&mut book, q);
    let first = book.push(decl(
        OWNER,
        "forward",
        Some(root),
        &[("candidates", list(&[DAVE])), ("reason", t("expertise"))],
    ));
    let second = book.push(decl(
        OWNER,
        "forward",
        Some(first),
        &[("candidates", list(&[BOB])), ("reason", t("capacity"))],
    ));
    let read = book.ledger().commitment(&book.view(root), Time(0));
    assert_eq!(read.ping_pong.count, 2);
    assert!(read.ping_pong.over);
    assert_eq!(
        read.ping_pong.chain[1],
        ForwardTarget::Candidates(vec![party(BOB)])
    );
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
    let mut book = Book::new();
    let q = queue(
        &mut book,
        &[("lease", u(5000)), ("lease_expiry", t("return_to_pool"))],
    );
    let root = pooled(&mut book, q);
    let claim = book.push(decl(BOB, "claim", Some(root), &[]));
    let at = book.time(claim);
    let ledger = book.ledger();
    let view = book.view(root);
    assert_eq!(
        ledger.commitment(&view, Time(at.saturating_add(1000))).lease,
        LeaseStatus::Running(Time(at.saturating_add(5000)))
    );
    let expired = ledger.commitment(&view, Time(at.saturating_add(6000)));
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
    let mut book = Book::new();
    let q = queue(&mut book, &[]);
    let root = pooled(&mut book, q);
    let v2 = book.push(decl(
        OWNER,
        "queue_definition",
        Some(q),
        &[
            ("owner", t(OWNER)),
            ("candidates", list(&[BOB])),
            ("start_within", u(1)),
        ],
    ));
    let ledger = book.ledger();
    let views = book.views();
    let read = ledger
        .queue(&views, &q, &party(OWNER), Time(u64::MAX / 4))
        .unwrap();
    assert_eq!(
        read.versions.iter().map(|v| v.version).collect::<Vec<_>>(),
        [q, v2]
    );
    assert_eq!(read.accountability.unwrap().party, party(OWNER));
    assert_eq!(read.work.len(), 1);
    assert_eq!(read.work[0].commitment, root);
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
    let mut book = Book::new();
    let q = queue(&mut book, &[("wip_limit", u(1))]);
    let first = pooled(&mut book, q);
    let second = pooled(&mut book, q);
    book.push(decl(BOB, "claim", Some(first), &[]));
    let ledger = book.ledger();
    let views = book.views();
    let one = ledger.workload(&views, &party(BOB), &party(BOB)).unwrap();
    assert_eq!((one.workload.open, one.workload.claimed), (1, 1));
    assert_eq!(one.held[0].via, HoldVia::Claim);
    assert_eq!(one.held[0].queue, Some(q));
    assert!(!one.limits[0].overloaded);
    book.push(decl(BOB, "claim", Some(second), &[]));
    let ledger = book.ledger();
    let views = book.views();
    let two = ledger.workload(&views, &party(BOB), &party(OWNER)).unwrap();
    assert_eq!(two.workload.open, 2);
    assert!(two.limits[0].overloaded);
    let over = ledger.queue(&views, &q, &party(OWNER), Time(0)).unwrap();
    assert_eq!(over.overloaded[0].party, party(BOB));
    assert_eq!(
        ledger.workload(&views, &party(BOB), &party(DAVE)),
        Err(ReadRefusal::NotFound)
    );
}

// RC-10 RC-12 RC-6
#[test]
fn rc_10_a_queue_version_supersedes_the_version_in_force_and_names_an_accountable_owner() {
    let mut book = Book::new();
    let q = queue(&mut book, &[]);
    let fresh = |head: Option<RecordId>, owner: &str| {
        decl(
            OWNER,
            "queue_definition",
            head,
            &[("owner", t(owner)), ("candidates", list(&[BOB]))],
        )
    };
    assert_eq!(book.check(&fresh(Some(q), OWNER)), Ok(()));
    assert_eq!(
        book.check(&fresh(Some(q), AGENT)),
        Err(Refusal::NotAccountable)
    );
    book.push(fresh(Some(q), OWNER));
    assert_eq!(
        book.check(&fresh(Some(q), OWNER)),
        Err(Refusal::WrongTarget)
    );
    let root = pooled(&mut book, q);
    assert_eq!(
        book.check(&fresh(Some(root), OWNER)),
        Err(Refusal::WrongTarget)
    );
    assert!(reads_ledger(&fresh(None, OWNER)));
}

// RC-48 RC-6
#[test]
fn rc_48_an_organisation_has_one_rule_chain_with_an_accountable_fallback() {
    let mut book = Book::new();
    let rule = |head: Option<RecordId>, organization: &str, fallback: &str| {
        decl(
            OWNER,
            "org_rule",
            head,
            &[("organization", t(organization)), ("fallback", t(fallback))],
        )
    };
    assert_eq!(book.check(&rule(None, ORG, OWNER)), Ok(()));
    assert_eq!(
        book.check(&rule(None, ORG, AGENT)),
        Err(Refusal::NotAccountable)
    );
    assert_eq!(
        book.check(&rule(None, OWNER, OWNER)),
        Err(Refusal::WrongTarget)
    );
    let first = book.push(rule(None, ORG, OWNER));
    assert_eq!(book.check(&rule(None, ORG, BOB)), Err(Refusal::WrongTarget));
    assert_eq!(book.check(&rule(Some(first), ORG, BOB)), Ok(()));
    assert_eq!(
        named_parties(&rule(None, ORG, BOB)),
        [party(BOB), party(ORG)]
    );
}

// RC-9 RC-44 RC-6
#[test]
fn rc_9_a_waiver_scopes_a_commitment_of_the_ledger_and_participation_names_one_agent() {
    let mut book = Book::new();
    let root = book.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(BOB)), ("acceptor", t(ALICE))],
    ));
    let waiver = |c: RecordId, guarantee: &str| {
        decl(
            ALICE,
            "waiver",
            None,
            &[("guarantee", t(guarantee)), ("commitment", d(c))],
        )
    };
    assert_eq!(book.check(&waiver(root, "advance_notice")), Ok(()));
    assert_eq!(
        book.check(&waiver(id(777), "advance_notice")),
        Err(Refusal::WrongTarget)
    );
    assert_eq!(
        book.check(&waiver(root, "oversight")),
        Err(Refusal::WaiverForbidden)
    );
    assert_eq!(book.check(&engaging(ALICE, &[AGENT])), Ok(()));
    assert_eq!(
        book.check(&engaging(ALICE, &[BOB])),
        Err(Refusal::WrongTarget)
    );
    assert_eq!(
        book.check(&engaging(ALICE, &[AGENT, BOB])),
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
    assert_eq!(book.check(&agent_accountable), Err(Refusal::NotAccountable));
}

// RC-7 RC-5 E-45
#[test]
fn rc_7_a_transfer_is_an_amend_through_the_commitment_route_and_its_acceptance_an_acknowledgement()
{
    let mut book = Book::new();
    let root = book.push(decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(BOB)),
            ("acceptor", t(ALICE)),
            ("accountable", t(CAROL)),
        ],
    ));
    let amend = decl(CAROL, "amend", Some(root), &[("accountable", t(DAVE))]);
    assert_eq!(kind_of(&amend), Some(Kind::Commitment(Operation::Amend)));
    assert_eq!(record_action(&amend), Some("commit"));
    let entries = book.entries();
    let records: BTreeMap<RecordId, &Record> =
        entries.iter().map(|e| (e.id(), e.record())).collect();
    let view = book.view(root);
    assert_eq!(
        commitment::check(Some(&view), &proposed(&amend), &records, &Book::facts()),
        Ok(Operation::Amend)
    );
    drop(records);
    drop(entries);
    let transfer = book.push(amend);
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
    let entries = book.entries();
    let records: BTreeMap<RecordId, &Record> =
        entries.iter().map(|e| (e.id(), e.record())).collect();
    let view = book.view(root);
    assert!(involves(&view, &party(DAVE)));
    assert_eq!(
        commitment::check_responsibility(&view, &proposed(&accept), &records),
        Ok(AllocationAct::Acknowledgement)
    );
}
