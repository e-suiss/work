//! The commitment lifecycle over typed records: the thirteen states, the operation table, the per-item fold, validity, allowed transitions, the next move, implicit acceptance, four eyes, delegation, aggregation, the support chain and the end of `commitment.active`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code"
)]

use std::collections::BTreeMap;

use work_kernel::budget::{Amount, Budget, CONSUMPTION_EXT_KEY, Measure};
use work_kernel::calendar::LocalDateTime;
use work_kernel::catalog::{AggregationRule, ChangePolicy, CoreDerivedRole, DeclarationSubtype};
use work_kernel::clock::{ClockDefinition, ClockState, ClockView, PeriodicDefinition, Target};
use work_kernel::commitment::{
    AccessAnswer, ActiveEndCause, AggregateStatus, AggregationPolicy, Answer, Caller,
    CommitmentState, CommitmentView, Definition, Facts, ImplicitAcceptance, Initiator, Missing,
    Mover, Operation, Policy, Proposed, REPORT_EXT_KEY, REPORT_PARTS, RULES, Refusal, StepOutcome,
    Summary, SupportCause, TimeInputs, TimeProjection, active_ends_of, aggregate, allowed, check,
    clock_events, clock_signals, definition_records, derive_commitments, implicit_acceptance,
    needed, next_moves, offer_gaps, project_time, support_chain, support_signals, zones_named,
};
use work_kernel::commitment_time::{BodyError, TimeCondition};
use work_kernel::currency;
use work_kernel::derive::{
    AuthorityIssuer, BusinessCalendar, DerivationInputs, Effect, Entry, Ingest, NoEffect,
    ProfileVersion, Restriction, TrustInputs, derive,
};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time};
use work_kernel::items::{Area, Expect, ItemKey, touched_in};
use work_kernel::ontology::Obligor;
use work_kernel::record::{
    Act, Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Claim, ClaimType,
    Declaration, EvidenceRef, EvidenceSubject, EvidenceType, ExtValue, Extension, Param,
    ParamScalar, ParamValue, PartName, ProtocolVersion, Record, RecordCore, VersionVector,
    Visibility,
};
use work_kernel::relation::{DerivedRole, DerivedTarget, ReferenceTarget, Relation};
use work_kernel::rrule::Rule;
use work_kernel::rules::RuleSet;
use work_kernel::tz::Zone;
use work_kernel::uri::{ExtKey, TypeUri};
use work_kernel::validate::ActorType;

const ALICE: &str = "party:acme:alice";
const BOB: &str = "party:acme:bob";
const CAROL: &str = "party:acme:carol";
const BUYER: &str = "party:acme:buyer-org";
const AGENT: &str = "party:acme:agent-procure-7";
const AGENT_2: &str = "party:acme:agent-review-2";
const SUPPLIER: &str = "party:globex:supplier";
const SYS: &str = "party:acme:work-scheduler";
const CORE: &str = "https://suiss.app/ns/work/";

fn party(s: &str) -> PartyRef {
    PartyRef::new(s).unwrap()
}

fn id(n: usize) -> RecordId {
    let mut bytes = [0x5c_u8; 32];
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

fn yes() -> ParamValue {
    ParamValue::Scalar(ParamScalar::Bool(true))
}

fn items(list: &[u64]) -> ParamValue {
    ParamValue::List(list.iter().map(|n| ParamScalar::Uint(*n)).collect())
}

/// A Declaration of a core commitment subtype with sorted params.
fn decl(author: &str, name: &str, head: Option<RecordId>, params: &[(&str, ParamValue)]) -> Record {
    let mut params: Vec<Param> = params
        .iter()
        .map(|(k, v)| Param {
            name: PartName::parse(k).unwrap(),
            value: v.clone(),
        })
        .collect();
    params.sort_by(|a, b| work_kernel::id::canonical_text_cmp(a.name.as_str(), b.name.as_str()));
    Record::Declaration(Declaration {
        subtype: TypeUri::parse(&format!("{CORE}declaration/{name}")).unwrap(),
        occurred_at: None,
        core: RecordCore {
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

fn with_body(mut record: Record, parts: &[&str]) -> Record {
    core_mut(&mut record).body = Some(
        parts
            .iter()
            .map(|p| BodyCommitment {
                part: PartName::parse(p).unwrap(),
                commit: Digest::sha256([4; 32]),
            })
            .collect(),
    );
    record
}

fn for_principal(mut record: Record, chain: &[&str]) -> Record {
    let core = core_mut(&mut record);
    core.on_behalf_of = Some(chain.iter().copied().map(party).collect());
    core.capacity = Some(Capacity::For(party(chain[0])));
    record
}

fn with_evidence(mut record: Record) -> Record {
    let presenter = record.core().author.clone();
    core_mut(&mut record).evidence = Some(vec![EvidenceRef {
        subject: EvidenceSubject::Digest(Digest::sha256([5; 32])),
        evidence_type: EvidenceType::from_uri(
            TypeUri::parse(&format!("{CORE}evidence/artifact")).unwrap(),
        ),
        presenter,
        claimed_at: None,
        source: None,
        observation: None,
        visibility: None,
        signature: Digest::sha256([6; 32]),
    }]);
    record
}

fn fulfilling(mut record: Record, act: RecordId, root: RecordId) -> Record {
    core_mut(&mut record)
        .relations
        .get_or_insert_with(Vec::new)
        .push(Relation::DerivedFrom {
            source: Some(act),
            target: DerivedTarget::Record(root),
            role: DerivedRole::Core(CoreDerivedRole::Fulfills),
        });
    record
}

fn supporting(mut record: Record, parent: RecordId) -> Record {
    core_mut(&mut record)
        .relations
        .get_or_insert_with(Vec::new)
        .push(Relation::DerivedFrom {
            source: None,
            target: DerivedTarget::Record(parent),
            role: DerivedRole::Core(CoreDerivedRole::Supports),
        });
    record
}

fn claim(author: &str) -> Record {
    let core = decl(author, "promise", None, &[]).core().clone();
    Record::Claim(Claim {
        subtype: ClaimType::from_uri(TypeUri::parse(&format!("{CORE}claim/observation")).unwrap()),
        occurred_at: Time(1),
        core: RecordCore {
            capacity: None,
            basis: None,
            authority: None,
            ..core
        },
    })
}

struct Ledger {
    records: Vec<(RecordId, Record, ActorType, bool, u64)>,
    facts_met: Vec<(RecordId, u64)>,
    policy: Policy,
    budget_exhausted: bool,
}

impl Ledger {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            facts_met: Vec::new(),
            policy: Policy::default(),
            budget_exhausted: false,
        }
    }

    fn actor(author: &str) -> ActorType {
        match author {
            AGENT | AGENT_2 => ActorType::Agent,
            SUPPLIER | BUYER => ActorType::Organization,
            SYS => ActorType::System,
            _ => ActorType::Human,
        }
    }

    fn at(&mut self, record: Record, recorded_at: u64, step_up: bool) -> RecordId {
        let rid = id(self.records.len() + 1);
        let actor = Self::actor(record.core().author.as_str());
        self.records
            .push((rid, record, actor, step_up, recorded_at));
        rid
    }

    fn push(&mut self, record: Record) -> RecordId {
        let next = self.records.last().map_or(1000, |r| r.4 + 1000);
        self.at(record, next, false)
    }

    fn entries(&self) -> Vec<Entry<'_>> {
        self.records
            .iter()
            .zip(1_u64..)
            .map(|((rid, record, actor, step_up, at), position)| {
                Entry::unverified(
                    *rid,
                    record,
                    position,
                    Time(*at),
                    Ingest::Admitted,
                    Restriction::NoObjection,
                    AuthorityIssuer::Local,
                )
                .with_author(*actor, *step_up)
            })
            .collect()
    }

    fn facts(&self) -> Facts<'_> {
        Facts {
            conditions_met: &self.facts_met,
            policy: self.policy,
            budget_exhausted: self.budget_exhausted,
        }
    }

    fn views(&self) -> Vec<CommitmentView> {
        let entries = self.entries();
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
        let derivation = derive(&entries, &inputs).unwrap();
        derive_commitments(&entries, &derivation, &self.facts())
    }

    fn view(&self, root: RecordId) -> CommitmentView {
        self.views().into_iter().find(|v| v.root == root).unwrap()
    }

    fn outcome(&self, root: RecordId, record: RecordId) -> StepOutcome {
        self.view(root)
            .steps
            .iter()
            .find(|s| s.record == record)
            .unwrap()
            .outcome
    }

    fn records(&self) -> BTreeMap<RecordId, &Record> {
        self.records.iter().map(|r| (r.0, &r.1)).collect()
    }
}

fn request(ledger: &mut Ledger, extra: &[(&str, ParamValue)]) -> RecordId {
    let mut params = vec![("obligor", t(SUPPLIER)), ("acceptor", t(ALICE))];
    params.extend(extra.iter().cloned());
    ledger.push(with_body(
        decl(ALICE, "request", None, &params),
        &["acceptance_criterion"],
    ))
}

fn summary(view: &CommitmentView) -> Summary {
    view.summary()
}

fn uniform(state: CommitmentState) -> Summary {
    Summary::Uniform(state)
}

/// Request, promise and state by the supplier; returns the root and the statement.
fn stated(ledger: &mut Ledger, extra: &[(&str, ParamValue)]) -> (RecordId, RecordId) {
    let root = request(ledger, extra);
    let promise = ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let act = id(900);
    let state = ledger.push(fulfilling(
        decl(SUPPLIER, "state", Some(promise), &[]),
        act,
        root,
    ));
    (root, state)
}

fn accept(author: &str, head: RecordId, statement: RecordId) -> Record {
    decl(author, "accept", Some(head), &[("statement", d(statement))])
}

// CM-14 CM-15
#[test]
fn cm_14_cm_15_thirteen_closed_states_and_promised_is_not_accepted() {
    assert_eq!(CommitmentState::ALL.len(), 13);
    let terminal = CommitmentState::ALL
        .iter()
        .filter(|s| s.is_terminal())
        .count();
    assert_eq!(terminal, 8);
    assert_ne!(
        CommitmentState::Promised.wire_name(),
        CommitmentState::Accepted.wire_name()
    );
    for s in CommitmentState::ALL {
        assert!(!s.wire_name().contains('-'));
        assert_eq!(CommitmentState::from_wire_name(s.wire_name()), Some(*s));
    }
    assert_eq!(Summary::Mixed.wire_name(), "mixed");
    assert!(CommitmentState::from_wire_name("mixed").is_none());
}

// CM-17 P-71 CM-4
#[test]
fn cm_17_the_closed_operation_set_has_one_table_row_each() {
    assert_eq!(Operation::CLOSED_SET.len(), 27);
    assert_eq!(RULES.len(), Operation::ALL.len());
    for (rule, op) in RULES.iter().zip(Operation::ALL) {
        assert_eq!(rule.operation, *op);
        assert_ne!(rule.permits.len(), 0);
        assert_eq!(Operation::of(op.subtype()), Some(*op));
    }
    assert!(Operation::CLOSED_SET.contains(&Operation::Dispute));
    assert!(Operation::CLOSED_SET.contains(&Operation::Defer));
    assert!(Operation::CLOSED_SET.contains(&Operation::Resume));
    assert_eq!(Operation::of(DeclarationSubtype::ClaimResponsibility), None);
    assert_eq!(Operation::of(DeclarationSubtype::OpenCondition), None);
}

// CM-1 CM-28 MD-5 F-9 CM-25 C-29
#[test]
fn cm_1_cm_28_a_statement_or_an_executor_report_is_never_an_acceptance() {
    let mut ledger = Ledger::new();
    let (root, state) = stated(&mut ledger, &[]);
    ledger.push(claim(SUPPLIER));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Stated));
    assert_eq!(view.statement.as_ref().unwrap().record, state);
    assert_eq!(view.fulfilments, vec![id(900)]);
    assert!(view.unevidenced());
    assert!(!view.is_terminal());
}

// CM-2 CM-3 INV-7
#[test]
fn cm_2_cm_3_the_state_is_recomputed_from_the_records_and_silence_changes_nothing() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[("respond_by", u(10))]);
    let first = ledger.view(root);
    assert_eq!(first, ledger.view(root));
    assert_eq!(summary(&first), uniform(CommitmentState::Requested));
    ledger.push(claim(SUPPLIER));
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Requested)
    );
}

// CM-19 P-55
#[test]
fn cm_19_an_invalid_operation_is_refused_with_its_reason_and_kept() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let wrong = ledger.push(decl(ALICE, "promise", Some(root), &[]));
    let early = ledger.push(fulfilling(
        decl(SUPPLIER, "state", Some(wrong), &[]),
        id(900),
        root,
    ));
    assert_eq!(
        ledger.outcome(root, wrong),
        StepOutcome::Refused(Refusal::WrongRole)
    );
    assert_eq!(
        ledger.outcome(root, early),
        StepOutcome::Refused(Refusal::StateNotPermitted)
    );
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Requested)
    );
}

// CM-19 P-55
#[test]
fn cm_19_p_55_allowed_transitions_follow_role_state_and_access() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[("high_impact", yes())]);
    let view = ledger.view(root);
    let supplier = party(SUPPLIER);
    let caller = Caller {
        party: &supplier,
        actor: ActorType::Organization,
        step_up: false,
    };
    let ops: Vec<Operation> = allowed(&view, &caller, &[], &|_| AccessAnswer::Allow)
        .iter()
        .map(|a| a.operation)
        .collect();
    assert!(ops.contains(&Operation::Promise));
    assert!(ops.contains(&Operation::Decline));
    assert!(ops.contains(&Operation::Counter));
    assert!(!ops.contains(&Operation::Accept));
    assert!(!ops.contains(&Operation::Release));
    let alice = party(ALICE);
    let obligee = Caller {
        party: &alice,
        actor: ActorType::Human,
        step_up: false,
    };
    let denied = allowed(&view, &obligee, &[], &|op| {
        if op == Operation::Release {
            AccessAnswer::Deny
        } else {
            AccessAnswer::Allow
        }
    });
    let release = denied
        .iter()
        .find(|a| a.operation == Operation::Release)
        .unwrap();
    assert_eq!(release.missing, vec![Missing::AccessDenied]);
    assert!(!denied.iter().any(|a| a.operation == Operation::Promise));
    let promise = decl(ALICE, "promise", Some(root), &[]);
    let records = ledger.records();
    let proposed = Proposed {
        id: id(500),
        record: &promise,
        position: 9,
        recorded_at: Time(9000),
        author_actor: ActorType::Human,
        step_up: false,
        access: AccessAnswer::Allow,
        agent_side: false,
        control_supported: false,
    };
    assert_eq!(
        check(Some(&view), &proposed, &records, &ledger.facts()),
        Err(Refusal::WrongRole)
    );
    let good = decl(SUPPLIER, "promise", Some(root), &[]);
    let by_supplier = Proposed {
        record: &good,
        author_actor: ActorType::Organization,
        ..proposed
    };
    assert_eq!(
        check(Some(&view), &by_supplier, &records, &ledger.facts()),
        Ok(Operation::Promise)
    );
    let denied_write = Proposed {
        access: AccessAnswer::Deny,
        ..by_supplier
    };
    assert_eq!(
        check(Some(&view), &denied_write, &records, &ledger.facts()),
        Err(Refusal::AccessDenied)
    );
}

// CM-40 CM-60 P-55
#[test]
fn cm_40_cm_60_a_high_impact_acceptance_needs_a_step_up() {
    let mut ledger = Ledger::new();
    let (root, state) = stated(&mut ledger, &[("high_impact", yes())]);
    let view = ledger.view(root);
    let alice = party(ALICE);
    let caller = Caller {
        party: &alice,
        actor: ActorType::Human,
        step_up: false,
    };
    let list = allowed(&view, &caller, &[], &|_| AccessAnswer::Allow);
    let accept_entry = list
        .iter()
        .find(|a| a.operation == Operation::Accept)
        .unwrap();
    assert_eq!(accept_entry.missing, vec![Missing::StepUp]);
    let without = ledger.push(accept(ALICE, state, state));
    assert_eq!(
        ledger.outcome(root, without),
        StepOutcome::Refused(Refusal::StepUpRequired)
    );
    let with = ledger.at(accept(ALICE, without, state), 99_000, true);
    assert_eq!(ledger.outcome(root, with), StepOutcome::Applied);
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Accepted)
    );
}

// CM-16 CM-31 CM-24
#[test]
fn cm_16_cm_31_only_a_declared_validity_expires_and_a_promise_never_does() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[("respond_by", u(50_000))]);
    let early = ledger.push(with_basis(decl(SYS, "expire", Some(root), &[]), &[root]));
    assert_eq!(
        ledger.outcome(root, early),
        StepOutcome::Refused(Refusal::NotYetDue)
    );
    let late = ledger.at(
        with_basis(decl(SYS, "expire", Some(early), &[]), &[root]),
        60_000,
        false,
    );
    let view = ledger.view(root);
    assert_eq!(ledger.outcome(root, late), StepOutcome::Applied);
    assert_eq!(summary(&view), uniform(CommitmentState::Expired));
    assert_eq!(
        view.items[0].closing.unwrap().initiator,
        Initiator::WorkService
    );

    let mut promised = Ledger::new();
    let root = request(&mut promised, &[("respond_by", u(50_000))]);
    let promise = promised.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let expire = promised.at(
        with_basis(decl(SYS, "expire", Some(promise), &[]), &[root]),
        90_000,
        false,
    );
    assert_eq!(
        promised.outcome(root, expire),
        StepOutcome::Refused(Refusal::StateNotPermitted)
    );
    let by_party = promised.push(with_basis(
        decl(ALICE, "expire", Some(expire), &[]),
        &[root],
    ));
    assert_eq!(
        promised.outcome(root, by_party),
        StepOutcome::Refused(Refusal::WrongRole)
    );
}

// CM-29 CM-30 E-8 E-12
#[test]
fn cm_29_cm_30_cancel_and_release_differ_and_end_commitment_active() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let promise = ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let cancel = ledger.push(decl(
        SUPPLIER,
        "cancel",
        Some(promise),
        &[("reason", t("failed"))],
    ));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Cancelled));
    assert_eq!(view.items[0].closing.unwrap().initiator, Initiator::Obligor);
    assert_eq!(view.active_ends.len(), 1);
    assert_eq!(view.active_ends[0].record, cancel);
    assert_eq!(view.active_ends[0].cause, ActiveEndCause::Closed);

    let mut released = Ledger::new();
    let root = request(&mut released, &[]);
    let promise = released.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let by_obligor = released.push(decl(SUPPLIER, "release", Some(promise), &[]));
    released.push(decl(ALICE, "release", Some(by_obligor), &[]));
    let view = released.view(root);
    assert_eq!(
        released.outcome(root, by_obligor),
        StepOutcome::Refused(Refusal::WrongRole)
    );
    assert_eq!(summary(&view), uniform(CommitmentState::Released));
    assert_eq!(view.items[0].closing.unwrap().initiator, Initiator::Obligee);
}

// CM-34 P-24 MD-20
#[test]
fn cm_34_a_terminal_outcome_never_changes_and_a_late_statement_is_kept() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let promise = ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let cancel = ledger.push(decl(
        SUPPLIER,
        "cancel",
        Some(promise),
        &[("reason", t("abandoned"))],
    ));
    let late = ledger.push(fulfilling(
        decl(SUPPLIER, "state", Some(cancel), &[]),
        id(900),
        root,
    ));
    assert_eq!(
        ledger.outcome(root, late),
        StepOutcome::Refused(Refusal::TerminalOutcome)
    );
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Cancelled)
    );
}

// CM-35 CM-36 P-24
#[test]
fn cm_35_revocations_are_requests_the_counterparty_answers() {
    let mut ledger = Ledger::new();
    let (root, state) = stated(&mut ledger, &[]);
    let revoke = ledger.push(decl(
        SUPPLIER,
        "revoke_statement",
        Some(state),
        &[("reason", t("mistake"))],
    ));
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Stated)
    );
    let own = ledger.push(decl(
        SUPPLIER,
        "allow",
        Some(revoke),
        &[("revocation", d(revoke))],
    ));
    assert_eq!(
        ledger.outcome(root, own),
        StepOutcome::Refused(Refusal::WrongRole)
    );
    let allow = ledger.push(decl(
        ALICE,
        "allow",
        Some(own),
        &[("revocation", d(revoke))],
    ));
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Promised)
    );
    let revoke_promise = ledger.push(decl(
        SUPPLIER,
        "revoke_promise",
        Some(allow),
        &[("reason", t("circumstances_changed"))],
    ));
    let refuse = ledger.push(decl(
        ALICE,
        "refuse",
        Some(revoke_promise),
        &[
            ("revocation", d(revoke_promise)),
            ("reason", t("already_relied_on")),
        ],
    ));
    let view = ledger.view(root);
    assert!(view.disputed());
    assert_eq!(view.disputes, vec![refuse]);
    assert_eq!(summary(&view), uniform(CommitmentState::Promised));
    let again = ledger.push(decl(
        SUPPLIER,
        "revoke_promise",
        Some(refuse),
        &[("reason", t("duplicate"))],
    ));
    ledger.push(decl(
        ALICE,
        "allow",
        Some(again),
        &[("revocation", d(again))],
    ));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Withdrawn));
    assert_eq!(view.items[0].closing.unwrap().initiator, Initiator::Obligor);
    assert_eq!(view.steps.len(), 9);
}

// CM-35 CM-36 CM-34
#[test]
fn cm_35_an_allowed_revocation_of_acceptance_keeps_the_outcome_and_allows_reopening() {
    let mut ledger = Ledger::new();
    let (root, state) = stated(&mut ledger, &[]);
    let accepted = ledger.push(accept(ALICE, state, state));
    let revoke = ledger.push(decl(
        ALICE,
        "revoke_acceptance",
        Some(accepted),
        &[("reason", t("mistake"))],
    ));
    let dispute = ledger.push(decl(
        SUPPLIER,
        "dispute",
        Some(revoke),
        &[
            ("disputed", d(revoke)),
            ("reason", t("revocation_unfounded")),
        ],
    ));
    ledger.push(decl(
        SUPPLIER,
        "allow",
        Some(dispute),
        &[("revocation", d(revoke))],
    ));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Accepted));
    assert_eq!(view.reopening, Some(revoke));
    assert_eq!(view.disputes, vec![dispute]);
}

// CM-26 CM-36 CM-17
#[test]
fn cm_26_a_rejection_returns_to_execution_and_counts_until_acceptance() {
    let mut ledger = Ledger::new();
    let (root, state) = stated(&mut ledger, &[]);
    let reject = ledger.push(decl(
        ALICE,
        "reject",
        Some(state),
        &[("statement", d(state)), ("reason", t("incomplete"))],
    ));
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Promised)
    );
    let dispute = ledger.push(decl(
        SUPPLIER,
        "dispute",
        Some(reject),
        &[("disputed", d(reject)), ("reason", t("criteria_met"))],
    ));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Promised));
    assert!(view.disputed());
    let second = ledger.push(fulfilling(
        decl(SUPPLIER, "state", Some(dispute), &[]),
        id(901),
        root,
    ));
    let reject2 = ledger.push(decl(
        ALICE,
        "reject",
        Some(second),
        &[("statement", d(second)), ("reason", t("evidence_missing"))],
    ));
    assert_eq!(ledger.view(root).rejections, 2);
    let third = ledger.push(fulfilling(
        decl(SUPPLIER, "state", Some(reject2), &[]),
        id(902),
        root,
    ));
    let outdated = ledger.push(accept(ALICE, third, second));
    assert_eq!(
        ledger.outcome(root, outdated),
        StepOutcome::Refused(Refusal::WrongTarget)
    );
    ledger.push(accept(ALICE, outdated, third));
    let view = ledger.view(root);
    assert_eq!(view.rejections, 0);
    assert_eq!(view.rejected.len(), 2);
    assert_eq!(summary(&view), uniform(CommitmentState::Accepted));
}

// CM-37 CM-38 MD-5
#[test]
fn cm_37_cm_38_four_eyes_guards_an_agents_output() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let promise = ledger.push(for_principal(
        decl(AGENT, "promise", Some(root), &[]),
        &[SUPPLIER, BUYER],
    ));
    let state = ledger.push(for_principal(
        fulfilling(decl(AGENT, "state", Some(promise), &[]), id(900), root),
        &[SUPPLIER, BUYER],
    ));
    let alone = ledger.push(accept(ALICE, state, state));
    assert_eq!(
        ledger.outcome(root, alone),
        StepOutcome::Refused(Refusal::FourEyes)
    );
    let other_agent = ledger.push(for_principal(accept(AGENT_2, alone, state), &[ALICE]));
    assert_eq!(
        ledger.outcome(root, other_agent),
        StepOutcome::Refused(Refusal::FourEyes)
    );
    let not_acceptor = ledger.push(accept(BOB, other_agent, state));
    assert_eq!(
        ledger.outcome(root, not_acceptor),
        StepOutcome::Refused(Refusal::WrongRole)
    );

    let mut second = Ledger::new();
    let root = second.push(with_body(
        decl(
            ALICE,
            "request",
            None,
            &[("obligor", t(AGENT)), ("acceptor", t(CAROL))],
        ),
        &["acceptance_criterion"],
    ));
    let promise = second.push(decl(AGENT, "promise", Some(root), &[]));
    let state = second.push(fulfilling(
        decl(AGENT, "state", Some(promise), &[]),
        id(900),
        root,
    ));
    second.push(accept(CAROL, state, state));
    assert_eq!(
        summary(&second.view(root)),
        uniform(CommitmentState::Accepted)
    );
}

// CM-39 CM-38
#[test]
fn cm_39_a_recorded_waiver_lifts_four_eyes_unless_policy_forbids_it() {
    let build = |forbidden: bool| {
        let mut ledger = Ledger::new();
        ledger.policy.four_eyes_waiver_forbidden = forbidden;
        let root = ledger.push(with_body(
            decl(
                ALICE,
                "request",
                None,
                &[
                    ("obligor", t(AGENT)),
                    ("acceptor", t(ALICE)),
                    ("four_eyes_waived", yes()),
                ],
            ),
            &["acceptance_criterion"],
        ));
        let promise = ledger.push(decl(AGENT, "promise", Some(root), &[]));
        let state = ledger.push(fulfilling(
            decl(AGENT, "state", Some(promise), &[]),
            id(900),
            root,
        ));
        let accepted = ledger.push(accept(ALICE, state, state));
        ledger.outcome(root, accepted)
    };
    assert_eq!(build(false), StepOutcome::Applied);
    assert_eq!(build(true), StepOutcome::Refused(Refusal::FourEyes));
}

// CM-27 C-10
#[test]
fn cm_27_an_acceptance_that_needs_evidence_is_invalid_without_it() {
    let mut ledger = Ledger::new();
    let (root, state) = stated(&mut ledger, &[("evidence_required", yes())]);
    let bare = ledger.push(accept(ALICE, state, state));
    assert_eq!(
        ledger.outcome(root, bare),
        StepOutcome::Refused(Refusal::EvidenceRequired)
    );
    let evidenced = ledger.push(with_evidence(accept(ALICE, bare, state)));
    assert_eq!(ledger.outcome(root, evidenced), StepOutcome::Applied);

    let mut policy = Ledger::new();
    policy.policy.evidence_required = true;
    let (root, state) = stated(&mut policy, &[]);
    let bare = policy.push(accept(ALICE, state, state));
    assert_eq!(
        policy.outcome(root, bare),
        StepOutcome::Refused(Refusal::EvidenceRequired)
    );
}

// CM-41 CM-42 CM-3 INV-11 SEC-10
#[test]
fn cm_41_cm_42_implicit_acceptance_needs_prior_terms_and_never_bypasses_the_rules() {
    let mut ledger = Ledger::new();
    let (root, state) = stated(&mut ledger, &[]);
    let view = ledger.view(root);
    assert_eq!(
        implicit_acceptance(&view, Time(u64::MAX), &ledger.facts()),
        ImplicitAcceptance::NoTerms
    );
    let silent = ledger.at(
        with_basis(
            decl(
                SYS,
                "accept",
                Some(state),
                &[("statement", d(state)), ("implicit", yes())],
            ),
            &[state],
        ),
        u64::MAX / 4,
        false,
    );
    assert_eq!(
        ledger.outcome(root, silent),
        StepOutcome::Refused(Refusal::NothingPending)
    );

    let mut declared = Ledger::new();
    let root = request(&mut declared, &[]);
    let terms = declared.push(decl(
        ALICE,
        "implicit_acceptance_terms",
        Some(root),
        &[("window", u(10_000))],
    ));
    let promise = declared.push(decl(SUPPLIER, "promise", Some(terms), &[]));
    let state = declared.at(
        fulfilling(decl(SUPPLIER, "state", Some(promise), &[]), id(900), root),
        20_000,
        false,
    );
    let implicit = |head: RecordId| {
        with_basis(
            decl(
                SYS,
                "accept",
                Some(head),
                &[("statement", d(state)), ("implicit", yes())],
            ),
            &[terms],
        )
    };
    let view = declared.view(root);
    assert_eq!(
        implicit_acceptance(&view, Time(25_000), &declared.facts()),
        ImplicitAcceptance::Waiting(Time(30_000))
    );
    assert_eq!(
        implicit_acceptance(&view, Time(30_000), &declared.facts()),
        ImplicitAcceptance::Due
    );
    let early = declared.at(implicit(state), 25_000, false);
    assert_eq!(
        declared.outcome(root, early),
        StepOutcome::Refused(Refusal::NotYetDue)
    );
    let due = declared.at(implicit(early), 31_000, false);
    let view = declared.view(root);
    assert_eq!(declared.outcome(root, due), StepOutcome::Applied);
    assert_eq!(summary(&view), uniform(CommitmentState::Accepted));
    assert_eq!(
        view.items[0].closing.unwrap().initiator,
        Initiator::WorkService
    );

    let mut high = Ledger::new();
    let root = request(&mut high, &[("high_impact", yes())]);
    high.push(decl(
        ALICE,
        "implicit_acceptance_terms",
        Some(root),
        &[("window", u(1))],
    ));
    let view = high.view(root);
    assert_eq!(view.implicit.as_ref().unwrap().window, 1);
}

// CM-42 CM-38
#[test]
fn cm_42_an_implicit_acceptance_blocked_by_four_eyes_or_step_up_awaits_acceptance() {
    let mut ledger = Ledger::new();
    let root = ledger.push(decl(
        ALICE,
        "request",
        None,
        &[
            ("obligor", t(AGENT)),
            ("acceptor", t(ALICE)),
            ("high_impact", yes()),
        ],
    ));
    let terms = ledger.push(decl(
        ALICE,
        "implicit_acceptance_terms",
        Some(root),
        &[("window", u(1))],
    ));
    let promise = ledger.push(decl(AGENT, "promise", Some(terms), &[]));
    let state = ledger.push(fulfilling(
        decl(AGENT, "state", Some(promise), &[]),
        id(900),
        root,
    ));
    let view = ledger.view(root);
    assert_eq!(
        implicit_acceptance(&view, Time(u64::MAX), &ledger.facts()),
        ImplicitAcceptance::Blocked(Refusal::StepUpRequired)
    );
    let attempt = ledger.at(
        with_basis(
            decl(
                SYS,
                "accept",
                Some(state),
                &[("statement", d(state)), ("implicit", yes())],
            ),
            &[terms],
        ),
        u64::MAX / 4,
        false,
    );
    assert_eq!(
        ledger.outcome(root, attempt),
        StepOutcome::Refused(Refusal::StepUpRequired)
    );
}

// CM-43 CM-44 C-28 E-8 E-12
#[test]
fn cm_43_cm_44_delegation_is_two_records_and_the_old_obligor_stays_until_acceptance() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let promise = ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let proposal = ledger.push(with_body(
        decl(
            SUPPLIER,
            "delegate",
            Some(promise),
            &[
                ("step", t("proposal")),
                ("obligor", t(BUYER)),
                ("handover_reason", t("capacity")),
                ("stateful", yes()),
            ],
        ),
        &["summary", "done", "changed", "open_questions", "next_steps"],
    ));
    let view = ledger.view(root);
    assert_eq!(view.obligor, Obligor::Party(party(SUPPLIER)));
    assert!(next_moves(&view, &ledger.facts()).contains(&Mover::Party(party(BUYER))));
    let stranger = ledger.push(decl(
        CAROL,
        "delegate",
        Some(proposal),
        &[("step", t("acceptance")), ("proposal", d(proposal))],
    ));
    assert_eq!(
        ledger.outcome(root, stranger),
        StepOutcome::Refused(Refusal::WrongRole)
    );
    let acceptance = ledger.push(decl(
        BUYER,
        "delegate",
        Some(stranger),
        &[("step", t("acceptance")), ("proposal", d(proposal))],
    ));
    let view = ledger.view(root);
    assert_eq!(view.obligor, Obligor::Party(party(BUYER)));
    assert_eq!(summary(&view), uniform(CommitmentState::Promised));
    assert_eq!(view.handovers, vec![proposal]);
    assert_eq!(view.active_ends.len(), 1);
    assert_eq!(view.active_ends[0].obligor, party(SUPPLIER));
    assert_eq!(view.active_ends[0].record, acceptance);
    assert_eq!(view.active_ends[0].cause, ActiveEndCause::Delegated);
}

// E-12 E-8
#[test]
fn e_12_the_ends_a_proposed_record_gives_are_those_the_fold_derives_once_it_is_written() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let promise = ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let view = ledger.view(root);
    let records = ledger.records();
    let cancel = decl(
        SUPPLIER,
        "cancel",
        Some(promise),
        &[("reason", t("failed"))],
    );
    let proposed = Proposed {
        id: id(700),
        record: &cancel,
        position: 3,
        recorded_at: Time(3000),
        author_actor: ActorType::Organization,
        step_up: false,
        access: AccessAnswer::Allow,
        agent_side: false,
        control_supported: false,
    };
    let ends = active_ends_of(&view, &proposed, &records, &ledger.facts());
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].obligor, party(SUPPLIER));
    assert_eq!(ends[0].record, id(700));
    assert_eq!(ends[0].cause, ActiveEndCause::Closed);
    let mut written = Ledger::new();
    let root_w = request(&mut written, &[]);
    let promise_w = written.push(decl(SUPPLIER, "promise", Some(root_w), &[]));
    let cancel_w = written.push(decl(
        SUPPLIER,
        "cancel",
        Some(promise_w),
        &[("reason", t("failed"))],
    ));
    let derived = written.view(root_w).active_ends;
    assert_eq!(derived.len(), 1);
    assert_eq!(derived[0].record, cancel_w);
    assert_eq!(derived[0].obligor, ends[0].obligor);
    assert_eq!(derived[0].cause, ends[0].cause);
    let by_alice = decl(ALICE, "cancel", Some(promise), &[("reason", t("failed"))]);
    let refused = Proposed {
        record: &by_alice,
        author_actor: ActorType::Human,
        ..proposed
    };
    assert!(active_ends_of(&view, &refused, &records, &ledger.facts()).is_empty());
    let again = decl(SUPPLIER, "promise", Some(promise), &[]);
    let no_end = Proposed {
        record: &again,
        ..proposed
    };
    assert!(active_ends_of(&view, &no_end, &records, &ledger.facts()).is_empty());
    let mut delegated = Ledger::new();
    let root_d = request(&mut delegated, &[]);
    let promise_d = delegated.push(decl(SUPPLIER, "promise", Some(root_d), &[]));
    let proposal = delegated.push(with_body(
        decl(
            SUPPLIER,
            "delegate",
            Some(promise_d),
            &[
                ("step", t("proposal")),
                ("obligor", t(BUYER)),
                ("handover_reason", t("capacity")),
                ("stateful", yes()),
            ],
        ),
        &["summary", "done", "changed", "open_questions", "next_steps"],
    ));
    let view = delegated.view(root_d);
    let records = delegated.records();
    let acceptance = decl(
        BUYER,
        "delegate",
        Some(proposal),
        &[("step", t("acceptance")), ("proposal", d(proposal))],
    );
    let accepted = Proposed {
        id: id(701),
        record: &acceptance,
        position: 4,
        recorded_at: Time(4000),
        author_actor: ActorType::Organization,
        ..proposed
    };
    let ends = active_ends_of(&view, &accepted, &records, &delegated.facts());
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].obligor, party(SUPPLIER));
    assert_eq!(ends[0].cause, ActiveEndCause::Delegated);
}

// CM-43 CM-37
#[test]
fn cm_43_an_assignment_changes_the_obligee_and_never_the_acceptor() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let proposal = ledger.push(decl(
        ALICE,
        "assign",
        Some(root),
        &[("step", t("proposal")), ("obligee", t(BOB))],
    ));
    assert_eq!(ledger.view(root).obligee, party(ALICE));
    ledger.push(decl(
        BOB,
        "assign",
        Some(proposal),
        &[("step", t("acceptance")), ("proposal", d(proposal))],
    ));
    let view = ledger.view(root);
    assert_eq!(view.obligee, party(BOB));
    assert_eq!(view.acceptor, party(ALICE));
}

// CM-23
#[test]
fn cm_23_items_derive_their_own_states_and_the_summary_is_mixed() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[("item_count", u(2))]);
    let promise = ledger.push(decl(
        SUPPLIER,
        "promise",
        Some(root),
        &[("items", items(&[0]))],
    ));
    let decline = ledger.push(decl(
        SUPPLIER,
        "decline",
        Some(promise),
        &[("reason", t("no_capacity")), ("items", items(&[1]))],
    ));
    let view = ledger.view(root);
    assert_eq!(summary(&view), Summary::Mixed);
    assert_eq!(view.state_of(0), Some(CommitmentState::Promised));
    assert_eq!(view.state_of(1), Some(CommitmentState::Declined));
    let unknown = ledger.push(decl(
        SUPPLIER,
        "promise",
        Some(decline),
        &[("items", items(&[5]))],
    ));
    assert_eq!(
        ledger.outcome(root, unknown),
        StepOutcome::Refused(Refusal::UnknownItem)
    );
}

// CM-20 CM-21 CM-24
#[test]
fn cm_21_a_counter_offer_versions_the_offer_and_its_acceptance_is_a_promise() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[("due", u(100))]);
    let counter = ledger.push(decl(SUPPLIER, "counter", Some(root), &[("due", u(200))]));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Countered));
    assert_eq!(view.offer_version, 1);
    assert_eq!(view.terms.due, Some(Time(100)));
    let back = ledger.push(decl(ALICE, "counter", Some(counter), &[("due", u(150))]));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Requested));
    assert_eq!(view.terms.due, Some(Time(150)));
    let counter2 = ledger.push(decl(SUPPLIER, "counter", Some(back), &[("due", u(180))]));
    let stale = ledger.push(decl(
        ALICE,
        "accept_counter",
        Some(counter2),
        &[("counter", d(counter))],
    ));
    assert_eq!(
        ledger.outcome(root, stale),
        StepOutcome::Refused(Refusal::WrongTarget)
    );
    ledger.push(decl(
        ALICE,
        "accept_counter",
        Some(stale),
        &[("counter", d(counter2))],
    ));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Promised));
    assert_eq!(view.terms.due, Some(Time(180)));
    assert_eq!(view.offer_version, 3);
}

// CM-20
#[test]
fn cm_20_a_decline_closes_the_request_without_execution() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    ledger.push(decl(
        SUPPLIER,
        "decline",
        Some(root),
        &[("reason", t("out_of_scope"))],
    ));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Declined));
    assert!(view.statement.is_none());
}

// CM-22 CM-3
#[test]
fn cm_22_a_conditional_promise_becomes_a_promise_from_the_meeting_record_or_expires() {
    let condition = id(800);
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let conditional = ledger.push(decl(
        SUPPLIER,
        "promise_conditional",
        Some(root),
        &[("precondition", d(condition)), ("valid_until", u(70_000))],
    ));
    let view = ledger.view(root);
    assert_eq!(
        summary(&view),
        uniform(CommitmentState::ConditionallyPromised)
    );
    assert_eq!(
        next_moves(&view, &ledger.facts()),
        vec![Mover::PreconditionAddressee(condition)]
    );
    let met = Ledger {
        records: ledger.records.clone(),
        facts_met: vec![(condition, 3)],
        policy: Policy::default(),
        budget_exhausted: false,
    };
    assert_eq!(summary(&met.view(root)), uniform(CommitmentState::Promised));
    let expire = ledger.at(
        with_basis(decl(SYS, "expire", Some(conditional), &[]), &[conditional]),
        80_000,
        false,
    );
    assert_eq!(ledger.outcome(root, expire), StepOutcome::Applied);
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Expired)
    );
}

// CM-13 RC-10
#[test]
fn cm_13_a_pool_request_binds_whoever_promises() {
    let mut ledger = Ledger::new();
    let root = ledger.push(decl(
        ALICE,
        "request",
        None,
        &[("queue", d(id(700))), ("acceptor", t(ALICE))],
    ));
    let view = ledger.view(root);
    assert_eq!(
        next_moves(&view, &ledger.facts()),
        vec![Mover::Queue(id(700))]
    );
    ledger.push(decl(CAROL, "promise", Some(root), &[]));
    assert_eq!(ledger.view(root).obligor, Obligor::Party(party(CAROL)));
}

// CM-58 CM-49
#[test]
fn cm_58_the_next_move_follows_the_state() {
    let mut ledger = Ledger::new();
    let (root, _) = stated(&mut ledger, &[]);
    let view = ledger.view(root);
    assert_eq!(
        next_moves(&view, &ledger.facts()),
        vec![Mover::Party(party(ALICE))]
    );
    ledger.budget_exhausted = true;
    assert!(next_moves(&view, &ledger.facts()).contains(&Mover::Accountable));
    let mut requested = Ledger::new();
    let root = request(&mut requested, &[]);
    assert_eq!(
        next_moves(&requested.view(root), &requested.facts()),
        vec![Mover::Party(party(SUPPLIER))]
    );
}

// CM-17 ST-7
#[test]
fn cm_17_defer_and_notice_never_change_the_state() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let promise = ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let defer = ledger.push(decl(
        SUPPLIER,
        "defer",
        Some(promise),
        &[("reason", t("priority")), ("resume_at", u(70_000))],
    ));
    let view = ledger.view(root);
    assert!(view.deferred());
    assert_eq!(summary(&view), uniform(CommitmentState::Promised));
    let notice = ledger.push(decl(
        SUPPLIER,
        "notice",
        Some(defer),
        &[("notice_type", t("at_risk"))],
    ));
    let early = ledger.push(with_basis(
        decl(SYS, "resume", Some(notice), &[("deferral", d(defer))]),
        &[defer],
    ));
    assert_eq!(
        ledger.outcome(root, early),
        StepOutcome::Refused(Refusal::NotYetDue)
    );
    ledger.at(
        with_basis(
            decl(SYS, "resume", Some(early), &[("deferral", d(defer))]),
            &[defer],
        ),
        70_000,
        false,
    );
    let view = ledger.view(root);
    assert!(!view.deferred());
    assert_eq!(summary(&view), uniform(CommitmentState::Promised));
    assert_eq!(view.notices.len(), 1);
}

// CM-32 CM-33
#[test]
fn cm_32_cm_33_obsolete_and_administrative_close_name_their_initiator() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    ledger.push(decl(
        ALICE,
        "declare_obsolete",
        Some(root),
        &[("parent", d(id(600)))],
    ));
    let view = ledger.view(root);
    assert_eq!(summary(&view), uniform(CommitmentState::Obsolete));
    assert_eq!(view.items[0].closing.unwrap().initiator, Initiator::Obligee);

    let mut admin = Ledger::new();
    let root = request(&mut admin, &[]);
    admin.push(with_body(
        decl(CAROL, "administrative_close", Some(root), &[]),
        &["note"],
    ));
    let view = admin.view(root);
    assert_eq!(
        summary(&view),
        uniform(CommitmentState::ClosedAdministratively)
    );
    assert_eq!(
        view.items[0].closing.unwrap().initiator,
        Initiator::Administrator
    );
}

// CM-56 CM-57 CM-60 P-74 P-86
#[test]
fn cm_56_a_terms_amendment_needs_the_obligors_renewed_promise() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[("due", u(100))]);
    let promise = ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let instruction = ledger.push(decl(
        ALICE,
        "amend",
        Some(promise),
        &[("change_policy", t("rollback"))],
    ));
    let view = ledger.view(root);
    assert_eq!(view.instruction_version, 1);
    assert_eq!(view.terms.change_policy, ChangePolicy::Rollback);
    let terms = ledger.push(decl(
        ALICE,
        "amend",
        Some(instruction),
        &[("change", t("terms")), ("due", u(300))],
    ));
    let view = ledger.view(root);
    assert_eq!(view.terms.due, Some(Time(100)));
    assert!(view.pending.amendment.is_some());
    let refused = ledger.push(decl(
        SUPPLIER,
        "refuse",
        Some(terms),
        &[("amendment", d(terms)), ("reason", t("disagree"))],
    ));
    let view = ledger.view(root);
    assert_eq!(view.terms.due, Some(Time(100)));
    assert!(view.pending.amendment.is_none());
    let terms2 = ledger.push(decl(
        ALICE,
        "amend",
        Some(refused),
        &[("change", t("terms")), ("due", u(400))],
    ));
    let renewed = ledger.push(decl(
        SUPPLIER,
        "promise",
        Some(terms2),
        &[("amendment", d(terms2))],
    ));
    let view = ledger.view(root);
    assert_eq!(view.terms.due, Some(Time(400)));
    assert_eq!(summary(&view), uniform(CommitmentState::Promised));
    let raise = ledger.push(decl(
        SUPPLIER,
        "amend",
        Some(renewed),
        &[("high_impact", yes())],
    ));
    assert_eq!(ledger.view(root).steps.last().unwrap().record, raise);
}

// CM-56 P-74
#[test]
fn cm_56_p_74_the_same_author_writing_the_same_version_twice_is_refused() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let promise = ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    ledger.push(decl(
        ALICE,
        "amend",
        Some(promise),
        &[("change_policy", t("reject"))],
    ));
    ledger.push(decl(
        ALICE,
        "amend",
        Some(promise),
        &[("change_policy", t("queue"))],
    ));
    let entries = ledger.entries();
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
    let derivation = derive(&entries, &inputs).unwrap();
    assert_eq!(
        derivation.records[3].admission,
        work_kernel::derive::Admission::Rejected(work_kernel::reason::Reason::DuplicateVersion)
    );
    assert_eq!(derivation.records[2].effect, Effect::Normative);
    assert_ne!(derivation.records[3].effect, Effect::Normative);
    assert_ne!(
        derivation.records[3].effect,
        Effect::None(NoEffect::TerminalOutcome)
    );
}

// CM-57
#[test]
fn cm_57_interrupt_and_rollback_need_the_executors_control_capability() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let view = ledger.view(root);
    assert_eq!(view.terms.change_policy, ChangePolicy::Queue);
    let amend = decl(
        ALICE,
        "amend",
        Some(root),
        &[("change_policy", t("interrupt"))],
    );
    let records = ledger.records();
    let proposed = Proposed {
        id: id(500),
        record: &amend,
        position: 9,
        recorded_at: Time(9000),
        author_actor: ActorType::Human,
        step_up: false,
        access: AccessAnswer::Allow,
        agent_side: false,
        control_supported: false,
    };
    assert_eq!(
        check(Some(&view), &proposed, &records, &ledger.facts()),
        Err(Refusal::ControlNotSupported)
    );
    let supported = Proposed {
        control_supported: true,
        ..proposed
    };
    assert_eq!(
        check(Some(&view), &supported, &records, &ledger.facts()),
        Ok(Operation::Amend)
    );
}

// CM-6 CM-7 C-6
#[test]
fn cm_7_an_offer_with_an_agent_side_needs_its_six_fields() {
    let bare = decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(AGENT)), ("acceptor", t(ALICE))],
    );
    assert_eq!(offer_gaps(&bare).len(), 5);
    let ledger = Ledger::new();
    let records = ledger.records();
    let proposed = Proposed {
        id: id(1),
        record: &bare,
        position: 1,
        recorded_at: Time(1000),
        author_actor: ActorType::Human,
        step_up: false,
        access: AccessAnswer::Allow,
        agent_side: true,
        control_supported: false,
    };
    assert_eq!(
        check(None, &proposed, &records, &ledger.facts()),
        Err(Refusal::IncompleteOffer)
    );
    let human = Proposed {
        agent_side: false,
        ..proposed
    };
    assert_eq!(
        check(None, &human, &records, &ledger.facts()),
        Ok(Operation::Request)
    );
    let full = with_body(
        decl(
            ALICE,
            "request",
            None,
            &[("obligor", t(AGENT)), ("acceptor", t(ALICE)), ("due", u(5))],
        ),
        &["purpose", "delivery", "scope", "acceptance_criterion"],
    );
    assert_eq!(offer_gaps(&full).len(), 0);

    let mut undefined = Ledger::new();
    let root = undefined.push(decl(
        ALICE,
        "request",
        None,
        &[("obligor", t(SUPPLIER)), ("acceptor", t(ALICE))],
    ));
    let promise = undefined.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let state = undefined.push(fulfilling(
        decl(SUPPLIER, "state", Some(promise), &[]),
        id(900),
        root,
    ));
    let silent = undefined.push(accept(ALICE, state, state));
    assert_eq!(
        undefined.outcome(root, silent),
        StepOutcome::Refused(Refusal::CriterionUndefined)
    );
    undefined.push(decl(
        ALICE,
        "accept",
        Some(silent),
        &[("statement", d(state)), ("criterion_undefined", yes())],
    ));
    assert_eq!(
        summary(&undefined.view(root)),
        uniform(CommitmentState::Accepted)
    );
}

// CM-9 CM-10 CM-11 CM-12
#[test]
fn cm_9_commitment_types_keep_their_own_rule_on_one_lifecycle() {
    let mut ledger = Ledger::new();
    let follow = request(&mut ledger, &[("commitment_kind", t("follow_up"))]);
    assert_eq!(
        ledger.view(follow).opening,
        StepOutcome::Refused(Refusal::KindRequirement)
    );
    let help = request(&mut ledger, &[("commitment_kind", t("help_request"))]);
    assert_eq!(
        ledger.view(help).opening,
        StepOutcome::Refused(Refusal::KindRequirement)
    );
    let agent_help = ledger.push(decl(
        AGENT,
        "request",
        None,
        &[
            ("obligor", t(ALICE)),
            ("acceptor", t(AGENT)),
            ("commitment_kind", t("help_request")),
        ],
    ));
    let view = ledger.view(agent_help);
    assert_eq!(view.opening, StepOutcome::Refused(Refusal::IncompleteOffer));
    let with_condition = request(
        &mut ledger,
        &[
            ("commitment_kind", t("follow_up")),
            (
                "conditions",
                ParamValue::List(vec![ParamScalar::Digest(id(801).0)]),
            ),
        ],
    );
    assert_eq!(ledger.view(with_condition).opening, StepOutcome::Applied);
}

// CM-46 CM-47 C-28
#[test]
fn cm_46_cm_47_a_sub_commitment_supports_its_parent_and_signals_its_risk() {
    let mut ledger = Ledger::new();
    let parent = request(&mut ledger, &[]);
    let child = ledger.push(supporting(
        decl(
            SUPPLIER,
            "request",
            None,
            &[
                ("obligor", t(CAROL)),
                ("acceptor", t(SUPPLIER)),
                ("commitment_kind", t("sub_commitment")),
            ],
        ),
        parent,
    ));
    let grandchild = ledger.push(supporting(
        decl(
            CAROL,
            "request",
            None,
            &[("obligor", t(BOB)), ("acceptor", t(CAROL))],
        ),
        child,
    ));
    let promise = ledger.push(decl(CAROL, "promise", Some(child), &[]));
    let notice = ledger.push(decl(
        CAROL,
        "notice",
        Some(promise),
        &[("notice_type", t("at_risk"))],
    ));
    let cancel = ledger.push(decl(
        CAROL,
        "cancel",
        Some(notice),
        &[("reason", t("failed"))],
    ));
    let views = ledger.views();
    let parent_view = views.iter().find(|v| v.root == parent).unwrap();
    let signals = support_signals(parent_view, &views);
    let causes: Vec<SupportCause> = signals.iter().map(|s| s.cause).collect();
    assert_eq!(causes, vec![SupportCause::Cancelled, SupportCause::AtRisk]);
    assert_eq!(signals[0].record, cancel);
    assert_eq!(signals[0].notify, Some(party(SUPPLIER)));
    assert_eq!(summary(parent_view), uniform(CommitmentState::Requested));
    assert_eq!(support_chain(&views, grandchild), vec![child, parent]);
}

// CM-54 CM-55
#[test]
fn cm_54_cm_55_aggregation_counts_only_acceptances() {
    use Answer::{Accepted, ClosedWithoutAnswer, Pending, Rejected, TimedOut};
    let policy = |rule: AggregationRule, threshold: u32, veto: bool| AggregationPolicy {
        rule,
        threshold,
        veto,
        participants: vec![party(ALICE), party(BOB), party(CAROL)],
    };
    let all = aggregate(
        &policy(AggregationRule::All, 0, false),
        &[Accepted, Pending, Accepted],
    )
    .unwrap();
    assert_eq!(all.status, AggregateStatus::Pending);
    let all_no = aggregate(
        &policy(AggregationRule::All, 0, false),
        &[Accepted, ClosedWithoutAnswer, Pending],
    )
    .unwrap();
    assert_eq!(all_no.status, AggregateStatus::Unsatisfiable);
    assert_eq!(all_no.to_close, vec![2]);
    let any = aggregate(
        &policy(AggregationRule::Any, 0, false),
        &[Pending, Accepted, Pending],
    )
    .unwrap();
    assert_eq!(any.status, AggregateStatus::Satisfied);
    assert_eq!(any.to_close, vec![0, 2]);
    let k = aggregate(
        &policy(AggregationRule::KOfN, 2, false),
        &[Rejected, TimedOut, Pending],
    )
    .unwrap();
    assert_eq!(k.status, AggregateStatus::Unsatisfiable);
    let percent = policy(AggregationRule::Percentage, 50, false);
    assert_eq!(needed(&percent), Ok(2));
    let seq = aggregate(
        &policy(AggregationRule::Sequential, 0, false),
        &[Accepted, Pending, Pending],
    )
    .unwrap();
    assert_eq!(seq.next, Some(1));
    let veto = aggregate(
        &policy(AggregationRule::Any, 0, true),
        &[Accepted, Rejected, Pending],
    )
    .unwrap();
    assert_eq!(veto.status, AggregateStatus::Unsatisfiable);
    let silent = aggregate(
        &policy(AggregationRule::All, 0, false),
        &[
            ClosedWithoutAnswer,
            ClosedWithoutAnswer,
            ClosedWithoutAnswer,
        ],
    )
    .unwrap();
    assert_ne!(silent.status, AggregateStatus::Satisfied);
    assert!(aggregate(&policy(AggregationRule::All, 0, false), &[Accepted]).is_err());
    assert!(needed(&policy(AggregationRule::KOfN, 4, false)).is_err());
}

// T-89 OP-7 P-88
#[test]
fn t_89_a_commitment_record_touches_its_conflict_area() {
    let mut ledger = Ledger::new();
    let root = request(&mut ledger, &[]);
    let request_record = &ledger.records[0].1;
    let none = |_: &RecordId| -> Option<Area> { None };
    let touches = touched_in(request_record, root, &none);
    assert_eq!(touches.last().unwrap().item, ItemKey::Commitment(root));
    assert_eq!(touches.last().unwrap().expect, Expect::Version(0));
    let promise = decl(SUPPLIER, "promise", Some(root), &[]);
    let area = |_: &RecordId| {
        Some(Area {
            item: ItemKey::Commitment(root),
            version: 1,
            heads: vec![root],
        })
    };
    let touches = touched_in(&promise, id(77), &area);
    let last = touches.last().unwrap();
    assert_eq!(last.expect, Expect::Version(1));
    assert_eq!(last.heads, Some(vec![id(77)]));
    let blind = decl(SUPPLIER, "promise", Some(id(66)), &[]);
    let concurrent = |_: &RecordId| {
        Some(Area {
            item: ItemKey::Commitment(root),
            version: 2,
            heads: vec![id(55)],
        })
    };
    let touches = touched_in(&blind, id(78), &concurrent);
    assert_eq!(touches.last().unwrap().heads, Some(vec![id(55), id(78)]));
}

// CM-25 C-29
#[test]
fn cm_25_one_act_may_fulfil_several_commitments() {
    let mut ledger = Ledger::new();
    let act = id(900);
    let first = request(&mut ledger, &[]);
    let second = request(&mut ledger, &[]);
    let p1 = ledger.push(decl(SUPPLIER, "promise", Some(first), &[]));
    let p2 = ledger.push(decl(SUPPLIER, "promise", Some(second), &[]));
    ledger.push(fulfilling(
        decl(SUPPLIER, "state", Some(p1), &[]),
        act,
        first,
    ));
    ledger.push(fulfilling(
        decl(SUPPLIER, "state", Some(p2), &[]),
        act,
        second,
    ));
    assert_eq!(ledger.view(first).fulfilments, vec![act]);
    assert_eq!(ledger.view(second).fulfilments, vec![act]);
}

fn time_condition(kind: TimeCondition, head: Option<RecordId>) -> Record {
    with_body(
        decl(
            ALICE,
            "open_condition",
            head,
            &[
                ("condition_type", t(kind.uri())),
                ("wait_reason", t("internal")),
                ("address", t(SUPPLIER)),
                ("deadline", t("none")),
                ("criterion", t(&format!("{CORE}criterion/met"))),
            ],
        ),
        &["definition"],
    )
}

fn timed_clock(version: u32, target: Target, duration: u64) -> ClockDefinition {
    let (start, stop) = clock_events(target);
    ClockDefinition {
        version,
        target,
        duration,
        calendar: None,
        warnings: vec![500],
        grace: 0,
        pause: vec![],
        start: start.iter().map(|s| (*s).to_owned()).collect(),
        stop: stop.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn listing(conditions: &[RecordId]) -> ParamValue {
    ParamValue::List(
        conditions
            .iter()
            .map(|c| ParamScalar::Digest(c.0))
            .collect(),
    )
}

fn observation(author: &str, key: &str, value: Vec<u8>, referenced: RecordId) -> Record {
    let mut record = claim(author);
    let core = core_mut(&mut record);
    core.ext = Some(vec![Extension {
        key: ExtKey::parse(key).unwrap(),
        value: ExtValue(value),
    }]);
    core.relations = Some(vec![Relation::References {
        source: None,
        target: ReferenceTarget::Record(referenced),
        qualifier: None,
    }]);
    record
}

fn work_act(author: &str, served: RecordId) -> Record {
    let core = claim(author).core().clone();
    Record::Act(Act {
        subtype: TypeUri::parse(&format!("{CORE}act/work")).unwrap(),
        occurred_at: Time(1),
        core: RecordCore {
            relations: Some(vec![Relation::Serves {
                source: None,
                target: served,
                qualifier: None,
            }]),
            ..core
        },
    })
}

fn timing(
    ledger: &Ledger,
    root: RecordId,
    definitions: &BTreeMap<RecordId, Vec<u8>>,
    now: u64,
) -> TimeProjection {
    let entries = ledger.entries();
    let views = ledger.views();
    let view = views.iter().find(|v| v.root == root).unwrap();
    project_time(
        view,
        &TimeInputs {
            entries: &entries,
            views: &views,
            definitions,
            zones: &[],
            now: Time(now),
        },
    )
}

fn clock_of(projection: &TimeProjection, condition: RecordId) -> ClockView {
    projection
        .clocks
        .iter()
        .find(|p| p.condition == condition)
        .unwrap()
        .view
        .clone()
        .unwrap()
}

// CM-50 CM-51
#[test]
fn cm_50_the_records_of_a_commitment_start_and_stop_its_clocks_by_target() {
    let mut ledger = Ledger::new();
    let mut defs: BTreeMap<RecordId, Vec<u8>> = BTreeMap::new();
    let mut clocks = Vec::new();
    for target in [Target::Response, Target::Start, Target::Finish] {
        let c = ledger.at(time_condition(TimeCondition::Clock, None), 100, false);
        defs.insert(c, timed_clock(1, target, 60_000).encode().unwrap());
        clocks.push(c);
    }
    let root = ledger.at(
        with_body(
            decl(
                ALICE,
                "request",
                None,
                &[
                    ("obligor", t(SUPPLIER)),
                    ("acceptor", t(ALICE)),
                    ("conditions", listing(&clocks)),
                ],
            ),
            &["acceptance_criterion"],
        ),
        1_000,
        false,
    );
    let promise = ledger.at(decl(SUPPLIER, "promise", Some(root), &[]), 11_000, false);
    let act = ledger.at(work_act(SUPPLIER, root), 31_000, false);
    let state = ledger.at(
        fulfilling(decl(SUPPLIER, "state", Some(promise), &[]), act, root),
        41_000,
        false,
    );
    let rejected = ledger.at(
        decl(
            ALICE,
            "reject",
            Some(state),
            &[("statement", d(state)), ("reason", t("incomplete"))],
        ),
        51_000,
        false,
    );
    let projection = timing(&ledger, root, &defs, 200_000);
    assert_eq!(projection.undefined, Vec::<RecordId>::new());
    let response = clock_of(&projection, clocks[0]);
    assert_eq!(response.state, ClockState::Met);
    assert_eq!(response.elapsed, 10_000);
    let start = clock_of(&projection, clocks[1]);
    assert_eq!(start.state, ClockState::Met);
    assert_eq!(start.elapsed, 20_000);
    assert_eq!(ledger.outcome(root, rejected), StepOutcome::Applied);
    let finish = clock_of(&projection, clocks[2]);
    assert_eq!(finish.state, ClockState::Running);
    assert_eq!(finish.elapsed, 189_000);
    assert!(finish.breached.is_some());
    let restated = ledger.at(
        fulfilling(decl(SUPPLIER, "state", Some(rejected), &[]), act, root),
        210_000,
        false,
    );
    ledger.at(accept(ALICE, restated, restated), 220_000, false);
    let finish = clock_of(&timing(&ledger, root, &defs, 300_000), clocks[2]);
    assert_eq!(finish.state, ClockState::Met);
    assert_eq!(finish.met_at, Some(Time(220_000)));
}

// CM-51
#[test]
fn cm_51_a_superseding_condition_redefines_the_clock_forward_only() {
    let mut ledger = Ledger::new();
    let mut defs: BTreeMap<RecordId, Vec<u8>> = BTreeMap::new();
    let c = ledger.at(time_condition(TimeCondition::Clock, None), 100, false);
    defs.insert(c, timed_clock(1, Target::Finish, 100_000).encode().unwrap());
    let root = ledger.at(
        with_body(
            decl(
                ALICE,
                "request",
                None,
                &[
                    ("obligor", t(SUPPLIER)),
                    ("acceptor", t(ALICE)),
                    ("conditions", listing(&[c])),
                ],
            ),
            &["acceptance_criterion"],
        ),
        1_000,
        false,
    );
    ledger.at(decl(SUPPLIER, "promise", Some(root), &[]), 1_000, false);
    let shorter = ledger.at(time_condition(TimeCondition::Clock, Some(c)), 61_000, false);
    defs.insert(
        shorter,
        timed_clock(2, Target::Finish, 50_000).encode().unwrap(),
    );
    let stale = ledger.at(
        time_condition(TimeCondition::Clock, Some(shorter)),
        62_000,
        false,
    );
    defs.insert(
        stale,
        timed_clock(2, Target::Finish, 10_000).encode().unwrap(),
    );
    let other = ledger.at(
        time_condition(TimeCondition::Clock, Some(shorter)),
        63_000,
        false,
    );
    defs.insert(
        other,
        timed_clock(3, Target::Response, 10_000).encode().unwrap(),
    );
    let before = clock_of(&timing(&ledger, root, &defs, 60_000), c);
    assert_eq!(before.version, 1);
    assert_eq!(before.warning, Some(500));
    assert_eq!(before.breached, None);
    let after = timing(&ledger, root, &defs, 70_000);
    let projected = &after.clocks[0];
    assert_eq!(projected.definition, shorter);
    assert_eq!(projected.ignored, vec![stale, other]);
    let clock = projected.view.clone().unwrap();
    assert_eq!(clock.version, 2);
    assert_eq!(clock.breached, Some(Time(61_000)));
    assert_eq!(clock.reached[0].version, 1);
    let decoded = |r: RecordId| Definition::decode(TimeCondition::Clock, &defs[&r]).unwrap();
    assert_eq!(
        decoded(stale).continues(&decoded(shorter)),
        Err(BodyError("version"))
    );
    assert_eq!(
        decoded(other).continues(&decoded(shorter)),
        Err(BodyError("target"))
    );
    let mut wrong = timed_clock(1, Target::Response, 1);
    wrong.stop = vec!["accept".to_owned()];
    assert_eq!(
        Definition::decode(TimeCondition::Clock, &wrong.encode().unwrap()),
        Err(BodyError("stop"))
    );
}

// CM-48 CM-49 CM-63
#[test]
fn cm_48_cm_49_consumption_claims_on_the_budget_condition_exhaust_it_and_hand_the_move_over() {
    let mut ledger = Ledger::new();
    let mut defs: BTreeMap<RecordId, Vec<u8>> = BTreeMap::new();
    let euro = Measure::Money(currency::money("EUR").unwrap());
    let b = ledger.push(time_condition(TimeCondition::Budget, None));
    let budget = Budget {
        measure: euro,
        limit: 10_000,
        warnings: vec![800],
    };
    defs.insert(b, budget.encode().unwrap());
    let root = request(&mut ledger, &[("conditions", listing(&[b]))]);
    ledger.push(decl(SUPPLIER, "promise", Some(root), &[]));
    let spend = |amount: u64| {
        Amount {
            measure: euro,
            amount,
        }
        .encode()
        .unwrap()
    };
    ledger.push(observation(SUPPLIER, CONSUMPTION_EXT_KEY, spend(6_000), b));
    ledger.push(observation(CAROL, CONSUMPTION_EXT_KEY, spend(9_000), b));
    ledger.push(observation(
        SUPPLIER,
        CONSUMPTION_EXT_KEY,
        spend(9_000),
        root,
    ));
    let warned = timing(&ledger, root, &defs, u64::MAX / 4);
    let view = warned.budgets[0].view.unwrap();
    assert_eq!(view.consumed, 6_000);
    assert_eq!(view.ignored, 1);
    assert!(!warned.budget_exhausted());
    ledger.push(observation(SUPPLIER, CONSUMPTION_EXT_KEY, spend(4_000), b));
    let exhausted = timing(&ledger, root, &defs, u64::MAX / 4);
    assert!(exhausted.budget_exhausted());
    assert_eq!(exhausted.budgets[0].view.unwrap().warning, Some(800));
    ledger.budget_exhausted = exhausted.budget_exhausted();
    assert_eq!(
        next_moves(&ledger.view(root), &ledger.facts()),
        vec![Mover::Party(party(SUPPLIER)), Mover::Accountable]
    );
    assert_eq!(
        summary(&ledger.view(root)),
        uniform(CommitmentState::Promised)
    );
}

// CM-53 CM-64
#[test]
fn cm_53_reports_referencing_the_request_meet_the_periodic_update() {
    let berlin = Zone::from_tzif(
        "Europe/Berlin",
        "2026f",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/time/tzif/Europe_Berlin.tzif"
        )),
    )
    .unwrap();
    let mut ledger = Ledger::new();
    let mut defs: BTreeMap<RecordId, Vec<u8>> = BTreeMap::new();
    let day = 86_400_000_u64;
    let nine = 1_793_606_400_000_u64;
    let p = ledger.at(
        time_condition(TimeCondition::Periodic, None),
        nine - 2 * day,
        false,
    );
    let definition = PeriodicDefinition {
        version: 1,
        rule_text: "FREQ=DAILY".to_owned(),
        rule: Rule::parse("FREQ=DAILY").unwrap(),
        dtstart: LocalDateTime::parse_basic("20261102T090000").unwrap(),
        zone: "Europe/Berlin".to_owned(),
        tolerance: 3_600_000,
        schema: None,
    };
    defs.insert(p, definition.encode().unwrap());
    let root = ledger.at(
        with_body(
            decl(
                ALICE,
                "request",
                None,
                &[
                    ("obligor", t(SUPPLIER)),
                    ("acceptor", t(ALICE)),
                    ("commitment_kind", t("periodic_update")),
                    ("conditions", listing(&[p])),
                ],
            ),
            &["acceptance_criterion"],
        ),
        nine - day,
        false,
    );
    ledger.at(
        decl(SUPPLIER, "promise", Some(root), &[]),
        nine - day + 1,
        false,
    );
    let report = |author: &str, parts: &[&str]| {
        with_body(observation(author, REPORT_EXT_KEY, vec![0xa0], root), parts)
    };
    ledger.at(report(SUPPLIER, &REPORT_PARTS), nine + 60_000, false);
    ledger.at(report(SUPPLIER, &["status"]), nine + day, false);
    ledger.at(report(CAROL, &REPORT_PARTS), nine + day + 1, false);
    let entries = ledger.entries();
    let views = ledger.views();
    let view = views.iter().find(|v| v.root == root).unwrap();
    let zones = [berlin];
    let inputs = TimeInputs {
        entries: &entries,
        views: &views,
        definitions: &defs,
        zones: &zones,
        now: Time(nine + 2 * day - 1),
    };
    assert_eq!(zones_named(view, &inputs), vec!["Europe/Berlin".to_owned()]);
    let projection = project_time(view, &inputs);
    let periodic = &projection.periodic[0];
    assert_eq!(periodic.reports, 1);
    assert_eq!(periodic.ignored_reports, 2);
    let projected = periodic.view.clone().unwrap();
    assert_eq!(projected.tzdb, "2026f");
    assert_eq!(projected.due[0].expected, Time(nine));
    assert_eq!(projected.due[0].report, Some(Time(nine + 60_000)));
    assert_eq!(projected.missed, 1);
}

// CM-47 CM-50 CM-53
#[test]
fn cm_47_a_breached_clock_of_a_sub_commitment_signals_its_parent() {
    let mut ledger = Ledger::new();
    let mut defs: BTreeMap<RecordId, Vec<u8>> = BTreeMap::new();
    let parent = request(&mut ledger, &[]);
    let c = ledger.push(time_condition(TimeCondition::Clock, None));
    defs.insert(c, timed_clock(1, Target::Response, 1_500).encode().unwrap());
    let child = ledger.push(supporting(
        decl(
            SUPPLIER,
            "request",
            None,
            &[
                ("obligor", t(CAROL)),
                ("acceptor", t(SUPPLIER)),
                ("commitment_kind", t("sub_commitment")),
                ("conditions", listing(&[c])),
            ],
        ),
        parent,
    ));
    let entries = ledger.entries();
    let views = ledger.views();
    let inputs = |now: u64| TimeInputs {
        entries: &entries,
        views: &views,
        definitions: &defs,
        zones: &[],
        now: Time(now),
    };
    let parent_view = views.iter().find(|v| v.root == parent).unwrap();
    let child_view = views.iter().find(|v| v.root == child).unwrap();
    let opened = entries
        .iter()
        .find(|e| e.id() == child)
        .unwrap()
        .recorded_at()
        .0;
    let warned = project_time(child_view, &inputs(opened + 800));
    let signals = clock_signals(parent_view, &[(child_view, &warned)]);
    assert_eq!(signals[0].cause, SupportCause::ClockWarning);
    let breached = project_time(child_view, &inputs(opened + 1_500));
    let signals = clock_signals(parent_view, &[(child_view, &breached)]);
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].cause, SupportCause::ClockBreach);
    assert_eq!(signals[0].record, c);
    assert_eq!(signals[0].notify, Some(party(SUPPLIER)));
    let position = entries.iter().find(|e| e.id() == c).unwrap().position();
    assert_eq!(
        definition_records(parent_view, &inputs(opened)),
        vec![(c, position)]
    );
    assert_eq!(summary(parent_view), uniform(CommitmentState::Requested));
}
