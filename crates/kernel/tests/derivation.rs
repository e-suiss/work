//! The derivation skeleton: supersession, retroactivity, eligibility, conflict, divergence and ordering errors.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod fixtures;

use fixtures::*;
use work_kernel::derive::{
    Admission, Agreement, AuthorityIssuer, BusinessCalendar, ChainStatus, Derivation,
    DerivationInputs, DeriveError, Effect, Entry, Ingest, NoEffect, ProfileVersion, Restriction,
    TrustInputs, compare, derive,
};
use work_kernel::id::{PartyRef, RecordId, Time};
use work_kernel::reason::Reason;
use work_kernel::record::{
    Param, ParamScalar, ParamValue, PartName, ProtocolVersion, Record, RecordCore,
};
use work_kernel::relation::Relation;
use work_kernel::rules::RuleSet;

const BOB: &str = "party:acme:bob";
const PEER: &str = "party:peer:access";

fn op(author: &str, name: &str, supersedes: Option<RecordId>, basis: &[RecordId]) -> Record {
    let mut b = basis.to_vec();
    b.sort();
    declaration(
        &format!("{CORE}declaration/{name}"),
        RecordCore {
            capacity: Some(work_kernel::record::Capacity::Own),
            basis: Some(b),
            relations: supersedes.map(|target| {
                vec![Relation::Supersedes {
                    target,
                    qualifier: None,
                }]
            }),
            authority: Some(authority(0x90)),
            ..core(author)
        },
    )
}

fn superseding(author: &str, targets: &[RecordId], basis: &[RecordId]) -> Record {
    let mut record = op(author, "amend", None, basis);
    core_mut(&mut record).relations = Some(
        targets
            .iter()
            .map(|&target| Relation::Supersedes {
                target,
                qualifier: None,
            })
            .collect(),
    );
    record
}

fn at_protocol(mut record: Record, major: u64, minor: u64) -> Record {
    core_mut(&mut record).versions.protocol = ProtocolVersion { major, minor };
    record
}

fn effective(mut record: Record, at: u64) -> Record {
    core_mut(&mut record).params = Some(vec![Param {
        name: PartName::parse("effective_at").unwrap(),
        value: ParamValue::Scalar(ParamScalar::Uint(at)),
    }]);
    record
}

fn entries(records: &[(RecordId, Record)]) -> Vec<Entry<'_>> {
    records
        .iter()
        .zip(100_u64..)
        .map(|((id, record), position)| Entry {
            id: *id,
            record,
            position,
            recorded_at: Time(position * 1000),
            ingest: Ingest::Admitted,
            restriction: Restriction::NoObjection,
            issuer: AuthorityIssuer::Local,
        })
        .collect()
}

fn inputs(trusted: &[PartyRef]) -> DerivationInputs<'_> {
    DerivationInputs {
        protocol: ProtocolVersion { major: 1, minor: 0 },
        profile: ProfileVersion(1),
        practices: &[],
        trust: TrustInputs {
            trusted_publishers: trusted,
        },
        ledger_time: Time(1_000_000),
        calendar: BusinessCalendar::Continuous,
    }
}

fn run(entries: &[Entry<'_>]) -> Derivation {
    derive(entries, &inputs(&[])).unwrap()
}

// P-24 INV-2 C-33
#[test]
fn p_24_superseded_record_is_marked_never_removed() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
        (rid(3), op(ALICE, "amend", Some(rid(2)), &[rid(2)])),
    ];
    let d = run(&entries(&records));
    assert_eq!(d.records.len(), 3);
    assert_eq!(d.records[0].superseded_by, vec![rid(2)]);
    assert_eq!(d.records[1].superseded_by, vec![rid(3)]);
    assert!(d.records.iter().all(|r| r.admission == Admission::Admitted));
    assert_eq!(d.chains.len(), 1);
    assert_eq!(d.chains[0].heads, vec![rid(3)]);
    assert_eq!(d.chains[0].version, 2);
}

// P-24 P-74
#[test]
fn p_74_same_author_same_chain_same_version_is_rejected() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
        (rid(3), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
    ];
    let d = run(&entries(&records));
    assert_eq!(
        d.records[2].admission,
        Admission::Rejected(Reason::DuplicateVersion)
    );
    assert_eq!(d.records[0].superseded_by, vec![rid(2)]);
    assert_eq!(d.chains[0].heads, vec![rid(2)]);
}

// P-28 P-74
#[test]
fn p_28_p_74_concurrent_transitions_by_different_authors_conflict() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
        (rid(3), op(BOB, "amend", Some(rid(1)), &[rid(1)])),
    ];
    let d = run(&entries(&records));
    assert_eq!(d.records[1].effect, Effect::Normative);
    assert_eq!(d.records[2].admission, Admission::Admitted);
    assert_eq!(d.records[2].effect, Effect::Conflicted);
    assert_eq!(d.chains[0].status, ChainStatus::Conflicted);
    assert_eq!(d.chains[0].heads, vec![rid(2), rid(3)]);
    assert_eq!(d.records[0].superseded_by, vec![rid(2), rid(3)]);
}

// P-28
#[test]
fn p_28_resolution_citing_both_heads_closes_the_conflict() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
        (rid(3), op(BOB, "amend", Some(rid(1)), &[rid(1)])),
        (rid(4), op(BOB, "amend", Some(rid(3)), &[rid(3)])),
        (
            rid(5),
            op(
                ALICE,
                "conflict_resolution",
                Some(rid(2)),
                &[rid(2), rid(3)],
            ),
        ),
    ];
    let d = run(&entries(&records));
    assert_eq!(d.records[3].effect, Effect::None(NoEffect::Conflicted));
    assert_eq!(d.records[4].effect, Effect::Normative);
    assert_eq!(d.chains[0].status, ChainStatus::Open);
    assert_eq!(d.chains[0].heads, vec![rid(5)]);
}

// P-28
#[test]
fn p_28_a_transition_that_saw_the_head_does_not_conflict() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
        (rid(3), op(BOB, "amend", Some(rid(1)), &[rid(1), rid(2)])),
    ];
    let d = run(&entries(&records));
    assert_eq!(d.records[2].effect, Effect::Normative);
    assert_eq!(d.chains[0].status, ChainStatus::Open);
    assert_eq!(d.chains[0].heads, vec![rid(3)]);
}

// P-24 CM-34
#[test]
fn p_24_terminal_outcome_never_changes() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "cancel", Some(rid(1)), &[rid(1)])),
        (rid(3), op(ALICE, "amend", Some(rid(2)), &[rid(2)])),
    ];
    let d = run(&entries(&records));
    assert_eq!(d.chains[0].status, ChainStatus::Terminal);
    assert_eq!(d.records[2].admission, Admission::Admitted);
    assert_eq!(d.records[2].effect, Effect::None(NoEffect::TerminalOutcome));
    assert_eq!(d.chains[0].heads, vec![rid(2)]);
}

// INV-4 P-24
#[test]
fn inv_4_retroactive_declaration_is_rejected() {
    let records = [(rid(1), effective(op(ALICE, "promise", None, &[]), 99_999))];
    let d = run(&entries(&records));
    assert_eq!(
        d.records[0].admission,
        Admission::Rejected(Reason::RetroactiveDeclaration)
    );
    assert_eq!(d.chains, vec![]);
    let records = [(rid(1), effective(op(ALICE, "promise", None, &[]), 100_000))];
    assert_eq!(run(&entries(&records)).records[0].effect, Effect::Normative);
}

// INV-9 C-15 C-16 C-14 SEC-31
#[test]
fn inv_9_claims_and_acts_never_change_normative_state() {
    let mut claim = observation();
    let mut act = delivery();
    for r in [&mut claim, &mut act] {
        let c = core_mut(r);
        c.relations = Some(vec![Relation::Supersedes {
            target: rid(1),
            qualifier: None,
        }]);
        c.basis = Some(vec![rid(1)]);
    }
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), claim),
        (rid(3), act),
    ];
    let d = run(&entries(&records));
    assert_eq!(d.records[1].effect, Effect::None(NoEffect::NotADeclaration));
    assert_eq!(d.records[2].effect, Effect::None(NoEffect::NotADeclaration));
    assert_eq!(d.chains[0].heads, vec![rid(1)]);
    assert_eq!(d.chains[0].status, ChainStatus::Open);
    assert_eq!(d.records[0].superseded_by, vec![rid(2), rid(3)]);
}

// T-23 T-4
#[test]
fn t_23_restriction_results_gate_normative_effect() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
        (rid(3), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
    ];
    let mut e = entries(&records[..2]);
    e[1].restriction = Restriction::Deny;
    let d = run(&e);
    assert_eq!(d.records[1].effect, Effect::None(NoEffect::Denied));
    assert_eq!(d.chains[0].heads, vec![rid(1)]);
    e[1].restriction = Restriction::Require;
    let d = run(&e);
    assert_eq!(
        d.records[1].effect,
        Effect::None(NoEffect::RequirementPending)
    );
}

// T-6 P-31
#[test]
fn t_6_different_trust_inputs_diverge_explicitly() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(BOB, "accept", Some(rid(1)), &[rid(1)])),
    ];
    let mut e = entries(&records);
    e[1].issuer = AuthorityIssuer::Federated(party(PEER));
    let trusted = [party(PEER)];
    let with = derive(&e, &inputs(&trusted)).unwrap();
    let without = derive(&e, &inputs(&[])).unwrap();
    assert_eq!(with.records[1].effect, Effect::Normative);
    assert_eq!(
        without.records[1].effect,
        Effect::None(NoEffect::UntrustedAuthority)
    );
    assert_eq!(compare(&with, &without), Agreement::Diverged(vec![rid(2)]));
    assert_eq!(compare(&with, &with.clone()), Agreement::Same);
}

// INV-7 P-31 T-6
#[test]
fn inv_7_same_inputs_give_the_same_result() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
        (rid(3), op(BOB, "amend", Some(rid(1)), &[rid(1)])),
    ];
    let e = entries(&records);
    assert_eq!(run(&e), run(&e));
}

// P-27 T-6
#[test]
fn p_27_ledger_time_input_decides_pending_effect() {
    let records = [(
        rid(1),
        effective(op(ALICE, "promise", None, &[]), 2_000_000),
    )];
    let e = entries(&records);
    let early = derive(&e, &inputs(&[])).unwrap();
    assert_eq!(
        early.records[0].effect,
        Effect::None(NoEffect::NotYetEffective)
    );
    let mut later = inputs(&[]);
    later.ledger_time = Time(2_000_000);
    assert_eq!(
        derive(&e, &later).unwrap().records[0].effect,
        Effect::Normative
    );
}

// P-19
#[test]
fn p_19_quarantined_record_has_no_effect() {
    let records = [(rid(1), op(ALICE, "promise", None, &[]))];
    let mut e = entries(&records);
    e[0].ingest = Ingest::Quarantined(Reason::ExtensionCriticalUnknown);
    let d = run(&e);
    assert_eq!(
        d.records[0].admission,
        Admission::Quarantined(Reason::ExtensionCriticalUnknown)
    );
    assert_eq!(d.records[0].effect, Effect::None(NoEffect::NotAdmitted));
}

// P-24
#[test]
fn p_24_superseding_an_unknown_record_has_no_effect() {
    let records = [(rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)]))];
    let d = run(&entries(&records));
    assert_eq!(d.records[0].effect, Effect::None(NoEffect::UnknownTarget));
}

// T-4
#[test]
fn t_4_position_overflow_is_a_typed_error() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
    ];
    let mut e = entries(&records);
    e[0].position = u64::MAX;
    e[1].position = 0;
    assert_eq!(derive(&e, &inputs(&[])), Err(DeriveError::Overflow));
}

// P-11 P-27
#[test]
fn p_11_ledger_order_violations_are_errors() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
    ];
    let mut e = entries(&records);
    e[1].position = 105;
    assert_eq!(
        derive(&e, &inputs(&[])),
        Err(DeriveError::PositionGap { position: 105 })
    );
    let mut e = entries(&records);
    e[1].recorded_at = Time(0);
    assert_eq!(
        derive(&e, &inputs(&[])),
        Err(DeriveError::RecordedAtOutOfOrder { position: 101 })
    );
    let dup = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(1), op(ALICE, "promise", None, &[])),
    ];
    assert_eq!(
        derive(&entries(&dup), &inputs(&[])),
        Err(DeriveError::DuplicateRecord(rid(1)))
    );
}

// P-86 P-24 P-74
#[test]
fn p_86_version_is_one_more_than_the_highest_superseded_version_in_the_chain() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
        (rid(3), superseding(ALICE, &[rid(1), rid(2)], &[rid(2)])),
    ];
    let d = run(&entries(&records));
    assert_eq!(d.records[2].admission, Admission::Admitted);
    assert_eq!(d.records[2].effect, Effect::Normative);
    assert_eq!(d.chains.len(), 1);
    assert_eq!(d.chains[0].version, 2);
    assert_eq!(d.chains[0].heads, vec![rid(3)]);
}

// P-86 P-74
#[test]
fn p_86_a_target_in_another_chain_does_not_raise_the_version() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(BOB, "promise", None, &[])),
        (rid(3), op(BOB, "amend", Some(rid(2)), &[rid(2)])),
        (rid(4), superseding(ALICE, &[rid(1), rid(3)], &[rid(1)])),
        (rid(5), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
    ];
    let d = run(&entries(&records));
    assert_eq!(d.records[3].admission, Admission::Admitted);
    assert_eq!(
        d.records[4].admission,
        Admission::Rejected(Reason::DuplicateVersion)
    );
    assert_eq!(d.chains[0].version, 1);
    assert_eq!(d.chains[1].version, 1);
}

// T-4 P-87 P-19
#[test]
fn t_4_p_87_unknown_protocol_version_is_quarantined_in_derivation() {
    for (major, minor) in [(2, 0), (1, 1), (0, 9)] {
        let records = [(
            rid(1),
            at_protocol(op(ALICE, "promise", None, &[]), major, minor),
        )];
        let d = run(&entries(&records));
        assert_eq!(
            d.records[0].admission,
            Admission::Quarantined(Reason::ProtocolVersionUnknown)
        );
        assert_eq!(d.records[0].effect, Effect::None(NoEffect::NotAdmitted));
        assert_eq!(d.chains.len(), 0);
    }
}

// T-4 P-87 OP-28
#[test]
fn t_4_p_87_record_newer_than_the_active_protocol_has_no_effect() {
    let records = [(rid(1), op(ALICE, "promise", None, &[]))];
    let e = entries(&records);
    let mut older = inputs(&[]);
    older.protocol = ProtocolVersion { major: 0, minor: 9 };
    let d = derive(&e, &older).unwrap();
    assert_eq!(d.records[0].admission, Admission::Admitted);
    assert_eq!(d.records[0].effect, Effect::None(NoEffect::ProtocolVersion));
}

// T-4 P-87
#[test]
fn t_4_p_87_older_record_keeps_its_own_rules_under_a_newer_active_protocol() {
    let records = [
        (rid(1), op(ALICE, "promise", None, &[])),
        (rid(2), op(ALICE, "amend", Some(rid(1)), &[rid(1)])),
    ];
    let e = entries(&records);
    let mut newer = inputs(&[]);
    newer.protocol = ProtocolVersion { major: 2, minor: 0 };
    let d = derive(&e, &newer).unwrap();
    assert_eq!(d, run(&e));
    assert_eq!(d.records[1].effect, Effect::Normative);
    assert!(
        records
            .iter()
            .all(|(_, r)| RuleSet::of(r) == Some(RuleSet::V1_0))
    );
}
