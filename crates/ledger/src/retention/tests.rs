use suiss_retention::{Basis, HoldId, HoldKind, HoldScope, Period, Retain};
use work_store::RetentionClass;

use super::*;

const DAY: u64 = 86_400_000;
const RECORDED: u64 = 1_792_749_600_123;

fn tenant() -> TenantId {
    TenantId::new("tnt_acme")
}

fn dek(class: RetentionClass) -> ClassDek {
    ClassDek {
        dek_id: "01890a5d-ac96-774b-bcce-b302099a8057".to_owned(),
        subject: "party:acme:alice".to_owned(),
        class,
        newest_ms: Some(RECORDED),
    }
}

fn at(days: u64) -> Timestamp {
    Timestamp::from_unix_millis(RECORDED.saturating_add(days.saturating_mul(DAY)))
}

fn fresh(now: Timestamp, schedules: Vec<Schedule>) -> PolicySnapshot {
    PolicySnapshot {
        tenant: tenant(),
        taken_at: Timestamp::from_unix_millis(now.unix_millis().saturating_sub(3_600_000)),
        schedules,
    }
}

fn kept_for(class: Class, days: u32) -> Schedule {
    Schedule {
        tenant: tenant(),
        class,
        basis: Basis::new("test"),
        length: Length::For(Period::Days(days)),
        start: Event::Recorded,
        max: None,
        version: PolicyVersion::new(7),
    }
}

fn hold(id: &str, scope: HoldScope, until: Option<Timestamp>) -> Hold {
    Hold {
        id: HoldId::new(id),
        tenant: tenant(),
        scope,
        placed_at: Timestamp::from_unix_millis(RECORDED),
        until,
        kind: HoldKind::Litigation,
        suspicious_activity: false,
    }
}

// OP-14 OP-30 Access OP-147
#[test]
fn op_14_without_an_access_snapshot_nothing_is_destroyed() {
    for class in RetentionClass::ALL {
        for days in [0, 1, 401, 36_500] {
            assert_eq!(
                retention_decision(&tenant(), &dek(class), None, &[], at(days)),
                Decision::Defer(Defer::NoSnapshot),
                "{class:?} after {days} days"
            );
        }
    }
}

// OP-14 OP-30
#[test]
fn op_14_the_four_work_classes_take_the_work_default_and_the_others_have_none() {
    for class in RetentionClass::ALL {
        let c = class.class();
        assert_eq!(
            schedules_for(&tenant(), c, None),
            vec![Schedule::work_default(tenant(), c, PolicyVersion::new(0)).unwrap()]
        );
        assert!(
            schedules_for(&tenant(), c, None)
                .iter()
                .all(|s| s.max.is_none())
        );
    }
    for c in [
        Class::Audit,
        Class::Traffic,
        Class::DsrLog,
        Class::ErasureLog,
    ] {
        assert_eq!(schedules_for(&tenant(), c, None), Vec::new());
        let snapshot = fresh(at(0), vec![kept_for(c, 30)]);
        assert_eq!(
            schedules_for(&tenant(), c, Some(&snapshot)),
            vec![kept_for(c, 30)]
        );
    }
    let snapshot = fresh(at(0), vec![kept_for(Class::AgentTrace, 30)]);
    assert_eq!(
        schedules_for(&tenant(), Class::AgentTrace, Some(&snapshot)),
        vec![kept_for(Class::AgentTrace, 30)]
    );
    assert_eq!(
        schedules_for(&tenant(), Class::WorkRecord, Some(&snapshot)),
        vec![Schedule::work_default(tenant(), Class::WorkRecord, PolicyVersion::new(0)).unwrap()]
    );
}

// OP-14 OP-30 Access OP-147
#[test]
fn op_14_a_fresh_snapshot_destroys_an_agent_trace_dek_only_after_400_days() {
    let trace = dek(RetentionClass::AgentTrace);
    let early = at(399);
    assert!(matches!(
        retention_decision(&tenant(), &trace, Some(&fresh(early, vec![])), &[], early),
        Decision::Retain(Retain::Running { until }) if until == at(400)
    ));
    let late = at(400);
    assert_eq!(
        retention_decision(&tenant(), &trace, Some(&fresh(late, vec![])), &[], late),
        Decision::Destroy
    );
}

// OP-14 OP-30 Access OP-147
#[test]
fn op_14_events_work_cannot_see_defer() {
    let now = at(36_500);
    let snapshot = fresh(now, vec![]);
    for class in [
        RetentionClass::WorkRecord,
        RetentionClass::WorkEvidence,
        RetentionClass::WorkDraft,
    ] {
        assert_eq!(
            retention_decision(&tenant(), &dek(class), Some(&snapshot), &[], now),
            Decision::Defer(Defer::UnknownEnd),
            "{class:?}"
        );
    }
    let mut unrecorded = dek(RetentionClass::AgentTrace);
    unrecorded.newest_ms = None;
    assert_eq!(
        retention_decision(&tenant(), &unrecorded, Some(&snapshot), &[], now),
        Decision::Defer(Defer::UnknownStart)
    );
    let mut closing = kept_for(Class::AgentTrace, 1);
    closing.start = Event::ContractEnded;
    assert_eq!(
        retention_decision(
            &tenant(),
            &dek(RetentionClass::AgentTrace),
            Some(&fresh(now, vec![closing])),
            &[],
            now
        ),
        Decision::Defer(Defer::UnknownStart)
    );
}

// OP-14 Access OP-147
#[test]
fn op_14_a_stale_foreign_or_future_snapshot_defers() {
    let trace = dek(RetentionClass::AgentTrace);
    let now = at(1_000);
    let mut stale = fresh(now, vec![]);
    stale.taken_at = Timestamp::from_unix_millis(now.unix_millis().saturating_sub(DAY));
    assert_eq!(
        retention_decision(&tenant(), &trace, Some(&stale), &[], now),
        Decision::Defer(Defer::StaleSnapshot)
    );
    let mut foreign = fresh(now, vec![]);
    foreign.tenant = TenantId::new("tnt_other");
    assert_eq!(
        retention_decision(&tenant(), &trace, Some(&foreign), &[], now),
        Decision::Defer(Defer::NoSnapshot)
    );
    let mut ahead = fresh(now, vec![]);
    ahead.taken_at = Timestamp::from_unix_millis(now.unix_millis().saturating_add(1));
    assert_eq!(
        retention_decision(&tenant(), &trace, Some(&ahead), &[], now),
        Decision::Defer(Defer::NoSnapshot)
    );
    let mut misfiled = kept_for(Class::AgentTrace, 1);
    misfiled.tenant = TenantId::new("tnt_other");
    assert_eq!(
        retention_decision(
            &tenant(),
            &trace,
            Some(&fresh(now, vec![misfiled])),
            &[],
            now
        ),
        Decision::Defer(Defer::Mismatch)
    );
}

// OP-14 OP-12 Access OP-74 Access OP-147
#[test]
fn op_14_a_cached_access_hold_retains_until_it_ends() {
    let trace = dek(RetentionClass::AgentTrace);
    let now = at(1_000);
    let snapshot = fresh(now, vec![]);
    let decide =
        |holds: &[Hold]| retention_decision(&tenant(), &trace, Some(&snapshot), holds, now);
    for scope in [
        HoldScope::Subject(SubjectId::new("party:acme:alice")),
        HoldScope::Classes(vec![Class::AgentTrace]),
        HoldScope::Tenant,
    ] {
        assert_eq!(
            decide(&[hold("hld_1", scope.clone(), None)]),
            Decision::Retain(Retain::Held(HoldId::new("hld_1")))
        );
        assert_eq!(
            decide(&[hold("hld_1", scope.clone(), Some(at(1_001)))]),
            Decision::Retain(Retain::Held(HoldId::new("hld_1")))
        );
        assert_eq!(
            decide(&[hold("hld_1", scope, Some(at(999)))]),
            Decision::Destroy
        );
    }
    assert_eq!(
        decide(&[hold(
            "hld_2",
            HoldScope::Subject(SubjectId::new("party:acme:bob")),
            None
        )]),
        Decision::Destroy
    );
    assert_eq!(
        decide(&[hold(
            "hld_3",
            HoldScope::Classes(vec![Class::WorkRecord]),
            None
        )]),
        Decision::Destroy
    );
    assert_eq!(
        decide(&[hold("hld_4", HoldScope::Classes(vec![]), Some(at(1)))]),
        Decision::Defer(Defer::MalformedHold(HoldId::new("hld_4")))
    );
}

// OP-14 Access OP-147
#[test]
fn op_14_every_schedule_of_the_class_must_destroy() {
    let trace = dek(RetentionClass::AgentTrace);
    let now = at(20);
    let both = fresh(
        now,
        vec![
            kept_for(Class::AgentTrace, 10),
            kept_for(Class::AgentTrace, 30),
        ],
    );
    assert!(matches!(
        retention_decision(&tenant(), &trace, Some(&both), &[], now),
        Decision::Retain(Retain::Running { until }) if until == at(30)
    ));
    let shorter = fresh(now, vec![kept_for(Class::AgentTrace, 10)]);
    assert_eq!(
        retention_decision(&tenant(), &trace, Some(&shorter), &[], now),
        Decision::Destroy
    );
}
