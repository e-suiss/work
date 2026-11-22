//! The commitment time and money bodies against their vectors in `conformance/vectors/time`, and the rule tests of the budget (CM-48, CM-49, E-35), the clock (CM-50, CM-51, CM-52) and the periodic update (CM-53) over the vendored tzdb zones.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "test code"
)]

use serde_json::Value;
use work_kernel::budget::{
    AccessLimit, Amount, Budget, BudgetError, Choice, Consumption, Measure, Operation, Side,
};
use work_kernel::calendar::{
    Counting, Date, Interval, LocalDateTime, WorkCalendar, days_from_civil,
};
use work_kernel::clock::{
    ClockDefinition, ClockError, ClockEvent, ClockState, PauseCondition, PauseRefusal,
    PeriodicDefinition, Reached, Role, Target, Tier, Timed, Wait, project,
};
use work_kernel::commitment_time::{BodyError, CDDL, CONTRACT};
use work_kernel::currency::{self, CurrencyError, LIST_ONE_PUBLISHED};
use work_kernel::id::{PartyRef, Time};
use work_kernel::rrule::{Rule, RuleError};
use work_kernel::tz::Zone;

const BODIES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/time/bodies.json"
));
const TZ: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/time/tz.json"
));
const RRULE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/time/rrule.json"
));
const SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/cddl/work-commitment-time.cddl"
));
const BERLIN: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/time/tzif/Europe_Berlin.tzif"
));
const NEW_YORK: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/time/tzif/America_New_York.tzif"
));
const ISTANBUL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/time/tzif/Europe_Istanbul.tzif"
));
const SYDNEY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/time/tzif/Australia_Sydney.tzif"
));

const TZDB: &str = "2026f";
const HOUR: u64 = 3_600_000;

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn zone(name: &str) -> Zone {
    let bytes = match name {
        "Europe/Berlin" => BERLIN,
        "America/New_York" => NEW_YORK,
        "Europe/Istanbul" => ISTANBUL,
        "Australia/Sydney" => SYDNEY,
        _ => panic!("no fixture for {name}"),
    };
    Zone::from_tzif(name, TZDB, bytes).unwrap()
}

fn zones() -> Vec<Zone> {
    [
        "Europe/Berlin",
        "America/New_York",
        "Europe/Istanbul",
        "Australia/Sydney",
    ]
    .iter()
    .map(|n| zone(n))
    .collect()
}

fn utc(y: i32, mo: u8, d: u8, h: u64, mi: u64) -> Time {
    let days = u64::try_from(days_from_civil(y, mo, d).unwrap()).unwrap();
    Time((days * 86_400 + h * 3_600 + mi * 60) * 1_000)
}

fn istanbul(y: i32, mo: u8, d: u8, h: u64, mi: u64) -> Time {
    Time(utc(y, mo, d, h, mi).0 - 3 * HOUR)
}

fn party(name: &str) -> PartyRef {
    PartyRef::new(name).unwrap()
}

fn body_cases(roots: &[&str]) -> Vec<Value> {
    let v: Value = serde_json::from_str(BODIES).unwrap();
    assert_eq!(v["contract"], CONTRACT);
    assert_eq!(CDDL, SCHEMA);
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| roots.contains(&c["root"].as_str().unwrap()))
        .cloned()
        .collect()
}

fn check_body<T>(
    case: &Value,
    decode: fn(&[u8]) -> Result<T, BodyError>,
    encode: fn(&T) -> Result<Vec<u8>, BodyError>,
) {
    let id = case["id"].as_str().unwrap();
    let bytes = unhex(case["cbor"].as_str().unwrap());
    match decode(&bytes) {
        Ok(body) => {
            assert!(case["valid"] == true, "{id}: accepted");
            assert_eq!(encode(&body).unwrap(), bytes, "{id}");
        }
        Err(BodyError(member)) => {
            assert!(case["valid"] == false, "{id}: refused {member}");
            assert_eq!(member, case["refused"].as_str().unwrap(), "{id}");
        }
    }
}

// CM-48 CM-49 E-35
#[test]
fn cm_48_budget_and_consumption_bodies_match_their_vectors() {
    let cases = body_cases(&["budget", "consumption"]);
    assert!(cases.iter().any(|c| c["valid"] == true));
    assert!(cases.iter().any(|c| c["valid"] == false));
    for case in &cases {
        if case["root"] == "budget" {
            check_body(case, Budget::decode, Budget::encode);
        } else {
            check_body(case, Amount::decode, Amount::encode);
        }
    }
}

// CM-48
#[test]
fn cm_48_money_takes_a_list_one_currency_with_a_minor_unit_and_no_fund() {
    assert_eq!(LIST_ONE_PUBLISHED, "2026-09-17");
    assert_eq!(currency::money("EUR").unwrap().minor_units(), Some(2));
    assert_eq!(currency::money("JPY").unwrap().minor_units(), Some(0));
    assert_eq!(currency::money("TRY").unwrap().numeric(), 949);
    for code in [
        "XAU", "XAG", "XPT", "XPD", "XDR", "XTS", "XXX", "XBA", "XSU", "XUA",
    ] {
        assert_eq!(
            currency::money(code),
            Err(CurrencyError::NoMinorUnit),
            "{code}"
        );
        assert!(currency::lookup(code).is_some(), "{code}");
    }
    for code in ["BOV", "CLF", "COU", "MXV", "USN", "UYI", "CHE", "CHW"] {
        assert_eq!(currency::money(code), Err(CurrencyError::Fund), "{code}");
        assert!(currency::lookup(code).unwrap().is_fund(), "{code}");
    }
    assert_eq!(currency::money("eur"), Err(CurrencyError::Unknown));
    assert_eq!(currency::money("ABC"), Err(CurrencyError::Unknown));
}

fn euro() -> Measure {
    Measure::Money(currency::money("EUR").unwrap())
}

fn money(amount: u64) -> Amount {
    Amount {
        measure: euro(),
        amount,
    }
}

fn euro_budget(limit: u64) -> Budget {
    Budget {
        measure: euro(),
        limit,
        warnings: vec![500, 800],
    }
}

// CM-48 E-35
#[test]
fn cm_48_consumption_comes_from_executor_claims_and_children_roll_up() {
    let executor = party("party:acme:runner");
    let other = party("party:acme:bystander");
    let budget = euro_budget(1_000);
    let usd = Amount {
        measure: Measure::Money(currency::money("USD").unwrap()),
        amount: 50,
    };
    let claims = [
        Consumption {
            source: &executor,
            amount: money(300),
        },
        Consumption {
            source: &other,
            amount: money(5_000),
        },
        Consumption {
            source: &executor,
            amount: usd,
        },
        Consumption {
            source: &executor,
            amount: money(150),
        },
    ];
    let effort = Amount {
        measure: Measure::Effort,
        amount: 7,
    };
    let view = budget
        .evaluate(
            core::slice::from_ref(&executor),
            &claims,
            &[money(200), effort],
        )
        .unwrap();
    assert_eq!(view.own, 450);
    assert_eq!(view.children, 200);
    assert_eq!(view.consumed, 650);
    assert_eq!(view.remaining, 350);
    assert_eq!(view.warning, Some(500));
    assert!(!view.exhausted);
    assert_eq!(view.decision, None);
    assert_eq!(view.ignored, 2);
    assert_eq!(view.unmatched, 1);
    let total = budget
        .total(core::slice::from_ref(&executor), &claims, &[money(200)])
        .unwrap();
    assert_eq!(total, money(650));
    let nobody = budget.evaluate(&[], &claims, &[]).unwrap();
    assert_eq!(nobody.consumed, 0);
    assert_eq!(nobody.ignored, 4);
}

// CM-48
#[test]
fn cm_48_consumption_overflow_is_a_typed_error() {
    let executor = party("party:acme:runner");
    let budget = euro_budget(1_000);
    let claims = [
        Consumption {
            source: &executor,
            amount: money(u64::MAX),
        },
        Consumption {
            source: &executor,
            amount: money(1),
        },
    ];
    assert_eq!(
        budget.evaluate(core::slice::from_ref(&executor), &claims, &[]),
        Err(BudgetError::Overflow)
    );
    assert_eq!(
        budget.evaluate(&[], &[], &[money(u64::MAX), money(1)]),
        Err(BudgetError::Overflow)
    );
    let full = Budget {
        measure: Measure::Tokens,
        limit: u64::MAX,
        warnings: vec![999],
    };
    let tokens = Amount {
        measure: Measure::Tokens,
        amount: u64::MAX,
    };
    let view = full.evaluate(&[], &[], &[tokens]).unwrap();
    assert!(view.exhausted);
    assert_eq!(view.warning, Some(999));
}

// CM-49 E-35
#[test]
fn cm_49_an_exhausted_budget_asks_the_accountable_party_and_changes_nothing() {
    let executor = party("party:acme:runner");
    let budget = euro_budget(1_000);
    let before = budget.clone();
    let claims = [Consumption {
        source: &executor,
        amount: money(1_000),
    }];
    let view = budget
        .evaluate(core::slice::from_ref(&executor), &claims, &[])
        .unwrap();
    assert!(view.exhausted);
    assert_eq!(view.remaining, 0);
    assert_eq!(view.warning, Some(800));
    let decision = view.decision.unwrap();
    assert_eq!(
        decision.choices,
        [Choice::Continue, Choice::Reshape, Choice::Drop]
    );
    assert_eq!(budget, before);
    assert_eq!(Choice::Continue.operation(Side::Creditor), Operation::Amend);
    assert_eq!(Choice::Reshape.operation(Side::Obligor), Operation::Amend);
    assert_eq!(Choice::Drop.operation(Side::Creditor), Operation::Release);
    assert_eq!(Choice::Drop.operation(Side::Obligor), Operation::Cancel);
    let over = [Consumption {
        source: &executor,
        amount: money(4_000),
    }];
    let again = budget
        .evaluate(core::slice::from_ref(&executor), &over, &[])
        .unwrap();
    assert_eq!(again.consumed, 4_000);
    assert_eq!(again.decision, view.decision);
    assert_eq!(budget, before);
}

// CM-49
#[test]
fn cm_49_a_budget_never_widens_the_access_limit() {
    let budget = euro_budget(1_000);
    let limit = |measure, limit| AccessLimit { measure, limit };
    assert_eq!(budget.within_access_limits(&[]), Ok(()));
    assert_eq!(budget.within_access_limits(&[limit(euro(), 1_000)]), Ok(()));
    assert_eq!(
        budget.within_access_limits(&[limit(euro(), 999)]),
        Err(BudgetError::WidensAccessLimit)
    );
    let usd = Measure::Money(currency::money("USD").unwrap());
    assert_eq!(
        budget.within_access_limits(&[limit(usd, 1_000_000)]),
        Err(BudgetError::IncomparableAccessLimit)
    );
    assert_eq!(
        budget.within_access_limits(&[limit(Measure::Tokens, 1)]),
        Ok(())
    );
    let tokens = Budget {
        measure: Measure::Tokens,
        limit: 100,
        warnings: Vec::new(),
    };
    assert_eq!(
        tokens.within_access_limits(&[limit(Measure::Tokens, 50)]),
        Err(BudgetError::WidensAccessLimit)
    );
    let effort = Budget {
        measure: Measure::Effort,
        limit: u64::MAX,
        warnings: Vec::new(),
    };
    assert_eq!(effort.within_access_limits(&[limit(euro(), 1)]), Ok(()));
}

// CM-50 CM-51 CM-52
#[test]
fn cm_50_clock_and_periodic_bodies_match_their_vectors() {
    let cases = body_cases(&["clock", "periodic"]);
    assert!(cases.iter().any(|c| c["valid"] == true));
    assert!(cases.iter().any(|c| c["valid"] == false));
    for case in &cases {
        if case["root"] == "clock" {
            check_body(case, ClockDefinition::decode, ClockDefinition::encode);
        } else {
            check_body(case, PeriodicDefinition::decode, PeriodicDefinition::encode);
        }
    }
}

// CM-50
#[test]
fn cm_50_zone_offsets_and_local_times_match_tzdb() {
    let v: Value = serde_json::from_str(TZ).unwrap();
    assert_eq!(v["tzdb"], TZDB);
    for case in v["offsets"].as_array().unwrap() {
        let z = zone(case["zone"].as_str().unwrap());
        let t = case["utc_ms"].as_i64().unwrap() / 1_000;
        assert_eq!(
            i64::from(z.offset_at(t).unwrap()),
            case["offset_s"].as_i64().unwrap(),
            "{case}"
        );
    }
    for case in v["to_utc"].as_array().unwrap() {
        let z = zone(case["zone"].as_str().unwrap());
        let local = LocalDateTime::parse_basic(case["local"].as_str().unwrap()).unwrap();
        let at = z.instant(local).unwrap();
        assert_eq!(at.0, case["utc_ms"].as_u64().unwrap(), "{case}");
        if case["kind"] != "gap" {
            assert_eq!(z.local(at).unwrap(), local, "{case}");
        }
    }
}

// CM-50
#[test]
fn cm_50_zone_data_outside_tzif_version_2_is_refused() {
    let mut v1 = ISTANBUL.to_vec();
    v1[4] = 0;
    assert!(Zone::from_tzif("Europe/Istanbul", TZDB, &v1).is_err());
    assert!(Zone::from_tzif("Europe/Istanbul", TZDB, &ISTANBUL[..ISTANBUL.len() - 2]).is_err());
    assert!(Zone::from_tzif("Europe/Istanbul", TZDB, b"TZjf").is_err());
    assert!(Zone::from_tzif("", TZDB, ISTANBUL).is_err());
    assert!(Zone::from_tzif("Europe/Istanbul", "", ISTANBUL).is_err());
    let z = zone("Europe/Istanbul");
    assert_eq!(z.name(), "Europe/Istanbul");
    assert_eq!(z.version(), TZDB);
}

fn working_week() -> WorkCalendar {
    let day = vec![
        Interval {
            start: 540,
            end: 720,
        },
        Interval {
            start: 780,
            end: 1_080,
        },
    ];
    WorkCalendar {
        zone: "Europe/Istanbul".to_owned(),
        week: [
            day.clone(),
            day.clone(),
            day.clone(),
            day.clone(),
            day,
            Vec::new(),
            Vec::new(),
        ],
        holidays: vec![Date::new(2026, 10, 29).unwrap()],
    }
}

fn clock(duration: u64, calendar: Option<WorkCalendar>) -> ClockDefinition {
    ClockDefinition {
        version: 1,
        target: Target::Finish,
        duration,
        calendar,
        warnings: vec![500],
        grace: 0,
        pause: vec![PauseCondition {
            reason: "recipient_absent".to_owned(),
            awaited: Role::Creditor,
        }],
        start: vec!["promise".to_owned()],
        stop: vec!["state".to_owned()],
    }
}

// CM-50
#[test]
fn cm_50_a_business_calendar_counts_working_intervals_and_skips_holidays() {
    let zs = zones();
    let calendar = working_week();
    let counting = Counting::of(Some(&calendar), &zs).unwrap();
    assert_eq!(counting.zone().unwrap().version(), TZDB);
    let wednesday = istanbul(2026, 10, 28, 9, 0);
    assert_eq!(
        counting.advance(wednesday, 16 * HOUR).unwrap(),
        istanbul(2026, 10, 30, 18, 0)
    );
    let friday = istanbul(2026, 10, 30, 13, 0);
    assert_eq!(
        counting.advance(friday, 8 * HOUR).unwrap(),
        istanbul(2026, 11, 2, 12, 0)
    );
    assert_eq!(
        counting
            .elapsed(friday, istanbul(2026, 11, 2, 12, 0))
            .unwrap(),
        8 * HOUR
    );
    assert_eq!(
        counting
            .elapsed(istanbul(2026, 10, 31, 0, 0), istanbul(2026, 11, 2, 0, 0))
            .unwrap(),
        0
    );
    let mut nowhere = calendar.clone();
    nowhere.zone = "Mars/Olympus".to_owned();
    assert!(Counting::of(Some(&nowhere), &zs).is_err());
    let start = clock(16 * HOUR, Some(calendar));
    let view = project(
        &start,
        &[Timed {
            at: wednesday,
            event: ClockEvent::Started,
        }],
        &zs,
        istanbul(2026, 11, 2, 9, 0),
    )
    .unwrap();
    assert_eq!(view.breached, Some(istanbul(2026, 10, 30, 18, 0)));
    assert_eq!(view.tzdb.as_deref(), Some(TZDB));
}

// CM-50 CM-51
#[test]
fn cm_50_working_time_advance_and_count_agree() {
    let zs = zones();
    let calendar = working_week();
    let counting = Counting::of(Some(&calendar), &zs).unwrap();
    let mut seed: u64 = 0x5eed_c10c;
    for _ in 0..200 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let from = Time(istanbul(2026, 10, 1, 0, 0).0 + (seed >> 20) % (60 * 24 * HOUR));
        let amount = (seed >> 7) % (40 * HOUR);
        let at = counting.advance(from, amount).unwrap();
        assert!(at >= from);
        assert_eq!(
            counting.elapsed(from, at).unwrap(),
            amount,
            "{from:?} {amount}"
        );
        assert_eq!(
            Counting::Continuous.elapsed(from, Counting::Continuous.advance(from, amount).unwrap()),
            Ok(amount)
        );
    }
}

fn started(at: Time) -> Timed<'static> {
    Timed {
        at,
        event: ClockEvent::Started,
    }
}

// CM-51
#[test]
fn cm_51_the_clock_is_recomputed_from_history_at_any_time() {
    let zs = zones();
    let def = clock(16 * HOUR, Some(working_week()));
    let events = [started(istanbul(2026, 11, 2, 9, 0))];
    let now = istanbul(2026, 11, 3, 12, 0);
    let view = project(&def, &events, &zs, now).unwrap();
    assert_eq!(view, project(&def, &events, &zs, now).unwrap());
    assert_eq!(view.state, ClockState::Running);
    assert_eq!(view.elapsed, 11 * HOUR);
    assert_eq!(view.remaining, 5 * HOUR);
    assert_eq!(view.warning, Some(500));
    assert_eq!(
        view.reached,
        [Reached {
            tier: Tier::Warning(500),
            at: istanbul(2026, 11, 2, 18, 0),
            version: 1,
        }]
    );
    assert_eq!(view.breached, None);
    assert_eq!(view.next_change, Some(istanbul(2026, 11, 3, 18, 0)));
    let earlier = project(&def, &events, &zs, istanbul(2026, 11, 2, 15, 0)).unwrap();
    assert_eq!(earlier.elapsed, 5 * HOUR);
    assert_eq!(earlier.warning, None);
    assert_eq!(earlier.next_change, Some(istanbul(2026, 11, 2, 18, 0)));
    let met = [
        started(istanbul(2026, 11, 2, 9, 0)),
        Timed {
            at: istanbul(2026, 11, 2, 10, 0),
            event: ClockEvent::Stopped,
        },
    ];
    let done = project(&def, &met, &zs, istanbul(2026, 12, 1, 9, 0)).unwrap();
    assert_eq!(done.state, ClockState::Met);
    assert_eq!(done.elapsed, HOUR);
    assert_eq!(done.met_at, Some(istanbul(2026, 11, 2, 10, 0)));
    assert_eq!(done.next_change, None);
    let late = [
        Timed {
            at: istanbul(2026, 11, 2, 10, 0),
            event: ClockEvent::Stopped,
        },
        started(istanbul(2026, 11, 2, 9, 0)),
    ];
    assert_eq!(project(&def, &late, &zs, now), Err(ClockError::Order));
    let future = project(&def, &events, &zs, istanbul(2026, 11, 1, 9, 0)).unwrap();
    assert_eq!(future.state, ClockState::NotStarted);
}

// CM-51
#[test]
fn cm_51_a_redefinition_applies_forward_without_rewriting_reached_tiers() {
    let zs = zones();
    let monday = utc(2026, 11, 2, 9, 0);
    let first = clock(4 * HOUR, None);
    let mut longer = clock(8 * HOUR, None);
    longer.version = 2;
    let events = [
        started(monday),
        Timed {
            at: utc(2026, 11, 2, 12, 0),
            event: ClockEvent::Redefined(&longer),
        },
    ];
    let view = project(&first, &events, &zs, utc(2026, 11, 2, 14, 0)).unwrap();
    assert_eq!(view.version, 2);
    assert_eq!(view.elapsed, 5 * HOUR);
    assert_eq!(view.remaining, 3 * HOUR);
    assert_eq!(view.breached, None);
    assert_eq!(view.tzdb, None);
    assert_eq!(
        view.reached,
        [Reached {
            tier: Tier::Warning(500),
            at: utc(2026, 11, 2, 11, 0),
            version: 1,
        }]
    );
    let mut shorter = clock(2 * HOUR, None);
    shorter.version = 3;
    let cut = [
        started(monday),
        Timed {
            at: utc(2026, 11, 2, 12, 0),
            event: ClockEvent::Redefined(&shorter),
        },
    ];
    let view = project(&first, &cut, &zs, utc(2026, 11, 2, 14, 0)).unwrap();
    assert_eq!(view.breached, Some(utc(2026, 11, 2, 12, 0)));
    assert_eq!(
        view.reached.last(),
        Some(&Reached {
            tier: Tier::Breach,
            at: utc(2026, 11, 2, 12, 0),
            version: 3,
        })
    );
    let same = [
        started(monday),
        Timed {
            at: utc(2026, 11, 2, 12, 0),
            event: ClockEvent::Redefined(&first),
        },
    ];
    assert_eq!(
        project(&first, &same, &zs, utc(2026, 11, 2, 14, 0)),
        Err(ClockError::Version)
    );
}

// CM-52
#[test]
fn cm_52_only_a_declared_wait_on_an_addressed_party_pauses_the_clock() {
    let zs = zones();
    let def = clock(16 * HOUR, Some(working_week()));
    let creditor = party("party:acme:buyer");
    let obligor = party("party:acme:courier");
    let wait = Wait {
        reason: "recipient_absent",
        awaited: Some(&creditor),
        awaited_role: Some(Role::Creditor),
        author: &obligor,
        subject: "delivery address",
    };
    let events = [
        started(istanbul(2026, 11, 2, 9, 0)),
        Timed {
            at: istanbul(2026, 11, 2, 11, 0),
            event: ClockEvent::WaitOpened(wait),
        },
        Timed {
            at: istanbul(2026, 11, 3, 11, 0),
            event: ClockEvent::WaitClosed,
        },
    ];
    let paused = project(&def, &events, &zs, istanbul(2026, 11, 2, 15, 0)).unwrap();
    assert_eq!(paused.state, ClockState::Paused);
    assert_eq!(paused.paused_since, Some(istanbul(2026, 11, 2, 11, 0)));
    assert_eq!(paused.elapsed, 2 * HOUR);
    assert_eq!(paused.next_change, None);
    let resumed = project(&def, &events, &zs, istanbul(2026, 11, 3, 12, 0)).unwrap();
    assert_eq!(resumed.state, ClockState::Running);
    assert_eq!(resumed.paused_since, None);
    assert_eq!(resumed.elapsed, 3 * HOUR);
    assert!(resumed.refused.is_empty());
}

// CM-52
#[test]
fn cm_52_an_undeclared_unaddressed_or_one_sided_wait_does_not_pause() {
    let zs = zones();
    let def = clock(16 * HOUR, Some(working_week()));
    let creditor = party("party:acme:buyer");
    let obligor = party("party:acme:courier");
    let valid = Wait {
        reason: "recipient_absent",
        awaited: Some(&creditor),
        awaited_role: Some(Role::Creditor),
        author: &obligor,
        subject: "delivery address",
    };
    let cases = [
        (
            Wait {
                reason: "waiting_on_supplier",
                ..valid
            },
            PauseRefusal::Undeclared,
        ),
        (
            Wait {
                awaited_role: Some(Role::Obligor),
                ..valid
            },
            PauseRefusal::Undeclared,
        ),
        (
            Wait {
                awaited: None,
                ..valid
            },
            PauseRefusal::Unaddressed,
        ),
        (
            Wait {
                awaited: Some(&obligor),
                ..valid
            },
            PauseRefusal::SelfAddressed,
        ),
        (
            Wait {
                subject: "",
                ..valid
            },
            PauseRefusal::NoSubject,
        ),
    ];
    let opened = istanbul(2026, 11, 2, 11, 0);
    for (wait, refusal) in cases {
        let events = [
            started(istanbul(2026, 11, 2, 9, 0)),
            Timed {
                at: opened,
                event: ClockEvent::WaitOpened(wait),
            },
        ];
        let view = project(&def, &events, &zs, istanbul(2026, 11, 2, 15, 0)).unwrap();
        assert_eq!(view.state, ClockState::Running, "{refusal:?}");
        assert_eq!(view.elapsed, 5 * HOUR, "{refusal:?}");
        assert_eq!(view.refused, [(opened, refusal)]);
    }
}

// CM-52
#[test]
fn cm_52_muting_the_attention_item_never_pauses_the_clock() {
    let zs = zones();
    let def = clock(16 * HOUR, Some(working_week()));
    let events = [
        started(istanbul(2026, 11, 2, 9, 0)),
        Timed {
            at: istanbul(2026, 11, 2, 10, 0),
            event: ClockEvent::Muted,
        },
    ];
    let view = project(&def, &events, &zs, istanbul(2026, 11, 3, 18, 0)).unwrap();
    assert_eq!(view.state, ClockState::Running);
    assert_eq!(view.paused_since, None);
    assert_eq!(view.elapsed, 16 * HOUR);
    assert_eq!(view.breached, Some(istanbul(2026, 11, 3, 18, 0)));
}

// CM-53
#[test]
fn cm_53_recurrence_rules_match_their_vectors() {
    let v: Value = serde_json::from_str(RRULE).unwrap();
    assert_eq!(v["tzdb"], TZDB);
    for case in v["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let text = case["rule"].as_str().unwrap();
        if let Some(part) = case["refused"].as_str() {
            assert_eq!(
                Rule::parse(text).err().map(|RuleError(p)| p),
                Some(part),
                "{id}"
            );
            continue;
        }
        let rule = Rule::parse(text).unwrap_or_else(|e| panic!("{id}: {e}"));
        let start = LocalDateTime::parse_basic(case["dtstart"].as_str().unwrap()).unwrap();
        let z = zone(case["zone"].as_str().unwrap());
        let from = Time(case["from_ms"].as_u64().unwrap_or(0));
        let to = Time(case["to_ms"].as_u64().unwrap_or(u64::MAX));
        let got: Vec<u64> = rule
            .occurrences(start, &z, from, to, 100)
            .unwrap_or_else(|e| panic!("{id}: {e}"))
            .iter()
            .map(|t| t.0)
            .collect();
        let want: Vec<u64> = case["expect"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_u64().unwrap())
            .collect();
        assert_eq!(got, want, "{id}");
    }
}

// CM-53
#[test]
fn cm_53_a_report_missing_beyond_the_tolerance_is_a_breach_signal() {
    let zs = zones();
    let def = PeriodicDefinition {
        version: 1,
        rule_text: "FREQ=WEEKLY;BYDAY=MO;BYHOUR=9;BYMINUTE=0".to_owned(),
        rule: Rule::parse("FREQ=WEEKLY;BYDAY=MO;BYHOUR=9;BYMINUTE=0").unwrap(),
        dtstart: LocalDateTime::parse_basic("20261102T090000").unwrap(),
        zone: "Europe/Istanbul".to_owned(),
        tolerance: HOUR,
        schema: None,
    };
    let reports = [
        istanbul(2026, 11, 16, 8, 15),
        istanbul(2026, 11, 2, 9, 30),
        istanbul(2026, 11, 9, 12, 0),
    ];
    let opened = istanbul(2026, 11, 1, 0, 0);
    let now = istanbul(2026, 11, 23, 9, 30);
    let view = def.project(&zs, &reports, opened, None, now, 64).unwrap();
    let expected: Vec<Time> = view.due.iter().map(|d| d.expected).collect();
    assert_eq!(
        expected,
        [
            istanbul(2026, 11, 2, 9, 0),
            istanbul(2026, 11, 9, 9, 0),
            istanbul(2026, 11, 16, 9, 0),
            istanbul(2026, 11, 23, 9, 0),
        ]
    );
    let met: Vec<Option<Time>> = view.due.iter().map(|d| d.report).collect();
    assert_eq!(
        met,
        [
            Some(istanbul(2026, 11, 2, 9, 30)),
            None,
            Some(istanbul(2026, 11, 16, 8, 15)),
            None,
        ]
    );
    let missed: Vec<bool> = view.due.iter().map(|d| d.missed).collect();
    assert_eq!(missed, [false, true, false, false]);
    assert_eq!(view.missed, 1);
    assert_eq!(view.next_deadline, Some(istanbul(2026, 11, 23, 10, 0)));
    assert_eq!(view.tzdb, TZDB);
    let closed = def
        .project(
            &zs,
            &reports,
            opened,
            Some(istanbul(2026, 11, 20, 0, 0)),
            now,
            64,
        )
        .unwrap();
    assert_eq!(closed.due.len(), 3);
    assert_eq!(closed.next_deadline, None);
    let quiet = def
        .project(&zs, &[], opened, None, istanbul(2026, 11, 3, 0, 0), 64)
        .unwrap();
    assert_eq!(quiet.missed, 1);
    assert_eq!(quiet.next_deadline, Some(istanbul(2026, 11, 9, 10, 0)));
    assert_eq!(
        def.project(&zs, &[], opened, None, now, 2),
        Err(ClockError::Overflow)
    );
}
