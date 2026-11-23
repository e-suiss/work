use work_kernel::commitment::Refusal;
use work_kernel::id::{Digest, PartyRef};

use super::*;

// C-6 CM-17 E-45 P-54
#[test]
fn c_6_every_operation_a_caller_writes_has_one_typed_write_naming_its_action() {
    let doc = crate::openapi::value().unwrap();
    let paths = doc["paths"].as_object().unwrap();
    for op in Operation::CLOSED_SET
        .iter()
        .chain(&[Operation::ImplicitAcceptanceTerms])
    {
        let Some(action) = action_of(*op) else {
            continue;
        };
        let path = if *op == Operation::Request {
            "/v1/ledgers/{ledger}/commitments".to_owned()
        } else {
            format!(
                "/v1/ledgers/{{ledger}}/commitments/{{commitment}}/{}",
                op.wire_name().replace('_', "-")
            )
        };
        let post = &paths[path.as_str()]["post"];
        assert_eq!(post["x-work-action"], format!("work:{action}"), "{path}");
        let headers: Vec<&str> = post["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["in"] == "header")
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(headers.contains(&"Idempotency-Key"), "{path}");
        assert!(headers.contains(&"If-Match"), "{path}");
    }
    assert!(
        !paths.contains_key("/v1/ledgers/{ledger}/commitments/{commitment}/expire"),
        "expire is the Work service's own record"
    );
    assert_eq!(
        paths["/v1/ledgers/{ledger}/commitments/{commitment}"]["get"]["x-work-action"],
        "work:read"
    );
}

// P-55 CM-58 CM-42 CM-15
#[test]
fn p_55_what_a_transition_still_needs_and_the_next_move_are_spelled_by_their_wire_names() {
    let gate = RecordId(Digest::sha256([7; 32]));
    assert_eq!(missing(&Missing::StepUp), "step_up");
    assert_eq!(missing(&Missing::AccessPending), "access_pending");
    assert_eq!(
        missing(&Missing::Gate(gate)),
        format!("gate:{}", gate.to_external())
    );
    let party = PartyRef::new("party:acme:alice").unwrap();
    assert_eq!(
        mover(&Mover::Party(party)),
        MoverAnswer {
            kind: "party".to_owned(),
            id: Some("party:acme:alice".to_owned()),
        }
    );
    assert_eq!(mover(&Mover::Accountable).id, None);
    let blocked = implicit(ImplicitAcceptance::Blocked(Refusal::FourEyes));
    assert_eq!(blocked.status, "blocked");
    assert_eq!(blocked.reason.as_deref(), Some("four_eyes"));
    let waiting = implicit(ImplicitAcceptance::Waiting(Time(0)));
    assert_eq!(waiting.ends_at.as_deref(), Some("1970-01-01T00:00:00.000Z"));
    assert_ne!(
        work_kernel::commitment::CommitmentState::Promised.wire_name(),
        work_kernel::commitment::CommitmentState::Accepted.wire_name()
    );
}

fn breached_clock(condition: RecordId, later: RecordId) -> ClockProjection {
    use work_kernel::clock::{ClockView, Reached};

    ClockProjection {
        condition,
        definition: later,
        target: Target::Finish,
        view: Ok(ClockView {
            state: ClockState::Running,
            version: 2,
            elapsed: 61_000,
            remaining: 0,
            warning: Some(500),
            breached: Some(Time(61_000)),
            reached: vec![
                Reached {
                    tier: Tier::Warning(500),
                    at: Time(51_000),
                    version: 1,
                },
                Reached {
                    tier: Tier::Breach,
                    at: Time(61_000),
                    version: 2,
                },
            ],
            paused_since: None,
            met_at: None,
            refused: Vec::new(),
            next_change: None,
            tzdb: None,
        }),
        ignored: Vec::new(),
    }
}

// CM-50 CM-51 CM-48 CM-49 CM-53 CM-64
#[test]
fn cm_50_clocks_periodic_updates_and_budgets_are_answered_by_their_wire_names() {
    use work_kernel::budget::{Budget, BudgetView, Choice, Decision, Measure};
    use work_kernel::clock::{Due, PeriodicView};
    use work_kernel::currency;

    let condition = RecordId(Digest::sha256([8; 32]));
    let later = RecordId(Digest::sha256([9; 32]));
    let breached = breached_clock(condition, later);
    let answer = clock(&breached);
    assert_eq!(answer.target, "finish");
    assert_eq!(answer.state.as_deref(), Some("running"));
    assert_eq!(answer.definition, later.to_external());
    assert_eq!(
        answer
            .reached
            .iter()
            .map(|r| r.tier.as_str())
            .collect::<Vec<_>>(),
        ["warning", "breach"]
    );
    assert_eq!(answer.reached[0].version, 1);
    assert_eq!(
        answer.breached_at.as_deref(),
        Some("1970-01-01T00:01:01.000Z")
    );
    let refused = clock(&ClockProjection {
        view: Err(ClockError::Version),
        ..breached
    });
    assert_eq!(refused.error.as_deref(), Some("version"));
    assert_eq!(refused.state, None);
    let euro = Measure::Money(currency::money("EUR").unwrap());
    let exhausted = budget(&BudgetProjection {
        condition,
        definition: condition,
        budget: Budget {
            measure: euro,
            limit: 10_000,
            warnings: vec![800],
        },
        view: Ok(BudgetView {
            own: 10_000,
            children: 0,
            consumed: 10_000,
            remaining: 0,
            warning: Some(800),
            exhausted: true,
            decision: Some(Decision {
                choices: Choice::ALL,
            }),
            ignored: 1,
            unmatched: 0,
        }),
        ignored: Vec::new(),
    });
    assert_eq!(exhausted.measure, "money");
    assert_eq!(exhausted.currency.as_deref(), Some("EUR"));
    assert!(exhausted.exhausted);
    assert_eq!(exhausted.decision, ["continue", "reshape", "drop"]);
    let missed = periodic(&PeriodicProjection {
        condition,
        definition: condition,
        view: Ok(PeriodicView {
            due: vec![Due {
                expected: Time(0),
                deadline: Time(1_000),
                report: None,
                missed: true,
            }],
            missed: 1,
            next_deadline: None,
            tzdb: "2026f".to_owned(),
        }),
        reports: 0,
        ignored_reports: 2,
        ignored: Vec::new(),
    });
    assert_eq!(missed.missed, 1);
    assert!(missed.due[0].missed);
    assert_eq!(missed.ignored_reports, 2);
}
