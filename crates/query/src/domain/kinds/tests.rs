#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use work_kernel::catalog::DeclarationSubtype;
use work_kernel::codec::{Decoded, decode_record};
use work_kernel::commitment::Operation;
use work_kernel::record::{ExtValue, Extension};
use work_kernel::responsibility::ResponsibilityOperation;
use work_kernel::uri::TypeUri;
use work_proto::action::Action;

use super::*;

const RECORDS: &str = include_str!("../../../../../conformance/vectors/records/records.json");

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn acknowledgement(ext: Option<(&str, Value)>) -> Record {
    let records: serde_json::Value = serde_json::from_str(RECORDS).unwrap();
    let hex = records["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "record/declaration-promise-for-principal")
        .unwrap()["hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let Decoded::Record(record) = decode_record(&unhex(&hex)).unwrap() else {
        panic!("a record");
    };
    let Record::Declaration(mut d) = *record else {
        panic!("a Declaration");
    };
    d.subtype = TypeUri::parse("https://suiss.app/ns/work/declaration/acknowledgement").unwrap();
    d.core.params = None;
    d.core.ext = ext.map(|(key, value)| {
        vec![Extension {
            key: TypeUri::parse(key).unwrap(),
            value: ExtValue(dcbor::encode(&value, Limits::CEILING).unwrap()),
        }]
    });
    Record::Declaration(d)
}

fn decision(entries: &[(&str, &str)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| (Value::text(k), Value::text(v)))
            .collect(),
    )
}

const AGENT: &str = "agt_01jc8z3k5m7p9r1t3v5x7z9b2d";

// E-23 E-45
#[test]
fn e_23_an_acknowledgement_carrying_a_ceiling_decision_takes_work_agent_ceiling_decide() {
    for choice in CeilingChoice::ALL {
        let record = acknowledgement(Some((
            CEILING_EXT_KEY,
            decision(&[
                ("decision", choice.wire_name()),
                ("event", "evt_1"),
                ("agent", AGENT),
            ]),
        )));
        assert_eq!(
            ceiling_decision(&record),
            Some(CeilingDecision {
                decision: choice,
                event: "evt_1".to_owned(),
                agent: AGENT.to_owned(),
            })
        );
        assert_eq!(record_action(&record), Some(CEILING_ACTION));
    }
    assert!(known(CEILING_ACTION));
}

// E-23 E-45 RC-31
#[test]
fn e_23_a_plain_or_malformed_acknowledgement_still_takes_work_condition() {
    let plain = acknowledgement(None);
    assert_eq!(ceiling_decision(&plain), None);
    assert_eq!(record_action(&plain), Some("condition"));
    let long = "e".repeat(MAX_CEILING_EVENT.saturating_add(1));
    for body in [
        decision(&[("decision", "pause"), ("event", "evt_1"), ("agent", AGENT)]),
        decision(&[("decision", "stop"), ("agent", AGENT)]),
        decision(&[
            ("decision", "stop"),
            ("event", "evt_1"),
            ("agent", AGENT),
            ("why", "x"),
        ]),
        decision(&[("decision", "stop"), ("event", ""), ("agent", AGENT)]),
        decision(&[("decision", "stop"), ("event", &long), ("agent", AGENT)]),
        Value::text("stop"),
    ] {
        let record = acknowledgement(Some((CEILING_EXT_KEY, body)));
        assert_eq!(ceiling_decision(&record), None);
        assert_eq!(record_action(&record), Some("condition"));
    }
    let elsewhere = acknowledgement(Some((
        "https://suiss.app/ns/work/agent-ceiling-decision/2",
        decision(&[("decision", "stop"), ("event", "evt_1"), ("agent", AGENT)]),
    )));
    assert_eq!(record_action(&elsewhere), Some("condition"));
}

fn known(action: &str) -> bool {
    Action::parse(&format!("work:{action}")).is_some()
}

// E-45 RC-17
#[test]
fn e_45_every_responsibility_operation_takes_work_claim_or_work_assign() {
    for op in ResponsibilityOperation::ALL {
        let action = responsibility_action(*op);
        let expected = match op {
            ResponsibilityOperation::Claim
            | ResponsibilityOperation::Unclaim
            | ResponsibilityOperation::RenewLease => "claim",
            _ => "assign",
        };
        assert_eq!(action, expected, "{op:?}");
        assert!(known(action), "{op:?}");
    }
}

// E-45 RC-48 RC-36 RC-33 RC-31
#[test]
fn e_45_every_core_declaration_a_caller_writes_names_one_catalog_action() {
    for subtype in DeclarationSubtype::ALL {
        if Operation::of(*subtype).is_some() || ResponsibilityOperation::of(*subtype).is_some() {
            continue;
        }
        match declaration_action(*subtype) {
            Some(action) => assert!(known(action), "{subtype:?} {action}"),
            None => assert!(
                matches!(subtype, DeclarationSubtype::GateDecision),
                "{subtype:?}"
            ),
        }
    }
    assert_eq!(
        declaration_action(DeclarationSubtype::OrgRule),
        Some("org_rule_set")
    );
    assert_eq!(
        declaration_action(DeclarationSubtype::StopResponse),
        Some("stop_respond")
    );
    assert_eq!(
        declaration_action(DeclarationSubtype::ControlLease),
        Some("control")
    );
    assert_eq!(
        declaration_action(DeclarationSubtype::QueueDefinition),
        Some("assign")
    );
}

// RC-42 RC-43 RC-37
#[test]
fn rc_42_the_executor_claims_are_distinct_extension_keys() {
    for (i, key) in EXECUTOR_EXT_KEYS.iter().enumerate() {
        assert!(
            key.starts_with("https://suiss.app/ns/work/executor."),
            "{key}"
        );
        assert!(
            EXECUTOR_EXT_KEYS
                .iter()
                .skip(i.saturating_add(1))
                .all(|k| k != key),
            "{key}"
        );
    }
}
