use work_kernel::catalog::DeclarationSubtype;
use work_kernel::commitment::Operation;
use work_kernel::responsibility::ResponsibilityOperation;
use work_proto::action::Action;

use super::*;

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
