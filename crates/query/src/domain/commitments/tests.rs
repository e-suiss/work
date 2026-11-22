use work_kernel::commitment::Operation;
use work_kernel::id::Digest;

use super::*;

fn ledger() -> LedgerId {
    LedgerId(Digest::sha256([0x4c; 32]))
}

// E-45 CM-17 C-6
#[test]
fn e_45_every_commitment_operation_a_caller_writes_names_one_action() {
    for op in Operation::CLOSED_SET
        .iter()
        .chain(&[Operation::ImplicitAcceptanceTerms])
    {
        let action = action_of(*op);
        match op {
            Operation::Expire => assert_eq!(action, None),
            Operation::Accept | Operation::Reject => assert_eq!(action, Some("close")),
            Operation::Assign => assert_eq!(action, Some("assign")),
            Operation::AdministrativeClose => assert_eq!(action, Some("administrative_close")),
            Operation::ImplicitAcceptanceTerms => {
                assert_eq!(action, Some("autonomy_policy_set"));
            }
            _ => assert_eq!(action, Some("commit"), "{op:?}"),
        }
    }
}

// P-100 P-11 CM-2
#[test]
fn p_100_a_ledger_folds_only_from_its_own_genesis() {
    assert_eq!(fold(&ledger(), &[]).err(), Some(FoldError::Genesis));
    let stranger = StoredLogEntry {
        pos: 0,
        record_bytes: vec![0xa0],
        envelope_bytes: vec![0xa0],
        cose_sign1: None,
    };
    assert_eq!(
        fold(&ledger(), std::slice::from_ref(&stranger)).err(),
        Some(FoldError::Genesis)
    );
}
