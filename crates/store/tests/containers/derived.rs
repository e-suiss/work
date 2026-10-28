use work_store::{LedgerId, LedgerTx, PointerKey};

use crate::env::{Env, L, M, fails, hex, run, with_ledgers};

// T-15 OP-11 OP-12 T-12 T-14 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_15_timers_settle_once_and_only_the_reconciler_dequeues() {
    let env = Env::start().await;
    let l = hex(&L);
    let deriver = env.derived("work_deriver");
    let reconciler = env.derived("work_reconciler");
    run(
        &deriver,
        &l,
        &[&with_ledgers(
            "INSERT INTO derived.timer_v1 (ledger_id, family, timer_kind, item_kind, item_id, basis_pos, due_at, state)
             VALUES (decode('{L}', 'hex'), 'commitment_clock', 'deadline_breach', 'commitment', decode(repeat('01', 32), 'hex'),
                     0, '2026-10-24T17:00:00Z', 'pending');
             INSERT INTO derived.reconcile_queue (ledger_id, key_kind, key_id, cause)
             VALUES (decode('{L}', 'hex'), 'commitment', decode(repeat('01', 32), 'hex'), 'timer_due');
             INSERT INTO derived.projection_watermark (ledger_id, projection, version, state, applied_through_pos)
             VALUES (decode('{L}', 'hex'), 'timer', 1, 'building', -1);
             UPDATE derived.projection_watermark SET state = 'live', applied_through_pos = 0;",
        )],
    )
    .await;
    run(
        &reconciler,
        &l,
        &[
            "UPDATE derived.timer_v1 SET state = 'fired', settled_at = now()",
            "DELETE FROM derived.reconcile_queue",
        ],
    )
    .await;
    fails(
        &reconciler,
        &l,
        &["UPDATE derived.timer_v1 SET state = 'pending', settled_at = NULL"],
        Some("23514"),
    )
    .await;
    fails(
        &reconciler,
        &l,
        &["DELETE FROM derived.timer_v1"],
        Some("42501"),
    )
    .await;
    fails(
        &reconciler,
        &l,
        &["TRUNCATE derived.reconcile_queue"],
        Some("42501"),
    )
    .await;
    fails(
        &env.derived("work_app"),
        &l,
        &["DELETE FROM derived.reconcile_queue"],
        Some("42501"),
    )
    .await;
    fails(
        &deriver,
        &l,
        &["DELETE FROM derived.reconcile_queue"],
        Some("42501"),
    )
    .await;
    fails(
        &deriver,
        &l,
        &["UPDATE derived.projection_watermark SET state = 'building'"],
        Some("23514"),
    )
    .await;
    fails(
        &deriver,
        &l,
        &["UPDATE derived.projection_watermark SET applied_through_pos = -1"],
        Some("23514"),
    )
    .await;
    fails(
        &deriver,
        &l,
        &["UPDATE derived.reconcile_queue SET cause = 'full_scan'"],
        Some("42501"),
    )
    .await;
}

// OP-39 T-21 T-14 T-36 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_39_the_consumer_cursor_moves_forward_in_place() {
    let env = Env::start().await;
    let ledger = LedgerId::from_bytes(L);
    let deriver = env.derived("work_deriver");
    let key = |pos: u64, id: &str| PointerKey {
        pos,
        event_id: id.to_owned(),
    };
    let mut tx = LedgerTx::begin(&deriver, &ledger).await.unwrap();
    assert_eq!(tx.consumer_cursor("derive").await.unwrap(), None);
    assert!(
        tx.advance_consumer_cursor("derive", &key(1, "evt-1"))
            .await
            .unwrap()
    );
    assert!(
        tx.advance_consumer_cursor("derive", &key(1, "evt-2"))
            .await
            .unwrap()
    );
    assert!(
        !tx.advance_consumer_cursor("derive", &key(1, "evt-1"))
            .await
            .unwrap()
    );
    assert!(
        !tx.advance_consumer_cursor("derive", &key(0, "evt-9"))
            .await
            .unwrap()
    );
    assert!(
        !tx.advance_consumer_cursor("derive", &key(1, "evt-2"))
            .await
            .unwrap()
    );
    assert!(
        tx.advance_consumer_cursor("audit", &key(0, "evt-0"))
            .await
            .unwrap()
    );
    assert_eq!(
        tx.consumer_cursor("derive").await.unwrap(),
        Some(key(1, "evt-2"))
    );
    tx.commit().await.unwrap();
    let mut rolled = LedgerTx::begin(&deriver, &ledger).await.unwrap();
    assert!(
        rolled
            .advance_consumer_cursor("derive", &key(5, "evt-5"))
            .await
            .unwrap()
    );
    rolled.rollback().await.unwrap();
    let mut tx = LedgerTx::begin(&deriver, &ledger).await.unwrap();
    assert_eq!(
        tx.consumer_cursor("derive").await.unwrap(),
        Some(key(1, "evt-2"))
    );
    assert!(
        tx.advance_consumer_cursor("Derive", &key(2, "evt-3"))
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut other = LedgerTx::begin(&deriver, &LedgerId::from_bytes(M))
        .await
        .unwrap();
    assert_eq!(other.consumer_cursor("derive").await.unwrap(), None);
    other.rollback().await.unwrap();
}

// OP-39 T-36 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_39_only_the_deriver_writes_cursors_and_no_role_deletes_them() {
    let env = Env::start().await;
    let l = hex(&L);
    let deriver = env.derived("work_deriver");
    let mut tx = LedgerTx::begin(&deriver, &LedgerId::from_bytes(L))
        .await
        .unwrap();
    for (group, id) in [("derive", "evt-2"), ("audit", "evt-0")] {
        let to = PointerKey {
            pos: 1,
            event_id: id.to_owned(),
        };
        assert!(tx.advance_consumer_cursor(group, &to).await.unwrap());
    }
    tx.commit().await.unwrap();
    fails(
        &deriver,
        &l,
        &["UPDATE derived.consumer_cursor SET pos = 0"],
        Some("23514"),
    )
    .await;
    fails(
        &deriver,
        &l,
        &["UPDATE derived.consumer_cursor SET consumer_group = 'x'"],
        Some("42501"),
    )
    .await;
    for role in ["work_deriver", "work_reconciler", "work_owner"] {
        fails(
            &env.derived(role),
            &l,
            &["DELETE FROM derived.consumer_cursor"],
            Some("42501"),
        )
        .await;
        fails(
            &env.derived(role),
            &l,
            &["TRUNCATE derived.consumer_cursor"],
            Some("42501"),
        )
        .await;
    }
    for role in ["work_app", "work_reconciler"] {
        fails(
            &env.derived(role),
            &l,
            &["SELECT count(*) FROM derived.consumer_cursor"],
            Some("42501"),
        )
        .await;
    }
}
