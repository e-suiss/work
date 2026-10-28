use crate::env::{Env, L, fails, hex, run, with_ledgers};

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
