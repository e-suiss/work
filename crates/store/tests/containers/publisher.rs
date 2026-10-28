use work_store::{Cluster, LedgerId, PointerKey, PublisherPool, StoreError};

use crate::canonical::seeded;
use crate::env::{Env, L, M, fails, hex, run, scalar};

const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

async fn with_second_ledger() -> (Env, String, String) {
    let (env, l) = seeded().await;
    let m = hex(&M);
    let stmts = [
        "INSERT INTO ledger.head (ledger_id, pos, epoch) VALUES (ledger.current_ledger_id(), -1, 0)".to_owned(),
        "INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes, envelope_bytes) \
         VALUES (ledger.current_ledger_id(), 0, 0, decode(repeat('04', 32), 'hex'), '2026-10-23T11:00:00.000Z', \
         decode(repeat('00', 32), 'hex'), decode(repeat('21', 32), 'hex'), '\\xd2', '\\xa0')".to_owned(),
        format!(
            "INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent) \
             VALUES (ledger.current_ledger_id(), 0, 'evt-m0', 'work.opened', '{TRACE}')"
        ),
        "UPDATE ledger.head SET pos = 0, head_leaf = decode(repeat('21', 32), 'hex'), \
         head_recorded_at = '2026-10-23T11:00:00.000Z' \
         WHERE ledger_id = ledger.current_ledger_id() AND pos = -1 AND epoch = 0".to_owned(),
    ];
    let refs: Vec<&str> = stmts.iter().map(String::as_str).collect();
    run(&env.canonical("work_sequencer"), &m, &refs).await;
    (env, l, m)
}

// T-80 OP-34 T-17 T-13
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_80_outbox_ledgers_lists_only_ledgers_with_pending_pointers_in_order() {
    let (env, _, _) = with_second_ledger().await;
    let publisher = PublisherPool::new(env.canonical("work_publisher"))
        .await
        .unwrap();
    let (l, m) = (LedgerId::from_bytes(L), LedgerId::from_bytes(M));
    assert_eq!(publisher.outbox_ledgers(10).await.unwrap(), [l, m]);
    assert_eq!(publisher.outbox_ledgers(1).await.unwrap(), [l]);
    assert_eq!(publisher.outbox_ledgers(0).await.unwrap(), []);
    let mut tx = publisher.begin(&l).await.unwrap();
    let keys = [
        PointerKey {
            pos: 0,
            event_id: "evt-0".to_owned(),
        },
        PointerKey {
            pos: 0,
            event_id: "evt-1".to_owned(),
        },
    ];
    assert_eq!(tx.outbox_remove(&keys).await.unwrap(), 2);
    tx.commit().await.unwrap();
    assert_eq!(publisher.outbox_ledgers(10).await.unwrap(), [m]);
}

// T-80 T-79 T-13 OP-12 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_80_only_the_publisher_discovers_ledgers_and_returns_only_ids() {
    let (env, l, _) = with_second_ledger().await;
    let call = "SELECT count(*) FROM ledger.outbox_ledgers(10)";
    for role in [
        "work_app",
        "work_sequencer",
        "work_checkpointer",
        "work_erasure",
        "work_archive",
    ] {
        fails(&env.canonical(role), &l, &[call], Some("42501")).await;
        assert!(matches!(
            PublisherPool::new(env.canonical(role)).await,
            Err(StoreError::Role)
        ));
    }
    assert!(matches!(
        PublisherPool::new(env.canonical("work_owner")).await,
        Err(StoreError::Role)
    ));
    assert_eq!(
        scalar(&env.canonical("work_publisher"), "", call, false).await,
        2
    );
    let mut admin = env.admin(Cluster::Canonical).await;
    let shape: (String, String) = sqlx::query_as(
        "SELECT pg_get_function_result(p.oid), pg_get_function_arguments(p.oid) \
         FROM pg_proc p WHERE p.oid = 'ledger.outbox_ledgers(bigint)'::regprocedure",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(
        shape,
        (
            "SETOF ledger.digest32".to_owned(),
            "max_ledgers bigint".to_owned()
        )
    );
}

// T-80 T-13 T-36 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_80_outside_the_function_the_outbox_stays_ledger_scoped() {
    let (env, l, m) = with_second_ledger().await;
    let count = "SELECT count(*) FROM ledger.outbox";
    for role in ["work_publisher", "work_owner"] {
        let pool = env.canonical(role);
        assert_eq!(scalar(&pool, "", count, false).await, 0, "{role}");
        assert_eq!(scalar(&pool, &l, count, false).await, 2, "{role}");
        assert_eq!(scalar(&pool, &m, count, false).await, 1, "{role}");
    }
    assert_eq!(
        scalar(
            &env.canonical("work_owner"),
            "",
            "SELECT count(*) FROM ledger.outbox_ledgers(10)",
            false
        )
        .await,
        0
    );
    let mut tx = env.canonical("work_publisher").begin().await.unwrap();
    sqlx::query("SELECT set_config('app.outbox_scan', 'on', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM ledger.outbox")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(seen, 0);
    tx.rollback().await.unwrap();
    fails(
        &env.canonical("work_publisher"),
        "",
        &["SET LOCAL ROLE work_owner"],
        Some("42501"),
    )
    .await;
}
