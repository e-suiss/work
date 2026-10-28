use work_store::{Cluster, DeriverPool, LedgerId, PointerKey, PublisherPool, StoreError};

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
            "INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version) \
             VALUES (ledger.current_ledger_id(), 0, 'evt-m0', 'work.opened', '{TRACE}', 'work', decode(repeat('0c', 16), 'hex'), 1)"
        ),
        "UPDATE ledger.head SET pos = 0, head_leaf = decode(repeat('21', 32), 'hex'), \
         head_recorded_at = '2026-10-23T11:00:00.000Z' \
         WHERE ledger_id = ledger.current_ledger_id() AND pos = -1 AND epoch = 0".to_owned(),
    ];
    let refs: Vec<&str> = stmts.iter().map(String::as_str).collect();
    run(&env.canonical("work_sequencer"), &m, &refs).await;
    (env, l, m)
}

// T-80 T-83 OP-34 T-17 T-13
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_80_outbox_ledgers_lists_only_ledgers_with_pending_pointers_in_order() {
    let (env, _, _) = with_second_ledger().await;
    let publisher = PublisherPool::new(env.canonical("work_publisher"))
        .await
        .unwrap();
    let (l, m) = (LedgerId::from_bytes(L), LedgerId::from_bytes(M));
    assert_eq!(publisher.outbox_ledgers(None, 10).await.unwrap(), [l, m]);
    assert_eq!(publisher.outbox_ledgers(None, 1).await.unwrap(), [l]);
    assert_eq!(publisher.outbox_ledgers(None, 0).await.unwrap(), []);
    assert_eq!(publisher.outbox_ledgers(Some(&l), 10).await.unwrap(), [m]);
    assert_eq!(publisher.outbox_ledgers(Some(&m), 10).await.unwrap(), []);
    let below = LedgerId::from_bytes([0x01; 32]);
    assert_eq!(
        publisher.outbox_ledgers(Some(&below), 1).await.unwrap(),
        [l]
    );
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
    assert_eq!(publisher.outbox_ledgers(None, 10).await.unwrap(), [m]);
}

// T-80 T-82 T-83 T-79 T-13 OP-12 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_80_only_the_publisher_and_the_deriver_discover_ledgers_and_get_only_ids() {
    let (env, l, _) = with_second_ledger().await;
    let call = "SELECT count(*) FROM ledger.outbox_ledgers(NULL, 10)";
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
    for role in ["work_owner", "work_deriver"] {
        assert!(matches!(
            PublisherPool::new(env.canonical(role)).await,
            Err(StoreError::Role)
        ));
    }
    for role in ["work_owner", "work_publisher"] {
        assert!(matches!(
            DeriverPool::new(env.canonical(role)).await,
            Err(StoreError::Role)
        ));
    }
    for role in ["work_publisher", "work_deriver"] {
        assert_eq!(scalar(&env.canonical(role), "", call, false).await, 2);
        assert_eq!(
            scalar(
                &env.canonical(role),
                "",
                "SELECT count(*) FROM ledger.outbox_ledgers(NULL, NULL)",
                false
            )
            .await,
            0
        );
    }
    let deriver = DeriverPool::new(env.canonical("work_deriver"))
        .await
        .unwrap();
    assert_eq!(
        deriver.outbox_ledgers(None, 10).await.unwrap(),
        [LedgerId::from_bytes(L), LedgerId::from_bytes(M)]
    );
    let mut admin = env.admin(Cluster::Canonical).await;
    let shape: (String, String) = sqlx::query_as(
        "SELECT pg_get_function_result(p.oid), pg_get_function_arguments(p.oid) \
         FROM pg_proc p WHERE p.oid = 'ledger.outbox_ledgers(ledger.digest32, bigint)'::regprocedure",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(
        shape,
        (
            "SETOF ledger.digest32".to_owned(),
            "after_ledger ledger.digest32, max_ledgers bigint".to_owned()
        )
    );
    let old: Option<String> = sqlx::query_scalar(
        "SELECT pg_catalog.to_regprocedure('ledger.outbox_ledgers(bigint)')::text",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(old, None);
}

// T-82 T-21 T-13 OP-12 OP-34 T-79
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_82_the_deriver_reads_pointers_and_the_log_per_ledger_and_writes_nothing() {
    let (env, l, m) = with_second_ledger().await;
    let deriver = env.canonical("work_deriver");
    for (scope, outbox, log) in [(&l, 2, 1), (&m, 1, 1), (&String::new(), 0, 0)] {
        assert_eq!(
            scalar(&deriver, scope, "SELECT count(*) FROM ledger.outbox", false).await,
            outbox
        );
        assert_eq!(
            scalar(&deriver, scope, "SELECT count(*) FROM ledger.log", false).await,
            log
        );
    }
    for stmt in [
        "DELETE FROM ledger.outbox",
        "UPDATE ledger.outbox SET event_type = 'work.closed'",
        "TRUNCATE ledger.outbox",
        "INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version) \
         SELECT ledger_id, pos, 'evt-9', event_type, traceparent, item_kind, item_id, version FROM ledger.outbox LIMIT 1",
        "DELETE FROM ledger.log",
        "SELECT count(*) FROM ledger.head",
        "SELECT count(*) FROM work.record_header",
    ] {
        fails(&deriver, &l, &[stmt], Some("42501")).await;
    }
    let pool = DeriverPool::new(deriver).await.unwrap();
    let mut tx = pool.begin(&LedgerId::from_bytes(L)).await.unwrap();
    let rows = tx.outbox_pending_after(None, 10).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.version == 1 && r.record_id == [0x01; 32])
    );
    assert_eq!(tx.log_after(None, 10).await.unwrap().len(), 1);
    let keys: Vec<PointerKey> = rows.into_iter().map(|r| r.key).collect();
    assert!(tx.outbox_remove(&keys).await.is_err());
    tx.rollback().await.unwrap();
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
    fails(
        &env.canonical("work_owner"),
        "",
        &["SELECT count(*) FROM ledger.outbox_ledgers(NULL, 10)"],
        Some("42501"),
    )
    .await;
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
