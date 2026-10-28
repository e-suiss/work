use sqlx::PgPool;
use work_store::{
    CallerRef, Cluster, HOT_WINDOW_MS, IdempotencyDecision, IdempotencyKey, LedgerId, LedgerTx,
    StoreError, StoredKey, StoredOutcome,
};

use crate::canonical::seeded;
use crate::env::{L, M};

const DAY_MS: i64 = 86_400_000;
const DIGEST: [u8; 32] = [0x77; 32];
const OTHER: [u8; 32] = [0x78; 32];

fn key_at(ms: i64, tail: u16) -> String {
    let hex = format!("{ms:012x}");
    format!("{}-{}-7abc-9def-0123456789{tail:02x}", &hex[..8], &hex[8..])
}

fn parsed(text: &str) -> IdempotencyKey {
    IdempotencyKey::parse(text).unwrap()
}

fn alice() -> CallerRef {
    CallerRef::new("party:alice").unwrap()
}

fn recorded(created_at_ms: i64) -> StoredKey {
    StoredKey {
        request_digest: DIGEST,
        outcome: StoredOutcome::Recorded {
            pos: 0,
            record_id: [0x01; 32],
        },
        created_at_ms,
    }
}

fn rejected(digest: [u8; 32], created_at_ms: i64) -> StoredKey {
    StoredKey {
        request_digest: digest,
        outcome: StoredOutcome::Rejected {
            reason: "conflict".to_owned(),
        },
        created_at_ms,
    }
}

async fn db_ms(pool: &PgPool, expr: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT (extract(epoch FROM {expr}) * 1000)::bigint"
    )))
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn insert(pool: &PgPool, ledger: &[u8; 32], caller: &CallerRef, key: &str, row: &StoredKey) {
    let mut tx = LedgerTx::begin(pool, &LedgerId::from_bytes(*ledger))
        .await
        .unwrap();
    tx.insert_idempotency_key(caller, &parsed(key), row)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn decide(
    pool: &PgPool,
    ledger: &[u8; 32],
    caller: &CallerRef,
    key: &str,
    digest: &[u8; 32],
    now_ms: i64,
) -> IdempotencyDecision {
    let mut tx = LedgerTx::begin(pool, &LedgerId::from_bytes(*ledger))
        .await
        .unwrap();
    let d = tx.idempotency(caller, key, digest, now_ms).await.unwrap();
    tx.rollback().await.unwrap();
    d
}

// OP-36 P-54 T-13
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_8_the_same_key_and_digest_replays_the_first_result() {
    let (env, _) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let now = db_ms(&seq, "now()").await;
    let key = key_at(now, 1);
    let caller = alice();
    assert_eq!(
        decide(&seq, &L, &caller, &key, &DIGEST, now).await,
        IdempotencyDecision::Fresh(parsed(&key))
    );
    insert(&seq, &L, &caller, &key, &recorded(now)).await;
    assert_eq!(
        decide(&seq, &L, &caller, &key, &DIGEST, now).await,
        IdempotencyDecision::Replay(recorded(now))
    );
    assert_eq!(
        decide(&seq, &L, &caller, &key.to_uppercase(), &DIGEST, now).await,
        IdempotencyDecision::Replay(recorded(now))
    );
    let rejected_key = key_at(now, 2);
    insert(&seq, &L, &caller, &rejected_key, &rejected(DIGEST, now)).await;
    assert_eq!(
        decide(&seq, &L, &caller, &rejected_key, &DIGEST, now).await,
        IdempotencyDecision::Replay(rejected(DIGEST, now))
    );
    let bob = CallerRef::new("party:bob").unwrap();
    assert_eq!(
        decide(&seq, &L, &bob, &key, &DIGEST, now).await,
        IdempotencyDecision::Fresh(parsed(&key))
    );
    assert_eq!(
        decide(&seq, &M, &caller, &key, &DIGEST, now).await,
        IdempotencyDecision::Fresh(parsed(&key))
    );
    let mut tx = LedgerTx::begin(&env.canonical("work_app"), &LedgerId::from_bytes(L))
        .await
        .unwrap();
    assert_eq!(
        tx.idempotency_key(&caller, &parsed(&key)).await.unwrap(),
        Some(recorded(now))
    );
    tx.rollback().await.unwrap();
}

// OP-36
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_8_the_same_key_with_another_digest_is_a_conflict() {
    let (env, _) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let now = db_ms(&seq, "now()").await;
    let key = key_at(now, 3);
    insert(&seq, &L, &alice(), &key, &recorded(now)).await;
    assert_eq!(
        decide(&seq, &L, &alice(), &key, &OTHER, now).await,
        IdempotencyDecision::Conflict
    );
    let mut tx = LedgerTx::begin(&seq, &LedgerId::from_bytes(L))
        .await
        .unwrap();
    let dup = tx
        .insert_idempotency_key(&alice(), &parsed(&key), &rejected(OTHER, now))
        .await;
    let code = match dup {
        Err(StoreError::Db(e)) => e
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(std::borrow::Cow::into_owned),
        other => panic!("{other:?}"),
    };
    assert_eq!(code.as_deref(), Some("23505"));
}

// OP-36 P-96 P-97
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_38_keys_outside_the_window_are_answered_without_a_lookup() {
    let (env, _) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let now = db_ms(&seq, "now()").await;
    let old = key_at(now - HOT_WINDOW_MS - 1, 4);
    insert(&seq, &L, &alice(), &old, &recorded(now)).await;
    let expired = decide(&seq, &L, &alice(), &old, &DIGEST, now).await;
    assert_eq!(expired, IdempotencyDecision::Expired);
    assert_eq!(expired.reason_code(), Some("idempotency_key_expired"));
    let edge = key_at(now - HOT_WINDOW_MS, 5);
    assert_eq!(
        decide(&seq, &L, &alice(), &edge, &DIGEST, now).await,
        IdempotencyDecision::Fresh(parsed(&edge))
    );
    let future = key_at(now + work_store::CLOCK_UNCERTAINTY_MS + 1, 6);
    for bad in [
        future.as_str(),
        "req-1",
        "0199a0b1-c2d3-4e4f-8a5b-6c7d8e9f0a1b",
    ] {
        let d = decide(&seq, &L, &alice(), bad, &DIGEST, now).await;
        assert_eq!(d, IdempotencyDecision::Malformed, "{bad}");
        assert_eq!(d.reason_code(), Some("idempotency_key_malformed"));
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM work.idempotency_key")
        .fetch_one(&mut env.admin(Cluster::Canonical).await)
        .await
        .unwrap();
    assert_eq!(n, 2);
}

// OP-36 OP-37
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_36_the_hot_check_spans_every_hot_partition() {
    let (env, _) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let now = db_ms(&seq, "now()").await;
    let last_month = db_ms(
        &seq,
        "(date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' - interval '1 month' + interval '1 day')",
    )
    .await;
    let key = key_at(now - DAY_MS, 7);
    insert(&seq, &L, &alice(), &key, &rejected(DIGEST, last_month)).await;
    insert(&seq, &L, &alice(), &key, &rejected(OTHER, now)).await;
    let parts: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT tableoid) FROM work.idempotency_key WHERE caller_ref = 'party:alice'",
    )
    .fetch_one(&mut env.admin(Cluster::Canonical).await)
    .await
    .unwrap();
    assert_eq!(parts, 2);
    assert_eq!(
        decide(&seq, &L, &alice(), &key, &DIGEST, now).await,
        IdempotencyDecision::Replay(rejected(DIGEST, last_month))
    );
    assert_eq!(
        decide(&seq, &L, &alice(), &key, &OTHER, now).await,
        IdempotencyDecision::Conflict
    );
}

// OP-37 OP-12
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_36_a_key_row_in_a_month_without_a_partition_is_rejected() {
    let (env, _) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let now = db_ms(&seq, "now()").await;
    let key = key_at(now, 8);
    for at in [now - 5 * 365 * DAY_MS, now + 5 * 365 * DAY_MS] {
        let mut tx = LedgerTx::begin(&seq, &LedgerId::from_bytes(L))
            .await
            .unwrap();
        let code = match tx
            .insert_idempotency_key(&alice(), &parsed(&key), &rejected(DIGEST, at))
            .await
        {
            Err(StoreError::Db(e)) => e
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .map(std::borrow::Cow::into_owned),
            other => panic!("{other:?}"),
        };
        assert_eq!(code.as_deref(), Some("23514"), "{at}");
    }
}
