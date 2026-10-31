use sqlx::{AssertSqlSafe, Executor};
use work_store::{
    AppendBatch, AppendError, CallerRef, Cluster, Durability, Genesis, IdempotencyKey, ItemHeadRow,
    ItemRef, KeyRow, LedgerId, LogRow, NewHead, OutboxRow, SequencerPool, StoreError, StoredHead,
    StoredKey, StoredOutcome,
};

use crate::env::{Env, L, M, commit_fails, fails, hex, run, scalar, with_ledgers};

const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const AT: u64 = 1_792_749_600_123;
const GENESIS_LEAF: [u8; 32] = [0x11; 32];
const ITEM: ItemRef = ItemRef::Commitment([0x0a; 32]);

fn genesis(ledger: [u8; 32]) -> Genesis {
    Genesis {
        ledger: LedgerId::from_bytes(ledger),
        recorded_at_ms: AT,
        leaf: GENESIS_LEAF,
        bytes: vec![0xa1, 0x01, 0x02],
        durability: Durability::Quorum,
    }
}

fn record(pos: u64, prev: [u8; 32], leaf: [u8; 32], at: u64) -> LogRow {
    LogRow {
        pos,
        record_id: [0x20_u8.wrapping_add(u8::try_from(pos).unwrap()); 32],
        recorded_at_ms: at,
        prev,
        leaf,
        record_bytes: vec![0xd2],
        envelope_bytes: vec![0xa0],
    }
}

fn plus(a: u64, b: u64) -> u64 {
    a.checked_add(b).unwrap()
}

fn batch(epoch: u64, after: u64, version: u64) -> AppendBatch {
    let pos = plus(after, 1);
    let roots = usize::try_from(plus(pos, 1).count_ones()).unwrap();
    let leaf = [0x30_u8.wrapping_add(u8::try_from(pos).unwrap()); 32];
    let prev = if after == 0 {
        GENESIS_LEAF
    } else {
        [0x30_u8.wrapping_add(u8::try_from(after).unwrap()); 32]
    };
    AppendBatch {
        epoch,
        after,
        records: vec![record(pos, prev, leaf, plus(AT, pos))],
        items: vec![ItemHeadRow {
            item: ITEM,
            version,
            last_pos: pos,
            heads: Some(vec![leaf]),
        }],
        outbox: vec![OutboxRow {
            pos,
            event_id: format!("evt-{pos}"),
            event_type: "commitment.requested".to_owned(),
            traceparent: TRACE.to_owned(),
            item: ITEM,
            version,
        }],
        keys: vec![],
        head: NewHead {
            pos,
            leaf,
            recorded_at_ms: plus(AT, pos),
            frontier: vec![[0x40; 32]; roots],
        },
    }
}

async fn opened() -> (Env, SequencerPool) {
    let env = Env::start().await;
    let seq = SequencerPool::new(env.canonical("work_sequencer"))
        .await
        .unwrap();
    seq.open_ledger(&genesis(L)).await.unwrap();
    (env, seq)
}

fn head_sql(s: &str) -> String {
    with_ledgers(s)
}

// P-100 T-85 OP-27 OP-10
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_85_opening_writes_the_genesis_and_leadership_reads_its_frontier() {
    let (env, seq) = opened().await;
    let l = hex(&L);
    let app = env.canonical("work_app");
    let genesis_row = "SELECT count(*) FROM ledger.log \
                       WHERE pos = 0 AND prev IS NULL AND record_id = ledger_id \
                       AND record_bytes = '\\xa10102' AND envelope_bytes = record_bytes \
                       AND recorded_at = '2026-10-23T10:00:00.123Z'";
    assert_eq!(scalar(&app, &l, genesis_row, false).await, 1);
    let profile = "SELECT count(*) FROM work.ledger_profile WHERE durability_profile = 'quorum'";
    assert_eq!(scalar(&app, &l, profile, false).await, 1);
    let head = seq.acquire(&LedgerId::from_bytes(L)).await.unwrap();
    assert_eq!(
        head,
        StoredHead {
            epoch: 1,
            pos: 0,
            leaf: GENESIS_LEAF,
            recorded_at_ms: AT,
            frontier: vec![GENESIS_LEAF],
        }
    );
    assert_eq!(
        seq.acquire(&LedgerId::from_bytes(L)).await.unwrap().epoch,
        2
    );
    assert!(matches!(
        seq.open_ledger(&genesis(L)).await,
        Err(StoreError::AlreadyOpened)
    ));
    assert!(matches!(
        seq.acquire(&LedgerId::from_bytes(M)).await,
        Err(StoreError::NotOpened)
    ));
    assert!(matches!(
        SequencerPool::new(env.canonical("work_publisher")).await,
        Err(StoreError::Role)
    ));
}

// T-85 P-100
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_85_a_head_left_empty_does_not_commit() {
    let env = Env::start().await;
    let seq = env.canonical("work_sequencer");
    let m = hex(&M);
    let insert = "INSERT INTO ledger.head (ledger_id, pos, epoch, frontier) \
                  VALUES (ledger.current_ledger_id(), -1, 0, '\\x')";
    commit_fails(&seq, &m, &[insert], "23514").await;
    commit_fails(
        &seq,
        &m,
        &["SET CONSTRAINTS ALL IMMEDIATE", insert],
        "23514",
    )
    .await;
    assert_eq!(
        scalar(&seq, &m, "SELECT count(*) FROM ledger.head", false).await,
        0
    );
}

// T-85
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_85_the_frontier_has_one_root_per_set_bit_and_moves_only_with_the_head() {
    let (env, _seq) = opened().await;
    let seq = env.canonical("work_sequencer");
    let l = hex(&L);
    let m = hex(&M);
    fails(
        &seq,
        &m,
        &["INSERT INTO ledger.head (ledger_id, pos, epoch, frontier) \
           VALUES (ledger.current_ledger_id(), -1, 0, decode(repeat('11', 32), 'hex'))"],
        Some("23514"),
    )
    .await;
    let row = |pos: u64, prev: &str, leaf: &str| {
        head_sql(&format!(
            "INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, \
             record_bytes, envelope_bytes) VALUES (decode('{{L}}', 'hex'), {pos}, 0, \
             decode(repeat('{leaf}', 32), 'hex'), '2026-10-23T10:00:05Z', \
             decode(repeat('{prev}', 32), 'hex'), decode(repeat('{leaf}', 32), 'hex'), '\\xd2', '\\xa0')"
        ))
    };
    let (r1, r2) = (row(1, "11", "12"), row(2, "12", "13"));
    let advance = |frontier: &str| {
        head_sql(&format!(
            "UPDATE ledger.head SET pos = 2, head_leaf = decode(repeat('13', 32), 'hex'), \
             head_recorded_at = '2026-10-23T10:00:05Z', frontier = {frontier} \
             WHERE ledger_id = decode('{{L}}', 'hex') AND pos = 0 AND epoch = 0"
        ))
    };
    for wrong in [
        "decode(repeat('5a', 32), 'hex')",
        "decode(repeat('5a', 96), 'hex')",
        "'\\x'",
    ] {
        fails(&seq, &l, &[&r1, &r2, &advance(wrong)], Some("23514")).await;
    }
    let same_pos = head_sql(
        "UPDATE ledger.head SET frontier = decode(repeat('5a', 32), 'hex') \
         WHERE ledger_id = decode('{L}', 'hex')",
    );
    fails(&seq, &l, &[&same_pos], Some("23514")).await;
    let fence = head_sql(
        "UPDATE ledger.head SET epoch = epoch + 1, frontier = decode(repeat('5a', 32), 'hex') \
         WHERE ledger_id = decode('{L}', 'hex')",
    );
    fails(&seq, &l, &[&fence], Some("23514")).await;
    run(
        &seq,
        &l,
        &[
            &r1,
            &r2,
            &advance("decode(repeat('5a', 32) || repeat('13', 32), 'hex')"),
        ],
    )
    .await;
    let len = "SELECT octet_length(frontier)::bigint FROM ledger.head";
    assert_eq!(scalar(&seq, &l, len, false).await, 64);
}

// P-100 P-11
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_100_prev_is_absent_exactly_at_the_genesis() {
    let (env, _seq) = opened().await;
    let seq = env.canonical("work_sequencer");
    let l = hex(&L);
    let m = hex(&M);
    fails(
        &seq,
        &l,
        &[&head_sql(
            "INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, \
             record_bytes, envelope_bytes) VALUES (decode('{L}', 'hex'), 1, 0, \
             decode(repeat('02', 32), 'hex'), '2026-10-23T10:00:05Z', NULL, \
             decode(repeat('12', 32), 'hex'), '\\xd2', '\\xa0')",
        )],
        Some("23514"),
    )
    .await;
    fails(
        &seq,
        &m,
        &[
            "INSERT INTO ledger.head (ledger_id, pos, epoch, frontier) \
             VALUES (ledger.current_ledger_id(), -1, 0, '\\x')",
            "INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, \
             record_bytes, envelope_bytes) VALUES (ledger.current_ledger_id(), 0, 0, \
             ledger.current_ledger_id(), '2026-10-23T10:00:05Z', decode(repeat('00', 32), 'hex'), \
             decode(repeat('21', 32), 'hex'), '\\xd2', '\\xd2')",
        ],
        Some("23514"),
    )
    .await;
}

// T-74 OP-5 OP-10 P-29 T-17 T-85
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_74_an_append_moves_the_head_and_a_stale_batch_fails() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let l = hex(&L);
    let lead = seq.acquire(&ledger).await.unwrap();
    let first = batch(lead.epoch, 0, 1);
    seq.append(&ledger, &first).await.unwrap();
    let app = env.canonical("work_app");
    let mut tx = work_store::LedgerTx::begin(&app, &ledger).await.unwrap();
    let head = tx.head().await.unwrap().unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(head.pos, Some(1));
    assert_eq!(head.epoch, 1);
    assert_eq!(head.leaf, Some(first.head.leaf));
    assert_eq!(head.recorded_at_ms, Some(1_792_749_600_124));
    let item = "SELECT version FROM work.item_head";
    assert_eq!(scalar(&app, &l, item, false).await, 1);
    let publisher = env.canonical("work_publisher");
    let outbox = "SELECT count(*) FROM ledger.outbox WHERE pos = 1 AND event_id = 'evt-1'";
    assert_eq!(scalar(&publisher, &l, outbox, false).await, 1);

    assert!(matches!(
        seq.append(&ledger, &batch(lead.epoch, 0, 1)).await,
        Err(AppendError::Failed(StoreError::HeadMoved))
    ));
    let next = seq.acquire(&ledger).await.unwrap();
    assert_eq!(next.epoch, 2);
    assert_eq!(next.pos, 1);
    assert_eq!(next.frontier, first.head.frontier);
    assert!(matches!(
        seq.append(&ledger, &batch(lead.epoch, 1, 2)).await,
        Err(AppendError::Failed(StoreError::HeadMoved))
    ));
    assert!(matches!(
        seq.append(&ledger, &batch(next.epoch, 1, 1)).await,
        Err(AppendError::Refused(StoreError::ItemConflict(ITEM)))
    ));
    assert!(matches!(
        seq.append(&ledger, &batch(next.epoch, 1, 3)).await,
        Err(AppendError::Refused(StoreError::ItemConflict(ITEM)))
    ));
    let log = "SELECT count(*) FROM ledger.log";
    assert_eq!(scalar(&app, &l, log, false).await, 2);
    seq.append(&ledger, &batch(next.epoch, 1, 2)).await.unwrap();
    assert_eq!(scalar(&app, &l, log, false).await, 3);
    assert_eq!(scalar(&app, &l, item, false).await, 2);
    assert!(matches!(
        seq.append(&LedgerId::from_bytes(M), &batch(next.epoch, 0, 1))
            .await,
        Err(AppendError::Failed(StoreError::NotOpened))
    ));
}

// T-85 OP-10
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_85_leadership_is_refused_when_the_head_diverges_from_the_log() {
    let (env, seq) = opened().await;
    let mut admin = env.admin(Cluster::Canonical).await;
    admin
        .execute(AssertSqlSafe(head_sql(
            "SET session_replication_role = replica; \
             UPDATE ledger.head SET head_leaf = decode(repeat('99', 32), 'hex'), \
             frontier = decode(repeat('99', 32), 'hex') \
             WHERE ledger_id = decode('{L}', 'hex'); \
             RESET session_replication_role",
        )))
        .await
        .unwrap();
    assert!(matches!(
        seq.acquire(&LedgerId::from_bytes(L)).await,
        Err(StoreError::Diverged)
    ));
    let epoch = "SELECT epoch FROM ledger.head";
    assert_eq!(
        scalar(&env.canonical("work_app"), &hex(&L), epoch, false).await,
        0
    );
}

fn keyed(mut b: AppendBatch, key: &str) -> AppendBatch {
    let pos = b.head.pos;
    let record_id = b.records[0].record_id;
    b.keys.push(KeyRow {
        caller: CallerRef::new("caller-1").unwrap(),
        key: IdempotencyKey::parse(key).unwrap(),
        stored: StoredKey {
            request_digest: [0x77; 32],
            outcome: StoredOutcome::Recorded { pos, record_id },
            created_at_ms: i64::try_from(b.head.recorded_at_ms).unwrap(),
        },
    });
    b
}

// OP-8 OP-36 T-32 T-74
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_8_the_key_is_written_with_its_record_and_a_reused_key_is_refused() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger).await.unwrap();
    let key = "0192f0a0-0000-7000-8000-000000000001";
    seq.append(&ledger, &keyed(batch(head.epoch, 0, 1), key))
        .await
        .unwrap();
    let mut tx = work_store::LedgerTx::begin(&env.canonical("work_app"), &ledger)
        .await
        .unwrap();
    let stored = tx
        .idempotency_key(
            &CallerRef::new("caller-1").unwrap(),
            &IdempotencyKey::parse(key).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(
        stored.outcome,
        StoredOutcome::Recorded {
            pos: 1,
            record_id: record(1, GENESIS_LEAF, [0; 32], AT).record_id
        }
    );
    assert!(matches!(
        seq.append(&ledger, &keyed(batch(head.epoch, 1, 2), key))
            .await,
        Err(AppendError::Refused(StoreError::KeyReused))
    ));
    seq.append(&ledger, &batch(head.epoch, 1, 2)).await.unwrap();
}
