use sqlx::AssertSqlSafe;
use work_store::{Cluster, LedgerId, LedgerTx};

use crate::env::{Env, L, M, fails, hex, run, scalar, with_ledgers};

const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

const SEED: &str = "
INSERT INTO ledger.head (ledger_id, pos, epoch) VALUES (decode('{L}', 'hex'), -1, 0);
INSERT INTO work.ledger_profile VALUES (decode('{L}', 'hex'), 'single-node');
INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes, envelope_bytes)
VALUES (decode('{L}', 'hex'), 0, 0, decode(repeat('01', 32), 'hex'), '2026-10-23T10:00:00.123Z',
        decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'), '\\xd2', '\\xa0');
INSERT INTO work.record_header (
    ledger_id, pos, kind, record_type, author, author_actor_type, author_actor_type_source,
    occurred_at, ingest, proof_commit, protocol_major, protocol_minor, schema_digest)
VALUES (
    decode('{L}', 'hex'), 0, 'declaration', 'https://suiss.app/ns/work/declaration/request', 'party:alice',
    'human', 'access_binding', NULL, 'admitted', decode(repeat('22', 32), 'hex'), 1, 0,
    decode(repeat('33', 32), 'hex'));
INSERT INTO work.work_root VALUES (decode('{L}', 'hex'), '01890a5d-ac96-774b-bcce-b302099a8057', 0);
INSERT INTO work.log_concerns VALUES (decode('{L}', 'hex'), '01890a5d-ac96-774b-bcce-b302099a8057', 0);
INSERT INTO work.body_commitment VALUES (decode('{L}', 'hex'), 0, 'note', decode(repeat('44', 32), 'hex'));
INSERT INTO work.body_dek (ledger_id, subject_ref, retention_class, hsm_key_label, state)
VALUES (decode('{L}', 'hex'), 'party:alice', 'work_record', 'work-dek-0001', 'active');
INSERT INTO work.body_part (ledger_id, pos, part, dek_id, retention_class, storage, nonce, ciphertext, ciphertext_digest)
SELECT decode('{L}', 'hex'), 0, 'note', dek_id, 'work_record', 'inline', decode(repeat('55', 12), 'hex'), '\\xdeadbeef',
       decode(repeat('66', 32), 'hex')
  FROM work.body_dek WHERE hsm_key_label = 'work-dek-0001';
INSERT INTO work.body_commitment VALUES (decode('{L}', 'hex'), 0, 'attachment', decode(repeat('45', 32), 'hex'));
INSERT INTO work.body_part (ledger_id, pos, part, dek_id, retention_class, storage, nonce, object_key, ciphertext_digest)
SELECT decode('{L}', 'hex'), 0, 'attachment', dek_id, 'work_record', 'object_store', decode(repeat('56', 12), 'hex'),
       'ab/0/attachment', decode(repeat('67', 32), 'hex')
  FROM work.body_dek WHERE hsm_key_label = 'work-dek-0001';
INSERT INTO work.item_head (ledger_id, item_kind, item_id, version, last_pos, heads)
VALUES (decode('{L}', 'hex'), 'commitment', decode(repeat('01', 32), 'hex'), 1, 0,
        ARRAY[decode(repeat('01', 32), 'hex')]::ledger.digest32[]);
INSERT INTO work.idempotency_key (ledger_id, caller_ref, idem_key, request_digest, outcome, result_pos, result_record_id)
VALUES (decode('{L}', 'hex'), 'party:alice', 'req-1', decode(repeat('77', 32), 'hex'), 'recorded', 0,
        decode(repeat('01', 32), 'hex'));
INSERT INTO work.inbound_seen (ledger_id, source, source_id, content_digest, result_pos)
VALUES (decode('{L}', 'hex'), 'https://peer.example/ledgers/x', 'evt-9', decode(repeat('79', 32), 'hex'), 0);
INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent)
VALUES (decode('{L}', 'hex'), 0, 'evt-0', 'commitment.requested', '{T}'),
       (decode('{L}', 'hex'), 0, 'evt-1', 'work.opened', '{T}');
UPDATE ledger.head
   SET pos = 0, head_leaf = decode(repeat('11', 32), 'hex'), head_recorded_at = '2026-10-23T10:00:00.123Z'
 WHERE ledger_id = decode('{L}', 'hex') AND pos = -1 AND epoch = 0;
";

fn sql(s: &str) -> String {
    with_ledgers(s).replace("{T}", TRACE)
}

fn log_row(pos: i64, prev: &str, recorded_at: &str) -> String {
    sql(&format!(
        "INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes, envelope_bytes) \
         VALUES (decode('{{L}}', 'hex'), {pos}, 0, decode(repeat('02', 32), 'hex'), '{recorded_at}', \
         decode(repeat('{prev}', 32), 'hex'), decode(repeat('12', 32), 'hex'), '\\xd2', '\\xa0')"
    ))
}

pub(crate) async fn seeded() -> (Env, String) {
    let env = Env::start().await;
    let l = hex(&L);
    run(&env.canonical("work_sequencer"), &l, &[&sql(SEED)]).await;
    (env, l)
}

// T-36 OP-28
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_36_migrations_rerun_as_a_no_op() {
    let env = Env::start().await;
    for (cluster, applied) in [(Cluster::Canonical, 10), (Cluster::Derived, 6)] {
        work_store::migrate(&env.pool(cluster, "work_owner"), cluster)
            .await
            .unwrap();
        let mut c = env.admin(cluster).await;
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations WHERE success")
                .fetch_one(&mut c)
                .await
                .unwrap();
        assert_eq!(n, applied, "{cluster:?}");
    }
}

// OP-5 OP-9 OP-10 P-11 P-23 Access T6 Access FA-2
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_5_appends_need_a_contiguous_chain_and_the_head_compare_and_set() {
    let (env, l) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let ok = "2026-10-23T10:00:05Z";
    fails(&seq, &l, &[&log_row(2, "11", ok)], Some("23514")).await;
    fails(&seq, &l, &[&log_row(1, "99", ok)], Some("23514")).await;
    fails(
        &seq,
        &l,
        &[&log_row(1, "11", "2026-10-23T09:00:00Z")],
        Some("23514"),
    )
    .await;
    fails(&seq, &l, &[&log_row(0, "00", ok)], Some("23514")).await;
    fails(
        &seq,
        &l,
        &["SET CONSTRAINTS ALL IMMEDIATE", &log_row(1, "11", ok)],
        Some("23514"),
    )
    .await;
    fails(
        &seq,
        &l,
        &[&sql(
            "UPDATE ledger.head SET epoch = 1, pos = 5 WHERE ledger_id = decode('{L}', 'hex')",
        )],
        Some("23514"),
    )
    .await;
    fails(
        &seq,
        &l,
        &[&sql(
            "UPDATE ledger.head SET epoch = 0 - 1 WHERE ledger_id = decode('{L}', 'hex')",
        )],
        None,
    )
    .await;
    let stale = "WITH u AS (UPDATE ledger.head SET pos = 0 WHERE pos = 0 AND epoch = 7 RETURNING 1) \
                 SELECT count(*) FROM u";
    assert_eq!(scalar(&seq, &l, stale, false).await, 0);
    run(
        &seq,
        &l,
        &[
            &log_row(1, "11", ok),
            &sql(&format!(
                "UPDATE ledger.head SET pos = 1, head_leaf = decode(repeat('12', 32), 'hex'), head_recorded_at = '{ok}' \
                 WHERE ledger_id = decode('{{L}}', 'hex') AND pos = 0 AND epoch = 0"
            )),
        ],
    )
    .await;
    run(
        &seq,
        &l,
        &[&sql(
            "UPDATE ledger.head SET epoch = 1 WHERE ledger_id = decode('{L}', 'hex') AND epoch = 0",
        )],
    )
    .await;
    fails(&seq, &l, &[&log_row(2, "12", ok)], Some("23514")).await;
}

// OP-12 OP-17 T-36 Access OP-17 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_12_append_only_tables_reject_update_delete_and_truncate_from_every_role() {
    let (env, l) = seeded().await;
    let cases: &[(&str, &str)] = &[
        (
            "work_app",
            "INSERT INTO ledger.head (ledger_id, pos, epoch) VALUES (decode(repeat('ab', 32), 'hex'), -1, 0)",
        ),
        ("work_sequencer", "UPDATE ledger.log SET epoch = 1"),
        (
            "work_sequencer",
            "UPDATE work.record_header SET kind = 'act'",
        ),
        ("work_sequencer", "DELETE FROM ledger.log"),
        ("work_sequencer", "TRUNCATE ledger.log"),
        ("work_sequencer", "DELETE FROM work.item_head"),
        ("work_owner", "DELETE FROM ledger.log"),
        ("work_owner", "UPDATE work.body_part SET storage = 'inline'"),
        ("work_owner", "TRUNCATE ledger.log"),
        (
            "work_owner",
            "UPDATE work.ledger_profile SET durability_profile = 'quorum'",
        ),
        ("work_app", "UPDATE work.body_part SET storage = 'inline'"),
        ("work_publisher", "DELETE FROM work.idempotency_key"),
        ("work_publisher", "DELETE FROM ledger.log"),
        ("work_archive", "DELETE FROM work.idempotency_key"),
        ("work_archive", "SELECT count(*) FROM ledger.log"),
        ("work_erasure", "DELETE FROM work.body_part"),
    ];
    for (role, stmt) in cases {
        fails(&env.canonical(role), &l, &[stmt], Some("42501")).await;
    }
}

// T-13 T-36 Access OP-12 Access OP-18
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_13_rows_outside_the_ledger_scope_are_invisible_and_unwritable() {
    let (env, l) = seeded().await;
    let m = hex(&M);
    let app = env.canonical("work_app");
    let q = "SELECT count(*) FROM ledger.log";
    assert_eq!(scalar(&app, &l, q, false).await, 1);
    assert_eq!(scalar(&app, &m, q, false).await, 0);
    assert_eq!(scalar(&app, "", q, false).await, 0);
    let publisher = env.canonical("work_publisher");
    assert_eq!(
        scalar(&publisher, &m, "SELECT count(*) FROM ledger.outbox", false).await,
        0
    );
    let seq = env.canonical("work_sequencer");
    fails(
        &seq,
        &l,
        &["INSERT INTO work.work_root VALUES (decode(repeat('cd', 32), 'hex'), '01890a5d-ac96-774b-bcce-b302099a8058', 0)"],
        Some("42501"),
    )
    .await;
    fails(
        &seq,
        "",
        &["INSERT INTO ledger.head (ledger_id, pos, epoch) VALUES (decode(repeat('cd', 32), 'hex'), -1, 0)"],
        Some("42501"),
    )
    .await;
    let mut tx = LedgerTx::begin(&app, &LedgerId::from_bytes(L))
        .await
        .unwrap();
    let head = tx.head().await.unwrap().unwrap();
    assert_eq!(head.pos, Some(0));
    assert_eq!(head.epoch, 0);
    assert_eq!(head.leaf, Some([0x11; 32]));
    assert_eq!(head.recorded_at_ms, Some(1_792_749_600_123));
    tx.rollback().await.unwrap();
    let mut tx = LedgerTx::begin(&app, &LedgerId::from_bytes(M))
        .await
        .unwrap();
    assert_eq!(tx.head().await.unwrap(), None);
    tx.commit().await.unwrap();
}

// OP-4 P-20 Access T21 Access TI-13
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_4_a_witness_needs_a_mirror_and_durability_is_derived_from_rows() {
    let (env, l) = seeded().await;
    let cp = env.canonical("work_checkpointer");
    fails(
        &cp,
        &l,
        &[&sql("INSERT INTO ledger.checkpoint VALUES (decode('{L}', 'hex'), 1, decode(repeat('88', 32), 'hex'), decode(repeat('99', 32), 'hex'), '2026-10-23T10:00:01Z', '\\xd2')")],
        Some("23514"),
    )
    .await;
    run(
        &cp,
        &l,
        &[&sql("INSERT INTO ledger.checkpoint VALUES (decode('{L}', 'hex'), 1, decode(repeat('88', 32), 'hex'), decode(repeat('11', 32), 'hex'), '2026-10-23T10:00:01Z', '\\xd2')")],
    )
    .await;
    let cosign = sql(
        "INSERT INTO ledger.checkpoint_cosignature VALUES (decode('{L}', 'hex'), 1, 'witness_a', 'witness', '2026-10-23T10:00:02Z', '\\x01')",
    );
    fails(&cp, &l, &[&cosign], Some("23514")).await;
    fails(
        &cp,
        &l,
        &[&sql("INSERT INTO ledger.replica_progress (ledger_id, replica_id, mirrored_size) VALUES (decode('{L}', 'hex'), 'replica_a', 2)")],
        Some("23514"),
    )
    .await;
    let app = env.canonical("work_app");
    let durability = "SELECT count(*) FROM ledger.record_durability WHERE durability = 'included'";
    assert_eq!(scalar(&app, &l, durability, false).await, 1);
    run(
        &cp,
        &l,
        &[
            &sql("INSERT INTO ledger.replica_progress (ledger_id, replica_id, mirrored_size) VALUES (decode('{L}', 'hex'), 'replica_a', 1)"),
            &cosign,
        ],
    )
    .await;
    fails(
        &cp,
        &l,
        &["UPDATE ledger.replica_progress SET mirrored_size = 0"],
        Some("23514"),
    )
    .await;
    let witnessed = "SELECT count(*) FROM ledger.record_durability WHERE durability = 'witnessed'";
    assert_eq!(scalar(&app, &l, witnessed, false).await, 1);
}

// OP-8 OP-12 T-36 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_8_idempotency_keys_are_unique_within_a_month_and_partitions_fail_closed() {
    let (env, l) = seeded().await;
    let seq = env.canonical("work_sequencer");
    fails(
        &seq,
        &l,
        &["INSERT INTO work.idempotency_key (ledger_id, caller_ref, idem_key, request_digest, outcome, reason, created_at) \
           SELECT ledger_id, caller_ref, idem_key, decode(repeat('78', 32), 'hex'), 'rejected', 'conflict', created_at \
           FROM work.idempotency_key WHERE idem_key = 'req-1'"],
        Some("23505"),
    )
    .await;
    fails(
        &seq,
        &l,
        &["INSERT INTO work.idempotency_key (ledger_id, caller_ref, idem_key, request_digest, outcome, reason, created_at) \
           VALUES (decode(repeat('ab', 32), 'hex'), 'party:alice', 'req-old', decode(repeat('78', 32), 'hex'), 'rejected', 'conflict', \
           now() - interval '5 years')"],
        Some("23514"),
    )
    .await;
    let mut admin = env.admin(Cluster::Canonical).await;
    let parts: Vec<String> = sqlx::query_scalar(
        "SELECT c.oid::regclass::text FROM pg_inherits h JOIN pg_class c ON c.oid = h.inhrelid \
         WHERE h.inhparent IN ('work.idempotency_key'::regclass, 'work.inbound_seen'::regclass) ORDER BY 1",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    assert_eq!(parts.len(), 10, "{parts:?}");
    let part = parts.first().unwrap();
    fails(
        &seq,
        &l,
        &[&format!("SELECT count(*) FROM {part}")],
        Some("42501"),
    )
    .await;
    let owner = env.canonical("work_owner");
    fails(&owner, &l, &[&format!("TRUNCATE {part}")], Some("42501")).await;
    fails(&owner, &l, &[&format!("DELETE FROM {part}")], Some("42501")).await;
    fails(
        &seq,
        &l,
        &["UPDATE work.inbound_seen SET source_id = 'x'"],
        Some("42501"),
    )
    .await;
}

// P-42 T-17 T-21 Access OP-73 Access T26
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_42_outbox_pointers_are_checked_and_only_the_publisher_acknowledges() {
    let (env, l) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let pointer = |pos: u8, id: &str, ty: &str, trace: &str| {
        sql(&format!(
            "INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent) \
             VALUES (decode('{{L}}', 'hex'), {pos}, '{id}', '{ty}', '{trace}')"
        ))
    };
    let zero_trace = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
    fails(
        &seq,
        &l,
        &[&pointer(0, "evt-2", "commitment.requested", zero_trace)],
        Some("23514"),
    )
    .await;
    fails(
        &seq,
        &l,
        &[&pointer(0, "evt-3", "Commitment Requested", TRACE)],
        Some("23514"),
    )
    .await;
    fails(
        &seq,
        &l,
        &[&pointer(9, "evt-4", "commitment.requested", TRACE)],
        Some("23503"),
    )
    .await;
    let cases: &[(&str, &str)] = &[
        ("work_sequencer", "DELETE FROM ledger.outbox"),
        ("work_app", "DELETE FROM ledger.outbox"),
        ("work_app", "SELECT count(*) FROM ledger.outbox"),
        ("work_owner", "DELETE FROM ledger.outbox"),
        (
            "work_publisher",
            "UPDATE ledger.outbox SET event_type = 'work.closed'",
        ),
        ("work_publisher", "TRUNCATE ledger.outbox"),
        ("work_owner", "TRUNCATE ledger.outbox"),
        (
            "work_owner",
            "UPDATE ledger.outbox SET event_type = 'work.closed'",
        ),
    ];
    for (role, stmt) in cases {
        fails(&env.canonical(role), &l, &[stmt], Some("42501")).await;
    }
    let publisher = env.canonical("work_publisher");
    let pending = "SELECT count(*) FROM (SELECT pos, event_id FROM ledger.outbox \
                   WHERE ledger_id = ledger.current_ledger_id() ORDER BY pos, event_id LIMIT 100) p";
    assert_eq!(scalar(&publisher, &l, pending, false).await, 2);
    let ack = |ids: &str| {
        format!(
            "WITH d AS (DELETE FROM ledger.outbox WHERE ledger_id = ledger.current_ledger_id() \
             AND pos = 0 AND event_id IN ({ids}) RETURNING 1) SELECT count(*) FROM d"
        )
    };
    assert_eq!(
        scalar(&publisher, &l, &ack("'evt-0', 'evt-1'"), true).await,
        2
    );
    assert_eq!(scalar(&publisher, &l, &ack("'evt-0'"), true).await, 0);
    assert_eq!(scalar(&publisher, &l, pending, false).await, 0);
}

// OP-12 OP-14 OP-15 Access OP-74 Access OP-78
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_12_a_retention_hold_blocks_crypto_shredding() {
    let (env, l) = seeded().await;
    let erasure = env.canonical("work_erasure");
    run(
        &erasure,
        &l,
        &[&sql(
            "INSERT INTO work.retention_hold (ledger_id, hold_kind, subject_ref, state) \
                VALUES (decode('{L}', 'hex'), 'litigation', 'party:alice', 'active')",
        )],
    )
    .await;
    let destroy = "UPDATE work.body_dek SET state = 'destroyed', destroyed_at = now()";
    fails(&erasure, &l, &[destroy], Some("23514")).await;
    let completed = sql(
        "INSERT INTO work.erasure_log (ledger_id, dek_id, cause, state, completed_at) \
         SELECT decode('{L}', 'hex'), dek_id, 'subject_request', 'completed', now() FROM work.body_dek",
    );
    fails(&erasure, &l, &[&completed], Some("23514")).await;
    run(
        &erasure,
        &l,
        &["UPDATE work.retention_hold SET state = 'released', released_at = now()"],
    )
    .await;
    fails(
        &erasure,
        &l,
        &["UPDATE work.retention_hold SET state = 'active', released_at = NULL"],
        None,
    )
    .await;
    run(&erasure, &l, &[destroy, &completed]).await;
    fails(
        &erasure,
        &l,
        &["UPDATE work.body_dek SET state = 'active', destroyed_at = NULL"],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &["UPDATE work.body_dek SET hsm_key_label = 'x'"],
        Some("42501"),
    )
    .await;
}

// P-29 OP-7 C-40
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_29_item_versions_step_by_one_with_the_position() {
    let (env, l) = seeded().await;
    let seq = env.canonical("work_sequencer");
    fails(
        &seq,
        &l,
        &["UPDATE work.item_head SET version = 3, last_pos = 1"],
        Some("23514"),
    )
    .await;
    fails(
        &seq,
        &l,
        &["UPDATE work.item_head SET version = 2, last_pos = 0"],
        Some("23514"),
    )
    .await;
    fails(
        &seq,
        &l,
        &["UPDATE work.item_head SET item_kind = 'condition'"],
        Some("42501"),
    )
    .await;
}

// OP-12 OP-8 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_12_only_the_archive_role_drops_a_cold_partition_whose_copy_matches() {
    let (env, l) = seeded().await;
    let m = hex(&M);
    run(
        &env.canonical("work_owner"),
        &l,
        &["SELECT work.ensure_monthly_partitions('work.idempotency_key', 4, 0)"],
    )
    .await;
    let old = "(date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' - interval '3 months' + interval '1 day')";
    let seq = env.canonical("work_sequencer");
    for scope in [&l, &m] {
        let row = format!(
            "INSERT INTO work.idempotency_key (ledger_id, caller_ref, idem_key, request_digest, outcome, reason, created_at) \
             VALUES (decode('{scope}', 'hex'), 'party:bob', 'req-old', decode(repeat('78', 32), 'hex'), 'rejected', 'conflict', {old})"
        );
        run(&seq, scope, &[&row]).await;
    }
    let mut admin = env.admin(Cluster::Canonical).await;
    let part: String = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT c.oid::regclass::text FROM pg_inherits h JOIN pg_class c ON c.oid = h.inhrelid \
         WHERE h.inhparent = 'work.idempotency_key'::regclass \
         AND c.relname = 'idempotency_key_p' || to_char({old} AT TIME ZONE 'UTC', 'YYYYMM')"
    )))
    .fetch_one(&mut admin)
    .await
    .unwrap();
    let hot: String = sqlx::query_scalar(
        "SELECT c.oid::regclass::text FROM pg_inherits h JOIN pg_class c ON c.oid = h.inhrelid \
         WHERE h.inhparent = 'work.idempotency_key'::regclass ORDER BY c.relname DESC LIMIT 1",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    let archive = env.canonical("work_archive");
    let mut lines = Vec::new();
    for scope in [&l, &m] {
        let mut tx = archive.begin().await.unwrap();
        sqlx::query("SELECT set_config('app.ledger_id', $1, true)")
            .bind(scope)
            .execute(&mut *tx)
            .await
            .unwrap();
        let (n, digest): (i64, String) = sqlx::query_as(
            "SELECT row_count, encode(slice_digest, 'hex') FROM work.partition_slice($1::regclass)",
        )
        .bind(&part)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        lines.push(format!("{scope}:{n}:{digest}"));
    }
    lines.sort();
    let manifest = |lines: &[String]| {
        format!(
            "SELECT work.drop_archived_partition('{part}', sha256(convert_to('{}', 'UTF8'))::ledger.digest32)",
            lines.join("\n")
        )
    };
    let only_l = manifest(&lines[..1]);
    let full = manifest(&lines);
    fails(&archive, &l, &[&only_l], Some("22000")).await;
    fails(&seq, &l, &[&full], Some("42501")).await;
    fails(&env.canonical("work_app"), &l, &[&full], Some("42501")).await;
    let hot_drop = full.replace(&format!("'{part}'"), &format!("'{hot}'"));
    fails(&archive, &l, &[&hot_drop], Some("55006")).await;
    assert_eq!(scalar(&archive, &l, &full, true).await, 2);
    let gone: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
        .bind(&part)
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(gone, None);
    assert_eq!(
        scalar(
            &env.canonical("work_app"),
            &l,
            "SELECT count(*) FROM work.idempotency_key",
            false
        )
        .await,
        1
    );
}
