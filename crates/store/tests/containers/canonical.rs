use std::time::Duration;

use sqlx::AssertSqlSafe;
use suiss_retention::{Class, Hold, HoldId, HoldKind, HoldScope, SubjectId, TenantId, Timestamp};
use work_store::{
    ClassDek, Cluster, Erased, ErasureCause, ErasurePool, ErasureState, ErasureTarget, LedgerId,
    LedgerTx, RetentionClass, Shred, StoreError,
};

use crate::env::{Env, L, M, fails, hex, run, scalar, with_ledgers};

const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

const SEED: &str = "
INSERT INTO ledger.head (ledger_id, pos, epoch, frontier) VALUES (decode('{L}', 'hex'), -1, 0, '\\x');
INSERT INTO work.ledger_profile VALUES (decode('{L}', 'hex'), 'single-node');
INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes, envelope_bytes)
VALUES (decode('{L}', 'hex'), 0, 0, decode(repeat('01', 32), 'hex'), '2026-10-23T10:00:00.123Z',
        NULL, decode(repeat('11', 32), 'hex'), '\\xd2', '\\xa0');
INSERT INTO work.received_bytes (ledger_id, digest, kind, bytes, first_pos)
VALUES (decode('{L}', 'hex'), pg_catalog.sha256('\\xd28440a0f640'), 'cose_sign1', '\\xd28440a0f640', 0);
INSERT INTO work.record_header (
    ledger_id, pos, kind, record_type, author, author_actor_type, author_actor_type_source,
    occurred_at, ingest, proof_commit, protocol_major, protocol_minor, schema_digest)
VALUES (
    decode('{L}', 'hex'), 0, 'declaration', 'https://suiss.app/ns/work/declaration/request', 'party:alice',
    'human', 'access_binding', NULL, 'admitted', pg_catalog.sha256('\\xd28440a0f640'), 1, 0,
    decode(repeat('33', 32), 'hex'));
INSERT INTO work.log_received VALUES (decode('{L}', 'hex'), 0, 'author_signature', pg_catalog.sha256('\\xd28440a0f640'));
INSERT INTO work.work_root VALUES (decode('{L}', 'hex'), '01890a5d-ac96-774b-bcce-b302099a8057', 0);
INSERT INTO work.log_concerns VALUES (decode('{L}', 'hex'), '01890a5d-ac96-774b-bcce-b302099a8057', 0);
INSERT INTO work.body_commitment VALUES (decode('{L}', 'hex'), 0, 'note', decode(repeat('44', 32), 'hex'));
INSERT INTO work.body_dek (ledger_id, subject_ref, retention_class, kek_id, wrapped_key, state)
VALUES (decode('{L}', 'hex'), 'party:alice', 'work_record', 'work.{L}.kek.v1', decode(repeat('a1', 40), 'hex'), 'active');
INSERT INTO work.body_part (ledger_id, pos, part, dek_id, retention_class, storage, nonce, ciphertext, ciphertext_digest)
SELECT decode('{L}', 'hex'), 0, 'note', dek_id, 'work_record', 'inline', decode(repeat('55', 12), 'hex'), '\\xdeadbeef',
       decode(repeat('66', 32), 'hex')
  FROM work.body_dek WHERE kek_id = 'work.{L}.kek.v1';
INSERT INTO work.body_commitment VALUES (decode('{L}', 'hex'), 0, 'attachment', decode(repeat('45', 32), 'hex'));
INSERT INTO work.body_part (ledger_id, pos, part, dek_id, retention_class, storage, nonce, object_key, ciphertext_digest)
SELECT decode('{L}', 'hex'), 0, 'attachment', dek_id, 'work_record', 'object_store', decode(repeat('56', 12), 'hex'),
       'ab/0/attachment', decode(repeat('67', 32), 'hex')
  FROM work.body_dek WHERE kek_id = 'work.{L}.kek.v1';
INSERT INTO work.body_part_key (ledger_id, pos, part, wrapped_key)
VALUES (decode('{L}', 'hex'), 0, 'note', decode(repeat('b1', 40), 'hex')),
       (decode('{L}', 'hex'), 0, 'attachment', decode(repeat('b2', 40), 'hex'));
INSERT INTO work.item_head (ledger_id, item_kind, item_id, version, last_pos, heads)
VALUES (decode('{L}', 'hex'), 'commitment', decode(repeat('01', 32), 'hex'), 1, 0,
        ARRAY[decode(repeat('01', 32), 'hex')]::ledger.digest32[]);
INSERT INTO work.idempotency_key (ledger_id, caller_ref, idem_key, request_digest, outcome, result_pos, result_record_id)
VALUES (decode('{L}', 'hex'), 'party:alice', 'req-1', decode(repeat('77', 32), 'hex'), 'recorded', 0,
        decode(repeat('01', 32), 'hex'));
INSERT INTO work.inbound_seen (ledger_id, source, source_id, content_digest, result_pos)
VALUES (decode('{L}', 'hex'), 'https://peer.example/ledgers/x', 'evt-9', decode(repeat('79', 32), 'hex'), 0);
INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version)
VALUES (decode('{L}', 'hex'), 0, 'evt-0', 'commitment.requested', '{T}', 'commitment', decode(repeat('01', 32), 'hex'), 1),
       (decode('{L}', 'hex'), 0, 'evt-1', 'work.opened', '{T}', 'work', decode('01890a5dac96774bbcceb302099a8057', 'hex'), 1);
UPDATE ledger.head
   SET pos = 0, head_leaf = decode(repeat('11', 32), 'hex'), head_recorded_at = '2026-10-23T10:00:00.123Z',
       frontier = decode(repeat('11', 32), 'hex')
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
    for (cluster, applied) in [(Cluster::Canonical, 24), (Cluster::Derived, 7)] {
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
                "UPDATE ledger.head SET pos = 1, head_leaf = decode(repeat('12', 32), 'hex'), head_recorded_at = '{ok}', \
                 frontier = decode(repeat('5b', 32), 'hex') \
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
            "INSERT INTO ledger.head (ledger_id, pos, epoch, frontier) VALUES (decode(repeat('ab', 32), 'hex'), -1, 0, '\\x')",
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
        (
            "work_sequencer",
            "UPDATE work.received_bytes SET kind = 'foreign_record'",
        ),
        ("work_sequencer", "DELETE FROM work.log_received"),
        (
            "work_app",
            "INSERT INTO work.log_received SELECT * FROM work.log_received",
        ),
    ];
    for (role, stmt) in cases {
        fails(&env.canonical(role), &l, &[stmt], Some("42501")).await;
    }
}

// T-90 P-5 P-75
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_90_received_bytes_match_their_digest_and_bind_the_proof_commit() {
    let (env, l) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let received = |digest: &str, kind: &str, bytes: &str| {
        sql(&format!(
            "INSERT INTO work.received_bytes (ledger_id, digest, kind, bytes, first_pos) \
             VALUES (decode('{{L}}', 'hex'), {digest}, '{kind}', {bytes}, 0)"
        ))
    };
    let mismatched = received("decode(repeat('00', 32), 'hex')", "cose_sign1", "'\\xd2'");
    fails(&seq, &l, &[&mismatched], Some("23514")).await;
    let empty = received("pg_catalog.sha256('\\x')", "cose_sign1", "'\\x'");
    fails(&seq, &l, &[&empty], Some("23514")).await;
    let unknown = received("pg_catalog.sha256('\\xd2')", "jwt", "'\\xd2'");
    fails(&seq, &l, &[&unknown], Some("23514")).await;
    let large = received(
        "pg_catalog.sha256(pg_catalog.decode(repeat('ab', 262145), 'hex'))",
        "foreign_record",
        "pg_catalog.decode(repeat('ab', 262145), 'hex')",
    );
    fails(&seq, &l, &[&large], Some("23514")).await;
    let again = sql(
        "INSERT INTO work.received_bytes (ledger_id, digest, kind, bytes, first_pos) \
         VALUES (decode('{L}', 'hex'), pg_catalog.sha256('\\xd28440a0f640'), 'cose_sign1', \
         '\\xd28440a0f640', 0) ON CONFLICT (ledger_id, digest) DO NOTHING",
    );
    run(&seq, &l, &[&again]).await;
    let count = "SELECT count(*) FROM work.received_bytes";
    assert_eq!(scalar(&seq, &l, count, false).await, 1);
    let unbound = sql(
        "INSERT INTO work.log_received VALUES (decode('{L}', 'hex'), 0, 'auth_context', \
         decode(repeat('00', 32), 'hex'))",
    );
    fails(&seq, &l, &[&unbound], Some("23503")).await;
    let link = |role: &str| {
        sql(&format!(
            "INSERT INTO work.log_received VALUES (decode('{{L}}', 'hex'), 0, '{role}', \
             pg_catalog.sha256('\\xd28440a0f640'))"
        ))
    };
    fails(&seq, &l, &[&link("notary_signature")], Some("23514")).await;
    run(&seq, &l, &[&link("presenter_signature")]).await;
    let header = sql("INSERT INTO work.record_header ( \
             ledger_id, pos, kind, record_type, author, author_actor_type, author_actor_type_source, \
             occurred_at, ingest, proof_commit, protocol_major, protocol_minor, schema_digest) \
         VALUES (decode('{L}', 'hex'), 1, 'claim', 'https://suiss.app/ns/work/claim/observation', \
             'party:bob', 'agent', 'access_binding', '2026-10-23T10:00:01Z', 'admitted', \
             decode(repeat('22', 32), 'hex'), 1, 0, decode(repeat('33', 32), 'hex'))");
    let row = log_row(1, "11", "2026-10-23T10:00:05Z");
    fails(&seq, &l, &[&row, &header], Some("23503")).await;
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
        &["INSERT INTO ledger.head (ledger_id, pos, epoch, frontier) VALUES (decode(repeat('cd', 32), 'hex'), -1, 0, '\\x')"],
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

// OP-4 OP-46 P-20 Access T21 Access TI-13
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
        &[&sql("INSERT INTO ledger.checkpoint VALUES (decode('{L}', 'hex'), 1, decode(repeat('88', 32), 'hex'), decode(repeat('11', 32), 'hex'), '2026-10-23T10:00:01Z', \
                 pg_catalog.convert_to('work.example/ledger/{L}\n1\niIiI\ndurability single-node\ntime_sources dependent\nwitness independent 2\n\n\u{2014} work.example AAAA\n', 'UTF8'))")],
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
    assert_eq!(scalar(&app, &l, durability, false).await, 1);
    run(
        &cp,
        &l,
        &[&sql("INSERT INTO ledger.checkpoint_cosignature VALUES (decode('{L}', 'hex'), 1, 'witness_b', 'witness', '2026-10-23T10:00:03Z', '\\x02')")],
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
    let item = |pos: u8, id: &str, ty: &str, trace: &str, item: &str| {
        sql(&format!(
            "INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version) \
             VALUES (decode('{{L}}', 'hex'), {pos}, '{id}', '{ty}', '{trace}', {item})"
        ))
    };
    let commitment = "'commitment', decode(repeat('01', 32), 'hex'), 1";
    let pointer = |pos: u8, id: &str, ty: &str, trace: &str| item(pos, id, ty, trace, commitment);
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

// T-81 P-29 T-17 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_81_outbox_rows_name_one_checked_item_and_its_version() {
    let (env, l) = seeded().await;
    let seq = env.canonical("work_sequencer");
    let item = |pos: u8, id: &str, ty: &str, trace: &str, item: &str| {
        sql(&format!(
            "INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version) \
             VALUES (decode('{{L}}', 'hex'), {pos}, '{id}', '{ty}', '{trace}', {item})"
        ))
    };
    for bad in [
        "'gate', decode(repeat('01', 32), 'hex'), 1",
        "'work', decode(repeat('01', 32), 'hex'), 1",
        "'commitment', decode(repeat('01', 16), 'hex'), 1",
        "'commitment', decode(repeat('01', 32), 'hex'), 0",
    ] {
        fails(
            &seq,
            &l,
            &[&item(0, "evt-5", "commitment.requested", TRACE, bad)],
            Some("23514"),
        )
        .await;
    }
    fails(
        &seq,
        &l,
        &[&sql(
            "INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent) \
             VALUES (decode('{L}', 'hex'), 0, 'evt-6', 'commitment.requested', '{T}')",
        )],
        Some("23502"),
    )
    .await;
    run(
        &seq,
        &l,
        &[
            &item(
                0,
                "evt-7",
                "commitment.requested",
                TRACE,
                "'condition', decode(repeat('03', 32), 'hex'), 1",
            ),
            &item(
                0,
                "evt-8",
                "commitment.requested",
                TRACE,
                "'commitment', decode(repeat('02', 32), 'hex'), 4",
            ),
        ],
    )
    .await;
    let publisher = env.canonical("work_publisher");
    let rows = "SELECT count(*) FROM ledger.outbox WHERE ledger_id = ledger.current_ledger_id() AND pos = 0";
    assert_eq!(scalar(&publisher, &l, rows, false).await, 4);
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
        &[&sql("INSERT INTO work.retention_hold \
                (ledger_id, hold_id, hold_kind, scope, subject_ref, placed_at, state) \
                VALUES (decode('{L}', 'hex'), 'hld_1', 'litigation', 'subject', 'party:alice', \
                now(), 'active')")],
    )
    .await;
    let destroy =
        "UPDATE work.body_dek SET wrapped_key = NULL, state = 'destroyed', destroyed_at = now()";
    fails(&erasure, &l, &[destroy], Some("23514")).await;
    let completed = sql(
        "INSERT INTO work.erasure_log (ledger_id, dek_id, cause, state, settles_at, completed_at) \
         SELECT decode('{L}', 'hex'), dek_id, 'subject_request', 'completed', now(), now() \
           FROM work.body_dek",
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
        &[&sql(
            "UPDATE work.body_dek SET wrapped_key = decode(repeat('a1', 40), 'hex'), \
             state = 'active', destroyed_at = NULL",
        )],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &["UPDATE work.body_dek SET subject_ref = 'party:bob'"],
        Some("42501"),
    )
    .await;
}

// OP-45 OP-12 OP-15 P-25 Access OP-74 Access OP-78
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_45_a_part_key_is_shredded_once_and_never_under_a_hold() {
    let (env, l) = seeded().await;
    let erasure = env.canonical("work_erasure");
    let seq = env.canonical("work_sequencer");
    let shred = "UPDATE work.body_part_key SET wrapped_key = NULL, shredded_at = now() \
                 WHERE part = 'note'";
    let hold = sql("INSERT INTO work.retention_hold \
         (ledger_id, hold_id, hold_kind, scope, retention_classes, placed_at, state) \
         VALUES (decode('{L}', 'hex'), 'hld_2', 'regulator', 'classes', \
         ARRAY['work_record']::work.snake_name[], now(), 'active')");
    run(&erasure, &l, &[&hold]).await;
    fails(&erasure, &l, &[shred], Some("23514")).await;
    run(
        &erasure,
        &l,
        &["UPDATE work.retention_hold SET state = 'released', released_at = now()"],
    )
    .await;
    fails(
        &seq,
        &l,
        &["UPDATE work.body_part_key SET wrapped_key = NULL, shredded_at = now()"],
        Some("42501"),
    )
    .await;
    let early = sql("INSERT INTO work.erasure_log \
         (ledger_id, dek_id, cause, state, settles_at, completed_at, pos, part, request_pos) \
         SELECT decode('{L}', 'hex'), dek_id, 'redaction', 'completed', now(), now(), 0, 'note', 0 \
           FROM work.body_dek");
    fails(&erasure, &l, &[&early], Some("23514")).await;
    run(&erasure, &l, &[shred, &early]).await;
    fails(&erasure, &l, &[shred], Some("23514")).await;
    fails(
        &erasure,
        &l,
        &[&sql(
            "UPDATE work.body_part_key SET wrapped_key = decode(repeat('b1', 40), 'hex'), \
             shredded_at = NULL WHERE part = 'note'",
        )],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &[
            "UPDATE work.body_part_key SET wrapped_key = '\\x00', shredded_at = NULL \
           WHERE part = 'attachment'",
        ],
        Some("23514"),
    )
    .await;
    let n = scalar(
        &erasure,
        &l,
        "SELECT count(*) FROM work.body_part_key WHERE wrapped_key IS NULL",
        false,
    )
    .await;
    assert_eq!(n, 1);
    let part = scalar(
        &erasure,
        &l,
        "SELECT count(*) FROM work.body_part WHERE ciphertext IS NOT NULL",
        false,
    )
    .await;
    assert_eq!(part, 1);
}

// OP-45 OP-12 OP-15 P-25 Access OP-74 Access OP-78 Access CR-32
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
#[allow(
    clippy::too_many_lines,
    reason = "one erasure from the hold through the shred to its completion"
)]
async fn op_45_an_erasure_waits_on_a_hold_and_completes_only_after_it_settles() {
    let (env, l) = seeded().await;
    let erasure = env.canonical("work_erasure");
    let pool = ErasurePool::new(erasure.clone()).await.unwrap();
    let ledger = LedgerId::from_bytes(L);
    let subject = "party:alice";
    let class = RetentionClass::WorkRecord;
    let hour = Duration::from_hours(1);
    run(
        &erasure,
        &l,
        &[&sql("INSERT INTO work.retention_hold \
             (ledger_id, hold_id, hold_kind, scope, subject_ref, placed_at, state) \
             VALUES (decode('{L}', 'hex'), 'hld_3', 'litigation', 'subject', 'party:alice', \
             now(), 'active')")],
    )
    .await;
    let part_id = match pool.shred_part(&ledger, 0, 0, "note", hour).await.unwrap() {
        Erased::Held { erasure_id } => erasure_id,
        other => panic!("{other:?}"),
    };
    let again = pool.shred_part(&ledger, 0, 0, "note", hour).await.unwrap();
    assert_eq!(
        again,
        Erased::Held {
            erasure_id: part_id.clone(),
        }
    );
    let held = pool
        .destroy_dek(&ledger, subject, class, Shred::SubjectErasure, hour)
        .await
        .unwrap();
    let class_id = match held {
        Erased::Held { erasure_id } => erasure_id,
        other => panic!("{other:?}"),
    };
    let rows = pool.erasures(&ledger).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.state == ErasureState::WaitingOnHold));
    assert_eq!(rows[0].cause, ErasureCause::Redaction);
    assert_eq!(
        rows[0].target,
        ErasureTarget::Part {
            pos: 0,
            part: "note".to_owned(),
        }
    );
    assert_eq!(rows[1].cause, ErasureCause::SubjectRequest);
    assert_eq!(rows[1].target, ErasureTarget::Class);
    let gone = "SELECT count(*) FROM work.body_part_key WHERE wrapped_key IS NULL";
    assert_eq!(scalar(&erasure, &l, gone, false).await, 0);
    run(
        &erasure,
        &l,
        &["UPDATE work.retention_hold SET state = 'released', released_at = now()"],
    )
    .await;
    let shredded = pool.shred_part(&ledger, 0, 0, "note", hour).await.unwrap();
    let (erasure_id, settles_at_ms) = match shredded {
        Erased::Shredded {
            erasure_id,
            settles_at_ms,
            ..
        } => (erasure_id, settles_at_ms),
        other => panic!("{other:?}"),
    };
    assert_eq!(erasure_id, part_id);
    assert_eq!(scalar(&erasure, &l, gone, false).await, 1);
    assert_eq!(pool.settle(&ledger).await.unwrap(), Vec::<String>::new());
    let twice = pool.shred_part(&ledger, 0, 0, "note", hour).await.unwrap();
    assert_eq!(twice, Erased::Nothing);
    let destroyed = pool
        .destroy_dek(
            &ledger,
            subject,
            class,
            Shred::SubjectErasure,
            Duration::ZERO,
        )
        .await
        .unwrap();
    let (erasure_id, key) = match destroyed {
        Erased::Shredded {
            erasure_id, key, ..
        } => (erasure_id, key),
        other => panic!("{other:?}"),
    };
    assert_eq!(erasure_id, class_id);
    assert!(key.wrapped.is_some());
    assert_eq!(pool.settle(&ledger).await.unwrap(), vec![class_id]);
    let rows = pool.erasures(&ledger).await.unwrap();
    assert_eq!(rows[0].state, ErasureState::Shredded { settles_at_ms });
    let (settled, completed_at_ms) = match rows[1].state {
        ErasureState::Completed {
            settles_at_ms,
            completed_at_ms,
        } => (settles_at_ms, completed_at_ms),
        other => panic!("{other:?}"),
    };
    assert!(completed_at_ms >= settled);
    assert!(rows[0].requested_at_ms.saturating_add(3_600_000) <= settles_at_ms);
    let none = pool
        .destroy_dek(&ledger, subject, class, Shred::SubjectErasure, hour)
        .await
        .unwrap();
    assert_eq!(none, Erased::Nothing);
    assert_eq!(pool.settle(&ledger).await.unwrap(), Vec::<String>::new());
    fails(
        &erasure,
        &l,
        &[
            "UPDATE work.erasure_log SET state = 'completed', completed_at = now() \
           WHERE state = 'shredded'",
        ],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &["UPDATE work.erasure_log SET settles_at = now() WHERE state = 'shredded'"],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &[
            "UPDATE work.erasure_log SET state = 'shredded', completed_at = NULL \
           WHERE state = 'completed'",
        ],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &[&sql(
            "INSERT INTO work.erasure_log (ledger_id, dek_id, cause, state, settles_at) \
             SELECT decode('{L}', 'hex'), dek_id, 'subject_request', 'waiting_on_hold', now() \
               FROM work.body_dek",
        )],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &[&sql("INSERT INTO work.erasure_log \
             (ledger_id, dek_id, cause, state, settles_at, pos, part) \
             SELECT decode('{L}', 'hex'), dek_id, 'redaction', 'shredded', now(), 0, 'attachment' \
               FROM work.body_dek")],
        Some("23514"),
    )
    .await;
}

// P-111 OP-45 P-25
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_111_a_redaction_names_its_request_and_is_written_once() {
    let (env, l) = seeded().await;
    let erasure = env.canonical("work_erasure");
    let pool = ErasurePool::new(erasure.clone()).await.unwrap();
    let ledger = LedgerId::from_bytes(L);
    let hour = Duration::from_hours(1);
    let insert = |cause: &str, request: &str| {
        sql(&format!(
            "INSERT INTO work.erasure_log \
             (ledger_id, dek_id, cause, state, pos, part, request_pos) \
             SELECT decode('{{L}}', 'hex'), dek_id, '{cause}', 'waiting_on_hold', 0, 'note', \
             {request} FROM work.body_dek"
        ))
    };
    fails(&erasure, &l, &[&insert("redaction", "NULL")], Some("23514")).await;
    fails(
        &erasure,
        &l,
        &[&insert("subject_request", "0")],
        Some("23514"),
    )
    .await;
    let shredded = pool.shred_part(&ledger, 0, 0, "note", hour).await.unwrap();
    assert!(matches!(shredded, Erased::Shredded { .. }), "{shredded:?}");
    let again = pool.shred_part(&ledger, 0, 0, "note", hour).await.unwrap();
    assert_eq!(again, Erased::Nothing);
    let rows = pool.erasures(&ledger).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_pos, Some(0));
    assert_eq!(rows[0].cause, ErasureCause::Redaction);
    fails(&erasure, &l, &[&insert("redaction", "0")], Some("23505")).await;
}

// OP-45 OP-12 Access OP-74
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_45_a_rewrap_changes_only_the_kek_and_the_wrapped_key_together() {
    let (env, l) = seeded().await;
    let erasure = env.canonical("work_erasure");
    let seq = env.canonical("work_sequencer");
    fails(
        &erasure,
        &l,
        &[&sql("UPDATE work.body_dek SET kek_id = 'work.{L}.kek.v2'")],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &["UPDATE work.body_dek SET wrapped_key = decode(repeat('a2', 40), 'hex')"],
        Some("23514"),
    )
    .await;
    fails(
        &erasure,
        &l,
        &["UPDATE work.body_dek SET kek_id = 'hsm-label', \
           wrapped_key = decode(repeat('a2', 40), 'hex')"],
        Some("23514"),
    )
    .await;
    run(
        &erasure,
        &l,
        &[&sql(
            "UPDATE work.body_dek SET kek_id = 'work.{L}.kek.v2', \
             wrapped_key = decode(repeat('a2', 40), 'hex')",
        )],
    )
    .await;
    fails(
        &seq,
        &l,
        &[&sql(
            "INSERT INTO work.body_dek (ledger_id, subject_ref, retention_class, kek_id, \
             wrapped_key, state) VALUES (decode('{L}', 'hex'), 'party:bob', 'work_record', \
             'work.{L}.kek.v2', decode(repeat('a3', 39), 'hex'), 'active')",
        )],
        Some("23514"),
    )
    .await;
    run(
        &erasure,
        &l,
        &[
            "UPDATE work.body_dek SET wrapped_key = NULL, state = 'destroyed', \
           destroyed_at = now()",
        ],
    )
    .await;
    fails(
        &seq,
        &l,
        &[
            &sql(
                "INSERT INTO work.body_commitment VALUES (decode('{L}', 'hex'), 0, 'late', \
                 decode(repeat('46', 32), 'hex'))",
            ),
            &sql(
                "INSERT INTO work.body_part (ledger_id, pos, part, dek_id, retention_class, \
                 storage, nonce, ciphertext, ciphertext_digest) \
                 SELECT decode('{L}', 'hex'), 0, 'late', dek_id, 'work_record', 'inline', \
                 decode(repeat('57', 12), 'hex'), '\\xbeef', decode(repeat('68', 32), 'hex') \
                 FROM work.body_dek",
            ),
        ],
        Some("23514"),
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

/// The ledger of a `<ledger hex>:<rows>:<digest hex>` manifest line and the insert of the archive
/// record of its slice of `part` (OP-35).
fn archive_record(line: &str, part: &str) -> (String, String) {
    let mut fields = line.split(':');
    let (scope, n, digest) = (
        fields.next().unwrap().to_owned(),
        fields.next().unwrap().to_owned(),
        fields.next().unwrap().to_owned(),
    );
    let insert = format!(
        "INSERT INTO work.partition_archive (ledger_id, cold_partition, object_key, copy_digest, row_count) \
         VALUES (decode('{scope}', 'hex'), '{part}', 'archive/{part}/{scope}', decode('{digest}', 'hex'), {n})"
    );
    (scope, insert)
}

// OP-12 OP-8 OP-35 Access OP-73
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
    fails(&archive, &l, &[&full], Some("22000")).await;
    let (first, insert) = archive_record(&lines[0], &part);
    run(&archive, &first, &[&insert]).await;
    fails(&archive, &l, &[&full], Some("22000")).await;
    fails(&seq, &first, &[&insert], Some("42501")).await;
    let (second, insert) = archive_record(&lines[1], &part);
    run(&archive, &second, &[&insert]).await;
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

// OP-38 OP-35 OP-36 OP-32
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_38_a_partition_is_cold_only_30_days_and_u_after_its_range_ends() {
    let env = Env::start().await;
    let l = hex(&L);
    let archive = env.canonical("work_archive");
    for (as_of, cold) in [
        ("2026-12-01T00:00:00Z", 0),
        ("2026-12-01T00:00:00.249Z", 0),
        ("2026-12-01T00:00:00.250Z", 1),
        ("2026-12-01T00:00:01Z", 1),
    ] {
        let query = format!(
            "SELECT work.partition_is_cold('2026-11-01T00:00:00Z', '{as_of}')::int::bigint"
        );
        assert_eq!(scalar(&archive, &l, &query, false).await, cold, "{as_of}");
    }
    let judged = "SELECT count(*) FROM pg_catalog.pg_proc p \
                  WHERE p.pronamespace = 'work'::regnamespace \
                  AND p.proname IN ('drop_archived_partition', 'partition_ledgers') \
                  AND p.prosrc LIKE '%work.partition_is_cold(upper_bound, now())%' \
                  AND p.prosrc NOT LIKE '%30 days%'";
    let owner = env.canonical("work_owner");
    assert_eq!(scalar(&owner, &l, judged, false).await, 2);
}

fn access_hold(id: &str, scope: HoldScope, placed_at: u64, until: Option<u64>) -> Hold {
    Hold {
        id: HoldId::new(id),
        tenant: TenantId::new("tnt_acme"),
        scope,
        placed_at: Timestamp::from_unix_millis(placed_at),
        until: until.map(Timestamp::from_unix_millis),
        kind: HoldKind::Regulator,
        suspicious_activity: true,
    }
}

// OP-14 OP-12 OP-45 Access OP-74 Access OP-147
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
#[allow(
    clippy::too_many_lines,
    reason = "one hold cache from the first write through the lift to the expiry it allows"
)]
async fn op_14_the_hold_cache_keeps_what_access_sent_and_expiry_waits_on_it() {
    let (env, l) = seeded().await;
    let erasure = env.canonical("work_erasure");
    let pool = ErasurePool::new(erasure.clone()).await.unwrap();
    let ledger = LedgerId::from_bytes(L);
    let tenant = TenantId::new("tnt_acme");
    let hour = Duration::from_hours(1);
    let bob = access_hold(
        "hld_bob",
        HoldScope::Subject(SubjectId::new("party:bob")),
        1,
        None,
    );
    let classes = access_hold(
        "hld_classes",
        HoldScope::Classes(vec![Class::WorkRecord, Class::Ledger]),
        2,
        None,
    );
    for h in [&bob, &classes, &bob, &classes] {
        pool.cache_hold(&ledger, h).await.unwrap();
    }
    assert_eq!(
        pool.holds(&ledger, &tenant).await.unwrap(),
        vec![bob.clone(), classes.clone()]
    );
    let listed = pool.class_deks(&ledger, None, 10).await.unwrap();
    assert_eq!(listed.len(), 1);
    let dek = listed[0].clone();
    assert_eq!(dek.subject, "party:alice");
    assert_eq!(dek.class, RetentionClass::WorkRecord);
    assert_eq!(dek.newest_ms, Some(1_792_749_600_123));
    assert_eq!(
        pool.class_deks(&ledger, Some(&dek.dek_id), 10)
            .await
            .unwrap(),
        Vec::new()
    );
    assert_eq!(
        pool.expire_dek(&ledger, &dek, hour).await.unwrap(),
        Erased::Nothing
    );
    assert_eq!(pool.erasures(&ledger).await.unwrap(), Vec::new());
    let lifted = Hold {
        until: Some(Timestamp::from_unix_millis(3)),
        ..classes.clone()
    };
    pool.cache_hold(&ledger, &lifted).await.unwrap();
    pool.cache_hold(&ledger, &lifted).await.unwrap();
    assert_eq!(
        pool.holds(&ledger, &tenant).await.unwrap(),
        vec![bob.clone(), lifted.clone()]
    );
    for refused in [
        Hold {
            scope: HoldScope::Tenant,
            ..lifted.clone()
        },
        Hold {
            kind: HoldKind::Litigation,
            ..lifted.clone()
        },
        Hold {
            until: Some(Timestamp::from_unix_millis(4)),
            ..lifted.clone()
        },
        classes.clone(),
    ] {
        assert!(
            matches!(
                pool.cache_hold(&ledger, &refused).await,
                Err(StoreError::Constraint(_))
            ),
            "{refused:?}"
        );
    }
    let stale = ClassDek {
        newest_ms: Some(0),
        ..dek.clone()
    };
    assert_eq!(
        pool.expire_dek(&ledger, &stale, hour).await.unwrap(),
        Erased::Nothing
    );
    let everything = access_hold("hld_tenant", HoldScope::Tenant, 5, None);
    pool.cache_hold(&ledger, &everything).await.unwrap();
    assert_eq!(
        pool.expire_dek(&ledger, &dek, hour).await.unwrap(),
        Erased::Nothing
    );
    let gone = "SELECT count(*) FROM work.body_dek WHERE state = 'destroyed'";
    assert_eq!(scalar(&erasure, &l, gone, false).await, 0);
    pool.cache_hold(
        &ledger,
        &Hold {
            until: Some(Timestamp::from_unix_millis(6)),
            ..everything
        },
    )
    .await
    .unwrap();
    let Erased::Shredded { erasure_id, .. } = pool.expire_dek(&ledger, &dek, hour).await.unwrap()
    else {
        panic!("not shredded")
    };
    assert_eq!(scalar(&erasure, &l, gone, false).await, 1);
    let rows = pool.erasures(&ledger).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].erasure_id, erasure_id);
    assert_eq!(rows[0].cause, ErasureCause::RetentionExpired);
    assert_eq!(rows[0].target, ErasureTarget::Class);
    assert!(matches!(rows[0].state, ErasureState::Shredded { .. }));
    let tombstones =
        "SELECT count(*) FROM work.body_part_tombstone WHERE cause = 'retention_expired'";
    assert_eq!(scalar(&erasure, &l, tombstones, false).await, 2);
    assert_eq!(
        pool.class_deks(&ledger, None, 10).await.unwrap(),
        Vec::new()
    );
    assert_eq!(
        pool.expire_dek(&ledger, &dek, hour).await.unwrap(),
        Erased::Nothing
    );
    let held = sql(
        "SELECT count(*) WHERE work.retention_held(decode('{L}', 'hex'), 'party:carol', 'agent_trace')",
    );
    assert_eq!(scalar(&erasure, &l, &held, false).await, 0);
    let malformed = access_hold("hld_empty", HoldScope::Classes(vec![]), 7, Some(8));
    pool.cache_hold(&ledger, &malformed).await.unwrap();
    assert_eq!(scalar(&erasure, &l, &held, false).await, 1);
}
