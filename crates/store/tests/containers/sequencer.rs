use sqlx::{AssertSqlSafe, Executor};
use work_store::{
    AppendBatch, AppendError, CallerRef, CellId, ClaimAnswer, ClaimRow, Cluster, Delivery,
    DeliveryKind, Doorbell, Durability, ExecutorDeliveryRow, Expect, Genesis, HeaderRow,
    IdempotencyKey, InboundEvent, InboundRow, InboundSeen, ItemHeadRow, ItemRef, KeyRow, LedgerId,
    LedgerTx, LogRow, NewHead, OutboxRow, PublisherPool, ReceivedKind, ReceivedRole, ReceivedRow,
    Seat, SequencerPool, SingleUseRow, Skeleton, StoreError, StoredHead, StoredKey, StoredOutcome,
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

fn cell() -> CellId {
    CellId::new("cell-a").unwrap()
}

fn seat() -> Seat {
    Seat {
        cell: cell(),
        holder: [1; 16],
        lease_ms: 60_000,
    }
}

fn any(_: &[Vec<u8>]) -> bool {
    true
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
        received: vec![],
        skeleton: None,
        body: vec![],
        activation: false,
        signer: None,
        claims: vec![],
        deliveries: vec![],
        single_use: None,
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
            expect: Expect::Version(version.checked_sub(1).unwrap()),
            last_pos: pos,
            heads: Some(vec![leaf]),
        }],
        outbox: vec![OutboxRow {
            pos,
            event_id: format!("evt-{pos}"),
            event_type: "commitment.requested".to_owned(),
            traceparent: TRACE.to_owned(),
            item: ITEM,
        }],
        keys: vec![],
        inbound: vec![],
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
    seq.open_ledger(&genesis(L), &cell()).await.unwrap();
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
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
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
    let again = seq.acquire(&ledger, &seat(), any).await.unwrap();
    assert_eq!(again.epoch, 2);
    assert!(matches!(
        seq.open_ledger(&genesis(L), &cell()).await,
        Err(StoreError::AlreadyOpened)
    ));
    assert!(matches!(
        seq.acquire(&LedgerId::from_bytes(M), &seat(), any).await,
        Err(StoreError::NotOpened)
    ));
    assert!(matches!(
        SequencerPool::new(env.canonical("work_publisher")).await,
        Err(StoreError::Role)
    ));
}

// P-110 OP-28 T-85
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_110_an_activation_is_a_batch_of_its_own_and_leadership_reads_every_activation() {
    let (env, seq) = opened().await;
    let l = hex(&L);
    let app = env.canonical("work_app");
    let activations = "SELECT count(*) FROM ledger.version_activation";
    assert_eq!(scalar(&app, &l, activations, false).await, 1);
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut mixed = batch(head.epoch, 0, 1);
    mixed.records[0].activation = true;
    mixed.records[0].envelope_bytes = mixed.records[0].record_bytes.clone();
    let refused = seq.append(&ledger, &mixed).await;
    assert!(matches!(
        refused,
        Err(AppendError::Refused(StoreError::Constraint(c))) if c == "activation_alone"
    ));
    let mut lone = mixed.clone();
    lone.items.clear();
    lone.outbox.clear();
    seq.append(&ledger, &lone).await.unwrap();
    assert_eq!(scalar(&app, &l, activations, false).await, 2);
    let header = "SELECT count(*) FROM work.record_header";
    assert_eq!(scalar(&app, &l, header, false).await, 0);
    let mut seen = Vec::new();
    let read = |a: &[Vec<u8>]| {
        seen = a.to_vec();
        true
    };
    seq.acquire(&ledger, &seat(), read).await.unwrap();
    assert_eq!(seen, [vec![0xa1, 0x01, 0x02], vec![0xd2]]);
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
    let lead = seq.acquire(&ledger, &seat(), any).await.unwrap();
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
    let next = seq.acquire(&ledger, &seat(), any).await.unwrap();
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
        seq.acquire(&LedgerId::from_bytes(L), &seat(), any).await,
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
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
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

const WORK: ItemRef = ItemRef::Work([0x0c; 16]);
const COSE: [u8; 6] = [0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40];
const CONTEXT: &[u8] = b"work-vector:access:auth-context:alice";

fn header() -> HeaderRow {
    HeaderRow {
        kind: "claim",
        record_type: "https://suiss.app/ns/work/claim/observation".to_owned(),
        author: "party:acme:alice".to_owned(),
        author_actor_type: "human",
        author_actor_type_source: "access_binding",
        occurred_at_ms: Some(AT),
        ingest: "admitted",
        ingest_reason: None,
        proof_commit: None,
        auth_context_ref: Some([0x5a; 32]),
        protocol: (1, 0),
        schema_digest: [0x33; 32],
    }
}

fn received(kind: ReceivedKind, role: ReceivedRole, bytes: &[u8]) -> ReceivedRow {
    ReceivedRow {
        kind,
        role,
        bytes: bytes.to_vec(),
    }
}

/// `n` records after `after`, each concerning [`WORK`] with an [`Expect::Next`] head and one
/// pointer, received with the authentication context.
fn works(epoch: u64, after: u64, n: u64) -> AppendBatch {
    let mut b = batch(epoch, after, 1);
    b.records.clear();
    b.items.clear();
    b.outbox.clear();
    let mut prev = if after == 0 {
        GENESIS_LEAF
    } else {
        leaf(after)
    };
    for k in 1..=n {
        let pos = plus(after, k);
        let mut r = record(pos, prev, leaf(pos), plus(AT, pos));
        r.received = vec![received(
            ReceivedKind::AccessAuthContext,
            ReceivedRole::AuthContext,
            CONTEXT,
        )];
        r.skeleton = Some(Skeleton {
            header: header(),
            concerns: vec![[0x0c; 16]],
            basis: vec![[0x0d; 32]],
            relations: vec![],
            body: vec![],
            notice: None,
        });
        prev = r.leaf;
        b.records.push(r);
        b.items.push(ItemHeadRow {
            item: WORK,
            expect: Expect::Next,
            last_pos: pos,
            heads: None,
        });
        b.outbox.push(OutboxRow {
            pos,
            event_id: format!("evt-{pos}"),
            event_type: "work.updated".to_owned(),
            traceparent: TRACE.to_owned(),
            item: WORK,
        });
    }
    let last = plus(after, n);
    b.head = NewHead {
        pos: last,
        leaf: leaf(last),
        recorded_at_ms: plus(AT, last),
        frontier: vec![[0x40; 32]; usize::try_from(plus(last, 1).count_ones()).unwrap()],
    };
    b
}

fn leaf(pos: u64) -> [u8; 32] {
    [0x30_u8.wrapping_add(u8::try_from(pos).unwrap()); 32]
}

// T-89 T-81 OP-7 P-29 C-34 OP-13
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_89_next_versions_follow_the_stored_head_and_feed_the_outbox() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let l = hex(&L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    seq.append(&ledger, &works(head.epoch, 0, 2)).await.unwrap();
    seq.append(&ledger, &works(head.epoch, 2, 1)).await.unwrap();
    let app = env.canonical("work_app");
    let item = "SELECT version * 10 + last_pos FROM work.item_head WHERE item_kind = 'work'";
    assert_eq!(scalar(&app, &l, item, false).await, 33);
    let publisher = env.canonical("work_publisher");
    let seqs = "SELECT sum(version * pos)::bigint FROM ledger.outbox WHERE item_kind = 'work'";
    assert_eq!(scalar(&publisher, &l, seqs, false).await, 14);
    let concerns = "SELECT count(*) FROM work.log_concerns";
    assert_eq!(scalar(&app, &l, concerns, false).await, 3);
    let root = "SELECT first_pos * 10 + count(*) OVER () FROM work.work_root";
    assert_eq!(scalar(&app, &l, root, false).await, 11);
    let headers = "SELECT count(*) FROM work.record_header WHERE ingest = 'admitted'";
    assert_eq!(scalar(&app, &l, headers, false).await, 3);
    let basis = "SELECT count(*) FROM work.log_basis";
    assert_eq!(scalar(&app, &l, basis, false).await, 3);
    let context = "SELECT count(*) FROM work.received_bytes WHERE kind = 'access_auth_context'";
    assert_eq!(scalar(&app, &l, context, false).await, 1);
    let links = "SELECT count(*) FROM work.log_received WHERE role = 'auth_context'";
    assert_eq!(scalar(&app, &l, links, false).await, 3);
}

// T-81 T-89
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_81_a_pointer_without_its_item_head_is_refused() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut b = works(head.epoch, 0, 1);
    b.items.clear();
    assert!(matches!(
        seq.append(&ledger, &b).await,
        Err(AppendError::Refused(StoreError::OutboxItem(WORK)))
    ));
    let log = "SELECT count(*) FROM ledger.log";
    assert_eq!(
        scalar(&env.canonical("work_app"), &hex(&L), log, false).await,
        1
    );
}

// T-90 P-5 P-75
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_90_received_bytes_read_back_as_received_and_a_proof_commit_needs_them() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut signed = works(head.epoch, 0, 1);
    signed.records[0].received.push(received(
        ReceivedKind::CoseSign1,
        ReceivedRole::AuthorSignature,
        &COSE,
    ));
    seq.append(&ledger, &signed).await.unwrap();
    let mut tx = work_store::LedgerTx::begin(&env.canonical("work_app"), &ledger)
        .await
        .unwrap();
    let entries = tx.entries(0, 10).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].cose_sign1, None);
    assert_eq!(entries[1].pos, 1);
    assert_eq!(entries[1].cose_sign1.as_deref(), Some(COSE.as_slice()));
    assert_eq!(entries[1].record_bytes, vec![0xd2]);

    let mut unbound = works(head.epoch, 1, 1);
    if let Some(s) = unbound.records[0].skeleton.as_mut() {
        s.header.proof_commit = Some([0x22; 32]);
    }
    assert!(matches!(
        seq.append(&ledger, &unbound).await,
        Err(AppendError::Refused(StoreError::Constraint(c))) if c == "record_header_proof_fk"
    ));
    let mut oversized = works(head.epoch, 1, 1);
    oversized.records[0].received = vec![received(
        ReceivedKind::ForeignRecord,
        ReceivedRole::FederatedSource,
        &[0xab; 262_145],
    )];
    assert!(matches!(
        seq.append(&ledger, &oversized).await,
        Err(AppendError::Refused(StoreError::Constraint(c))) if c == "received_bytes_length_ck"
    ));
    let mut presented = works(head.epoch, 1, 1);
    presented.records[0].received.push(received(
        ReceivedKind::CoseSign1,
        ReceivedRole::PresenterSignature,
        &COSE,
    ));
    seq.append(&ledger, &presented).await.unwrap();
    let app = env.canonical("work_app");
    let l = hex(&L);
    let kept = "SELECT count(*) FROM work.received_bytes";
    assert_eq!(scalar(&app, &l, kept, false).await, 2);
    let first = "SELECT first_pos FROM work.received_bytes WHERE kind = 'cose_sign1'";
    assert_eq!(scalar(&app, &l, first, false).await, 1);
    let links = "SELECT count(*) FROM work.log_received";
    assert_eq!(scalar(&app, &l, links, false).await, 4);
}

// OP-8 OP-38 P-79
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_38_an_inbound_event_and_a_record_id_are_recorded_once() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let inbound = |pos: u64| InboundRow {
        pos,
        source: "https://peer.example/ledgers/x".to_owned(),
        source_id: "evt-9".to_owned(),
        content_digest: [0x79; 32],
        seen_at_ms: plus(AT, pos),
    };
    let mut first = works(head.epoch, 0, 1);
    first.inbound.push(inbound(1));
    seq.append(&ledger, &first).await.unwrap();
    let mut again = works(head.epoch, 1, 1);
    again.inbound.push(inbound(2));
    assert!(matches!(
        seq.append(&ledger, &again).await,
        Err(AppendError::Refused(StoreError::InboundSeen))
    ));
    let mut same = works(head.epoch, 1, 1);
    same.records[0].record_id = first.records[0].record_id;
    assert!(matches!(
        seq.append(&ledger, &same).await,
        Err(AppendError::Refused(StoreError::RecordExists))
    ));
    seq.append(&ledger, &works(head.epoch, 1, 1)).await.unwrap();
    let seen = "SELECT result_pos FROM work.inbound_seen";
    assert_eq!(
        scalar(&env.canonical("work_app"), &hex(&L), seen, false).await,
        1
    );
}

// P-35 T-12 T-100 OP-38 OP-8
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_35_an_inbound_event_without_a_record_is_seen_once_per_tenant_ledger() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let event = InboundEvent {
        source: "https://relay.example".to_owned(),
        source_id: "evt-1".to_owned(),
        content_digest: [0x51; 32],
        seen_at_ms: AT,
    };
    let mut tx = seq.begin(&ledger).await.unwrap();
    assert_eq!(tx.note_inbound(&event).await.unwrap(), InboundSeen::First);
    let racer = seq.clone();
    let late = InboundEvent {
        content_digest: [0x52; 32],
        seen_at_ms: plus(AT, 1_000),
        ..event.clone()
    };
    let second = tokio::spawn(async move {
        let mut tx = racer.begin(&ledger).await.unwrap();
        let seen = tx.note_inbound(&late).await.unwrap();
        tx.commit().await.unwrap();
        seen
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!second.is_finished());
    tx.commit().await.unwrap();
    assert_eq!(second.await.unwrap(), InboundSeen::Repeat);
    let other = InboundEvent {
        source_id: "evt-2".to_owned(),
        ..event.clone()
    };
    let mut tx = seq.begin(&ledger).await.unwrap();
    assert_eq!(tx.note_inbound(&other).await.unwrap(), InboundSeen::First);
    tx.commit().await.unwrap();
    let elsewhere = LedgerId::from_bytes(M);
    let mut tx = seq.begin(&elsewhere).await.unwrap();
    assert_eq!(tx.note_inbound(&event).await.unwrap(), InboundSeen::First);
    tx.commit().await.unwrap();
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut answer = works(head.epoch, 0, 1);
    answer.inbound.push(InboundRow {
        pos: 1,
        source: event.source.clone(),
        source_id: event.source_id.clone(),
        content_digest: [0x51; 32],
        seen_at_ms: plus(AT, 1),
    });
    assert!(matches!(
        seq.append(&ledger, &answer).await,
        Err(AppendError::Refused(StoreError::InboundSeen))
    ));
    let rows = "SELECT count(*) FROM work.inbound_seen WHERE result_pos IS NULL";
    let app = env.canonical("work_app");
    assert_eq!(scalar(&app, &hex(&L), rows, false).await, 2);
    assert_eq!(scalar(&app, &hex(&M), rows, false).await, 1);
}

async fn epoch_of(env: &Env) -> i64 {
    let epoch = "SELECT epoch FROM ledger.head";
    scalar(&env.canonical("work_app"), &hex(&L), epoch, false).await
}

// T-28 T-85 OP-10 OP-5
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_28_a_live_lease_keeps_another_node_out_until_it_is_released_or_expires() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let a = seat();
    let b = Seat {
        holder: [2; 16],
        ..seat()
    };
    let first = seq.acquire(&ledger, &a, any).await.unwrap();
    assert_eq!(first.epoch, 1);
    assert!(matches!(
        seq.acquire(&ledger, &b, any).await,
        Err(StoreError::LeaseHeld)
    ));
    assert_eq!(epoch_of(&env).await, 1);
    seq.renew(&ledger, &a, 1).await.unwrap();
    assert!(matches!(
        seq.renew(&ledger, &b, 1).await,
        Err(StoreError::LeaseLost)
    ));
    seq.release(&ledger, &a, 1).await.unwrap();
    assert!(matches!(
        seq.release(&ledger, &a, 1).await,
        Err(StoreError::LeaseLost)
    ));

    let second = seq.acquire(&ledger, &b, any).await.unwrap();
    assert_eq!(second.epoch, 2);
    assert!(matches!(
        seq.renew(&ledger, &a, 1).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        seq.append(&ledger, &batch(1, 0, 1)).await,
        Err(AppendError::Failed(StoreError::HeadMoved))
    ));
    seq.append(&ledger, &batch(2, 0, 1)).await.unwrap();

    let brief = Seat { lease_ms: 50, ..b };
    assert_eq!(seq.acquire(&ledger, &brief, any).await.unwrap().epoch, 3);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let third = seq.acquire(&ledger, &a, any).await.unwrap();
    assert_eq!(third.epoch, 4);
    assert_eq!(third.pos, 1);
    assert!(matches!(
        seq.renew(&ledger, &brief, 3).await,
        Err(StoreError::LeaseLost)
    ));
    let log = "SELECT count(*) FROM ledger.log";
    assert_eq!(
        scalar(&env.canonical("work_app"), &hex(&L), log, false).await,
        2
    );
}

// OP-9 C-35 T-85
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_9_a_wrong_directory_entry_is_refused_by_the_sequencer() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let app = env.canonical("work_app");
    let mut tx = LedgerTx::begin(&app, &ledger).await.unwrap();
    assert_eq!(tx.placement().await.unwrap(), Some(cell()));
    tx.rollback().await.unwrap();
    let unknown = LedgerId::from_bytes(M);
    let mut other = LedgerTx::begin(&app, &unknown).await.unwrap();
    assert_eq!(other.placement().await.unwrap(), None);
    other.rollback().await.unwrap();

    run(
        &env.canonical("work_owner"),
        &hex(&L),
        &["UPDATE work.placement SET cell = 'cell-b'"],
    )
    .await;
    let mut tx = LedgerTx::begin(&app, &ledger).await.unwrap();
    let routed = tx.placement().await.unwrap().unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(routed.as_str(), "cell-b");
    let elsewhere = Seat {
        cell: routed,
        holder: [3; 16],
        lease_ms: 60_000,
    };
    assert!(matches!(
        seq.acquire(&ledger, &elsewhere, any).await,
        Err(StoreError::Misrouted)
    ));
    assert!(matches!(
        seq.acquire(&unknown, &elsewhere, any).await,
        Err(StoreError::NotOpened)
    ));
    assert_eq!(epoch_of(&env).await, 0);
    let lease = "SELECT count(*) FROM ledger.sequencer_lease";
    assert_eq!(scalar(&app, &hex(&L), lease, false).await, 0);
    assert_eq!(seq.acquire(&ledger, &seat(), any).await.unwrap().epoch, 1);
    fails(
        &env.canonical("work_owner"),
        &hex(&L),
        &["UPDATE ledger.ledger_cell SET cell = 'cell-b'"],
        None,
    )
    .await;
}

// OP-28 P-87 T-85
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_28_a_node_without_the_active_versions_never_takes_the_ledger() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let seen = std::sync::Mutex::new(Vec::new());
    let refuse = |activations: &[Vec<u8>]| {
        seen.lock().unwrap().extend_from_slice(activations);
        false
    };
    assert!(matches!(
        seq.acquire(&ledger, &seat(), refuse).await,
        Err(StoreError::Unsupported)
    ));
    assert_eq!(*seen.lock().unwrap(), [genesis(L).bytes]);
    assert_eq!(epoch_of(&env).await, 0);

    let current = seq.acquire(&ledger, &seat(), any).await.unwrap();
    assert_eq!(current.epoch, 1);
    let older = Seat {
        holder: [4; 16],
        ..seat()
    };
    assert!(matches!(
        seq.acquire(&ledger, &older, |_: &[Vec<u8>]| false).await,
        Err(StoreError::Unsupported)
    ));
    assert_eq!(epoch_of(&env).await, 1);
    seq.renew(&ledger, &seat(), 1).await.unwrap();
    seq.append(&ledger, &batch(1, 0, 1)).await.unwrap();
}

/// A small deterministic generator, so the interleaving below is the same on every run.
fn step(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    state.checked_shr(33).unwrap()
}

// OP-7 T-89 P-28 P-29
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_7_no_transition_on_a_stale_conflict_area_head_is_ever_committed() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut state = 0x5eed_u64;
    let mut stored = 0_u64;
    let mut after = 0_u64;
    let mut refused = 0_u64;
    for _ in 0..120 {
        let roll = step(&mut state).checked_rem(4).unwrap();
        let expect = match roll {
            0 if stored > 0 => Expect::Version(step(&mut state).checked_rem(stored).unwrap()),
            1 => Expect::Next,
            2 => Expect::Version(plus(stored, 1)),
            _ => Expect::Version(stored),
        };
        let mut b = batch(head.epoch, after, 1);
        b.items[0].expect = expect;
        let outcome = seq.append(&ledger, &b).await;
        let current = matches!(expect, Expect::Next) || expect == Expect::Version(stored);
        if current {
            outcome.unwrap();
            stored = plus(stored, 1);
            after = plus(after, 1);
        } else {
            assert!(
                matches!(
                    outcome,
                    Err(AppendError::Refused(StoreError::ItemConflict(ITEM)))
                ),
                "{expect:?} against {stored}"
            );
            refused = plus(refused, 1);
        }
    }
    assert!(refused > 0);
    assert!(after > 0);
    let app = env.canonical("work_app");
    let mut tx = LedgerTx::begin(&app, &ledger).await.unwrap();
    assert_eq!(tx.item_version(&ITEM).await.unwrap(), Some(stored));
    assert_eq!(tx.head().await.unwrap().unwrap().pos, Some(after));
    tx.rollback().await.unwrap();
    let pointers = "SELECT count(*) FROM ledger.outbox";
    let publisher = env.canonical("work_publisher");
    assert_eq!(
        scalar(&publisher, &hex(&L), pointers, false).await,
        i64::try_from(after).unwrap()
    );
}

fn claim(subject: u8) -> ClaimRow {
    ClaimRow {
        subject: [subject; 16],
        commitment: [0xc0; 32],
        issuer: [0x11; 16],
        domain: [0x22; 32],
        pep: [0x33; 32],
    }
}

fn answer(at_ms: u64) -> ClaimAnswer {
    ClaimAnswer {
        claim: [0x44; 16],
        position: 9,
        at_ms,
    }
}

async fn kept_as_answered(app: &sqlx::PgPool, ledger: &LedgerId, record: &[u8; 32], at: u64) {
    let mut read = LedgerTx::begin(app, ledger).await.unwrap();
    let kept = read.claim_deliveries(record).await.unwrap();
    read.rollback().await.unwrap();
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0].attempts, 2);
    assert_eq!(
        kept[0].delivery,
        Delivery::Delivered {
            claim: [0x44; 16],
            position: 9,
            replayed: true,
            at_ms: plus(at, 1000),
        }
    );
    assert_eq!(
        kept[1].delivery,
        Delivery::Quarantined {
            claim: [0x44; 16],
            position: 9,
            reason: "source-not-accepted".to_owned(),
            at_ms: at,
        }
    );
}

async fn discovered(publisher: &PublisherPool, ledger: &LedgerId, at: u64) {
    assert_eq!(
        publisher.claim_ledgers(None, at, 10).await.unwrap(),
        [*ledger]
    );
    assert_eq!(
        publisher
            .claim_ledgers(None, at.checked_sub(1).unwrap(), 10)
            .await
            .unwrap(),
        []
    );
    assert_eq!(
        publisher.claim_ledgers(Some(ledger), at, 10).await.unwrap(),
        []
    );
}

// E-12 E-8
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn e_12_a_claim_is_written_with_its_record_and_settled_by_its_delivery_only() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut refused = batch(head.epoch, 0, 2);
    refused.records[0].claims = vec![claim(1)];
    assert!(matches!(
        seq.append(&ledger, &refused).await,
        Err(AppendError::Refused(StoreError::ItemConflict(ITEM)))
    ));
    let app = env.canonical("work_app");
    let l = hex(&L);
    let rows = "SELECT count(*) FROM work.claim_delivery";
    assert_eq!(scalar(&app, &l, rows, false).await, 0);
    let mut written = batch(head.epoch, 0, 1);
    written.records[0].claims = vec![claim(1), claim(2)];
    seq.append(&ledger, &written).await.unwrap();
    assert_eq!(scalar(&app, &l, rows, false).await, 2);
    let at = plus(AT, 1);
    let record = written.records[0].record_id;
    let publisher = PublisherPool::new(env.canonical("work_publisher"))
        .await
        .unwrap();
    discovered(&publisher, &ledger, at).await;
    let mut tx = publisher.begin(&ledger).await.unwrap();
    let due = tx.claims_due(at, 10).await.unwrap();
    assert_eq!(due.len(), 2);
    let first = &due[0];
    assert_eq!(first.key.record, record);
    assert_eq!(first.key.subject, [1; 16]);
    assert_eq!(first.claim, claim(1));
    assert_eq!(first.issued_at_ms, at);
    assert_eq!(first.pos, 1);
    assert_eq!(first.attempts, 0);
    assert_eq!(
        first.delivery,
        Delivery::Pending {
            next_attempt_ms: at,
            last_error: None,
        }
    );
    let (one, two) = (due[0].key, due[1].key);
    assert!(
        tx.claim_retry(&one, "access_unreachable", plus(at, 1000))
            .await
            .unwrap()
    );
    assert_eq!(tx.claims_due(at, 10).await.unwrap().len(), 1);
    assert!(
        tx.claim_quarantined(&two, &answer(at), "source-not-accepted")
            .await
            .unwrap()
    );
    assert_eq!(tx.claims_due(at, 10).await.unwrap(), []);
    let later = tx.claims_due(plus(at, 1000), 10).await.unwrap();
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].attempts, 1);
    assert_eq!(
        later[0].delivery,
        Delivery::Pending {
            next_attempt_ms: plus(at, 1000),
            last_error: Some("access_unreachable".to_owned()),
        }
    );
    assert!(
        tx.claim_delivered(&one, &answer(plus(at, 1000)), true)
            .await
            .unwrap()
    );
    assert!(
        !tx.claim_delivered(&one, &answer(plus(at, 2000)), false)
            .await
            .unwrap()
    );
    assert!(
        !tx.claim_retry(&two, "access_timeout", plus(at, 5000))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert_eq!(
        publisher
            .claim_ledgers(None, plus(at, 86_400_000), 10)
            .await
            .unwrap(),
        []
    );
    kept_as_answered(&app, &ledger, &record, at).await;
}

// E-12 E-8
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn e_12_only_the_sequencer_writes_a_claim_and_only_its_delivery_settles_it_once() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut written = batch(head.epoch, 0, 1);
    written.records[0].claims = vec![claim(1)];
    seq.append(&ledger, &written).await.unwrap();
    let l = hex(&L);
    let insert = "INSERT INTO work.claim_delivery \
                  (ledger_id, record_id, subject, pos, commitment, issuer, domain_id, pep, \
                   issued_at, delivery, attempts, next_attempt_at) \
                  SELECT ledger_id, record_id, decode(repeat('09', 16), 'hex'), pos, commitment, \
                   issuer, domain_id, pep, issued_at, 'pending', 0, next_attempt_at \
                  FROM work.claim_delivery";
    let settle = "UPDATE work.claim_delivery SET attempts = attempts + 1";
    for role in ["work_app", "work_publisher", "work_checkpointer"] {
        fails(&env.canonical(role), &l, &[insert], Some("42501")).await;
    }
    for role in ["work_app", "work_sequencer", "work_checkpointer"] {
        fails(&env.canonical(role), &l, &[settle], Some("42501")).await;
    }
    let publisher = env.canonical("work_publisher");
    for stmt in [
        "DELETE FROM work.claim_delivery",
        "TRUNCATE work.claim_delivery",
        "UPDATE work.claim_delivery SET issued_at = issued_at + interval '1 millisecond'",
    ] {
        fails(&publisher, &l, &[stmt], Some("42501")).await;
    }
    fails(
        &publisher,
        &l,
        &["UPDATE work.claim_delivery SET attempts = 0, delivery = 'delivered'"],
        Some("23514"),
    )
    .await;
    run(&publisher, &l, &[settle]).await;
    fails(
        &publisher,
        &l,
        &["UPDATE work.claim_delivery SET attempts = 0"],
        Some("23514"),
    )
    .await;
    run(
        &publisher,
        &l,
        &["UPDATE work.claim_delivery SET delivery = 'quarantined', \
           access_claim = decode(repeat('44', 16), 'hex'), access_pos = 9, \
           held_reason = 'source-not-accepted', settled_at = next_attempt_at"],
    )
    .await;
    fails(&publisher, &l, &[settle], Some("23514")).await;
    let other = hex(&M);
    let seen = "SELECT count(*) FROM work.claim_delivery";
    assert_eq!(scalar(&publisher, &other, seen, false).await, 0);
    assert_eq!(scalar(&publisher, &l, seen, false).await, 1);
    fails(
        &env.canonical("work_app"),
        &l,
        &["SELECT count(*) FROM work.claim_delivery_ledgers(NULL, 0, 10)"],
        Some("42501"),
    )
    .await;
}

fn delivery(addressee: &str, kind: DeliveryKind) -> ExecutorDeliveryRow {
    ExecutorDeliveryRow {
        addressee: addressee.to_owned(),
        kind,
        commitment: [0xc0; 32],
        body: vec![0xa1, 0x01, 0x02],
    }
}

fn binding(authority: u8, key: &str) -> SingleUseRow {
    SingleUseRow {
        authority: [authority; 32],
        key: key.to_owned(),
        relies_on: vec![[0x0d; 32], [0x0e; 32]],
    }
}

// RC-42 E-39
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn rc_42_a_delivery_is_written_with_its_record_in_order_and_its_doorbell_settled_once() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut refused = batch(head.epoch, 0, 2);
    refused.records[0].deliveries = vec![delivery("party:acme:agent", DeliveryKind::Commitment)];
    assert!(matches!(
        seq.append(&ledger, &refused).await,
        Err(AppendError::Refused(StoreError::ItemConflict(ITEM)))
    ));
    let app = env.canonical("work_app");
    let l = hex(&L);
    let rows = "SELECT count(*) FROM work.executor_delivery";
    assert_eq!(scalar(&app, &l, rows, false).await, 0);
    let mut first = batch(head.epoch, 0, 1);
    first.records[0].deliveries = vec![
        delivery("party:acme:agent", DeliveryKind::Commitment),
        delivery("party:acme:agent", DeliveryKind::Request),
    ];
    seq.append(&ledger, &first).await.unwrap();
    let mut second = batch(head.epoch, 1, 2);
    second.records[0].deliveries = vec![delivery("party:acme:robot", DeliveryKind::Request)];
    seq.append(&ledger, &second).await.unwrap();
    let mut read = LedgerTx::begin(&app, &ledger).await.unwrap();
    let mine = read
        .executor_deliveries("party:acme:agent", 0, 100)
        .await
        .unwrap();
    assert_eq!(mine.iter().map(|d| d.seq).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(mine[0].row.kind, DeliveryKind::Commitment);
    assert_eq!(mine[0].record, first.records[0].record_id);
    assert_eq!(mine[0].issued_at_ms, plus(AT, 1));
    assert_eq!(mine[1].row.body, vec![0xa1, 0x01, 0x02]);
    let after = read
        .executor_deliveries("party:acme:agent", 1, 100)
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    let other = read
        .executor_deliveries("party:acme:robot", 0, 100)
        .await
        .unwrap();
    assert_eq!(other.iter().map(|d| d.seq).collect::<Vec<_>>(), [3]);
    read.rollback().await.unwrap();
    let publisher = PublisherPool::new(env.canonical("work_publisher"))
        .await
        .unwrap();
    let at = plus(AT, 2);
    assert_eq!(
        publisher.doorbell_ledgers(None, at, 10).await.unwrap(),
        [ledger]
    );
    let mut tx = publisher.begin(&ledger).await.unwrap();
    assert_eq!(tx.doorbells_due(at, 10).await.unwrap().len(), 3);
    assert!(
        tx.doorbell_retry(1, "webhook_unreachable", plus(at, 1000))
            .await
            .unwrap()
    );
    assert!(tx.doorbell_settled(2, true, at).await.unwrap());
    assert!(!tx.doorbell_settled(2, false, at).await.unwrap());
    assert!(tx.doorbell_settled(3, false, at).await.unwrap());
    assert_eq!(tx.doorbells_due(at, 10).await.unwrap(), []);
    let later = tx.doorbells_due(plus(at, 1000), 10).await.unwrap();
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].attempts, 1);
    assert_eq!(
        later[0].doorbell,
        Doorbell::Pending {
            next_attempt_ms: plus(at, 1000),
            last_error: Some("webhook_unreachable".to_owned()),
        }
    );
    tx.commit().await.unwrap();
    let mut read = LedgerTx::begin(&app, &ledger).await.unwrap();
    let kept = read
        .executor_deliveries("party:acme:agent", 0, 100)
        .await
        .unwrap();
    read.rollback().await.unwrap();
    assert_eq!(kept[1].doorbell, Doorbell::Rung { at_ms: at });
}

// RC-42 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn rc_42_only_the_sequencer_writes_a_delivery_and_only_its_doorbell_changes() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut written = batch(head.epoch, 0, 1);
    written.records[0].deliveries = vec![delivery("party:acme:agent", DeliveryKind::Request)];
    seq.append(&ledger, &written).await.unwrap();
    let l = hex(&L);
    let insert = "INSERT INTO work.executor_delivery \
                  (ledger_id, seq, pos, record_id, addressee, kind, commitment, body, issued_at, \
                   doorbell, attempts, next_attempt_at) \
                  SELECT ledger_id, seq + 1, pos, record_id, 'party:acme:mallory', kind, \
                   commitment, body, issued_at, 'pending', 0, next_attempt_at \
                  FROM work.executor_delivery";
    let settle = "UPDATE work.executor_delivery SET attempts = attempts + 1";
    for role in ["work_app", "work_publisher", "work_checkpointer"] {
        fails(&env.canonical(role), &l, &[insert], Some("42501")).await;
    }
    for role in ["work_app", "work_sequencer", "work_checkpointer"] {
        fails(&env.canonical(role), &l, &[settle], Some("42501")).await;
    }
    let publisher = env.canonical("work_publisher");
    for stmt in [
        "DELETE FROM work.executor_delivery",
        "TRUNCATE work.executor_delivery",
        "UPDATE work.executor_delivery SET addressee = 'party:acme:mallory'",
        "UPDATE work.executor_delivery SET body = '\\x00'",
    ] {
        fails(&publisher, &l, &[stmt], Some("42501")).await;
    }
    run(&publisher, &l, &[settle]).await;
    fails(
        &publisher,
        &l,
        &["UPDATE work.executor_delivery SET attempts = 0"],
        Some("23514"),
    )
    .await;
    run(
        &publisher,
        &l,
        &["UPDATE work.executor_delivery SET doorbell = 'rung', settled_at = next_attempt_at"],
    )
    .await;
    fails(&publisher, &l, &[settle], Some("23514")).await;
    let other = hex(&M);
    let seen = "SELECT count(*) FROM work.executor_delivery";
    assert_eq!(scalar(&publisher, &other, seen, false).await, 0);
    assert_eq!(scalar(&publisher, &l, seen, false).await, 1);
    fails(
        &env.canonical("work_app"),
        &l,
        &["SELECT count(*) FROM work.executor_delivery_ledgers(NULL, 0, 10)"],
        Some("42501"),
    )
    .await;
}

// SEC-15 OP-4 OP-47
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn sec_15_a_binding_is_written_once_with_its_record_and_names_what_it_relied_on() {
    let (env, seq) = opened().await;
    let ledger = LedgerId::from_bytes(L);
    let head = seq.acquire(&ledger, &seat(), any).await.unwrap();
    let mut first = batch(head.epoch, 0, 1);
    first.records[0].single_use = Some(binding(4, "cmt_a/rec_b"));
    seq.append(&ledger, &first).await.unwrap();
    for (authority, key) in [(4, "cmt_a/rec_c"), (5, "cmt_a/rec_b")] {
        let mut reused = batch(head.epoch, 1, 2);
        reused.records[0].single_use = Some(binding(authority, key));
        assert!(matches!(
            seq.append(&ledger, &reused).await,
            Err(AppendError::Refused(StoreError::Constraint(_)))
        ));
    }
    let app = env.canonical("work_app");
    let mut read = LedgerTx::begin(&app, &ledger).await.unwrap();
    let used = read.single_uses(&[4; 32], "cmt_a/rec_x").await.unwrap();
    assert_eq!(used.len(), 1);
    assert_eq!(used[0].key, "cmt_a/rec_b");
    assert_eq!(used[0].pos, 1);
    assert_eq!(used[0].record, first.records[0].record_id);
    assert_eq!(
        read.single_uses(&[9; 32], "cmt_a/rec_b")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(read.single_uses(&[9; 32], "none").await.unwrap(), []);
    assert_eq!(
        read.acted_upon(&[0x0e; 32]).await.unwrap(),
        Some(first.records[0].record_id)
    );
    assert_eq!(read.acted_upon(&[0x0f; 32]).await.unwrap(), None);
    read.rollback().await.unwrap();
    let l = hex(&L);
    for role in ["work_app", "work_publisher", "work_sequencer"] {
        for stmt in [
            "UPDATE work.single_use SET idem_key = 'other'",
            "DELETE FROM work.single_use",
            "TRUNCATE work.single_use",
        ] {
            fails(&env.canonical(role), &l, &[stmt], None).await;
        }
    }
}
