//! The leader against real PostgreSQL 18 (P-100, T-85, T-74, §18 OP-5, OP-10; T-36 rule 7,
//! T-37 rule 9): opening a ledger with its genesis, committing batches behind the head
//! compare-and-set, fencing an earlier leader and refusing an item conflict without stepping
//! down. These tests need Docker; `just test-containers` runs them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::sync::Arc;
use std::time::Duration;

use suiss_crypto::dcbor::Value;
use tokio::sync::Semaphore;
use work_ledger::{
    Clock, ClockError, EventPointer, GenesisInput, GroupCommit, GroupConfig, ItemChange, Leader,
    LedgerError, PendingRecord, SubmitError, genesis,
};
use work_store::{Cluster, Durability, ItemRef, LedgerId, Pool, SequencerPool, StoreError};
use work_testkit::Postgres;

const PASSWORD: &str = "test-only-not-a-secret";
const LOGINS: &str = "ALTER ROLE work_owner LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_sequencer LOGIN PASSWORD 'test-only-not-a-secret';";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const AT: u64 = 1_792_749_600_123;

struct Env {
    pg: Postgres,
}

impl Env {
    async fn start() -> Self {
        let pg = Postgres::start().await.unwrap();
        let psql = |db: &'static str| ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db];
        let mut roles = psql("postgres").to_vec();
        roles.extend(["-c", work_store::BOOTSTRAP_ROLES, "-c", LOGINS]);
        pg.client(&roles).await.unwrap();
        let statements: Vec<String> = work_store::BOOTSTRAP_DATABASES
            .split(';')
            .map(|s| {
                s.lines()
                    .filter(|l| !l.trim_start().starts_with("--"))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .filter(|s| !s.trim().is_empty())
            .collect();
        let mut databases = psql("postgres").to_vec();
        for stmt in &statements {
            databases.extend(["-c", stmt.as_str()]);
        }
        pg.client(&databases).await.unwrap();
        for cluster in Cluster::ALL {
            let mut bootstrap = psql(cluster.database()).to_vec();
            bootstrap.extend(["-c", cluster.bootstrap()]);
            pg.client(&bootstrap).await.unwrap();
        }
        let env = Self { pg };
        for cluster in Cluster::ALL {
            work_store::migrate(&env.pool(cluster, "work_owner"), cluster)
                .await
                .unwrap();
        }
        env
    }

    fn pool(&self, cluster: Cluster, role: &str) -> Pool {
        let url = format!(
            "postgres://{role}:{PASSWORD}@{}:{}/{}",
            self.pg.host(),
            self.pg.port(),
            cluster.database()
        );
        Pool::connect_lazy(&url).unwrap()
    }

    async fn sequencer(&self) -> SequencerPool {
        SequencerPool::new(self.pool(Cluster::Canonical, "work_sequencer"))
            .await
            .unwrap()
    }
}

fn record(n: u8, item: ItemRef, version: u64) -> PendingRecord {
    PendingRecord {
        record_id: [n; 32],
        record_bytes: vec![0xa1, 0x01, n],
        actor_type: Value::Map(vec![(
            Value::text("author"),
            Value::Array(vec![Value::text("human"), Value::text("access_binding")]),
        )]),
        proof_commit: None,
        auth_context: Some(Value::Map(vec![(
            Value::text("ref"),
            Value::Array(vec![Value::int(-16), Value::Bytes(vec![n; 32])]),
        )])),
        ingest: Value::text("admitted"),
        items: vec![ItemChange {
            item,
            version,
            heads: Some(vec![[n; 32]]),
        }],
        outbox: vec![EventPointer {
            event_id: format!("evt-{n}"),
            event_type: "commitment.requested".to_owned(),
            traceparent: TRACE.to_owned(),
            item,
            version,
        }],
        idempotency: None,
    }
}

// P-100 T-85 T-74 OP-5 OP-10 OP-3
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_85_a_leader_opens_commits_and_is_fenced_by_the_next() {
    let env = Env::start().await;
    let pool = env.sequencer().await;
    let opened = genesis(
        &GenesisInput {
            recorded_at_ms: AT,
            protocol: (1, 0),
            schema: [0x5c; 32],
            nonce: [0x7e; 32],
        },
        Durability::SingleNode,
    )
    .unwrap();
    Leader::open(&pool, &opened).await.unwrap();
    assert!(matches!(
        Leader::open(&pool, &opened).await,
        Err(LedgerError::Store(StoreError::AlreadyOpened))
    ));

    let mut first = Leader::acquire(pool.clone(), opened.ledger).await.unwrap();
    assert_eq!(first.epoch(), 1);
    assert_eq!(first.head().pos, 0);
    assert_eq!(first.head().leaf, opened.leaf);
    assert_eq!(first.head().frontier.nodes(), [opened.leaf]);

    let asked = ItemRef::Commitment([0x0a; 32]);
    let other = ItemRef::Commitment([0x0b; 32]);
    let at = AT.checked_add(1000).unwrap();
    assert_eq!(
        first
            .commit(at, &[record(1, asked, 1), record(2, other, 1)])
            .await
            .unwrap(),
        2
    );
    assert!(first.fence().allows(2));
    assert_eq!(first.head().recorded_at, at);

    assert!(matches!(
        first.commit(at, &[record(3, asked, 1)]).await,
        Err(LedgerError::Refused(StoreError::ItemConflict(_)))
    ));
    assert_eq!(first.commit(at, &[record(3, asked, 2)]).await.unwrap(), 3);

    let mut second = Leader::acquire(pool.clone(), opened.ledger).await.unwrap();
    assert_eq!(second.epoch(), 2);
    assert_eq!(second.head(), first.head());

    assert!(matches!(
        first.commit(at, &[record(4, other, 2)]).await,
        Err(LedgerError::Failed(_))
    ));
    assert!(matches!(
        first.commit(at, &[record(4, other, 2)]).await,
        Err(LedgerError::SteppedDown)
    ));

    assert_eq!(second.commit(AT, &[record(4, other, 2)]).await.unwrap(), 4);
    assert_eq!(second.head().recorded_at, at);
    let third = Leader::acquire(pool, opened.ledger).await.unwrap();
    assert_eq!(third.head(), second.head());
}

/// A virtual ledger clock (T-32 rule 2): each reading takes one permit, so a test can hold the
/// writer between batches.
struct Gate {
    permits: Arc<Semaphore>,
    at: u64,
}

impl Clock for Gate {
    async fn now(&mut self) -> Result<u64, ClockError> {
        self.permits
            .acquire()
            .await
            .map_err(|e| ClockError(e.to_string()))?
            .forget();
        self.at = self
            .at
            .checked_add(1)
            .ok_or(ClockError("overflow".to_owned()))?;
        Ok(self.at)
    }
}

async fn opened(env: &Env) -> (SequencerPool, LedgerId) {
    let pool = env.sequencer().await;
    let g = genesis(
        &GenesisInput {
            recorded_at_ms: AT,
            protocol: (1, 0),
            schema: [0x5c; 32],
            nonce: [0x3d; 32],
        },
        Durability::Quorum,
    )
    .unwrap();
    Leader::open(&pool, &g).await.unwrap();
    (pool, g.ledger)
}

fn work(n: u8) -> ItemRef {
    let mut id = [0_u8; 16];
    id[0] = n;
    ItemRef::Work(id)
}

// OP-31 OP-5 OP-3 T-74
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_31_concurrent_requests_share_batches_and_get_contiguous_positions() {
    let env = Env::start().await;
    let (pool, ledger) = opened(&env).await;
    let leader = Leader::acquire(pool.clone(), ledger).await.unwrap();
    let permits = Arc::new(Semaphore::new(0));
    let clock = Gate {
        permits: permits.clone(),
        at: AT,
    };
    let (group, task) = GroupCommit::spawn(leader, clock, GroupConfig::default());
    let mut waiting = Vec::new();
    for n in 1..=100_u8 {
        let g = group.clone();
        waiting.push(tokio::spawn(async move {
            g.submit(record(n, work(n), 1)).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    permits.add_permits(1000);
    let mut positions = Vec::new();
    for w in waiting {
        positions.push(w.await.unwrap().unwrap().pos);
    }
    positions.sort_unstable();
    assert_eq!(positions, (1..=100).collect::<Vec<u64>>());
    drop(group);
    task.await.unwrap().unwrap();
    let head = Leader::acquire(pool, ledger).await.unwrap();
    assert_eq!(head.head().pos, 100);
    assert!(head.head().recorded_at <= AT.checked_add(100).unwrap());
}

// OP-41 OP-31
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_41_a_full_queue_answers_busy_at_once_and_writes_nothing() {
    let env = Env::start().await;
    let (pool, ledger) = opened(&env).await;
    let leader = Leader::acquire(pool.clone(), ledger).await.unwrap();
    let permits = Arc::new(Semaphore::new(0));
    let clock = Gate {
        permits: permits.clone(),
        at: AT,
    };
    let config = GroupConfig::new(256, 1 << 20, 2, Duration::from_secs(1)).unwrap();
    let (group, task) = GroupCommit::spawn(leader, clock, config);
    let first = {
        let g = group.clone();
        tokio::spawn(async move { g.submit(record(1, work(1), 1)).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let queued: Vec<_> = (2..=3_u8)
        .map(|n| {
            let g = group.clone();
            tokio::spawn(async move { g.submit(record(n, work(n), 1)).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        group.submit(record(4, work(4), 1)).await,
        Err(SubmitError::Busy { retry_after }) if retry_after == Duration::from_secs(1)
    ));
    permits.add_permits(10);
    assert_eq!(first.await.unwrap().unwrap().pos, 1);
    for q in queued {
        q.await.unwrap().unwrap();
    }
    drop(group);
    task.await.unwrap().unwrap();
    assert_eq!(Leader::acquire(pool, ledger).await.unwrap().head().pos, 3);
}

// OP-31 P-29 T-74
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_31_a_refused_record_does_not_sink_its_batch() {
    let env = Env::start().await;
    let (pool, ledger) = opened(&env).await;
    let leader = Leader::acquire(pool.clone(), ledger).await.unwrap();
    let permits = Arc::new(Semaphore::new(0));
    let clock = Gate {
        permits: permits.clone(),
        at: AT,
    };
    let (group, task) = GroupCommit::spawn(leader, clock, GroupConfig::default());
    let shared = work(9);
    let mut waiting = Vec::new();
    for (n, item, version) in [
        (1, work(1), 1),
        (2, shared, 1),
        (3, shared, 1),
        (4, work(4), 1),
    ] {
        let g = group.clone();
        waiting.push(tokio::spawn(async move {
            g.submit(record(n, item, version)).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    permits.add_permits(100);
    let results: Vec<_> = futures_join(waiting).await;
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(SubmitError::Refused(StoreError::ItemConflict(_)))))
            .count(),
        1
    );
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
    drop(group);
    task.await.unwrap().unwrap();
    assert_eq!(Leader::acquire(pool, ledger).await.unwrap().head().pos, 3);
}

async fn futures_join<T>(handles: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}
