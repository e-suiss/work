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

use suiss_crypto::dcbor::Value;
use work_ledger::{
    EventPointer, GenesisInput, ItemChange, Leader, LedgerError, PendingRecord, genesis,
};
use work_store::{Cluster, Durability, ItemRef, Pool, SequencerPool, StoreError};
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
