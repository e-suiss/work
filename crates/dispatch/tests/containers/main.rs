//! The outbox publisher and the event consumer against real PostgreSQL 18 and NATS JetStream
//! (T-17, T-18, T-21, T-76, T-81, T-82, T-83, §18 OP-25, OP-34, OP-39; T-36 rule 7, T-37 rule 9). These tests need
//! Docker; `just test-containers` runs them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use async_nats::jetstream::{self, stream::DiscardPolicy};
use futures_util::StreamExt;
use work_dispatch::{
    BusError, Committed, Consumer, ConsumerConfig, DispatchError, Event, Handler, HandlerError,
    Health, JetStreamBus, JetStreamPull, PgCommitted, PgOutbox, Published, Publisher,
    PublisherConfig, StreamSettings,
};
use work_store::{Cluster, DeriverPool, LedgerId, LedgerTx, PointerKey, Pool, PublisherPool};
use work_testkit::{Nats, Postgres};

const PASSWORD: &str = "test-only-not-a-secret";
const LOGINS: &str = include_str!("../../../store/fixtures/publisher-logins.sql");
const SEED: &str = include_str!("../../../store/fixtures/publisher-outbox.sql");
const REDELIVER: &str = include_str!("../../../store/fixtures/publisher-redeliver.sql");
const L: [u8; 32] = [0xab; 32];
const M: [u8; 32] = [0xcd; 32];
const OTHER_LEDGER: &str = include_str!("../../../store/fixtures/publisher-second-ledger.sql");
const SOURCE: &str = "https://work.test";

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
            work_store::migrate(&env.pool_on(cluster, "work_owner"), cluster)
                .await
                .unwrap();
        }
        env.sql(SEED).await;
        env
    }

    fn pool(&self, role: &str) -> Pool {
        self.pool_on(Cluster::Canonical, role)
    }

    fn pool_on(&self, cluster: Cluster, role: &str) -> Pool {
        let url = format!(
            "postgres://{role}:{PASSWORD}@{}:{}/{}",
            self.pg.host(),
            self.pg.port(),
            cluster.database()
        );
        Pool::connect_lazy(&url).unwrap()
    }

    async fn sql(&self, sql: &str) {
        self.pg
            .client(&[
                "psql",
                "-X",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "-d",
                "work",
                "-c",
                sql,
            ])
            .await
            .unwrap();
    }

    async fn pending(&self) -> Vec<String> {
        let pool = self.pool("work_publisher");
        let mut tx = LedgerTx::begin(&pool, &LedgerId::from_bytes(L))
            .await
            .unwrap();
        let rows = tx.outbox_pending(100).await.unwrap();
        tx.rollback().await.unwrap();
        rows.into_iter().map(|r| r.key.event_id).collect()
    }
}

fn config() -> PublisherConfig {
    PublisherConfig {
        batch_size: 3,
        max_in_flight: 2,
        call_timeout: Duration::from_secs(2),
        ..PublisherConfig::new(SOURCE)
    }
}

async fn publisher(env: &Env, client: async_nats::Client) -> Publisher<PgOutbox, JetStreamBus> {
    with_config(env, client, config()).await
}

async fn with_config(
    env: &Env,
    client: async_nats::Client,
    config: PublisherConfig,
) -> Publisher<PgOutbox, JetStreamBus> {
    let pool = PublisherPool::new(env.pool("work_publisher"))
        .await
        .unwrap();
    Publisher::new(
        PgOutbox::new(pool),
        JetStreamBus::new(client, Duration::from_secs(2)),
        config,
    )
    .unwrap()
}

async fn stream_messages(js: &jetstream::Context) -> u64 {
    let stream = js.get_stream("WORK_EVENTS").await.unwrap();
    stream.get_info().await.unwrap().state.messages
}

// T-17 T-76 P-35 P-42
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_17_pointers_are_published_with_msg_id_and_removed_after_the_ack() {
    let env = Env::start().await;
    let nats = Nats::start().await.unwrap();
    let p = publisher(&env, nats.connect().await.unwrap()).await;
    p.ensure_stream().await.unwrap();
    let ledger = LedgerId::from_bytes(L);
    let done = p.publish_ledger(&ledger).await.unwrap();
    assert_eq!(
        done,
        Published {
            acked: 4,
            duplicates: 0,
            removed: 4
        }
    );
    assert_eq!(env.pending().await, Vec::<String>::new());
    let js = nats.jetstream().await.unwrap();
    assert_eq!(stream_messages(&js).await, 4);
    let stream = js.get_stream("WORK_EVENTS").await.unwrap();
    let info = stream.get_info().await.unwrap();
    assert_eq!(info.config.subjects, ["work.evt.*.*.>"]);
    assert_eq!(info.config.max_age, Duration::from_hours(7 * 24));
    assert_eq!(info.config.duplicate_window, Duration::from_mins(2));
    assert_eq!(info.config.num_replicas, 1);
    assert_eq!(info.config.storage, jetstream::stream::StorageType::File);
    let first = stream.get_raw_message(1).await.unwrap();
    assert_eq!(
        first.subject.as_str(),
        StreamSettings::default().subject(&L, "work.opened")
    );
    let header = |name: &str| first.headers.get(name).map(|v| v.as_str().to_owned());
    assert_eq!(header("Nats-Msg-Id").as_deref(), Some("evt-0"));
    assert_eq!(
        header("traceparent").as_deref(),
        Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    );
    let event: serde_json::Value = serde_json::from_slice(&first.payload).unwrap();
    assert_eq!(event["id"], "evt-0");
    assert_eq!(event["type"], "work.opened");
    assert_eq!(event["time"], "2026-10-23T10:00:00.123Z");
    assert_eq!(
        event["source"],
        format!("{SOURCE}/ledgers/{}", "ab".repeat(32))
    );
    assert_eq!(event["recordid"], "01".repeat(32));
    assert_eq!(event["pos"], "0");
    assert_eq!(event["seq"], "1");
    let declined = stream.get_raw_message(4).await.unwrap();
    let event: serde_json::Value = serde_json::from_slice(&declined.payload).unwrap();
    assert_eq!(event["id"], "evt-3");
    assert_eq!(event["seq"], "3");
}

// T-76 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_76_a_redelivered_pointer_is_published_once_per_event_id() {
    let env = Env::start().await;
    let nats = Nats::start().await.unwrap();
    let p = publisher(&env, nats.connect().await.unwrap()).await;
    p.ensure_stream().await.unwrap();
    let ledger = LedgerId::from_bytes(L);
    p.publish_ledger(&ledger).await.unwrap();
    env.sql(REDELIVER).await;
    assert_eq!(env.pending().await, ["evt-0"]);
    let again = p.publish_ledger(&ledger).await.unwrap();
    assert_eq!(
        again,
        Published {
            acked: 1,
            duplicates: 1,
            removed: 1
        }
    );
    assert_eq!(env.pending().await, Vec::<String>::new());
    let js = nats.jetstream().await.unwrap();
    assert_eq!(stream_messages(&js).await, 4);
}

// OP-34 T-17
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_34_a_pointer_is_removed_only_after_its_ack() {
    let env = Env::start().await;
    let nats = Nats::start().await.unwrap();
    let p = publisher(&env, nats.connect().await.unwrap()).await;
    p.ensure_stream().await.unwrap();
    let js = nats.jetstream().await.unwrap();
    let mut limited = js
        .get_stream("WORK_EVENTS")
        .await
        .unwrap()
        .get_info()
        .await
        .unwrap()
        .config;
    limited.max_messages = 1;
    limited.discard = DiscardPolicy::New;
    js.update_stream(limited).await.unwrap();
    let err = p
        .publish_ledger(&LedgerId::from_bytes(L))
        .await
        .unwrap_err();
    assert!(matches!(err, DispatchError::Bus(_)), "{err}");
    assert_eq!(env.pending().await, ["evt-1", "evt-2", "evt-3"]);
    assert_eq!(stream_messages(&js).await, 1);
}

// T-21 T-28 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_21_nats_outage_keeps_the_pointers_until_it_returns() {
    let env = Env::start().await;
    let down = async_nats::ConnectOptions::new()
        .retry_on_initial_connect()
        .connect("nats://127.0.0.1:1")
        .await
        .unwrap();
    let p = publisher(&env, down).await;
    let ledger = LedgerId::from_bytes(L);
    let err = p.publish_ledger(&ledger).await.unwrap_err();
    assert!(
        matches!(
            err,
            DispatchError::Bus(BusError::TimedOut | BusError::Unavailable(_))
        ),
        "{err}"
    );
    assert_eq!(env.pending().await, ["evt-0", "evt-1", "evt-2", "evt-3"]);
    let nats = Nats::start().await.unwrap();
    let p = publisher(&env, nats.connect().await.unwrap()).await;
    p.ensure_stream().await.unwrap();
    assert_eq!(p.publish_ledger(&ledger).await.unwrap().removed, 4);
    assert_eq!(env.pending().await, Vec::<String>::new());
}

// T-80 OP-34 T-17 T-21
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_80_run_discovers_the_ledgers_with_pending_pointers() {
    let env = Env::start().await;
    env.sql(OTHER_LEDGER).await;
    let nats = Nats::start().await.unwrap();
    let quick = PublisherConfig {
        ledgers_per_poll: 1,
        poll_interval: Duration::from_millis(50),
        ..config()
    };
    let p = with_config(&env, nats.connect().await.unwrap(), quick).await;
    assert_eq!(
        p.discover(None).await.unwrap(),
        [LedgerId::from_bytes(L)],
        "ascending, bounded by the limit"
    );
    assert_eq!(
        p.discover(Some(&LedgerId::from_bytes(L))).await.unwrap(),
        [LedgerId::from_bytes(M)],
        "the next page starts after the last id"
    );
    p.run(tokio::time::sleep(Duration::from_secs(3))).await;
    assert_eq!(env.pending().await, Vec::<String>::new());
    assert_eq!(p.discover(None).await.unwrap(), Vec::<LedgerId>::new());
    let js = nats.jetstream().await.unwrap();
    assert_eq!(stream_messages(&js).await, 5);
    let stream = js.get_stream("WORK_EVENTS").await.unwrap();
    let last = stream.get_raw_message(5).await.unwrap();
    assert_eq!(
        last.subject.as_str(),
        StreamSettings::default().subject(&M, "work.opened")
    );
    let event: serde_json::Value = serde_json::from_slice(&last.payload).unwrap();
    assert_eq!(event["ledger"], "cd".repeat(32));
    assert_eq!(event["pos"], "0");
    assert_eq!(
        event["source"],
        format!("{SOURCE}/ledgers/{}", "cd".repeat(32))
    );
}

// T-80 T-79 T-13 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_80_only_a_publisher_role_builds_the_publisher_pool() {
    let env = Env::start().await;
    assert!(matches!(
        PublisherPool::new(env.pool("work_owner")).await,
        Err(work_store::StoreError::Role)
    ));
    assert!(PublisherPool::new(env.pool("work_publisher")).await.is_ok());
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Event>>);

impl Recorder {
    fn ids(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.id.clone())
            .collect()
    }
}

impl Handler for Recorder {
    fn handle(&self, event: &Event) -> impl Future<Output = Result<(), HandlerError>> + Send {
        self.0.lock().unwrap().push(event.clone());
        std::future::ready(Ok(()))
    }
}

fn consumer_config() -> ConsumerConfig {
    let partition = work_dispatch::domain::partition(&L, StreamSettings::default().partitions);
    ConsumerConfig {
        batch_size: 3,
        max_in_flight: 8,
        fetch_wait: Duration::from_millis(500),
        call_timeout: Duration::from_secs(2),
        fallback_interval: Duration::from_millis(100),
        ledgers_per_scan: 16,
        seen_capacity: 1024,
        ..ConsumerConfig::new("derive", vec![partition])
    }
}

async fn committed(env: &Env) -> PgCommitted {
    PgCommitted::new(
        DeriverPool::new(env.pool("work_deriver")).await.unwrap(),
        env.pool_on(Cluster::Derived, "work_deriver"),
    )
}

// T-21 T-82 OP-34 T-17 T-81
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_21_committed_state_is_read_from_a_ledger_pos_cursor() {
    let env = Env::start().await;
    let o = committed(&env).await;
    let ledger = LedgerId::from_bytes(L);
    let ids = |rows: Vec<work_store::PendingEvent>| -> Vec<String> {
        rows.into_iter().map(|r| r.key.event_id).collect()
    };
    let first = o.pending_after(&ledger, None, 2).await.unwrap();
    let last = first.last().map(|r| r.key.clone()).unwrap();
    assert_eq!(
        first
            .iter()
            .map(|r| (r.item, r.version))
            .collect::<Vec<_>>(),
        [
            (work_store::ItemRef::Work([0x0b; 16]), 1),
            (work_store::ItemRef::Commitment([0x0a; 32]), 1)
        ]
    );
    assert_eq!(ids(first), ["evt-0", "evt-1"]);
    let rest = o.pending_after(&ledger, Some(&last), 10).await.unwrap();
    assert_eq!(rest.first().map(|r| r.record_id), Some([0x02; 32]));
    assert_eq!(ids(rest), ["evt-2", "evt-3"]);
    let end = PointerKey {
        pos: 2,
        event_id: "evt-3".to_owned(),
    };
    assert_eq!(
        ids(o.pending_after(&ledger, Some(&end), 10).await.unwrap()),
        Vec::<String>::new()
    );
    let log: Vec<u64> = o
        .log_after(&ledger, None, 2)
        .await
        .unwrap()
        .iter()
        .map(|r| r.pos)
        .collect();
    assert_eq!(log, [0, 1]);
    let tail = o.log_after(&ledger, Some(1), 10).await.unwrap();
    assert_eq!(tail.iter().map(|r| r.pos).collect::<Vec<_>>(), [2]);
    assert_eq!(
        tail.first().map(|r| r.recorded_at_ms),
        Some(1_792_749_602_500)
    );
    assert_eq!(o.log_after(&ledger, Some(2), 10).await.unwrap().len(), 0);
    let other = LedgerId::from_bytes(M);
    assert_eq!(o.log_after(&other, None, 10).await.unwrap().len(), 0);
    assert_eq!(o.ledgers(None, 10).await.unwrap(), [ledger]);
    assert_eq!(o.ledgers(Some(&ledger), 10).await.unwrap(), []);
    assert_eq!(o.cursor(&ledger, "derive").await.unwrap(), None);
}

// OP-39 T-21 T-82
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_39_the_fallback_resumes_from_the_cursor_the_effect_advanced() {
    let env = Env::start().await;
    let ledger = LedgerId::from_bytes(L);
    let derived = env.pool_on(Cluster::Derived, "work_deriver");
    let mut tx = LedgerTx::begin(&derived, &ledger).await.unwrap();
    let at = PointerKey {
        pos: 0,
        event_id: "evt-1".to_owned(),
    };
    assert!(tx.advance_consumer_cursor("derive", &at).await.unwrap());
    tx.commit().await.unwrap();
    let o = committed(&env).await;
    assert_eq!(o.cursor(&ledger, "derive").await.unwrap(), Some(at));
    let down = async_nats::ConnectOptions::new()
        .retry_on_initial_connect()
        .connect("nats://127.0.0.1:1")
        .await
        .unwrap();
    let config = consumer_config();
    let part = *config.partitions.first().unwrap();
    let mut c = Consumer::new(
        JetStreamPull::new(down, Duration::from_secs(2)),
        Recorder::default(),
        config,
    )
    .unwrap();
    let done = c.fallback(&o, part).await.unwrap();
    assert_eq!(done.handled, 2);
    assert_eq!(c.handler().ids(), ["evt-2", "evt-3"]);
    assert_eq!(env.pending().await, ["evt-0", "evt-1", "evt-2", "evt-3"]);
}

// T-76 OP-25 T-18
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_76_per_partition_durable_consumers_take_each_event_once() {
    let env = Env::start().await;
    let nats = Nats::start().await.unwrap();
    let p = publisher(&env, nats.connect().await.unwrap()).await;
    p.ensure_stream().await.unwrap();
    p.publish_ledger(&LedgerId::from_bytes(L)).await.unwrap();
    let config = consumer_config();
    let part = *config.partitions.first().unwrap();
    let mut c = Consumer::new(
        JetStreamPull::new(nats.connect().await.unwrap(), Duration::from_secs(2)),
        Recorder::default(),
        config,
    )
    .unwrap();
    assert_eq!(c.prepare().await, Health::Live);
    let js = nats.jetstream().await.unwrap();
    let mut stream = js.get_stream("WORK_EVENTS").await.unwrap();
    let names: Vec<String> = stream.consumer_names().map(|n| n.unwrap()).collect().await;
    assert_eq!(names, [c.config().durable(part)]);
    let info = stream
        .get_consumer::<jetstream::consumer::pull::Config>(&c.config().durable(part))
        .await
        .unwrap()
        .info()
        .await
        .unwrap()
        .config
        .clone();
    assert_eq!(
        info.filter_subject,
        c.config().stream.partition_filter(part)
    );
    assert_eq!(info.max_ack_pending, 8);
    let first = c.poll(part).await.unwrap();
    let second = c.poll(part).await.unwrap();
    assert_eq!(first.handled + second.handled, 4);
    assert_eq!(first.health, Health::Live);
    assert_eq!(c.handler().ids(), ["evt-0", "evt-1", "evt-2", "evt-3"]);
    let events = c.handler().0.lock().unwrap().clone();
    assert!(events.iter().all(|e| e.ledger == L));
    assert_eq!(
        events.iter().map(|e| e.pos).collect::<Vec<_>>(),
        [0, 0, 1, 2]
    );
    assert_eq!(c.poll(part).await.unwrap().handled, 0);
    let pending = stream
        .get_consumer::<jetstream::consumer::pull::Config>(&c.config().durable(part))
        .await
        .unwrap()
        .info()
        .await
        .unwrap()
        .num_ack_pending;
    assert_eq!(pending, 0);
    assert_eq!(stream.info().await.unwrap().state.consumer_count, 1);
}

// T-21 T-28 T-18 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_21_consumer_falls_back_to_committed_state_while_nats_is_unreachable() {
    let env = Env::start().await;
    let down = async_nats::ConnectOptions::new()
        .retry_on_initial_connect()
        .connect("nats://127.0.0.1:1")
        .await
        .unwrap();
    let o = committed(&env).await;
    let config = consumer_config();
    let part = *config.partitions.first().unwrap();
    let mut c = Consumer::new(
        JetStreamPull::new(down, Duration::from_secs(2)),
        Recorder::default(),
        config,
    )
    .unwrap();
    c.run(&o, tokio::time::sleep(Duration::from_secs(3))).await;
    assert_eq!(c.health(), Health::Degraded);
    assert_eq!(
        c.handler().ids(),
        ["evt-0", "evt-1", "evt-2", "evt-3"],
        "repeats across scans drop by event id"
    );
    assert_eq!(env.pending().await, ["evt-0", "evt-1", "evt-2", "evt-3"]);
    let nats = Nats::start().await.unwrap();
    let p = publisher(&env, nats.connect().await.unwrap()).await;
    p.ensure_stream().await.unwrap();
    p.publish_ledger(&LedgerId::from_bytes(L)).await.unwrap();
    let mut live = Consumer::new(
        JetStreamPull::new(nats.connect().await.unwrap(), Duration::from_secs(2)),
        Recorder::default(),
        consumer_config(),
    )
    .unwrap();
    assert_eq!(live.prepare().await, Health::Live);
    let first = live.poll(part).await.unwrap();
    let second = live.poll(part).await.unwrap();
    assert_eq!(first.health, Health::Live);
    assert_eq!(first.handled + second.handled, 4);
    let from_log = c.handler().0.lock().unwrap().clone();
    let from_nats = live.handler().0.lock().unwrap().clone();
    assert_eq!(from_nats, from_log, "both paths carry the same events");
}
