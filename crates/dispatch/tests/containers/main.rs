//! The outbox publisher against real PostgreSQL 18 and NATS JetStream (T-17, T-21, T-76,
//! §18 OP-34; T-36 rule 7, T-37 rule 9). These tests need Docker; `just test-containers` runs
//! them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::time::Duration;

use async_nats::jetstream::{self, stream::DiscardPolicy};
use work_dispatch::{
    BusError, DispatchError, JetStreamBus, PgOutbox, Published, Publisher, PublisherConfig,
    StreamSettings,
};
use work_store::{Cluster, LedgerId, LedgerTx, Pool};
use work_testkit::{Nats, Postgres};

const PASSWORD: &str = "test-only-not-a-secret";
const LOGINS: &str = include_str!("../../../store/fixtures/publisher-logins.sql");
const SEED: &str = include_str!("../../../store/fixtures/publisher-outbox.sql");
const REDELIVER: &str = include_str!("../../../store/fixtures/publisher-redeliver.sql");
const L: [u8; 32] = [0xab; 32];
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
        let mut canonical = psql("work").to_vec();
        canonical.extend(["-c", Cluster::Canonical.bootstrap()]);
        pg.client(&canonical).await.unwrap();
        let env = Self { pg };
        work_store::migrate(&env.pool("work_owner"), Cluster::Canonical)
            .await
            .unwrap();
        env.sql(SEED).await;
        env
    }

    fn pool(&self, role: &str) -> Pool {
        let url = format!(
            "postgres://{role}:{PASSWORD}@{}:{}/work",
            self.pg.host(),
            self.pg.port()
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

fn publisher(env: &Env, client: async_nats::Client) -> Publisher<PgOutbox, JetStreamBus> {
    Publisher::new(
        PgOutbox::new(env.pool("work_publisher")),
        JetStreamBus::new(client, Duration::from_secs(2)),
        config(),
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
    let p = publisher(&env, nats.connect().await.unwrap());
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
}

// T-76 OP-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_76_a_redelivered_pointer_is_published_once_per_event_id() {
    let env = Env::start().await;
    let nats = Nats::start().await.unwrap();
    let p = publisher(&env, nats.connect().await.unwrap());
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
    let p = publisher(&env, nats.connect().await.unwrap());
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
    let p = publisher(&env, down);
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
    let p = publisher(&env, nats.connect().await.unwrap());
    p.ensure_stream().await.unwrap();
    assert_eq!(p.publish_ledger(&ledger).await.unwrap().removed, 4);
    assert_eq!(env.pending().await, Vec::<String>::new());
}
