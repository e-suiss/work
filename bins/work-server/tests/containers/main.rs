//! `work-server` against real PostgreSQL 18, NATS JetStream and, on Linux, the signer process
//! (T-17, T-20, T-21, T-39, T-76, T-79, T-84, OP-28, OP-34): it starts only when both databases,
//! its writing roles and JetStream answer, never migrates, survives losing NATS, publishes a
//! committed record's event to `WORK_EVENTS` and is ready only while PostgreSQL and the signer
//! answer. These tests need Docker; `just test-containers` runs them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

#[cfg(target_os = "linux")]
mod signer;

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use async_nats::jetstream::consumer::{AckPolicy, DeliverPolicy, PullConsumer, pull};
use futures_util::StreamExt as _;
use serde_json::Value as Json;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::Digest;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::{Reason, Schema};
use work_kernel::validate::{ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin};
use work_kernel::verify::{SignatureCheck, SignatureVerifier};
use work_ledger::{
    Arrival, AuthContext, GenesisInput, Leader, PendingRecord, Submission, admit, genesis,
};
use work_store::{Cluster, Durability, LedgerId, LedgerTx, Pool, SequencerPool};
use work_testkit::{Nats, Postgres};

const PASSWORD: &str = "test-only-not-a-secret";
const ROLES: [&str; 6] = [
    "work_owner",
    "work_app",
    "work_sequencer",
    "work_checkpointer",
    "work_publisher",
    "work_deriver",
];
const DEADLINE: Duration = Duration::from_secs(60);
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const AT: u64 = 1_792_749_600_123;
const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
const CONTEXT: &[u8] = b"work-vector:access:auth-context:alice";
pub(crate) const PREFIX: &str = "work.example/ledger/";

/// Both databases, bootstrapped as the administrator does and migrated when asked.
struct Databases {
    pg: Postgres,
    canonical: String,
    derived: String,
}

impl Databases {
    async fn start(migrated: bool) -> Self {
        let pg = Postgres::start().await.unwrap();
        let psql = |db: &'static str| ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db];
        let logins: Vec<String> = ROLES
            .iter()
            .map(|r| format!("ALTER ROLE {r} LOGIN PASSWORD '{PASSWORD}'"))
            .collect();
        let mut roles = psql("postgres").to_vec();
        roles.extend(["-c", work_store::BOOTSTRAP_ROLES]);
        for login in &logins {
            roles.extend(["-c", login.as_str()]);
        }
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
        let dbs = Self {
            pg,
            canonical: Cluster::Canonical.database().to_owned(),
            derived: Cluster::Derived.database().to_owned(),
        };
        if migrated {
            for cluster in Cluster::ALL {
                work_store::migrate(&dbs.pool_on(cluster, "work_owner"), cluster)
                    .await
                    .unwrap();
            }
        }
        dbs
    }

    fn url(&self, role: &str, database: &str) -> String {
        format!(
            "postgres://{role}@{}:{}/{database}",
            self.pg.host(),
            self.pg.port()
        )
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

    async fn tables(&self, database: &str, pattern: &str) -> String {
        self.pg
            .client(&[
                "psql",
                "-X",
                "-q",
                "-At",
                "-d",
                database,
                "-c",
                &format!("\\dt {pattern}"),
            ])
            .await
            .unwrap()
            .trim()
            .to_owned()
    }
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// The API and internal addresses of one server.
#[derive(Clone, Copy)]
pub(crate) struct Addresses {
    pub(crate) api: SocketAddr,
    pub(crate) internal: SocketAddr,
}

impl Addresses {
    fn free() -> Self {
        Self {
            api: free_address(),
            internal: free_address(),
        }
    }
}

const UNANSWERED_TIME_SOURCES: &str = r#"[ledger_time]
nts = [{ host = "127.0.0.1", port = 9 }, { host = "127.0.0.1", port = 9 }]
roughtime = [
  { address = "127.0.0.1:9", public_key = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=", version = "rfc" },
  { address = "127.0.0.1:9", public_key = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=", version = "rfc" },
  { address = "127.0.0.1:9", public_key = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=", version = "draft-11" },
]
"#;

/// How a server is started.
pub(crate) struct Launch<'a> {
    pub(crate) nats: &'a str,
    pub(crate) at: Addresses,
    pub(crate) stdout: Stdio,
    pub(crate) signer: Option<PathBuf>,
    pub(crate) publisher_role: &'a str,
}

impl<'a> Launch<'a> {
    pub(crate) fn new(nats: &'a str, at: Addresses) -> Self {
        Self {
            nats,
            at,
            stdout: Stdio::piped(),
            signer: None,
            publisher_role: "work_publisher",
        }
    }
}

fn server(dbs: &Databases, launch: Launch<'_>) -> Child {
    let name = format!("work-server-{}", launch.at.api.port());
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = launch.signer.unwrap_or_else(|| dir.join("no-signer.sock"));
    let canonical = dbs.url("work_app", &dbs.canonical);
    let derived = dbs.url("work_app", &dbs.derived);
    let sequencer = dbs.url("work_sequencer", &dbs.canonical);
    let checkpointer = dbs.url("work_checkpointer", &dbs.canonical);
    let publisher = dbs.url(launch.publisher_role, &dbs.canonical);
    let deriver = dbs.url("work_deriver", &dbs.derived);
    let config = format!(
        "{UNANSWERED_TIME_SOURCES}\n[signer]\nsocket = \"{}\"\n\n[checkpoint]\norigin_prefix = \"{PREFIX}\"\n\n[replica]\ndirectory = \"{}\"\n\n[publisher]\nsource = \"https://work.test\"\n",
        socket.display(),
        dir.join("replica").display(),
    );
    let path = dir.join("work.toml");
    std::fs::write(&path, config).unwrap();
    Command::new(env!("CARGO_BIN_EXE_work-server"))
        .env_clear()
        .env("WORK_CONFIG", path)
        .env("WORK_LISTEN", launch.at.api.to_string())
        .env("WORK_INTERNAL_LISTEN", launch.at.internal.to_string())
        .env("WORK_POSTGRES__CANONICAL", canonical)
        .env("WORK_POSTGRES__DERIVED", derived)
        .env("WORK_POSTGRES__SEQUENCER", sequencer)
        .env("WORK_POSTGRES__CHECKPOINTER", checkpointer)
        .env("WORK_POSTGRES__PUBLISHER", publisher)
        .env("WORK_POSTGRES__DERIVER", deriver)
        .env("WORK_NATS__URL", launch.nats)
        .env("WORK_STARTUP_TIMEOUT_MS", "5000")
        .env("PGPASSWORD", PASSWORD)
        .stdout(launch.stdout)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

async fn listening(child: &mut Child, listen: SocketAddr) {
    let up = tokio::time::timeout(DEADLINE, async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("work-server exited with {status} before listening");
            }
            if tokio::net::TcpStream::connect(listen).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    if up.is_err() {
        let _ = child.kill();
        panic!("work-server did not listen within {DEADLINE:?}");
    }
}

async fn refused(mut child: Child) -> String {
    let status: ExitStatus = tokio::time::timeout(DEADLINE, async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let _ = child.kill();
        panic!("work-server still runs after {DEADLINE:?}")
    });
    assert!(!status.success(), "{status}");
    let output = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `GET path` on `at`; the status code and the body.
pub(crate) async fn get(at: SocketAddr, path: &str) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(at).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: work\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    let status = answer.split(' ').nth(1).unwrap().parse().unwrap();
    let body = answer
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

// T-20 MD-14 OP-28 T-79
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_20_starts_with_postgres_18_and_jetstream_and_does_not_migrate() {
    let dbs = Databases::start(false).await;
    assert_eq!(dbs.pg.server_major_version().await.unwrap(), "18");
    let nats = Nats::start().await.unwrap();
    let at = Addresses::free();
    let mut child = server(&dbs, Launch::new(nats.url(), at));
    listening(&mut child, at.api).await;
    listening(&mut child, at.internal).await;

    for database in [&dbs.canonical, &dbs.derived] {
        assert_eq!(
            dbs.tables(database, "*._sqlx_migrations").await,
            "",
            "{database}"
        );
    }
    child.kill().unwrap();
    let log = String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).into_owned();
    for database in ["\"canonical\"", "\"derived\""] {
        assert!(
            log.lines()
                .any(|l| l.contains("postgres.connected") && l.contains(database)),
            "{log}"
        );
    }
    for role in [
        "\"sequencer\"",
        "\"checkpointer\"",
        "\"publisher\"",
        "\"deriver\"",
    ] {
        assert!(
            log.lines()
                .any(|l| l.contains("postgres.role_checked") && l.contains(role)),
            "{log}"
        );
    }
    assert!(log.contains("jetstream.checked"), "{log}");
}

// T-20 T-84 MD-14 T-9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_20_refuses_to_start_without_jetstream() {
    let dbs = Databases::start(false).await;
    let nats = Nats::start_without_jetstream().await.unwrap();
    let child = server(&dbs, Launch::new(nats.url(), Addresses::free()));
    let log = refused(child).await;
    assert!(log.contains("server.start_refused"), "{log}");
    assert!(log.contains("JetStream"), "{log}");
}

// T-20 T-84 MD-14 T-9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_20_refuses_to_start_when_nats_is_unreachable() {
    let dbs = Databases::start(false).await;
    let nowhere = format!("nats://{}", free_address());
    let child = server(&dbs, Launch::new(&nowhere, Addresses::free()));
    let log = refused(child).await;
    assert!(log.contains("server.start_refused"), "{log}");
}

// T-20 OP-2
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_20_refuses_to_start_when_a_database_is_missing() {
    let mut dbs = Databases::start(false).await;
    let nats = Nats::start().await.unwrap();
    dbs.derived = "work_absent".to_owned();
    let child = server(&dbs, Launch::new(nats.url(), Addresses::free()));
    let log = refused(child).await;
    assert!(log.contains("server.start_refused"), "{log}");
}

// T-79 OP-12 T-13 T-93
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_79_refuses_to_start_when_a_writing_pool_logs_in_as_another_role() {
    let dbs = Databases::start(false).await;
    let nats = Nats::start().await.unwrap();
    let launch = Launch {
        publisher_role: "work_app",
        ..Launch::new(nats.url(), Addresses::free())
    };
    let log = refused(server(&dbs, launch)).await;
    assert!(log.contains("server.start_refused"), "{log}");
    assert!(log.contains("publisher"), "{log}");
}

// T-21 T-84 T-28 T-39
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_21_losing_nats_after_start_does_not_stop_the_server() {
    let dbs = Databases::start(false).await;
    let nats = Nats::start().await.unwrap();
    let at = Addresses::free();
    let launch = Launch {
        stdout: Stdio::null(),
        ..Launch::new(nats.url(), at)
    };
    let mut child = server(&dbs, launch);
    listening(&mut child, at.internal).await;

    drop(nats);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(child.try_wait().unwrap().is_none(), "work-server exited");
    tokio::net::TcpStream::connect(at.api).await.unwrap();
    assert_eq!(get(at.internal, "/livez").await.0, 200);
    let (_, metrics) = get(at.internal, "/metrics").await;
    assert!(
        metrics.contains("work_dependency_up{dependency=\"nats\"} 0"),
        "{metrics}"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Signed arrivals are not used here; every check refuses.
struct Unsigned;

impl SignatureVerifier for Unsigned {
    fn check(&self, _cose_sign1: &[u8]) -> SignatureCheck {
        SignatureCheck::Rejected(Reason::Schema(Schema::Container))
    }
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

/// The golden unsigned human comment Claim, declared in `ledger` and concerning one Work.
fn comment(ledger: &LedgerId) -> Vec<u8> {
    let records: Json = serde_json::from_str(RECORDS).unwrap();
    let template = &records["records"][4];
    assert_eq!(template["id"], "record/claim-comment-private");
    let mut v = dcbor::decode(&unhex(template["hex"].as_str().unwrap()), Limits::CEILING).unwrap();
    let Value::Map(fields) = &mut v else {
        panic!("record")
    };
    for (key, value) in fields.iter_mut() {
        match key {
            Value::Text(k) if k == "ledger" => *value = Digest(*ledger.as_bytes()).to_value(),
            Value::Text(k) if k == "concerns" => {
                *value = Value::Array(vec![Value::Bytes(vec![7; 16])]);
            }
            _ => {}
        }
    }
    dcbor::encode(&v, Limits::CEILING).unwrap()
}

fn pending(ledger: &LedgerId, record: &[u8], actors: &ActorTypes) -> PendingRecord {
    admit(
        &Unsigned,
        ledger,
        Submission {
            arrival: Arrival::Unsigned {
                record,
                auth_context: AuthContext {
                    bytes: CONTEXT,
                    assurance: "aal2",
                    step_up: false,
                },
            },
            actor_types: actors,
            origin: Origin::Direct,
            understood_extensions: &[],
            limits: SemanticLimits::default(),
            event_type: "work.recorded",
            traceparent: TRACE,
            idempotency: None,
            inbound: None,
        },
    )
    .unwrap()
}

async fn next_event(consumer: &PullConsumer) -> async_nats::Message {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let mut batch = consumer
                .batch()
                .max_messages(1)
                .expires(Duration::from_secs(1))
                .messages()
                .await
                .unwrap();
            if let Some(next) = batch.next().await {
                return next.unwrap().split().0;
            }
        }
    })
    .await
    .unwrap()
}

// T-17 T-76 OP-34 T-81 P-42 T-39 T-93
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_17_a_committed_record_reaches_jetstream_through_the_server() {
    let dbs = Databases::start(true).await;
    let nats = Nats::start().await.unwrap();
    let at = Addresses::free();
    let launch = Launch {
        stdout: Stdio::null(),
        ..Launch::new(nats.url(), at)
    };
    let mut child = server(&dbs, launch);
    listening(&mut child, at.internal).await;

    let sequencer = SequencerPool::new(dbs.pool_on(Cluster::Canonical, "work_sequencer"))
        .await
        .unwrap();
    let opened = genesis(
        &GenesisInput {
            recorded_at_ms: AT,
            protocol: (1, 0),
            schema: [0x5c; 32],
            nonce: [0x2a; 32],
        },
        Durability::SingleNode,
    )
    .unwrap();
    let ledger = opened.ledger;
    Leader::open(&sequencer, &opened).await.unwrap();
    let mut leader = Leader::acquire(sequencer, ledger).await.unwrap();
    let actors = ActorTypes {
        author: ActorTypeEntry {
            actor_type: ActorType::Human,
            source: ActorTypeSource::AccessBinding,
        },
        on_behalf_of: vec![],
        evidence: vec![],
    };
    let record = pending(&ledger, &comment(&ledger), &actors);
    assert_eq!(record.outbox().len(), 1);
    let event_id = record.outbox()[0].event_id.clone();
    assert_eq!(leader.commit(AT + 5, &[record]).await.unwrap(), 1);

    let js = nats.jetstream().await.unwrap();
    let stream = tokio::time::timeout(DEADLINE, async {
        loop {
            if let Ok(stream) = js.get_stream("WORK_EVENTS").await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap();
    let consumer: PullConsumer = stream
        .create_consumer(pull::Config {
            deliver_policy: DeliverPolicy::All,
            ack_policy: AckPolicy::None,
            ..Default::default()
        })
        .await
        .unwrap();
    let message = next_event(&consumer).await;
    let headers = message.headers.clone().unwrap();
    assert_eq!(headers.get("Nats-Msg-Id").unwrap().as_str(), event_id);
    assert_eq!(headers.get("traceparent").unwrap().as_str(), TRACE);
    let ledger_hex = ledger.to_hex();
    let subject = message.subject.as_str();
    let tail = format!(".{ledger_hex}.work.recorded");
    assert!(subject.starts_with("work.evt."), "{subject}");
    assert!(subject.ends_with(&tail), "{subject}");
    let event: Json = serde_json::from_slice(&message.payload).unwrap();
    assert_eq!(event["id"], event_id.as_str());
    assert_eq!(event["ledger"], ledger_hex.as_str());
    assert_eq!(event["pos"], "1");
    assert_eq!(event["traceparent"], TRACE);
    let source = format!("https://work.test/ledgers/{ledger_hex}");
    assert_eq!(event["source"], source);

    let publisher = dbs.pool_on(Cluster::Canonical, "work_publisher");
    let drained = tokio::time::timeout(DEADLINE, async {
        loop {
            let mut tx = LedgerTx::begin(&publisher, &ledger).await.unwrap();
            let left = tx.outbox_pending(10).await.unwrap();
            tx.rollback().await.unwrap();
            if left.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(drained.is_ok(), "the pointer stayed in the outbox");
    child.kill().unwrap();
    child.wait().unwrap();
}
