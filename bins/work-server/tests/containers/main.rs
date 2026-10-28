//! `work-server` start-up against real PostgreSQL 18 and NATS (T-20, T-21, OP-28): it starts
//! only when both databases and JetStream answer, never migrates, and survives losing NATS.
//! These tests need Docker; `just test-containers` runs them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use work_testkit::{Nats, Postgres};

const ROLE: &str = "work_boot";
const PASSWORD: &str = "test-only-not-a-secret";
const DEADLINE: Duration = Duration::from_secs(60);

struct Databases {
    pg: Postgres,
    canonical: String,
    derived: String,
}

impl Databases {
    async fn start() -> Self {
        let pg = Postgres::start().await.unwrap();
        pg.client(&[
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            "postgres",
            "-c",
            &format!("CREATE ROLE {ROLE} LOGIN PASSWORD '{PASSWORD}'"),
        ])
        .await
        .unwrap();
        let canonical = pg.database().await.unwrap().name().to_owned();
        let derived = pg.database().await.unwrap().name().to_owned();
        Self {
            pg,
            canonical,
            derived,
        }
    }

    fn url(&self, database: &str) -> String {
        format!(
            "postgres://{ROLE}@{}:{}/{database}",
            self.pg.host(),
            self.pg.port()
        )
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

fn server(dbs: &Databases, nats_url: &str, listen: SocketAddr, stdout: Stdio) -> Child {
    Command::new(env!("CARGO_BIN_EXE_work-server"))
        .env_clear()
        .env(
            "WORK_CONFIG",
            format!("{}/absent-work.toml", env!("CARGO_TARGET_TMPDIR")),
        )
        .env("WORK_LISTEN", listen.to_string())
        .env("WORK_POSTGRES__CANONICAL", dbs.url(&dbs.canonical))
        .env("WORK_POSTGRES__DERIVED", dbs.url(&dbs.derived))
        .env("WORK_NATS__URL", nats_url)
        .env("WORK_STARTUP_TIMEOUT_MS", "5000")
        .env("PGPASSWORD", PASSWORD)
        .stdout(stdout)
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

// T-20 MD-14 OP-28
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_20_starts_with_postgres_18_and_jetstream_and_does_not_migrate() {
    let dbs = Databases::start().await;
    assert_eq!(dbs.pg.server_major_version().await.unwrap(), "18");
    let nats = Nats::start().await.unwrap();
    let listen = free_address();
    let mut child = server(&dbs, nats.url(), listen, Stdio::piped());
    listening(&mut child, listen).await;

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
    assert!(log.contains("jetstream.checked"), "{log}");
}

// T-20 MD-14 T-9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_20_refuses_to_start_without_jetstream() {
    let dbs = Databases::start().await;
    let nats = Nats::start_without_jetstream().await.unwrap();
    let child = server(&dbs, nats.url(), free_address(), Stdio::piped());
    let log = refused(child).await;
    assert!(log.contains("server.start_refused"), "{log}");
    assert!(log.contains("JetStream"), "{log}");
}

// T-20 MD-14 T-9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_20_refuses_to_start_when_nats_is_unreachable() {
    let dbs = Databases::start().await;
    let nowhere = format!("nats://{}", free_address());
    let child = server(&dbs, &nowhere, free_address(), Stdio::piped());
    let log = refused(child).await;
    assert!(log.contains("server.start_refused"), "{log}");
}

// T-20 OP-2
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_20_refuses_to_start_when_a_database_is_missing() {
    let mut dbs = Databases::start().await;
    let nats = Nats::start().await.unwrap();
    dbs.derived = "work_absent".to_owned();
    let child = server(&dbs, nats.url(), free_address(), Stdio::piped());
    let log = refused(child).await;
    assert!(log.contains("server.start_refused"), "{log}");
}

// T-21 T-28 T-39
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_21_losing_nats_after_start_does_not_stop_the_server() {
    let dbs = Databases::start().await;
    let nats = Nats::start().await.unwrap();
    let listen = free_address();
    let mut child = server(&dbs, nats.url(), listen, Stdio::null());
    listening(&mut child, listen).await;

    drop(nats);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(child.try_wait().unwrap().is_none(), "work-server exited");
    tokio::net::TcpStream::connect(listen).await.unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
}
