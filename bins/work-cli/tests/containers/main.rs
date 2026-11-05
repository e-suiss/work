//! `work-cli export` and `work-cli verify` against real PostgreSQL 18 (P-2, T-10, MD-12 item 5):
//! a ledger opened with its genesis and a version activation is exported from the canonical
//! database as `work_app` and verified from the file alone, with no database, network or Access.
//! These tests need Docker; `just test-containers` runs them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::process::Command;

use work_export::adapters::StoreSource;
use work_export::app;
use work_export::domain::Trust;
use work_kernel::record::ProtocolVersion;
use work_kernel::rules::RuleSet;
use work_ledger::{ActivationRequest, GenesisInput, Leader, Node, Rng, RngError, genesis};
use work_store::{CellId, Cluster, Durability, ExportLog, Pool, SequencerPool};
use work_testkit::Postgres;

const PASSWORD: &str = "test-only-not-a-secret";
const LOGINS: &str = "ALTER ROLE work_owner LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_sequencer LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_app LOGIN PASSWORD 'test-only-not-a-secret';";
const AT: u64 = 1_792_749_600_123;

#[derive(Debug)]
struct Holder(u8);

impl Rng for Holder {
    fn fill(&self, out: &mut [u8]) -> Result<(), RngError> {
        out.fill(self.0);
        Ok(())
    }
}

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

    fn url(&self, role: &str) -> String {
        format!(
            "postgres://{role}:{PASSWORD}@{}:{}/{}",
            self.pg.host(),
            self.pg.port(),
            Cluster::Canonical.database()
        )
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
}

// MD-12 P-2 T-10 P-110 T-31
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn md_12_a_ledger_exported_by_work_cli_verifies_without_the_database() {
    let env = Env::start().await;
    let pool = SequencerPool::new(env.pool(Cluster::Canonical, "work_sequencer"))
        .await
        .unwrap();
    let input = GenesisInput {
        recorded_at_ms: AT,
        protocol: (0, 9),
        schema: [0x5c; 32],
        nonce: [0x52; 32],
    };
    let opened = genesis(&input, Durability::SingleNode).unwrap();
    let ledger = opened.ledger;
    let cell = CellId::new("cell-a").unwrap();
    Leader::open(&pool, &opened, &cell).await.unwrap();
    let v0_9 = ProtocolVersion { major: 0, minor: 9 };
    let v1_0 = ProtocolVersion { major: 1, minor: 0 };
    let node = Node::new(cell, &Holder(1))
        .unwrap()
        .with_protocols(&[v0_9, v1_0]);
    let mut leader = Leader::acquire(pool, ledger, &node).await.unwrap();
    let request = ActivationRequest {
        protocol: v1_0,
        schema: *RuleSet::V1_0.schema().as_bytes(),
        auth_context: [0x0c; 32],
        assurance: "aal3".to_owned(),
        step_up: true,
    };
    let at = AT.checked_add(1000).unwrap();
    assert_eq!(leader.activate(at, &request).await.unwrap(), 1);

    let log = ExportLog::new(env.pool(Cluster::Canonical, "work_app"))
        .await
        .unwrap();
    let mut bundle = Vec::new();
    let written = app::export(&StoreSource::new(log), &ledger, &mut bundle)
        .await
        .unwrap();
    assert_eq!((written.entries, written.checkpoints), (2, 0));
    let text = String::from_utf8(bundle).unwrap();
    let report = app::verify(&text, &Trust::default()).unwrap();
    assert_eq!(report.ledger, *ledger.as_bytes());
    assert_eq!((report.entries, report.records, report.activations), (2, 0, 1));
    assert!(
        ExportLog::new(env.pool(Cluster::Canonical, "work_sequencer"))
            .await
            .is_err()
    );

    let dir = std::env::temp_dir().join(format!("work-export-{}", ledger.to_hex()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bundle.jsonl");
    let trust = dir.join("trust.json");
    std::fs::write(&trust, r#"{"authors": []}"#).unwrap();
    let cli = env!("CARGO_BIN_EXE_work-cli");
    let export = |target: &std::path::Path| {
        Command::new(cli)
            .env("WORK_EXPORT_URL", env.url("work_app"))
            .args(["export", &ledger.to_hex(), target.to_str().unwrap()])
            .output()
            .unwrap()
    };
    let exported = export(&path);
    assert!(exported.status.success(), "{}", String::from_utf8_lossy(&exported.stderr));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    assert!(!export(&path).status.success());
    let verified = Command::new(cli)
        .env_remove("WORK_EXPORT_URL")
        .args(["verify", path.to_str().unwrap(), trust.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(verified.status.success(), "{}", String::from_utf8_lossy(&verified.stderr));
    let line = String::from_utf8(verified.stdout).unwrap();
    assert!(line.starts_with(&format!("verified {}: 2 entries", ledger.to_hex())), "{line}");
    std::fs::remove_dir_all(&dir).unwrap();
}
