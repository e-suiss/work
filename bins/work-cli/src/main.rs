//! Work command line: administration, export, replay and offline verification.

use std::process::ExitCode;

use suiss_crypto::secret::Secret;
use work_ledger::{Retention, S3Config, WormStore, tls_trusting};
use work_store::{ArchivePool, Cluster, Durability, LedgerId, Pool, SequencerPool};

const USAGE: &str = "usage: work-cli --version | work-cli migrate <canonical|derived> | \
                     work-cli rebuild <ledger hex> <single-node|quorum> | work-cli archive";

/// The canonical database the archive job runs in, as a `work_archive` login (OP-35).
const ARCHIVE_URL: &str = "WORK_ARCHIVE_URL";

/// The archive bucket with Object Lock: endpoint, region, bucket, the days each copy stays
/// locked, and the PEM roots of an `https` endpoint (OP-35, OP-33 item 3).
const ARCHIVE_ENDPOINT: &str = "WORK_ARCHIVE_S3_ENDPOINT";
const ARCHIVE_REGION: &str = "WORK_ARCHIVE_S3_REGION";
const ARCHIVE_BUCKET: &str = "WORK_ARCHIVE_S3_BUCKET";
const ARCHIVE_RETENTION: &str = "WORK_ARCHIVE_RETENTION_DAYS";
const ARCHIVE_ROOTS: &str = "WORK_ARCHIVE_S3_CA_ROOTS";
const KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const SECRET: &str = "AWS_SECRET_ACCESS_KEY";

/// The live canonical database a rebuild reads, as a `work_app` login (OP-1).
const LIVE_URL: &str = "WORK_REBUILD_LIVE_URL";

/// The empty, migrated canonical database a rebuild writes, as a `work_sequencer` login (OP-1).
const TARGET_URL: &str = "WORK_REBUILD_TARGET_URL";

enum Command {
    Migrate(Cluster),
    Rebuild(LedgerId, Durability),
    Archive,
}

fn durability(name: &str) -> Option<Durability> {
    [Durability::SingleNode, Durability::Quorum]
        .into_iter()
        .find(|d| d.as_str() == name)
}

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "command line output"
)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--version"] => {
            println!("work-cli {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ["migrate", name] => Cluster::parse(name).map(Command::Migrate),
        ["rebuild", ledger, profile] => LedgerId::from_hex(ledger)
            .zip(durability(profile))
            .map(|(l, d)| Command::Rebuild(l, d)),
        ["archive"] => Some(Command::Archive),
        _ => None,
    };
    match command {
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Some(Command::Migrate(cluster)) => {
            if let Err(e) = migrate(cluster) {
                eprintln!("migrate {}: {e}", cluster.database());
                return ExitCode::FAILURE;
            }
            println!("{} migrated", cluster.database());
            ExitCode::SUCCESS
        }
        Some(Command::Rebuild(ledger, profile)) => match rebuild(ledger, profile) {
            Ok(report) if report.is_clean() => {
                println!(
                    "rebuild-diff {}: clean through position {}",
                    ledger.to_hex(),
                    report.through()
                );
                ExitCode::SUCCESS
            }
            Ok(report) => {
                eprintln!(
                    "rebuild-diff {}: sev-1, {} rows differ through position {}",
                    ledger.to_hex(),
                    report.rows(),
                    report.through()
                );
                for t in report.tables() {
                    eprintln!(
                        "  {}: {} missing, {} unexpected",
                        t.table,
                        t.missing.len(),
                        t.unexpected.len()
                    );
                }
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("rebuild {}: {e}", ledger.to_hex());
                ExitCode::FAILURE
            }
        },
        Some(Command::Archive) => match archive() {
            Ok(dropped) => {
                for (part, rows) in &dropped {
                    println!("archived {part}: {rows} rows copied, verified and dropped");
                }
                println!("{} cold partitions archived", dropped.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("archive: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

/// The separate migration step (OP-28, T-36 rule 5); the node never migrates at start-up.
/// The connection comes from the libpq environment, as a login that can `SET ROLE work_owner`.
fn migrate(cluster: Cluster) -> Result<(), String> {
    runtime()?
        .block_on(work_store::migrate_from_env(cluster))
        .map_err(|e| e.to_string())
}

/// The rebuild-diff of `ledger` (§18 OP-1 item 3): the live database from `WORK_REBUILD_LIVE_URL`
/// is only read, the rebuild goes to the database from `WORK_REBUILD_TARGET_URL`, which must not
/// hold the ledger yet.
fn rebuild(ledger: LedgerId, profile: Durability) -> Result<work_store::RebuildDiff, String> {
    let url = |name: &str| std::env::var(name).map_err(|_| format!("{name} is not set"));
    let live = url(LIVE_URL)?;
    let target = url(TARGET_URL)?;
    runtime()?.block_on(async move {
        let live = Pool::connect(&live).await.map_err(|e| e.to_string())?;
        let target = Pool::connect(&target).await.map_err(|e| e.to_string())?;
        let target = SequencerPool::new(target)
            .await
            .map_err(|e| e.to_string())?;
        work_ledger::rebuild_diff(&live, &target, ledger, profile)
            .await
            .map_err(|e| e.to_string())
    })
}

/// The cold archive (§18 OP-35, OP-34 item 5): every partition of `work.idempotency_key` and
/// `work.inbound_seen` whose month ended 30 days ago is copied slice by slice to the bucket with
/// Object Lock, verified, recorded and dropped by the archive role.
fn archive() -> Result<Vec<(String, u64)>, String> {
    let var = |name: &str| std::env::var(name).map_err(|_| format!("{name} is not set"));
    let url = var(ARCHIVE_URL)?;
    let days: u32 = var(ARCHIVE_RETENTION)?
        .parse()
        .map_err(|_| format!("{ARCHIVE_RETENTION} is not a number of days"))?;
    let retention = Retention::days(days).map_err(|e| e.to_string())?;
    let tls = match std::env::var(ARCHIVE_ROOTS) {
        Ok(path) => {
            let pem = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
            Some(tls_trusting(&pem).map_err(|e| e.to_string())?)
        }
        Err(_) => None,
    };
    let config = S3Config {
        endpoint: var(ARCHIVE_ENDPOINT)?,
        region: var(ARCHIVE_REGION)?,
        bucket: var(ARCHIVE_BUCKET)?,
        key_id: var(KEY_ID)?,
        secret: Secret::new(var(SECRET)?),
        tls,
    };
    let store = WormStore::new(config, retention).map_err(|e| e.to_string())?;
    runtime()?.block_on(async move {
        let pool = Pool::connect(&url).await.map_err(|e| e.to_string())?;
        let pool = ArchivePool::new(pool).await.map_err(|e| e.to_string())?;
        let now = pool.now_ms().await.map_err(|e| e.to_string())?;
        store.prepare(now).await.map_err(|e| e.to_string())?;
        work_ledger::archive_cold(&pool, &store)
            .await
            .map_err(|e| e.to_string())
    })
}
