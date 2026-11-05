//! Work command line: administration, export, replay and offline verification.

use std::process::ExitCode;

use suiss_crypto::secret::Secret;
use work_export::adapters::StoreSource;
use work_export::app::{self, Exported};
use work_export::domain::{Report, Trust, hex};
use work_ledger::{Node, Retention, S3Config, SystemRng, WormStore, tls_trusting};
use work_store::{
    ArchivePool, CellId, Cluster, Durability, ExportLog, LedgerId, Pool, SequencerPool,
};
use work_telemetry::{DEFAULT_METRIC_INTERVAL, Meters, MetricConfig, meter_provider};

const USAGE: &str = "usage: work-cli --version | work-cli migrate <canonical|derived> | \
                     work-cli rebuild <ledger hex> <single-node|quorum> | work-cli archive | \
                     work-cli export <ledger hex> <bundle> | work-cli verify <bundle> <trust>";

/// The cell a rebuild's scratch database leads the rebuilt ledger in (OP-9, OP-1 item 3).
const REBUILD_CELL: &str = "rebuild";

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

/// The OTLP/gRPC collector the sev-1 rebuild-diff counter is exported to; unset exports nothing
/// (OP-47 item 9, OP-18).
const OTLP_ENDPOINT: &str = "WORK_OTLP_ENDPOINT";

/// The canonical database an export reads, as a `work_app` login (P-2, T-10).
const EXPORT_URL: &str = "WORK_EXPORT_URL";

enum Command {
    Migrate(Cluster),
    Rebuild(LedgerId, Durability),
    Archive,
    Export(LedgerId, String),
    Verify(String, String),
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
        ["export", l, p] => LedgerId::from_hex(l).map(|l| Command::Export(l, (*p).to_owned())),
        ["verify", b, t] => Some(Command::Verify((*b).to_owned(), (*t).to_owned())),
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
                if let Err(e) = count_diff() {
                    eprintln!("rebuild-diff {}: metric not exported: {e}", ledger.to_hex());
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
        Some(Command::Export(ledger, path)) => match export(ledger, &path) {
            Ok(written) => {
                println!(
                    "exported {}: {} entries and {} checkpoints to {path}",
                    ledger.to_hex(),
                    written.entries,
                    written.checkpoints
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("export {}: {e}", ledger.to_hex());
                ExitCode::FAILURE
            }
        },
        Some(Command::Verify(bundle, trust)) => match verify(&bundle, &trust) {
            Ok(report) => {
                println!("{}", summary(&report));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("verify {bundle}: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Writes the `work-export/1` bundle of `ledger` to the new file `path` from the canonical
/// database at `WORK_EXPORT_URL`, which is only read (P-2 items 2 and 3, T-10).
fn export(ledger: LedgerId, path: &str) -> Result<Exported, String> {
    let url = std::env::var(EXPORT_URL).map_err(|_| format!("{EXPORT_URL} is not set"))?;
    runtime()?.block_on(async move {
        let pool = Pool::connect(&url).await.map_err(|e| e.to_string())?;
        let log = ExportLog::new(pool).await.map_err(|e| e.to_string())?;
        let file = std::fs::File::create_new(path).map_err(|e| format!("{path}: {e}"))?;
        let mut out = std::io::BufWriter::new(file);
        app::export(&StoreSource::new(log), &ledger, &mut out)
            .await
            .map_err(|e| e.to_string())
    })
}

/// Verifies the bundle at `bundle` under the trusted keys at `trust`, with no database, network
/// or Access (P-2 item 2).
fn verify(bundle: &str, trust: &str) -> Result<Report, String> {
    let read = |path: &str| std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"));
    let trust = Trust::parse(&read(trust)?).map_err(|e| e.to_string())?;
    app::verify(&read(bundle)?, &trust).map_err(|e| e.to_string())
}

/// The one-line summary of a verified bundle; it names what was checked, never truth or
/// authorisation (SEC-5).
fn summary(r: &Report) -> String {
    format!(
        "verified {}: {} entries ({} records: {} signed, {} with an Access context; {} \
         activations), root {}, {} checkpoints ({} log-signed, {} witness cosignatures), fold \
         through position {} with {} chains ({} conflicted)",
        hex(&r.ledger),
        r.entries,
        r.records,
        r.signed,
        r.auth_context,
        r.activations,
        hex(&r.root),
        r.checkpoints,
        r.checkpoints_signed,
        r.cosignatures,
        r.folded_through,
        r.chains,
        r.conflicted
    )
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
        let cell = CellId::new(REBUILD_CELL).ok_or_else(|| "rebuild cell".to_owned())?;
        let node = Node::new(cell, &SystemRng).map_err(|e| e.to_string())?;
        work_ledger::rebuild_diff(&live, &target, &node, ledger, profile)
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

/// The export settings of the rebuild-diff counter: `WORK_OTLP_ENDPOINT`, never with credentials
/// in it (T-56).
fn metric_config(endpoint: Option<String>) -> Result<MetricConfig, String> {
    let endpoint = endpoint.filter(|e| !e.is_empty());
    if endpoint.as_deref().is_some_and(|e| e.contains('@')) {
        return Err(format!("{OTLP_ENDPOINT} must not carry credentials"));
    }
    Ok(MetricConfig {
        service: "work-cli".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        endpoint,
        interval: DEFAULT_METRIC_INTERVAL,
    })
}

/// Counts one sev-1 rebuild-diff on `work.ledger.rebuild_diff`, with no label, and flushes it to
/// the collector before the process exits (§18 OP-47 item 9, OP-18 item 3).
fn count_diff() -> Result<(), String> {
    let config = metric_config(std::env::var(OTLP_ENDPOINT).ok())?;
    let runtime = runtime()?;
    let provider = {
        let _entered = runtime.enter();
        meter_provider(&config).map_err(|e| e.to_string())?
    };
    Meters::new(&provider).rebuild_diff().add(1, &[]);
    runtime
        .block_on(async move { tokio::task::spawn_blocking(move || provider.shutdown()).await })
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-47 OP-18 T-39 T-56
    #[test]
    fn op_47_the_rebuild_diff_counter_exports_only_where_configured() {
        assert_eq!(metric_config(None).unwrap().endpoint, None);
        assert_eq!(metric_config(Some(String::new())).unwrap().endpoint, None);
        assert_eq!(
            metric_config(Some("http://collector:4317".to_owned()))
                .unwrap()
                .endpoint
                .as_deref(),
            Some("http://collector:4317")
        );
        assert!(metric_config(Some("http://u:pw@collector:4317".to_owned())).is_err());
        assert_eq!(count_diff(), Ok(()));
    }
}
