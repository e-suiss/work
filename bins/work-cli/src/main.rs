//! Work command line: administration, export, replay and offline verification.

use std::process::ExitCode;

use work_store::{Cluster, Durability, LedgerId, Pool, SequencerPool};

const USAGE: &str = "usage: work-cli --version | work-cli migrate <canonical|derived> | \
                     work-cli rebuild <ledger hex> <single-node|quorum>";

/// The live canonical database a rebuild reads, as a `work_app` login (OP-1).
const LIVE_URL: &str = "WORK_REBUILD_LIVE_URL";

/// The empty, migrated canonical database a rebuild writes, as a `work_sequencer` login (OP-1).
const TARGET_URL: &str = "WORK_REBUILD_TARGET_URL";

enum Command {
    Migrate(Cluster),
    Rebuild(LedgerId, Durability),
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
