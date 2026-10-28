//! Work command line: administration, export, replay and offline verification.

use std::process::ExitCode;

use work_store::Cluster;

const USAGE: &str = "usage: work-cli --version | work-cli migrate <canonical|derived>";

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "command line output"
)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cluster = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--version"] => {
            println!("work-cli {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ["migrate", name] => Cluster::parse(name),
        _ => None,
    };
    let Some(cluster) = cluster else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if let Err(e) = migrate(cluster) {
        eprintln!("migrate {}: {e}", cluster.database());
        return ExitCode::FAILURE;
    }
    println!("{} migrated", cluster.database());
    ExitCode::SUCCESS
}

/// The separate migration step (OP-28, T-36 rule 5); the node never migrates at start-up.
/// The connection comes from the libpq environment, as a login that can `SET ROLE work_owner`.
fn migrate(cluster: Cluster) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime
        .block_on(work_store::migrate_from_env(cluster))
        .map_err(|e| e.to_string())
}
