//! The conformant test executor (T-105): a real minimal executor of Work's coordination contract (RC-42) that connects to Access as a registered Party, pulls its deliveries from Work, runs a configurable step script per commitment and answers every request as RC-36 and RC-39 say. It is never deployed in production, fakes neither Access nor Relay and has no privileged path (RC-41). Started as `work-executor [--config <file>]`, or with `WORK_EXECUTOR_CONFIG` naming the file; `WORK_EXECUTOR_LEDGER` names the ledger over the file's.

mod access;
mod clock;
mod config;
mod doorbell;
mod protocol;
mod record;
mod runner;
mod script;
mod web;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tokio::sync::Notify;
use work_access_client::adapters::{public_config, roots};

use crate::access::{Identity, Work};
use crate::config::{CONFIG_ENV, Config, LEDGER_ENV};
use crate::runner::Shared;
use crate::web::Http;

fn config_path(args: &[String], env: Option<String>) -> Option<PathBuf> {
    match args {
        [flag, path, ..] if flag == "--config" => Some(PathBuf::from(path)),
        _ => env.map(PathBuf::from),
    }
}

#[allow(clippy::print_stderr, reason = "telemetry is not installed yet")]
fn refused(why: &str) -> ExitCode {
    eprintln!("work-executor: {why}");
    ExitCode::FAILURE
}

fn shared(config: Config) -> Result<Shared, String> {
    let identity = Identity::load(&config)?;
    let pem = std::fs::read(&config.access.tls_roots)
        .map_err(|e| format!("{}: {e}", config.access.tls_roots.display()))?;
    let tls = public_config(roots(&pem).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let work = Work::new(Http::new(tls), &config);
    Ok(Shared {
        config,
        identity,
        work,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = config_path(&args, std::env::var(CONFIG_ENV).ok()) else {
        return refused("no configuration: --config <file> or WORK_EXECUTOR_CONFIG");
    };
    let ledger = std::env::var(LEDGER_ENV).ok().filter(|l| !l.is_empty());
    let config = match Config::load(&path, ledger.as_deref()) {
        Ok(config) => config,
        Err(error) => return refused(&format!("invalid configuration: {error}")),
    };
    if let Err(error) = work_telemetry::init(&config.log) {
        return refused(&format!("telemetry: {error}"));
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return refused(&format!("runtime: {error}")),
    };
    let shared = match shared(config) {
        Ok(shared) => Arc::new(shared),
        Err(error) => {
            tracing::error!(
                event = "executor.start_refused",
                error = error.as_str(),
                "the executor does not start"
            );
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let notify = Arc::new(Notify::new());
        if let Some(listen) = shared.config.executor.doorbell.clone() {
            let ledger = shared.work.ledger().to_owned();
            let bell = Arc::clone(&notify);
            tokio::spawn(async move {
                if let Err(error) = doorbell::serve(&listen, ledger, bell).await {
                    tracing::warn!(event = "executor.doorbell_down", %error, "the doorbell is not served; the executor pulls");
                }
            });
        }
        tracing::info!(
            event = "executor.started",
            ledger = shared.work.ledger(),
            api = shared.config.work.api.as_str(),
            "work-executor started"
        );
        tokio::select! {
            () = runner::run(&shared, &notify) => {}
            _ = tokio::signal::ctrl_c() => {
                tracing::info!(event = "executor.stopped", "work-executor stopped");
            }
        }
    });
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-105
    #[test]
    fn t_105_the_configuration_file_is_named_by_flag_or_environment() {
        let flag = vec!["--config".to_owned(), "/etc/work-executor.toml".to_owned()];
        assert_eq!(
            config_path(&flag, Some("/other".to_owned())),
            Some(PathBuf::from("/etc/work-executor.toml"))
        );
        assert_eq!(
            config_path(&[], Some("/env.toml".to_owned())),
            Some(PathBuf::from("/env.toml"))
        );
        assert_eq!(config_path(&[], None), None);
    }
}
