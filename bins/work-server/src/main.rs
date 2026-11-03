//! Work server (T-1). Reads configuration, installs telemetry and composes crates;
//! business logic lives in `crates/` (T-31). Started as `work-server parser-worker` it is a
//! locked-down parser worker instead (T-72).

mod config;
mod health;
mod parser;
mod services;
mod startup;

use std::process::ExitCode;

use config::Config;
use services::Services;
use startup::{Infrastructure, TimeDriver};
use tokio::sync::watch;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(parser::MODE) {
        return parser::main(args.get(1..).unwrap_or_default());
    }
    let config = match Config::load() {
        Ok(config) => config,
        Err(error) => {
            #[allow(clippy::print_stderr, reason = "telemetry is not installed yet")]
            {
                eprintln!("work-server: invalid configuration: {error}");
            }
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            #[allow(clippy::print_stderr, reason = "telemetry is not installed yet")]
            {
                eprintln!("work-server: cannot start the async runtime: {error}");
            }
            return ExitCode::FAILURE;
        }
    };

    let telemetry = {
        let _entered = runtime.enter();
        config
            .trace_config()
            .map_err(|e| e.to_string())
            .and_then(|trace| {
                work_telemetry::init_with_traces(&config.log, &trace).map_err(|e| e.to_string())
            })
    };
    let _telemetry = match telemetry {
        Ok(telemetry) => telemetry,
        Err(error) => {
            #[allow(clippy::print_stderr, reason = "telemetry failed to install")]
            {
                eprintln!("work-server: {error}");
            }
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(run(&config))
}

async fn run(config: &Config) -> ExitCode {
    let infrastructure = match Infrastructure::connect(config).await {
        Ok(infrastructure) => infrastructure,
        Err(error) => {
            tracing::error!(event = "server.start_refused", %error, "mandatory infrastructure is not usable");
            return ExitCode::FAILURE;
        }
    };
    let time = match TimeDriver::start(config) {
        Ok(time) => time,
        Err(error) => {
            tracing::error!(event = "server.start_refused", %error, "ledger time does not start");
            infrastructure.close(config.startup_timeout()).await;
            return ExitCode::FAILURE;
        }
    };
    let services = match Services::start(config, &infrastructure, time.clock()) {
        Ok(services) => services,
        Err(error) => {
            tracing::error!(event = "server.start_refused", %error, "services do not start");
            time.stop();
            infrastructure.close(config.startup_timeout()).await;
            return ExitCode::FAILURE;
        }
    };
    let served = serve(config, health::router(services.health(&infrastructure))).await;
    services.stop();
    time.stop();
    infrastructure.close(config.startup_timeout()).await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "server stopped with an error");
            ExitCode::FAILURE
        }
    }
}

async fn stopped(mut stop: watch::Receiver<bool>) {
    let _stopped = stop.wait_for(|s| *s).await.is_ok();
}

async fn serve(config: &Config, internal: axum::Router) -> std::io::Result<()> {
    let api = tokio::net::TcpListener::bind(config.listen).await?;
    let health = tokio::net::TcpListener::bind(config.internal_listen).await?;
    tracing::info!(listen = %config.listen, internal_listen = %config.internal_listen, version = env!("CARGO_PKG_VERSION"), "work-server listening");
    let (stop, stopping) = watch::channel(false);
    let api = axum::serve(api, axum::Router::new())
        .with_graceful_shutdown(stopped(stopping.clone()))
        .into_future();
    let health = axum::serve(health, internal)
        .with_graceful_shutdown(stopped(stopping))
        .into_future();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        let _sent = stop.send(true);
    });
    let served = tokio::try_join!(api, health).map(|((), ())| ());
    signal.abort();
    served
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => tracing::info!("SIGTERM received; shutting down"),
                    _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received; shutting down"),
                }
            }
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM; only SIGINT stops the server");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
