//! Work server (T-1). Reads configuration, installs telemetry and composes crates;
//! business logic lives in `crates/` (T-31).

mod config;
mod startup;

use std::process::ExitCode;

use config::Config;
use startup::Infrastructure;

fn main() -> ExitCode {
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

    if let Err(error) = work_telemetry::init(&config.log) {
        #[allow(clippy::print_stderr, reason = "telemetry failed to install")]
        {
            eprintln!("work-server: {error}");
        }
        return ExitCode::FAILURE;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "cannot start the async runtime");
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
    let served = serve(config).await;
    infrastructure.close(config.startup_timeout()).await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "server stopped with an error");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: &Config) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(listen = %config.listen, version = env!("CARGO_PKG_VERSION"), "work-server listening");
    axum::serve(listener, axum::Router::new())
        .with_graceful_shutdown(shutdown_signal())
        .await
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
