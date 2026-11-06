//! Work server (T-1). Reads configuration, starts its parser workers before anything else,
//! installs telemetry and composes crates; business logic lives in `crates/` (T-31). Started as
//! `work-server parser-worker` it is a locked-down parser worker instead (T-72, T-94).

mod api;
mod config;
mod health;
mod inbound;
mod pairing;
mod parser;
mod services;
mod startup;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use config::Config;
use services::Services;
use startup::{AccessLink, Infrastructure, RelayLink, TimeDriver};
use tokio::sync::watch;
use work_http::common::TraceIds;
use work_http::inbound::{self as entry, Receiver};
use work_reconciler::adapters::PgInbound;

use crate::inbound::{AccessReceiver, TlsListener};
use work_ledger::{Rng as _, SystemRng};

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

    let run_as = config.parser.run_as.as_deref();
    let parsers = config
        .parser_timeout()
        .map_err(|e| e.to_string())
        .and_then(|timeout| {
            parser::pool(config.parser.workers, timeout, run_as).map_err(|e| e.to_string())
        });

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
                work_telemetry::init_with_otel(&config.log, &trace).map_err(|e| e.to_string())
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

    let _parsers = match parsers {
        Ok(pool) => {
            tracing::info!(
                event = "parser.workers_started",
                workers = pool.live(),
                "parser workers started"
            );
            Some(pool)
        }
        Err(error) => {
            tracing::error!(event = "parser.workers_unavailable", %error, "parser workers did not start; nothing can be scanned");
            None
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
    let access = match AccessLink::start(config, time.clock()).await {
        Ok(access) => access,
        Err(error) => {
            tracing::error!(event = "server.start_refused", %error, "Access refuses the start");
            time.stop();
            infrastructure.close(config.startup_timeout()).await;
            return ExitCode::FAILURE;
        }
    };
    let relay = match RelayLink::start(config, &access.client).await {
        Ok(relay) => relay,
        Err(error) => {
            tracing::error!(event = "server.start_refused", %error, "Relay refuses the start");
            access.stop();
            time.stop();
            infrastructure.close(config.startup_timeout()).await;
            return ExitCode::FAILURE;
        }
    };
    let services = match Services::start(config, &infrastructure, time.clock()) {
        Ok(services) => services,
        Err(error) => {
            tracing::error!(event = "server.start_refused", %error, "services do not start");
            relay.stop();
            access.stop();
            time.stop();
            infrastructure.close(config.startup_timeout()).await;
            return ExitCode::FAILURE;
        }
    };
    let health = services.health(
        &infrastructure,
        Arc::clone(&access.up),
        Arc::clone(&relay.up),
    );
    let receiver: Arc<dyn Receiver> = Arc::new(AccessReceiver::new(
        Arc::clone(&access.client),
        services.pairer(),
        PgInbound::new(infrastructure.sequencer.clone()),
        config.client_id_reader(),
        inbound::notices(config, &infrastructure, services.sequence()),
    ));
    let routes = api::routes(
        config,
        &api::Backing {
            canonical: &infrastructure.canonical,
            realms: &infrastructure.access,
            access: &access.client,
            pep: access.pep.as_deref(),
            sequence: services.sequence(),
        },
        Arc::new(SystemTraceIds),
    );
    let served = serve(config, routes, health::router(health), receiver).await;
    services.stop().await;
    relay.stop();
    access.stop();
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

/// New trace ids from the operating system's CSPRNG, for a request whose span has no trace
/// context (P-42).
struct SystemTraceIds;

impl TraceIds for SystemTraceIds {
    fn fresh(&self) -> Option<[u8; 24]> {
        let mut out = [0_u8; 24];
        SystemRng.fill(&mut out).ok()?;
        Some(out)
    }
}

async fn stopped(mut stop: watch::Receiver<bool>) {
    let _stopped = stop.wait_for(|s| *s).await.is_ok();
}

/// The event entry's listener (T-102 item 2); a certificate or key that does not load leaves
/// the entry unserved, so Access delivers again later.
async fn event_entry(config: &Config) -> std::io::Result<Option<TlsListener>> {
    let Some(addr) = config.inbound.listen else {
        return Ok(None);
    };
    match startup::inbound_tls(config) {
        Ok(tls) => {
            tracing::info!(event = "inbound.listening", listen = %addr, "event entry listening");
            Ok(Some(TlsListener::bind(addr, tls).await?))
        }
        Err(error) => {
            tracing::error!(event = "inbound.unserved", %error, "the event entry does not start");
            Ok(None)
        }
    }
}

async fn serve(
    config: &Config,
    routes: axum::Router,
    internal: axum::Router,
    receiver: Arc<dyn Receiver>,
) -> std::io::Result<()> {
    let api = tokio::net::TcpListener::bind(config.listen).await?;
    let health = tokio::net::TcpListener::bind(config.internal_listen).await?;
    let events = event_entry(config).await?;
    tracing::info!(listen = %config.listen, internal_listen = %config.internal_listen, version = env!("CARGO_PKG_VERSION"), "work-server listening");
    let (stop, stopping) = watch::channel(false);
    let routes = routes.into_make_service_with_connect_info::<SocketAddr>();
    let api = axum::serve(api, routes)
        .with_graceful_shutdown(stopped(stopping.clone()))
        .into_future();
    let health = axum::serve(health, internal)
        .with_graceful_shutdown(stopped(stopping.clone()))
        .into_future();
    let events = async move {
        if let Some(listener) = events {
            axum::serve(listener, entry::router(receiver))
                .with_graceful_shutdown(stopped(stopping))
                .await
        } else {
            stopped(stopping).await;
            Ok(())
        }
    };
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        let _sent = stop.send(true);
    });
    let served = tokio::try_join!(api, health, events).map(|((), (), ())| ());
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
