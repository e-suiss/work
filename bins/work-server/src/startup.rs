//! Start-up checks of the mandatory infrastructure (T-20, T-84, MD-14): both PostgreSQL
//! databases answer and run major version 18 or later, the sequencer, checkpointer, publisher,
//! deriver and Access pairing pools log in as their own roles (T-79, OP-12, T-103), and NATS answers with JetStream enabled
//! within the start-up timeout; otherwise the process does not start. Migrations are not run
//! here (OP-28). Once running, losing NATS is only a delay (T-21, T-28, T-84): the client
//! reconnects in the background and the loss is logged. The ledger time driver starts here
//! too: its sources are configured and counted at load (OP-32 item 4, OP-43 item 3), and a source
//! that does not answer yet never blocks start-up (OP-43 item 2). The signer is not needed to
//! start; until it answers the process is not ready and nothing is checkpointed (T-39 rule 6).
//! Access's discovery is read here too (T-96, E-2): an answer that refuses start stops the
//! process, while an Access that does not answer is an outage that refuses consequential actions
//! and never readiness (T-28).

use std::future::Future;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use work_access_client::adapters::{DEFAULT_TIMEOUT, HttpsTransport, public_config, roots};
use work_access_client::app::{Client, DISCOVERY_INTERVAL_MS};
use work_access_client::ports::Clock as AccessClockPort;
use work_ledger::SystemRng;
use work_ledger::time::{
    LedgerTime, NTS_EVENT_QUEUE, ProcessMonotonic, RoughtimeUdp, read_roots, spawn_nts,
};
use work_store::{
    AccessPool, CheckpointerPool, DeriverPool, Pool, PublisherPool, SequencerPool, StoreError,
};

use crate::config::Config;

/// The lowest accepted `server_version_num` (T-20).
pub(crate) const MIN_POSTGRES_VERSION_NUM: i32 = 180_000;

const APPLICATION_NAME: &str = "work-server";

/// The server runs a PostgreSQL major version below 18.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("PostgreSQL server_version_num {found} is below the required {MIN_POSTGRES_VERSION_NUM}")]
pub(crate) struct PostgresTooOld {
    pub(crate) found: i32,
}

/// Why the process refused to start.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StartupError {
    #[error("{database}: {source}")]
    Postgres {
        database: &'static str,
        source: StoreError,
    },
    #[error("{database}: {source}")]
    PostgresVersion {
        database: &'static str,
        source: PostgresTooOld,
    },
    #[error("{0}: no answer within {1:?}")]
    Timeout(&'static str, Duration),
    #[error("nats: {0}")]
    Nats(#[from] async_nats::ConnectError),
    #[error("nats: JetStream is not available: {0}")]
    JetStream(#[from] async_nats::jetstream::context::AccountError),
    #[error("ledger_time.nts_roots: {0}")]
    NtsRoots(std::io::Error),
    #[error("ledger time: {0}")]
    LedgerTime(String),
    #[error("configuration: {0}")]
    Config(String),
    #[error("access: {0}")]
    Access(String),
}

/// Ledger time as the Access client reads it; while ledger time is unavailable the client is at
/// the end of time and refuses every consequential call (OP-6, T-28).
#[derive(Debug, Clone)]
pub(crate) struct AccessClock(LedgerTime<ProcessMonotonic>);

impl AccessClockPort for AccessClock {
    fn now_ms(&self) -> u64 {
        self.0.read().unwrap_or(u64::MAX)
    }
}

/// Whether the discovery of the `[suiss] access` issuer last answered, and the task that reads
/// it again every [`DISCOVERY_INTERVAL_MS`] (T-96 items 1, 2). The process holds no PEP
/// certificate yet, so its client refuses every consequential call.
#[derive(Debug)]
pub(crate) struct AccessLink {
    pub(crate) up: Arc<AtomicBool>,
    refresh: JoinHandle<()>,
}

impl AccessLink {
    /// Reads Access's discovery once. An answer that refuses start (another issuer, version or
    /// region, a missing capability) stops the process; an Access that does not answer only
    /// lowers the `access` gauge until a later read answers (T-96 item 2, T-28, T-93 item 3).
    pub(crate) async fn start(
        config: &Config,
        time: LedgerTime<ProcessMonotonic>,
    ) -> Result<Self, StartupError> {
        let refused = |e: &dyn std::fmt::Display| StartupError::Access(e.to_string());
        let (issuer, region, pem) = config.access().map_err(|e| refused(&e))?;
        let tls = public_config(roots(&pem).map_err(|e| refused(&e))?).map_err(|e| refused(&e))?;
        let client = Arc::new(Client::new(
            HttpsTransport::new(tls, DEFAULT_TIMEOUT),
            AccessClock(time),
            issuer,
            region,
            0,
        ));
        let up = Arc::new(AtomicBool::new(false));
        match client.discover().await {
            Ok(doc) => {
                up.store(true, Ordering::Relaxed);
                tracing::info!(
                    event = "access.discovered",
                    issuer = doc.issuer.as_str(),
                    relay = doc.relay.as_str(),
                    "Access discovery read"
                );
            }
            Err(error) if error.code() == "start_refused" => return Err(refused(&error)),
            Err(error) => tracing::warn!(
                event = "access.unreachable",
                %error,
                "Access does not answer; consequential actions are refused until it does"
            ),
        }
        let refresh = tokio::spawn(rediscover(client, Arc::clone(&up)));
        Ok(Self { up, refresh })
    }

    /// Stops the refresh.
    pub(crate) fn stop(self) {
        self.refresh.abort();
    }
}

async fn rediscover(client: Arc<Client<HttpsTransport, AccessClock>>, up: Arc<AtomicBool>) {
    let mut ticks = tokio::time::interval(Duration::from_millis(DISCOVERY_INTERVAL_MS));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticks.tick().await;
    loop {
        ticks.tick().await;
        match client.discover().await {
            Ok(_) => up.store(true, Ordering::Relaxed),
            Err(error) => {
                up.store(false, Ordering::Relaxed);
                tracing::warn!(
                    event = "access.unreachable",
                    %error,
                    "Access discovery failed; the last document is kept"
                );
            }
        }
    }
}

/// The running ledger time driver: one per NTS server, the NTS event follower and the
/// Roughtime rounds (OP-32, OP-43).
#[derive(Debug)]
pub(crate) struct TimeDriver {
    time: LedgerTime<ProcessMonotonic>,
    handles: Vec<JoinHandle<()>>,
}

impl TimeDriver {
    /// Starts the driver on the configured sources.
    pub(crate) fn start(config: &Config) -> Result<Self, StartupError> {
        let roots = match &config.ledger_time.nts_roots {
            Some(path) => {
                let file = std::fs::File::open(path).map_err(StartupError::NtsRoots)?;
                read_roots(&mut BufReader::new(file)).map_err(StartupError::NtsRoots)?
            }
            None => Vec::new(),
        };
        let nts = config.nts_servers();
        let roughtime = config
            .roughtime_servers()
            .map_err(|e| StartupError::LedgerTime(e.to_string()))?;
        let mono = Arc::new(ProcessMonotonic::start());
        let time = LedgerTime::new(nts.len(), roughtime.len(), Arc::clone(&mono))
            .map_err(|e| StartupError::LedgerTime(e.to_string()))?;
        let (events, received) = mpsc::channel(NTS_EVENT_QUEUE);
        let mut handles = spawn_nts(nts, roots, &mono, &events)
            .map_err(|e| StartupError::LedgerTime(e.to_string()))?;
        handles.push(tokio::spawn(time.clone().follow_nts(received)));
        let rounds = time.clone();
        let udp = RoughtimeUdp::new(roughtime, mono, Arc::new(SystemRng));
        handles.push(tokio::spawn(rounds.run_roughtime(udp)));
        tracing::info!(
            event = "ledger_time.started",
            nts = config.ledger_time.nts.len(),
            roughtime = config.ledger_time.roughtime.len(),
            "ledger time driver started"
        );
        Ok(Self { time, handles })
    }

    /// The ledger time the `Clock` port reads (OP-6, OP-32).
    pub(crate) fn clock(&self) -> LedgerTime<ProcessMonotonic> {
        self.time.clone()
    }

    /// Stops every part of the driver.
    pub(crate) fn stop(self) {
        for handle in self.handles {
            handle.abort();
        }
    }
}

/// Accepts PostgreSQL 18 or later (T-20).
pub(crate) const fn check_postgres_version(num: i32) -> Result<(), PostgresTooOld> {
    if num < MIN_POSTGRES_VERSION_NUM {
        return Err(PostgresTooOld { found: num });
    }
    Ok(())
}

/// The connections checked at start-up, held for the life of the process.
#[derive(Debug)]
pub(crate) struct Infrastructure {
    pub(crate) canonical: Pool,
    pub(crate) derived: Pool,
    pub(crate) nats: async_nats::Client,
    pub(crate) sequencer: SequencerPool,
    pub(crate) checkpointer: CheckpointerPool,
    pub(crate) publisher: PublisherPool,
    pub(crate) deriver: Pool,
    pub(crate) access: AccessPool,
    roles: Vec<(&'static str, Pool)>,
}

impl Infrastructure {
    /// Connects to both databases, to the canonical one as each writing role, and to NATS, and
    /// checks them (T-20).
    pub(crate) async fn connect(config: &Config) -> Result<Self, StartupError> {
        let limit = config.startup_timeout();
        let pg = &config.postgres;
        let canonical = postgres("canonical", &pg.canonical, limit).await?;
        let derived = postgres("derived", &pg.derived, limit).await?;
        let sequencer_pool = postgres("sequencer", &pg.sequencer, limit).await?;
        let sequencer = role(
            "sequencer",
            limit,
            SequencerPool::new(sequencer_pool.clone()),
        )
        .await?;
        let checkpointer_pool = postgres("checkpointer", &pg.checkpointer, limit).await?;
        let checkpointer = role(
            "checkpointer",
            limit,
            CheckpointerPool::new(checkpointer_pool.clone()),
        )
        .await?;
        let publisher_pool = postgres("publisher", &pg.publisher, limit).await?;
        let publisher = role(
            "publisher",
            limit,
            PublisherPool::new(publisher_pool.clone()),
        )
        .await?;
        let deriver_pool = postgres("deriver", &pg.deriver, limit).await?;
        role("deriver", limit, DeriverPool::new(deriver_pool.clone())).await?;
        let access_pool = postgres("access", &pg.access, limit).await?;
        let access = role("access", limit, AccessPool::new(access_pool.clone())).await?;
        let nats = nats(&config.nats.url, limit).await?;
        Ok(Self {
            canonical,
            derived,
            nats,
            sequencer,
            checkpointer,
            publisher,
            deriver: deriver_pool.clone(),
            access,
            roles: vec![
                ("sequencer", sequencer_pool),
                ("checkpointer", checkpointer_pool),
                ("publisher", publisher_pool),
                ("deriver", deriver_pool),
                ("access", access_pool),
            ],
        })
    }

    /// Closes the pools and drains NATS, waiting at most `limit` for each.
    pub(crate) async fn close(self, limit: Duration) {
        if bounded("nats", limit, self.nats.drain()).await.is_err() {
            tracing::warn!(event = "nats.drain_failed", "NATS did not drain");
        }
        let _ = bounded("canonical", limit, self.canonical.close()).await;
        let _ = bounded("derived", limit, self.derived.close()).await;
        for (name, pool) in self.roles {
            let _ = bounded(name, limit, pool.close()).await;
        }
    }
}

async fn role<T>(
    database: &'static str,
    limit: Duration,
    check: impl Future<Output = Result<T, StoreError>>,
) -> Result<T, StartupError> {
    let checked = bounded(database, limit, check)
        .await?
        .map_err(|source| StartupError::Postgres { database, source })?;
    tracing::info!(event = "postgres.role_checked", database);
    Ok(checked)
}

async fn bounded<T>(
    what: &'static str,
    limit: Duration,
    call: impl Future<Output = T>,
) -> Result<T, StartupError> {
    tokio::time::timeout(limit, call)
        .await
        .map_err(|_| StartupError::Timeout(what, limit))
}

async fn postgres(
    database: &'static str,
    url: &str,
    limit: Duration,
) -> Result<Pool, StartupError> {
    let err = |source| StartupError::Postgres { database, source };
    let pool = bounded(
        database,
        limit,
        work_store::connect(url, APPLICATION_NAME, limit),
    )
    .await?
    .map_err(err)?;
    let num = bounded(database, limit, work_store::server_version_num(&pool))
        .await?
        .map_err(err)?;
    check_postgres_version(num)
        .map_err(|source| StartupError::PostgresVersion { database, source })?;
    tracing::info!(
        event = "postgres.connected",
        database,
        server_version_num = num
    );
    Ok(pool)
}

async fn nats(url: &str, limit: Duration) -> Result<async_nats::Client, StartupError> {
    let options = match (std::env::var("NATS_USER"), std::env::var("NATS_PASSWORD")) {
        (Ok(user), Ok(password)) => {
            async_nats::ConnectOptions::with_user_and_password(user, password)
        }
        _ => async_nats::ConnectOptions::new(),
    };
    let client = bounded(
        "nats",
        limit,
        options
            .name(APPLICATION_NAME)
            .connection_timeout(limit)
            .request_timeout(Some(limit))
            .event_callback(|event| async move {
                match event {
                    async_nats::Event::Connected => {
                        tracing::info!(event = "nats.connected", "NATS connected");
                    }
                    async_nats::Event::Disconnected => tracing::warn!(
                        event = "nats.disconnected",
                        "NATS lost; consumers fall back to polling the outbox"
                    ),
                    other => tracing::warn!(event = "nats.event_received", nats = %other),
                }
            })
            .connect(url),
    )
    .await??;
    let account = bounded(
        "nats JetStream",
        limit,
        async_nats::jetstream::new(client.clone()).query_account(),
    )
    .await??;
    tracing::info!(
        event = "jetstream.checked",
        jetstream_streams = account.streams,
        "NATS JetStream is available"
    );
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-20 MD-14 T-93
    #[test]
    fn t_20_postgres_18_and_later_are_accepted() {
        for num in [180_000, 180_006, 190_002, i32::MAX] {
            assert_eq!(check_postgres_version(num), Ok(()), "{num}");
        }
    }

    // T-20 MD-14 T-93
    #[test]
    fn t_20_postgres_older_than_18_is_refused() {
        for num in [170_006, 179_999, 160_000, 90_624, 0, -1, i32::MIN] {
            assert_eq!(
                check_postgres_version(num),
                Err(PostgresTooOld { found: num }),
                "{num}"
            );
        }
    }
}
