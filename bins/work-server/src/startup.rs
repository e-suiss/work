//! Start-up checks of the mandatory infrastructure (T-20, MD-14): both PostgreSQL databases
//! answer and run major version 18 or later, and NATS answers with JetStream enabled; otherwise
//! the process does not start. Migrations are not run here (OP-28). Once running, losing NATS
//! is only a delay (T-21, T-28): the client reconnects in the background and the loss is logged.

use std::future::Future;
use std::time::Duration;

use work_store::{Pool, StoreError};

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
    canonical: Pool,
    derived: Pool,
    nats: async_nats::Client,
}

impl Infrastructure {
    /// Connects to both databases and to NATS and checks them (T-20).
    pub(crate) async fn connect(config: &Config) -> Result<Self, StartupError> {
        let limit = config.startup_timeout();
        let canonical = postgres("canonical", &config.postgres.canonical, limit).await?;
        let derived = postgres("derived", &config.postgres.derived, limit).await?;
        let nats = nats(&config.nats.url, limit).await?;
        Ok(Self {
            canonical,
            derived,
            nats,
        })
    }

    /// Closes the pools and drains NATS, waiting at most `limit` for each.
    pub(crate) async fn close(self, limit: Duration) {
        if bounded("nats", limit, self.nats.drain()).await.is_err() {
            tracing::warn!(event = "nats.drain_failed", "NATS did not drain");
        }
        let _ = bounded("canonical", limit, self.canonical.close()).await;
        let _ = bounded("derived", limit, self.derived.close()).await;
    }
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

    // T-20 MD-14
    #[test]
    fn t_20_postgres_18_and_later_are_accepted() {
        for num in [180_000, 180_006, 190_002, i32::MAX] {
            assert_eq!(check_postgres_version(num), Ok(()), "{num}");
        }
    }

    // T-20 MD-14
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
