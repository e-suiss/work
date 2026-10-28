use std::str::FromStr;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::StoreError;

/// A pool over `url` that connects eagerly and waits at most `timeout` for a connection (T-20).
/// A password missing from `url` comes from the libpq environment (`PGPASSWORD`, `PGPASSFILE`).
///
/// # Errors
/// [`StoreError::Db`] if the URL is invalid or no connection is made within `timeout`.
pub async fn connect(
    url: &str,
    application_name: &str,
    timeout: Duration,
) -> Result<PgPool, StoreError> {
    let options = PgConnectOptions::from_str(url)?.application_name(application_name);
    Ok(PgPoolOptions::new()
        .acquire_timeout(timeout)
        .connect_with(options)
        .await?)
}

/// The running server's `server_version_num`, e.g. `180006` for 18.6 (T-20).
///
/// # Errors
/// [`StoreError::Db`].
pub async fn server_version_num(pool: &PgPool) -> Result<i32, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT pg_catalog.current_setting('server_version_num')::int4")
            .fetch_one(pool)
            .await?,
    )
}
