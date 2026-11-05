//! `work-cli access pair [--tenant <tnt_…>]` (T-103 item 1): the server's pairing step at once, over every active tenant or one, with the server's own settings from the same environment names, printing each signal. It is the step `work-server` runs at start and every hour, not a second way of pairing.

use std::path::PathBuf;
use std::time::Duration;

use work_access_client::app::platform::{Report, Scope, Signal};
use work_access_client::domain::AccessError;
use work_access_client::ports::Random;
use work_ledger::{Rng as _, SystemRng};
use work_proto::id::TenantId;
use work_reconciler::adapters::PgPairing;
use work_reconciler::app::{AccessSettings, pair};
use work_store::{AccessPool, Pool};

use crate::clock::Wall;

/// The canonical database as a `work_access` login.
const DB_URL: &str = "WORK_POSTGRES__ACCESS";

/// Upper bound on connecting to the database.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The operating system's CSPRNG for assertion `jti`s.
struct Os;

impl Random for Os {
    fn fill(&self, out: &mut [u8]) -> Result<(), AccessError> {
        SystemRng
            .fill(out)
            .map_err(|_| AccessError::KeyStore("no randomness".to_owned()))
    }
}

/// The step's settings from the server's environment names; the module, token and call bound
/// default as in the server.
fn settings(var: &dyn Fn(&str) -> Option<String>) -> Result<AccessSettings, String> {
    let need = |name: &str| var(name).ok_or_else(|| format!("{name} is not set"));
    let timeout_ms = match var("WORK_ACCESS__CALL_TIMEOUT_MS") {
        Some(ms) => ms
            .parse::<u64>()
            .map_err(|_| "WORK_ACCESS__CALL_TIMEOUT_MS is not a number".to_owned())?,
        None => 5_000,
    };
    Ok(AccessSettings {
        issuer: need("WORK_SUISS__ACCESS")?,
        region: need("WORK_ACCESS__REGION")?,
        client_id: need("WORK_ACCESS_CLIENT_ID")?,
        receiver: format!("{}/v1/inbound/events", need("WORK_PUBLISHER__SOURCE")?),
        module: PathBuf::from(
            var("WORK_ACCESS__MODULE")
                .unwrap_or_else(|| "/usr/lib/softhsm/libsofthsm2.so".to_owned()),
        ),
        token: var("WORK_ACCESS__TOKEN").unwrap_or_else(|| "work".to_owned()),
        pin_file: PathBuf::from(need("WORK_ACCESS__PIN_FILE")?),
        roots_file: PathBuf::from(need("WORK_ACCESS__TLS_ROOTS")?),
        timeout: Duration::from_millis(timeout_ms),
    })
}

/// Runs the step over `tenant`, or every active tenant.
pub(crate) fn run(tenant: Option<TenantId>) -> Result<Report, String> {
    let env = |name: &str| std::env::var(name).ok();
    let settings = settings(&env)?;
    let url = env(DB_URL).ok_or_else(|| format!("{DB_URL} is not set"))?;
    let scope = tenant.map_or(Scope::All, Scope::Tenant);
    crate::runtime()?.block_on(async move {
        let pool = tokio::time::timeout(CONNECT_TIMEOUT, Pool::connect(&url))
            .await
            .map_err(|_| "the database did not answer".to_owned())?
            .map_err(|e| e.to_string())?;
        let pool = AccessPool::new(pool).await.map_err(|e| e.to_string())?;
        Ok(pair(&settings, &PgPairing::new(pool), Wall, Os, &scope).await)
    })
}

/// Whether the step ended without a signal the operator has to act on.
pub(crate) fn clean(report: &Report) -> bool {
    report
        .signals
        .iter()
        .all(|s| matches!(s, Signal::Cleared { .. } | Signal::StreamRecreated { .. }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    // T-103
    #[test]
    fn t_103_the_command_reads_the_server_settings_and_names_what_is_missing() {
        let mut env = BTreeMap::from([
            ("WORK_SUISS__ACCESS", "https://access.example"),
            ("WORK_ACCESS__REGION", "eu-central"),
            ("WORK_ACCESS_CLIENT_ID", "cli_work"),
            ("WORK_PUBLISHER__SOURCE", "https://work.example"),
            ("WORK_ACCESS__PIN_FILE", "/run/secrets/access-pin"),
            ("WORK_ACCESS__TLS_ROOTS", "/run/access/ca.crt"),
        ]);
        let read = |env: &BTreeMap<&str, &str>| {
            let env = env.clone();
            settings(&move |n: &str| env.get(n).map(|v| (*v).to_owned()))
        };
        let s = read(&env).unwrap();
        assert_eq!(s.receiver, "https://work.example/v1/inbound/events");
        assert_eq!(s.token, "work");
        assert_eq!(s.timeout, Duration::from_secs(5));
        env.insert("WORK_ACCESS__CALL_TIMEOUT_MS", "x");
        assert!(read(&env).is_err());
        env.remove("WORK_ACCESS__CALL_TIMEOUT_MS");
        env.remove("WORK_ACCESS_CLIENT_ID");
        assert_eq!(read(&env).unwrap_err(), "WORK_ACCESS_CLIENT_ID is not set");
        assert!(clean(&Report::default()));
        assert!(!clean(&Report {
            signals: vec![Signal::Failed {
                tenant: None,
                error: AccessError::Timeout,
            }],
            ..Report::default()
        }));
    }
}
