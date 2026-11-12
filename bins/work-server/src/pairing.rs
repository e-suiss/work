//! Work's Access pairing and event stream upkeep in the server (T-103 item 1): the step runs once at start and then every hour beside the tenant reconciliation, on ledger time and the operating system's CSPRNG; every signal is a log event and the gauges `work_access_unpaired_realms`, `work_access_event_stream_recreated_total` and `work_access_event_stream_up` go to `/metrics`. A step that fails never stops the server; the next hour tries again.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::task::JoinHandle;
use work_access_client::app::platform::{Report, Scope, Signal};
use work_access_client::domain::AccessError;
use work_access_client::domain::tenants::RECONCILE_INTERVAL_MS;
use work_access_client::ports::{Clock, Random};
use work_ledger::time::{LedgerTime, ProcessMonotonic};
use work_ledger::{Rng as _, SystemRng};
use work_proto::id::TenantId;
use work_reconciler::adapters::PgPairing;
use work_reconciler::app::{AccessSettings, pair};

/// Ledger time as the pairing step's clock; no trusted time reads as the epoch, so nothing is
/// signed and every assertion is refused until ledger time is back.
#[derive(Clone)]
pub(crate) struct Ledger(pub(crate) LedgerTime<ProcessMonotonic>);

impl Clock for Ledger {
    fn now_ms(&self) -> u64 {
        self.0.read().unwrap_or_default()
    }
}

/// The operating system's CSPRNG for assertion `jti`s.
pub(crate) struct Os;

impl Random for Os {
    fn fill(&self, out: &mut [u8]) -> Result<(), AccessError> {
        SystemRng
            .fill(out)
            .map_err(|_| AccessError::KeyStore("no randomness".to_owned()))
    }
}

/// The gauges of the last step.
#[derive(Debug, Default)]
pub(crate) struct PairingStats {
    unpaired: AtomicU64,
    recreated: AtomicU64,
    stream_up: AtomicBool,
}

impl PairingStats {
    fn record(&self, report: &Report) {
        if let Some(n) = report.unpaired_realms {
            self.unpaired.store(n, Ordering::Relaxed);
        }
        if let Some(n) = report.recreated {
            self.recreated.store(n, Ordering::Relaxed);
        }
        self.stream_up.store(report.stream_up, Ordering::Relaxed);
    }

    /// `work_access_unpaired_realms`.
    pub(crate) fn unpaired(&self) -> u64 {
        self.unpaired.load(Ordering::Relaxed)
    }

    /// `work_access_event_stream_recreated_total`.
    pub(crate) fn recreated(&self) -> u64 {
        self.recreated.load(Ordering::Relaxed)
    }

    /// `work_access_event_stream_up`.
    pub(crate) fn stream_up(&self) -> bool {
        self.stream_up.load(Ordering::Relaxed)
    }
}

fn log(report: &Report) {
    for signal in &report.signals {
        tracing::warn!(event = signal.event(), %signal, "Access pairing signal");
    }
    tracing::info!(
        event = "access.pairing_ran",
        tenants = report.tenants,
        paired = report.paired,
        signals = report.signals.len(),
        "Access pairing step ran"
    );
}

/// One pairing step over a scope, with what it needs and the gauges it sets; the hourly task
/// and `tenant.created` share it (T-103 item 1, T-102 item 5).
#[derive(Clone)]
pub(crate) struct Pairer {
    pub(crate) settings: Arc<AccessSettings>,
    pub(crate) store: PgPairing,
    pub(crate) clock: LedgerTime<ProcessMonotonic>,
    pub(crate) stats: Arc<PairingStats>,
}

/// How many steps a `tenant.created` gets while Access is not ready for the new tenant (PD).
const NEW_TENANT_STEPS: u32 = 6;

/// How long a `tenant.created` step waits before it runs again (PD).
const NEW_TENANT_WAIT: Duration = Duration::from_secs(5);

/// Whether a step over `tenant` ended in an outage of that tenant's pairing, which the same
/// step may get past a moment later: Access announces a tenant before its realms answer.
fn deferred(report: &Report, tenant: &TenantId) -> bool {
    report.signals.iter().any(|s| {
        matches!(s, Signal::Failed { tenant: Some(t), error } if t == tenant && error.is_temporary())
    })
}

impl Pairer {
    /// Runs one step over `scope`, logs its signals and keeps its gauges.
    pub(crate) async fn run(&self, scope: &Scope) -> Report {
        let report = pair(
            &self.settings,
            &self.store,
            Ledger(self.clock.clone()),
            Os,
            scope,
        )
        .await;
        log(&report);
        self.stats.record(&report);
        report
    }

    /// The step of a `tenant.created` (T-102 item 5): over the new tenant at once, and again
    /// every [`NEW_TENANT_WAIT`], at most [`NEW_TENANT_STEPS`] times, while its pairing ends in
    /// an outage; after that the hourly step takes it.
    pub(crate) async fn run_created(&self, tenant: TenantId) {
        let scope = Scope::Tenant(tenant.clone());
        for step in 1..=NEW_TENANT_STEPS {
            let report = self.run(&scope).await;
            if step == NEW_TENANT_STEPS || !deferred(&report, &tenant) {
                break;
            }
            tokio::time::sleep(NEW_TENANT_WAIT).await;
        }
    }
}

/// How long the first step waits for ledger time, in seconds; nothing is signed without it.
const LEDGER_TIME_WAIT_S: u32 = 120;

/// Starts the step: as soon as ledger time answers, at most [`LEDGER_TIME_WAIT_S`] after start,
/// then every [`RECONCILE_INTERVAL_MS`].
pub(crate) fn spawn(pairer: Pairer) -> JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..LEDGER_TIME_WAIT_S {
            if pairer.clock.read().is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let mut hourly = tokio::time::interval(Duration::from_millis(RECONCILE_INTERVAL_MS));
        loop {
            hourly.tick().await;
            let _report = pairer.run(&Scope::Due).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use work_access_client::domain::streams::StreamStatus;

    use super::*;

    // T-103
    #[test]
    fn t_103_the_gauges_keep_the_last_values_the_store_gave() {
        let stats = PairingStats::default();
        stats.record(&Report {
            unpaired_realms: Some(2),
            recreated: Some(1),
            stream_up: true,
            ..Report::default()
        });
        assert_eq!(
            (stats.unpaired(), stats.recreated(), stats.stream_up()),
            (2, 1, true)
        );
        stats.record(&Report {
            signals: vec![Signal::StreamDown {
                stream: "6f1c2a4e-9b0d-4c3e-8a71-2d5f0e9b4c11".to_owned(),
                status: StreamStatus::Paused,
            }],
            ..Report::default()
        });
        assert_eq!(
            (stats.unpaired(), stats.recreated(), stats.stream_up()),
            (2, 1, false)
        );
        assert!(Os.fill(&mut [0; 32]).is_ok());
    }

    // T-102 T-103
    #[test]
    fn t_102_a_new_tenant_s_step_runs_again_only_after_an_outage_of_its_own_pairing() {
        let beta = TenantId::new("tnt_beta").unwrap();
        let failed = |tenant: Option<&str>, error: AccessError| Report {
            signals: vec![Signal::Failed {
                tenant: tenant.map(|t| TenantId::new(t).unwrap()),
                error,
            }],
            ..Report::default()
        };
        assert!(deferred(
            &failed(Some("tnt_beta"), AccessError::Timeout),
            &beta
        ));
        assert!(deferred(
            &failed(Some("tnt_beta"), AccessError::Stale),
            &beta
        ));
        assert!(!deferred(
            &failed(Some("tnt_acme"), AccessError::Timeout),
            &beta
        ));
        assert!(!deferred(&failed(None, AccessError::Timeout), &beta));
        assert!(!deferred(
            &failed(Some("tnt_beta"), AccessError::Answer("pairing")),
            &beta
        ));
        assert!(!deferred(&Report::default(), &beta));
    }
}
