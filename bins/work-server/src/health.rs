//! The internal health endpoints (T-39 rule 6, OP-18 item 5): `/livez` answers while the process
//! serves, `/readyz` is ready only while both PostgreSQL databases and the signer answer, each
//! within one second, and `/metrics` is the Prometheus text exposition over a bounded label set
//! (T-39 rule 5). A NATS, Access or Relay outage never makes the process unready; it shows as an
//! alarm gauge on `/metrics` and in the log (T-21, T-28, T-84), as do the realms the Access
//! pairing step could not pair and the state of Work's Access event stream (T-103).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::time::timeout;
use work_ledger::time::{LedgerTime, ProcessMonotonic};
use work_ledger::{CheckpointStats, Ledgers, SignerClient};
use work_store::Pool;

use crate::pairing::PairingStats;

/// Upper bound on each readiness probe.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// The Prometheus text exposition content type.
const EXPOSITION: &str = "text/plain; version=0.0.4; charset=utf-8";

/// What the health endpoints look at.
pub(crate) struct Health {
    pub(crate) canonical: Pool,
    pub(crate) derived: Pool,
    pub(crate) signer: SignerClient,
    pub(crate) nats: async_nats::Client,
    pub(crate) ledgers: Arc<Ledgers<LedgerTime<ProcessMonotonic>>>,
    pub(crate) checkpoints: Arc<CheckpointStats>,
    /// Whether the last Access discovery answered (T-96 item 2).
    pub(crate) access: Arc<AtomicBool>,
    pub(crate) pairing: Arc<PairingStats>,
}

/// The answers of one round of probes.
#[allow(
    clippy::struct_excessive_bools,
    reason = "one answer per probed dependency"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Probes {
    pub(crate) canonical: bool,
    pub(crate) derived: bool,
    pub(crate) signer: bool,
    pub(crate) nats: bool,
    pub(crate) access: bool,
}

impl Probes {
    /// Ready: both databases and the signer answer; NATS does not count (T-39 rule 6, T-84).
    pub(crate) const fn ready(self) -> bool {
        self.canonical && self.derived && self.signer
    }

    /// The readiness dependencies that did not answer.
    pub(crate) fn missing(self) -> Vec<&'static str> {
        [
            ("postgres_canonical", self.canonical),
            ("postgres_derived", self.derived),
            ("signer", self.signer),
        ]
        .into_iter()
        .filter(|(_, up)| !up)
        .map(|(name, _)| name)
        .collect()
    }
}

/// The counts `/metrics` reports besides the probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Counts {
    pub(crate) ledgers_led: usize,
    pub(crate) checkpoints_stored: u64,
    pub(crate) checkpoint_failures: u64,
    pub(crate) mirrors: u64,
    pub(crate) mirror_failures: u64,
    pub(crate) unpaired_realms: u64,
    pub(crate) event_stream_recreated: u64,
    pub(crate) event_stream_up: bool,
}

fn gauge(up: bool) -> u8 {
    u8::from(up)
}

/// The Prometheus text of `probes` and `counts`; the only label is `dependency`, from a fixed
/// set (T-39 rule 5, OP-18 item 3).
pub(crate) fn exposition(probes: Probes, counts: Counts) -> String {
    format!(
        "# HELP work_up The process serves.\n\
         # TYPE work_up gauge\n\
         work_up 1\n\
         # HELP work_ready Both PostgreSQL databases and the signer answer (T-39 rule 6).\n\
         # TYPE work_ready gauge\n\
         work_ready {}\n\
         # HELP work_dependency_up A dependency answers; NATS never changes readiness (T-84).\n\
         # TYPE work_dependency_up gauge\n\
         work_dependency_up{{dependency=\"postgres_canonical\"}} {}\n\
         work_dependency_up{{dependency=\"postgres_derived\"}} {}\n\
         work_dependency_up{{dependency=\"signer\"}} {}\n\
         work_dependency_up{{dependency=\"nats\"}} {}\n\
         work_dependency_up{{dependency=\"access\"}} {}\n\
         # HELP work_ledgers_led Ledgers this process leads.\n\
         # TYPE work_ledgers_led gauge\n\
         work_ledgers_led {}\n\
         # HELP work_checkpoints_stored_total Checkpoints signed and stored.\n\
         # TYPE work_checkpoints_stored_total counter\n\
         work_checkpoints_stored_total {}\n\
         # HELP work_checkpoint_failures_total Checkpoint attempts that stored nothing.\n\
         # TYPE work_checkpoint_failures_total counter\n\
         work_checkpoint_failures_total {}\n\
         # HELP work_replica_mirrors_total Mirror passes that reached the largest checkpoint.\n\
         # TYPE work_replica_mirrors_total counter\n\
         work_replica_mirrors_total {}\n\
         # HELP work_replica_mirror_failures_total Mirror passes that failed.\n\
         # TYPE work_replica_mirror_failures_total counter\n\
         work_replica_mirror_failures_total {}\n\
         # HELP work_access_unpaired_realms Live realms that three pairing runs in a row did not pair (T-103).\n\
         # TYPE work_access_unpaired_realms gauge\n\
         work_access_unpaired_realms {}\n\
         # HELP work_access_event_stream_recreated_total Times Work opened its Access event stream again (T-103).\n\
         # TYPE work_access_event_stream_recreated_total counter\n\
         work_access_event_stream_recreated_total {}\n\
         # HELP work_access_event_stream_up Work's Access event stream is enabled (T-102).\n\
         # TYPE work_access_event_stream_up gauge\n\
         work_access_event_stream_up {}\n",
        gauge(probes.ready()),
        gauge(probes.canonical),
        gauge(probes.derived),
        gauge(probes.signer),
        gauge(probes.nats),
        gauge(probes.access),
        counts.ledgers_led,
        counts.checkpoints_stored,
        counts.checkpoint_failures,
        counts.mirrors,
        counts.mirror_failures,
        counts.unpaired_realms,
        counts.event_stream_recreated,
        gauge(counts.event_stream_up),
    )
}

async fn postgres(pool: &Pool) -> bool {
    matches!(
        timeout(PROBE_TIMEOUT, work_store::server_version_num(pool)).await,
        Ok(Ok(_))
    )
}

async fn signer(client: &SignerClient) -> bool {
    matches!(timeout(PROBE_TIMEOUT, client.log_key()).await, Ok(Ok(_)))
}

impl Health {
    async fn probe(&self) -> Probes {
        let (canonical, derived, signer) = tokio::join!(
            postgres(&self.canonical),
            postgres(&self.derived),
            signer(&self.signer)
        );
        Probes {
            canonical,
            derived,
            signer,
            nats: self.nats.connection_state() == async_nats::connection::State::Connected,
            access: self.access.load(Ordering::Relaxed),
        }
    }

    async fn counts(&self) -> Counts {
        Counts {
            ledgers_led: self.ledgers.led().await.len(),
            checkpoints_stored: self.checkpoints.stored(),
            checkpoint_failures: self.checkpoints.failed(),
            mirrors: self.checkpoints.mirrored(),
            mirror_failures: self.checkpoints.mirror_failed(),
            unpaired_realms: self.pairing.unpaired(),
            event_stream_recreated: self.pairing.recreated(),
            event_stream_up: self.pairing.stream_up(),
        }
    }
}

async fn readyz(State(health): State<Arc<Health>>) -> (StatusCode, String) {
    let probes = health.probe().await;
    if !probes.nats {
        tracing::warn!(
            event = "nats.unavailable",
            "NATS is unreachable; readiness is kept and events wait in the outbox"
        );
    }
    if probes.ready() {
        (StatusCode::OK, "ready\n".to_owned())
    } else {
        let missing = probes.missing().join(" ");
        tracing::warn!(event = "server.not_ready", %missing, "not ready");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("not ready: {missing}\n"),
        )
    }
}

async fn metrics(State(health): State<Arc<Health>>) -> impl IntoResponse {
    let probes = health.probe().await;
    let counts = health.counts().await;
    (
        [(header::CONTENT_TYPE, EXPOSITION)],
        exposition(probes, counts),
    )
}

/// The internal router.
pub(crate) fn router(health: Health) -> Router {
    Router::new()
        .route("/livez", get(|| async { "live\n" }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(Arc::new(health))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: Probes = Probes {
        canonical: true,
        derived: true,
        signer: true,
        nats: true,
        access: true,
    };

    const NONE: Counts = Counts {
        ledgers_led: 0,
        checkpoints_stored: 0,
        checkpoint_failures: 0,
        mirrors: 0,
        mirror_failures: 0,
        unpaired_realms: 0,
        event_stream_recreated: 0,
        event_stream_up: false,
    };

    // T-39 T-84 T-21 T-93
    #[test]
    fn t_39_readiness_looks_only_at_postgres_and_the_signer() {
        assert!(ALL.ready());
        assert!(Probes { nats: false, ..ALL }.ready());
        for down in [
            Probes {
                canonical: false,
                ..ALL
            },
            Probes {
                derived: false,
                ..ALL
            },
            Probes {
                signer: false,
                ..ALL
            },
        ] {
            assert!(!down.ready(), "{down:?}");
            assert_eq!(down.missing().len(), 1);
        }
        assert_eq!(
            Probes {
                signer: false,
                nats: false,
                ..ALL
            }
            .missing(),
            ["signer"]
        );
    }

    // T-96 T-28 T-93
    #[test]
    fn t_96_an_access_outage_raises_its_alarm_and_keeps_readiness() {
        let down = Probes {
            access: false,
            ..ALL
        };
        assert!(down.ready());
        assert_eq!(down.missing(), [] as [&str; 0]);
        let text = exposition(down, NONE);
        assert!(
            text.contains("work_dependency_up{dependency=\"access\"} 0\n"),
            "{text}"
        );
        assert!(text.contains("\nwork_ready 1\n"), "{text}");
        assert!(exposition(ALL, NONE).contains("work_dependency_up{dependency=\"access\"} 1\n"));
    }

    // T-39 OP-18 T-93 T-103
    #[test]
    fn t_39_metrics_raise_the_nats_alarm_with_a_bounded_label_set() {
        let text = exposition(Probes { nats: false, ..ALL }, NONE);
        assert!(text.contains("\nwork_ready 1\n"), "{text}");
        assert!(text.contains("work_dependency_up{dependency=\"nats\"} 0\n"));
        assert!(text.contains("work_dependency_up{dependency=\"signer\"} 1\n"));
        let not_ready = exposition(
            Probes {
                signer: false,
                ..ALL
            },
            NONE,
        );
        assert!(not_ready.contains("\nwork_ready 0\n"));
        let pairing = exposition(
            ALL,
            Counts {
                unpaired_realms: 2,
                event_stream_recreated: 1,
                ..NONE
            },
        );
        assert!(pairing.contains("\nwork_access_unpaired_realms 2\n"));
        assert!(pairing.contains("\nwork_access_event_stream_recreated_total 1\n"));
        assert!(pairing.contains("\nwork_access_event_stream_up 0\n"));
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (name, value) = line.rsplit_once(' ').unwrap_or_default();
            assert!(value.parse::<u64>().is_ok(), "{line}");
            if let Some((_, labels)) = name.split_once('{') {
                let (key, _) = labels.split_once('=').unwrap_or_default();
                assert_eq!(key, "dependency", "{line}");
            }
        }
    }
}
