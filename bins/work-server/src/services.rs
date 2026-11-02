//! The long-running parts of the process, started once the infrastructure is checked: the
//! outbox publisher to NATS JetStream (T-17, T-76, OP-34), the ledgers this process leads with
//! their group commit writers on ledger time (OP-6, OP-31, OP-41), and the checkpointer that
//! signs their checkpoints through `work-signer` on the OP-33 cadence and mirrors them to the
//! directory replica before any witness (P-20, OP-4 item 3).

use std::sync::Arc;

use tokio::task::JoinHandle;
use work_dispatch::{JetStreamBus, PgOutbox, Publisher};
use work_ledger::time::{LedgerTime, ProcessMonotonic};
use work_ledger::{
    CheckpointSetup, CheckpointStats, DirectoryReplica, Ledgers, SignerClient, run_checkpoints,
};

use crate::config::Config;
use crate::health::Health;
use crate::startup::{Infrastructure, StartupError};

/// The ledgers of this process on the ledger time clock.
pub(crate) type ServerLedgers = Ledgers<LedgerTime<ProcessMonotonic>>;

/// The running services.
pub(crate) struct Services {
    handles: Vec<JoinHandle<()>>,
    ledgers: Arc<ServerLedgers>,
    checkpoints: Arc<CheckpointStats>,
    signer: SignerClient,
}

impl Services {
    /// Starts the publisher and the checkpointer.
    pub(crate) fn start(
        config: &Config,
        infrastructure: &Infrastructure,
        clock: LedgerTime<ProcessMonotonic>,
    ) -> Result<Self, StartupError> {
        let settings = config.publisher_config();
        let bus = JetStreamBus::new(infrastructure.nats.clone(), settings.call_timeout);
        let outbox = PgOutbox::new(infrastructure.publisher.clone());
        let publisher = Publisher::new(outbox, bus, settings)
            .map_err(|e| StartupError::Config(e.to_string()))?;
        let group = config
            .group_config()
            .map_err(|e| StartupError::Config(e.to_string()))?;
        let sequencer = infrastructure.sequencer.clone();
        let ledgers = Arc::new(Ledgers::new(sequencer, clock, group));
        let signer = SignerClient::new(&config.signer.socket, config.signer_timeout());
        let directory = config
            .replica_directory()
            .map_err(|e| StartupError::Config(e.to_string()))?;
        let setup = CheckpointSetup {
            pool: infrastructure.checkpointer.clone(),
            signer: signer.clone(),
            origin_prefix: config.checkpoint.origin_prefix.clone(),
            replica: DirectoryReplica::new(&config.replica.id, directory),
            cadence: config
                .cadence()
                .map_err(|e| StartupError::Config(e.to_string()))?,
            declaration: config
                .declaration()
                .map_err(|e| StartupError::Config(e.to_string()))?,
        };
        let checkpoints = Arc::new(CheckpointStats::default());
        let handles = vec![
            tokio::spawn(async move { publisher.run(std::future::pending()).await }),
            tokio::spawn(run_checkpoints(
                Arc::clone(&ledgers),
                setup,
                Arc::clone(&checkpoints),
            )),
        ];
        tracing::info!(
            event = "server.services_started",
            "outbox publisher and checkpointer started"
        );
        Ok(Self {
            handles,
            ledgers,
            checkpoints,
            signer,
        })
    }

    /// What the health endpoints look at.
    pub(crate) fn health(&self, infrastructure: &Infrastructure) -> Health {
        Health {
            canonical: infrastructure.canonical.clone(),
            derived: infrastructure.derived.clone(),
            signer: self.signer.clone(),
            nats: infrastructure.nats.clone(),
            ledgers: Arc::clone(&self.ledgers),
            checkpoints: Arc::clone(&self.checkpoints),
        }
    }

    /// Stops the publisher and the checkpointer; pointers not yet acknowledged stay in the
    /// outbox (T-21).
    pub(crate) fn stop(self) {
        for handle in self.handles {
            handle.abort();
        }
    }
}
