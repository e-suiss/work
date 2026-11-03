//! Typed process configuration, validated at start-up (T-32 rule 8).

use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU8;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use work_dispatch::{PublisherConfig, StreamSettings};
use work_kernel::proof::{TimeSources, Verifier, WitnessProfile};
use work_ledger::time::{
    NTS_KE_PORT, NtsServer, RoughtimeServer, RoughtimeVersion, TimeConfigError, check_sources,
};
use work_ledger::{
    Cadence, CadenceError, DEFAULT_CHECKPOINT_RECORDS, DEFAULT_MAX_BYTES, DEFAULT_MAX_RECORDS,
    DEFAULT_QUEUE, Declaration, DeclarationError, Deployment, GroupConfig, GroupConfigError,
    Witness, WitnessClient, WitnessEndpoint, WitnessRole, witness_tls,
};
use work_telemetry::{DEFAULT_MAX_QUEUE_SIZE, InvalidSampleRatio, SampleRatio, TraceConfig};

/// Validated process configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Listen address; loopback unless the operator exposes it.
    pub(crate) listen: SocketAddr,
    /// The internal network address of `/livez`, `/readyz` and `/metrics` (T-39 rule 6).
    pub(crate) internal_listen: SocketAddr,
    /// `tracing` filter directives.
    pub(crate) log: String,
    /// The two PostgreSQL databases (T-20, OP-2).
    pub(crate) postgres: Postgres,
    /// The NATS JetStream server (T-20, T-21).
    pub(crate) nats: Nats,
    /// Trace export (T-39, OP-18).
    pub(crate) trace: Trace,
    /// Upper bound on each external call made at start-up, in milliseconds.
    pub(crate) startup_timeout_ms: u64,
    /// The ledger time sources (OP-32, OP-42, OP-43).
    pub(crate) ledger_time: LedgerTime,
    /// The signer process (T-7, T-72).
    pub(crate) signer: Signer,
    /// Checkpoint origin and cadence (P-20, OP-33).
    pub(crate) checkpoint: Checkpoint,
    /// The replica every checkpoint is mirrored to (OP-4 item 3, OP-33 item 3).
    pub(crate) replica: Replica,
    /// The outbox publisher (T-17, T-76, OP-34).
    pub(crate) publisher: Publisher,
    /// Group commit values (OP-31, OP-41).
    pub(crate) group_commit: GroupCommitValues,
    /// What every checkpoint declares (OP-32 item 5, OP-33 item 1, OP-46 item 3).
    pub(crate) declaration: DeclarationValues,
    /// The witnesses every mirrored checkpoint is sent to (OP-33 item 1, OP-46 item 10).
    pub(crate) witnesses: Vec<WitnessValues>,
    /// Witness client settings.
    pub(crate) witnessing: Witnessing,
}

/// A witness: where it takes checkpoints, the key its cosignatures verify under and how it
/// counts.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WitnessValues {
    /// The `witness_id` its cosignatures and observations are stored under.
    pub(crate) id: String,
    /// Its submission prefix, `http(s)://host[:port][/prefix]`.
    pub(crate) url: String,
    /// Its `tlog-cosignature/v1` verifier key, `name+id+base64`; exactly one of `key` and
    /// `key_file` is set.
    pub(crate) key: Option<String>,
    /// A file holding its verifier key, read when the configuration is loaded, for a witness
    /// whose key is made when it starts.
    pub(crate) key_file: Option<PathBuf>,
    /// How it counts; `counted` unless it serves gossip only.
    #[serde(default)]
    pub(crate) role: WitnessRoleWire,
}

/// `role` of a witness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum WitnessRoleWire {
    /// Its cosignatures are stored and count towards `witness independent k`.
    #[default]
    #[serde(rename = "counted")]
    Counted,
    /// Gossip and monitoring only, as the witness Suiss runs (OP-33 item 1).
    #[serde(rename = "gossip")]
    Gossip,
}

/// Witness client settings.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Witnessing {
    /// Upper bound on one exchange with a witness, in milliseconds.
    pub(crate) call_timeout_ms: u64,
    /// A PEM file of the roots the certificates of `https` witnesses are verified against.
    pub(crate) tls_roots: Option<PathBuf>,
}

/// The profile declaration; by default a self-hosted installation that claims neither
/// independent time sources nor any witness (OP-46).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeclarationValues {
    /// Where the installation runs.
    pub(crate) deployment: DeploymentWire,
    /// Whether the NTS sources are run by different organisations (OP-32 item 5).
    pub(crate) time_sources: TimeSourcesWire,
    /// The witness profile (OP-33).
    pub(crate) witness: WitnessWire,
    /// The number k of independent witnesses, used only with `witness = "independent"`.
    pub(crate) independent_witnesses: u8,
}

/// `deployment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum DeploymentWire {
    /// The Suiss-operated service.
    #[serde(rename = "saas")]
    Saas,
    /// A self-hosted or local installation.
    #[serde(rename = "self-host")]
    SelfHost,
}

/// `time_sources`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum TimeSourcesWire {
    /// Run by different organisations.
    #[serde(rename = "independent")]
    Independent,
    /// Not independent, as locally and in CI.
    #[serde(rename = "dependent")]
    Dependent,
}

/// `witness`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum WitnessWire {
    /// No witness is declared.
    #[serde(rename = "none")]
    Undeclared,
    /// The dependent witness of a local or single-node installation.
    #[serde(rename = "local-dependent")]
    LocalDependent,
    /// `independent_witnesses` independent witnesses.
    #[serde(rename = "independent")]
    Independent,
}

/// The signer's Unix socket.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signer {
    /// The socket path, shared with `work-signer`.
    pub(crate) socket: PathBuf,
    /// Upper bound on one exchange with the signer, in milliseconds.
    pub(crate) call_timeout_ms: u64,
}

/// Checkpoint settings.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    /// The origin of a ledger's checkpoints is this prefix and the ledger id in hex; the same
    /// prefix the signer is configured with, e.g. `work.example/ledger/`.
    pub(crate) origin_prefix: String,
    /// Ledger time between checkpoints of a ledger with new records, in milliseconds.
    pub(crate) interval_ms: u64,
    /// New records after which a checkpoint is due at once.
    pub(crate) records: u64,
}

/// The directory replica.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Replica {
    /// The `replica_id` its progress is stored under.
    pub(crate) id: String,
    /// The directory it is written to; none configured stops the process.
    pub(crate) directory: Option<PathBuf>,
}

/// Outbox publisher settings; the other values are the OP-34 policy defaults.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Publisher {
    /// The installation URI events name as their source, `https://` and a host.
    pub(crate) source: String,
    /// `WORK_EVENTS` file-storage replicas: 1 on a single node, 3 in the multi-node profile.
    pub(crate) stream_replicas: usize,
}

/// Group commit values (OP-31 item 2, OP-41).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupCommitValues {
    /// Most records in one batch.
    pub(crate) max_records: usize,
    /// Most record bytes in one batch.
    pub(crate) max_bytes: usize,
    /// Pending requests per ledger.
    pub(crate) queue: usize,
    /// `Retry-After` of a request refused on a full queue, in milliseconds.
    pub(crate) retry_after_ms: u64,
}

/// Ledger time sources; none by default, so an installation names its own (OP-32 item 4,
/// OP-43 item 3).
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerTime {
    /// NTS servers run by different operators, at least two (OP-32).
    pub(crate) nts: Vec<Nts>,
    /// Roughtime servers, at least three (OP-43).
    pub(crate) roughtime: Vec<Roughtime>,
    /// A PEM file of trust roots NTS-KE accepts besides the platform's.
    pub(crate) nts_roots: Option<PathBuf>,
}

/// An NTS server: its NTS-KE host and port.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Nts {
    /// Host name or address, also the TLS server name.
    pub(crate) host: String,
    /// NTS-KE port.
    #[serde(default = "nts_ke_port")]
    pub(crate) port: u16,
}

const fn nts_ke_port() -> u16 {
    NTS_KE_PORT
}

/// A Roughtime server.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Roughtime {
    /// `host:port`.
    pub(crate) address: String,
    /// The long-term Ed25519 public key, base64.
    pub(crate) public_key: String,
    /// The version it speaks.
    pub(crate) version: RoughtimeWire,
}

/// The Roughtime versions the driver speaks (OP-42 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum RoughtimeWire {
    /// RFC 10049.
    #[serde(rename = "rfc")]
    Rfc,
    /// draft-ietf-ntp-roughtime-11.
    #[serde(rename = "draft-11")]
    Draft11,
}

/// PostgreSQL connection URLs; passwords come from the libpq environment, never from here.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Postgres {
    /// The canonical `work` database.
    pub(crate) canonical: String,
    /// The derived `work_derived` database.
    pub(crate) derived: String,
    /// The canonical database as `work_sequencer`, the ledger writer (T-85).
    pub(crate) sequencer: String,
    /// The canonical database as `work_checkpointer` (P-20, OP-4).
    pub(crate) checkpointer: String,
    /// The canonical database as `work_publisher` (OP-34).
    pub(crate) publisher: String,
    /// The derived database as `work_deriver`, for the gossip comparison (SEC-32).
    pub(crate) deriver: String,
}

/// NATS connection settings.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Nats {
    /// Server URL, without credentials; the user and password come from `NATS_USER` and `NATS_PASSWORD`.
    pub(crate) url: String,
}

/// Trace export settings.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trace {
    /// The OTLP/gRPC collector endpoint; none exports no spans.
    pub(crate) endpoint: Option<String>,
    /// The share of new root traces that are sampled, in `0.0..=1.0` (§18 OP-40 rule 2).
    pub(crate) sample_ratio: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8090)),
            internal_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8091)),
            log: "info".to_owned(),
            postgres: Postgres {
                canonical: "postgres://localhost/work".to_owned(),
                derived: "postgres://localhost/work_derived".to_owned(),
                sequencer: "postgres://work_sequencer@localhost/work".to_owned(),
                checkpointer: "postgres://work_checkpointer@localhost/work".to_owned(),
                publisher: "postgres://work_publisher@localhost/work".to_owned(),
                deriver: "postgres://work_deriver@localhost/work_derived".to_owned(),
            },
            nats: Nats {
                url: "nats://127.0.0.1:4222".to_owned(),
            },
            trace: Trace {
                endpoint: None,
                sample_ratio: SampleRatio::DEFAULT.get(),
            },
            // OP-40
            startup_timeout_ms: 5_000,
            ledger_time: LedgerTime::default(),
            signer: Signer {
                socket: PathBuf::from("/run/work-signer/signer.sock"),
                call_timeout_ms: 5_000,
            },
            // OP-33
            checkpoint: Checkpoint {
                origin_prefix: String::new(),
                interval_ms: 60_000,
                records: DEFAULT_CHECKPOINT_RECORDS,
            },
            replica: Replica {
                id: "local".to_owned(),
                directory: None,
            },
            publisher: Publisher {
                source: String::new(),
                stream_replicas: StreamSettings::default().replicas,
            },
            // OP-31 OP-41
            group_commit: GroupCommitValues {
                max_records: DEFAULT_MAX_RECORDS,
                max_bytes: DEFAULT_MAX_BYTES,
                queue: DEFAULT_QUEUE,
                retry_after_ms: 1_000,
            },
            // OP-46
            declaration: DeclarationValues {
                deployment: DeploymentWire::SelfHost,
                time_sources: TimeSourcesWire::Dependent,
                witness: WitnessWire::Undeclared,
                independent_witnesses: 0,
            },
            witnesses: Vec::new(),
            // OP-44
            witnessing: Witnessing {
                call_timeout_ms: 5_000,
                tls_roots: None,
            },
        }
    }
}

/// Why the configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error(transparent)]
    Parse(#[from] Box<figment::Error>),
    #[error("log filter must not be empty")]
    EmptyLogFilter,
    #[error("`{0}` must not carry a password; use the environment or a credentials file")]
    PasswordInUrl(&'static str),
    #[error("startup_timeout_ms must be positive")]
    ZeroTimeout,
    #[error("trace.sample_ratio: {0}")]
    SampleRatio(#[from] InvalidSampleRatio),
    #[error("ledger_time: {0}")]
    TimeSources(#[from] TimeConfigError),
    #[error("ledger_time.roughtime[{0}].public_key is not 32 bytes of base64")]
    RoughtimeKey(usize),
    #[error("signer.call_timeout_ms must be positive")]
    SignerTimeout,
    #[error("checkpoint.origin_prefix must be a non-empty origin start ending with `/`")]
    OriginPrefix,
    #[error("checkpoint: {0}")]
    Cadence(#[from] CadenceError),
    #[error("replica.id must be a non-empty identifier and replica.directory must be set")]
    Replica,
    #[error("publisher: {0}")]
    Publisher(#[from] work_dispatch::ConfigError),
    #[error("group_commit: {0}")]
    GroupCommit(#[from] GroupConfigError),
    #[error("declaration: {0}")]
    Declaration(#[from] DeclarationError),
    #[error("declaration.independent_witnesses must be at least 1 with witness = \"independent\"")]
    Witnesses,
    #[error("witnesses[{0}].{1} is malformed or repeated")]
    Witness(usize, &'static str),
    #[error(
        "{declared} independent witnesses are declared but {configured} counted ones are configured"
    )]
    TooFewWitnesses { declared: u8, configured: usize },
    #[error("witnessing.call_timeout_ms must be positive")]
    WitnessTimeout,
    #[error("witnessing.tls_roots: {0}")]
    WitnessRoots(String),
}

impl Config {
    pub(crate) fn load() -> Result<Self, ConfigError> {
        let file = std::env::var("WORK_CONFIG").unwrap_or_else(|_| "work.toml".to_owned());
        Self::from_figment(
            &Figment::from(Serialized::defaults(Self::default()))
                .merge(Toml::file(file))
                .merge(Env::prefixed("WORK_").ignore(&["CONFIG"]).split("__")),
        )
    }

    fn from_figment(figment: &Figment) -> Result<Self, ConfigError> {
        let config: Self = figment.extract().map_err(Box::new)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.log.trim().is_empty() {
            return Err(ConfigError::EmptyLogFilter);
        }
        let endpoint = self.trace.endpoint.as_deref().unwrap_or_default();
        for (key, url) in [
            ("postgres.canonical", self.postgres.canonical.as_str()),
            ("postgres.derived", self.postgres.derived.as_str()),
            ("postgres.sequencer", self.postgres.sequencer.as_str()),
            ("postgres.checkpointer", self.postgres.checkpointer.as_str()),
            ("postgres.publisher", self.postgres.publisher.as_str()),
            ("postgres.deriver", self.postgres.deriver.as_str()),
            ("nats.url", self.nats.url.as_str()),
            ("trace.endpoint", endpoint),
        ] {
            if has_password(url) {
                return Err(ConfigError::PasswordInUrl(key));
            }
        }
        if self.startup_timeout_ms == 0 {
            return Err(ConfigError::ZeroTimeout);
        }
        SampleRatio::new(self.trace.sample_ratio)?;
        check_sources(self.ledger_time.nts.len(), self.ledger_time.roughtime.len())?;
        self.roughtime_servers()?;
        if self.signer.call_timeout_ms == 0 {
            return Err(ConfigError::SignerTimeout);
        }
        if !origin_prefix_ok(&self.checkpoint.origin_prefix) {
            return Err(ConfigError::OriginPrefix);
        }
        self.cadence()?;
        self.replica_directory()?;
        self.publisher_config().validate()?;
        self.group_config()?;
        self.declaration()?;
        self.witness_endpoints()?;
        Ok(())
    }

    /// The configured witnesses; under `witness = "independent"` at least as many counted ones
    /// as declared (OP-33 item 1, OP-46 item 5).
    pub(crate) fn witness_endpoints(&self) -> Result<Vec<WitnessEndpoint>, ConfigError> {
        let limit = Duration::from_millis(self.witnessing.call_timeout_ms);
        if limit.is_zero() {
            return Err(ConfigError::WitnessTimeout);
        }
        let tls = match &self.witnessing.tls_roots {
            Some(path) => {
                let file = std::fs::File::open(path)
                    .map_err(|e| ConfigError::WitnessRoots(e.to_string()))?;
                let config = witness_tls(&mut BufReader::new(file))
                    .map_err(|e| ConfigError::WitnessRoots(e.to_string()))?;
                Some(config)
            }
            None => None,
        };
        let mut endpoints = Vec::with_capacity(self.witnesses.len());
        for (i, w) in self.witnesses.iter().enumerate() {
            let repeated = self.witnesses.iter().filter(|o| o.id == w.id).count() > 1;
            if !ident_ok(&w.id) || repeated {
                return Err(ConfigError::Witness(i, "id"));
            }
            let vkey = match (&w.key, &w.key_file) {
                (Some(key), None) => key.clone(),
                (None, Some(path)) => std::fs::read_to_string(path)
                    .map_err(|_| ConfigError::Witness(i, "key_file"))?,
                _ => return Err(ConfigError::Witness(i, "key")),
            };
            let key = Verifier::parse(vkey.trim())
                .ok()
                .filter(Verifier::is_cosigner)
                .ok_or(ConfigError::Witness(i, "key"))?;
            let client = WitnessClient::new(&w.url, tls.clone(), limit)
                .map_err(|_| ConfigError::Witness(i, "url"))?;
            endpoints.push(WitnessEndpoint {
                witness: Witness {
                    id: w.id.clone(),
                    key,
                },
                role: match w.role {
                    WitnessRoleWire::Counted => WitnessRole::Counted,
                    WitnessRoleWire::Gossip => WitnessRole::Gossip,
                },
                client,
            });
        }
        if self.declaration.witness == WitnessWire::Independent {
            let configured = endpoints
                .iter()
                .filter(|e| e.role == WitnessRole::Counted)
                .count();
            let declared = self.declaration.independent_witnesses;
            if configured < usize::from(declared) {
                return Err(ConfigError::TooFewWitnesses {
                    declared,
                    configured,
                });
            }
        }
        Ok(endpoints)
    }

    /// The checkpoint cadence (OP-33 item 4).
    pub(crate) fn cadence(&self) -> Result<Cadence, ConfigError> {
        Ok(Cadence::new(
            Duration::from_millis(self.checkpoint.interval_ms),
            self.checkpoint.records,
        )?)
    }

    /// The replica directory.
    pub(crate) fn replica_directory(&self) -> Result<&PathBuf, ConfigError> {
        let id_ok = ident_ok(&self.replica.id);
        self.replica
            .directory
            .as_ref()
            .filter(|d| id_ok && !d.as_os_str().is_empty())
            .ok_or(ConfigError::Replica)
    }

    /// The publisher settings: the OP-34 policy defaults with the configured source and stream
    /// replicas (T-76).
    pub(crate) fn publisher_config(&self) -> PublisherConfig {
        let mut config = PublisherConfig::new(self.publisher.source.clone());
        config.stream.replicas = self.publisher.stream_replicas;
        config
    }

    /// The group commit values (OP-31, OP-41).
    pub(crate) fn group_config(&self) -> Result<GroupConfig, ConfigError> {
        let g = &self.group_commit;
        Ok(GroupConfig::new(
            g.max_records,
            g.max_bytes,
            g.queue,
            Duration::from_millis(g.retry_after_ms),
        )?)
    }

    /// The profile every checkpoint declares (OP-46 item 3).
    pub(crate) fn declaration(&self) -> Result<Declaration, ConfigError> {
        let d = &self.declaration;
        let deployment = match d.deployment {
            DeploymentWire::Saas => Deployment::Saas,
            DeploymentWire::SelfHost => Deployment::SelfHost,
        };
        let time_sources = match d.time_sources {
            TimeSourcesWire::Independent => TimeSources::Independent,
            TimeSourcesWire::Dependent => TimeSources::Dependent,
        };
        let witness = match d.witness {
            WitnessWire::Undeclared => WitnessProfile::Undeclared,
            WitnessWire::LocalDependent => WitnessProfile::LocalDependent,
            WitnessWire::Independent => WitnessProfile::Independent(
                NonZeroU8::new(d.independent_witnesses).ok_or(ConfigError::Witnesses)?,
            ),
        };
        Ok(Declaration::new(deployment, time_sources, witness)?)
    }

    pub(crate) const fn signer_timeout(&self) -> Duration {
        Duration::from_millis(self.signer.call_timeout_ms)
    }

    /// The configured NTS servers (OP-32).
    pub(crate) fn nts_servers(&self) -> Vec<NtsServer> {
        self.ledger_time
            .nts
            .iter()
            .map(|n| NtsServer {
                host: n.host.clone(),
                port: n.port,
            })
            .collect()
    }

    /// The configured Roughtime servers with their decoded keys (OP-43).
    pub(crate) fn roughtime_servers(&self) -> Result<Vec<RoughtimeServer>, ConfigError> {
        self.ledger_time
            .roughtime
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let public_key: [u8; 32] = STANDARD
                    .decode(r.public_key.trim())
                    .ok()
                    .and_then(|k| k.try_into().ok())
                    .ok_or(ConfigError::RoughtimeKey(i))?;
                Ok(RoughtimeServer {
                    address: r.address.clone(),
                    public_key,
                    version: match r.version {
                        RoughtimeWire::Rfc => RoughtimeVersion::Rfc,
                        RoughtimeWire::Draft11 => RoughtimeVersion::Draft11,
                    },
                })
            })
            .collect()
    }

    /// The trace export settings of this process.
    pub(crate) fn trace_config(&self) -> Result<TraceConfig, ConfigError> {
        Ok(TraceConfig {
            service: "work-server".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint: self.trace.endpoint.clone(),
            sample_ratio: SampleRatio::new(self.trace.sample_ratio)?,
            max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
        })
    }

    pub(crate) const fn startup_timeout(&self) -> Duration {
        Duration::from_millis(self.startup_timeout_ms)
    }
}

/// A stored `ledger.ident`: `[a-z][a-z0-9_]{0,63}`.
fn ident_ok(id: &str) -> bool {
    let mut bytes = id.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && id.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn origin_prefix_ok(prefix: &str) -> bool {
    prefix.len() > 1
        && prefix.ends_with('/')
        && !prefix.starts_with('/')
        && prefix.chars().all(|c| c.is_ascii_graphic() && c != '+')
}

fn has_password(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=";

    const WITNESS_A: &str = "witness.example+4ac50073+BAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH";

    const WITNESS_B: &str =
        "witness-b.example+723dbe83+BAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

    const LOG_KEY: &str = "work.example+9e925851+AQcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH";

    fn witness(id: &str, url: &str, key: &str, role: &str) -> String {
        format!(
            "[[witnesses]]\nid = \"{id}\"\nurl = \"{url}\"\nkey = \"{key}\"\nrole = \"{role}\"\n"
        )
    }

    fn time_sources(nts: usize, roughtime: usize) -> String {
        let nts: Vec<String> = (0..nts)
            .map(|i| format!("{{ host = \"nts-{i}.example\" }}"))
            .collect();
        let roughtime: Vec<String> = (0..roughtime)
            .map(|i| {
                format!(
                    "{{ address = \"rt-{i}.example:2002\", public_key = \"{KEY}\", version = \"rfc\" }}"
                )
            })
            .collect();
        format!(
            "[ledger_time]\nnts = [{}]\nroughtime = [{}]\n",
            nts.join(", "),
            roughtime.join(", ")
        )
    }

    const REQUIRED: &str = "[checkpoint]\norigin_prefix = \"work.example/ledger/\"\n[replica]\ndirectory = \"/var/lib/work/replica\"\n[publisher]\nsource = \"https://work.example\"\n";

    fn with(toml: &str) -> Result<Config, ConfigError> {
        Config::from_figment(
            &Figment::from(Serialized::defaults(Config::default()))
                .merge(Toml::string(&time_sources(2, 3)))
                .merge(Toml::string(REQUIRED))
                .merge(Toml::string(toml)),
        )
    }

    #[test]
    fn default_listen_address_is_loopback() {
        assert!(Config::default().listen.ip().is_loopback());
    }

    // T-39 OP-18 T-93
    #[test]
    fn t_39_health_endpoints_listen_on_an_internal_address_of_their_own() {
        let config = Config::default();
        assert!(config.internal_listen.ip().is_loopback());
        assert_ne!(config.internal_listen, config.listen);
        let set = with("internal_listen = \"10.0.0.5:9091\"").unwrap();
        assert_eq!(set.internal_listen.port(), 9091);
    }

    // OP-33 P-20 T-93
    #[test]
    fn op_33_checkpoints_default_to_60_s_or_1000_records_and_need_a_replica() {
        let config = with("").unwrap();
        assert_eq!(config.cadence().unwrap(), Cadence::default());
        assert_eq!(config.checkpoint.interval_ms, 60_000);
        assert_eq!(config.checkpoint.records, 1000);
        assert_eq!(config.replica.id, "local");
        let fast = "[checkpoint]\ninterval_ms = 5000\nrecords = 10";
        let cadence = with(fast).unwrap().cadence().unwrap();
        assert!(cadence.due(10, 0));
        assert!(cadence.due(1, 5000));
        assert!(!cadence.due(9, 4999));
        for (toml, why) in [
            ("[checkpoint]\ninterval_ms = 0", "interval"),
            ("[checkpoint]\nrecords = 0", "records"),
        ] {
            assert!(matches!(with(toml), Err(ConfigError::Cadence(_))), "{why}");
        }
        for toml in [
            "[replica]\ndirectory = \"\"",
            "[replica]\nid = \"\"",
            "[replica]\nid = \"Local\"",
            "[replica]\nid = \"1local\"",
        ] {
            assert!(matches!(with(toml), Err(ConfigError::Replica)), "{toml}");
        }
        let without = Config::from_figment(
            &Figment::from(Serialized::defaults(Config::default()))
                .merge(Toml::string(&time_sources(2, 3)))
                .merge(Toml::string(
                    "[checkpoint]\norigin_prefix = \"work.example/ledger/\"\n[publisher]\nsource = \"https://work.example\"",
                )),
        );
        assert!(matches!(without, Err(ConfigError::Replica)));
    }

    // T-7 P-20 T-93
    #[test]
    fn t_7_the_checkpoint_origin_prefix_is_required_and_ends_with_a_slash() {
        for prefix in ["", "/", "work.example/ledger", "/w/", "w x/", "a+b/"] {
            assert!(
                matches!(
                    with(&format!("[checkpoint]\norigin_prefix = \"{prefix}\"")),
                    Err(ConfigError::OriginPrefix)
                ),
                "{prefix}"
            );
        }
        assert!(with("[checkpoint]\norigin_prefix = \"work.example/ledger/\"").is_ok());
        assert!(matches!(
            with("[signer]\ncall_timeout_ms = 0"),
            Err(ConfigError::SignerTimeout)
        ));
        let config = with("[signer]\nsocket = \"/run/s/signer.sock\"").unwrap();
        assert_eq!(config.signer.socket, PathBuf::from("/run/s/signer.sock"));
        assert_eq!(config.signer_timeout(), Duration::from_secs(5));
    }

    // T-17 T-76 OP-34 T-93
    #[test]
    fn t_76_the_publisher_takes_the_policy_defaults_and_needs_an_https_source() {
        let config = with("").unwrap();
        let publisher = config.publisher_config();
        assert_eq!(publisher, PublisherConfig::new("https://work.example"));
        assert_eq!(publisher.stream.name, "WORK_EVENTS");
        assert_eq!(publisher.stream.replicas, 1);
        let multi = with("[publisher]\nstream_replicas = 3").unwrap();
        assert_eq!(multi.publisher_config().stream.replicas, 3);
        for toml in [
            "[publisher]\nsource = \"\"",
            "[publisher]\nsource = \"http://work.example\"",
            "[publisher]\nstream_replicas = 0",
        ] {
            assert!(
                matches!(with(toml), Err(ConfigError::Publisher(_))),
                "{toml}"
            );
        }
    }

    // OP-46 OP-33 OP-32 T-93
    #[test]
    fn op_46_the_declaration_defaults_to_claiming_nothing_and_saas_needs_independence() {
        let local = Declaration::new(
            Deployment::SelfHost,
            TimeSources::Dependent,
            WitnessProfile::Undeclared,
        );
        assert_eq!(with("").unwrap().declaration().ok(), local.ok());
        let saas = format!(
            "[declaration]\ndeployment = \"saas\"\ntime_sources = \"independent\"\nwitness = \"independent\"\nindependent_witnesses = 2\n{}{}",
            witness("witness_a", "http://a.example", WITNESS_A, "counted"),
            witness("witness_b", "http://b.example", WITNESS_B, "counted")
        );
        let two = NonZeroU8::new(2).unwrap();
        assert_eq!(
            with(&saas).unwrap().declaration().unwrap(),
            Declaration::new(
                Deployment::Saas,
                TimeSources::Independent,
                WitnessProfile::Independent(two),
            )
            .unwrap()
        );
        let compose = "[declaration]\nwitness = \"local-dependent\"";
        assert!(with(compose).is_ok());
        for toml in [
            "[declaration]\ndeployment = \"saas\"",
            "[declaration]\ndeployment = \"saas\"\nwitness = \"independent\"\nindependent_witnesses = 2",
        ] {
            assert!(
                matches!(with(toml), Err(ConfigError::Declaration(_))),
                "{toml}"
            );
        }
        assert!(matches!(
            with("[declaration]\nwitness = \"independent\""),
            Err(ConfigError::Witnesses)
        ));
        assert!(matches!(
            with("[declaration]\nwitness = \"cosigned\""),
            Err(ConfigError::Parse(_))
        ));
    }

    // OP-33 OP-46 SEC-32
    #[test]
    fn op_33_witnesses_need_a_unique_id_a_cosigner_key_and_an_http_url() {
        assert!(with("").unwrap().witness_endpoints().unwrap().is_empty());
        let both = format!(
            "{}{}",
            witness("witness_a", "http://witness:7380", WITNESS_A, "counted"),
            witness(
                "suiss_gossip",
                "http://gossip.example/w/",
                WITNESS_B,
                "gossip"
            )
        );
        let endpoints = with(&both).unwrap().witness_endpoints().unwrap();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].witness.id, "witness_a");
        assert_eq!(endpoints[0].witness.key.to_vkey(), WITNESS_A);
        assert_eq!(endpoints[0].role, WitnessRole::Counted);
        assert_eq!(endpoints[1].role, WitnessRole::Gossip);
        let default_role = "[[witnesses]]\nid = \"w\"\nurl = \"http://w\"\nkey = \"";
        let config = with(&format!("{default_role}{WITNESS_A}\"")).unwrap();
        assert_eq!(
            config.witness_endpoints().unwrap()[0].role,
            WitnessRole::Counted
        );
        for (toml, field) in [
            (witness("Witness", "http://w", WITNESS_A, "counted"), "id"),
            (
                format!(
                    "{}{}",
                    witness("w", "http://w", WITNESS_A, "counted"),
                    witness("w", "http://v", WITNESS_B, "counted")
                ),
                "id",
            ),
            (witness("w", "http://w", LOG_KEY, "counted"), "key"),
            (
                witness("w", "http://w", "witness.example+00000000+AAAA", "counted"),
                "key",
            ),
            (witness("w", "witness:7380", WITNESS_A, "counted"), "url"),
            (
                witness("w", "https://w.example", WITNESS_A, "counted"),
                "url",
            ),
        ] {
            assert!(
                matches!(with(&toml), Err(ConfigError::Witness(0 | 1, f)) if f == field),
                "{toml}"
            );
        }
        let path =
            std::env::temp_dir().join(format!("work-witness-{}.vkey", std::process::id()));
        std::fs::write(&path, format!("{WITNESS_A}\n")).unwrap();
        let from_file = format!(
            "[[witnesses]]\nid = \"w\"\nurl = \"http://w\"\nkey_file = \"{}\"\n",
            path.display()
        );
        let endpoints = with(&from_file).unwrap().witness_endpoints().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(endpoints[0].witness.key.to_vkey(), WITNESS_A);
        assert!(matches!(with(&from_file), Err(ConfigError::Witness(0, "key_file"))));
        assert!(matches!(
            with("[[witnesses]]\nid = \"w\"\nurl = \"http://w\"\n"),
            Err(ConfigError::Witness(0, "key"))
        ));
        assert!(matches!(
            with(&format!(
                "{}key_file = \"/run/witness/vkey\"\n",
                witness("w", "http://w", WITNESS_A, "counted")
            )),
            Err(ConfigError::Witness(0, "key"))
        ));
        assert!(matches!(
            with(&witness("w", "http://w", WITNESS_A, "trusted")),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            with("[witnessing]\ncall_timeout_ms = 0"),
            Err(ConfigError::WitnessTimeout)
        ));
        assert!(matches!(
            with("[witnessing]\ntls_roots = \"/nonexistent/roots.pem\""),
            Err(ConfigError::WitnessRoots(_))
        ));
    }

    // OP-33 OP-46
    #[test]
    fn op_46_independent_k_needs_k_counted_witnesses_configured() {
        let one = "[declaration]\nwitness = \"independent\"\nindependent_witnesses = 1\n";
        assert!(matches!(
            with(one),
            Err(ConfigError::TooFewWitnesses {
                declared: 1,
                configured: 0
            })
        ));
        let gossip_only = format!(
            "{one}{}",
            witness("suiss_gossip", "http://g", WITNESS_B, "gossip")
        );
        assert!(matches!(
            with(&gossip_only),
            Err(ConfigError::TooFewWitnesses {
                declared: 1,
                configured: 0
            })
        ));
        let counted = format!(
            "{one}{}",
            witness("witness_a", "http://a", WITNESS_A, "counted")
        );
        assert_eq!(
            with(&counted).unwrap().witness_endpoints().unwrap().len(),
            1
        );
        let local = format!(
            "[declaration]\nwitness = \"local-dependent\"\n{}",
            witness("witness_a", "http://witness:7380", WITNESS_A, "counted")
        );
        assert!(with(&local).is_ok());
    }

    // OP-41 OP-31
    #[test]
    fn op_41_group_commit_values_come_from_the_configuration() {
        let config = with("").unwrap();
        assert_eq!(config.group_config().unwrap(), GroupConfig::default());
        let small = "[group_commit]\nqueue = 8\nretry_after_ms = 2000";
        let set = with(small).unwrap().group_config().unwrap();
        assert_eq!(
            set,
            GroupConfig::new(256, 1 << 20, 8, Duration::from_secs(2)).unwrap()
        );
        for toml in [
            "[group_commit]\nqueue = 0",
            "[group_commit]\nmax_records = 257",
            "[group_commit]\nretry_after_ms = 0",
        ] {
            assert!(
                matches!(with(toml), Err(ConfigError::GroupCommit(_))),
                "{toml}"
            );
        }
    }

    #[test]
    fn defaults_with_time_sources_are_valid() {
        assert!(with("").is_ok());
    }

    // OP-32 OP-43
    #[test]
    fn op_43_fewer_than_two_nts_or_three_roughtime_servers_stop_the_process() {
        assert!(matches!(
            Config::default().validate(),
            Err(ConfigError::TimeSources(TimeConfigError::TooFewNts {
                found: 0
            }))
        ));
        assert!(matches!(
            with(&time_sources(1, 3)),
            Err(ConfigError::TimeSources(TimeConfigError::TooFewNts {
                found: 1
            }))
        ));
        assert!(matches!(
            with(&time_sources(2, 2)),
            Err(ConfigError::TimeSources(TimeConfigError::TooFewRoughtime {
                found: 2
            }))
        ));
        let config = with(&time_sources(2, 3)).unwrap();
        assert_eq!(config.nts_servers().len(), 2);
        assert!(config.nts_servers().iter().all(|n| n.port == 4460));
        let servers = config.roughtime_servers().unwrap();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0].public_key[0], 208);
        assert_eq!(servers[0].version, RoughtimeVersion::Rfc);
    }

    // OP-42 OP-43
    #[test]
    fn op_42_roughtime_servers_name_a_32_byte_key_and_a_known_version() {
        let entry = |address: &str, key: &str, version: &str| {
            format!(
                "{{ address = \"{address}\", public_key = \"{key}\", version = \"{version}\" }}"
            )
        };
        let toml = |last_key: &str, first_version: &str| {
            format!(
                "[ledger_time]\nroughtime = [{}, {}, {}]",
                entry("a:2003", KEY, first_version),
                entry("b:2002", KEY, "rfc"),
                entry("c:2002", last_key, "rfc")
            )
        };
        assert!(matches!(
            with(&toml("AAAA", "draft-11")),
            Err(ConfigError::RoughtimeKey(2))
        ));
        let config = with(&toml(KEY, "draft-11")).unwrap();
        assert_eq!(
            config.roughtime_servers().unwrap()[0].version,
            RoughtimeVersion::Draft11
        );
        assert!(matches!(
            with(&toml(KEY, "draft-08")),
            Err(ConfigError::Parse(_))
        ));
    }

    // T-32 T-41
    #[test]
    fn t_32_unknown_keys_such_as_a_dev_mode_are_rejected() {
        for key in [
            "dev_mode = true",
            "skip_signature = true",
            "without_access = true",
        ] {
            assert!(matches!(with(key), Err(ConfigError::Parse(_))), "{key}");
        }
    }

    // T-32
    #[test]
    fn t_32_invalid_configuration_stops_the_process() {
        assert!(matches!(
            with("log = \"  \""),
            Err(ConfigError::EmptyLogFilter)
        ));
        assert!(with("listen = \"not an address\"").is_err());
        assert!(matches!(
            with("startup_timeout_ms = 0"),
            Err(ConfigError::ZeroTimeout)
        ));
    }

    // T-20 MD-14 OP-2 T-93
    #[test]
    fn t_20_both_databases_and_nats_are_configured() {
        let config = with(
            "[postgres]\ncanonical = \"postgres://work_app@db/work\"\nderived = \"postgres://work_app@db/work_derived\"\n[nats]\nurl = \"nats://bus:4222\"",
        )
        .unwrap();
        assert_eq!(config.postgres.canonical, "postgres://work_app@db/work");
        assert_eq!(
            config.postgres.derived,
            "postgres://work_app@db/work_derived"
        );
        assert_eq!(config.nats.url, "nats://bus:4222");
        assert!(matches!(
            with("[nats]\nurl = \"nats://bus\"\njetstream = false"),
            Err(ConfigError::Parse(_))
        ));
    }

    // OP-40 OP-18 T-39
    #[test]
    fn op_40_new_root_traces_are_sampled_at_one_in_ten_by_default() {
        let config = Config::default();
        assert_eq!(config.trace.endpoint, None);
        let trace = config.trace_config().unwrap();
        assert_eq!(trace.sample_ratio, SampleRatio::DEFAULT);
        assert!((trace.sample_ratio.get() - 0.1).abs() < f64::EPSILON);
        let set =
            with("[trace]\nendpoint = \"http://collector:4317\"\nsample_ratio = 1.0").unwrap();
        let trace = set.trace_config().unwrap();
        assert_eq!(trace.sample_ratio, SampleRatio::ALWAYS);
        assert_eq!(trace.endpoint.as_deref(), Some("http://collector:4317"));
        for bad in ["-0.1", "1.5", "nan"] {
            assert!(
                matches!(
                    with(&format!("[trace]\nsample_ratio = {bad}")),
                    Err(ConfigError::SampleRatio(_))
                ),
                "{bad}"
            );
        }
    }

    // T-20 OP-18 T-93
    #[test]
    fn t_20_urls_with_a_password_are_rejected() {
        for (toml, key) in [
            (
                "[postgres]\ncanonical = \"postgres://u:pw@db/work\"",
                "postgres.canonical",
            ),
            (
                "[postgres]\nderived = \"postgres://u:p%40w@db:5432/work_derived?sslmode=require\"",
                "postgres.derived",
            ),
            ("[nats]\nurl = \"nats://u:pw@bus:4222\"", "nats.url"),
            (
                "[postgres]\nsequencer = \"postgres://work_sequencer:pw@db/work\"",
                "postgres.sequencer",
            ),
            (
                "[postgres]\ncheckpointer = \"postgres://work_checkpointer:pw@db/work\"",
                "postgres.checkpointer",
            ),
            (
                "[postgres]\npublisher = \"postgres://work_publisher:pw@db/work\"",
                "postgres.publisher",
            ),
            (
                "[postgres]\nderiver = \"postgres://work_deriver:pw@db/work_derived\"",
                "postgres.deriver",
            ),
            (
                "[trace]\nendpoint = \"http://u:pw@collector:4317\"",
                "trace.endpoint",
            ),
        ] {
            assert!(
                matches!(with(toml), Err(ConfigError::PasswordInUrl(k)) if k == key),
                "{toml}"
            );
        }
        assert!(!has_password("postgres://work_app@db/work?options=a:b@c"));
        assert!(!has_password("postgres://db:5432/work"));
        assert!(has_password("postgres://work_app:@db/work"));
    }
}
