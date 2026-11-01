//! Typed process configuration, validated at start-up (T-32 rule 8).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use work_ledger::time::{
    NTS_KE_PORT, NtsServer, RoughtimeServer, RoughtimeVersion, TimeConfigError, check_sources,
};
use work_telemetry::{DEFAULT_MAX_QUEUE_SIZE, InvalidSampleRatio, SampleRatio, TraceConfig};

/// Validated process configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Listen address; loopback unless the operator exposes it.
    pub(crate) listen: SocketAddr,
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
            log: "info".to_owned(),
            postgres: Postgres {
                canonical: "postgres://localhost/work".to_owned(),
                derived: "postgres://localhost/work_derived".to_owned(),
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
        Ok(())
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

    fn with(toml: &str) -> Result<Config, ConfigError> {
        Config::from_figment(
            &Figment::from(Serialized::defaults(Config::default()))
                .merge(Toml::string(&time_sources(2, 3)))
                .merge(Toml::string(toml)),
        )
    }

    #[test]
    fn default_listen_address_is_loopback() {
        assert!(Config::default().listen.ip().is_loopback());
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

    // T-20 MD-14 OP-2
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

    // T-20 OP-18
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
