//! Typed process configuration, validated at start-up (T-32 rule 8).

use std::net::{Ipv4Addr, SocketAddr};

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

/// Validated process configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Listen address; loopback unless the operator exposes it.
    pub(crate) listen: SocketAddr,
    /// `tracing` filter directives.
    pub(crate) log: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8090)),
            log: "info".to_owned(),
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
}

impl Config {
    pub(crate) fn load() -> Result<Self, ConfigError> {
        let file = std::env::var("WORK_CONFIG").unwrap_or_else(|_| "work.toml".to_owned());
        Self::from_figment(
            &Figment::from(Serialized::defaults(Self::default()))
                .merge(Toml::file(file))
                .merge(Env::prefixed("WORK_").ignore(&["CONFIG"])),
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(toml: &str) -> Result<Config, ConfigError> {
        Config::from_figment(
            &Figment::from(Serialized::defaults(Config::default())).merge(Toml::string(toml)),
        )
    }

    #[test]
    fn default_listen_address_is_loopback() {
        assert!(Config::default().listen.ip().is_loopback());
    }

    #[test]
    fn defaults_are_valid() {
        assert!(Config::default().validate().is_ok());
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
    }
}
