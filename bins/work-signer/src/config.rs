//! The signer's configuration, one TOML file read before anything else (T-32 rule 8).

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Validated signer configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// The Unix socket the signer listens on; the only way to reach it.
    pub(crate) socket: PathBuf,
    /// Origins the signer signs checkpoints for start with this prefix, e.g.
    /// `work.example/ledger/`.
    pub(crate) origin_prefix: String,
    /// The PKCS#11 token (T-56).
    pub(crate) pkcs11: Pkcs11,
    /// The log key: the ledger acknowledgement and checkpoint key.
    pub(crate) log_key: LogKey,
    /// The unprivileged identity a signer started as root switches to (SA-22).
    pub(crate) run_as: Option<Identity>,
}

/// Where the key store is.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pkcs11 {
    /// The PKCS#11 module, loaded before the lockdown.
    pub(crate) module: PathBuf,
    /// The token label.
    pub(crate) token: String,
    /// A file holding the user PIN.
    pub(crate) pin_file: PathBuf,
    /// The directory the module keeps its token in, the one path the lockdown leaves open.
    pub(crate) token_dir: PathBuf,
}

/// The log key in the token.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogKey {
    /// The PKCS#11 label of the Ed25519 key pair.
    pub(crate) label: String,
    /// The C2SP note key name its signature lines carry.
    pub(crate) name: String,
}

/// A user and group id.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    /// User id.
    pub(crate) uid: u32,
    /// Group id.
    pub(crate) gid: u32,
}

/// Why the configuration is refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// The file could not be read.
    #[error("{0}: {1}")]
    Read(PathBuf, std::io::Error),
    /// The file is not a valid configuration.
    #[error("{0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    /// The origin prefix is empty, does not end with `/` or holds a character no origin may.
    #[error("origin_prefix must be a non-empty origin start ending with `/`")]
    OriginPrefix,
    /// The note key name breaks the C2SP naming rules.
    #[error("log_key.name is not a valid note key name")]
    KeyName,
}

impl Config {
    /// Reads and checks the file at `path`.
    pub(crate) fn load(path: &Path) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_owned(), e))?;
        let config: Self =
            toml::from_str(&text).map_err(|e| ConfigError::Parse(path.to_owned(), e))?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), ConfigError> {
        let start = self
            .origin_prefix
            .strip_suffix('/')
            .ok_or(ConfigError::OriginPrefix)?;
        suiss_crypto::note::check_name(start).map_err(|_| ConfigError::OriginPrefix)?;
        suiss_crypto::note::check_name(&self.log_key.name).map_err(|_| ConfigError::KeyName)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn parse(prefix: &str, name: &str) -> Result<(), ConfigError> {
        let text = format!(
            "socket = \"/run/work-signer/signer.sock\"\n\
             origin_prefix = \"{prefix}\"\n\
             [pkcs11]\n\
             module = \"/usr/lib/softhsm/libsofthsm2.so\"\n\
             token = \"work\"\n\
             pin_file = \"/run/secrets/pin\"\n\
             token_dir = \"/var/lib/softhsm/tokens\"\n\
             [log_key]\n\
             label = \"work.log.v1\"\n\
             name = \"{name}\"\n"
        );
        let config: Config = toml::from_str(&text).unwrap();
        config.check()
    }

    // T-7
    #[test]
    fn t_7_the_origin_prefix_and_the_key_name_follow_the_note_rules() {
        assert!(parse("work.example/ledger/", "work.example").is_ok());
        assert!(matches!(
            parse("work.example/ledger", "work.example"),
            Err(ConfigError::OriginPrefix)
        ));
        assert!(matches!(
            parse("/", "work.example"),
            Err(ConfigError::OriginPrefix)
        ));
        assert!(matches!(
            parse("work example/", "work.example"),
            Err(ConfigError::OriginPrefix)
        ));
        assert!(matches!(
            parse("work.example/ledger/", "work+example"),
            Err(ConfigError::KeyName)
        ));
    }
}
