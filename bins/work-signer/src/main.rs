//! The Work signer process (T-7, T-10, T-56, T-72): it reads the token PIN into `memfd_secret`
//! memory, logs in to the PKCS#11 token, loads the log key, binds its Unix socket and then locks
//! itself down with the shared signer profile (no network syscalls, Landlock, two-phase
//! seccomp, no `io_uring`) before it answers anything; if any step fails it does not start. It
//! signs ledger acknowledgements, which are checkpoints, and never an author signature.

mod answer;
mod config;

use std::io::Read as _;
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use suiss_crypto::cose::PublicKey;
use suiss_crypto::pkcs11::{HsmError, KeyStore};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::Signer as _;
use suiss_sandbox::{LandlockAbi, Lockdown, Profile, RunAs, SecretMemory};

use crate::answer::LogKey;
use crate::config::{Config, ConfigError};

/// Why the signer does not start.
#[derive(Debug, thiserror::Error)]
enum StartError {
    /// The configuration was refused.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The PIN file could not be read into secret memory.
    #[error("PIN file {0}: {1}")]
    Pin(PathBuf, std::io::Error),
    /// The PIN file is empty or not UTF-8.
    #[error("PIN file {0} holds no PIN")]
    PinEmpty(PathBuf),
    /// Secret memory for the PIN is not available (`memfd_secret`).
    #[error("secret memory for the PIN: {0}")]
    SecretMemory(suiss_sandbox::Error),
    /// The token or the log key could not be opened.
    #[error("key store ({}): {0}", .0.code())]
    KeyStore(HsmError),
    /// The log key is not an Ed25519 key.
    #[error("the log key must be an Ed25519 key")]
    KeyType,
    /// The socket could not be bound.
    #[error("socket {0}: {1}")]
    Socket(PathBuf, std::io::Error),
    /// The lockdown could not be applied.
    #[error("lockdown failed: {0}")]
    Lockdown(suiss_sandbox::Error),
}

#[allow(clippy::print_stderr, reason = "the signer's start-up and refusal lines")]
fn say(line: &str) {
    eprintln!("work-signer: {line}");
}

#[allow(clippy::print_stdout, reason = "command line output")]
fn version() {
    println!("work-signer {}", env!("CARGO_PKG_VERSION"));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["--version"] => {
            version();
            ExitCode::SUCCESS
        }
        ["--config", path] => match run(Path::new(path)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                say(&format!("refusing to start: {e}"));
                ExitCode::FAILURE
            }
        },
        _ => {
            say("usage: work-signer --config <file> | --version");
            ExitCode::from(2)
        }
    }
}

fn read_pin(path: &Path) -> Result<Secret<String>, StartError> {
    let io = |e| StartError::Pin(path.to_owned(), e);
    let mut file = std::fs::File::open(path).map_err(io)?;
    let len = file.metadata().map_err(io)?.len();
    let len = usize::try_from(len)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| StartError::PinEmpty(path.to_owned()))?;
    let mut memory = SecretMemory::new(len).map_err(StartError::SecretMemory)?;
    file.read_exact(memory.as_mut_slice()).map_err(io)?;
    let pin = std::str::from_utf8(memory.as_slice())
        .map(|p| p.trim_end_matches(['\n', '\r']))
        .ok()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| StartError::PinEmpty(path.to_owned()))?;
    Ok(Secret::new(pin.to_owned()))
}

fn bind(config: &Config) -> Result<UnixListener, StartError> {
    let path = &config.socket;
    let io = |e| StartError::Socket(path.clone(), e);
    if path.exists() {
        std::fs::remove_file(path).map_err(io)?;
    }
    let listener = UnixListener::bind(path).map_err(io)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    if let Some(id) = config.run_as {
        std::os::unix::fs::chown(path, Some(id.uid), Some(id.gid)).map_err(io)?;
    }
    Ok(listener)
}

fn lockdown(config: &Config) -> Result<Lockdown, StartError> {
    let mut lockdown = Lockdown::new(Profile::Signer, LandlockAbi::REQUIRED)
        .allow_read_write(&config.pkcs11.token_dir);
    if let Some(id) = config.run_as {
        lockdown = lockdown.run_as(RunAs::new(id.uid, id.gid).map_err(StartError::Lockdown)?);
    }
    Ok(lockdown)
}

fn run(path: &Path) -> Result<(), StartError> {
    let config = Config::load(path)?;
    let pin = read_pin(&config.pkcs11.pin_file)?;
    let token = KeyStore::open(&config.pkcs11.module, &config.pkcs11.token, &pin)
        .map_err(StartError::KeyStore)?;
    drop(pin);
    let signer = token
        .signer(&config.log_key.label)
        .map_err(StartError::KeyStore)?;
    let PublicKey::Ed25519(public) = signer.public_key() else {
        return Err(StartError::KeyType);
    };
    let listener = bind(&config)?;
    let locked = lockdown(&config)?
        .apply()
        .map_err(StartError::Lockdown)?;
    let report = locked.narrow().map_err(StartError::Lockdown)?;
    say(&format!(
        "serving on {}, lockdown {} seccomp phase {} landlock abi {}",
        config.socket.display(),
        report.profile.as_str(),
        report.seccomp_phase,
        report.landlock_kernel_abi
    ));
    let key = LogKey {
        signer,
        public,
        name: config.log_key.name,
        origin_prefix: config.origin_prefix,
    };
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(e) = key.serve(&mut stream) {
                    say(&format!("connection closed: {e}"));
                }
            }
            Err(e) => say(&format!("accept failed: {e}")),
        }
    }
    drop(token);
    Ok(())
}
