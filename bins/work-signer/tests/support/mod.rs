//! Shared helpers of the signer tests: a SoftHSM token with a generated log key, and the
//! signer process started as root through `sudo -n`, which drops to the test's identity.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use suiss_crypto::cose::PublicKey;
use suiss_crypto::note::Verifier;
use suiss_crypto::pkcs11::KeyStore;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::Signer as _;
use work_proto::signer::{self as frames, Status};

pub(crate) const PIN: &str = "4711";
pub(crate) const LABEL: &str = "work.log.v1";
pub(crate) const NAME: &str = "work.example";
pub(crate) const PREFIX: &str = "work.example/ledger/";
pub(crate) const ROOT: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

pub(crate) fn module() -> PathBuf {
    std::env::var_os("PKCS11_MODULE").map_or_else(
        || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from,
    )
}

pub(crate) fn token_dir() -> PathBuf {
    let conf =
        std::env::var_os("SOFTHSM2_CONF").expect("SOFTHSM2_CONF names the SoftHSM configuration");
    let text = std::fs::read_to_string(conf).unwrap();
    let dir = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("directories.tokendir"))
        .and_then(|rest| rest.trim().strip_prefix('='))
        .unwrap();
    PathBuf::from(dir.trim())
}

pub(crate) fn ids() -> (u32, u32) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let field = |name: &str| -> u32 {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap()
            .parse()
            .unwrap()
    };
    (field("Uid:"), field("Gid:"))
}

/// A token of its own and the log key generated in it.
pub(crate) struct Token {
    pub(crate) dir: PathBuf,
    pub(crate) label: String,
    pub(crate) public: [u8; 32],
}

impl Token {
    pub(crate) fn new(test: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("work-signer-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let label = format!("{test}-{}", std::process::id());
        let init = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                &label,
                "--so-pin",
                "12345678",
                "--pin",
                PIN,
            ])
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let store = KeyStore::open(&module(), &label, &Secret::new(PIN.to_owned())).unwrap();
        let key = store.generate_ed25519(LABEL).unwrap();
        let PublicKey::Ed25519(public) = key.public_key() else {
            panic!("an Ed25519 key");
        };
        std::fs::write(dir.join("pin"), format!("{PIN}\n")).unwrap();
        Self { dir, label, public }
    }

    pub(crate) fn socket(&self) -> PathBuf {
        self.dir.join("signer.sock")
    }

    pub(crate) fn config(&self, run_as: Option<(u32, u32)>) -> PathBuf {
        let mut text = format!(
            "socket = \"{}\"\norigin_prefix = \"{PREFIX}\"\n\n[pkcs11]\nmodule = \"{}\"\ntoken = \"{}\"\npin_file = \"{}\"\ntoken_dir = \"{}\"\n\n[log_key]\nlabel = \"{LABEL}\"\nname = \"{NAME}\"\n",
            self.socket().display(),
            module().display(),
            self.label,
            self.dir.join("pin").display(),
            token_dir().display(),
        );
        if let Some((uid, gid)) = run_as {
            text.push_str(&format!("\n[run_as]\nuid = {uid}\ngid = {gid}\n"));
        }
        let path = self.dir.join("signer.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    pub(crate) fn verifier(&self) -> Verifier {
        Verifier::ed25519(NAME, self.public).unwrap()
    }
}

/// The signer started as root through `sudo -n`; it drops to the test's identity.
pub(crate) struct Signer {
    child: Child,
    pub(crate) socket: PathBuf,
}

impl Signer {
    pub(crate) fn start(token: &Token) -> Self {
        let config = token.config(Some(ids()));
        let child = Command::new("sudo")
            .args([
                "-n",
                "--preserve-env=SOFTHSM2_CONF",
                env!("CARGO_BIN_EXE_work-signer"),
                "--config",
            ])
            .arg(&config)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut signer = Self {
            child,
            socket: token.socket(),
        };
        for _ in 0..400 {
            if UnixStream::connect(&signer.socket).is_ok() {
                return signer;
            }
            if let Some(status) = signer.child.try_wait().unwrap() {
                let mut err = String::new();
                signer
                    .child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut err)
                    .unwrap();
                panic!("the signer exited with {status}: {err}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the signer did not listen");
    }

    pub(crate) fn pid(&self) -> u32 {
        let me = self.child.id();
        let children =
            std::fs::read_to_string(format!("/proc/{me}/task/{me}/children")).unwrap_or_default();
        children
            .split_whitespace()
            .next()
            .map_or(me, |c| c.parse().unwrap())
    }

    pub(crate) fn ask(&self, kind: u8, payload: &[u8]) -> (Status, Vec<u8>) {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .write_all(&frames::frame(kind, payload).unwrap())
            .unwrap();
        let mut head = [0_u8; frames::HEADER];
        stream.read_exact(&mut head).unwrap();
        let header = frames::header(head).unwrap();
        let mut answer = vec![0_u8; header.len];
        stream.read_exact(&mut answer).unwrap();
        (Status::from_byte(header.code).unwrap(), answer)
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        let pid = self.pid();
        let _ = Command::new("sudo")
            .args(["-n", "kill", "-TERM", &pid.to_string()])
            .status();
        let _ = self.child.wait();
    }
}
