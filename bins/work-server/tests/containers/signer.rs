//! Readiness with the real signer (T-39 rule 6, T-84): a `SoftHSM` token with a generated log
//! key and `work-signer` started as root through `sudo -n`, dropping to the test's identity.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use suiss_crypto::pkcs11::KeyStore;
use suiss_crypto::secret::Secret;
use work_testkit::Nats;

use super::{Addresses, Databases, Launch, PREFIX, get, listening, server};

const PIN: &str = "4711";
const LABEL: &str = "work.log.v1";

fn module() -> PathBuf {
    std::env::var_os("PKCS11_MODULE").map_or_else(
        || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from,
    )
}

fn token_dir() -> PathBuf {
    let conf = std::env::var_os("SOFTHSM2_CONF").unwrap();
    let text = std::fs::read_to_string(conf).unwrap();
    let dir = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("directories.tokendir"))
        .and_then(|rest| rest.trim().strip_prefix('='))
        .unwrap();
    PathBuf::from(dir.trim())
}

fn ids() -> (u32, u32) {
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

/// A token of its own with the log key, and the signer's configuration over it.
struct Token {
    dir: PathBuf,
    label: String,
}

impl Token {
    fn new(test: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("work-server-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let label = format!("server-{test}-{}", std::process::id());
        let init = Command::new("softhsm2-util")
            .args(["--init-token", "--free", "--label", &label])
            .args(["--so-pin", "12345678", "--pin", PIN])
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let store = KeyStore::open(&module(), &label, &Secret::new(PIN.to_owned())).unwrap();
        store.generate_ed25519(LABEL).unwrap();
        std::fs::write(dir.join("pin"), format!("{PIN}\n")).unwrap();
        Self { dir, label }
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("signer.sock")
    }

    fn config(&self) -> PathBuf {
        let (uid, gid) = ids();
        let text = format!(
            "socket = \"{}\"\norigin_prefix = \"{PREFIX}\"\n\n[pkcs11]\nmodule = \"{}\"\ntoken = \"{}\"\npin_file = \"{}\"\ntoken_dir = \"{}\"\n\n[log_key]\nlabel = \"{LABEL}\"\nname = \"work.example\"\n\n[run_as]\nuid = {uid}\ngid = {gid}\n",
            self.socket().display(),
            module().display(),
            self.label,
            self.dir.join("pin").display(),
            token_dir().display(),
        );
        let path = self.dir.join("signer.toml");
        std::fs::write(&path, text).unwrap();
        path
    }
}

/// `work-signer`, built next to `work-server`, started as root through `sudo -n`.
struct Signer {
    child: Child,
}

impl Signer {
    fn start(token: &Token) -> Self {
        let binary = Path::new(env!("CARGO_BIN_EXE_work-server")).with_file_name("work-signer");
        assert!(binary.exists(), "{} is not built", binary.display());
        let child = Command::new("sudo")
            .args(["-n", "--preserve-env=SOFTHSM2_CONF"])
            .arg(&binary)
            .arg("--config")
            .arg(token.config())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut signer = Self { child };
        for _ in 0..400 {
            if std::os::unix::net::UnixStream::connect(token.socket()).is_ok() {
                return signer;
            }
            if let Some(status) = signer.child.try_wait().unwrap() {
                panic!("the signer exited with {status}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the signer did not listen");
    }

    fn pid(&self) -> u32 {
        let me = self.child.id();
        let children =
            std::fs::read_to_string(format!("/proc/{me}/task/{me}/children")).unwrap_or_default();
        children
            .split_whitespace()
            .next()
            .map_or(me, |c| c.parse().unwrap())
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

async fn becomes(at: std::net::SocketAddr, path: &str, status: u16) -> String {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let (got, body) = get(at, path).await;
            if got == status {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{path} did not answer {status}"))
}

// T-39 T-84 T-21 T-28 OP-18 T-93
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker, SoftHSM and sudo"]
async fn t_39_readiness_follows_postgres_and_the_signer_and_never_nats() {
    let dbs = Databases::start(true).await;
    let nats = Nats::start().await.unwrap();
    let token = Token::new("readiness");
    let at = Addresses::free();
    let launch = Launch {
        stdout: Stdio::null(),
        signer: Some(token.socket()),
        ..Launch::new(nats.url(), at)
    };
    let mut child = server(&dbs, launch);
    listening(&mut child, at.internal).await;
    let body = becomes(at.internal, "/readyz", 503).await;
    assert!(body.contains("signer"), "{body}");
    assert_eq!(get(at.internal, "/livez").await.0, 200);

    let signer = Signer::start(&token);
    becomes(at.internal, "/readyz", 200).await;
    let (_, metrics) = get(at.internal, "/metrics").await;
    assert!(metrics.contains("\nwork_ready 1\n"), "{metrics}");
    assert!(metrics.contains("work_dependency_up{dependency=\"signer\"} 1"));
    assert!(metrics.contains("work_dependency_up{dependency=\"nats\"} 1"));

    drop(nats);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(get(at.internal, "/readyz").await.0, 200);
    let (_, metrics) = get(at.internal, "/metrics").await;
    assert!(
        metrics.contains("work_dependency_up{dependency=\"nats\"} 0"),
        "{metrics}"
    );

    drop(signer);
    let body = becomes(at.internal, "/readyz", 503).await;
    assert!(body.contains("signer"), "{body}");
    assert_eq!(get(at.internal, "/livez").await.0, 200);
    assert!(child.try_wait().unwrap().is_none(), "work-server exited");
    child.kill().unwrap();
    child.wait().unwrap();
}
