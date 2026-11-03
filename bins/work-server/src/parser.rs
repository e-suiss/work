//! The parser worker mode of the server binary (T-72, SEC-35): `work-server parser-worker` builds the secret scanner, locks itself down with the shared parser worker profile before it reads a byte of input (no sockets, no path, no port, two-phase seccomp, no `io_uring`, an empty capability set) and then answers scan requests on its standard input and output until the input closes; if any step fails it does not start. A process started as root needs `--run-as <uid>:<gid>`; an unprivileged one needs an empty capability bounding set, as in its container.

use std::process::ExitCode;

use suiss_sandbox::{LandlockAbi, Lockdown, Profile, RunAs};
use work_parse::secret::{BuildError, SecretScanner};
use work_parse::worker::{ServeError, serve};

/// The first argument that starts the binary as a parser worker.
pub(crate) const MODE: &str = "parser-worker";

/// Why the parser worker does not start or stops early.
#[derive(Debug, thiserror::Error)]
enum WorkerError {
    /// The command line is not `parser-worker [--run-as <uid>:<gid>]`.
    #[error("usage: work-server parser-worker [--run-as <uid>:<gid>]")]
    Usage,
    /// The run-as identity is root or not two numbers.
    #[error("--run-as must name a non-root uid and gid")]
    RunAs,
    /// The embedded rule set does not build.
    #[error("secret scanner: {0}")]
    Scanner(BuildError),
    /// The lockdown could not be applied.
    #[error("lockdown failed: {0}")]
    Lockdown(suiss_sandbox::Error),
}

#[allow(
    clippy::print_stderr,
    reason = "the parser worker's start-up and refusal lines"
)]
fn say(line: &str) {
    eprintln!("work-server parser-worker: {line}");
}

/// The lockdown of a parser worker: the parser worker profile, nothing declared.
pub(crate) fn lockdown(run_as: Option<RunAs>) -> Lockdown {
    let lockdown = Lockdown::new(Profile::ParserWorker, LandlockAbi::REQUIRED);
    match run_as {
        Some(id) => lockdown.run_as(id),
        None => lockdown,
    }
}

fn run_as(args: &[String]) -> Result<Option<RunAs>, WorkerError> {
    match args {
        [] => Ok(None),
        [flag, ids] if flag == "--run-as" => {
            let (uid, gid) = ids.split_once(':').ok_or(WorkerError::RunAs)?;
            let uid = uid.parse().map_err(|_| WorkerError::RunAs)?;
            let gid = gid.parse().map_err(|_| WorkerError::RunAs)?;
            RunAs::new(uid, gid)
                .map(Some)
                .map_err(|_| WorkerError::RunAs)
        }
        _ => Err(WorkerError::Usage),
    }
}

/// Runs the parser worker with the arguments after [`MODE`].
pub(crate) fn main(args: &[String]) -> ExitCode {
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Stop::Start(e @ WorkerError::Usage)) => {
            say(&e.to_string());
            ExitCode::from(2)
        }
        Err(Stop::Start(e)) => {
            say(&format!("refusing to start: {e}"));
            ExitCode::FAILURE
        }
        Err(Stop::Serve(e)) => {
            say(&format!("stopped: {e}"));
            ExitCode::FAILURE
        }
    }
}

enum Stop {
    Start(WorkerError),
    Serve(ServeError),
}

fn run(args: &[String]) -> Result<(), Stop> {
    let identity = run_as(args).map_err(Stop::Start)?;
    let scanner = SecretScanner::builtin().map_err(|e| Stop::Start(WorkerError::Scanner(e)))?;
    let locked = lockdown(identity)
        .apply()
        .map_err(|e| Stop::Start(WorkerError::Lockdown(e)))?;
    let report = locked
        .narrow()
        .map_err(|e| Stop::Start(WorkerError::Lockdown(e)))?;
    say(&format!(
        "serving, lockdown {} seccomp phase {} landlock abi {}",
        report.profile.as_str(),
        report.seccomp_phase,
        report.landlock_kernel_abi
    ));
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    serve(&scanner, &mut input, &mut output).map_err(Stop::Serve)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    // T-72
    #[test]
    fn t_72_the_parser_worker_lockdown_declares_no_path_and_no_port() {
        let plain = lockdown(None);
        assert_eq!(plain.profile(), Profile::ParserWorker);
        let shown = format!("{plain:?}");
        for field in [
            "landlock_abi: V4",
            "read_only: []",
            "read_write: []",
            "execute: []",
            "tcp_connect: []",
            "tcp_bind: []",
            "run_as: None",
        ] {
            assert!(shown.contains(field), "{shown}");
        }
        let id = RunAs::new(65532, 65533).unwrap();
        let switched = format!("{:?}", lockdown(Some(id)));
        assert!(switched.contains("uid: 65532, gid: 65533"), "{switched}");
        assert!(switched.contains("read_only: []"), "{switched}");
    }

    // T-72
    #[test]
    fn t_72_the_parser_worker_takes_only_an_unprivileged_run_as_identity() {
        assert!(matches!(run_as(&args(&[])), Ok(None)));
        let parsed = run_as(&args(&["--run-as", "65532:65533"])).unwrap();
        let id = parsed.unwrap();
        assert_eq!((id.uid(), id.gid()), (65532, 65533));
        let identities: [&[&str]; 4] = [
            &["--run-as", "0:0"],
            &["--run-as", "65532:0"],
            &["--run-as", "65532"],
            &["--run-as", "a:b"],
        ];
        for bad in identities {
            let got = run_as(&args(bad));
            assert!(matches!(got, Err(WorkerError::RunAs)), "{bad:?}");
        }
        let usages: [&[&str]; 3] = [&["--run-as"], &["--config"], &["--run-as", "1:1", "x"]];
        for bad in usages {
            let got = run_as(&args(bad));
            assert!(matches!(got, Err(WorkerError::Usage)), "{bad:?}");
        }
    }
}
