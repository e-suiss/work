//! The parser worker process (T-72, SEC-35, P-95): `work-server parser-worker` answers scan
//! requests on its pipes only inside its lockdown, which needs root to empty the capability
//! bounding set before it switches to the test's own identity, refuses malformed and oversized
//! requests with stable codes, and does not start when the lockdown cannot be set up. `sudo -n`
//! must work, as in CI.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::process::Command;
use std::time::Duration;

use work_kernel::record::PartName;
use work_parse::secret::{ScanOutcome, ScanPart};
use work_parse::worker::{Worker, WorkerError};
use work_proto::parser::{self as frames, Kind, Status, refusal};

const EXE: &str = env!("CARGO_BIN_EXE_work-server");

const FILL36: &str = "Zq8kR2mN4vX7bT1yW9cL3pH6dF0sJ5gA2eUo";

const OVER_PART: usize = 256 * 1024 + 1;

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

fn locked_worker() -> Worker {
    let (uid, gid) = ids();
    let mut command = Command::new("sudo");
    command
        .args(["-n", EXE, "parser-worker", "--run-as"])
        .arg(format!("{uid}:{gid}"));
    Worker::spawn(&mut command, Duration::from_secs(20)).unwrap()
}

fn worker_pid(sudo: u32) -> u32 {
    let children =
        std::fs::read_to_string(format!("/proc/{sudo}/task/{sudo}/children")).unwrap_or_default();
    children
        .split_whitespace()
        .next()
        .map_or(sudo, |c| c.parse().unwrap())
}

fn name(s: &str) -> PartName {
    PartName::parse(s).unwrap()
}

// T-72 SEC-35 P-95
#[test]
fn t_72_sec_35_the_parser_worker_scans_only_inside_its_lockdown() {
    let mut worker = locked_worker();
    let title = name("title");
    let note = name("note");
    let report = [ScanPart::new(&title, b"weekly report")];
    assert_eq!(worker.scan(&report).unwrap(), ScanOutcome::Clean);

    let status = std::fs::read_to_string(format!("/proc/{}/status", worker_pid(worker.id())));
    let status = status.unwrap();
    let field = |name: &str| -> String {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap()
            .trim()
            .to_owned()
    };
    assert_eq!(field("Seccomp:"), "2");
    assert_eq!(field("NoNewPrivs:"), "1");
    assert_eq!(field("CapEff:"), "0000000000000000");
    assert_eq!(field("CapPrm:"), "0000000000000000");
    assert_eq!(field("CapBnd:"), "0000000000000000");
    let (uid, _) = ids();
    assert_eq!(
        field("Uid:").split_whitespace().collect::<Vec<_>>(),
        vec![uid.to_string(); 4]
    );
    assert!(field("Seccomp_filters:").parse::<u32>().unwrap() >= 4);

    let secret = ["ghp_", FILL36].concat();
    let leaky = [
        ScanPart::new(&title, b"weekly report"),
        ScanPart::new(&note, secret.as_bytes()),
    ];
    let found = worker.scan(&leaky).unwrap();
    let shown = format!("{found} {found:?}");
    let view = "secret_detected (rule github-pat, part note)";
    assert!(shown.starts_with(view), "{shown}");
    assert!(!shown.contains(FILL36), "{shown}");

    let kind = worker.request(0x7f, b"").unwrap();
    assert_eq!(kind, (Status::Refused, refusal::KIND.as_bytes().to_vec()));
    let one: &[u8] = b"a";
    let twice = frames::scan_request(&[("note", one), ("note", one)]).unwrap();
    let malformed = worker.request(Kind::Scan.as_byte(), &twice).unwrap();
    let expected = (Status::Refused, refusal::MALFORMED.as_bytes().to_vec());
    assert_eq!(malformed, expected);
    let big = vec![b'x'; OVER_PART];
    let oversized = worker.scan(&[ScanPart::new(&note, &big)]);
    assert!(
        matches!(oversized, Err(WorkerError::Refused(refusal::TOO_LARGE))),
        "{oversized:?}"
    );
    assert_eq!(worker.scan(&report).unwrap(), ScanOutcome::Clean);
}

// T-72
#[test]
fn t_72_the_parser_worker_refuses_to_start_when_its_lockdown_cannot_be_set_up() {
    let out = Command::new(EXE).arg("parser-worker").output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("refusing to start: lockdown failed"), "{err}");
    assert!(out.stdout.is_empty());

    let mut command = Command::new(EXE);
    command.arg("parser-worker");
    let mut worker = Worker::spawn(&mut command, Duration::from_secs(20)).unwrap();
    let note = name("note");
    let scanned = worker.scan(&[ScanPart::new(&note, b"fine")]);
    assert!(matches!(scanned, Err(WorkerError::Io(_))), "{scanned:?}");
    let again = worker.scan(&[ScanPart::new(&note, b"fine")]);
    assert!(matches!(again, Err(WorkerError::Gone)), "{again:?}");
}
