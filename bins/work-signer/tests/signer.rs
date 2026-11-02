//! The signer process against a real `SoftHSM` token (T-7, T-10, T-56, T-72): it starts only
//! inside its lockdown, which needs root to empty the capability bounding set before it switches
//! to the test's own identity, answers on its Unix socket with checkpoint note signatures under
//! the token's key and refuses every other request. `SOFTHSM2_CONF` names the `SoftHSM`
//! configuration and `sudo -n` must work, as in CI.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

mod support;

use std::os::unix::net::UnixStream;
use std::process::Command;

use suiss_crypto::note::verify_checkpoint;
use suiss_crypto::sig::PureBackend;
use work_proto::signer::{self as frames, Kind, Status, refusal};

use support::{NAME, PREFIX, ROOT, Signer, Token, ids};

fn body(origin: &str) -> String {
    format!("{origin}\n7\n{ROOT}\n")
}

fn refused(code: &str) -> (Status, Vec<u8>) {
    (Status::Refused, code.as_bytes().to_vec())
}

// T-7 T-10 T-56 P-20 T-88
#[test]
fn t_7_the_signer_signs_checkpoints_of_its_ledgers_only() {
    let token = Token::new("kinds");
    let signer = Signer::start(&token);

    let (status, key) = signer.ask(Kind::LogKey.as_byte(), &[]);
    assert_eq!(status, Status::Signed);
    assert_eq!(
        frames::parse_log_key(&key).unwrap(),
        (token.public, NAME.to_owned())
    );

    let origin = format!("{PREFIX}ab12");
    let checkpoint = body(&origin);
    let (status, line) = signer.ask(Kind::Checkpoint.as_byte(), checkpoint.as_bytes());
    assert_eq!(status, Status::Signed);
    let note = format!("{checkpoint}\n{}", String::from_utf8(line).unwrap());
    let (cp, accepted) =
        verify_checkpoint(&PureBackend, &note, &origin, &token.verifier(), &[]).unwrap();
    assert_eq!(cp.size, 7);
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].timestamp, None);

    let record = [0xd2, 0x84, 0x40, 0xa0, 0x40, 0x40];
    assert_eq!(
        signer.ask(Kind::Checkpoint.as_byte(), &record),
        refused(refusal::NOT_CHECKPOINT)
    );
    assert_eq!(
        signer.ask(
            Kind::Checkpoint.as_byte(),
            body("access.example/domain/ab12").as_bytes()
        ),
        refused(refusal::ORIGIN)
    );
    assert_eq!(
        signer.ask(Kind::LogKey.as_byte(), b"x"),
        refused(refusal::PAYLOAD)
    );
    for kind in [0_u8, 3, 4, 0x7f, 0xff] {
        assert_eq!(
            signer.ask(kind, checkpoint.as_bytes()),
            refused(refusal::KIND)
        );
    }
}

// T-72 T-10
#[test]
fn t_72_the_signer_serves_only_inside_its_lockdown() {
    let token = Token::new("locked");
    let signer = Signer::start(&token);
    let status = std::fs::read_to_string(format!("/proc/{}/status", signer.pid())).unwrap();
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
    assert_eq!(field("CapBnd:"), "0000000000000000");
    let (uid, _) = ids();
    assert_eq!(
        field("Uid:").split_whitespace().collect::<Vec<_>>(),
        vec![uid.to_string(); 4]
    );
    assert!(field("Seccomp_filters:").parse::<u32>().unwrap() >= 4);
}

// T-72
#[test]
fn t_72_the_signer_refuses_to_start_when_its_lockdown_cannot_be_set_up() {
    let token = Token::new("refused");
    let out = Command::new(env!("CARGO_BIN_EXE_work-signer"))
        .arg("--config")
        .arg(token.config(None))
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("refusing to start: lockdown failed"), "{err}");
    assert!(UnixStream::connect(token.socket()).is_err());
}
