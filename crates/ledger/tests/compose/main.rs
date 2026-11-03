//! Ledger time against the local environment (OP-32, OP-42, OP-43, T-41): the two chrony NTS
//! servers and the three `roughenough-server` 2.2.0 servers of `deploy/compose`, through the same
//! adapters the server runs. These tests need `just dev`; `just test-compose` runs them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use work_ledger::SystemRng;
use work_ledger::time::{
    LedgerTime, NTS_EVENT_QUEUE, NtsServer, ProcessMonotonic, RoughtimeQuery, RoughtimeServer,
    RoughtimeUdp, RoughtimeVersion, Round, read_roots, spawn_nts,
};

const ROOT: &str = include_str!("../../../../deploy/compose/nts/pki/root.pem");
const DEADLINE: Duration = Duration::from_secs(240);

const ROUGHTIME: [(u16, [u8; 32]); 3] = [
    (
        15319,
        [
            100, 246, 237, 156, 180, 228, 187, 130, 129, 8, 95, 1, 213, 130, 33, 21, 43, 3, 118,
            150, 44, 232, 37, 191, 223, 153, 143, 178, 254, 89, 130, 243,
        ],
    ),
    (
        15320,
        [
            69, 110, 148, 62, 230, 81, 251, 228, 64, 242, 248, 217, 70, 39, 226, 10, 69, 95, 60,
            43, 192, 130, 7, 166, 139, 180, 101, 145, 4, 75, 118, 185,
        ],
    ),
    (
        15321,
        [
            200, 82, 225, 184, 148, 128, 140, 58, 230, 40, 252, 42, 203, 76, 235, 89, 134, 92, 29,
            248, 174, 189, 7, 214, 250, 32, 160, 30, 203, 159, 41, 101,
        ],
    ),
];

fn udp(servers: Vec<RoughtimeServer>, mono: Arc<ProcessMonotonic>) -> RoughtimeUdp {
    RoughtimeUdp::new(servers, mono, Arc::new(SystemRng))
}

fn roughtime() -> Vec<RoughtimeServer> {
    ROUGHTIME
        .iter()
        .map(|(port, public_key)| RoughtimeServer {
            address: format!("127.0.0.1:{port}"),
            public_key: *public_key,
            version: RoughtimeVersion::Rfc,
        })
        .collect()
}

fn nts() -> Vec<NtsServer> {
    [14460, 14461]
        .into_iter()
        .map(|port| NtsServer {
            host: "127.0.0.1".to_owned(),
            port,
        })
        .collect()
}

async fn ledger_time(
    mono: &Arc<ProcessMonotonic>,
) -> (
    LedgerTime<ProcessMonotonic>,
    Vec<tokio::task::JoinHandle<()>>,
) {
    let time = LedgerTime::new(2, 3, Arc::clone(mono)).unwrap();
    let (events, received) = mpsc::channel(NTS_EVENT_QUEUE);
    let roots = read_roots(&mut ROOT.as_bytes()).unwrap();
    let mut handles = spawn_nts(nts(), roots, mono, &events).unwrap();
    handles.push(tokio::spawn(time.clone().follow_nts(received)));
    let ready = tokio::time::timeout(DEADLINE, async {
        while time.read().is_err() {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await;
    assert!(ready.is_ok(), "no NTS ledger time within {DEADLINE:?}");
    (time, handles)
}

// OP-42
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn op_42_rfc_answers_of_the_three_compose_servers_verify() {
    let q = udp(roughtime(), Arc::new(ProcessMonotonic::start()));
    for server in 0..q.servers() {
        let answer = q.query(server).await.unwrap();
        assert!(answer.radius_ms >= 1_000, "{answer:?}");
        assert!(answer.rtt_ms < 5_000, "{answer:?}");
    }
}

// OP-42
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn op_42_another_key_or_version_gives_no_answer() {
    let mut servers = roughtime();
    servers[0].public_key = servers[1].public_key;
    servers[1].version = RoughtimeVersion::Draft11;
    let q = udp(servers, Arc::new(ProcessMonotonic::start()));
    assert!(q.query(0).await.is_err());
    assert!(q.query(1).await.is_err());
    assert!(q.query(2).await.is_ok());
}

// OP-32
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn op_32_two_compose_nts_servers_give_ledger_time_that_follows_the_monotonic_clock() {
    let mono = Arc::new(ProcessMonotonic::start());
    let (time, handles) = ledger_time(&mono).await;
    let first = time.read().unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let second = time.read().unwrap();
    let advanced = second - first;
    assert!((1_750..=2_250).contains(&advanced), "{advanced} ms");
    for handle in handles {
        handle.abort();
    }
}

// OP-43
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local environment"]
async fn op_43_the_three_compose_servers_bound_ledger_time_and_a_silent_round_keeps_nts() {
    let mono = Arc::new(ProcessMonotonic::start());
    let (time, handles) = ledger_time(&mono).await;
    let q = udp(roughtime(), Arc::clone(&mono));
    assert_eq!(time.round(&q).await, Round::Answered(3));
    assert!(time.read().is_ok());
    let mut silent = roughtime();
    for server in &mut silent {
        server.address = "127.0.0.1:9".to_owned();
    }
    let silent = udp(silent, Arc::clone(&mono));
    assert_eq!(time.round(&silent).await, Round::Unanswered);
    assert!(time.read().is_ok());
    for handle in handles {
        handle.abort();
    }
}
