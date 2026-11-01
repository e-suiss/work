#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;

use suiss_ledger::time::TimeError;

use super::*;
use crate::time::domain::{NtsSample, RoughtimeAnswer};
use crate::time::ports::QueryError;

const T: u64 = 1_793_505_043_000;

/// A virtual monotonic clock on Tokio's paused time (T-32 rule 2).
#[derive(Debug)]
struct VirtualMono {
    start: tokio::time::Instant,
}

impl VirtualMono {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: tokio::time::Instant::now(),
        })
    }
}

impl Monotonic for VirtualMono {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap()
    }
}

/// Scripted answers per server and the virtual times the queries ran at.
struct Script {
    mono: Arc<VirtualMono>,
    answers: StdMutex<Vec<VecDeque<Option<u64>>>>,
    asked: StdMutex<Vec<(u64, usize)>>,
}

impl Script {
    fn new(mono: &Arc<VirtualMono>, answers: Vec<Vec<Option<u64>>>) -> Arc<Self> {
        Arc::new(Self {
            mono: Arc::clone(mono),
            answers: StdMutex::new(answers.into_iter().map(VecDeque::from).collect()),
            asked: StdMutex::new(Vec::new()),
        })
    }
}

impl RoughtimeQuery for Arc<Script> {
    fn servers(&self) -> usize {
        self.answers.lock().unwrap().len()
    }

    fn query(
        &self,
        server: usize,
    ) -> impl Future<Output = Result<RoughtimeAnswer, QueryError>> + Send {
        let mono_ms = self.mono.now_ms();
        self.asked.lock().unwrap().push((mono_ms, server));
        let next = self.answers.lock().unwrap()[server].pop_front().flatten();
        std::future::ready(
            next.map(|offset| RoughtimeAnswer {
                midpoint_ms: T + offset + mono_ms,
                radius_ms: 1_000,
                rtt_ms: 20,
                mono_ms,
            })
            .ok_or_else(|| QueryError("no answer".to_owned())),
        )
    }
}

fn sampled(mono: &Arc<VirtualMono>) -> LedgerTime<VirtualMono> {
    let time = LedgerTime::new(2, 3, Arc::clone(mono)).unwrap();
    for source in 0..2 {
        time.apply(NtsEvent::Sample {
            source,
            sample: NtsSample {
                unix_ms: T + mono.now_ms(),
                mono_ms: mono.now_ms(),
            },
        });
    }
    time
}

const FAR: u64 = 3_600_000;

// OP-32 OP-43
#[test]
fn op_43_fewer_than_three_roughtime_or_two_nts_servers_do_not_start() {
    let mono = Arc::new(VirtualMono {
        start: tokio::time::Instant::now(),
    });
    assert_eq!(
        LedgerTime::new(2, 2, Arc::clone(&mono)).unwrap_err(),
        TimeConfigError::TooFewRoughtime { found: 2 }
    );
    assert_eq!(
        LedgerTime::new(1, 3, Arc::clone(&mono)).unwrap_err(),
        TimeConfigError::TooFewNts { found: 1 }
    );
    assert_eq!(
        check_sources(0, 0),
        Err(TimeConfigError::TooFewNts { found: 0 })
    );
    assert!(LedgerTime::new(2, 3, mono).is_ok());
}

// OP-43
#[tokio::test(start_paused = true)]
async fn op_43_no_answer_raises_a_warning_and_commits_continue_on_nts() {
    let mono = VirtualMono::new();
    let time = sampled(&mono);
    let none = Script::new(&mono, vec![vec![None], vec![None], vec![None]]);
    assert_eq!(time.round(&none).await, Round::Unanswered);
    assert_eq!(time.read(), Ok(T));
}

// OP-43
#[tokio::test(start_paused = true)]
async fn op_43_a_single_outlier_does_not_stop_commits_and_the_majority_does() {
    let mono = VirtualMono::new();
    let time = sampled(&mono);
    let one_off = Script::new(&mono, vec![vec![Some(0)], vec![Some(0)], vec![Some(FAR)]]);
    assert_eq!(time.round(&one_off).await, Round::Answered(3));
    assert_eq!(time.read(), Ok(T));
    let two_off = Script::new(&mono, vec![vec![Some(0)], vec![Some(FAR)], vec![Some(FAR)]]);
    assert_eq!(time.round(&two_off).await, Round::Answered(3));
    assert_eq!(time.read(), Err(TimeFault::OutsideRoughtime));
    let alone_off = Script::new(&mono, vec![vec![None], vec![Some(FAR)], vec![None]]);
    assert_eq!(time.round(&alone_off).await, Round::Answered(1));
    assert_eq!(time.read(), Err(TimeFault::OutsideRoughtime));
    let alone_on = Script::new(&mono, vec![vec![None], vec![None], vec![Some(0)]]);
    assert_eq!(time.round(&alone_on).await, Round::Answered(1));
    assert_eq!(time.read(), Ok(T));
}

// OP-43
#[tokio::test(start_paused = true)]
async fn op_43_rounds_run_at_start_up_and_every_3600_s_and_a_failed_first_round_does_not_block() {
    let mono = VirtualMono::new();
    let time = sampled(&mono);
    let script = Script::new(
        &mono,
        vec![
            vec![None, Some(0), Some(FAR)],
            vec![None, Some(0), Some(FAR)],
            vec![None, Some(0), Some(0)],
        ],
    );
    let driver = tokio::spawn(time.clone().run_roughtime(Arc::clone(&script)));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(time.read(), Ok(T + 1_000));
    assert!(!time.state().bounded());
    tokio::time::sleep(Duration::from_secs(3_600)).await;
    assert!(time.state().bounded());
    tokio::time::sleep(Duration::from_secs(3_600)).await;
    let asked: Vec<(u64, usize)> = script.asked.lock().unwrap().clone();
    let at: Vec<u64> = asked.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        at,
        vec![
            0, 0, 0, 3_600_000, 3_600_000, 3_600_000, 7_200_000, 7_200_000, 7_200_000
        ]
    );
    assert_eq!(asked.iter().filter(|(_, s)| *s == 2).count(), 3);
    driver.abort();
}

// OP-32
#[tokio::test(start_paused = true)]
async fn op_32_the_clock_port_carries_samples_forward_and_stops_without_two_sources() {
    let mono = VirtualMono::new();
    let mut time = LedgerTime::new(2, 3, Arc::clone(&mono)).unwrap();
    let (tx, rx) = mpsc::channel(NTS_EVENT_QUEUE);
    let follower = tokio::spawn(time.clone().follow_nts(rx));
    assert!(time.now().await.is_err());
    for source in 0..2 {
        tx.send(NtsEvent::Sample {
            source,
            sample: NtsSample {
                unix_ms: T,
                mono_ms: 0,
            },
        })
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(64)).await;
    assert_eq!(time.now().await, Ok(T + 64_000));
    tx.send(NtsEvent::Lost { source: 1 }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(time.read(), Err(TimeFault::Nts(TimeError::TooFewSources)));
    let err = time.now().await.unwrap_err();
    assert!(err.0.contains("too few time sources"), "{err}");
    drop(tx);
    follower.await.unwrap();
}
