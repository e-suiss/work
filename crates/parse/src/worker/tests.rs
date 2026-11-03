use std::fmt::Write as _;
use std::io::Cursor;

use super::*;

const FILL36: &str = "Zq8kR2mN4vX7bT1yW9cL3pH6dF0sJ5gA2eUo";

const OVER_PART: usize = 256 * 1024 + 1;

const OVER_HALF: usize = 128 * 1024 + 1;

fn scanner() -> SecretScanner {
    SecretScanner::builtin().unwrap()
}

fn name(s: &str) -> PartName {
    PartName::parse(s).unwrap()
}

fn token() -> String {
    ["ghp_", FILL36].concat()
}

fn request(parts: &[(&str, &[u8])]) -> Vec<u8> {
    frames::scan_request(parts).unwrap()
}

fn refused(code: &str) -> (Status, Vec<u8>) {
    (Status::Refused, code.as_bytes().to_vec())
}

fn scan_kind() -> u8 {
    Kind::Scan.as_byte()
}

// SEC-35 P-95 T-72 T-94
#[test]
fn sec_35_p_95_the_worker_answers_clean_or_the_part_and_rule_of_a_detection_only() {
    let s = scanner();
    let secret = token();
    let title: &[u8] = b"weekly report";
    let clean = request(&[("title", title)]);
    let nothing = (Status::Clean, Vec::new());
    assert_eq!(answer(&s, scan_kind(), &clean), nothing);
    let empty = request(&[]);
    assert_eq!(answer(&s, scan_kind(), &empty), nothing);
    let leaky = request(&[("title", title), ("note", secret.as_bytes())]);
    let (status, payload) = answer(&s, scan_kind(), &leaky);
    assert_eq!(status, Status::Detected);
    let named = frames::parse_detection(&payload);
    assert_eq!(named, Ok(("note", "github-pat")));
    let fill = FILL36.as_bytes();
    assert!(!payload.windows(fill.len()).any(|w| w == fill));
}

// T-72 SEC-18 T-94
#[test]
fn t_72_malformed_or_oversized_requests_are_refused_with_stable_codes() {
    let s = scanner();
    let fine: &[u8] = b"fine";
    let ok = request(&[("note", fine)]);
    for kind in [0_u8, 2, 3, 0x7f, 0xff] {
        assert_eq!(answer(&s, kind, &ok), refused(refusal::KIND), "{kind}");
    }
    let mut trailing = ok.clone();
    trailing.push(0);
    for bad in [
        Vec::new(),
        vec![0],
        ok.split_last().unwrap().1.to_vec(),
        trailing,
        request(&[("Note", fine)]),
        request(&[("note", fine), ("note", fine)]),
    ] {
        let answered = answer(&s, scan_kind(), &bad);
        assert_eq!(answered, refused(refusal::MALFORMED), "{bad:?}");
    }
    let big = vec![b'x'; OVER_PART];
    let one = request(&[("note", big.as_slice())]);
    assert_eq!(answer(&s, scan_kind(), &one), refused(refusal::TOO_LARGE));
    let half = vec![b'x'; OVER_HALF];
    let two = request(&[("a", half.as_slice()), ("b", half.as_slice())]);
    assert_eq!(answer(&s, scan_kind(), &two), refused(refusal::TOO_LARGE));
}

// T-72 T-94
#[test]
fn t_72_the_worker_loop_answers_until_its_input_closes_and_stops_at_an_untrusted_frame() {
    let s = scanner();
    let fine: &[u8] = b"fine";
    let ok = frames::frame(scan_kind(), &request(&[("note", fine)])).unwrap();
    let mut input = ok.clone();
    input.extend(frames::frame(9, b"").unwrap());
    let mut output = Vec::new();
    serve(&s, &mut Cursor::new(input), &mut output).unwrap();
    let mut expected = frames::frame(Status::Clean.as_byte(), b"").unwrap();
    let kind = frames::frame(Status::Refused.as_byte(), refusal::KIND.as_bytes()).unwrap();
    expected.extend(kind);
    assert_eq!(output, expected);

    let frame = frames::frame(Status::Refused.as_byte(), refusal::FRAME.as_bytes()).unwrap();
    for head in [[2_u8, 1, 0, 0, 0, 0], [1, 1, 0xff, 0xff, 0xff, 0xff]] {
        let mut input = head.to_vec();
        input.extend(ok.clone());
        let mut output = Vec::new();
        let served = serve(&s, &mut Cursor::new(input), &mut output);
        assert!(matches!(served, Err(ServeError::Frame(_))), "{served:?}");
        assert_eq!(output, frame);
    }

    let cut = ok.split_last().unwrap().1.to_vec();
    let mut output = Vec::new();
    let served = serve(&s, &mut Cursor::new(cut), &mut output);
    assert!(matches!(served, Err(ServeError::Io(_))), "{served:?}");
    assert_eq!(output, Vec::<u8>::new());
}

// T-72 T-94
#[test]
fn t_72_a_worker_that_does_not_answer_in_time_is_killed_and_not_used_again() {
    let mut command = Command::new("sleep");
    command.arg("30");
    let mut worker = Worker::spawn(&mut command, Duration::from_millis(300)).unwrap();
    let part = name("note");
    let parts = [ScanPart::new(&part, b"fine")];
    let first = worker.scan(&parts);
    assert!(matches!(first, Err(WorkerError::Timeout(_))), "{first:?}");
    let second = worker.scan(&parts);
    assert!(matches!(second, Err(WorkerError::Gone)), "{second:?}");
}

fn answering(request_len: usize, answer: &[u8]) -> Worker {
    let mut escaped = String::new();
    for b in answer {
        write!(escaped, "\\{b:03o}").unwrap();
    }
    let wait = format!("head -c {request_len} >/dev/null");
    let script = format!("{wait}; printf '{escaped}'; exec cat >/dev/null");
    let mut command = Command::new("sh");
    command.arg("-c").arg(script);
    Worker::spawn(&mut command, Duration::from_secs(10)).unwrap()
}

// T-72 P-95 T-94
#[test]
fn t_72_an_answer_that_does_not_belong_to_the_request_retires_the_worker() {
    let part = name("note");
    let parts = [ScanPart::new(&part, b"fine")];
    let fine: &[u8] = b"fine";
    let len = frames::frame(scan_kind(), &request(&[("note", fine)]))
        .unwrap()
        .len();
    let frame = |status: u8, payload: &[u8]| frames::frame(status, payload).unwrap();
    let detected = Status::Detected.as_byte();
    let foreign = [
        frame(detected, &frames::detection("title", "github-pat").unwrap()),
        frame(detected, &frames::detection("note", "github pat").unwrap()),
        frame(Status::Clean.as_byte(), b"x"),
        frame(Status::Refused.as_byte(), b"parser-unknown"),
        frame(7, b""),
        vec![2, 0, 0, 0, 0, 0],
    ];
    for answer in foreign {
        let mut worker = answering(len, &answer);
        let first = worker.scan(&parts);
        assert!(matches!(first, Err(WorkerError::Answer)), "{first:?}");
        assert!(matches!(worker.scan(&parts), Err(WorkerError::Gone)));
    }

    let mut worker = answering(len, &frame(detected, b"\x04notegithub-pat"));
    let outcome = worker.scan(&parts).unwrap();
    assert_eq!(outcome.reason_code(), Some("secret_detected"));
    let shown = format!("{outcome}");
    assert_eq!(shown, "secret_detected (rule github-pat, part note)");
    let too_large = frame(Status::Refused.as_byte(), refusal::TOO_LARGE.as_bytes());
    let mut worker = answering(len, &too_large);
    let refused = worker.scan(&parts);
    assert!(
        matches!(refused, Err(WorkerError::Refused(refusal::TOO_LARGE))),
        "{refused:?}"
    );
}

// SEC-35 P-95 T-94
#[test]
fn sec_35_p_95_the_in_process_scan_answers_as_a_worker_does() {
    let s = scanner();
    let secret = token();
    let title: &[u8] = b"weekly report";
    assert_eq!(Scan::scan(&s, &[("title", title)]), Ok(Verdict::Clean));
    assert_eq!(Scan::scan(&s, &[]), Ok(Verdict::Clean));
    let found = Scan::scan(&s, &[("title", title), ("note", secret.as_bytes())]);
    assert_eq!(
        found,
        Ok(Verdict::Detected {
            part: "note".to_owned(),
            rule: "github-pat".to_owned(),
        })
    );
    assert!(!format!("{found:?}").contains(FILL36));
    let malformed = Err(ScanFailure::Refused(refusal::MALFORMED));
    let twice = Scan::scan(&s, &[("note", title), ("note", title)]);
    assert_eq!(twice, malformed);
    assert_eq!(Scan::scan(&s, &[("Not A Name", title)]), malformed);
    let over = vec![b'a'; OVER_PART];
    let too_large = Err(ScanFailure::Refused(refusal::TOO_LARGE));
    assert_eq!(Scan::scan(&s, &[("note", over.as_slice())]), too_large);
}

fn answers(request_len: usize, answers: &[Vec<u8>]) -> Command {
    let mut script = String::new();
    for answer in answers {
        let mut escaped = String::new();
        for b in answer {
            write!(escaped, "\\{b:03o}").unwrap();
        }
        write!(script, "head -c {request_len} >/dev/null; printf '{escaped}'; ").unwrap();
    }
    script.push_str("exec cat >/dev/null");
    let mut command = Command::new("sh");
    command.arg("-c").arg(script);
    command
}

// T-94 T-72 SEC-35
#[test]
fn t_94_a_pool_keeps_a_worker_that_answered_and_retires_one_that_failed() {
    let fine: &[u8] = b"fine";
    let len = frames::frame(scan_kind(), &request(&[("note", fine)]))
        .unwrap()
        .len();
    let frame = |status: u8, payload: &[u8]| frames::frame(status, payload).unwrap();
    let clean = frame(Status::Clean.as_byte(), b"");
    let too_large = frame(Status::Refused.as_byte(), refusal::TOO_LARGE.as_bytes());
    let mut commands = [answers(len, &[clean, too_large])].into_iter();
    let pool = Pool::spawn(1, || commands.next().unwrap(), Duration::from_secs(2)).unwrap();
    assert_eq!(pool.live(), 1);
    assert_eq!(pool.scan(&[("note", fine)]), Ok(Verdict::Clean));
    assert_eq!(
        pool.scan(&[("note", fine)]),
        Err(ScanFailure::Refused(refusal::TOO_LARGE))
    );
    assert_eq!(pool.live(), 1);
    assert_eq!(pool.scan(&[("note", fine)]), Err(ScanFailure::Unavailable));
    assert_eq!(pool.live(), 0);
    assert_eq!(pool.scan(&[("note", fine)]), Err(ScanFailure::Unavailable));
    assert_eq!(
        pool.scan(&[("note", fine), ("note", fine)]),
        Err(ScanFailure::Refused(refusal::MALFORMED))
    );
}

// T-94 T-72
#[test]
fn t_94_a_pool_that_cannot_start_a_worker_does_not_start() {
    let started = Pool::spawn(
        2,
        || Command::new("/nonexistent/work-server"),
        Duration::from_secs(1),
    );
    assert!(matches!(started, Err(WorkerError::Spawn(_))), "{started:?}");
    let mut sleeper = Command::new("sleep");
    sleeper.arg("30");
    let mut commands = [sleeper].into_iter();
    let pool = Pool::spawn(1, || commands.next().unwrap(), Duration::from_millis(300)).unwrap();
    let fine: &[u8] = b"fine";
    assert_eq!(pool.scan(&[("note", fine)]), Err(ScanFailure::Unavailable));
    assert_eq!(pool.live(), 0);
}
