//! The parser worker's request loop and the server's handle on a worker process (T-72, SEC-35, P-95, SEC-18): the worker reads `work_proto::parser` frames from its standard input, scans the decoded body parts of each scan request with the built-in rule set and answers on its standard output with clean, the part and rule id of a detection, or a stable refusal code; a frame it cannot trust ends the loop. The handle starts the worker process, bounds every exchange by a deadline after which it kills the process, checks every answer against the request and never uses a worker again once an exchange failed. The worker process locks itself down at its entry point; this crate does not (T-72 rule 2).

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::Duration;

use work_kernel::record::PartName;
use work_proto::parser::{self as frames, FrameError, Kind, Status, refusal};

use crate::secret::{RuleId, ScanError, ScanOutcome, ScanPart, SecretScanner};

/// The answer to a request of kind byte `kind` with `payload`.
#[must_use]
pub fn answer(scanner: &SecretScanner, kind: u8, payload: &[u8]) -> (Status, Vec<u8>) {
    let answered = match Kind::from_byte(kind) {
        Some(Kind::Scan) => scan(scanner, payload).and_then(|outcome| encode(&outcome)),
        None => Err(refusal::KIND),
    };
    answered.unwrap_or_else(|code| (Status::Refused, code.as_bytes().to_vec()))
}

fn encode(outcome: &ScanOutcome) -> Result<(Status, Vec<u8>), &'static str> {
    match outcome {
        ScanOutcome::Clean => Ok((Status::Clean, Vec::new())),
        ScanOutcome::Detected { rule_id, part } => {
            let detection = frames::detection(part.as_str(), rule_id.as_str());
            detection
                .map(|d| (Status::Detected, d))
                .map_err(|_| refusal::MALFORMED)
        }
    }
}

fn parts(payload: &[u8]) -> Result<Vec<(PartName, &[u8])>, &'static str> {
    let raw = frames::scan_parts(payload).map_err(|_| refusal::MALFORMED)?;
    let mut parts: Vec<(PartName, &[u8])> = Vec::with_capacity(raw.len());
    for (name, content) in raw {
        let name = PartName::parse(name).ok_or(refusal::MALFORMED)?;
        if parts.iter().any(|(seen, _)| *seen == name) {
            return Err(refusal::MALFORMED);
        }
        parts.push((name, content));
    }
    Ok(parts)
}

fn scan(scanner: &SecretScanner, payload: &[u8]) -> Result<ScanOutcome, &'static str> {
    let parts = parts(payload)?;
    let views: Vec<ScanPart<'_>> = parts
        .iter()
        .map(|(name, content)| ScanPart::new(name, content))
        .collect();
    scanner.scan(&views).map_err(|e| match e {
        ScanError::PartTooLarge { .. } | ScanError::TotalTooLarge { .. } => refusal::TOO_LARGE,
    })
}

/// Why the request loop stopped before its input closed.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Reading or writing a pipe failed.
    #[error("pipe: {0}")]
    Io(#[from] std::io::Error),
    /// A frame header the worker cannot trust; it was refused with `parser-frame`.
    #[error("frame refused: {0}")]
    Frame(FrameError),
}

fn write_answer<W: Write>(output: &mut W, status: Status, payload: &[u8]) -> std::io::Result<()> {
    let frame = frames::frame(status.as_byte(), payload).map_err(std::io::Error::other)?;
    output.write_all(&frame)?;
    output.flush()
}

/// Answers the requests on `input` until it closes.
///
/// # Errors
/// [`ServeError::Frame`] after a frame of another version or over the payload ceiling, which is
/// answered with `parser-frame` first; [`ServeError::Io`] when a pipe fails or a payload is cut
/// short.
pub fn serve<R: Read, W: Write>(
    scanner: &SecretScanner,
    input: &mut R,
    output: &mut W,
) -> Result<(), ServeError> {
    loop {
        let mut head = [0_u8; frames::HEADER];
        match input.read_exact(&mut head) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(ServeError::Io(e)),
        }
        let header = match frames::header(head) {
            Ok(header) => header,
            Err(e) => {
                write_answer(output, Status::Refused, refusal::FRAME.as_bytes())?;
                return Err(ServeError::Frame(e));
            }
        };
        let mut payload = vec![0_u8; header.len];
        input.read_exact(&mut payload)?;
        let (status, answer) = answer(scanner, header.code, &payload);
        write_answer(output, status, &answer)?;
    }
}

/// Why an exchange with a worker failed.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// The worker process could not be started.
    #[error("starting the parser worker: {0}")]
    Spawn(std::io::Error),
    /// The worker process has no piped standard input or output.
    #[error("the parser worker has no pipes")]
    Pipes,
    /// A pipe to the worker failed or the worker closed it.
    #[error("parser worker pipe: {0}")]
    Io(std::io::Error),
    /// The request does not fit a frame.
    #[error("request: {0}")]
    Request(FrameError),
    /// The worker did not answer within the deadline and was killed.
    #[error("the parser worker did not answer within {0:?}")]
    Timeout(Duration),
    /// The worker sent an answer that does not belong to the request.
    #[error("the answer does not belong to the request")]
    Answer,
    /// The worker refused the request with a stable code.
    #[error("the parser worker refused the request: {0}")]
    Refused(&'static str),
    /// An earlier exchange failed; the worker is not used again.
    #[error("the parser worker is no longer used")]
    Gone,
}

/// A running parser worker process and its pipes.
#[derive(Debug)]
pub struct Worker {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    timeout: Duration,
    gone: bool,
}

fn exchange(
    stdin: &mut ChildStdin,
    stdout: &mut ChildStdout,
    request: &[u8],
) -> Result<(Status, Vec<u8>), WorkerError> {
    stdin.write_all(request).map_err(WorkerError::Io)?;
    stdin.flush().map_err(WorkerError::Io)?;
    let mut head = [0_u8; frames::HEADER];
    stdout.read_exact(&mut head).map_err(WorkerError::Io)?;
    let header = frames::header(head).map_err(|_| WorkerError::Answer)?;
    let status = Status::from_byte(header.code).ok_or(WorkerError::Answer)?;
    let mut answer = vec![0_u8; header.len];
    stdout.read_exact(&mut answer).map_err(WorkerError::Io)?;
    Ok((status, answer))
}

impl Worker {
    /// Starts `command` with piped standard input and output as a parser worker whose every
    /// exchange must end within `timeout`. A server starts its workers before it locks itself
    /// down, because no lockdown profile may create processes (T-72).
    ///
    /// # Errors
    /// [`WorkerError::Spawn`] or [`WorkerError::Pipes`].
    pub fn spawn(command: &mut Command, timeout: Duration) -> Result<Self, WorkerError> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(WorkerError::Spawn)?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WorkerError::Pipes);
        };
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout,
            timeout,
            gone: false,
        })
    }

    /// The process id of the started command.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Sends one request frame and reads its answer within the deadline; on a failed exchange
    /// the worker is killed and not used again.
    ///
    /// # Errors
    /// [`WorkerError::Request`], [`WorkerError::Io`], [`WorkerError::Timeout`],
    /// [`WorkerError::Answer`] or [`WorkerError::Gone`].
    pub fn request(&mut self, kind: u8, payload: &[u8]) -> Result<(Status, Vec<u8>), WorkerError> {
        let request = frames::frame(kind, payload).map_err(WorkerError::Request)?;
        if self.gone {
            return Err(WorkerError::Gone);
        }
        let Self {
            child,
            stdin,
            stdout,
            timeout,
            gone,
        } = self;
        let Some(stdin) = stdin.as_mut() else {
            return Err(WorkerError::Gone);
        };
        let (sender, receiver) = sync_channel(1);
        let result = std::thread::scope(|scope| {
            let _exchange = scope.spawn(move || {
                let _ = sender.send(exchange(stdin, stdout, &request));
            });
            match receiver.recv_timeout(*timeout) {
                Ok(result) => result,
                Err(RecvTimeoutError::Timeout) => {
                    let _ = child.kill();
                    Err(WorkerError::Timeout(*timeout))
                }
                Err(RecvTimeoutError::Disconnected) => Err(WorkerError::Gone),
            }
        });
        if result.is_err() {
            *gone = true;
            let _ = child.kill();
        }
        result
    }

    /// Scans `parts` in the worker (SEC-35): clean, or the rule id and the name of a part of
    /// this request (P-95).
    ///
    /// # Errors
    /// [`WorkerError::Refused`] with the worker's code, [`WorkerError::Answer`] for an answer
    /// that does not belong to the request, and the errors of [`Worker::request`].
    pub fn scan(&mut self, parts: &[ScanPart<'_>]) -> Result<ScanOutcome, WorkerError> {
        let raw: Vec<(&str, &[u8])> = parts
            .iter()
            .map(|p| (p.name().as_str(), p.content()))
            .collect();
        let payload = frames::scan_request(&raw).map_err(WorkerError::Request)?;
        let (status, answer) = self.request(Kind::Scan.as_byte(), &payload)?;
        let outcome = match status {
            Status::Clean if answer.is_empty() => Ok(ScanOutcome::Clean),
            Status::Detected => detected(parts, &answer),
            Status::Refused => Err(refused(&answer)),
            Status::Clean => Err(WorkerError::Answer),
        };
        if matches!(outcome, Err(WorkerError::Answer)) {
            self.gone = true;
            let _ = self.child.kill();
        }
        outcome
    }
}

fn refused(answer: &[u8]) -> WorkerError {
    refusal::ALL
        .into_iter()
        .find(|code| code.as_bytes() == answer)
        .map_or(WorkerError::Answer, WorkerError::Refused)
}

fn detected(parts: &[ScanPart<'_>], answer: &[u8]) -> Result<ScanOutcome, WorkerError> {
    let (part, rule) = frames::parse_detection(answer).map_err(|_| WorkerError::Answer)?;
    let part = parts
        .iter()
        .map(ScanPart::name)
        .find(|name| name.as_str() == part)
        .ok_or(WorkerError::Answer)?;
    let rule_id = RuleId::from_worker(rule).ok_or(WorkerError::Answer)?;
    Ok(ScanOutcome::Detected {
        rule_id,
        part: part.clone(),
    })
}

impl Drop for Worker {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests;
