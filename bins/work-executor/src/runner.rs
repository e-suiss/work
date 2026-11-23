//! The executor's loop (T-105 item 1, RC-36, RC-39, RC-42, RC-43): it pulls the deliveries addressed to it, long-polling and woken early by the content-free doorbell, and runs one job per commitment it is given: the capability declaration, an open session, automatic control mode and a running status first, then the step script with heartbeats at the declared interval, each request answered as the capability and the configuration decide, a stop applied now or after a non-cancellable step, a pause or a takeover holding the script still and a return of control writing the handover note. Every refusal by Access or Work is logged with its exact problem and the loop goes on.

use std::collections::BTreeMap;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value as Json;
use suiss_crypto::dcbor::Value;
use suiss_crypto::digest::sha256;
use tokio::sync::{Notify, mpsc};
use tokio::time::{MissedTickBehavior, interval, sleep};
use work_access_client::ports::Clock as _;
use work_kernel::catalog::{ClaimSubtype, DeclarationSubtype, StopAnswer};
use work_kernel::control::body::{
    AttemptOutcome, CommitmentDelivery, ControlMode, ExecutionState, ProgressReport,
    RequestDelivery, RequestKind,
};
use work_kernel::control::executor::{
    CAPABILITY_EXT_KEY, CONTROL_MODE_EXT_KEY, HEARTBEAT_EXT_KEY, REPORT_EXT_KEY, SESSION_EXT_KEY,
    STATUS_EXT_KEY, report_record,
};
use work_kernel::id::LedgerId;
use work_kernel::record::Kind;
use work_proto::id::ExternalId as _;

use crate::access::{Identity, Refusal, Work, Write, problem};
use crate::clock::{Os, Wall};
use crate::config::Config;
use crate::protocol::{self, Decision, Delivered, Effect, Pulled};
use crate::record::{Draft, Part, Shape, sign};
use crate::script::{Next, Run, Step};

/// What every task of the executor shares.
#[derive(Debug)]
pub(crate) struct Shared {
    /// The configuration.
    pub(crate) config: Config,
    /// Who the executor is.
    pub(crate) identity: Identity,
    /// Work's API.
    pub(crate) work: Work,
}

/// The longest pause between two failed pulls.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// One contract element to write.
struct Element<'a> {
    name: &'static str,
    shape: Shape,
    action: &'static str,
    body: Vec<u8>,
    basis: Vec<[u8; 32]>,
    note: Option<&'a str>,
}

impl Shared {
    fn path(&self, commitment: &str) -> String {
        format!(
            "/v1/ledgers/{}/commitments/{commitment}",
            self.work.ledger()
        )
    }

    /// Writes one element for `commitment`; a refusal is logged and the executor goes on.
    async fn write(&self, commitment: &str, element: Element<'_>) -> Option<String> {
        let Some(author) = self.identity.party() else {
            Refusal::Local("party_unknown").log("record", element.name, commitment);
            return None;
        };
        let Ok(ledger) = LedgerId::parse_external(self.work.ledger()) else {
            Refusal::Local("ledger").log("record", element.name, commitment);
            return None;
        };
        let build = |receipt: &[u8; 32]| -> Result<(Vec<u8>, Vec<Json>), String> {
            let mut parts = vec![Part::contract(
                element.body.clone(),
                Os.bytes().map_err(|e| e.to_string())?,
            )];
            if let Some(reason) = element.note {
                parts.push(Part::note(reason, Os.bytes().map_err(|e| e.to_string())?));
            }
            let draft = Draft {
                shape: element.shape.clone(),
                author: author.clone(),
                ledger: *ledger.0.as_bytes(),
                occurred_at: Wall.now_ms(),
                receipt: *receipt,
                basis: element.basis.clone(),
                parts,
            };
            let record = draft.encode().map_err(|e| e.to_string())?;
            let signed = sign(self.identity.service(), &record).map_err(|e| e.to_string())?;
            Ok((signed, draft.parts.iter().map(Part::opening).collect()))
        };
        let write = Write {
            path: format!("{}/executor/{}", self.path(commitment), element.name),
            action: element.action,
            declaration: sha256(&element.body),
            record: &build,
            version_of: Some(self.path(commitment)),
        };
        match self.work.write(&self.identity, &write).await {
            Ok(record) => {
                tracing::info!(
                    event = "executor.written",
                    element = element.name,
                    commitment,
                    record = record.as_str(),
                    "written"
                );
                Some(record)
            }
            Err(refusal) => {
                refusal.log("write", element.name, commitment);
                None
            }
        }
    }

    async fn claim(
        &self,
        commitment: &str,
        name: &'static str,
        key: &'static str,
        body: Result<Vec<u8>, work_kernel::control::body::ControlBodyError>,
        basis: [u8; 32],
    ) {
        let Ok(body) = body else {
            Refusal::Local("body").log("record", name, commitment);
            return;
        };
        let element = Element {
            name,
            shape: Shape::Claim(ClaimSubtype::Observation, Some(key)),
            action: "write",
            body,
            basis: vec![basis],
            note: None,
        };
        self.write(commitment, element).await;
    }

    async fn report(&self, commitment: &str, report: &ProgressReport, basis: [u8; 32]) {
        let Ok(body) = report.encode() else {
            Refusal::Local("body").log("record", "reports", commitment);
            return;
        };
        let shape = match report_record(report.event) {
            (Kind::Act, _) => Shape::Act(REPORT_EXT_KEY),
            (_, subtype) => Shape::Claim(
                subtype.unwrap_or(ClaimSubtype::Observation),
                Some(REPORT_EXT_KEY),
            ),
        };
        let element = Element {
            name: "reports",
            shape,
            action: "write",
            body,
            basis: vec![basis],
            note: None,
        };
        self.write(commitment, element).await;
    }

    /// Answers `request` for `commitment` (RC-36, RC-42): a stop with a `stop_response`
    /// Declaration citing it, a refusal with its reason in `note`; any other request with an
    /// `observation` Claim of the response citing it.
    async fn respond(&self, commitment: &str, request: &RequestDelivery, decision: &Decision) {
        let Ok(body) = decision.response.encode() else {
            Refusal::Local("body").log("record", "responses", commitment);
            return;
        };
        let (shape, action) = if request.kind == RequestKind::Stop {
            (
                Shape::Declaration(
                    DeclarationSubtype::StopResponse,
                    vec![(
                        "response",
                        Value::text(decision.response.answer.wire_name()),
                    )],
                ),
                "stop_respond",
            )
        } else {
            (Shape::Claim(ClaimSubtype::Observation, None), "write")
        };
        let element = Element {
            name: "responses",
            shape,
            action,
            body,
            basis: vec![*request.record.as_bytes()],
            note: decision.response.reason.as_deref(),
        };
        tracing::info!(
            event = "executor.answered",
            commitment,
            request = request.kind.wire_name(),
            answer = decision.response.answer.wire_name(),
            "request answered"
        );
        self.write(commitment, element).await;
    }
}

/// A job's view of one commitment.
struct Job {
    shared: Arc<Shared>,
    commitment: String,
    delivery: CommitmentDelivery,
    session: String,
    attempt: u32,
    beat: u64,
    run: Run,
    requests: mpsc::Receiver<RequestDelivery>,
}

/// Where a job stands between steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    Running,
    Paused,
    Driven,
}

/// What ends a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Completed,
    Failed,
    Stopped,
}

impl Job {
    fn version(&self) -> [u8; 32] {
        *self.delivery.version.as_bytes()
    }

    async fn status(&self, state: ExecutionState, need: &str) {
        let script = &self.shared.config.script;
        let body = protocol::status(state, &self.run.done(), need, self.run.current(script));
        self.shared
            .claim(
                &self.commitment,
                "status",
                STATUS_EXT_KEY,
                body.encode(),
                self.version(),
            )
            .await;
    }

    async fn mode(&self, mode: ControlMode, lease: Option<work_kernel::id::Digest>) {
        let body = protocol::control_mode(mode, lease);
        self.shared
            .claim(
                &self.commitment,
                "control-mode",
                CONTROL_MODE_EXT_KEY,
                body.encode(),
                self.version(),
            )
            .await;
    }

    async fn heartbeat(&mut self, departing: bool) {
        self.beat = self.beat.saturating_add(1);
        let body = protocol::heartbeat(&self.session, self.beat, departing);
        self.shared
            .claim(
                &self.commitment,
                "heartbeat",
                HEARTBEAT_EXT_KEY,
                body.encode(),
                self.version(),
            )
            .await;
    }

    async fn session(&self, outcome: Option<(AttemptOutcome, Option<&str>)>) {
        let body = protocol::session(
            &self.session,
            self.delivery.commitment,
            self.attempt,
            outcome,
        );
        self.shared
            .claim(
                &self.commitment,
                "session",
                SESSION_EXT_KEY,
                body.encode(),
                self.version(),
            )
            .await;
    }

    async fn start(&self) {
        let capability = self.shared.config.capability.encode();
        self.shared
            .claim(
                &self.commitment,
                "capability",
                CAPABILITY_EXT_KEY,
                capability,
                self.version(),
            )
            .await;
        self.session(None).await;
        self.mode(ControlMode::Automatic, None).await;
        self.status(ExecutionState::Running, "").await;
    }

    async fn end(&mut self, end: End, reason: Option<&str>) {
        match end {
            End::Completed => {
                self.status(ExecutionState::Completed, "").await;
                self.session(Some((AttemptOutcome::Succeeded, None))).await;
            }
            End::Failed => {
                self.status(ExecutionState::Failed, reason.unwrap_or_default())
                    .await;
                self.session(Some((AttemptOutcome::Failed, reason))).await;
            }
            End::Stopped => {
                self.status(ExecutionState::Stopped, "").await;
                self.session(Some((
                    AttemptOutcome::Abandoned,
                    Some(reason.unwrap_or("stopped on request")),
                )))
                .await;
            }
        }
        self.heartbeat(true).await;
        tracing::info!(event = "executor.job_ended", commitment = self.commitment.as_str(), end = ?end, "job ended");
    }

    /// Answers one request and gives back what follows from it.
    async fn answer(&self, request: &RequestDelivery) -> Effect {
        let config = &self.shared.config;
        let decision = protocol::decide(
            request,
            &config.capability,
            &config.responses,
            self.run.current(&config.script),
        );
        self.shared
            .respond(&self.commitment, request, &decision)
            .await;
        if decision.response.answer == StopAnswer::Refuse {
            return Effect::Nothing;
        }
        decision.effect
    }

    /// Applies `effect` while the job holds still or between steps; `true` ends the job.
    async fn apply(&mut self, effect: Effect, request: &RequestDelivery, hold: &mut Hold) -> bool {
        match effect {
            Effect::Stop | Effect::StopAfterStep => true,
            Effect::Pause => {
                *hold = Hold::Paused;
                self.status(ExecutionState::Paused, "a resume").await;
                false
            }
            Effect::Resume if *hold == Hold::Paused => {
                *hold = Hold::Running;
                self.status(ExecutionState::Running, "").await;
                false
            }
            Effect::TakeOver => {
                *hold = Hold::Driven;
                self.mode(ControlMode::Manual, Some(request.record)).await;
                self.status(
                    ExecutionState::Paused,
                    "control back from the second driver",
                )
                .await;
                false
            }
            Effect::ReturnControl => {
                self.handover(request).await;
                *hold = Hold::Running;
                self.mode(ControlMode::Automatic, None).await;
                self.status(ExecutionState::Running, "").await;
                false
            }
            Effect::Resume | Effect::Nothing => false,
        }
    }

    async fn handover(&self, request: &RequestDelivery) {
        let script = &self.shared.config.script;
        let next = self.run.current(script).unwrap_or_default();
        let Ok(body) = protocol::handover(&self.delivery, &self.run.done(), next).encode() else {
            return;
        };
        let element = Element {
            name: "handover",
            shape: Shape::Declaration(
                DeclarationSubtype::HandoffNote,
                vec![
                    ("handover_reason", Value::text("control_transfer")),
                    ("stateful", Value::Bool(true)),
                ],
            ),
            action: "control",
            body,
            basis: vec![*request.record.as_bytes()],
            note: None,
        };
        self.shared.write(&self.commitment, element).await;
    }

    /// Holds still until a request lets the job go on, keeping its heartbeats; `true` ends it.
    async fn hold(&mut self, hold: &mut Hold, beat: &mut tokio::time::Interval) -> bool {
        while *hold != Hold::Running {
            tokio::select! {
                request = self.requests.recv() => {
                    let Some(request) = request else { return true };
                    let effect = self.answer(&request).await;
                    if self.apply(effect, &request, hold).await {
                        return true;
                    }
                }
                _ = beat.tick() => self.heartbeat(false).await,
            }
        }
        false
    }

    /// Runs `wait` milliseconds, answering requests and beating meanwhile; gives back a stop
    /// that cuts the wait short, or the effect to apply once it ends.
    async fn wait(
        &mut self,
        ms: u64,
        beat: &mut tokio::time::Interval,
        pending: &mut Vec<(Effect, RequestDelivery)>,
    ) -> bool {
        let mut done = pin!(sleep(Duration::from_millis(ms)));
        loop {
            tokio::select! {
                () = &mut done => return false,
                _ = beat.tick() => self.heartbeat(false).await,
                request = self.requests.recv() => {
                    let Some(request) = request else { return true };
                    match self.answer(&request).await {
                        Effect::Stop => return true,
                        Effect::Nothing => {}
                        effect => pending.push((effect, request)),
                    }
                }
            }
        }
    }

    /// Goes silent: no heartbeat and no answer from now on (T-105 item 1).
    async fn silent(&mut self) {
        tracing::info!(
            event = "executor.silent",
            commitment = self.commitment.as_str(),
            "silent: no heartbeat and no answer from now on"
        );
        while let Some(request) = self.requests.recv().await {
            tracing::info!(
                event = "executor.unanswered",
                commitment = self.commitment.as_str(),
                request = request.kind.wire_name(),
                "silent: request left unanswered"
            );
        }
    }

    async fn run(mut self) {
        self.start().await;
        let mut beat = interval(Duration::from_millis(
            self.shared.config.executor.heartbeat_ms,
        ));
        beat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut hold = Hold::Running;
        let shared = Arc::clone(&self.shared);
        let script = &shared.config.script;
        loop {
            if self.hold(&mut hold, &mut beat).await {
                return self.end(End::Stopped, None).await;
            }
            let Next::Step(step) = self.run.next(script) else {
                return self.end(End::Completed, None).await;
            };
            self.status(ExecutionState::Running, "").await;
            let mut pending: Vec<(Effect, RequestDelivery)> = Vec::new();
            match &step.step {
                Step::Wait(ms) => {
                    if self.wait(*ms, &mut beat, &mut pending).await {
                        return self.end(End::Stopped, None).await;
                    }
                }
                Step::Write(summary) => {
                    let report = protocol::action_report(
                        &self.delivery,
                        &self.session,
                        summary,
                        shared.config.executor.external_idempotent,
                    );
                    self.shared
                        .report(&self.commitment, &report, self.version())
                        .await;
                }
                Step::Fail(reason) => {
                    let report = protocol::error_report(&self.session, reason);
                    self.shared
                        .report(&self.commitment, &report, self.version())
                        .await;
                    return self.end(End::Failed, Some(reason)).await;
                }
                Step::Silent => return self.silent().await,
            }
            self.run.advance(script);
            while let Ok(request) = self.requests.try_recv() {
                let effect = self.answer(&request).await;
                pending.push((effect, request));
            }
            for (effect, request) in pending {
                if self.apply(effect, &request, &mut hold).await {
                    return self.end(End::Stopped, None).await;
                }
            }
        }
    }
}

/// The pull loop: it never ends on a refusal.
pub(crate) async fn run(shared: &Arc<Shared>, doorbell: &Notify) {
    let mut cursor = "0".to_owned();
    let mut backoff = Duration::from_secs(1);
    let mut jobs: BTreeMap<String, mpsc::Sender<RequestDelivery>> = BTreeMap::new();
    let wait_s = shared.config.executor.wait_s;
    loop {
        if shared.identity.party().is_none()
            && let Some(tenant) = shared.identity.tenant()
        {
            match shared.identity.pair(tenant).await {
                Ok(()) => tracing::info!(
                    event = "executor.paired",
                    party = shared.identity.party().unwrap_or_default().as_str(),
                    "the executor's product is paired"
                ),
                Err(refusal) => refusal.log("pairing", "pairing", ""),
            }
        }
        let path = format!(
            "/v1/ledgers/{}/executor/deliveries?after={cursor}&wait={wait_s}",
            shared.work.ledger()
        );
        let bound = Duration::from_secs(wait_s.saturating_add(15));
        let pulled = match shared
            .work
            .call(&shared.identity, "GET", &path, &[], None, bound)
            .await
        {
            Ok(answer) if answer.status == 200 => serde_json::from_slice::<Pulled>(&answer.body)
                .map_err(|_| Refusal::Local("deliveries")),
            Ok(answer) => Err(problem(&answer)),
            Err(refusal) => Err(refusal),
        };
        match pulled {
            Ok(pulled) => {
                backoff = Duration::from_secs(1);
                let empty = pulled.deliveries.is_empty();
                for wire in &pulled.deliveries {
                    dispatch(shared, &mut jobs, wire);
                }
                cursor = pulled.cursor;
                if empty && wait_s == 0 {
                    tokio::select! {
                        () = doorbell.notified() => {}
                        () = sleep(Duration::from_secs(1)) => {}
                    }
                }
            }
            Err(refusal) => {
                refusal.log("pull", "deliveries", "");
                tokio::select! {
                    () = doorbell.notified() => {}
                    () = sleep(backoff) => {}
                }
                backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
            }
        }
    }
}

fn dispatch(
    shared: &Arc<Shared>,
    jobs: &mut BTreeMap<String, mpsc::Sender<RequestDelivery>>,
    wire: &protocol::Wire,
) {
    let delivery = match wire.decode() {
        Ok(d) => d,
        Err(error) => {
            tracing::warn!(
                event = "executor.delivery_unread",
                seq = wire.seq.as_str(),
                record = wire.record.as_str(),
                %error,
                "a delivery the kernel decoder refuses"
            );
            return;
        }
    };
    tracing::info!(
        event = "executor.delivered",
        seq = delivery.seq,
        commitment = delivery.commitment.as_str(),
        record = wire.record.as_str(),
        "delivery"
    );
    jobs.retain(|_, sender| !sender.is_closed());
    match delivery.what {
        Delivered::Commitment(given) => {
            if jobs.contains_key(&delivery.commitment) {
                tracing::info!(
                    event = "executor.already_running",
                    commitment = delivery.commitment.as_str(),
                    "a job runs for the commitment already"
                );
                return;
            }
            let (sender, requests) = mpsc::channel(16);
            jobs.insert(delivery.commitment.clone(), sender);
            let session = protocol::session_ref(
                &shared.config.executor.session_prefix,
                &delivery.commitment,
                1,
            );
            let job = Job {
                shared: Arc::clone(shared),
                commitment: delivery.commitment,
                delivery: given,
                session,
                attempt: 1,
                beat: 0,
                run: Run::new(),
                requests,
            };
            tokio::spawn(job.run());
        }
        Delivered::Request(request) => match jobs.get(&delivery.commitment) {
            Some(sender) => {
                if let Err(error) = sender.try_send(request) {
                    tracing::warn!(
                        event = "executor.request_dropped",
                        commitment = delivery.commitment.as_str(),
                        %error,
                        "the job takes no more requests"
                    );
                }
            }
            None => {
                let shared = Arc::clone(shared);
                let commitment = delivery.commitment;
                tokio::spawn(async move {
                    let config = &shared.config;
                    let decision =
                        protocol::decide(&request, &config.capability, &config.responses, None);
                    shared.respond(&commitment, &request, &decision).await;
                });
            }
        },
    }
}
