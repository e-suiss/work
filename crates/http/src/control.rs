//! The control family of the REST API (RC-3, RC-8, RC-26 … RC-43, E-45, C-6, P-54 items 4 and 5, WD-149): one typed write per control record a caller writes on a commitment, `POST /v1/ledgers/{ledger}/commitments/{commitment}/<control record>`, each taking the signed record of exactly that kind, which names the commitment by citing its `request` in `basis`, with its Access evidence, one `Idempotency-Key` and the `If-Match` of the version of the first Work it concerns (an operator correction continues the commitment and names the commitment's version), and naming its Access action; the principal's autonomy policy is written at `POST /v1/ledgers/{ledger}/autonomy-policies`. The kernel checks every control record against the executor's capability declaration, its control mode, the commitment's control leases and stop requests before anything is written, and a refused one is answered `422 record_rejected` with the reason `["control", code]` and kept under its key. The control of a commitment is answered inside its read; nothing of it is stored.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, post};
use axum::{Extension, Router};
use serde::Serialize;
use utoipa::ToSchema;
use work_kernel::catalog::DeclarationSubtype;
use work_kernel::commitment::Operation;
use work_kernel::control::axis::{Axes, Request};
use work_kernel::control::stop::{StopTiming, StopView};
use work_kernel::id::{LedgerId, RecordId, Time};
use work_kernel::responsibility::LeaseStatus;
use work_proto::id::ExternalId as _;
use work_query::domain::control::{ControlRead, MoveAutonomy};
use work_query::domain::kinds::FORCED_STOP_EXT_KEY;
use work_query::domain::writes::{Expected, Form, Kind};

use crate::commitments::{Typed, write};
use crate::common::RequestContext;
use crate::json::rfc3339_millis;
use crate::problem::{Problem, ProblemCode};
use crate::reads::{ApiServices, caller_of};
use crate::writes::{created, declaration_request, write_problem};

fn time(t: Time) -> String {
    rfc3339_millis(i64::try_from(t.0).unwrap_or(i64::MAX)).unwrap_or_default()
}

fn rec(id: &RecordId) -> String {
    id.to_external()
}

/// A control request Work offers or a move asks (RC-3, RC-42).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlRequestAnswer {
    /// `start`, `stop`, `resume`, `takeover`, `return_control`, `change` or `budget_exhausted`.
    pub kind: String,
    /// The stop type of a `stop`: `immediate`, `finish_then_stop` or `pause`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_type: Option<String>,
    /// The change policy of a `change`: `interrupt` or `rollback`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_policy: Option<String>,
}

/// The autonomy of one move the caller may make (RC-27, RC-28, RC-49).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlMoveAnswer {
    /// The Access action it asks for, `work:<action>`.
    pub action: String,
    /// The commitment operation's wire name, for a commitment move.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// The control request, for a control move.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<ControlRequestAnswer>,
    /// `proceed`, `proceed_and_notify`, `require_gate` or `deny`.
    pub outcome: String,
    /// Why, in evaluation order.
    pub causes: Vec<String>,
    /// The agent only suggests; the action is accepted separately (RC-28).
    pub suggest: bool,
}

/// The autonomy of the caller's moves under the autonomy policy in force or the defaults
/// (RC-27, RC-49); Access decides each move when it is written and its deny is final.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlAutonomyAnswer {
    /// The autonomy policy in force, `rec_…`; absent when the defaults apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// The moves.
    pub moves: Vec<ControlMoveAnswer>,
}

/// Who drives the execution environment (RC-33).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlDriverAnswer {
    /// The responsible driver.
    pub party: String,
    /// The `control_lease` grant in force, `rec_…`, when a second driver drives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease: Option<String>,
}

/// The separate axes of the execution (RC-30, ST-4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlAxesAnswer {
    /// From Access: `granted`, `revoked` or `unknown`; `revoked` once a recorded Access
    /// revocation counts, otherwise `unknown`, since the read asks Access nothing.
    pub authority: String,
    /// The executor's control mode Claim: `automatic`, `intervened` or `manual`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// From the executor's status Claims: `running`, `paused`, `stopped`, `failed`,
    /// `completed` or `unknown`.
    pub execution: String,
    /// From its heartbeats, stale at twice the declared interval: `live`, `stale`, `unknown`,
    /// `departed` or `not_applicable`.
    pub liveness: String,
    /// The driver.
    pub driver: ControlDriverAnswer,
}

/// One stop request as its separate records derive it (RC-36 … RC-40, E-28).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlStopAnswer {
    /// The `stop_request`, `rec_…`.
    pub request: String,
    /// Who asked.
    pub requester: String,
    /// `immediate`, `finish_then_stop` or `pause`.
    pub stop_type: String,
    /// `pending`, `accepted`, `finishing_then_stop` or `refused`.
    pub progress: String,
    /// The doer's latest `stop_response`, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    /// The executor's confirming status Claim, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
    /// `confirmed` only by that Claim, otherwise `unknown`.
    pub state: String,
    /// The first forced stop recorded after the request, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forced: Option<String>,
    /// The non-cancellable step the stop waits for; absent when it applies at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_step: Option<String>,
    /// Who must see a refusal.
    pub attention: Vec<String>,
    /// Whether the principal is shown the Access revocation path.
    pub revocation_path: bool,
    /// The `resume_after_stop` that lifts it, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resumed: Option<String>,
    /// The executor reported running after the confirmed stop without a resumption.
    pub restarted_without_resume: bool,
}

/// An action around a takeover (RC-8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlInterventionAnswer {
    /// The Act, `rec_…`.
    pub record: String,
    /// `under_lease` or `outside_coordination`.
    pub mark: String,
}

/// The ownership lease with the executor's activity (RC-18, WD-150 item 19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlLeaseAnswer {
    /// `no_lease`, `running` or `expired`.
    pub status: String,
    /// When it runs out or ran out, RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// What happens once it ran out: `return_to_pool` or `keep_and_signal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    /// The ledger times of the executor's status and heartbeat Claims that renew it, RFC 3339
    /// UTC.
    pub activity: Vec<String>,
}

/// The control of a commitment at the evaluation time; nothing of it is stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ControlAnswer {
    /// The executor: the obligor in force; only its Claims count (RC-41).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
    /// The capability declaration in force, `rec_…`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// The control requests Work offers now: only those the capability declaration, the
    /// integration depth and the control mode allow (RC-3, RC-34).
    pub offered_requests: Vec<ControlRequestAnswer>,
    /// The autonomy of the caller's moves.
    pub autonomy: ControlAutonomyAnswer,
    /// The axes and the driver; absent without an executor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<ControlAxesAnswer>,
    /// Every stop request.
    pub stops: Vec<ControlStopAnswer>,
    /// The actions around takeovers.
    pub interventions: Vec<ControlInterventionAnswer>,
    /// The ownership lease.
    pub lease: ControlLeaseAnswer,
}

fn request(r: &Request) -> ControlRequestAnswer {
    ControlRequestAnswer {
        kind: r.kind.wire_name().to_owned(),
        stop_type: r.stop_type.map(|s| s.wire_name().to_owned()),
        change_policy: r.change_policy.map(|p| p.wire_name().to_owned()),
    }
}

fn movement(m: &MoveAutonomy) -> ControlMoveAnswer {
    ControlMoveAnswer {
        action: m.action.clone(),
        operation: m.operation.map(|o| o.wire_name().to_owned()),
        request: m.request.as_ref().map(request),
        outcome: m.autonomy.outcome.wire_name().to_owned(),
        causes: m
            .autonomy
            .causes
            .iter()
            .map(|c| c.wire_name().to_owned())
            .collect(),
        suggest: m.autonomy.suggest,
    }
}

fn axes(a: &Axes) -> ControlAxesAnswer {
    ControlAxesAnswer {
        authority: a.authority.wire_name().to_owned(),
        mode: a.control.map(|m| m.wire_name().to_owned()),
        execution: a.execution.wire_name().to_owned(),
        liveness: a.liveness.wire_name().to_owned(),
        driver: ControlDriverAnswer {
            party: a.driver.party.as_str().to_owned(),
            lease: a.driver.lease.as_ref().map(rec),
        },
    }
}

fn stop(s: &StopView) -> ControlStopAnswer {
    ControlStopAnswer {
        request: rec(&s.request),
        requester: s.requester.as_str().to_owned(),
        stop_type: s.stop_type.wire_name().to_owned(),
        progress: s.progress.wire_name().to_owned(),
        response: s.response.as_ref().map(rec),
        confirmation: s.confirmation.as_ref().map(rec),
        state: s.state.wire_name().to_owned(),
        forced: s.forced.as_ref().map(rec),
        after_step: match &s.timing {
            StopTiming::Now => None,
            StopTiming::AfterStep(step) => Some(step.clone()),
        },
        attention: s.attention.iter().map(|p| p.as_str().to_owned()).collect(),
        revocation_path: s.revocation_path,
        resumed: s.resumed.as_ref().map(rec),
        restarted_without_resume: s.restarted_without_resume,
    }
}

fn lease(status: LeaseStatus, activity: &[Time]) -> ControlLeaseAnswer {
    let (name, until, expiry) = match status {
        LeaseStatus::NoLease => ("no_lease", None, None),
        LeaseStatus::Running(at) => ("running", Some(time(at)), None),
        LeaseStatus::Expired { at, expiry } => (
            "expired",
            Some(time(at)),
            Some(expiry.wire_name().to_owned()),
        ),
    };
    ControlLeaseAnswer {
        status: name.to_owned(),
        until,
        expiry,
        activity: activity.iter().copied().map(time).collect(),
    }
}

impl ControlAnswer {
    /// The answer of `read`.
    #[must_use]
    pub fn of(read: &ControlRead) -> Self {
        Self {
            executor: read.executor.as_ref().map(|p| p.as_str().to_owned()),
            capability: read.capability.as_ref().map(rec),
            offered_requests: read.offered.iter().map(request).collect(),
            autonomy: ControlAutonomyAnswer {
                policy: read.policy.as_ref().map(rec),
                moves: read.autonomy.iter().map(movement).collect(),
            },
            control: read.axes.as_ref().map(axes),
            stops: read.stops.iter().map(stop).collect(),
            interventions: read
                .interventions
                .iter()
                .map(|(record, mark)| ControlInterventionAnswer {
                    record: rec(record),
                    mark: mark.wire_name().to_owned(),
                })
                .collect(),
            lease: lease(read.lease, &read.activity),
        }
    }
}

macro_rules! control_write {
    ($name:ident, $kind:expr, $form:expr, $path:tt, $id:tt, $action:tt, $doc:tt) => {
        #[doc = $doc]
        #[utoipa::path(
            post,
            path = $path,
            operation_id = $id,
            tag = "control",
            params(
                ("ledger" = String, Path, description = "The ledger, `led_…`."),
                ("commitment" = String, Path, description = "The commitment, `cmt_…`, whose `request` the record cites in `basis`."),
                ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
                ("If-Match" = String, Header, description = "The strong ETag of the version of the first Work the record concerns; an operator correction names the commitment's version.")
            ),
            request_body(content = crate::writes::NewDeclaration, content_type = "application/json"),
            responses(
                (status = 201, description = "The record is in the ledger.", body = crate::commitments::CommitmentWritten, headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 400, description = "A body, identifier or header that does not open, a record of another kind or shape, one that does not cite this commitment, or a `definition` part that was not opened.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("WWW-Authenticate" = String, description = "The DPoP challenge."),
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 403, description = "The Access evidence does not authorise this record.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 404, description = "No such ledger.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 412, description = "The Work or the commitment is no longer at the If-Match version.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 413, description = "A body part is above its bound.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 422, description = "The kernel refused the record, with its reason (`control` and the refusal, such as `undeclared`, `unsupported`, `mode`, `second_driver`, `not_doer`, `uncited` or `basis:<gap>`); the refusal is kept under its key; or a body part carries a secret.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 428, description = "No If-Match.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota.")
                )),
                (status = 429, description = "The caller has spent its quota.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota."),
                    ("Retry-After" = String, description = "Seconds until the next window.")
                )),
                (status = 503, description = "Access cannot be reached, the ledger is busy, or the outcome is being checked; send the same request again.", body = Problem,
                    content_type = "application/problem+json", headers(
                    ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
                    ("RateLimit-Policy" = String, description = "The quota policy."),
                    ("RateLimit" = String, description = "What is left of the quota."),
                    ("Retry-After" = String, description = "Seconds to wait when the ledger is busy.")
                ))
            ),
            security(("access_token" = [])),
            extensions(("x-work-action" = json!($action)))
        )]
        #[allow(
            clippy::needless_pass_by_value,
            reason = "axum hands extractors over by value"
        )]
        pub async fn $name(
            State(services): State<Arc<ApiServices>>,
            Path((ledger, commitment)): Path<(String, String)>,
            Extension(context): Extension<RequestContext>,
            method: Method,
            uri: Uri,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            let typed = Typed {
                kind: $kind,
                form: $form,
                ledger: &ledger,
                commitment: Some(&commitment),
            };
            write(&services, typed, &context, &method, &uri, &headers, &body).await
        }
    };
}

control_write!(
    grant_or_release_control_lease,
    Kind::Declaration(DeclarationSubtype::ControlLease),
    None,
    "/v1/ledgers/{ledger}/commitments/{commitment}/control-leases",
    "write_control_lease",
    "work:control",
    "Grants a time-bound control lease to a second driver, or releases one; the `definition` part carries the `work/control/1` lease (RC-33, RC-34)."
);
control_write!(
    write_handoff_note,
    Kind::Declaration(DeclarationSubtype::HandoffNote),
    None,
    "/v1/ledgers/{ledger}/commitments/{commitment}/handoff-notes",
    "write_handoff_note",
    "work:control",
    "The handover note of whoever gives control back (RC-34, CM-45)."
);
control_write!(
    request_attention,
    Kind::Declaration(DeclarationSubtype::AttentionRequest),
    None,
    "/v1/ledgers/{ledger}/commitments/{commitment}/attention-requests",
    "request_attention",
    "work:condition",
    "Asks a Party to look at the commitment; neither a consultation nor a takeover (RC-31)."
);
control_write!(
    consult,
    Kind::Declaration(DeclarationSubtype::OpenCondition),
    Some(Form::Consultation),
    "/v1/ledgers/{ledger}/commitments/{commitment}/consultations",
    "consult",
    "work:condition",
    "Opens a decision or information wait: the doer asks and keeps control (RC-31)."
);
control_write!(
    request_stop,
    Kind::Declaration(DeclarationSubtype::StopRequest),
    None,
    "/v1/ledgers/{ledger}/commitments/{commitment}/stop-requests",
    "request_stop",
    "work:stop_request",
    "Asks the executor to stop with its stop type; refused when its capability declaration does not support the stop type (RC-36, RC-3, SEC-7)."
);
control_write!(
    respond_to_stop,
    Kind::Declaration(DeclarationSubtype::StopResponse),
    None,
    "/v1/ledgers/{ledger}/commitments/{commitment}/stop-responses",
    "respond_to_stop",
    "work:stop_respond",
    "The doer's answer to one stop request it cites: accept, finish then stop, or refuse with its reason in `note` (RC-36, RC-38)."
);
control_write!(
    record_forced_stop,
    Kind::Executor(FORCED_STOP_EXT_KEY),
    None,
    "/v1/ledgers/{ledger}/commitments/{commitment}/forced-stops",
    "record_forced_stop",
    "work:write",
    "Records a forced stop, an `observation` Claim whose forced stop extension names its source: `enforcement` by the executor, `access_revocation` by a system Party; it never confirms the stop (RC-37, RC-38)."
);
control_write!(
    resume_after_stop,
    Kind::Declaration(DeclarationSubtype::ResumeAfterStop),
    None,
    "/v1/ledgers/{ledger}/commitments/{commitment}/resume-after-stop",
    "resume_after_stop",
    "work:stop_request",
    "Lifts the stop request it cites; a stopped execution never resumes by itself (RC-40)."
);
control_write!(
    correct,
    Kind::Commitment(Operation::Amend),
    Some(Form::Correction),
    "/v1/ledgers/{ledger}/commitments/{commitment}/corrections",
    "correct_commitment",
    "work:commit",
    "An operator correction: an `amend` whose change policy is `interrupt` or `rollback`, offered only when the executor declares it, with a version that only grows (RC-40, CM-56, CM-57)."
);

/// Sets the principal's autonomy policy.
///
/// The body carries the signed `autonomy_policy` Declaration, whose `definition` part is the
/// `work/control/1` policy; it speaks for the principal, and a policy wider than the defaults is
/// an expansion only the principal writes in person, never an agent (RC-27, RC-29, RC-49).
#[utoipa::path(
    post,
    path = "/v1/ledgers/{ledger}/autonomy-policies",
    operation_id = "set_autonomy_policy",
    tag = "control",
    params(
        ("ledger" = String, Path, description = "The ledger, `led_…`."),
        ("Idempotency-Key" = String, Header, description = "A UUIDv7; the same key with the same body answers the first result."),
        ("If-Match" = String, Header, description = "The strong ETag of the version of the first Work the record concerns.")
    ),
    request_body(content = crate::writes::NewDeclaration, content_type = "application/json"),
    responses(
        (status = 201, description = "The record is in the ledger.", body = crate::writes::WrittenAnswer, headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 400, description = "A body, identifier or header that does not open, a record that is not an `autonomy_policy`, or a `definition` part that was not opened.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 401, description = "No valid Access access token and DPoP proof.", body = Problem,
            content_type = "application/problem+json", headers(
            ("WWW-Authenticate" = String, description = "The DPoP challenge."),
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 403, description = "The Access evidence does not authorise this record.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 404, description = "No such ledger.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 412, description = "The Work is no longer at the If-Match version.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 413, description = "A body part is above its bound.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 422, description = "The kernel refused the policy, with its reason (`control` and `not_principal`, `expansion_not_by_principal` or `definition:<member>`); the refusal is kept under its key; or a body part carries a secret.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 428, description = "No If-Match.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota.")
        )),
        (status = 429, description = "The caller has spent its quota.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds until the next window.")
        )),
        (status = 503, description = "Access cannot be reached, the ledger is busy, or the outcome is being checked; send the same request again.", body = Problem,
            content_type = "application/problem+json", headers(
            ("Request-Id" = String, description = "The request, `<trace id>-<span id>`."),
            ("RateLimit-Policy" = String, description = "The quota policy."),
            ("RateLimit" = String, description = "What is left of the quota."),
            ("Retry-After" = String, description = "Seconds to wait when the ledger is busy.")
        ))
    ),
    security(("access_token" = [])),
    extensions(("x-work-action" = json!("work:autonomy_policy_set")))
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands extractors over by value"
)]
pub async fn set_autonomy_policy(
    State(services): State<Arc<ApiServices>>,
    Path(ledger): Path<String>,
    Extension(context): Extension<RequestContext>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match caller_of(&services, &method, &uri, &headers).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let Ok(ledger) = LedgerId::parse_external(&ledger) else {
        return Problem::new(ProblemCode::InvalidId).into_response();
    };
    let mut request = match declaration_request(&body, &headers, context.traceparent().to_string())
    {
        Ok(request) => request,
        Err(problem) => return problem.into_response(),
    };
    request.expected = Some(Expected {
        kind: Kind::Declaration(DeclarationSubtype::AutonomyPolicy),
        commitment: None,
        form: None,
    });
    match services.writes.declare(&caller, &ledger, &request).await {
        Ok(written) => created(&ledger, &written),
        Err(refused) => write_problem(refused).into_response(),
    }
}

/// The control routes: the typed write of every control record a caller writes on a commitment
/// and the principal's autonomy policy.
pub fn routes() -> Router<Arc<ApiServices>> {
    let typed: [(&str, MethodRouter<Arc<ApiServices>>); 9] = [
        ("control-leases", post(grant_or_release_control_lease)),
        ("handoff-notes", post(write_handoff_note)),
        ("attention-requests", post(request_attention)),
        ("consultations", post(consult)),
        ("stop-requests", post(request_stop)),
        ("stop-responses", post(respond_to_stop)),
        ("forced-stops", post(record_forced_stop)),
        ("resume-after-stop", post(resume_after_stop)),
        ("corrections", post(correct)),
    ];
    typed.into_iter().fold(
        Router::new().route(
            "/v1/ledgers/{ledger}/autonomy-policies",
            post(set_autonomy_policy),
        ),
        |router, (path, route)| {
            router.route(
                &format!("/v1/ledgers/{{ledger}}/commitments/{{commitment}}/{path}"),
                route,
            )
        },
    )
}

#[cfg(test)]
mod tests;
