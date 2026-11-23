//! The `OpenAPI` 3.1 document of the REST API (T-98 item 1, P-54 item 2): generated from the `utoipa` derives of this crate with every object's keys in sorted order, written to `sdks/openapi/work-v1.json` by `cargo xtask openapi` and compared byte for byte by `cargo xtask check openapi`, which also checks that every operation but a public one names one Access action (E-45 item 3).

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use utoipa::OpenApi as _;

use crate::authority::{
    ApprovalAnswer, ApprovalReturned, AuthorityDecision, BasisInput, HoldingInput,
    NewAuthorityRequest, ProofInput,
};
use crate::commitments::{
    ActiveEndAnswer, AllowedAnswer, BudgetAnswer, ClockAnswer, CommitmentAnswer, CommitmentWritten,
    DueAnswer, ImplicitAnswer, ItemAnswer, MoverAnswer, NoticeAnswer, PendingAnswer,
    PeriodicAnswer, ReachedAnswer, SignalAnswer, StatementAnswer, StepAnswer, TermsAnswer,
    TimeAnswer,
};
use crate::executor::{DeliveriesAnswer, DeliveryAnswer};
use crate::problem::{FieldError, Problem, ProblemCode, ProblemType};
use crate::reads::{
    AuthContextAnswer, AuthorSignature, ChangeEntry, ChangesAnswer, CheckpointAnswer,
    EvidenceAnswer, InclusionAnswer, LedgerAttestation, WitnessAnswer, WorkAnswer,
};
use crate::works::{NewWork, OpenedWork};
use crate::writes::{
    ActorTypesInput, AuthContextInput, AuthorityInput, BodyPartInput, NewDeclaration, WrittenAnswer,
};

/// The committed document, relative to the workspace root.
pub const DOCUMENT: &str = "sdks/openapi/work-v1.json";

/// The operation extension naming the Access action (E-45 item 3).
pub const ACTION_EXTENSION: &str = "x-work-action";

/// The security scheme of every operation that acts for a caller: an Access access token bound
/// to a `DPoP` proof (RFC 9449; C-9, E-7).
pub const SECURITY_SCHEME: &str = "access_token";

fn security_scheme() -> Value {
    serde_json::json!({
        "type": "http",
        "scheme": "DPoP",
        "description": "An Access access token of a live realm of the tenant, whose aud names Work, in Authorization: DPoP <token>, with its DPoP proof over this request in the DPoP header (RFC 9449). The caller is the Access Party its client's pairwise sub resolves to; there is no bearer token."
    })
}

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Work API",
        version = "1",
        description = "The Work REST API. Errors are RFC 9457 problems; every operation that acts for a caller names the Access action it asks for in x-work-action, and a public operation names none."
    ),
    paths(
        crate::api::problem_type,
        crate::reads::get_work,
        crate::reads::list_changes,
        crate::reads::get_record_evidence,
        crate::writes::create_declaration,
        crate::works::create_work,
        crate::authority::create_authority_request,
        crate::authority::get_approval_return,
        crate::commitments::create_commitment,
        crate::commitments::get_commitment,
        crate::commitments::promise,
        crate::commitments::promise_conditional,
        crate::commitments::decline,
        crate::commitments::counter,
        crate::commitments::accept_counter,
        crate::commitments::state,
        crate::commitments::accept,
        crate::commitments::reject,
        crate::commitments::cancel,
        crate::commitments::release,
        crate::commitments::delegate,
        crate::commitments::assign,
        crate::commitments::dispute,
        crate::commitments::defer,
        crate::commitments::resume,
        crate::commitments::revoke_request,
        crate::commitments::revoke_promise,
        crate::commitments::revoke_statement,
        crate::commitments::revoke_acceptance,
        crate::commitments::allow,
        crate::commitments::refuse,
        crate::commitments::amend,
        crate::commitments::notice,
        crate::commitments::declare_obsolete,
        crate::commitments::administrative_close,
        crate::commitments::implicit_acceptance_terms,
        crate::executor::list_executor_deliveries,
        crate::executor::capability,
        crate::executor::status,
        crate::executor::control_mode,
        crate::executor::heartbeat,
        crate::executor::session,
        crate::executor::report,
        crate::executor::stop_response,
        crate::executor::request_response,
        crate::executor::handover
    ),
    components(schemas(
        Problem,
        ProblemCode,
        FieldError,
        ProblemType,
        WorkAnswer,
        ChangeEntry,
        ChangesAnswer,
        AuthorSignature,
        AuthContextAnswer,
        LedgerAttestation,
        CheckpointAnswer,
        InclusionAnswer,
        WitnessAnswer,
        EvidenceAnswer,
        NewDeclaration,
        AuthContextInput,
        AuthorityInput,
        ActorTypesInput,
        BodyPartInput,
        WrittenAnswer,
        NewWork,
        OpenedWork,
        NewAuthorityRequest,
        BasisInput,
        HoldingInput,
        ProofInput,
        AuthorityDecision,
        ApprovalAnswer,
        ApprovalReturned,
        CommitmentWritten,
        CommitmentAnswer,
        ItemAnswer,
        TermsAnswer,
        PendingAnswer,
        StatementAnswer,
        NoticeAnswer,
        ActiveEndAnswer,
        StepAnswer,
        AllowedAnswer,
        MoverAnswer,
        SignalAnswer,
        ImplicitAnswer,
        TimeAnswer,
        ClockAnswer,
        ReachedAnswer,
        PeriodicAnswer,
        DueAnswer,
        BudgetAnswer,
        DeliveriesAnswer,
        DeliveryAnswer
    ))
)]
struct Api;

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let entries: BTreeMap<String, Value> = map.into_iter().collect();
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect::<Map<String, Value>>(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// True for an operation that asks for no identity: its `security` is exactly one empty
/// requirement (E-45 item 3, T-98 item 6).
#[must_use]
pub fn is_public(operation: &Value) -> bool {
    let Some(requirements) = operation.get("security").and_then(Value::as_array) else {
        return false;
    };
    requirements.len() == 1 && requirements.iter().all(is_empty_requirement)
}

fn is_empty_requirement(requirement: &Value) -> bool {
    requirement.as_object().is_some_and(Map::is_empty)
}

/// The document as a JSON value.
///
/// # Errors
/// The serialisation error.
pub fn value() -> Result<Value, serde_json::Error> {
    let mut doc = serde_json::to_value(Api::openapi())?;
    if let Some(components) = doc.get_mut("components").and_then(Value::as_object_mut) {
        let schemes = components
            .entry("securitySchemes")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(schemes) = schemes.as_object_mut() {
            schemes.insert(SECURITY_SCHEME.to_owned(), security_scheme());
        }
    }
    Ok(sorted(doc))
}

/// The document as pretty JSON with a trailing newline.
///
/// # Errors
/// The serialisation error.
pub fn document() -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(&value()?)?;
    text.push('\n');
    Ok(text)
}
