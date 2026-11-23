//! The commitment Declaration write path (P-13, P-21, P-105, P-116, P-12, E-13, E-14, E-45, MD-4 item 5, OP-8, T-28, T-101 item 7): the caller is named by Access first; the `Idempotency-Key` and `If-Match` are decided against the ledger's canonical rows; then every Access answer the record depends on is asked online under a bound, never from a cache that outlives Access's own rules: the realm's governing domain from Work's pairing, the signing key's binding through the signed key lookup or the realm keys of an `auth_context` artifact, and the Exercise with its decision receipt. Only then does the kernel admit the record, with the receipt kept as received beside it; its body openings, checked against the record's commitments once Access authorised it, are scanned for secrets and sealed, and the ledger's writer commits the record with its parts in one transaction. When Access cannot answer, nothing is written (fail-closed).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;

use tokio::time::timeout;
use work_access_client::app::{Client, Looked};
use work_access_client::domain::discovery::Issuer;
use work_access_client::domain::exercise::{Intent, VerifiedExercise};
use work_access_client::domain::keys::{AsOf, DomainId, KernelId, Kid};
use work_access_client::domain::{AccessError, from_b64url};
use work_access_client::ports::{Clock, PartyKinds, Transport};
use work_kernel::catalog::DeclarationSubtype;
use work_kernel::codec::{Decoded, decode_record, record_id};
use work_kernel::commitment::{Definition, Operation, Refusal, condition_of};
use work_kernel::commitment_time::DEFINITION_PART;
use work_kernel::control::body::ProgressReport;
use work_kernel::control::executor::{
    CONTRACT_PART, REPORT_EXT_KEY, SingleUse, Use, check_single_use,
};
use work_kernel::control::stop::check_response;
use work_kernel::cose::{AuthorKeys, KeySet, parse_container};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId};
use work_kernel::items::{ItemKey, touched};
use work_kernel::limits::SemanticLimits;
use work_kernel::ontology::{Commitment, Obligor};
use work_kernel::record::{AuthorityProofKind, Record};
use work_kernel::validate::{ActorType, Origin};
use work_ledger::{
    ActorBindings, AdmitError, Arrival, AuthContext, BodyError, Committed, Declared,
    DeclaredActors, KeyClaim, LedgerError, Ledgers, PartRead, PendingRecord, Submission,
    SubmitError, admit,
};
use work_store::{
    AccessPool, CallerRef, ClaimRow, DeliveryKind, ExecutorDeliveryRow, IdempotencyDecision,
    ItemRef, LedgerTx, Pool, RealmState, SingleUseRow, StoreError, StoredLogEntry, StoredOutcome,
    UsedRow,
};

use crate::app::caller::ACCESS_BOUND;
use crate::domain::caller::Caller;
use crate::domain::commitments::{Asked, Folded, LOG_PAGE, Scope, facts, fold, operation_of};
use crate::domain::executor::{
    Element, ExecutorRefusal, bound_to, change_of, check_body, commitment_delivery, element_of,
    executor_of, request_of,
};
use crate::domain::kinds::{Kind, kind_of, record_action};
use crate::domain::writes::{
    AuthContextGiven, AuthorityGiven, DeclarationRequest, WriteRefusal, Written, actor_type,
    body_refusal, check_action, check_authority, check_openings, header_kid, party_ref, signer,
};
use crate::ports::{Bodies, Pending, RecordWrites, Sequence};

/// The event type of a record whose wire name gives no catalogued type (P-38).
const FALLBACK_EVENT: &str = "work.updated";

impl<C: work_ledger::Clock + Clone + Send + Sync + 'static> Sequence for Ledgers<C> {
    fn submit<'a>(
        &'a self,
        ledger: &'a work_store::LedgerId,
        record: PendingRecord,
    ) -> Pending<'a, Result<Committed, SubmitError>> {
        Box::pin(Ledgers::submit(self, ledger, record))
    }

    fn reject<'a>(
        &'a self,
        ledger: &'a work_store::LedgerId,
        claim: &'a KeyClaim,
        reason: &'a str,
        at_ms: u64,
    ) -> Pending<'a, Result<(), LedgerError>> {
        Box::pin(Ledgers::reject(self, ledger, claim, reason, at_ms))
    }
}

/// The write path over the Access client, the canonical rows read as `work_app`, Work's
/// pairing rows, the ledgers' writers and their body store.
pub struct Writes<T, C, P> {
    access: Arc<Client<T, C>>,
    audience: Option<String>,
    canonical: Pool,
    realms: AccessPool,
    sequence: Arc<dyn Sequence>,
    parties: P,
    bodies: Arc<dyn Bodies>,
}

impl<T, C, P> std::fmt::Debug for Writes<T, C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writes")
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

pub(crate) fn unverifiable(error: &AccessError) -> WriteRefusal {
    WriteRefusal::Unverifiable(match error {
        AccessError::Transport(_) | AccessError::Timeout | AccessError::Unavailable { .. } => {
            "access_unreachable"
        }
        AccessError::Stale => "access_stale",
        AccessError::Unserved(_) => "access_unserved",
        AccessError::Expired => "pep_certificate_expired",
        AccessError::Disabled => "client_disabled",
        AccessError::Answer(code) => code,
        _ => "access_answer",
    })
}

pub(crate) async fn bounded<V>(
    call: impl Future<Output = Result<V, AccessError>>,
) -> Result<V, AccessError> {
    timeout(ACCESS_BOUND, call)
        .await
        .map_err(|_| AccessError::Timeout)?
}

pub(crate) fn store_ledger(ledger: &LedgerId) -> work_store::LedgerId {
    work_store::LedgerId::from_bytes(*ledger.0.as_bytes())
}

fn item_ref(key: ItemKey) -> Option<ItemRef> {
    match key {
        ItemKey::Work(w) => Some(ItemRef::Work(*w.as_bytes())),
        ItemKey::Commitment(r) => Some(ItemRef::Commitment(*r.0.as_bytes())),
        ItemKey::Condition(r) => Some(ItemRef::Condition(*r.0.as_bytes())),
        _ => None,
    }
}

fn replayed(outcome: StoredOutcome) -> Result<Written, WriteRefusal> {
    match outcome {
        StoredOutcome::Recorded { pos, record_id } => Ok(Written {
            record: RecordId(Digest::sha256(record_id)),
            pos,
            replayed: true,
        }),
        StoredOutcome::Rejected { reason } => Err(WriteRefusal::Rejected(reason)),
    }
}

fn submit_refusal(error: &SubmitError) -> WriteRefusal {
    match error {
        SubmitError::Rejected(reason) => WriteRefusal::Rejected(reason.to_string()),
        SubmitError::AuthContext(invalid) => WriteRefusal::AuthContext(invalid.to_string()),
        SubmitError::Busy { retry_after } => WriteRefusal::Busy {
            retry_after_s: u32::try_from(retry_after.as_secs().max(1)).unwrap_or(u32::MAX),
        },
        SubmitError::Refused(StoreError::ItemConflict(_)) => WriteRefusal::PreconditionFailed,
        _ => WriteRefusal::NotRecorded,
    }
}

fn admit_refusal(error: &AdmitError) -> WriteRefusal {
    match error {
        AdmitError::Rejected(reason) => WriteRefusal::Rejected(reason.to_string()),
        AdmitError::AuthContext(invalid) => WriteRefusal::AuthContext(invalid.to_string()),
    }
}

/// Every stored entry of the ledger in position order, read in the transaction's snapshot.
pub(crate) async fn log_of(tx: &mut LedgerTx<'_>) -> Result<Vec<StoredLogEntry>, StoreError> {
    let mut out: Vec<StoredLogEntry> = Vec::new();
    loop {
        let from = out.last().map_or(0, |e| e.pos.saturating_add(1));
        let page = tx.entries(from, LOG_PAGE).await?;
        let full = page.len() >= usize::try_from(LOG_PAGE).unwrap_or(usize::MAX);
        out.extend(page);
        if !full {
            return Ok(out);
        }
    }
}

/// Whether the write of `record` reads the ledger's records: a commitment or responsibility
/// operation or another record whose validity the kernel checks against earlier records, a
/// continuation, whose conflict area the records give, or an element of the executor contract,
/// whose commitment and executor the records give (CM-19, RC-17, RC-41, T-89).
fn folds(record: &Record, request: &DeclarationRequest) -> bool {
    !matches!(kind_of(record), None | Some(Kind::Claim | Kind::Act))
        || record.supersedes().next().is_some()
        || element_of(record, request.executor).is_some()
}

/// The opened `definition` part a request carries.
fn definition_of(request: &DeclarationRequest) -> Option<&[u8]> {
    request
        .body
        .iter()
        .find(|o| o.part == CONTRACT_PART)
        .map(|o| o.content.as_slice())
}

/// The authority context and idempotency key an action report binds, read before Access is
/// asked so the bindings already used are read in the same snapshot (SEC-15).
fn binding_of(record: &Record, request: &DeclarationRequest) -> Option<([u8; 32], String)> {
    if element_of(record, request.executor) != Some(Element::Report) {
        return None;
    }
    let report = ProgressReport::decode(definition_of(request)?).ok()?;
    let binding = report.binding?;
    Some((
        *binding.authority_context.as_bytes(),
        binding.idempotency_key,
    ))
}

async fn decide(
    tx: &mut LedgerTx<'_>,
    caller: &CallerRef,
    record: &Record,
    request: &DeclarationRequest,
    now_ms: u64,
) -> Result<Precheck, WriteRefusal> {
    if tx
        .head()
        .await
        .map_err(|_| WriteRefusal::NotRecorded)?
        .is_none()
    {
        return Err(WriteRefusal::NotFound);
    }
    let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
    let key = match tx
        .idempotency(caller, &request.idempotency_key, &request.digest, now)
        .await
        .map_err(|_| WriteRefusal::NotRecorded)?
    {
        IdempotencyDecision::Fresh(key) => key,
        IdempotencyDecision::Replay(row) => return Ok(Precheck::Done(replayed(row.outcome))),
        IdempotencyDecision::Conflict => {
            return Err(WriteRefusal::Idempotency("idempotency_key_conflict"));
        }
        IdempotencyDecision::Expired => {
            return Err(WriteRefusal::Idempotency("idempotency_key_expired"));
        }
        IdempotencyDecision::Malformed => {
            return Err(WriteRefusal::Idempotency("idempotency_key_malformed"));
        }
    };
    let version = match touched(record).first().and_then(|t| item_ref(t.item)) {
        Some(item) => tx
            .item_version(&item)
            .await
            .map_err(|_| WriteRefusal::NotRecorded)?
            .unwrap_or(0),
        None => 0,
    };
    let log = if folds(record, request) {
        Some(log_of(tx).await.map_err(|_| WriteRefusal::NotRecorded)?)
    } else {
        None
    };
    let used = match binding_of(record, request) {
        Some((authority, key)) => tx
            .single_uses(&authority, &key)
            .await
            .map_err(|_| WriteRefusal::NotRecorded)?,
        None => Vec::new(),
    };
    Ok(Precheck::Fresh(Box::new(Fresh {
        claim: KeyClaim {
            caller: caller.clone(),
            key,
            request_digest: request.digest,
        },
        version,
        log,
        used,
    })))
}

/// A new request as the ledger's snapshot found it: its key, the version of the first Work
/// it touches, for a write that reads the commitments every stored entry, and for an action
/// report the bindings that already use its authority context or idempotency key (SEC-15).
struct Fresh {
    claim: KeyClaim,
    version: u64,
    log: Option<Vec<StoredLogEntry>>,
    used: Vec<UsedRow>,
}

/// What the ledger's rows decide before Access is asked.
enum Precheck {
    /// A new request under this key.
    Fresh(Box<Fresh>),
    /// The answer of the request first sent under this key (OP-8).
    Done(Result<Written, WriteRefusal>),
}

/// The record a request carries, with its `SignedRecord` bytes.
struct Carried {
    bytes: Vec<u8>,
    record: Record,
}

fn carried(request: &DeclarationRequest) -> Result<Carried, WriteRefusal> {
    let bytes = if request.auth_context.is_some() {
        request.record.clone()
    } else {
        parse_container(&request.record)
            .map_err(|r| WriteRefusal::Rejected(r.to_string()))?
            .payload
            .ok_or_else(|| WriteRefusal::Rejected("schema:container".to_owned()))?
    };
    match decode_record(&bytes).map_err(|r| WriteRefusal::Rejected(r.to_string()))? {
        Decoded::Record(record) => Ok(Carried {
            bytes,
            record: *record,
        }),
        Decoded::UnknownProtocol(_) => Err(WriteRefusal::Rejected(
            "protocol_version_unknown".to_owned(),
        )),
    }
}

fn declared(record: &Record, request: &DeclarationRequest) -> Result<DeclaredActors, WriteRefusal> {
    let core = record.core();
    let rings = core.on_behalf_of.as_deref().unwrap_or_default();
    let presenters = core.evidence.as_deref().unwrap_or_default();
    let types = &request.declared;
    if rings.len() != types.on_behalf_of.len() || presenters.len() != types.evidence.len() {
        return Err(WriteRefusal::Invalid("actor_types"));
    }
    Ok(DeclaredActors {
        author: Declared {
            party: core.author.clone(),
            actor_type: types.author,
        },
        on_behalf_of: rings
            .iter()
            .zip(&types.on_behalf_of)
            .map(|(p, t)| Declared {
                party: p.clone(),
                actor_type: *t,
            })
            .collect(),
        evidence: presenters
            .iter()
            .zip(&types.evidence)
            .map(|(e, t)| Declared {
                party: e.presenter.clone(),
                actor_type: *t,
            })
            .collect(),
    })
}

/// The Exercise a record refers to, with the intent it was approved for, when the record is one
/// a caller writes, names an `authority` and the intent is that of the record's action on this
/// ledger and valid now (E-45, P-13); a clock, periodic or budget Condition is part of the
/// commitment's terms and takes `work:commit` (WD-146).
fn authority_of<'a>(
    record: &Record,
    request: &'a DeclarationRequest,
    ledger: &LedgerId,
    now_ms: u64,
) -> Result<(&'a AuthorityGiven, Intent), WriteRefusal> {
    let action = record_action(record).ok_or(WriteRefusal::Invalid("operation"))?;
    if record.core().authority.is_none() {
        return Err(WriteRefusal::Rejected("authority_missing".to_owned()));
    }
    let given = request
        .authority
        .as_ref()
        .ok_or(WriteRefusal::Invalid("authority"))?;
    let intent = Intent::from_bytes(&given.intent).map_err(|_| WriteRefusal::Invalid("intent"))?;
    check_action(&intent, ledger, now_ms, action).map_err(WriteRefusal::Denied)?;
    Ok((given, intent))
}

/// The record a typed endpoint carries must be the kind it names (C-6); the executor report
/// endpoint takes a report Claim or the Act an action report travels as (RC-42, RC-43).
fn expected_operation(record: &Record, request: &DeclarationRequest) -> Result<(), WriteRefusal> {
    match &request.expected {
        Some(expected)
            if kind_of(record) != Some(expected.kind)
                && !(request.executor
                    && expected.kind == Kind::Executor(REPORT_EXT_KEY)
                    && element_of(record, true) == Some(Element::Report)) =>
        {
            Err(WriteRefusal::Invalid("operation"))
        }
        _ => Ok(()),
    }
}

/// The version `If-Match` names: the commitment or Condition a continuation touches, otherwise
/// the first Work the record concerns; a typed endpoint's continuation must continue the
/// commitment it names (P-54 item 5, T-89, C-6). An element of the executor contract that
/// continues nothing names the version of the commitment its route names, which its write
/// checks it names (RC-42).
fn expected_version(
    record: &Record,
    request: &DeclarationRequest,
    folded: Option<&Folded>,
    work_version: u64,
) -> Result<(), WriteRefusal> {
    let area = folded.and_then(|f| f.area_for(record));
    if area.is_none()
        && element_of(record, request.executor).is_some()
        && let Some(commitment) = request.expected.and_then(|e| e.commitment)
    {
        let version = folded.map_or(0, |f| f.version_of(commitment));
        if version != request.if_match {
            return Err(WriteRefusal::PreconditionFailed);
        }
        return Ok(());
    }
    if let Some(commitment) = request.expected.and_then(|e| e.commitment)
        && area.as_ref().map(|a| a.item) != Some(ItemKey::Commitment(commitment))
    {
        return Err(WriteRefusal::Invalid("commitment"));
    }
    if area.map_or(work_version, |a| a.version) != request.if_match {
        return Err(WriteRefusal::PreconditionFailed);
    }
    Ok(())
}

/// The governing domain of `caller`'s realm and the issuers of the realms of its tenant Work is
/// paired with, from Work's pairing rows (P-115 item 2, P-116).
pub(crate) async fn caller_realm(
    realms: &AccessPool,
    caller: &Caller,
) -> Result<(DomainId, BTreeSet<String>), WriteRefusal> {
    let rows = realms
        .realms(caller.tenant.as_str())
        .await
        .map_err(|_| WriteRefusal::Unverifiable("realm_unreadable"))?;
    let paired: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.state == RealmState::Paired)
        .map(|r| r.issuer.clone())
        .collect();
    let domain = rows
        .iter()
        .find(|r| r.realm == caller.realm && r.state == RealmState::Paired)
        .and_then(|r| r.domain)
        .ok_or(WriteRefusal::Unverifiable("realm_unpaired"))?;
    Ok((DomainId(domain), paired))
}

/// What admitting one record needs once Access authorised it.
struct Admission<'a> {
    caller: &'a Caller,
    ledger: &'a LedgerId,
    request: &'a DeclarationRequest,
    declared: DeclaredActors,
    carried: &'a Carried,
    domain: DomainId,
    paired: &'a BTreeSet<String>,
    now_ms: u64,
    folded: Option<&'a Folded>,
}

/// An admitted record and its author's Access actor type.
struct Admitted {
    pending: PendingRecord,
    author_actor: ActorType,
}

fn kernel_id(party: &PartyRef) -> Option<KernelId> {
    KernelId::parse(party.as_str()).ok()
}

/// What the executor rules decided of an element.
enum Executed {
    /// A new element, with the binding an action report writes beside it.
    Fresh(Option<SingleUseRow>),
    /// The action report that first used the same binding (SEC-15).
    Replay(Written),
}

/// The commitment scope of the record, for a write that reads the commitments (RC-41, RC-42).
fn scope_of(at: &Admission<'_>, admitted: &Admitted) -> Result<Option<Scope>, WriteRefusal> {
    let Some(folded) = at.folded else {
        return Ok(None);
    };
    let record = &at.carried.record;
    let asked = Asked {
        record,
        id: record_id(&at.carried.bytes),
        author_actor: admitted.author_actor,
        step_up: admitted.pending.step_up(),
        agent_side: false,
        now_ms: at.now_ms,
    };
    folded
        .scope(&asked, &facts())
        .map(Some)
        .map_err(|_| WriteRefusal::NotRecorded)
}

/// The executor contract rules of `element` (RC-41, RC-42, RC-43, RC-36, SEC-15).
fn check_executor(
    element: Element,
    at: &Admission<'_>,
    scope: &Scope,
    used: &[UsedRow],
) -> Result<Executed, ExecutorRefusal> {
    let record = &at.carried.record;
    let commitment = scope.commitment.ok_or(ExecutorRefusal::Commitment)?;
    if at
        .request
        .expected
        .and_then(|e| e.commitment)
        .is_some_and(|named| named != commitment)
    {
        return Err(ExecutorRefusal::Commitment);
    }
    let view = scope.before.as_ref().ok_or(ExecutorRefusal::Commitment)?;
    let executor = executor_of(view).ok_or(ExecutorRefusal::NotExecutor)?;
    if &record.core().author != executor {
        return Err(ExecutorRefusal::NotExecutor);
    }
    let binding = check_body(element, record, &commitment, definition_of(at.request))?;
    if element == Element::StopResponse {
        let cited: Vec<(RecordId, &Record)> = scope.cited.iter().map(|(i, r)| (*i, r)).collect();
        check_response(record, &cited, executor)
            .map_err(|r| ExecutorRefusal::Control(r.wire_name()))?;
    }
    let Some(binding) = binding else {
        return Ok(Executed::Fresh(None));
    };
    let contexts: Vec<Digest> = used.iter().map(|u| Digest::sha256(u.authority)).collect();
    let earlier: Vec<Use<'_>> = used
        .iter()
        .zip(&contexts)
        .map(|(u, context)| Use {
            context,
            key: u.key.as_str(),
        })
        .collect();
    let context = Digest::sha256(binding.authority);
    let new = Use {
        context: &context,
        key: binding.key.as_str(),
    };
    match check_single_use(&earlier, new).map_err(|r| ExecutorRefusal::Control(r.wire_name()))? {
        SingleUse::Fresh => Ok(Executed::Fresh(Some(SingleUseRow {
            authority: binding.authority,
            key: binding.key,
            relies_on: binding.relies_on,
        }))),
        SingleUse::Replay => {
            let first = used
                .iter()
                .find(|u| u.authority == binding.authority && u.key == binding.key)
                .ok_or(ExecutorRefusal::Control("context_reused"))?;
            Ok(Executed::Replay(Written {
                record: RecordId(Digest::sha256(first.record)),
                pos: first.pos,
                replayed: true,
            }))
        }
    }
}

/// The deliveries a record makes to the executor assigned to its commitment, computed from the
/// fold with the record applied next and written in the same transaction (RC-42, T-105, E-39):
/// the commitment to the Party a binding record binds it to, with the record's Access decision
/// receipt digest as its single-use authority context, and to the executor in force the request
/// a stop request, a control lease, a resume after a stop or a correction carries.
fn deliveries(
    at: &Admission<'_>,
    scope: Option<&Scope>,
) -> Result<Vec<ExecutorDeliveryRow>, WriteRefusal> {
    let Some(scope) = scope else {
        return Ok(Vec::new());
    };
    let (Some(before), Some(after)) = (scope.before.as_ref(), scope.after.as_ref()) else {
        return Ok(Vec::new());
    };
    let record = &at.carried.record;
    let id = record_id(&at.carried.bytes);
    let mut out = Vec::new();
    if let Some(party) = bound_to(before, after, id) {
        let authority = record
            .core()
            .authority
            .as_ref()
            .map(|a| *a.digest.as_bytes())
            .ok_or_else(|| WriteRefusal::Rejected("authority_missing".to_owned()))?;
        let mut cited: Vec<RecordId> = record.basis().to_vec();
        cited.extend(scope.context.iter().copied());
        let body = commitment_delivery(after, id, authority, scope.budget, &cited)
            .encode()
            .map_err(|_| WriteRefusal::NotRecorded)?;
        out.push(ExecutorDeliveryRow {
            addressee: party.as_str().to_owned(),
            kind: DeliveryKind::Commitment,
            commitment: *after.root.0.as_bytes(),
            body,
        });
    }
    let asked =
        request_of(record, id, definition_of(at.request)).or_else(|| change_of(before, after, id));
    if let (Some(request), Some(executor)) = (asked, executor_of(after)) {
        out.push(ExecutorDeliveryRow {
            addressee: executor.as_str().to_owned(),
            kind: DeliveryKind::Request,
            commitment: *after.root.0.as_bytes(),
            body: request.encode().map_err(|_| WriteRefusal::NotRecorded)?,
        });
    }
    Ok(out)
}

impl<T, C, P> Writes<T, C, P>
where
    T: Transport + 'static,
    C: Clock + 'static,
    P: PartyKinds + 'static,
{
    /// Writes over `access`, whose receipts name `audience`, the `x5t#S256` of Work's PEP
    /// certificate, the PEP that commits Work's Exercises (Access OP-149 m.11); with none, every
    /// write is `authority_unverifiable`. Body openings are sealed through `bodies` (OP-45).
    #[must_use]
    pub fn new(
        access: Arc<Client<T, C>>,
        audience: Option<String>,
        canonical: Pool,
        realms: AccessPool,
        sequence: Arc<dyn Sequence>,
        parties: P,
        bodies: Arc<dyn Bodies>,
    ) -> Self {
        Self {
            access,
            audience: audience.filter(|a| !a.is_empty()),
            canonical,
            realms,
            sequence,
            parties,
            bodies,
        }
    }

    /// The body parts of the record at `pos` of `ledger` in part order at ledger time `now_ms`,
    /// each readable with its checked content or unreadable once its keys are gone (OP-45
    /// item 5, OP-13); no caller scope applies, so the write path reads only records it already
    /// folds.
    ///
    /// # Errors
    /// [`BodyError`] for a part that does not open to its commitment or a store that failed.
    pub async fn parts(
        &self,
        ledger: &LedgerId,
        pos: u64,
        now_ms: u64,
    ) -> Result<Vec<(String, PartRead)>, BodyError> {
        self.bodies.parts(&store_ledger(ledger), pos, now_ms).await
    }

    /// Seals the request's openings into `pending` (SEC-35 item 2, OP-45): a detected secret
    /// names only its part and rule.
    async fn seal(
        &self,
        ledger: &LedgerId,
        pending: &mut PendingRecord,
        request: &DeclarationRequest,
        now_ms: u64,
    ) -> Result<(), WriteRefusal> {
        let sealed = self
            .bodies
            .seal(&store_ledger(ledger), pending, &request.body, now_ms)
            .await;
        match sealed {
            Ok(()) => Ok(()),
            Err(BodyError::SecretDetected { part, rule }) => {
                tracing::warn!(
                    event = "body.secret_detected",
                    part = part.as_str(),
                    rule = rule.as_str(),
                    "a write is refused: a body part carries a secret"
                );
                Err(WriteRefusal::SecretDetected { part, rule })
            }
            Err(error) => {
                let refusal = body_refusal(&error);
                if refusal == WriteRefusal::NotRecorded {
                    tracing::warn!(
                        event = "body.unsealed",
                        error = %error,
                        "a write is refused: its body is not sealed"
                    );
                }
                Err(refusal)
            }
        }
    }

    /// The idempotency decision and the `If-Match` check, in one snapshot of the ledger.
    async fn precheck(
        &self,
        caller: &CallerRef,
        ledger: &LedgerId,
        record: &Record,
        request: &DeclarationRequest,
        now_ms: u64,
    ) -> Result<Precheck, WriteRefusal> {
        let mut tx = LedgerTx::begin_snapshot(&self.canonical, &store_ledger(ledger))
            .await
            .map_err(|_| WriteRefusal::NotRecorded)?;
        let decided = decide(&mut tx, caller, record, request, now_ms).await;
        let _closed = tx.rollback().await;
        decided
    }

    /// The governing domain of the caller's realm and the issuers of the realms of its tenant
    /// Work is paired with, as an `auth_context` names its realm (P-115 item 2, P-116).
    async fn realm(&self, caller: &Caller) -> Result<(DomainId, BTreeSet<String>), WriteRefusal> {
        caller_realm(&self.realms, caller).await
    }

    /// The bindings Access names for the record's Parties: the author's from its signing key,
    /// and the principals' and presenters' from the Party lookup (P-12, MD-7 item 3).
    async fn bindings(
        &self,
        domain: DomainId,
        record: &Record,
        author: Option<(PartyRef, ActorType)>,
    ) -> Result<ActorBindings, WriteRefusal> {
        let core = record.core();
        let others: Vec<KernelId> = core
            .on_behalf_of
            .iter()
            .flatten()
            .chain(core.evidence.iter().flatten().map(|e| &e.presenter))
            .filter_map(kernel_id)
            .collect();
        let kinds = if others.is_empty() {
            BTreeMap::new()
        } else {
            bounded(self.parties.kinds(domain, &others))
                .await
                .map_err(|e| unverifiable(&e))?
        };
        let mut bindings = ActorBindings::new();
        let conflict = |_| WriteRefusal::Unverifiable("access_answer");
        if let Some((party, actor)) = author {
            bindings.bind(party, actor).map_err(conflict)?;
        }
        for (id, kind) in kinds {
            if let Some(party) = party_ref(&id) {
                bindings.bind(party, actor_type(kind)).map_err(conflict)?;
            }
        }
        Ok(bindings)
    }

    /// The Exercise of `given`, asked of Access now and verified for `intent` (T-101 item 7).
    async fn exercise(
        &self,
        domain: DomainId,
        given: &AuthorityGiven,
        intent: &Intent,
        audience: &str,
    ) -> Result<VerifiedExercise, WriteRefusal> {
        bounded(
            self.access
                .exercise(domain, &given.exercise, intent, audience),
        )
        .await
        .map_err(|e| match e {
            AccessError::Refused { status: 404, .. } => WriteRefusal::Denied("exercise_unknown"),
            AccessError::Answer(code) => WriteRefusal::Denied(code),
            other => unverifiable(&other),
        })
    }

    /// Admits an unsigned human record: its author is the caller Access named, and its
    /// `auth_context` artifact verifies under the realm keys of the caller's token issuer
    /// (P-21 item 3, P-116).
    async fn unsigned(
        &self,
        at: &Admission<'_>,
        given: &AuthContextGiven,
        claim: Option<KeyClaim>,
    ) -> Result<Admitted, WriteRefusal> {
        let record = &at.carried.record;
        let named = at.caller.party().map_err(WriteRefusal::Denied)?;
        if record.core().author != named.reference {
            return Err(WriteRefusal::Denied("author_not_caller"));
        }
        let issuer = Issuer::parse(&at.caller.issuer)
            .map_err(|_| WriteRefusal::Unverifiable("access_answer"))?;
        let kid = header_kid(&given.artifact)
            .ok_or_else(|| WriteRefusal::AuthContext("signature".to_owned()))?;
        let keys = bounded(self.access.realm_keys(&issuer, &kid))
            .await
            .map_err(|e| unverifiable(&e))?;
        let bindings = self.bindings(at.domain, record, None).await?;
        let submission = Submission {
            arrival: Arrival::Unsigned {
                record: &at.carried.bytes,
                auth_context: AuthContext {
                    bytes: &given.artifact,
                    digest: &given.digest,
                    realm_keys: &keys,
                    issuer: &at.caller.issuer,
                    paired: at.paired,
                    now_ms: at.now_ms,
                },
            },
            declared: &at.declared,
            bindings: &bindings,
            origin: Origin::Direct,
            understood_extensions: &[],
            limits: SemanticLimits::default(),
            event_type: FALLBACK_EVENT,
            traceparent: &at.request.traceparent,
            idempotency: claim,
            inbound: None,
            areas: at.folded.map(Folded::areas),
        };
        let none = KeySet::default();
        let verifier = AuthorKeys {
            author: &record.core().author,
            keys: &none,
        };
        let pending = admit(&verifier, &store_ledger(at.ledger), submission)
            .map_err(|e| admit_refusal(&e))?;
        Ok(Admitted {
            pending,
            author_actor: ActorType::Human,
        })
    }

    /// Admits a signed record against the key Access binds to its `kid` now, whose Party's
    /// `actor_kind` is the author's actor type (P-21 item 1, P-105, P-12, SEC-19).
    async fn signed(
        &self,
        at: &Admission<'_>,
        claim: Option<KeyClaim>,
    ) -> Result<Admitted, WriteRefusal> {
        let record = &at.carried.record;
        let kid = header_kid(&at.request.record)
            .ok_or_else(|| WriteRefusal::Rejected("signature:header_profile".to_owned()))?;
        let looked = bounded(self.access.keys(at.domain, &[Kid(kid)], &AsOf::Head))
            .await
            .map_err(|e| unverifiable(&e))?;
        let signed = signer(looked.iter().find_map(|l| match l {
            Looked::Known(c) => Some(&c.key),
            Looked::Unknown(_) => None,
        }));
        let bindings = self
            .bindings(at.domain, record, signed.party.clone())
            .await?;
        let author = signed
            .party
            .as_ref()
            .map_or(&record.core().author, |(p, _)| p);
        let verifier = AuthorKeys {
            author,
            keys: &signed.keys,
        };
        let submission = Submission {
            arrival: Arrival::Signed(&at.request.record),
            declared: &at.declared,
            bindings: &bindings,
            origin: Origin::Direct,
            understood_extensions: &[],
            limits: SemanticLimits::default(),
            event_type: FALLBACK_EVENT,
            traceparent: &at.request.traceparent,
            idempotency: claim,
            inbound: None,
            areas: at.folded.map(Folded::areas),
        };
        let pending = admit(&verifier, &store_ledger(at.ledger), submission)
            .map_err(|e| admit_refusal(&e))?;
        let author_actor = signed.party.as_ref().map_or(ActorType::Human, |(_, a)| *a);
        Ok(Admitted {
            pending,
            author_actor,
        })
    }

    /// Whether a side of the commitment a `request` opens is an agent: its author, or its
    /// obligor or acceptor as Access binds them (CM-7).
    async fn agent_side(
        &self,
        domain: DomainId,
        record: &Record,
        author_actor: ActorType,
    ) -> Result<bool, WriteRefusal> {
        if author_actor == ActorType::Agent {
            return Ok(true);
        }
        let Some(opened) = Commitment::of(record) else {
            return Ok(false);
        };
        let mut sides: Vec<KernelId> = kernel_id(&opened.acceptor).into_iter().collect();
        if let Obligor::Party(obligor) = &opened.obligor {
            sides.extend(kernel_id(obligor));
        }
        if sides.is_empty() {
            return Ok(false);
        }
        let kinds = bounded(self.parties.kinds(domain, &sides))
            .await
            .map_err(|e| unverifiable(&e))?;
        Ok(kinds.values().any(|k| actor_type(*k) == ActorType::Agent))
    }

    /// The kernel's validity check of a commitment or responsibility operation, or of an
    /// `acknowledgement` in a commitment chain, before it is written (CM-19, RC-17, RC-5): a
    /// refused operation writes nothing into the log, its refusal is kept under the request's
    /// idempotency key and answered with the kernel's reason; a refusal that cannot be kept is
    /// `not_recorded`, and the same request asks again.
    async fn gate(
        &self,
        at: &Admission<'_>,
        admitted: &Admitted,
        claim: Option<&KeyClaim>,
    ) -> Result<(), WriteRefusal> {
        let record = &at.carried.record;
        let kind = kind_of(record);
        let commitment = matches!(kind, Some(Kind::Commitment(_)));
        let responsibility = matches!(
            kind,
            Some(Kind::Responsibility(_) | Kind::Declaration(DeclarationSubtype::Acknowledgement))
        );
        if !(commitment || responsibility) {
            return Ok(());
        }
        let folded = at.folded.ok_or(WriteRefusal::NotRecorded)?;
        let asked = Asked {
            record,
            id: record_id(&at.carried.bytes),
            author_actor: admitted.author_actor,
            step_up: admitted.pending.step_up(),
            agent_side: if commitment {
                self.agent_side(at.domain, record, admitted.author_actor)
                    .await?
            } else {
                false
            },
            now_ms: at.now_ms,
        };
        let reason = if commitment {
            match folded.check(&asked, &facts()) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(refusal)) => format!("commitment:{}", refusal.wire_name()),
                Err(_) => return Err(WriteRefusal::NotRecorded),
            }
        } else {
            match folded.check_responsibility(&asked, &facts()) {
                Ok(Some(Ok(_))) => return Ok(()),
                Ok(None) if matches!(kind, Some(Kind::Declaration(_))) => return Ok(()),
                Ok(None) => format!("responsibility:{}", Refusal::NothingPending.wire_name()),
                Ok(Some(Err(refusal))) => format!("responsibility:{}", refusal.wire_name()),
                Err(_) => return Err(WriteRefusal::NotRecorded),
            }
        };
        if let Some(claim) = claim {
            self.sequence
                .reject(&store_ledger(at.ledger), claim, &reason, at.now_ms)
                .await
                .map_err(|_| WriteRefusal::NotRecorded)?;
        }
        Err(WriteRefusal::Rejected(reason))
    }

    /// The executor contract rules of an element (RC-41, RC-42, RC-43, SEC-15): the record names
    /// the commitment its route names, its author is the executor assigned to it, its
    /// `definition` body decodes as its element, a `stop_response` answers one stop request it
    /// cites, and an action report binds an authority context and an idempotency key neither of
    /// which another report used. The same binding again is a replay of the report that first
    /// used it: nothing is written and its record is answered with `replayed`. A refusal is a
    /// decision kept under the request's idempotency key like the kernel's.
    async fn executor(
        &self,
        at: &Admission<'_>,
        scope: Option<&Scope>,
        used: &[UsedRow],
        claim: Option<&KeyClaim>,
    ) -> Result<Executed, WriteRefusal> {
        let record = &at.carried.record;
        let Some(element) = element_of(record, at.request.executor) else {
            return Ok(Executed::Fresh(None));
        };
        let checked = check_executor(element, at, scope.ok_or(WriteRefusal::NotRecorded)?, used);
        match checked {
            Ok(executed) => Ok(executed),
            Err(refusal) => {
                let reason = refusal.reason();
                if let Some(claim) = claim {
                    self.sequence
                        .reject(&store_ledger(at.ledger), claim, &reason, at.now_ms)
                        .await
                        .map_err(|_| WriteRefusal::NotRecorded)?;
                }
                Err(WriteRefusal::Rejected(reason))
            }
        }
    }

    /// The `definition` part a clock, periodic or budget Condition carries must be a
    /// `work/commitment-time/1` body of its type, and one that supersedes an earlier Condition
    /// must continue that Condition's definition (CM-48, CM-50, CM-51, CM-53, WD-146); a
    /// refusal names the member, as `definition:<member>`.
    async fn check_definition(
        &self,
        ledger: &LedgerId,
        record: &Record,
        request: &DeclarationRequest,
        folded: Option<&Folded>,
        now_ms: u64,
    ) -> Result<(), WriteRefusal> {
        let Some(kind) = condition_of(record) else {
            return Ok(());
        };
        let refused = |member: &str| WriteRefusal::Rejected(format!("definition:{member}"));
        let content = request
            .body
            .iter()
            .find(|o| o.part == DEFINITION_PART)
            .ok_or(WriteRefusal::Invalid("body_unopened"))?;
        let next = Definition::decode(kind, &content.content).map_err(|e| refused(e.0))?;
        let Some(previous) = record.supersedes().next() else {
            return Ok(());
        };
        let pos = folded
            .ok_or(WriteRefusal::NotRecorded)?
            .position_of(previous)
            .ok_or_else(|| refused("supersedes"))?;
        let parts = self
            .parts(ledger, pos, now_ms)
            .await
            .map_err(|_| WriteRefusal::NotRecorded)?;
        let earlier = parts
            .into_iter()
            .find_map(|(name, read)| match read {
                PartRead::Readable(o) if name == DEFINITION_PART => Some(o.content),
                PartRead::Readable(_) | PartRead::Unreadable => None,
            })
            .and_then(|b| Definition::decode(kind, &b).ok())
            .ok_or_else(|| refused("supersedes"))?;
        next.continues(&earlier).map_err(|e| refused(e.0))
    }

    async fn write(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        request: &DeclarationRequest,
    ) -> Result<Written, WriteRefusal> {
        let audience = self
            .audience
            .as_deref()
            .ok_or(WriteRefusal::Unverifiable("audience_unset"))?;
        let now_ms = self.access.now_ms();
        let carried = carried(request)?;
        let record = &carried.record;
        expected_operation(record, request)?;
        let caller_ref = CallerRef::new(
            caller
                .party()
                .map_err(WriteRefusal::Denied)?
                .reference
                .as_str(),
        )
        .ok_or(WriteRefusal::Unverifiable("access_answer"))?;
        let fresh = match self
            .precheck(&caller_ref, ledger, record, request, now_ms)
            .await?
        {
            Precheck::Fresh(fresh) => *fresh,
            Precheck::Done(answer) => return answer,
        };
        let (given, intent) = authority_of(record, request, ledger, now_ms)?;
        let (domain, paired) = self.realm(caller).await?;
        let exercise = self.exercise(domain, given, &intent, audience).await?;
        check_authority(record.core(), &exercise).map_err(WriteRefusal::Denied)?;
        let folded = fresh
            .log
            .as_deref()
            .map(|log| fold(ledger, log))
            .transpose()
            .map_err(|_| WriteRefusal::NotRecorded)?;
        expected_version(record, request, folded.as_ref(), fresh.version)?;
        check_openings(record.core(), &request.body)?;
        self.check_definition(ledger, record, request, folded.as_ref(), now_ms)
            .await?;
        let at = Admission {
            caller,
            ledger,
            request,
            declared: declared(record, request)?,
            carried: &carried,
            domain,
            paired: &paired,
            now_ms,
            folded: folded.as_ref(),
        };
        let claim = Some(fresh.claim);
        let kept = claim.clone();
        let admitted = match &request.auth_context {
            Some(given) => self.unsigned(&at, given, claim).await?,
            None => self.signed(&at, claim).await?,
        };
        self.gate(&at, &admitted, kept.as_ref()).await?;
        let scope = scope_of(&at, &admitted)?;
        let single_use = match self
            .executor(&at, scope.as_ref(), &fresh.used, kept.as_ref())
            .await?
        {
            Executed::Fresh(single_use) => single_use,
            Executed::Replay(written) => return Ok(written),
        };
        let deliveries = deliveries(&at, scope.as_ref())?;
        let claims = self.claims(&at, &admitted).await?;
        let mut pending = admitted.pending;
        pending.end_claims(claims);
        pending.deliver(deliveries);
        if let Some(binding) = single_use {
            pending.use_once(binding);
        }
        pending
            .keep_authority_proof(AuthorityProofKind::DecisionReceipt, &exercise.receipt)
            .map_err(|_| WriteRefusal::Denied("authority_digest"))?;
        pending.for_tenant(caller.tenant.as_str());
        self.seal(ledger, &mut pending, request, now_ms).await?;
        let committed = self
            .sequence
            .submit(&store_ledger(ledger), pending)
            .await
            .map_err(|e| submit_refusal(&e))?;
        Ok(Written {
            record: record_id(&carried.bytes),
            pos: committed.pos,
            replayed: false,
        })
    }

    /// The `commitment_active` Claim of each end of `commitment.active` the record gives once
    /// written, as Work's service Party in the realm's governing domain over Work's PEP (E-8,
    /// E-12, WD-146 items 1 and 5): computed before the write from the fold of the log with the
    /// record applied after the head, and written in the same transaction as the record, so
    /// every end a committed record gives reaches Access from its delivery row and none is
    /// sent for a record that was not written. An obligor without an Access `PartyID` gets none;
    /// Work only ends commitment-scoped authority and never starts it.
    async fn claims(
        &self,
        at: &Admission<'_>,
        admitted: &Admitted,
    ) -> Result<Vec<ClaimRow>, WriteRefusal> {
        let record = &at.carried.record;
        if operation_of(record).is_none_or(|op| op == Operation::Request) {
            return Ok(Vec::new());
        }
        let folded = at.folded.ok_or(WriteRefusal::NotRecorded)?;
        let asked = Asked {
            record,
            id: record_id(&at.carried.bytes),
            author_actor: admitted.author_actor,
            step_up: admitted.pending.step_up(),
            agent_side: false,
            now_ms: at.now_ms,
        };
        let Some((root, ends)) = folded
            .ends(&asked, &facts())
            .map_err(|_| WriteRefusal::NotRecorded)?
        else {
            return Ok(Vec::new());
        };
        let subjects: BTreeSet<[u8; 16]> = ends
            .iter()
            .filter_map(|e| kernel_id(&e.obligor))
            .map(|k| k.0)
            .collect();
        if subjects.is_empty() {
            return Ok(Vec::new());
        }
        let pep = self
            .audience
            .as_deref()
            .and_then(|a| from_b64url(a).ok())
            .and_then(|a| <[u8; 32]>::try_from(a).ok())
            .ok_or(WriteRefusal::Unverifiable("audience_unset"))?;
        let issuer = self
            .realms
            .realms(at.caller.tenant.as_str())
            .await
            .map_err(|_| WriteRefusal::Unverifiable("realm_unreadable"))?
            .into_iter()
            .find(|r| r.realm == at.caller.realm && r.state == RealmState::Paired)
            .and_then(|r| r.party)
            .ok_or(WriteRefusal::Unverifiable("realm_unpaired"))?;
        Ok(subjects
            .into_iter()
            .map(|subject| ClaimRow {
                subject,
                commitment: *root.0.as_bytes(),
                issuer,
                domain: at.domain.0,
                pep,
            })
            .collect())
    }
}

impl<T, C, P> RecordWrites for Writes<T, C, P>
where
    T: Transport + 'static,
    C: Clock + 'static,
    P: PartyKinds + 'static,
{
    fn declare<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        request: &'a DeclarationRequest,
    ) -> Pending<'a, Result<Written, WriteRefusal>> {
        Box::pin(self.write(caller, ledger, request))
    }
}
