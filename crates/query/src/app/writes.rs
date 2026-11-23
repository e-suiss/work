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
use work_kernel::codec::{Decoded, decode_record, record_id};
use work_kernel::commitment::{Definition, Operation, condition_of};
use work_kernel::commitment_time::DEFINITION_PART;
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
    AccessPool, CallerRef, ClaimRow, IdempotencyDecision, ItemRef, LedgerTx, Pool, RealmState,
    StoreError, StoredLogEntry, StoredOutcome,
};

use crate::app::caller::ACCESS_BOUND;
use crate::domain::caller::Caller;
use crate::domain::commitments::{Asked, Folded, LOG_PAGE, action_of, facts, fold, operation_of};
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

/// Whether the write of `record` reads the ledger's commitments: a commitment operation, whose
/// validity the kernel checks, or a continuation, whose conflict area the records give (CM-19,
/// T-89).
fn folds(record: &Record) -> bool {
    operation_of(record).is_some() || record.supersedes().next().is_some()
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
    let log = if folds(record) {
        Some(log_of(tx).await.map_err(|_| WriteRefusal::NotRecorded)?)
    } else {
        None
    };
    Ok(Precheck::Fresh(Box::new(Fresh {
        claim: KeyClaim {
            caller: caller.clone(),
            key,
            request_digest: request.digest,
        },
        version,
        log,
    })))
}

/// A new request as the ledger's snapshot found it: its key, the version of the first Work
/// it touches and, for a write that reads the commitments, every stored entry.
struct Fresh {
    claim: KeyClaim,
    version: u64,
    log: Option<Vec<StoredLogEntry>>,
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

/// The Exercise a commitment Declaration refers to, with the intent it was approved for, when
/// the record is one `work:commit` covers, names an `authority` and the intent is that of this
/// ledger and valid now (E-45, P-13); a clock, periodic or budget Condition is part of the
/// commitment's terms and takes `work:commit` too (WD-146).
fn authority_of<'a>(
    record: &Record,
    request: &'a DeclarationRequest,
    ledger: &LedgerId,
    now_ms: u64,
) -> Result<(&'a AuthorityGiven, Intent), WriteRefusal> {
    let action = match operation_of(record) {
        Some(op) => action_of(op),
        None => condition_of(record).map(|_| "commit"),
    }
    .ok_or(WriteRefusal::Invalid("operation"))?;
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

/// The record a typed commitment endpoint carries must be the operation it names (C-6).
fn expected_operation(record: &Record, request: &DeclarationRequest) -> Result<(), WriteRefusal> {
    match &request.expected {
        Some(expected) if operation_of(record) != Some(expected.operation) => {
            Err(WriteRefusal::Invalid("operation"))
        }
        _ => Ok(()),
    }
}

/// The version `If-Match` names: the commitment or Condition a continuation touches, otherwise
/// the first Work the record concerns; a typed endpoint's continuation must continue the
/// commitment it names (P-54 item 5, T-89, C-6).
fn expected_version(
    record: &Record,
    request: &DeclarationRequest,
    folded: Option<&Folded>,
    work_version: u64,
) -> Result<(), WriteRefusal> {
    let area = folded.and_then(|f| f.area_for(record));
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

    /// The kernel's validity check of a commitment operation before it is written (CM-19): a
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
        if operation_of(record).is_none() {
            return Ok(());
        }
        let folded = at.folded.ok_or(WriteRefusal::NotRecorded)?;
        let asked = Asked {
            record,
            id: record_id(&at.carried.bytes),
            author_actor: admitted.author_actor,
            step_up: admitted.pending.step_up(),
            agent_side: self
                .agent_side(at.domain, record, admitted.author_actor)
                .await?,
            now_ms: at.now_ms,
        };
        let refusal = match folded.check(&asked, &facts()) {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(refusal)) => refusal,
            Err(_) => return Err(WriteRefusal::NotRecorded),
        };
        let reason = format!("commitment:{}", refusal.wire_name());
        if let Some(claim) = claim {
            self.sequence
                .reject(&store_ledger(at.ledger), claim, &reason, at.now_ms)
                .await
                .map_err(|_| WriteRefusal::NotRecorded)?;
        }
        Err(WriteRefusal::Rejected(reason))
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
        let claims = self.claims(&at, &admitted).await?;
        let mut pending = admitted.pending;
        pending.end_claims(claims);
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
