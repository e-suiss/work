//! The commitment Declaration write path (P-13, P-21, P-105, P-116, P-12, E-13, E-14, E-45, MD-4 item 5, OP-8, T-28, T-101 item 7): the caller is named by Access first; the `Idempotency-Key` and `If-Match` are decided against the ledger's canonical rows; then every Access answer the record depends on is asked online under a bound, never from a cache that outlives Access's own rules: the realm's governing domain from Work's pairing, the signing key's binding through the signed key lookup or the realm keys of an `auth_context` artifact, and the Exercise with its decision receipt. Only then does the kernel admit the record, with the receipt kept as received beside it, and the ledger's writer commit it. When Access cannot answer, nothing is written (fail-closed).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;

use tokio::time::timeout;
use work_access_client::app::{Client, Looked};
use work_access_client::domain::AccessError;
use work_access_client::domain::discovery::Issuer;
use work_access_client::domain::exercise::{Intent, VerifiedExercise};
use work_access_client::domain::keys::{AsOf, DomainId, KernelId, Kid};
use work_access_client::ports::{Clock, PartyKinds, Transport};
use work_kernel::codec::{Decoded, decode_record, record_id};
use work_kernel::cose::{AuthorKeys, KeySet, parse_container};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId};
use work_kernel::items::{ItemKey, touched};
use work_kernel::limits::SemanticLimits;
use work_kernel::record::{AuthorityProofKind, Record};
use work_kernel::validate::{ActorType, Origin};
use work_ledger::{
    ActorBindings, AdmitError, Arrival, AuthContext, Committed, Declared, DeclaredActors, KeyClaim,
    Ledgers, PendingRecord, Submission, SubmitError, admit,
};
use work_store::{
    AccessPool, CallerRef, IdempotencyDecision, ItemRef, LedgerTx, Pool, RealmState, StoreError,
    StoredOutcome,
};

use crate::app::caller::ACCESS_BOUND;
use crate::domain::caller::Caller;
use crate::domain::writes::{
    AuthContextGiven, AuthorityGiven, DeclarationRequest, WriteRefusal, Written, actor_type,
    check_authority, check_intent, commit_operation, header_kid, party_ref, signer,
};
use crate::ports::{Pending, RecordWrites, Sequence};

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
}

/// The write path over the Access client, the canonical rows read as `work_app`, Work's
/// pairing rows and the ledgers' writers.
pub struct Writes<T, C, P> {
    access: Arc<Client<T, C>>,
    audience: Option<String>,
    canonical: Pool,
    realms: AccessPool,
    sequence: Arc<dyn Sequence>,
    parties: P,
}

impl<T, C, P> std::fmt::Debug for Writes<T, C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writes")
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

fn unverifiable(error: &AccessError) -> WriteRefusal {
    WriteRefusal::Unverifiable(match error {
        AccessError::Transport(_) | AccessError::Timeout | AccessError::Unavailable { .. } => {
            "access_unreachable"
        }
        AccessError::Stale => "access_stale",
        AccessError::Unserved(_) => "access_unserved",
        AccessError::Expired => "pep_certificate_expired",
        AccessError::Disabled => "client_disabled",
        _ => "access_answer",
    })
}

async fn bounded<V>(call: impl Future<Output = Result<V, AccessError>>) -> Result<V, AccessError> {
    timeout(ACCESS_BOUND, call)
        .await
        .map_err(|_| AccessError::Timeout)?
}

fn store_ledger(ledger: &LedgerId) -> work_store::LedgerId {
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

fn submit_refusal(error: SubmitError) -> WriteRefusal {
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

fn admit_refusal(error: AdmitError) -> WriteRefusal {
    match error {
        AdmitError::Rejected(reason) => WriteRefusal::Rejected(reason.to_string()),
        AdmitError::AuthContext(invalid) => WriteRefusal::AuthContext(invalid.to_string()),
    }
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
    if version != request.if_match {
        return Err(WriteRefusal::PreconditionFailed);
    }
    Ok(Precheck::Fresh(KeyClaim {
        caller: caller.clone(),
        key,
        request_digest: request.digest,
    }))
}

/// What the ledger's rows decide before Access is asked.
enum Precheck {
    /// A new request under this key.
    Fresh(KeyClaim),
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
/// ledger and valid now (E-45, P-13).
fn authority_of<'a>(
    record: &Record,
    request: &'a DeclarationRequest,
    ledger: &LedgerId,
    now_ms: u64,
) -> Result<(&'a AuthorityGiven, Intent), WriteRefusal> {
    if !commit_operation(record) {
        return Err(WriteRefusal::Invalid("operation"));
    }
    if record.core().authority.is_none() {
        return Err(WriteRefusal::Rejected("authority_missing".to_owned()));
    }
    let given = request
        .authority
        .as_ref()
        .ok_or(WriteRefusal::Invalid("authority"))?;
    let intent = Intent::from_bytes(&given.intent).map_err(|_| WriteRefusal::Invalid("intent"))?;
    check_intent(&intent, ledger, now_ms).map_err(WriteRefusal::Denied)?;
    Ok((given, intent))
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
    /// Writes over `access`, whose receipts name `audience`, Work's Access `client_id`; with
    /// none, every write is `authority_unverifiable`.
    #[must_use]
    pub fn new(
        access: Arc<Client<T, C>>,
        audience: Option<String>,
        canonical: Pool,
        realms: AccessPool,
        sequence: Arc<dyn Sequence>,
        parties: P,
    ) -> Self {
        Self {
            access,
            audience: audience.filter(|a| !a.is_empty()),
            canonical,
            realms,
            sequence,
            parties,
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

    /// The governing domain of the caller's realm and the realms of its tenant Work is paired
    /// with (P-115 item 2).
    async fn realm(&self, caller: &Caller) -> Result<(DomainId, BTreeSet<String>), WriteRefusal> {
        let rows = self
            .realms
            .realms(caller.tenant.as_str())
            .await
            .map_err(|_| WriteRefusal::Unverifiable("realm_unreadable"))?;
        let paired: BTreeSet<String> = rows
            .iter()
            .filter(|r| r.state == RealmState::Paired)
            .map(|r| r.realm.clone())
            .collect();
        let domain = rows
            .iter()
            .find(|r| r.realm == caller.realm && r.state == RealmState::Paired)
            .and_then(|r| r.domain)
            .ok_or(WriteRefusal::Unverifiable("realm_unpaired"))?;
        Ok((DomainId(domain), paired))
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
    ) -> Result<PendingRecord, WriteRefusal> {
        let record = &at.carried.record;
        if record.core().author != at.caller.party {
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
        };
        let none = KeySet::default();
        let verifier = AuthorKeys {
            author: &record.core().author,
            keys: &none,
        };
        admit(&verifier, &store_ledger(at.ledger), submission).map_err(admit_refusal)
    }

    /// Admits a signed record against the key Access binds to its `kid` now, whose Party's
    /// `actor_kind` is the author's actor type (P-21 item 1, P-105, P-12, SEC-19).
    async fn signed(
        &self,
        at: &Admission<'_>,
        claim: Option<KeyClaim>,
    ) -> Result<PendingRecord, WriteRefusal> {
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
        };
        admit(&verifier, &store_ledger(at.ledger), submission).map_err(admit_refusal)
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
        let caller_ref = CallerRef::new(caller.party.as_str())
            .ok_or(WriteRefusal::Unverifiable("access_answer"))?;
        let claim = match self
            .precheck(&caller_ref, ledger, record, request, now_ms)
            .await?
        {
            Precheck::Fresh(claim) => Some(claim),
            Precheck::Done(answer) => return answer,
        };
        let (given, intent) = authority_of(record, request, ledger, now_ms)?;
        let (domain, paired) = self.realm(caller).await?;
        let exercise = self.exercise(domain, given, &intent, audience).await?;
        check_authority(record.core(), &exercise).map_err(WriteRefusal::Denied)?;
        let at = Admission {
            caller,
            ledger,
            request,
            declared: declared(record, request)?,
            carried: &carried,
            domain,
            paired: &paired,
            now_ms,
        };
        let mut pending = match &request.auth_context {
            Some(given) => self.unsigned(&at, given, claim).await?,
            None => self.signed(&at, claim).await?,
        };
        pending
            .keep_authority_proof(AuthorityProofKind::DecisionReceipt, &exercise.receipt)
            .map_err(|_| WriteRefusal::Denied("authority_digest"))?;
        let committed = self
            .sequence
            .submit(&store_ledger(ledger), pending)
            .await
            .map_err(submit_refusal)?;
        Ok(Written {
            record: record_id(&carried.bytes),
            pos: committed.pos,
            replayed: false,
        })
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
