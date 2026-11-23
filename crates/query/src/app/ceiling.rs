//! The attention of an `agent.ceiling_exceeded` event (E-23, P-114 item 2): the tenant's Work service system Party, from the first paired realm of the tenant that names one, writes the `observation` Claim of [`crate::domain::ceiling`] with `origin = automation` into the ledger that holds the record the event's `correlationid` names, signed with `work-access-service` in the PKCS#11 token and admitted through the kernel like any signed record. Without that record nothing is written and the caller logs it; a second write of the same bytes is the record already present.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use suiss_crypto::cose::{Algorithm, PublicKey};
use suiss_crypto::signer::{Signer, sign_sign1};
use work_access_client::domain::keys::KernelId;
use work_access_client::domain::metadata::thumbprint;
use work_kernel::cose::{AuthorKeys, CONTENT_TYPE, KeySet};
use work_kernel::id::{Digest, LedgerId};
use work_kernel::limits::SemanticLimits;
use work_kernel::validate::{ActorType, Origin};
use work_ledger::{
    ActorBindings, Arrival, Declared, DeclaredActors, Submission, SubmitError, admit,
};
use work_store::{AccessPool, LedgerTx, Pool, RealmState, StoreError};

use crate::domain::ceiling::{NoticeInput, NoticeRefusal, basis_of, notice_record, rests_on};
use crate::domain::writes::party_ref;
use crate::ports::Sequence;

/// The event type of the attention's outbox pointers.
const NOTICE_EVENT: &str = "work.updated";

/// The Relay event the attention answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeilingEvent {
    /// The tenant, `tnt_…`.
    pub tenant: String,
    /// The event's `id`.
    pub id: String,
    /// The event's `source`.
    pub source: String,
    /// The event's `correlationid`.
    pub correlation: Option<String>,
    /// The agent, `agt_…`.
    pub agent: Option<String>,
}

/// What became of the attention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Raised {
    /// Written into the ledger at this position.
    Written([u8; 32], u64),
    /// The ledger already holds it.
    Present([u8; 32]),
}

/// Why no attention was written.
#[derive(Debug, thiserror::Error)]
pub enum CeilingError {
    /// No paired realm of the tenant names Work's service Party.
    #[error("no service Party for the tenant")]
    Unpaired,
    /// No ledger of the tenant holds the record the event names (P-114 item 2).
    #[error("no record of Work to rest on")]
    Basis,
    /// The event cannot carry the attention.
    #[error(transparent)]
    Refused(#[from] NoticeRefusal),
    /// A store read failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The attention could not be signed.
    #[error("attention not signed: {0}")]
    Record(String),
    /// The kernel did not admit it.
    #[error("attention not admitted: {0}")]
    Admit(String),
    /// The ledger's writer did not commit it.
    #[error("attention not committed: {0}")]
    Submit(String),
}

/// The attention writer over Work's pairing rows, the canonical rows, the ledgers this process
/// leads and the service key.
pub struct Ceilings<K> {
    canonical: Pool,
    realms: AccessPool,
    sequence: Arc<dyn Sequence>,
    service: Arc<K>,
}

impl<K> std::fmt::Debug for Ceilings<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ceilings").finish_non_exhaustive()
    }
}

fn present(error: &SubmitError) -> bool {
    matches!(error, SubmitError::Refused(StoreError::RecordExists))
}

impl<K: Signer + Send + Sync + 'static> Ceilings<K> {
    /// A writer over `canonical` as `work_app`, `realms` as `work_access`, `sequence` and the
    /// `work-access-service` key `service`.
    #[must_use]
    pub fn new(
        canonical: Pool,
        realms: AccessPool,
        sequence: Arc<dyn Sequence>,
        service: Arc<K>,
    ) -> Self {
        Self {
            canonical,
            realms,
            sequence,
            service,
        }
    }

    async fn rested(
        &self,
        tenant: &str,
        record: &[u8; 32],
    ) -> Result<Option<([u8; 32], Vec<u8>)>, CeilingError> {
        for ledger in self.realms.tenant_ledgers(tenant).await? {
            let store = work_store::LedgerId::from_bytes(ledger);
            let mut tx = LedgerTx::begin_snapshot(&self.canonical, &store).await?;
            let found = tx.record_bytes(record).await;
            let _closed = tx.rollback().await;
            if let Some(bytes) = found? {
                return Ok(Some((ledger, bytes)));
            }
        }
        Ok(None)
    }

    /// Writes the attention of `event`, taken at `now_ms`.
    ///
    /// # Errors
    /// [`CeilingError`].
    pub async fn raise(&self, event: &CeilingEvent, now_ms: u64) -> Result<Raised, CeilingError> {
        let basis = event
            .correlation
            .as_deref()
            .and_then(basis_of)
            .ok_or(CeilingError::Basis)?;
        let author = self
            .realms
            .realms(&event.tenant)
            .await?
            .into_iter()
            .filter(|r| r.state == RealmState::Paired)
            .find_map(|r| r.party.and_then(|p| party_ref(&KernelId(p))))
            .ok_or(CeilingError::Unpaired)?;
        let (ledger, bytes) = self
            .rested(&event.tenant, basis.0.as_bytes())
            .await?
            .ok_or(CeilingError::Basis)?;
        let (owner, concerns) = rests_on(&bytes).ok_or(CeilingError::Basis)?;
        let input = NoticeInput {
            author: author.clone(),
            ledger: LedgerId(Digest::sha256(ledger)),
            basis,
            audience: Some(owner),
            concerns,
            event: event.id.clone(),
            source: event.source.clone(),
            agent: event.agent.clone(),
            at_ms: now_ms,
        };
        let record = notice_record(&input)?;
        let key = self.service.public_key();
        let kid = thumbprint(&key);
        let cose = sign_sign1(self.service.as_ref(), kid, CONTENT_TYPE, &record)
            .map_err(|e| CeilingError::Record(e.to_string()))?;
        let mut keys = KeySet {
            keys: BTreeMap::new(),
            allowed: BTreeSet::from([Algorithm::Ed25519]),
        };
        if !matches!(key, PublicKey::Ed25519(_)) || keys.insert(kid, key).is_err() {
            return Err(CeilingError::Record("service key".to_owned()));
        }
        let mut bindings = ActorBindings::new();
        bindings
            .bind(author.clone(), ActorType::System)
            .map_err(|_| CeilingError::Record("binding".to_owned()))?;
        let declared = DeclaredActors {
            author: Declared {
                party: author.clone(),
                actor_type: ActorType::System,
            },
            on_behalf_of: Vec::new(),
            evidence: Vec::new(),
        };
        let submission = Submission {
            arrival: Arrival::Signed(&cose),
            declared: &declared,
            bindings: &bindings,
            origin: Origin::Automation,
            understood_extensions: &[],
            limits: SemanticLimits::default(),
            event_type: NOTICE_EVENT,
            traceparent: "",
            idempotency: None,
            inbound: None,
            areas: None,
        };
        let verifier = AuthorKeys {
            author: &author,
            keys: &keys,
        };
        let store = work_store::LedgerId::from_bytes(ledger);
        let mut pending =
            admit(&verifier, &store, submission).map_err(|e| CeilingError::Admit(e.to_string()))?;
        pending.for_tenant(&event.tenant);
        match self.sequence.submit(&store, pending).await {
            Ok(committed) => Ok(Raised::Written(ledger, committed.pos)),
            Err(e) if present(&e) => Ok(Raised::Present(ledger)),
            Err(e) => Err(CeilingError::Submit(e.to_string())),
        }
    }
}
