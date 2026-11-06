//! The SEC-36 compromise window notice (WD-123): for a `party.compromised` event, the Work service system Party of the event's domain, read from Work's pairing rows, writes one `observation` Claim into every ledger of the tenant that holds a record of the window, signed with `work-access-service` in the PKCS#11 token and admitted through the kernel like any signed record; a ledger that already holds the notice of the event is skipped, and a second delivery of the event writes nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use suiss_crypto::cose::{Algorithm, PublicKey};
use suiss_crypto::signer::{Signer, sign_sign1};
use work_access_client::domain::events::Compromise;
use work_access_client::domain::keys::KernelId;
use work_access_client::domain::metadata::thumbprint;
use work_kernel::compromise::{NoticeInput, notice_record};
use work_kernel::cose::{AuthorKeys, CONTENT_TYPE, KeySet};
use work_kernel::limits::SemanticLimits;
use work_kernel::validate::{ActorType, Origin};
use work_ledger::{
    ActorBindings, Arrival, Declared, DeclaredActors, Submission, SubmitError, admit,
};
use work_store::{AccessPool, LedgerTx, Pool, StoreError};

use crate::domain::notices::{Unplannable, plan};
use crate::domain::writes::party_ref;
use crate::ports::Sequence;

/// The event type of the notice's outbox pointers; it touches no item, so it has none.
const NOTICE_EVENT: &str = "work.updated";

/// What became of the notice in one ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Noticed {
    /// Written at this position.
    Written([u8; 32], u64),
    /// The ledger already holds the notice of the event.
    Present([u8; 32]),
}

/// Why the notices of an event were not all written.
#[derive(Debug, thiserror::Error)]
pub enum NoticeError {
    /// No paired realm of the event's domain names Work's service Party.
    #[error("no service Party for the domain")]
    Unpaired,
    /// The event cannot carry a notice.
    #[error(transparent)]
    Unplannable(#[from] Unplannable),
    /// A store read failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The notice could not be written or signed.
    #[error("notice not written: {0}")]
    Record(String),
    /// The kernel did not admit the notice.
    #[error("notice not admitted: {0}")]
    Admit(String),
    /// The ledger's writer did not commit it.
    #[error("notice not committed: {0}")]
    Submit(String),
}

/// The notice writer over Work's pairing rows, the canonical rows, the ledgers this process
/// leads and the service key.
pub struct Notices<K> {
    canonical: Pool,
    realms: AccessPool,
    sequence: Arc<dyn Sequence>,
    service: Arc<K>,
}

impl<K> std::fmt::Debug for Notices<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notices").finish_non_exhaustive()
    }
}

fn store_ledger(ledger: [u8; 32]) -> work_store::LedgerId {
    work_store::LedgerId::from_bytes(ledger)
}

fn present(error: &SubmitError) -> bool {
    match error {
        SubmitError::Refused(StoreError::RecordExists) => true,
        SubmitError::Refused(StoreError::Constraint(c)) => c == "compromise_notice_pk",
        _ => false,
    }
}

impl<K: Signer + Send + Sync + 'static> Notices<K> {
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

    /// Writes the notice of `compromise` into every ledger of its tenant that holds a record of
    /// its window, in ledger order.
    ///
    /// # Errors
    /// [`NoticeError`]; the notices written before it stay.
    pub async fn write(&self, compromise: &Compromise) -> Result<Vec<Noticed>, NoticeError> {
        let realm = self
            .realms
            .realm_of_domain(&compromise.domain.0)
            .await?
            .filter(|r| r.tenant == compromise.tenant.as_str())
            .ok_or(NoticeError::Unpaired)?;
        let author = realm
            .party
            .and_then(|p| party_ref(&KernelId(p)))
            .ok_or(NoticeError::Unpaired)?;
        let kids: Vec<[u8; 32]> = compromise.kids.iter().map(|k| k.0).collect();
        let hits = self
            .realms
            .window_ledgers(
                compromise.tenant.as_str(),
                &kids,
                &compromise.party,
                compromise.window.0,
                compromise.window.1,
            )
            .await?;
        let mut out = Vec::new();
        for input in plan(compromise, &author, &hits)? {
            out.push(self.write_one(&compromise.tenant, &input).await?);
        }
        Ok(out)
    }

    async fn write_one(
        &self,
        tenant: &work_proto::id::TenantId,
        input: &NoticeInput,
    ) -> Result<Noticed, NoticeError> {
        let ledger = *input.ledger.0.as_bytes();
        let mut tx = LedgerTx::begin_snapshot(&self.canonical, &store_ledger(ledger)).await?;
        let held = tx.has_notice(&input.window.event_digest).await;
        let _closed = tx.rollback().await;
        if held? {
            return Ok(Noticed::Present(ledger));
        }
        let bytes = notice_record(input).map_err(|e| NoticeError::Record(e.to_string()))?;
        let key = self.service.public_key();
        let kid = thumbprint(&key);
        let cose = sign_sign1(self.service.as_ref(), kid, CONTENT_TYPE, &bytes)
            .map_err(|e| NoticeError::Record(e.to_string()))?;
        let mut keys = KeySet {
            keys: BTreeMap::new(),
            allowed: BTreeSet::from([Algorithm::Ed25519]),
        };
        if !matches!(key, PublicKey::Ed25519(_)) || keys.insert(kid, key).is_err() {
            return Err(NoticeError::Record("service key".to_owned()));
        }
        let mut bindings = ActorBindings::new();
        bindings
            .bind(input.author.clone(), ActorType::System)
            .map_err(|_| NoticeError::Record("binding".to_owned()))?;
        let declared = DeclaredActors {
            author: Declared {
                party: input.author.clone(),
                actor_type: ActorType::System,
            },
            on_behalf_of: Vec::new(),
            evidence: Vec::new(),
        };
        let submission = Submission {
            arrival: Arrival::Signed(&cose),
            declared: &declared,
            bindings: &bindings,
            origin: Origin::Direct,
            understood_extensions: &[],
            limits: SemanticLimits::default(),
            event_type: NOTICE_EVENT,
            traceparent: "",
            idempotency: None,
            inbound: None,
        };
        let verifier = AuthorKeys {
            author: &input.author,
            keys: &keys,
        };
        let mut pending = admit(&verifier, &store_ledger(ledger), submission)
            .map_err(|e| NoticeError::Admit(e.to_string()))?;
        pending.for_tenant(tenant.as_str());
        match self.sequence.submit(&store_ledger(ledger), pending).await {
            Ok(committed) => Ok(Noticed::Written(ledger, committed.pos)),
            Err(e) if present(&e) => Ok(Noticed::Present(ledger)),
            Err(e) => Err(NoticeError::Submit(e.to_string())),
        }
    }
}
