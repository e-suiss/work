//! The authority request of a `work:commit` (T-101 item 2 and its note, E-7, E-17, P-13, P-116 item 6, T-28): Work's PEP commits the caller's intent at Access's decision point over its certificate, only after it checked that the intent is the `work:commit` of an existing ledger valid now and that the caller's own device Instance stated exactly that commit to Work's PEP in the caller's realm's governing domain. An allowed Exercise is returned only with its decision receipt verified for the intent and addressed to Work's PEP; a `REQUIRE_ACTION` is returned with the step-up Access names and, when Access asks for an approval, with the typed authority request and, given the approver's pre-signed contribution, the Approval Surface URL of the pushed request. Work approves nothing on the caller's behalf. When Access cannot answer, nothing is returned as authority (fail-closed).

use std::sync::Arc;

use work_access_client::app::Client;
use work_access_client::domain::AccessError;
use work_access_client::domain::adp::{
    AuthorityRequest, Decision, Evaluation, Statement, denial_code, needs_approval, step_up,
    valid_reason,
};
use work_access_client::domain::approval::{ApprovalRequest, State as ApprovalState};
use work_access_client::domain::b64url;
use work_access_client::domain::discovery::Issuer;
use work_access_client::domain::exercise::{Capacity, Intent};
use work_access_client::ports::{Clock, Transport};
use work_kernel::id::LedgerId;
use work_store::{AccessPool, LedgerTx, Pool};

use crate::app::writes::{bounded, caller_realm, store_ledger, unverifiable};
use crate::domain::authority::{
    Approval, AuthorityAnswer, AuthorityAsk, approval_state, expires_at, forwarded_key,
};
use crate::domain::caller::Caller;
use crate::domain::writes::{WriteRefusal, check_intent};
use crate::ports::{AuthorityRequests, Pending};

/// The authority requests over the Access client, the canonical rows read as `work_app` and
/// Work's pairing rows.
pub struct Authorities<T, C> {
    access: Arc<Client<T, C>>,
    audience: Option<String>,
    canonical: Pool,
    realms: AccessPool,
    redirect_uri: String,
}

impl<T, C> std::fmt::Debug for Authorities<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorities")
            .field("audience", &self.audience)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

fn refused_call(error: &AccessError, code: &'static str) -> WriteRefusal {
    match error {
        AccessError::Refused { status, .. } if (400..500).contains(status) => {
            WriteRefusal::Denied(code)
        }
        other => unverifiable(other),
    }
}

fn exercise_refusal(error: &AccessError) -> WriteRefusal {
    match error {
        AccessError::Refused { status: 404, .. } => WriteRefusal::Denied("exercise_unknown"),
        AccessError::Answer(code) => WriteRefusal::Denied(code),
        other => unverifiable(other),
    }
}

impl<T, C> Authorities<T, C>
where
    T: Transport + 'static,
    C: Clock + 'static,
{
    /// Requests over `access`, whose decisions name `audience`, the `x5t#S256` of Work's PEP
    /// certificate; with none, every request is `authority_unverifiable`. `redirect_uri` is the
    /// URI registered for Work's client that the Approval Surface sends the browser back to,
    /// `<origin>/v1/access/approval` (T-101 item 7).
    #[must_use]
    pub fn new(
        access: Arc<Client<T, C>>,
        audience: Option<String>,
        canonical: Pool,
        realms: AccessPool,
        redirect_uri: String,
    ) -> Self {
        Self {
            access,
            audience: audience.filter(|a| !a.is_empty()),
            canonical,
            realms,
            redirect_uri,
        }
    }

    async fn exists(&self, ledger: &LedgerId) -> Result<(), WriteRefusal> {
        let mut tx = LedgerTx::begin_snapshot(&self.canonical, &store_ledger(ledger))
            .await
            .map_err(|_| WriteRefusal::NotRecorded)?;
        let head = tx.head().await;
        let _closed = tx.rollback().await;
        match head {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(WriteRefusal::NotFound),
            Err(_) => Err(WriteRefusal::NotRecorded),
        }
    }

    async fn push(
        &self,
        caller: &Caller,
        party: &str,
        request: &serde_json::Value,
        contribution: &serde_json::Value,
        key: &str,
    ) -> Result<Approval, WriteRefusal> {
        let realm = Issuer::parse(&caller.issuer)
            .map_err(|_| WriteRefusal::Unverifiable("access_answer"))?;
        if !contribution.is_object() {
            return Err(WriteRefusal::Invalid("contribution"));
        }
        let pushed = bounded(self.access.push_approval(
            &realm,
            request,
            contribution,
            &forwarded_key("push", party, key),
        ))
        .await
        .map_err(|e| refused_call(&e, "approval_refused"))?;
        let state = ApprovalState::new(&approval_state(party, &pushed.digest))
            .map_err(|_| WriteRefusal::Unverifiable("access_answer"))?;
        let url = bounded(self.access.approval_url(
            &realm,
            &ApprovalRequest::Pushed(pushed.request_uri.clone()),
            &self.redirect_uri,
            &state,
        ))
        .await
        .map_err(|e| unverifiable(&e))?;
        Ok(Approval {
            url,
            request_uri: pushed.request_uri,
            expires_at: pushed.expires_at,
        })
    }

    async fn ask(
        &self,
        caller: &Caller,
        ledger: &LedgerId,
        ask: &AuthorityAsk,
    ) -> Result<AuthorityAnswer, WriteRefusal> {
        let audience = self
            .audience
            .as_deref()
            .ok_or(WriteRefusal::Unverifiable("audience_unset"))?;
        if !valid_reason(&ask.reason) {
            return Err(WriteRefusal::Invalid("reason"));
        }
        if !(16..=64).contains(&ask.nonce.len()) {
            return Err(WriteRefusal::Invalid("nonce"));
        }
        let now_ms = self.access.now_ms();
        let intent =
            Intent::from_bytes(&ask.intent).map_err(|_| WriteRefusal::Invalid("intent"))?;
        check_intent(&intent, ledger, now_ms).map_err(WriteRefusal::Denied)?;
        self.exists(ledger).await?;
        let (domain, _) = caller_realm(&self.realms, caller).await?;
        let statement = Statement {
            domain: &domain,
            nonce: &ask.nonce,
            intent: &intent.digest,
            pep: audience,
            capacity: Capacity::Own,
            basis: ask.basis,
        };
        statement.check(&ask.ais, now_ms).map_err(|e| match e {
            AccessError::Answer(code) => WriteRefusal::Invalid(code),
            _ => WriteRefusal::Invalid("ais"),
        })?;
        let party = b64url(&caller.party_id);
        let body = Evaluation {
            party: &party,
            intent: &ask.intent,
            statement: statement.clone(),
            ais: &ask.ais,
            contributions: &ask.contributions,
        }
        .body()
        .map_err(|_| WriteRefusal::Invalid("intent"))?;
        let key = forwarded_key("evaluation", &party, &ask.idempotency_key);
        let decision = bounded(self.access.evaluate(body, &key))
            .await
            .map_err(|e| refused_call(&e, "evaluation_refused"))?;
        match decision {
            Decision::Allow { exercise, receipt } => {
                let receipt = receipt.as_ref().map(|(s, e)| (s.as_slice(), e.as_slice()));
                let verified = bounded(
                    self.access
                        .allowed(domain, &exercise, receipt, &intent, audience),
                )
                .await
                .map_err(|e| exercise_refusal(&e))?;
                Ok(AuthorityAnswer::Allowed(Box::new(verified)))
            }
            Decision::Deny { blockers } => Err(WriteRefusal::Denied(denial_code(&blockers))),
            Decision::RequireAction { unmet, .. } => {
                let request = if needs_approval(&unmet) {
                    Some(
                        AuthorityRequest {
                            party: &party,
                            intent: &ask.intent,
                            statement,
                            reason: &ask.reason,
                            expires_at_ms: expires_at(now_ms, intent.valid_until_ms),
                        }
                        .json()
                        .map_err(|_| WriteRefusal::Invalid("reason"))?,
                    )
                } else {
                    None
                };
                let approval = match (&request, &ask.contribution) {
                    (Some(r), Some(c)) => Some(
                        self.push(caller, &party, r, c, &ask.idempotency_key)
                            .await?,
                    ),
                    _ => None,
                };
                Ok(AuthorityAnswer::RequireAction {
                    step_up: step_up(&unmet),
                    unmet,
                    request,
                    approval,
                })
            }
        }
    }
}

impl<T, C> AuthorityRequests for Authorities<T, C>
where
    T: Transport + 'static,
    C: Clock + 'static,
{
    fn request<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        ask: &'a AuthorityAsk,
    ) -> Pending<'a, Result<AuthorityAnswer, WriteRefusal>> {
        Box::pin(self.ask(caller, ledger, ask))
    }
}
