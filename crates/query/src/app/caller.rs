//! Naming the caller of a request (C-9, E-7, SEC-18, T-28; Access OP-149 m.19 (g), m.31 (a), m.34): the `DPoP` access token's issuer must be a live realm of an active tenant of Work's region, the token verifies under that realm's token keys and names Work, its `access_tenant` is that realm's tenant, the proof binds it to this request once, and Access resolves its pairwise `sub` to the `PartyID`: in the sector of the token's client for a user's token, in Work's own for a platform product's or a tenant API client's service token, which may also name an API client without a Party. Every call to Access runs under a bound; when Access does not answer, the request is `authority_unverifiable` and no caller is named.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::timeout;
use work_access_client::app::Client;
use work_access_client::domain::AccessError;
use work_access_client::domain::discovery::Issuer;
use work_access_client::domain::token::{
    ProofRules, TokenRules, unverified, verify_access_token, verify_proof,
};
use work_access_client::ports::{Clock, Transport};

use crate::domain::caller::{
    Caller, CallerRefusal, Presented, REPLAY_ENTRIES, ReplayCache, dpop_token, party_of,
    same_tenant, sector,
};
use crate::ports::{Authenticate, Pending};

/// The bound of one call to Access on a request's path (T-32 rule 7; PD).
pub const ACCESS_BOUND: Duration = Duration::from_secs(5);

/// Names callers from their Access tokens, over the Access client.
pub struct Authenticator<T, C> {
    access: Arc<Client<T, C>>,
    audience: Option<String>,
    replay: Mutex<ReplayCache>,
}

impl<T, C> std::fmt::Debug for Authenticator<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

fn unverifiable(error: &AccessError) -> CallerRefusal {
    match error {
        AccessError::Transport(_) | AccessError::Timeout | AccessError::Unavailable { .. } => {
            CallerRefusal::Unverifiable("access_unreachable")
        }
        AccessError::Stale => CallerRefusal::Unverifiable("access_stale"),
        AccessError::Unserved(_) => CallerRefusal::Unverifiable("access_unserved"),
        _ => CallerRefusal::Unverifiable("access_answer"),
    }
}

async fn bounded<V>(
    call: impl Future<Output = Result<V, AccessError>>,
) -> Result<V, CallerRefusal> {
    timeout(ACCESS_BOUND, call)
        .await
        .map_err(|_| CallerRefusal::Unverifiable("access_unreachable"))?
        .map_err(|e| unverifiable(&e))
}

impl<T: Transport, C: Clock> Authenticator<T, C> {
    /// Names callers for the audience `audience`, Work's Access `client_id` (T-96 item 3); with
    /// none, every request is `authority_unverifiable`.
    #[must_use]
    pub fn new(access: Arc<Client<T, C>>, audience: Option<String>) -> Self {
        Self {
            access,
            audience: audience.filter(|a| !a.is_empty()),
            replay: Mutex::new(ReplayCache::new(REPLAY_ENTRIES)),
        }
    }

    /// The caller `presented` names.
    ///
    /// # Errors
    /// [`CallerRefusal::Unauthenticated`] for a missing, malformed, foreign, expired or unbound
    /// token, one whose `access_tenant` is not its realm's tenant (`token_tenant`), a proof that
    /// does not fit, a replayed proof, a subject Access does not know or a Party Access
    /// disabled (`party_disabled`, T-102 item 5);
    /// [`CallerRefusal::Unverifiable`] when Access does not answer.
    pub async fn caller(&self, presented: Presented<'_>) -> Result<Caller, CallerRefusal> {
        let token = dpop_token(presented.authorization)?;
        let proof = presented
            .dpop
            .ok_or(CallerRefusal::Unauthenticated("dpop_proof_missing"))?;
        let audience = self
            .audience
            .as_deref()
            .ok_or(CallerRefusal::Unverifiable("audience_unset"))?;
        if self.access.disabled() {
            return Err(CallerRefusal::Unverifiable("client_disabled"));
        }
        let (issuer, kid) = unverified(token)?;
        let realm = bounded(self.access.realm_of(&issuer))
            .await?
            .ok_or(CallerRefusal::Unauthenticated("token_issuer"))?;
        let parsed =
            Issuer::parse(&issuer).map_err(|_| CallerRefusal::Unauthenticated("token_issuer"))?;
        let keys = bounded(self.access.realm_keys(&parsed, &kid)).await?;
        let now_ms = self.access.now_ms();
        let claims = verify_access_token(
            token,
            &keys,
            &TokenRules {
                issuer: &issuer,
                audience,
                now_ms,
            },
        )?;
        let proved = verify_proof(
            proof,
            &ProofRules {
                method: presented.method,
                url: presented.url,
                token,
                jkt: &claims.jkt,
                now_ms,
            },
        )?;
        self.replay
            .lock()
            .map_err(|_| CallerRefusal::Unverifiable("replay_cache"))?
            .admit(claims.jkt, &proved.jti, proved.iat_ms, now_ms)?;
        same_tenant(claims.tenant.as_deref(), &realm.tenant)?;
        let subject = bounded(self.access.subject(
            &realm.tenant,
            &realm.realm,
            sector(claims.kind, &claims.client_id, audience),
            &claims.sub,
        ))
        .await?;
        let party = party_of(subject, claims.kind, &claims.client_id)?;
        if party
            .as_ref()
            .is_some_and(|p| self.access.party_disabled(&realm.tenant, &p.id))
        {
            return Err(CallerRefusal::Unauthenticated("party_disabled"));
        }
        Ok(Caller {
            tenant: realm.tenant,
            realm: realm.realm,
            issuer,
            client_id: claims.client_id,
            kind: claims.kind,
            party,
        })
    }
}

impl<T, C> Authenticate for Authenticator<T, C>
where
    T: Transport + 'static,
    C: Clock + 'static,
{
    fn authenticate<'a>(
        &'a self,
        presented: Presented<'a>,
    ) -> Pending<'a, Result<Caller, CallerRefusal>> {
        Box::pin(self.caller(presented))
    }
}

#[cfg(test)]
mod tests {
    use work_access_client::adapters::{DEFAULT_TIMEOUT, HttpsTransport, public_config, roots};

    use super::*;

    /// A closed port on the loopback address: what a client of an Access that is down reaches.
    const CLOSED: &str = "https://127.0.0.1:1/realms/platform";

    struct At(u64);

    impl Clock for At {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    fn unreachable() -> Authenticator<HttpsTransport, At> {
        let pem = include_bytes!("../../../../deploy/compose/nts/pki/root.pem");
        let tls = public_config(roots(pem).unwrap()).unwrap();
        let client = Client::new(
            HttpsTransport::new(tls, DEFAULT_TIMEOUT),
            At(1_793_793_600_000),
            Issuer::parse(CLOSED).unwrap(),
            "local",
            0,
        );
        Authenticator::new(Arc::new(client), Some("cli_work".to_owned()))
    }

    fn presented<'a>(authorization: Option<&'a str>, dpop: Option<&'a str>) -> Presented<'a> {
        Presented {
            authorization,
            dpop,
            method: "GET",
            url: "https://work.example/v1/ledgers/led_01/changes",
        }
    }

    /// A token whose payload names `iss`, unsigned: only its issuer and key id are read before
    /// Access is asked for the realm.
    fn token(iss: &str) -> String {
        let b64 = work_access_client::domain::b64url;
        let header = b64(format!(
            r#"{{"alg":"ES256","kid":"{}","typ":"at+jwt"}}"#,
            b64(&[1; 32])
        )
        .as_bytes());
        let payload = b64(format!(r#"{{"iss":"{iss}"}}"#).as_bytes());
        format!("{header}.{payload}.{}", b64(&[2; 64]))
    }

    // E-38 T-28 SEC-8 MD-3 E-7
    #[tokio::test]
    async fn e_38_when_access_does_not_answer_no_caller_is_named() {
        let auth = unreachable();
        let token = token("https://access.example/realms/acme");
        let header = format!("DPoP {token}");
        let refused = auth
            .authenticate(presented(Some(&header), Some("proof")))
            .await;
        assert!(
            matches!(refused, Err(CallerRefusal::Unverifiable(_))),
            "{refused:?}"
        );
        let unset = Authenticator::new(Arc::clone(&auth.access), Some(String::new()));
        assert_eq!(
            unset.caller(presented(Some(&header), Some("proof"))).await,
            Err(CallerRefusal::Unverifiable("audience_unset"))
        );
    }

    // T-102
    #[tokio::test]
    async fn t_102_once_access_disables_work_s_client_no_caller_is_named() {
        let auth = unreachable();
        let header = format!("DPoP {}", token("https://access.example/realms/acme"));
        auth.access.disable().unwrap();
        assert_eq!(
            auth.caller(presented(Some(&header), Some("proof"))).await,
            Err(CallerRefusal::Unverifiable("client_disabled"))
        );
        assert_eq!(
            auth.caller(presented(None, Some("proof"))).await,
            Err(CallerRefusal::Unauthenticated("token_missing"))
        );
    }

    // E-5 E-6 INV-30 E-7
    #[test]
    fn e_5_no_client_or_product_has_a_path_of_its_own_to_a_caller() {
        let sources = [
            include_str!("caller.rs"),
            include_str!("../domain/caller.rs"),
            include_str!("../../../http/src/reads.rs"),
        ];
        for source in sources {
            let code = source.split("#[cfg(test)]").next().unwrap_or_default();
            for line in code.lines().map(str::trim).filter(|l| !l.starts_with("//")) {
                for named in ["client_id ==", "client_id !=", "\"cli_", "x5t", "peer_addr"] {
                    assert!(!line.contains(named), "{line}");
                }
                for product in ["\"one\"", "\"relay\"", "\"pay\"", "\"executor\""] {
                    assert!(!line.to_ascii_lowercase().contains(product), "{line}");
                }
            }
        }
    }

    // SEC-18 E-7 T-10
    #[tokio::test]
    async fn sec_18_a_request_without_a_dpop_token_and_proof_names_no_caller_and_asks_nothing() {
        let auth = unreachable();
        let token = token("https://access.example/realms/acme");
        let dpop = format!("DPoP {token}");
        let bearer = format!("Bearer {token}");
        for (authorization, proof, code) in [
            (None, Some("proof"), "token_missing"),
            (Some(bearer.as_str()), Some("proof"), "token_scheme"),
            (Some(dpop.as_str()), None, "dpop_proof_missing"),
            (Some("DPoP not-a-jwt"), Some("proof"), "token_format"),
        ] {
            assert_eq!(
                auth.caller(presented(authorization, proof)).await,
                Err(CallerRefusal::Unauthenticated(code)),
                "{code}"
            );
        }
    }
}
