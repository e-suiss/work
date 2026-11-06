//! Work's credential for Relay (T-99 item 4, Relay E-93; Access A28 (a)): the Access service token for Relay's Access `client_id` with a fresh `DPoP` proof per call, from [`ServiceTokens`]. A token Access cannot give now is a missing credential, so the intent stays in the outbox (T-28); a token Relay answers `401` is dropped and asked for again on the next call.

use suiss_crypto::signer::Signer;
use work_access_client::app::service::ServiceTokens;
use work_access_client::ports::{Clock, Random, Transport};
use work_relay_client::domain::answer::RelayError;
use work_relay_client::ports::{Authorization, Credential};

/// The Relay credential over Work's service tokens for Relay.
#[derive(Debug)]
pub struct RelayCredential<T, C, R, K, D>(pub ServiceTokens<T, C, R, K, D>);

impl<T, C, R, K, D> Credential for RelayCredential<T, C, R, K, D>
where
    T: Transport,
    C: Clock,
    R: Random,
    K: Signer + Send + Sync,
    D: Signer + Send + Sync,
{
    async fn authorize(&self, method: &str, url: &str) -> Result<Authorization, RelayError> {
        let headers = self
            .0
            .authorize(method, url)
            .await
            .map_err(|e| RelayError::Credential(e.to_string()))?;
        Ok(Authorization {
            authorization: headers.authorization,
            dpop: headers.dpop,
        })
    }

    fn rejected(&self) {
        if let Err(error) = self.0.forget() {
            tracing::warn!(
                event = "relay.credential_kept",
                %error,
                "the refused token could not be dropped"
            );
        }
    }
}
