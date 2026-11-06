//! The REST routes of the process (P-53, P-56, T-97, WD-115): the public ones always, and those that act for a caller once `[api] origin` is set and the read position keys open in the `[access]` token (T-56). The caller is named over the process's Access client with Work's `client_id` as `aud`, an authority request is committed at Access's decision point through the same client and its PEP certificate, and a commitment Declaration is written through the same client, Work's pairing rows and the ledgers this process leads, under a decision receipt addressed to the process's PEP certificate (P-13); while those routes cannot be served this is logged, and the public ones keep answering.

use std::sync::Arc;

use suiss_crypto::pkcs11::KeyStore;
use work_http::api::{ApiConfig, router, router_with};
use work_http::common::TraceIds;
use work_http::reads::ApiServices;
use work_query::adapters::PositionKeys;
use work_query::app::authority::Authorities;
use work_query::app::caller::Authenticator;
use work_query::app::reads::Reads;
use work_query::app::writes::Writes;
use work_query::ports::Sequence;
use work_store::{AccessPool, Pool};

use crate::config::Config;
use crate::startup::{AccessClient, read_pin};

/// What the routes that act for a caller are built from.
pub(crate) struct Backing<'a> {
    /// The canonical database as `work_app`.
    pub(crate) canonical: &'a Pool,
    /// Work's pairing rows.
    pub(crate) realms: &'a AccessPool,
    /// The process's Access client.
    pub(crate) access: &'a Arc<AccessClient>,
    /// The `x5t#S256` of the PEP certificate, the audience of Access's decision receipts.
    pub(crate) pep: Option<&'a str>,
    /// The ledgers this process leads.
    pub(crate) sequence: Arc<dyn Sequence>,
}

fn services(config: &Config, backing: &Backing<'_>) -> Result<ApiServices, String> {
    if config.api.origin.is_empty() {
        return Err("api.origin is not set".to_owned());
    }
    let pin = read_pin(&config.access.pin_file)?;
    let store = KeyStore::open(&config.access.module, &config.access.token, &pin)
        .map_err(|e| e.to_string())?;
    let keys = PositionKeys::open(
        &store,
        config.api.position_key,
        config.api.previous_position_key,
    )
    .map_err(|e| e.to_string())?;
    Ok(ApiServices {
        auth: Arc::new(Authenticator::new(
            Arc::clone(backing.access),
            Some(config.client_id()),
        )),
        reads: Arc::new(Reads::new(backing.canonical.clone(), Arc::new(keys))),
        writes: Arc::new(Writes::new(
            Arc::clone(backing.access),
            backing.pep.map(str::to_owned),
            backing.canonical.clone(),
            backing.realms.clone(),
            Arc::clone(&backing.sequence),
            Arc::clone(backing.access),
        )),
        authorities: Arc::new(Authorities::new(
            Arc::clone(backing.access),
            backing.pep.map(str::to_owned),
            backing.canonical.clone(),
            backing.realms.clone(),
            format!("{}/v1/access/approval", config.api.origin),
        )),
        origin: config.api.origin.clone(),
    })
}

/// The REST routes, with those that act for a caller when they can be served.
pub(crate) fn routes(
    config: &Config,
    backing: &Backing<'_>,
    ids: Arc<dyn TraceIds>,
) -> axum::Router {
    match services(config, backing) {
        Ok(services) => {
            tracing::info!(
                event = "api.caller_routes_served",
                origin = services.origin.as_str(),
                "the routes that act for a caller are served"
            );
            router_with(ApiConfig::default(), ids, Arc::new(services))
        }
        Err(error) => {
            tracing::error!(
                event = "api.caller_routes_unserved",
                %error,
                "the routes that act for a caller are not served"
            );
            router(ApiConfig::default(), ids)
        }
    }
}
