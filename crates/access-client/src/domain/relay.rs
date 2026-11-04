//! Relay's discovery document (T-99 items 1–3; Relay E-81): found at `<suiss_relay>/.well-known/relay-configuration`, used only when its `issuer` is `suiss_relay`, its `access_issuer` is Work's Access issuer, its region is Work's, it supports the dated contract version Work speaks and it offers the events capability.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::domain::AccessError;
use crate::domain::discovery::Issuer;

/// The capability Relay must offer before Work starts (T-99 item 3), compared in Relay's
/// spelling.
pub const REQUIRED_RELAY_CAPABILITY: &str = "urn:esuiss:relay:events:1";

/// The well-known path of Relay's discovery document below `suiss_relay`.
pub const RELAY_CONFIGURATION: &str = "/.well-known/relay-configuration";

#[derive(Deserialize)]
struct Wire {
    issuer: String,
    api_base: String,
    region: String,
    access_issuer: String,
    contract_versions_supported: Vec<String>,
    jwks_uri: String,
    capabilities: Vec<String>,
    #[serde(default)]
    events_endpoint: Option<String>,
}

/// The checked Relay discovery document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayConfiguration {
    /// Relay's issuer, `suiss_relay`: the `source` of its events.
    pub issuer: Issuer,
    /// `<issuer>/v1`.
    pub api_base: String,
    /// The product event key set.
    pub jwks_uri: String,
    /// The capability URNs.
    pub capabilities: BTreeSet<String>,
    /// The events endpoint.
    pub events_endpoint: String,
}

impl RelayConfiguration {
    /// The URL of the document for `suiss_relay` (T-99 item 1).
    #[must_use]
    pub fn url(suiss_relay: &Issuer) -> String {
        suiss_relay.join(RELAY_CONFIGURATION)
    }

    /// Reads and checks the document fetched for `suiss_relay` (T-99 item 1, E-4).
    ///
    /// # Errors
    /// [`AccessError`]; each refuses start.
    pub fn from_json(
        body: &[u8],
        suiss_relay: &Issuer,
        access: &Issuer,
        region: &str,
        contract_version: &str,
    ) -> Result<Self, AccessError> {
        let w: Wire = serde_json::from_slice(body)
            .map_err(|_| AccessError::Document("relay-configuration"))?;
        if w.issuer != suiss_relay.as_str() {
            return Err(AccessError::Issuer("relay-configuration"));
        }
        if w.access_issuer != access.as_str() {
            return Err(AccessError::Issuer("relay-configuration access_issuer"));
        }
        if w.region != region {
            return Err(AccessError::Region("relay-configuration"));
        }
        if !w
            .contract_versions_supported
            .iter()
            .any(|v| v == contract_version)
        {
            return Err(AccessError::ContractVersion(contract_version.to_owned()));
        }
        let capabilities: BTreeSet<String> = w.capabilities.into_iter().collect();
        if !capabilities.contains(REQUIRED_RELAY_CAPABILITY) {
            return Err(AccessError::Capability(
                REQUIRED_RELAY_CAPABILITY.to_owned(),
            ));
        }
        let https = |u: &str| u.starts_with("https://");
        let events_endpoint = w
            .events_endpoint
            .filter(|u| https(u))
            .ok_or_else(|| AccessError::Endpoint("events_endpoint".to_owned()))?;
        if !https(&w.jwks_uri) || !https(&w.api_base) {
            return Err(AccessError::Endpoint("jwks_uri".to_owned()));
        }
        Ok(Self {
            issuer: suiss_relay.clone(),
            api_base: w.api_base,
            jwks_uri: w.jwks_uri,
            capabilities,
            events_endpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{
        "issuer": "https://relay.example",
        "api_base": "https://relay.example/v1",
        "region": "eu-central",
        "access_issuer": "https://acme.id.example",
        "contract_version": "2026-11-01",
        "contract_versions_supported": ["2026-11-01"],
        "jwks_uri": "https://relay.example/.well-known/relay-jwks.json",
        "capabilities": ["urn:esuiss:relay:events:1"],
        "events_endpoint": "https://relay.example/v1/events"
    }"#;

    fn relay() -> Issuer {
        Issuer::parse("https://relay.example").unwrap()
    }

    fn access() -> Issuer {
        Issuer::parse("https://acme.id.example").unwrap()
    }

    fn read(doc: &str) -> Result<RelayConfiguration, AccessError> {
        RelayConfiguration::from_json(
            doc.as_bytes(),
            &relay(),
            &access(),
            "eu-central",
            "2026-11-01",
        )
    }

    // T-99
    #[test]
    fn t_99_relay_is_found_from_access_discovery() {
        assert_eq!(
            RelayConfiguration::url(&relay()),
            "https://relay.example/.well-known/relay-configuration"
        );
        let doc = read(DOC).unwrap();
        assert_eq!(doc.issuer, relay());
        assert_eq!(doc.events_endpoint, "https://relay.example/v1/events");
    }

    // T-99
    #[test]
    fn t_99_a_relay_document_whose_issuer_is_not_suiss_relay_refuses_start() {
        let other = DOC.replace(
            "\"issuer\": \"https://relay.example\"",
            "\"issuer\": \"https://other.example\"",
        );
        let err = read(&other).unwrap_err();
        assert_eq!(err, AccessError::Issuer("relay-configuration"));
        assert_eq!(err.code(), "start_refused");
    }

    // T-99
    #[test]
    fn t_99_a_relay_document_of_another_access_refuses_start() {
        let other = DOC.replace(
            "\"access_issuer\": \"https://acme.id.example\"",
            "\"access_issuer\": \"https://other.id.example\"",
        );
        assert_eq!(
            read(&other),
            Err(AccessError::Issuer("relay-configuration access_issuer"))
        );
    }

    // T-99
    #[test]
    fn t_99_region_version_and_events_capability_are_needed_at_start() {
        assert_eq!(
            read(&DOC.replace("\"region\": \"eu-central\"", "\"region\": \"us-east\"")),
            Err(AccessError::Region("relay-configuration"))
        );
        assert_eq!(
            read(&DOC.replace("[\"2026-11-01\"]", "[\"2026-10-01\"]")),
            Err(AccessError::ContractVersion("2026-11-01".to_owned()))
        );
        assert_eq!(
            read(&DOC.replace(
                "[\"urn:esuiss:relay:events:1\"]",
                "[\"urn:suiss:relay:events:1\"]"
            )),
            Err(AccessError::Capability(
                REQUIRED_RELAY_CAPABILITY.to_owned()
            ))
        );
    }
}
