//! Relay's discovery document (T-99 items 1–3, T-104; Relay E-81, E-90): found at `<suiss_relay>/.well-known/relay-configuration`, used only when its `issuer` is `suiss_relay`, its `access_issuer` is Work's Access issuer, its region is Work's, it supports the dated contract version Work speaks, it offers the events capability and it names the Access client whose sector its subscriber and responder `sub`s are in. Every other capability is looked for when it is used: its endpoint is kept only while the document lists the capability with an `https` endpoint.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::domain::AccessError;
use crate::domain::discovery::Issuer;

/// The capability Relay must offer before Work starts (T-99 item 3).
pub const REQUIRED_RELAY_CAPABILITY: &str = "urn:suiss:relay:events:1";

/// The well-known path of Relay's discovery document below `suiss_relay`.
pub const RELAY_CONFIGURATION: &str = "/.well-known/relay-configuration";

/// The problem code of a Relay that does not serve the `Relay-Version` asked for.
pub const UNSUPPORTED_VERSION: &str = "unsupported_api_version";

#[derive(Deserialize)]
struct Wire {
    issuer: String,
    api_base: String,
    region: String,
    access_issuer: String,
    access_client_id: String,
    contract_versions_supported: Vec<String>,
    jwks_uri: String,
    capabilities: Vec<String>,
    #[serde(default)]
    events_endpoint: Option<String>,
    #[serde(default)]
    waitpoints_endpoint: Option<String>,
    #[serde(default)]
    escalation_policies_endpoint: Option<String>,
    #[serde(default)]
    agents_endpoint: Option<String>,
}

/// The capability of the waitpoint operations (T-99 item 3).
pub const WAITPOINT_CAPABILITY: &str = "urn:suiss:relay:waitpoint:1";

/// The capability of the escalation policy operations.
pub const ESCALATION_CAPABILITY: &str = "urn:suiss:relay:escalation:1";

/// The capability of the ceiling decision operations.
pub const AGENT_CEILING_CAPABILITY: &str = "urn:suiss:relay:agent_ceiling:1";

/// The capability of signed product events (T-100 item 4).
pub const PRODUCT_EVENTS_CAPABILITY: &str = "urn:suiss:relay:product_events:1";

/// The checked Relay discovery document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayConfiguration {
    /// Relay's issuer, `suiss_relay`: the `source` of its events.
    pub issuer: Issuer,
    /// `<issuer>/v1`.
    pub api_base: String,
    /// The product event key set.
    pub jwks_uri: String,
    /// The `client_id` of Relay's Access client: the sector of every subscriber `external_id`
    /// and responder `sub`, and the `client_id` of `subjects:resolve` (T-104).
    pub access_client_id: String,
    /// The capability URNs.
    pub capabilities: BTreeSet<String>,
    /// The events endpoint.
    pub events_endpoint: String,
    /// The waitpoints endpoint, while Relay offers waitpoints.
    pub waitpoints_endpoint: Option<String>,
    /// The escalation policies endpoint, while Relay offers escalation.
    pub escalation_policies_endpoint: Option<String>,
    /// The agents endpoint, while Relay offers ceiling decisions.
    pub agents_endpoint: Option<String>,
}

/// The error of Relay's discovery answer `error` for `contract_version`: a Relay that refuses the
/// dated version itself does not support it either, and refuses start (T-99 item 2).
#[must_use]
pub fn version_refused(error: AccessError, contract_version: &str) -> AccessError {
    match error {
        AccessError::Refused {
            status: 400, code, ..
        } if code == UNSUPPORTED_VERSION => {
            AccessError::ContractVersion(contract_version.to_owned())
        }
        other => other,
    }
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
        if w.access_client_id.is_empty() || w.access_client_id.len() > 256 {
            return Err(AccessError::Document(
                "relay-configuration access_client_id",
            ));
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
        let offered = |capability: &str, endpoint: Option<String>| {
            endpoint.filter(|u| capabilities.contains(capability) && https(u))
        };
        let waitpoints_endpoint = offered(WAITPOINT_CAPABILITY, w.waitpoints_endpoint);
        let escalation_policies_endpoint =
            offered(ESCALATION_CAPABILITY, w.escalation_policies_endpoint);
        let agents_endpoint = offered(AGENT_CEILING_CAPABILITY, w.agents_endpoint);
        Ok(Self {
            issuer: suiss_relay.clone(),
            api_base: w.api_base,
            jwks_uri: w.jwks_uri,
            access_client_id: w.access_client_id,
            capabilities,
            events_endpoint,
            waitpoints_endpoint,
            escalation_policies_endpoint,
            agents_endpoint,
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
        "access_client_id": "app_relay",
        "contract_version": "2026-11-01",
        "contract_versions_supported": ["2026-11-01"],
        "jwks_uri": "https://relay.example/.well-known/relay-jwks.json",
        "capabilities": ["urn:suiss:relay:events:1"],
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
        assert_eq!(doc.access_client_id, "app_relay");
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
                "[\"urn:suiss:relay:events:1\"]",
                "[\"urn:esuiss:relay:events:1\"]"
            )),
            Err(AccessError::Capability(
                REQUIRED_RELAY_CAPABILITY.to_owned()
            ))
        );
    }

    // T-99
    #[test]
    fn t_99_an_endpoint_is_kept_only_while_its_capability_is_offered() {
        let plain = read(DOC).unwrap();
        assert_eq!(plain.waitpoints_endpoint, None);
        assert_eq!(plain.escalation_policies_endpoint, None);
        assert_eq!(plain.agents_endpoint, None);
        let endpoints = "\"events_endpoint\": \"https://relay.example/v1/events\",
        \"waitpoints_endpoint\": \"https://relay.example/v1/waitpoints\",
        \"escalation_policies_endpoint\": \"http://relay.example/v1/escalation_policies\",
        \"agents_endpoint\": \"https://relay.example/v1/agents\"";
        let named = DOC.replace(
            "\"events_endpoint\": \"https://relay.example/v1/events\"",
            endpoints,
        );
        assert_ne!(named, DOC);
        assert_eq!(read(&named).unwrap().waitpoints_endpoint, None);
        let offered = read(&named.replace(
            "[\"urn:suiss:relay:events:1\"]",
            "[\"urn:suiss:relay:events:1\", \"urn:suiss:relay:waitpoint:1\", \"urn:suiss:relay:escalation:1\"]",
        ))
        .unwrap();
        assert_eq!(
            offered.waitpoints_endpoint.as_deref(),
            Some("https://relay.example/v1/waitpoints")
        );
        assert_eq!(offered.escalation_policies_endpoint, None);
        assert_eq!(offered.agents_endpoint, None);
        assert!(!offered.capabilities.contains(PRODUCT_EVENTS_CAPABILITY));
    }

    // T-99
    #[test]
    fn t_99_a_relay_that_refuses_the_dated_version_refuses_start() {
        let refused = |status, code: &str| AccessError::Refused {
            status,
            code: code.to_owned(),
            reason: None,
            errors: Vec::new(),
        };
        assert_eq!(
            version_refused(refused(400, UNSUPPORTED_VERSION), "2026-10-01"),
            AccessError::ContractVersion("2026-10-01".to_owned())
        );
        assert_eq!(
            version_refused(refused(400, "malformed_request"), "2026-10-01"),
            refused(400, "malformed_request")
        );
        assert_eq!(
            version_refused(AccessError::Timeout, "2026-10-01"),
            AccessError::Timeout
        );
    }

    // T-99
    #[test]
    fn t_99_a_relay_document_without_its_access_client_refuses_start() {
        let missing = DOC.replace("        \"access_client_id\": \"app_relay\",\n", "");
        assert_ne!(missing, DOC);
        assert_eq!(
            read(&missing),
            Err(AccessError::Document("relay-configuration"))
        );
        let long = "a".repeat(257);
        for id in ["", long.as_str()] {
            assert_eq!(
                read(&DOC.replace("\"app_relay\"", &format!("\"{id}\""))),
                Err(AccessError::Document(
                    "relay-configuration access_client_id"
                ))
            );
        }
    }
}
