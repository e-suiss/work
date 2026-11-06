//! The single connection setting and Suiss discovery (T-96, E-3; Access OP-149 m.2, m.3, m.15 (f), (g)): the configured Access issuer, the realm's `/.well-known/suiss-configuration` document, its `endpoints` as RFC 6570 level 1 templates, the `AuthZEN` capabilities required at start and the deterministic CBOR `discovery` of Domain Metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Deserialize;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::domain::{AccessError, from_b64url};

/// The capabilities Access must offer before Work starts (T-96 item 2, Access OP-149 m.2).
pub const REQUIRED_CAPABILITIES: [&str; 3] = [
    "urn:suiss:access:adp:1",
    "urn:suiss:access:explain:1",
    "urn:suiss:access:consistency-token:1",
];

/// The well-known suffix of the Suiss configuration document (Access OP-149 m.3).
pub const SUISS_CONFIGURATION: &str = "suiss-configuration";

/// Upper bound of an endpoint URL, from the CDDL `https-url` rule.
pub const MAX_URL: usize = 2048;

/// How long past Access's `max-age` a discovery document stays fresh: the bound of the refresh
/// call that replaces it (T-32 rule 7).
pub const REFRESH_GRACE_MS: u64 = 5_000;

/// Whether the discovery document `read`, as the time it was read and Access's `max-age`, both
/// in milliseconds, still carries a consequential action at `now_ms` (T-96 item 2, T-28).
/// Without a document nothing does.
///
/// # Errors
/// [`AccessError::Unserved`] without a document, [`AccessError::Stale`] past the bound.
pub fn fresh(read: Option<(u64, u64)>, now_ms: u64) -> Result<(), AccessError> {
    let Some((read_at_ms, max_age_ms)) = read else {
        return Err(AccessError::Unserved(Endpoint::Adp));
    };
    if now_ms.saturating_sub(read_at_ms) > max_age_ms.saturating_add(REFRESH_GRACE_MS) {
        return Err(AccessError::Stale);
    }
    Ok(())
}

/// An `https` base URL: the Access issuer of `[suiss] access` or Relay's `suiss_relay`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Issuer(String);

impl Issuer {
    /// Reads `text`: `https`, a host, an optional path, no trailing slash, no query, fragment
    /// or user information (T-96 item 1).
    ///
    /// # Errors
    /// [`AccessError::Setting`].
    pub fn parse(text: &str) -> Result<Self, AccessError> {
        let rest = text.strip_prefix("https://").ok_or(AccessError::Setting)?;
        let host = rest.split('/').next().unwrap_or_default();
        let printable = text.bytes().all(|b| (b'!'..=b'~').contains(&b));
        if host.is_empty()
            || !printable
            || text.len() > MAX_URL
            || rest.contains(['?', '#', '@', '{', '}'])
            || rest.contains("//")
            || rest.ends_with('/')
        {
            return Err(AccessError::Setting);
        }
        Ok(Self(text.to_owned()))
    }

    /// The URL text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The well-known URL of `suffix`, inserted between the host and the path (RFC 8414 §3.1).
    #[must_use]
    pub fn well_known(&self, suffix: &str) -> String {
        let rest = self.0.strip_prefix("https://").unwrap_or(&self.0);
        match rest.split_once('/') {
            Some((host, path)) => format!("https://{host}/.well-known/{suffix}/{path}"),
            None => format!("https://{rest}/.well-known/{suffix}"),
        }
    }

    /// The URL of `path` below this base.
    #[must_use]
    pub fn join(&self, path: &str) -> String {
        format!("{}{path}", self.0)
    }
}

/// An Access endpoint of the Suiss configuration (Access OP-149 m.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Endpoint {
    /// The `AuthZEN` discovery document.
    Adp,
    /// `GET /access/v1/keys/{kid}`.
    KeyLookup,
    /// `POST /access/v1/keys:batchGet`.
    KeyBatch,
    /// `GET /access/v1/parties/{party}` (Access OP-149 m.28 (c)).
    PartyLookup,
    /// `POST /access/v1/parties:batchGet` (Access OP-149 m.28 (c)).
    PartyBatch,
    /// `POST /access/v1/eligibility:check`.
    Eligibility,
    /// `GET /access/v1/tenants/{tenant}/snapshot`.
    TenantSnapshot,
    /// The Frontend API `auth_context` endpoint.
    AuthContext,
    /// The Frontend API Instance endpoint.
    Instances,
    /// `POST /access/v1/tenants/{tenant}/pairing/challenges`.
    PairingChallenges,
    /// `POST /access/v1/tenants/{tenant}/pairing`.
    Pairing,
    /// `/access/v1/platform/streams`.
    PlatformStreams,
    /// `POST /access/v1/tenants/{tenant}/subjects:resolve`.
    SubjectResolution,
    /// `GET /access/v1/exercises/{exercise}`.
    Exercise,
    /// `GET /access/v1/exercises/{exercise}/agency`.
    ExerciseAgency,
    /// `POST /access/v1/claims:ingest` (Access OP-150 item 2).
    ClaimIngest,
    /// The Token Status List `{list}` (Access OP-150 item 2).
    StatusList,
    /// The Frontend API Approval Surface (`approval`, E-17).
    Approval,
    /// The Frontend API pushed approval requests (`approval_requests`, E-17).
    ApprovalRequests,
    /// The realm's pushed authorization request endpoint (RFC 9126).
    PushedAuthorizationRequest,
}

const ENDPOINTS: [(&str, Endpoint, Option<&str>); 20] = [
    ("adp", Endpoint::Adp, None),
    ("key_lookup", Endpoint::KeyLookup, Some("kid")),
    ("key_batch", Endpoint::KeyBatch, None),
    ("party_lookup", Endpoint::PartyLookup, Some("party")),
    ("party_batch", Endpoint::PartyBatch, None),
    ("eligibility", Endpoint::Eligibility, None),
    ("tenant_snapshot", Endpoint::TenantSnapshot, Some("tenant")),
    ("auth_context", Endpoint::AuthContext, None),
    ("instances", Endpoint::Instances, None),
    (
        "pairing_challenges",
        Endpoint::PairingChallenges,
        Some("tenant"),
    ),
    ("pairing", Endpoint::Pairing, Some("tenant")),
    ("platform_streams", Endpoint::PlatformStreams, None),
    (
        "subject_resolution",
        Endpoint::SubjectResolution,
        Some("tenant"),
    ),
    ("exercise", Endpoint::Exercise, Some("exercise")),
    (
        "exercise_agency",
        Endpoint::ExerciseAgency,
        Some("exercise"),
    ),
    ("claim_ingest", Endpoint::ClaimIngest, None),
    ("status_list", Endpoint::StatusList, Some("list")),
    ("approval", Endpoint::Approval, None),
    ("approval_requests", Endpoint::ApprovalRequests, None),
    (
        "pushed_authorization_request",
        Endpoint::PushedAuthorizationRequest,
        None,
    ),
];

impl Endpoint {
    /// The member name in `endpoints`.
    #[must_use]
    pub fn name(self) -> &'static str {
        ENDPOINTS
            .iter()
            .find(|(_, e, _)| *e == self)
            .map_or("", |(n, _, _)| n)
    }

    fn named(name: &str) -> Option<(Self, Option<&'static str>)> {
        ENDPOINTS
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, e, v)| (*e, *v))
    }
}

/// An endpoint URL, an RFC 6570 level 1 template with at most the one variable its endpoint
/// names (Access OP-149 m.15 (g)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    text: String,
    variable: Option<&'static str>,
}

impl Template {
    fn parse(
        endpoint: &str,
        text: &str,
        variable: Option<&'static str>,
    ) -> Result<Self, AccessError> {
        let bad = || AccessError::Endpoint(endpoint.to_owned());
        let printable = text.bytes().all(|b| (b'!'..=b'~').contains(&b));
        let rest = text.strip_prefix("https://").ok_or_else(bad)?;
        if !printable || rest.is_empty() || text.len() > MAX_URL || text.contains('#') {
            return Err(bad());
        }
        let opens = text.matches('{').count();
        let closes = text.matches('}').count();
        let wanted = usize::from(variable.is_some());
        let named = variable.is_none_or(|v| text.contains(&format!("{{{v}}}")));
        if opens != wanted || closes != wanted || !named {
            return Err(bad());
        }
        Ok(Self {
            text: text.to_owned(),
            variable,
        })
    }

    /// The template text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The URL with `value` put in for the variable, percent-encoded as an RFC 6570 simple
    /// string expansion; a template without a variable is returned as it is.
    #[must_use]
    pub fn expand(&self, value: &str) -> String {
        match self.variable {
            Some(v) => self.text.replace(&format!("{{{v}}}"), &percent(value)),
            None => self.text.clone(),
        }
    }
}

/// RFC 6570 simple string expansion: every byte outside the unreserved set is percent-encoded.
#[must_use]
pub fn percent(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The endpoints Access serves; only served endpoints appear (Access OP-149 m.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoints(BTreeMap<Endpoint, Template>);

impl Endpoints {
    /// Reads `(name, url)` pairs; an unknown name or a malformed URL refuses the whole set.
    ///
    /// # Errors
    /// [`AccessError::Endpoint`].
    pub fn from_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, AccessError> {
        let mut out = BTreeMap::new();
        for (name, url) in pairs {
            let (endpoint, variable) =
                Endpoint::named(name).ok_or_else(|| AccessError::Endpoint(name.to_owned()))?;
            if out
                .insert(endpoint, Template::parse(name, url, variable)?)
                .is_some()
            {
                return Err(AccessError::Endpoint(name.to_owned()));
            }
        }
        Ok(Self(out))
    }

    /// Reads the deterministic CBOR `{v: 1, endpoints}` that Domain Metadata carries as its
    /// opaque `discovery` (`suiss-discovery.cddl`).
    ///
    /// # Errors
    /// [`AccessError::Document`] or [`AccessError::Endpoint`].
    pub fn from_signed(bytes: &[u8]) -> Result<Self, AccessError> {
        const DOC: AccessError = AccessError::Document("signed discovery");
        let Ok(Value::Map(entries)) = dcbor::decode(bytes, Limits::CEILING) else {
            return Err(DOC);
        };
        let (mut version, mut endpoints) = (false, None);
        for (k, v) in &entries {
            match (k, v) {
                (Value::Text(k), Value::Unsigned(1)) if k == "v" => version = true,
                (Value::Text(k), Value::Map(e)) if k == "endpoints" => endpoints = Some(e),
                _ => return Err(DOC),
            }
        }
        let endpoints = endpoints.filter(|_| version).ok_or(DOC)?;
        let mut pairs = Vec::with_capacity(endpoints.len());
        for (k, v) in endpoints {
            match (k, v) {
                (Value::Text(k), Value::Text(v)) => pairs.push((k.as_str(), v.as_str())),
                _ => return Err(DOC),
            }
        }
        Self::from_pairs(pairs)
    }

    /// The template of `endpoint`; an endpoint Access does not serve refuses the action that
    /// needs it (Access OP-149 m.2, T-28).
    ///
    /// # Errors
    /// [`AccessError::Unserved`].
    pub fn get(&self, endpoint: Endpoint) -> Result<&Template, AccessError> {
        self.0.get(&endpoint).ok_or(AccessError::Unserved(endpoint))
    }

    /// The template of `endpoint`, cross-checked against the domain's signed discovery when it
    /// carries one: a served endpoint must agree with it.
    ///
    /// # Errors
    /// [`AccessError::Unserved`] or [`AccessError::DiscoveryMismatch`].
    pub fn agreed(
        &self,
        endpoint: Endpoint,
        signed: Option<&Self>,
    ) -> Result<&Template, AccessError> {
        let own = self.get(endpoint)?;
        match signed.map(|s| s.get(endpoint)) {
            None => Ok(own),
            Some(Ok(t)) if t == own => Ok(own),
            Some(_) => Err(AccessError::DiscoveryMismatch(endpoint)),
        }
    }
}

#[derive(Deserialize)]
struct Wire {
    suiss_configuration_version: u64,
    issuer: String,
    suiss_region: String,
    suiss_relay: String,
    suiss_management_api: String,
    suiss_event_subscriptions: BTreeMap<String, String>,
    suiss_products: BTreeMap<String, String>,
    endpoints: BTreeMap<String, String>,
}

/// The realm's Suiss configuration document (Access OP-149 m.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuissConfiguration {
    /// The realm issuer; the configured `[suiss] access`.
    pub issuer: Issuer,
    /// The deployment's region.
    pub region: String,
    /// Relay's base URL, also its `issuer` (T-99 item 1).
    pub relay: Issuer,
    /// The management API's base URL.
    pub management_api: String,
    /// The event subscription documents.
    pub event_subscriptions: BTreeMap<String, String>,
    /// Product name to base URL.
    pub products: BTreeMap<String, String>,
    /// The endpoints in service.
    pub endpoints: Endpoints,
}

impl SuissConfiguration {
    /// Reads the document fetched for `configured`; it must be version 1 of that issuer, name an
    /// `https` Relay and only known, well-formed endpoints. Unknown members are ignored.
    ///
    /// # Errors
    /// [`AccessError`].
    pub fn from_json(body: &[u8], configured: &Issuer) -> Result<Self, AccessError> {
        let wire: Wire = serde_json::from_slice(body)
            .map_err(|_| AccessError::Document("suiss-configuration"))?;
        if wire.suiss_configuration_version != 1 {
            return Err(AccessError::Version);
        }
        if wire.issuer != configured.as_str() {
            return Err(AccessError::Issuer("suiss-configuration"));
        }
        if wire.suiss_region.is_empty() {
            return Err(AccessError::Document("suiss-configuration"));
        }
        let relay = Issuer::parse(&wire.suiss_relay)
            .map_err(|_| AccessError::Endpoint("suiss_relay".to_owned()))?;
        let endpoints =
            Endpoints::from_pairs(wire.endpoints.iter().map(|(k, v)| (k.as_str(), v.as_str())))?;
        Ok(Self {
            issuer: configured.clone(),
            region: wire.suiss_region,
            relay,
            management_api: wire.suiss_management_api,
            event_subscriptions: wire.suiss_event_subscriptions,
            products: wire.suiss_products,
            endpoints,
        })
    }

    /// What start needs (T-96 item 2, Access OP-149 m.2): the `adp` endpoint, the `AuthZEN`
    /// capabilities and Work's region (E-4). Every other endpoint is looked up when used.
    ///
    /// # Errors
    /// [`AccessError`].
    pub fn check_start(
        &self,
        authzen: &AuthzenConfiguration,
        region: &str,
    ) -> Result<(), AccessError> {
        self.endpoints
            .get(Endpoint::Adp)
            .map_err(|_| AccessError::Capability("adp".to_owned()))?;
        if let Some(missing) = REQUIRED_CAPABILITIES
            .iter()
            .find(|c| !authzen.capabilities.contains(**c))
        {
            return Err(AccessError::Capability((*missing).to_owned()));
        }
        if self.region != region {
            return Err(AccessError::Region("suiss-configuration"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct AuthzenWire {
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    signed_metadata: Option<String>,
}

/// The `AuthZEN` discovery document of the realm, or of one domain with its signed Domain
/// Metadata (Access L1-ADP-11, §9.5.1 #6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthzenConfiguration {
    /// The capability URNs, in Access's spelling.
    pub capabilities: BTreeSet<String>,
    /// The domain's `COSE_Sign1` Domain Metadata, in a domain's document.
    pub signed_metadata: Option<Vec<u8>>,
}

impl AuthzenConfiguration {
    /// Reads the document.
    ///
    /// # Errors
    /// [`AccessError::Document`].
    pub fn from_json(body: &[u8]) -> Result<Self, AccessError> {
        let wire: AuthzenWire = serde_json::from_slice(body)
            .map_err(|_| AccessError::Document("authzen-configuration"))?;
        let signed_metadata = wire
            .signed_metadata
            .as_deref()
            .map(from_b64url)
            .transpose()
            .map_err(|_| AccessError::Document("authzen-configuration"))?;
        Ok(Self {
            capabilities: wire.capabilities.into_iter().collect(),
            signed_metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::tests::hex;

    const EXAMPLE: &str =
        include_str!("../../../../conformance/vectors/access/suiss-configuration.json");
    const SIGNED: &str =
        include_str!("../../../../conformance/vectors/access/suiss-discovery.json");

    fn acme() -> Issuer {
        Issuer::parse("https://acme.id.example").unwrap()
    }

    fn authzen(capabilities: &[&str]) -> AuthzenConfiguration {
        AuthzenConfiguration {
            capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
            signed_metadata: None,
        }
    }

    // T-96 T-28 E-38
    #[test]
    fn t_96_a_stale_discovery_refuses_consequential_actions() {
        assert_eq!(fresh(None, 0), Err(AccessError::Unserved(Endpoint::Adp)));
        let read = Some((1_000, 300_000));
        assert_eq!(fresh(read, 1_000), Ok(()));
        assert_eq!(fresh(read, 1_000 + 300_000 + REFRESH_GRACE_MS), Ok(()));
        assert_eq!(
            fresh(read, 1_001 + 300_000 + REFRESH_GRACE_MS),
            Err(AccessError::Stale)
        );
        assert_eq!(AccessError::Stale.code(), "authority_unverifiable");
        assert_eq!(fresh(Some((u64::MAX, u64::MAX)), 0), Ok(()));
    }

    // T-96
    #[test]
    fn t_96_the_setting_is_an_https_issuer_without_trailing_slash_query_or_fragment() {
        for good in [
            "https://acme.id.example",
            "https://id.example/realms/acme",
            "https://id.example:8443",
        ] {
            assert!(Issuer::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "http://acme.id.example",
            "https://",
            "https://acme.id.example/",
            "https://acme.id.example?x=1",
            "https://acme.id.example#x",
            "https://user@acme.id.example",
            "https://acme.id.example//x",
            "https://acme id.example",
        ] {
            assert_eq!(Issuer::parse(bad), Err(AccessError::Setting), "{bad}");
        }
    }

    // T-96
    #[test]
    fn t_96_the_suiss_configuration_is_found_at_the_inserted_well_known_path() {
        assert_eq!(
            acme().well_known(SUISS_CONFIGURATION),
            "https://acme.id.example/.well-known/suiss-configuration"
        );
        assert_eq!(
            Issuer::parse("https://id.example/realms/acme")
                .unwrap()
                .well_known(SUISS_CONFIGURATION),
            "https://id.example/.well-known/suiss-configuration/realms/acme"
        );
    }

    // T-96
    #[test]
    fn t_96_the_access_example_document_is_read_with_its_endpoints() {
        let doc = SuissConfiguration::from_json(EXAMPLE.as_bytes(), &acme()).unwrap();
        assert_eq!(doc.region, "eu-central");
        assert_eq!(doc.relay.as_str(), "https://relay.example");
        assert_eq!(
            doc.endpoints
                .get(Endpoint::KeyLookup)
                .unwrap()
                .expand("a/b c"),
            "https://access.example/access/v1/keys/a%2Fb%20c"
        );
        assert_eq!(
            doc.endpoints
                .get(Endpoint::TenantSnapshot)
                .unwrap()
                .expand("tnt_01"),
            "https://access.example/access/v1/tenants/tnt_01/snapshot"
        );
        assert_eq!(
            doc.endpoints.get(Endpoint::AuthContext),
            Err(AccessError::Unserved(Endpoint::AuthContext))
        );
    }

    // T-96
    #[test]
    fn t_96_claim_ingest_and_the_status_list_are_read_once_served() {
        let served = EXAMPLE.replace(
            "\"adp\":",
            "\"claim_ingest\": \"https://access.example/access/v1/claims:ingest\", \"status_list\": \"https://access.example/access/v1/status-lists/{list}\", \"adp\":",
        );
        let doc = SuissConfiguration::from_json(served.as_bytes(), &acme()).unwrap();
        assert_eq!(
            doc.endpoints.get(Endpoint::ClaimIngest).unwrap().as_str(),
            "https://access.example/access/v1/claims:ingest"
        );
        assert_eq!(
            doc.endpoints
                .get(Endpoint::StatusList)
                .unwrap()
                .expand("l1"),
            "https://access.example/access/v1/status-lists/l1"
        );
        let unnamed = EXAMPLE.replace(
            "\"adp\":",
            "\"status_list\": \"https://access.example/access/v1/status-lists\", \"adp\":",
        );
        assert!(matches!(
            SuissConfiguration::from_json(unnamed.as_bytes(), &acme()),
            Err(AccessError::Endpoint(_))
        ));
    }

    // T-96
    #[test]
    fn t_96_another_issuer_or_version_refuses_start() {
        let other = Issuer::parse("https://other.id.example").unwrap();
        assert_eq!(
            SuissConfiguration::from_json(EXAMPLE.as_bytes(), &other),
            Err(AccessError::Issuer("suiss-configuration"))
        );
        let v2 = EXAMPLE.replace(
            "\"suiss_configuration_version\": 1",
            "\"suiss_configuration_version\": 2",
        );
        assert_eq!(
            SuissConfiguration::from_json(v2.as_bytes(), &acme()),
            Err(AccessError::Version)
        );
        let unknown = EXAMPLE.replace(
            "\"adp\":",
            "\"webhooks\": \"https://a.example/w\", \"adp\":",
        );
        assert!(matches!(
            SuissConfiguration::from_json(unknown.as_bytes(), &acme()),
            Err(AccessError::Endpoint(_))
        ));
        let plain = EXAMPLE.replace(
            "https://access.example/access/v1/eligibility",
            "http://access.example/access/v1/eligibility",
        );
        assert!(SuissConfiguration::from_json(plain.as_bytes(), &acme()).is_err());
    }

    // T-96
    #[test]
    fn t_96_start_needs_adp_the_three_capabilities_and_the_region() {
        let doc = SuissConfiguration::from_json(EXAMPLE.as_bytes(), &acme()).unwrap();
        assert_eq!(
            doc.check_start(&authzen(&REQUIRED_CAPABILITIES), "eu-central"),
            Ok(())
        );
        assert_eq!(
            doc.check_start(&authzen(&REQUIRED_CAPABILITIES[..2]), "eu-central"),
            Err(AccessError::Capability(
                "urn:suiss:access:consistency-token:1".to_owned()
            ))
        );
        assert_eq!(
            doc.check_start(&authzen(&["urn:esuiss:access:adp:1"]), "eu-central"),
            Err(AccessError::Capability("urn:suiss:access:adp:1".to_owned()))
        );
        assert_eq!(
            doc.check_start(&authzen(&REQUIRED_CAPABILITIES), "us-east"),
            Err(AccessError::Region("suiss-configuration"))
        );
        let without_adp = EXAMPLE.replace(
            "\"adp\": \"https://access.example/.well-known/authzen-configuration\",",
            "",
        );
        let doc = SuissConfiguration::from_json(without_adp.as_bytes(), &acme()).unwrap();
        assert!(
            doc.check_start(&authzen(&REQUIRED_CAPABILITIES), "eu-central")
                .is_err()
        );
    }

    // T-96
    #[test]
    fn t_96_a_missing_endpoint_fails_closed_when_used() {
        let doc = SuissConfiguration::from_json(EXAMPLE.as_bytes(), &acme()).unwrap();
        let err = doc.endpoints.get(Endpoint::Instances).unwrap_err();
        assert_eq!(err, AccessError::Unserved(Endpoint::Instances));
        assert_eq!(err.code(), "authority_unverifiable");
    }

    // T-96
    #[test]
    fn t_96_signed_discovery_matches_the_access_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(SIGNED).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let valid = case["valid"].as_bool().unwrap();
            if let Some(cbor) = case["cbor"].as_str() {
                let read = Endpoints::from_signed(&hex(cbor));
                assert_eq!(read.is_ok(), valid, "{id}");
                let json = &case["json"]["endpoints"];
                let from_json = Endpoints::from_pairs(
                    json.as_object()
                        .unwrap()
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str().unwrap())),
                )
                .unwrap();
                assert_eq!(read.unwrap(), from_json, "{id}");
            } else {
                let edn: serde_json::Value =
                    serde_json::from_str(case["edn"].as_str().unwrap()).unwrap();
                let value = cbor_of(&edn);
                let bytes = dcbor::encode(&value, Limits::CEILING).unwrap();
                assert_eq!(Endpoints::from_signed(&bytes).is_ok(), valid, "{id}");
            }
        }
    }

    fn cbor_of(json: &serde_json::Value) -> Value {
        match json {
            serde_json::Value::Object(m) => {
                let mut entries: Vec<(Vec<u8>, (Value, Value))> = m
                    .iter()
                    .map(|(k, v)| {
                        let key = Value::text(k);
                        (
                            dcbor::encode(&key, Limits::CEILING).unwrap(),
                            (key, cbor_of(v)),
                        )
                    })
                    .collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Map(entries.into_iter().map(|(_, e)| e).collect())
            }
            serde_json::Value::String(s) => Value::text(s),
            serde_json::Value::Number(n) => Value::Unsigned(n.as_u64().unwrap()),
            _ => panic!("not in the vectors"),
        }
    }

    // T-96
    #[test]
    fn t_96_a_served_endpoint_must_agree_with_the_signed_discovery() {
        let doc = SuissConfiguration::from_json(EXAMPLE.as_bytes(), &acme()).unwrap();
        let same =
            Endpoints::from_pairs([("key_lookup", "https://access.example/access/v1/keys/{kid}")])
                .unwrap();
        let other =
            Endpoints::from_pairs([("key_lookup", "https://evil.example/access/v1/keys/{kid}")])
                .unwrap();
        assert!(doc.endpoints.agreed(Endpoint::KeyLookup, None).is_ok());
        assert!(
            doc.endpoints
                .agreed(Endpoint::KeyLookup, Some(&same))
                .is_ok()
        );
        assert_eq!(
            doc.endpoints.agreed(Endpoint::KeyLookup, Some(&other)),
            Err(AccessError::DiscoveryMismatch(Endpoint::KeyLookup))
        );
        assert_eq!(
            doc.endpoints.agreed(Endpoint::Eligibility, Some(&same)),
            Err(AccessError::DiscoveryMismatch(Endpoint::Eligibility))
        );
    }

    // T-96
    #[test]
    fn t_96_every_endpoint_access_serves_is_read_with_its_variable() {
        let served = [
            (
                "adp",
                "https://access.example/.well-known/authzen-configuration",
            ),
            ("approval", "https://acme.id.example/v1/approve"),
            (
                "approval_requests",
                "https://acme.id.example/v1/approve/requests",
            ),
            ("auth_context", "https://acme.id.example/v1/me/auth-context"),
            (
                "pushed_authorization_request",
                "https://acme.id.example/par",
            ),
            (
                "claim_ingest",
                "https://access.example/access/v1/claims:ingest",
            ),
            (
                "eligibility",
                "https://access.example/access/v1/eligibility:check",
            ),
            (
                "exercise",
                "https://access.example/access/v1/exercises/{exercise}",
            ),
            (
                "exercise_agency",
                "https://access.example/access/v1/exercises/{exercise}/agency",
            ),
            ("instances", "https://acme.id.example/v1/me/instances"),
            (
                "key_batch",
                "https://access.example/access/v1/keys:batchGet",
            ),
            ("key_lookup", "https://access.example/access/v1/keys/{kid}"),
            (
                "party_batch",
                "https://access.example/access/v1/parties:batchGet",
            ),
            (
                "party_lookup",
                "https://access.example/access/v1/parties/{party}",
            ),
            (
                "status_list",
                "https://access.example/access/v1/status-lists/{list}",
            ),
            (
                "pairing",
                "https://access.example/access/v1/tenants/{tenant}/pairing",
            ),
            (
                "pairing_challenges",
                "https://access.example/access/v1/tenants/{tenant}/pairing/challenges",
            ),
            (
                "platform_streams",
                "https://access.example/access/v1/platform/streams",
            ),
            (
                "subject_resolution",
                "https://access.example/access/v1/tenants/{tenant}/subjects:resolve",
            ),
            (
                "tenant_snapshot",
                "https://access.example/access/v1/tenants/{tenant}/snapshot",
            ),
        ];
        let endpoints = Endpoints::from_pairs(served).unwrap();
        assert_eq!(
            endpoints
                .get(Endpoint::PairingChallenges)
                .unwrap()
                .expand("tnt_01"),
            "https://access.example/access/v1/tenants/tnt_01/pairing/challenges"
        );
        assert_eq!(
            endpoints
                .get(Endpoint::ExerciseAgency)
                .unwrap()
                .expand("e/1"),
            "https://access.example/access/v1/exercises/e%2F1/agency"
        );
        assert_eq!(
            endpoints
                .get(Endpoint::PartyLookup)
                .unwrap()
                .expand("AwMDAwMDAwMDAwMDAwMDAw"),
            "https://access.example/access/v1/parties/AwMDAwMDAwMDAwMDAwMDAw"
        );
        assert_eq!(
            endpoints
                .get(Endpoint::PlatformStreams)
                .unwrap()
                .expand("x"),
            "https://access.example/access/v1/platform/streams"
        );
        for (name, _, _) in ENDPOINTS {
            assert!(served.iter().any(|(n, _)| *n == name), "{name}");
        }
        assert!(
            Endpoints::from_pairs([("exercise", "https://a.example/exercises/{tenant}")]).is_err()
        );
    }

    // T-96
    #[test]
    fn t_96_a_template_names_only_its_own_variable() {
        assert!(Endpoints::from_pairs([("key_lookup", "https://a.example/keys")]).is_err());
        assert!(
            Endpoints::from_pairs([("key_lookup", "https://a.example/keys/{tenant}")]).is_err()
        );
        assert!(Endpoints::from_pairs([("key_batch", "https://a.example/keys/{kid}")]).is_err());
        assert!(Endpoints::from_pairs([("key_lookup", "https://a.example/{kid}/{kid}")]).is_err());
    }
}
