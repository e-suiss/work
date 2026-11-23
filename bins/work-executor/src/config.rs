//! The executor's configuration, one TOML file read before anything else (T-105, T-32 rule 8): the Work API and ledger, the Access issuer and the identity the executor connects as, the PKCS#11 token its keys live in, the capability it declares, how it answers requests and the step script it runs for each commitment.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use work_kernel::catalog::{ChangePolicy, StopAnswer, StopType};
use work_kernel::control::body::{Capability, Depth, Operation};

use crate::script::{Script, ScriptError};

/// The environment variable naming the configuration file.
pub(crate) const CONFIG_ENV: &str = "WORK_EXECUTOR_CONFIG";

/// The environment variable naming the ledger, over the file's `work.ledger`: the local
/// environment opens its ledgers while it runs.
pub(crate) const LEDGER_ENV: &str = "WORK_EXECUTOR_LEDGER";

/// The default heartbeat interval, milliseconds.
const DEFAULT_HEARTBEAT_MS: u64 = 5_000;

/// The default long-poll wait, seconds; Work waits at most 30.
const DEFAULT_WAIT_S: u64 = 25;

/// The validated configuration.
#[derive(Debug)]
pub(crate) struct Config {
    /// The log filter.
    pub(crate) log: String,
    /// Where Work is.
    pub(crate) work: Work,
    /// Where Access is and who the executor is there.
    pub(crate) access: Access,
    /// The basis the executor exercises its authority on.
    pub(crate) authority: Authority,
    /// The token its keys live in.
    pub(crate) pkcs11: Pkcs11,
    /// The loop's settings.
    pub(crate) executor: Executor,
    /// The capability it declares (RC-42).
    pub(crate) capability: Capability,
    /// How it answers requests (RC-36).
    pub(crate) responses: Responses,
    /// The step script of every commitment.
    pub(crate) script: Script,
}

/// Where Work is.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Work {
    /// The API base URL, `http://` or `https://`, without a trailing `/`.
    pub(crate) api: String,
    /// The ledger the executor works in, `led_…`; [`LEDGER_ENV`] names it instead.
    #[serde(default)]
    pub(crate) ledger: String,
    /// The `x5t#S256` of Work's PEP certificate the Actor Intent Statement addresses, read from
    /// this PEM file.
    pub(crate) pep_certificate: PathBuf,
}

/// Where Access is and the OAuth client the executor's service Party connects with (T-101).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Access {
    /// The platform realm's issuer.
    pub(crate) issuer: String,
    /// Work's region (E-4).
    pub(crate) region: String,
    /// The PEM roots Access's and Work's server certificates verify against.
    pub(crate) tls_roots: PathBuf,
    /// The executor's OAuth `client_id`.
    #[serde(default)]
    pub(crate) client_id: Option<String>,
    /// A file holding it, read at start, when `client_id` is not given.
    #[serde(default)]
    pub(crate) client_id_file: Option<PathBuf>,
    /// The `client_id` of the product the executor's product is: its `jq` key in the bootstrap
    /// summary `bootstrap_file`.
    #[serde(default)]
    pub(crate) product: Option<String>,
    /// Access's bootstrap summary, when the client ids come from it.
    #[serde(default)]
    pub(crate) bootstrap_file: Option<PathBuf>,
    /// Work's `client_id`, the token's `resource`.
    #[serde(default)]
    pub(crate) resource: Option<String>,
    /// A file holding Work's `client_id`.
    #[serde(default)]
    pub(crate) resource_file: Option<PathBuf>,
    /// The tenant whose realms the executor's product pairs with at start, `tnt_…`; without it
    /// the product must be paired already and `[executor] party` names its service Party.
    #[serde(default)]
    pub(crate) pair_tenant: Option<String>,
    /// The slug of the realm of `bootstrap_file` whose tenant the product pairs with, instead
    /// of `pair_tenant`.
    #[serde(default)]
    pub(crate) pair_realm: Option<String>,
}

/// The basis of every Exercise the executor asks Work's PEP to commit.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authority {
    /// The governing domain, unpadded base64url of 32 bytes; from the pairing challenge when
    /// the executor pairs first.
    #[serde(default)]
    pub(crate) domain: Option<String>,
    /// The Grant held, unpadded base64url of 16 bytes.
    #[serde(default)]
    pub(crate) grant: Option<String>,
    /// Its holder, unpadded base64url of 16 bytes; the executor's own Party when absent.
    #[serde(default)]
    pub(crate) holder: Option<String>,
    /// The position that opened the holding.
    #[serde(default)]
    pub(crate) since: Option<u64>,
    /// The digest of the pinned action schema, unpadded base64url of 32 bytes; zeros when
    /// absent.
    #[serde(default)]
    pub(crate) action_schema: Option<String>,
}

/// The token and the labels of the executor's keys (T-56).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pkcs11 {
    /// The PKCS#11 module.
    pub(crate) module: PathBuf,
    /// The token label.
    pub(crate) token: String,
    /// A file holding the user PIN.
    pub(crate) pin_file: PathBuf,
    /// The client assertion key, P-256.
    pub(crate) client_key: String,
    /// The `DPoP` key, P-256.
    pub(crate) dpop_key: String,
    /// The service Instance key, Ed25519: signs the records and the Actor Intent Statements.
    pub(crate) service_key: String,
}

/// The loop's settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Executor {
    /// The executor's service Party, when it does not pair at start.
    pub(crate) party: Option<String>,
    /// The heartbeat interval it declares and keeps, milliseconds.
    pub(crate) heartbeat_ms: u64,
    /// How long one pull waits for a delivery, 0 to 30 seconds.
    pub(crate) wait_s: u64,
    /// Where the doorbell listener listens, if anywhere.
    pub(crate) doorbell: Option<String>,
    /// The scheme-prefixed reference the session references start with.
    pub(crate) session_prefix: String,
    /// The actor type the executor declares for itself (P-12): Access's binding wins.
    pub(crate) actor_type: String,
    /// Whether the external system of a `write` step honours the idempotency key (SEC-15).
    pub(crate) external_idempotent: bool,
}

/// What the executor answers each kind of request (RC-36).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Responses {
    /// The answer to a stop with stop type `immediate` or `finish_then_stop`.
    pub(crate) stop: StopAnswer,
    /// The answer to a pause.
    pub(crate) pause: StopAnswer,
    /// The answer to a takeover.
    pub(crate) takeover: StopAnswer,
    /// The reason a refusal carries.
    pub(crate) reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutorFile {
    #[serde(default)]
    party: Option<String>,
    #[serde(default)]
    heartbeat_ms: Option<u64>,
    #[serde(default)]
    wait_s: Option<u64>,
    #[serde(default)]
    doorbell: Option<String>,
    #[serde(default)]
    session_prefix: Option<String>,
    #[serde(default)]
    actor_type: Option<String>,
    #[serde(default)]
    external_idempotent: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityFile {
    #[serde(default)]
    operations: Vec<String>,
    #[serde(default)]
    stop_types: Vec<String>,
    #[serde(default)]
    change_policies: Vec<String>,
    #[serde(default)]
    non_cancellable: Vec<String>,
    #[serde(default)]
    safe_state: Option<String>,
    #[serde(default)]
    checkpoints: bool,
    depth: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponsesFile {
    #[serde(default)]
    stop: Option<String>,
    #[serde(default)]
    pause: Option<String>,
    #[serde(default)]
    takeover: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    log: Option<String>,
    work: Work,
    access: Access,
    #[serde(default)]
    authority: Authority,
    pkcs11: Pkcs11,
    executor: ExecutorFile,
    capability: CapabilityFile,
    #[serde(default)]
    responses: Option<ResponsesFile>,
    script: Vec<String>,
}

/// Why the configuration is refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// The file could not be read.
    #[error("{0}: {1}")]
    Read(PathBuf, std::io::Error),
    /// The file is not a configuration.
    #[error("{0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    /// A value is outside what the field takes.
    #[error("{0}")]
    Invalid(&'static str),
    /// The capability does not fit the `capability` rule.
    #[error("capability: {0}")]
    Capability(&'static str),
    /// A step of the script does not parse.
    #[error(transparent)]
    Script(#[from] ScriptError),
}

fn sorted<T>(
    names: &[String],
    parse: impl Fn(&str) -> Option<T>,
    what: &'static str,
) -> Result<Vec<T>, ConfigError> {
    let mut names: Vec<&str> = names.iter().map(String::as_str).collect();
    names.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    names.dedup();
    names
        .into_iter()
        .map(|n| parse(n).ok_or(ConfigError::Capability(what)))
        .collect()
}

fn capability(file: &CapabilityFile, heartbeat_ms: u64) -> Result<Capability, ConfigError> {
    let capability = Capability {
        operations: sorted(&file.operations, Operation::from_wire_name, "operations")?,
        stop_types: sorted(&file.stop_types, StopType::from_wire_name, "stop_types")?,
        change_policies: sorted(
            &file.change_policies,
            ChangePolicy::from_wire_name,
            "change_policies",
        )?,
        non_cancellable: sorted(&file.non_cancellable, |s| Some(s.to_owned()), "steps")?,
        safe_state: file.safe_state.clone(),
        checkpoints: file.checkpoints,
        heartbeat: Some(heartbeat_ms),
        depth: Depth::from_wire_name(&file.depth).ok_or(ConfigError::Capability("depth"))?,
    };
    capability
        .encode()
        .map_err(|e| ConfigError::Capability(e.0))?;
    Ok(capability)
}

fn answer(text: Option<&str>, default: StopAnswer) -> Result<StopAnswer, ConfigError> {
    text.map_or(Ok(default), |t| {
        StopAnswer::from_wire_name(t).ok_or(ConfigError::Invalid(
            "responses: accept, finish_then_stop or refuse",
        ))
    })
}

fn responses(file: Option<&ResponsesFile>) -> Result<Responses, ConfigError> {
    let reason = file
        .and_then(|f| f.reason.clone())
        .unwrap_or_else(|| "the executor's local policy refuses this request".to_owned());
    if reason.is_empty() || reason.len() > work_kernel::control::body::MAX_REASON {
        return Err(ConfigError::Invalid(
            "responses.reason must be 1 to 1024 bytes",
        ));
    }
    Ok(Responses {
        stop: answer(file.and_then(|f| f.stop.as_deref()), StopAnswer::Accept)?,
        pause: answer(file.and_then(|f| f.pause.as_deref()), StopAnswer::Accept)?,
        takeover: answer(file.and_then(|f| f.takeover.as_deref()), StopAnswer::Accept)?,
        reason,
    })
}

fn executor(file: ExecutorFile) -> Result<Executor, ConfigError> {
    let heartbeat_ms = file.heartbeat_ms.unwrap_or(DEFAULT_HEARTBEAT_MS);
    if heartbeat_ms == 0 {
        return Err(ConfigError::Invalid(
            "executor.heartbeat_ms must be at least 1",
        ));
    }
    let wait_s = file.wait_s.unwrap_or(DEFAULT_WAIT_S);
    if wait_s > 30 {
        return Err(ConfigError::Invalid("executor.wait_s must be 0 to 30"));
    }
    let session_prefix = file
        .session_prefix
        .unwrap_or_else(|| "urn:work-executor:session:".to_owned());
    if work_kernel::uri::ExternalRef::parse(&format!("{session_prefix}1")).is_none() {
        return Err(ConfigError::Invalid(
            "executor.session_prefix must start an external reference",
        ));
    }
    let actor_type = file.actor_type.unwrap_or_else(|| "system".to_owned());
    if work_kernel::validate::ActorType::from_wire_name(&actor_type).is_none() {
        return Err(ConfigError::Invalid(
            "executor.actor_type is not an actor type",
        ));
    }
    Ok(Executor {
        party: file.party,
        heartbeat_ms,
        wait_s,
        doorbell: file.doorbell,
        session_prefix,
        actor_type,
        external_idempotent: file.external_idempotent,
    })
}

impl Config {
    /// Reads and checks the file at `path`.
    pub(crate) fn load(path: &Path, ledger: Option<&str>) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_owned(), e))?;
        Self::parse(&text, ledger).map_err(|e| match e {
            ConfigError::Parse(_, inner) => ConfigError::Parse(path.to_owned(), inner),
            other => other,
        })
    }

    /// Checks the text of a configuration file, `ledger` naming the ledger over the file's.
    pub(crate) fn parse(text: &str, ledger: Option<&str>) -> Result<Self, ConfigError> {
        let file: File = toml::from_str(text).map_err(|e| ConfigError::Parse(PathBuf::new(), e))?;
        let api = file.work.api.trim_end_matches('/').to_owned();
        if !(api.starts_with("http://") || api.starts_with("https://")) {
            return Err(ConfigError::Invalid(
                "work.api must be an http or https URL",
            ));
        }
        let ledger = ledger.map_or_else(|| file.work.ledger.clone(), str::to_owned);
        if !ledger.starts_with("led_") {
            return Err(ConfigError::Invalid("work.ledger must be a led_ id"));
        }
        if file.access.client_id.is_none()
            && file.access.client_id_file.is_none()
            && (file.access.product.is_none() || file.access.bootstrap_file.is_none())
        {
            return Err(ConfigError::Invalid(
                "access needs client_id, client_id_file or product with bootstrap_file",
            ));
        }
        if file.access.resource.is_none()
            && file.access.resource_file.is_none()
            && file.access.bootstrap_file.is_none()
        {
            return Err(ConfigError::Invalid(
                "access needs resource, resource_file or bootstrap_file",
            ));
        }
        let executor = executor(file.executor)?;
        let pairs = file.access.pair_tenant.is_some()
            || (file.access.pair_realm.is_some() && file.access.bootstrap_file.is_some());
        if executor.party.is_none() && !pairs {
            return Err(ConfigError::Invalid(
                "executor.party, access.pair_tenant or access.pair_realm names the executor's Party",
            ));
        }
        let capability = capability(&file.capability, executor.heartbeat_ms)?;
        let script = Script::parse(&file.script)?;
        Ok(Self {
            log: file.log.unwrap_or_else(|| "info".to_owned()),
            work: Work {
                api,
                ledger,
                ..file.work
            },
            access: file.access,
            authority: file.authority,
            pkcs11: file.pkcs11,
            executor,
            capability,
            responses: responses(file.responses.as_ref())?,
            script,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::Step;

    pub(crate) const SAMPLE: &str = r#"
log = "debug"
script = ["wait 200", "deploy: write deployed the build", "fail the disk is full"]

[work]
api = "http://work-server:8090/"
ledger = "led_AAAA"
pep_certificate = "/var/lib/access/product-tls/work-pep.crt"

[access]
issuer = "https://access-server:8443/realms/platform"
region = "eu"
tls_roots = "/var/lib/access/product-tls/ca.crt"
product = "one"
bootstrap_file = "/var/lib/access/bootstrap/bootstrap.json"
pair_tenant = "tnt_platform"

[pkcs11]
module = "/usr/lib/softhsm/libsofthsm2.so"
token = "work-dev"
pin_file = "/run/secrets/access-pin"
client_key = "one-access-client"
dpop_key = "one-access-dpop"
service_key = "one-access-service"

[executor]
heartbeat_ms = 2000
doorbell = "0.0.0.0:8095"

[capability]
operations = ["takeover", "cancel", "pause_resume"]
stop_types = ["pause", "immediate", "finish_then_stop"]
non_cancellable = ["deploy"]
safe_state = "idle"
checkpoints = false
depth = "full"

[responses]
takeover = "refuse"
reason = "a human may not drive this environment"
"#;

    // T-105 RC-42
    #[test]
    fn t_105_the_configuration_names_work_access_the_token_the_capability_and_the_script() {
        let c = Config::parse(SAMPLE, None).unwrap();
        assert_eq!(c.log, "debug");
        assert_eq!(c.work.api, "http://work-server:8090");
        assert_eq!(c.executor.heartbeat_ms, 2000);
        assert_eq!(c.executor.wait_s, 25);
        assert_eq!(c.executor.actor_type, "system");
        assert_eq!(c.executor.doorbell.as_deref(), Some("0.0.0.0:8095"));
        assert_eq!(c.capability.heartbeat, Some(2000));
        assert_eq!(
            c.capability.operations,
            vec![
                Operation::Cancel,
                Operation::Takeover,
                Operation::PauseResume
            ]
        );
        assert_eq!(c.capability.non_cancellable, vec!["deploy".to_owned()]);
        assert_eq!(c.responses.stop, StopAnswer::Accept);
        assert_eq!(c.responses.takeover, StopAnswer::Refuse);
        assert_eq!(c.script.steps.len(), 3);
        assert_eq!(c.script.steps[1].name, "deploy");
        assert!(matches!(c.script.steps[2].step, Step::Fail(ref r) if r == "the disk is full"));
        assert_eq!(c.pkcs11.service_key, "one-access-service");
        assert_eq!(c.work.ledger, "led_AAAA");
        let named = Config::parse(SAMPLE, Some("led_BBBB")).unwrap();
        assert_eq!(named.work.ledger, "led_BBBB");
        assert!(Config::parse(SAMPLE, Some("BBBB")).is_err());
        let by_realm = SAMPLE.replace(
            "pair_tenant = \"tnt_platform\"",
            "pair_realm = \"platform\"",
        );
        assert!(Config::parse(&by_realm, None).is_ok());
    }

    // T-105 RC-42 RC-39
    #[test]
    fn t_105_a_configuration_outside_its_rules_is_refused() {
        let refused = |from: &str, to: &str| {
            let text = SAMPLE.replace(from, to);
            assert_ne!(text, SAMPLE, "{from}");
            Config::parse(&text, None).unwrap_err()
        };
        assert!(matches!(
            refused("heartbeat_ms = 2000", "heartbeat_ms = 0"),
            ConfigError::Invalid(_)
        ));
        assert!(matches!(
            refused("doorbell = ", "wait_s = 31\ndoorbell = "),
            ConfigError::Invalid(_)
        ));
        assert!(matches!(
            refused("http://work-server:8090/", "work-server:8090"),
            ConfigError::Invalid(_)
        ));
        assert!(matches!(
            refused("depth = \"full\"", "depth = \"traffic_light\""),
            ConfigError::Capability("depth")
        ));
        assert!(matches!(
            refused("\"takeover\", \"cancel\", ", ""),
            ConfigError::Capability("stop_types")
        ));
        assert!(matches!(
            refused("takeover = \"refuse\"", "takeover = \"maybe\""),
            ConfigError::Invalid(_)
        ));
        assert!(matches!(
            refused("\"wait 200\"", "\"wait soon\""),
            ConfigError::Script(_)
        ));
        assert!(matches!(
            refused("pair_tenant = \"tnt_platform\"", ""),
            ConfigError::Invalid(_)
        ));
        assert!(matches!(
            refused("[executor]", "[executor]\nspeed = 3"),
            ConfigError::Parse(..)
        ));
    }
}
