//! Use cases (T-32): one pairing step of Work with Access (T-103 item 1) over every adapter it needs, the same for start-up, the hourly run, `tenant.created` and `work-cli access pair`. Each step reads the PIN and the roots, loads the PEP certificate and Work's two Access keys from the token and drops them again when it ends, so a rotated key or certificate is used by the next step.

use std::path::{Path, PathBuf};
use std::time::Duration;

use suiss_crypto::secret::Secret;
use work_access_client::adapters::{
    AccessKeys, HttpsTransport, PEP_LABEL, PepCredential, platform_config, roots,
};
use work_access_client::app::Client;
use work_access_client::app::platform::{Platform, Report, Scope, Signal, Step, run};
use work_access_client::domain::AccessError;
use work_access_client::domain::discovery::Issuer;
use work_access_client::ports::{Clock, Random};

use crate::adapters::PgPairing;

/// What a pairing step reads (T-96 item 1, T-101 note, T-103).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessSettings {
    /// `[suiss] access`.
    pub issuer: String,
    /// Work's region (E-4).
    pub region: String,
    /// `WORK_ACCESS_CLIENT_ID`.
    pub client_id: String,
    /// `<installation URI>/v1/inbound/events`, the stream's push endpoint.
    pub receiver: String,
    /// The PKCS#11 module.
    pub module: PathBuf,
    /// The token label.
    pub token: String,
    /// The file holding the user PIN.
    pub pin_file: PathBuf,
    /// The PEM roots of Access's server certificate.
    pub roots_file: PathBuf,
    /// Upper bound on one call to Access.
    pub timeout: Duration,
}

fn read(path: &Path, what: &str) -> Result<Vec<u8>, AccessError> {
    std::fs::read(path)
        .map_err(|e| AccessError::KeyStore(format!("{what} {}: {e}", path.display())))
}

async fn step<C, R>(
    settings: &AccessSettings,
    store: &PgPairing,
    clock: C,
    random: R,
    scope: &Scope,
) -> Result<Report, AccessError>
where
    C: Clock + Clone,
    R: Random,
{
    let issuer = Issuer::parse(&settings.issuer)?;
    let pin = String::from_utf8(read(&settings.pin_file, "PIN file")?)
        .map_err(|_| AccessError::KeyStore("the PIN file is not UTF-8".to_owned()))?;
    let pin = Secret::new(pin.trim_end().to_owned());
    let trusted = roots(&read(&settings.roots_file, "roots")?)?;
    let pep = PepCredential::load(&settings.module, &settings.token, &pin, PEP_LABEL)?;
    let keys = AccessKeys::load(&settings.module, &settings.token, &pin)?;
    let client = Client::new(
        HttpsTransport::new(pep.client_config(trusted.clone())?, settings.timeout),
        clock.clone(),
        issuer.clone(),
        &settings.region,
        pep.not_after_ms(),
    );
    let platform = Platform::new(
        HttpsTransport::new(platform_config(trusted)?, settings.timeout),
        clock,
        random,
        keys.client,
        &settings.client_id,
        &issuer,
    );
    let step = Step {
        store,
        service: &keys.service,
        receiver: &settings.receiver,
    };
    Ok(run(&client, &platform, &step, scope).await)
}

/// One pairing step over `scope`; a step that cannot start, for a malformed setting, an
/// unreadable PIN or roots, or a key missing from the token, is a report with that one
/// [`Signal::Failed`].
pub async fn pair<C, R>(
    settings: &AccessSettings,
    store: &PgPairing,
    clock: C,
    random: R,
    scope: &Scope,
) -> Report
where
    C: Clock + Clone,
    R: Random,
{
    match step(settings, store, clock, random, scope).await {
        Ok(report) => report,
        Err(error) => Report {
            signals: vec![Signal::Failed {
                tenant: None,
                error,
            }],
            ..Report::default()
        },
    }
}
