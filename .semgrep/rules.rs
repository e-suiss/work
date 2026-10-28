// ruleid: secret-derive-debug
#[derive(Clone, Debug)]
struct AccessToken {
    value: String,
}

// ok: secret-derive-debug
#[derive(Clone, Debug)]
struct WorkTitle {
    value: String,
}

// ok: secret-derive-debug
#[derive(Clone, Debug)]
struct BodyCommitment {
    digest: Vec<u8>,
}

// ok: secret-derive-debug
#[derive(Clone, Debug)]
struct PracticePin {
    digest: Vec<u8>,
}

// ruleid: secret-derive-debug
#[derive(Debug)]
struct RecordBody {
    bytes: Vec<u8>,
}

// ruleid: secret-derive-debug
#[derive(Debug, Clone)]
pub(crate) struct DbPassword(String);

// ruleid: secret-derive-debug
#[derive(Debug)]
#[serde(untagged)]
pub enum Credential {
    Key(Vec<u8>),
}

// ruleid: secret-derive-debug
#[cfg_attr(test, derive(Debug))]
struct SessionToken {
    value: String,
}

// ok: secret-derive-debug
#[cfg_attr(test, derive(Debug))]
struct SessionState {
    open: bool,
}

// ok: secret-derive-debug
#[derive(Debug)]
struct TokenizerConfig {
    width: u8,
}

fn metrics(id: &str) {
    // ruleid: metric-identity-label
    counter!("work_declarations_total", "work_id" => id);
    // ruleid: metric-identity-label
    counter!("work_declarations_total", "outcome" => label(id), "party_id" => id);
    // ruleid: metric-identity-label
    meter.add(1, &[KeyValue::new("work_id", id.to_owned())]);
    // ok: metric-identity-label
    counter!("work_declarations_total", "outcome" => "accepted");
    // ok: metric-identity-label
    meter.add(1, &[KeyValue::new("outcome", "accepted")]);
}

fn switches(config: &Config) {
    // ruleid: license-flag
    if config.is_enterprise {}
    // ok: license-flag
    if config.is_enabled {}
}

fn secrets(key: &SigningKey) -> Result<(), Error> {
    // ruleid: secret-formatted
    let s = format!("key {}", key.expose());
    // ruleid: secret-formatted
    println!("key {}", key.expose_secret());
    // ruleid: secret-formatted
    return Err(anyhow!("bad key {}", key.expose()));
    // ok: secret-formatted
    println!("key {}", key.fingerprint());
}

fn sql() {
    // ruleid: sql-outside-store
    let rows = sqlx::query("select 1");
}

fn exit() {
    // ruleid: process-exit-in-library
    std::process::exit(1);
}

fn telemetry(record: &Record, body: &[u8], token: &Token) {
    // ruleid: telemetry-content-field
    tracing::info!(body = ?body, "received");
    // ruleid: telemetry-content-field
    info!(record = %record.id, ?body, "received");
    // ruleid: telemetry-content-field
    tracing::debug!(request.payload = %record.payload, "parsed");
    // ruleid: telemetry-content-field
    warn!(refresh_token = %token, "expired");
    // ruleid: telemetry-content-field
    let span = info_span!("declare", record = %record.id, record_body = tracing::field::Empty);
    // ruleid: telemetry-content-field
    info!(gen_ai.request.model = "model-x", "agent.called");
    // ruleid: telemetry-content-field
    error!("cannot parse {body:?}");
    // ok: telemetry-content-field
    info!(record = %record.id, work = %record.work, correlation = %record.correlation, "record.accepted");
    // ok: telemetry-content-field
    info!(record = %record.id, "body received");
    // ok: telemetry-content-field
    debug!(tokenizer_width = 4, panel = "left", "configured");
}
