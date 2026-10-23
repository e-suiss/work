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
