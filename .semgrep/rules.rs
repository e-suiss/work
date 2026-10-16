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

fn metrics() {
    // ruleid: metric-identity-label
    counter!("work_declarations_total", "work_id" => id);
    // ok: metric-identity-label
    counter!("work_declarations_total", "outcome" => "accepted");
}

fn switches(config: &Config) {
    // ruleid: paid-or-cloud-only-path
    if config.is_enterprise {}
}

fn sql() {
    // ruleid: sql-outside-store
    let rows = sqlx::query("select 1");
}
