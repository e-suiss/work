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
