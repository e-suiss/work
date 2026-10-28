//! Migration guard rails over `crates/store/` migrations and the binaries: no column for a
//! credential, secret or payment value (SEC-24, P-17, F-9), the static counterpart of the
//! `no_secret_columns` schema test; indexes on existing tables built `CONCURRENTLY` in a
//! `-- no-transaction` migration (OP-28 rule 1, T-36 rule 5); and no binary other than
//! `work-cli` runs the migrator (OP-28 rule 1).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::derived::{Cursor, Schema, Token, is_migration, statements, tokenize};
use crate::rules::files::{extension, is_test_file, read, rel, walk};
use crate::rules::lex::{find_token, in_regions, lex, line_at, test_regions};

const CREDENTIALS: &str = "credential-columns";
const STEP: &str = "migration-step";

/// Column-name fragments the schema must not carry, in the order and syntax of the
/// `no_secret_columns` regular expression in `crates/store/tests/containers/schema.rs`:
/// `_?` is an optional underscore and a trailing `$` anchors at the end of the name.
pub(crate) const SECRET_COLUMN_TERMS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_?key",
    "private_?key",
    "otp",
    "cookie",
    "session",
    "card",
    "pan$",
    "cvv",
    "cvc",
    "iban",
    "account_number",
    "wrapped_dek",
    "dek_material",
];

/// The sqlx directive that runs a migration outside a transaction.
pub(crate) const NO_TRANSACTION: &str = "-- no-transaction";

/// The one binary that runs migrations (OP-28 rule 1).
const MIGRATING_BIN: &str = "bins/work-cli/";

/// Identifiers of the migration step in `work-store` and `sqlx`.
const MIGRATOR_TOKENS: &[&str] = &["migrate", "migrate_from_env", "Migrator"];

fn violation(rule: &'static str, path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{path}:{line}")),
        message,
    }
}

fn term_matches(term: &str, column: &str) -> bool {
    let (stem, anchored) = match term.strip_suffix('$') {
        Some(stem) => (stem, true),
        None => (term, false),
    };
    let variants = match stem.split_once("_?") {
        Some((a, b)) => vec![format!("{a}{b}"), format!("{a}_{b}")],
        None => vec![stem.to_owned()],
    };
    variants.iter().any(|v| {
        if anchored {
            column.ends_with(v.as_str())
        } else {
            column.contains(v.as_str())
        }
    })
}

/// The first term a column name matches, compared case-sensitively as PostgreSQL stores it.
pub(crate) fn secret_term(column: &str) -> Option<&'static str> {
    SECRET_COLUMN_TERMS
        .iter()
        .copied()
        .find(|t| term_matches(t, column))
}

/// Credential, secret and payment columns in the schema built from the migrations.
pub(crate) fn credential_violations(schema: &Schema) -> Vec<Violation> {
    schema
        .columns()
        .filter_map(|(table, column, file, line)| {
            secret_term(column).map(|term| {
                violation(
                    CREDENTIALS,
                    file,
                    line,
                    format!(
                        "column `{table}.{column}` matches `{term}`: Work stores only the credential kind, assurance level and an opaque reference, never a password, token, cookie, API secret, private key, OTP or card data (SEC-24, P-17, F-9)"
                    ),
                )
            })
        })
        .collect()
}

fn created_tables(stmts: &[Vec<Token>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for stmt in stmts {
        let mut c = Cursor::new(stmt);
        if !c.eat("create") {
            continue;
        }
        for kw in ["global", "local", "temporary", "temp", "unlogged"] {
            c.eat(kw);
        }
        if !c.eat("table") {
            continue;
        }
        c.eat_all(&["if", "not", "exists"]);
        if let Some(name) = c.name() {
            out.insert(name.key());
        }
    }
    out
}

/// Index and transaction violations in one migration file.
pub(crate) fn index_violations(rel_path: &str, sql: &str) -> Vec<Violation> {
    let no_tx = sql.starts_with(NO_TRANSACTION);
    let stmts = statements(tokenize(sql));
    let created = created_tables(&stmts);
    let mut out = Vec::new();
    for stmt in &stmts {
        let mut c = Cursor::new(stmt);
        let line = c.line();
        if no_tx && c.eat_all(&["set", "local"]) {
            out.push(violation(
                STEP,
                rel_path,
                line,
                "`SET LOCAL` has no effect in a `-- no-transaction` migration; use `SET` (OP-28 rule 1)".to_owned(),
            ));
            continue;
        }
        if !c.eat("create") {
            continue;
        }
        c.eat("unique");
        if !c.eat("index") {
            continue;
        }
        let concurrent = c.eat("concurrently");
        c.eat_all(&["if", "not", "exists"]);
        if !c.is_kw("on") {
            c.word();
        }
        if !c.eat("on") {
            continue;
        }
        c.eat("only");
        let Some(table) = c.name() else { continue };
        let key = table.key();
        if concurrent && !no_tx {
            out.push(violation(
                STEP,
                rel_path,
                line,
                format!(
                    "`CREATE INDEX CONCURRENTLY` on `{key}` cannot run in the migration transaction; start the file with `{NO_TRANSACTION}` (OP-28 rule 1)"
                ),
            ));
        } else if !concurrent && !created.contains(&key) {
            out.push(violation(
                STEP,
                rel_path,
                line,
                format!(
                    "index on the existing table `{key}` must be created `CONCURRENTLY` in a `{NO_TRANSACTION}` migration (OP-28 rule 1, T-36 rule 5)"
                ),
            ));
        }
    }
    out
}

/// Calls of the migrator in one binary source file outside tests.
pub(crate) fn migrator_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = Vec::new();
    for token in MIGRATOR_TOKENS {
        for at in find_token(&lexed.code, token) {
            let line = line_at(&lexed.code, at);
            if !in_regions(&tests, line) {
                out.push(violation(
                    STEP,
                    rel_path,
                    line,
                    format!(
                        "`{token}` in a binary other than work-cli: migrations run as a separate step (`work-cli migrate`), never at node start-up (OP-28 rule 1, T-36 rule 5)"
                    ),
                ));
            }
        }
    }
    out
}

fn is_migrating_bin_source(rel_path: &str) -> bool {
    rel_path.starts_with("bins/")
        && !rel_path.starts_with(MIGRATING_BIN)
        && extension(rel_path) == "rs"
        && !is_test_file(rel_path)
}

pub(crate) fn check_credentials(root: &Path) -> Result<Vec<Violation>, String> {
    let mut schema = Schema::default();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if is_migration(&rel_path) {
            schema.apply(&rel_path, &read(&path)?);
        }
    }
    Ok(credential_violations(&schema))
}

pub(crate) fn check_step(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if is_migration(&rel_path) {
            out.extend(index_violations(&rel_path, &read(&path)?));
        } else if is_migrating_bin_source(&rel_path) {
            out.extend(migrator_violations(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANON: &str = "crates/store/migrations/canonical/0001_x.sql";

    fn columns(sql: &str) -> Vec<String> {
        let mut schema = Schema::default();
        schema.apply(CANON, sql);
        credential_violations(&schema)
            .into_iter()
            .map(|v| format!("{}: {}", v.path.display(), v.message))
            .collect()
    }

    fn indexes(sql: &str) -> Vec<String> {
        index_violations(CANON, sql)
            .into_iter()
            .map(|v| format!("{}: {}", v.path.display(), v.message))
            .collect()
    }

    // SEC-24 P-17 F-9
    #[test]
    fn sec_24_credential_and_payment_columns_are_rejected() {
        let v = columns(
            "
CREATE TABLE work.party_login (
    ledger_id         ledger.digest32 NOT NULL,
    credential_kind   text NOT NULL,
    assurance_level   text NOT NULL,
    credential_ref    text NOT NULL,
    password_hash     bytea,
    refresh_token     text,
    session_cookie    text,
    apikey            text,
    signing_private_key bytea,
    otp_seed          bytea,
    card_pan          text,
    CONSTRAINT party_login_pk PRIMARY KEY (ledger_id)
);
ALTER TABLE work.party_login ADD COLUMN client_secret text, ADD COLUMN iban text;
ALTER TABLE work.party_login RENAME COLUMN credential_ref TO api_key;
",
        );
        let terms = [
            "client_secret",
            "iban",
            "api_key",
            "password_hash",
            "refresh_token",
            "session_cookie",
            "apikey",
            "signing_private_key",
            "otp_seed",
            "card_pan",
        ];
        assert_eq!(v.len(), terms.len(), "{v:?}");
        for term in terms {
            assert!(
                v.iter()
                    .any(|f| f.contains(&format!("`work.party_login.{term}`"))),
                "{term} not rejected: {v:?}"
            );
        }
        assert!(
            v.iter().any(|f| f.starts_with(&format!("{CANON}:7:"))),
            "{v:?}"
        );
    }

    // SEC-24 P-17
    #[test]
    fn sec_24_kind_assurance_and_opaque_reference_columns_pass() {
        let v = columns(
            "
CREATE TABLE work.party_login (
    ledger_id       ledger.digest32 NOT NULL,
    credential_kind text NOT NULL,
    assurance_level text NOT NULL,
    credential_ref  text NOT NULL,
    span_id         text,
    japan_office    text,
    body_commitment bytea
);
",
        );
        assert!(v.is_empty(), "{v:?}");
        assert_eq!(secret_term("pan"), Some("pan$"));
        assert_eq!(secret_term("pane"), None);
        assert_eq!(secret_term("private_key"), Some("private_?key"));
        assert_eq!(secret_term("privatekey"), Some("private_?key"));
    }

    // SEC-24 T-36
    #[test]
    fn sec_24_terms_match_the_schema_security_test() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let text =
            std::fs::read_to_string(root.join("crates/store/tests/containers/schema.rs")).unwrap();
        let at = text.find("'no_secret_columns'").unwrap();
        let rest = &text[at..];
        let open = rest.find("attname ~ '(").unwrap() + "attname ~ '(".len();
        let close = rest[open..].find(")'").unwrap() + open;
        let terms: Vec<&str> = rest[open..close].split('|').collect();
        assert_eq!(terms, SECRET_COLUMN_TERMS);
    }

    // SEC-24
    #[test]
    fn sec_24_the_committed_migrations_carry_no_credential_column() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let v = check_credentials(root).unwrap();
        assert!(v.is_empty(), "{v:?}");
    }

    // OP-28 T-36
    #[test]
    fn op_28_index_on_an_existing_table_must_be_concurrent() {
        let v = indexes(
            "SET LOCAL lock_timeout = '10s';
CREATE INDEX log_pos_ix ON work.log (ledger_id, pos);
CREATE UNIQUE INDEX IF NOT EXISTS head_uq ON ONLY work.head (ledger_id);
CREATE INDEX ON work.log (recorded_at);
",
        );
        assert_eq!(v.len(), 3, "{v:?}");
        assert!(v[0].starts_with(&format!("{CANON}:2:")), "{v:?}");
        assert!(
            v[0].contains("`work.log` must be created `CONCURRENTLY`"),
            "{v:?}"
        );
        assert!(v[1].contains("`work.head`"), "{v:?}");
        assert!(v[2].contains("`work.log`"), "{v:?}");
    }

    // OP-28
    #[test]
    fn op_28_index_on_a_table_created_in_the_same_migration_may_block() {
        let v = indexes(
            "CREATE TABLE IF NOT EXISTS work.retention_hold (ledger_id ledger.digest32 NOT NULL);
CREATE INDEX retention_hold_ix ON work.retention_hold (ledger_id);
CREATE UNIQUE INDEX retention_hold_uq ON work.retention_hold (ledger_id) WHERE true;
",
        );
        assert!(v.is_empty(), "{v:?}");
    }

    // OP-28
    #[test]
    fn op_28_concurrent_index_needs_a_no_transaction_migration() {
        let in_tx = indexes("CREATE INDEX CONCURRENTLY log_pos_ix ON work.log (ledger_id, pos);");
        assert_eq!(in_tx.len(), 1, "{in_tx:?}");
        assert!(in_tx[0].contains(NO_TRANSACTION), "{in_tx:?}");
        let no_tx = indexes(
            "-- no-transaction
-- OP-28
SET lock_timeout = '10s';
CREATE INDEX CONCURRENTLY IF NOT EXISTS log_pos_ix ON work.log (ledger_id, pos);
",
        );
        assert!(no_tx.is_empty(), "{no_tx:?}");
        let local = indexes(
            "-- no-transaction
SET LOCAL lock_timeout = '10s';
CREATE INDEX CONCURRENTLY log_pos_ix ON work.log (ledger_id, pos);
",
        );
        assert_eq!(local.len(), 1, "{local:?}");
        assert!(local[0].contains("`SET LOCAL`"), "{local:?}");
    }

    // OP-28
    #[test]
    fn op_28_the_committed_migrations_build_indexes_safely() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut v = Vec::new();
        for path in walk(root).unwrap() {
            let rel_path = rel(root, &path);
            if is_migration(&rel_path) {
                v.extend(index_violations(&rel_path, &read(&path).unwrap()));
            }
        }
        assert!(v.is_empty(), "{v:?}");
    }

    // OP-28 T-36
    #[test]
    fn op_28_only_work_cli_runs_the_migrator() {
        let server = "fn main() {\n    let rt = runtime();\n    rt.block_on(work_store::migrate_from_env(Cluster::Canonical));\n    sqlx::migrate!(\"migrations\").run(&pool);\n}\n";
        let v = migrator_violations("bins/work-server/src/main.rs", server);
        assert_eq!(v.len(), 2, "{v:?}");
        let ok = "fn main() {\n    let migrated = \"migrate\"; // migrate\n}\n#[cfg(test)]\nmod tests {\n    fn setup() { work_store::migrate(c); }\n}\n";
        assert!(migrator_violations("bins/work-server/src/main.rs", ok).is_empty());
        assert!(is_migrating_bin_source("bins/work-server/src/main.rs"));
        assert!(is_migrating_bin_source("bins/work-signer/src/main.rs"));
        assert!(!is_migrating_bin_source("bins/work-cli/src/main.rs"));
        assert!(!is_migrating_bin_source("bins/work-server/tests/boot.rs"));
    }

    // OP-28
    #[test]
    fn op_28_work_server_never_migrates_at_start_up() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut v = Vec::new();
        for path in walk(&root.join("bins")).unwrap() {
            let rel_path = rel(root, &path);
            if is_migrating_bin_source(&rel_path) {
                v.extend(migrator_violations(&rel_path, &read(&path).unwrap()));
            }
        }
        assert!(v.is_empty(), "{v:?}");
        let cli = read(&root.join("bins/work-cli/src/main.rs")).unwrap();
        assert!(!migrator_violations("bins/work-cli/src/main.rs", &cli).is_empty());
    }
}
