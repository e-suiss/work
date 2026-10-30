use sqlx::postgres::PgPoolOptions;
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, PgPool};
use work_store::{Cluster, LedgerId};
use work_testkit::Postgres;

const PASSWORD: &str = "test-only-not-a-secret";

const ROLES: [&str; 9] = [
    "work_owner",
    "work_app",
    "work_sequencer",
    "work_checkpointer",
    "work_publisher",
    "work_erasure",
    "work_archive",
    "work_deriver",
    "work_reconciler",
];

pub(crate) const L: [u8; 32] = [0xab; 32];
pub(crate) const M: [u8; 32] = [0xcd; 32];

pub(crate) fn hex(ledger: &[u8; 32]) -> String {
    LedgerId::from_bytes(*ledger).to_hex()
}

pub(crate) struct Env {
    pub(crate) pg: Postgres,
}

impl Env {
    pub(crate) async fn start() -> Self {
        let pg = Postgres::start().await.unwrap();
        let mut admin = PgConnection::connect(&pg.superuser_url("postgres"))
            .await
            .unwrap();
        admin.execute(work_store::BOOTSTRAP_ROLES).await.unwrap();
        for role in ROLES {
            let sql = format!("ALTER ROLE {role} LOGIN PASSWORD '{PASSWORD}'");
            admin.execute(AssertSqlSafe(sql)).await.unwrap();
        }
        for stmt in statements(work_store::BOOTSTRAP_DATABASES) {
            admin.execute(AssertSqlSafe(stmt)).await.unwrap();
        }
        admin.close().await.unwrap();
        let env = Self { pg };
        for cluster in Cluster::ALL {
            let mut c = PgConnection::connect(&env.pg.superuser_url(cluster.database()))
                .await
                .unwrap();
            c.execute(cluster.bootstrap()).await.unwrap();
            c.close().await.unwrap();
            work_store::migrate(&env.pool(cluster, "work_owner"), cluster)
                .await
                .unwrap();
        }
        env
    }

    pub(crate) fn pool(&self, cluster: Cluster, role: &str) -> PgPool {
        let url = format!(
            "postgres://{role}:{PASSWORD}@{}:{}/{}",
            self.pg.host(),
            self.pg.port(),
            cluster.database()
        );
        PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy(&url)
            .unwrap()
    }

    pub(crate) fn canonical(&self, role: &str) -> PgPool {
        self.pool(Cluster::Canonical, role)
    }

    pub(crate) fn derived(&self, role: &str) -> PgPool {
        self.pool(Cluster::Derived, role)
    }

    pub(crate) async fn admin(&self, cluster: Cluster) -> PgConnection {
        PgConnection::connect(&self.pg.superuser_url(cluster.database()))
            .await
            .unwrap()
    }
}

fn statements(sql: &str) -> Vec<String> {
    sql.split(';')
        .map(|s| {
            s.lines()
                .filter(|l| !l.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|s| !s.trim().is_empty())
        .collect()
}

async fn scoped(
    pool: &PgPool,
    scope: &str,
    stmts: &[&str],
    commit: bool,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.ledger_id', $1, true)")
        .bind(scope)
        .execute(&mut *tx)
        .await?;
    for s in stmts {
        sqlx::raw_sql(AssertSqlSafe((*s).to_owned()))
            .execute(&mut *tx)
            .await?;
    }
    if commit {
        tx.commit().await
    } else {
        tx.rollback().await
    }
}

/// Runs `stmts` in one transaction scoped to `scope` and commits.
pub(crate) async fn run(pool: &PgPool, scope: &str, stmts: &[&str]) {
    if let Err(e) = scoped(pool, scope, stmts, true).await {
        panic!("{stmts:?}: {e}");
    }
}

/// Runs `stmts` scoped to `scope`, expects a failure with `code` (any if `None`), rolls back.
pub(crate) async fn fails(pool: &PgPool, scope: &str, stmts: &[&str], code: Option<&str>) {
    match scoped(pool, scope, stmts, false).await {
        Ok(()) => panic!("expected a failure: {stmts:?}"),
        Err(e) => {
            if let Some(want) = code {
                let got = e
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .map(std::borrow::Cow::into_owned);
                assert_eq!(got.as_deref(), Some(want), "{stmts:?}: {e}");
            }
        }
    }
}

/// Runs `stmts` scoped to `scope` and expects the commit, or a statement, to fail with `code`.
pub(crate) async fn commit_fails(pool: &PgPool, scope: &str, stmts: &[&str], code: &str) {
    match scoped(pool, scope, stmts, true).await {
        Ok(()) => panic!("expected the commit to fail: {stmts:?}"),
        Err(e) => {
            let got = e
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .map(std::borrow::Cow::into_owned);
            assert_eq!(got.as_deref(), Some(code), "{stmts:?}: {e}");
        }
    }
}

/// One `bigint` from `query` scoped to `scope`; commits only with `commit`.
pub(crate) async fn scalar(pool: &PgPool, scope: &str, query: &str, commit: bool) -> i64 {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.ledger_id', $1, true)")
        .bind(scope)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar(AssertSqlSafe(query.to_owned()))
        .fetch_one(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("{query}: {e}"));
    if commit {
        tx.commit().await.unwrap();
    } else {
        tx.rollback().await.unwrap();
    }
    n
}

/// `sql` with `{L}` and `{M}` replaced by the hex of the two test ledgers.
pub(crate) fn with_ledgers(sql: &str) -> String {
    sql.replace("{L}", &hex(&L)).replace("{M}", &hex(&M))
}
