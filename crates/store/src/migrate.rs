use sqlx::migrate::Migrator;
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection, PgPool};

use crate::StoreError;

static FOUNDATION: Migrator = sqlx::migrate!("migrations/foundation");
static CANONICAL: Migrator = sqlx::migrate!("migrations/canonical");
static DERIVED: Migrator = sqlx::migrate!("migrations/derived");

/// One of the two databases (OP-2, T-11): no foreign key or join crosses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cluster {
    /// `work`: the ledger, record headers, bodies and SYNC-DERIVED rows.
    Canonical,
    /// `work_derived`: projections, timers and the reconcile queue.
    Derived,
}

impl Cluster {
    /// Both clusters.
    pub const ALL: [Self; 2] = [Self::Canonical, Self::Derived];

    /// The local database name.
    #[must_use]
    pub const fn database(self) -> &'static str {
        match self {
            Self::Canonical => "work",
            Self::Derived => "work_derived",
        }
    }

    /// Per-database setup the administrator runs once before the first migration.
    #[must_use]
    pub const fn bootstrap(self) -> &'static str {
        match self {
            Self::Canonical => include_str!("../bootstrap/canonical.sql"),
            Self::Derived => include_str!("../bootstrap/derived.sql"),
        }
    }

    /// From the command line name, `canonical` or `derived`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "canonical" => Some(Self::Canonical),
            "derived" => Some(Self::Derived),
            _ => None,
        }
    }

    /// The foundation migrations (schemas, domains, guards) followed by the cluster's own.
    fn migrator(self) -> Migrator {
        let own = match self {
            Self::Canonical => &CANONICAL,
            Self::Derived => &DERIVED,
        };
        Migrator::with_migrations(FOUNDATION.iter().chain(own.iter()).cloned().collect())
    }
}

/// Applies the pending migrations of `cluster` as `work_owner` (OP-28, T-36 rule 5): a separate
/// step run by `work-cli migrate`, never at node start-up.
///
/// # Errors
/// [`StoreError::Migrate`].
pub async fn migrate(pool: &PgPool, cluster: Cluster) -> Result<(), StoreError> {
    Ok(cluster.migrator().run(pool).await?)
}

/// [`migrate`] over one connection configured by the libpq environment (`PGHOST`, `PGUSER`,
/// `PGPASSFILE`, `PGSSLMODE`, …); the database defaults to [`Cluster::database`].
///
/// # Errors
/// [`StoreError`].
pub async fn migrate_from_env(cluster: Cluster) -> Result<(), StoreError> {
    let mut opts = PgConnectOptions::new().application_name("work-migrate");
    if opts.get_database().is_none() {
        opts = opts.database(cluster.database());
    }
    let mut conn = PgConnection::connect_with(&opts).await?;
    cluster.migrator().run(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-36 OP-28
    #[test]
    fn t_36_foundation_runs_first_and_versions_are_unique() {
        let last_foundation = FOUNDATION.iter().map(|m| m.version).max().unwrap();
        for cluster in Cluster::ALL {
            let m = cluster.migrator();
            let versions: Vec<i64> = m.iter().map(|m| m.version).collect();
            let mut sorted = versions.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(versions, sorted, "{cluster:?}");
            assert_eq!(
                m.iter()
                    .take(FOUNDATION.iter().count())
                    .map(|m| m.version)
                    .max(),
                Some(last_foundation)
            );
        }
        let own = CANONICAL.iter().chain(DERIVED.iter());
        assert!(own.map(|m| m.version).all(|v| v > last_foundation));
    }

    // T-36 OP-12
    #[test]
    fn t_36_every_migration_runs_as_the_owner_with_timeouts_in_one_transaction() {
        for m in FOUNDATION
            .iter()
            .chain(CANONICAL.iter())
            .chain(DERIVED.iter())
        {
            let code: Vec<&str> = m
                .sql
                .as_str()
                .lines()
                .filter(|l| !l.starts_with("--") && !l.trim().is_empty())
                .take(3)
                .collect();
            assert_eq!(
                code,
                [
                    "SET LOCAL ROLE work_owner;",
                    "SET LOCAL lock_timeout = '10s';",
                    "SET LOCAL statement_timeout = '5min';"
                ],
                "{}",
                m.description
            );
            assert!(!m.no_tx, "{}", m.description);
        }
    }

    // OP-2 T-11
    #[test]
    fn op_2_tables_live_in_exactly_one_cluster() {
        let creates = |m: &Migrator, schema: &str| {
            m.iter()
                .any(|x| x.sql.as_str().contains(&format!("CREATE TABLE {schema}.")))
        };
        assert!(!creates(&FOUNDATION, "ledger") && !creates(&FOUNDATION, "work"));
        assert!(creates(&CANONICAL, "ledger") && creates(&CANONICAL, "work"));
        assert!(!creates(&CANONICAL, "derived"));
        assert!(creates(&DERIVED, "derived"));
        assert!(!creates(&DERIVED, "ledger") && !creates(&DERIVED, "work"));
        assert_eq!(Cluster::parse("canonical"), Some(Cluster::Canonical));
        assert_eq!(Cluster::parse("derived"), Some(Cluster::Derived));
        assert_eq!(Cluster::parse("work"), None);
    }
}
