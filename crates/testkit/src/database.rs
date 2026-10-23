use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use testcontainers::core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, Healthcheck, ImageExt};
use tokio::sync::Mutex;

use crate::{TestkitError, compose_image};

const PORT: u16 = 5432;
const SUPERUSER: &str = "postgres";
const PASSWORD: &str = "local-only-not-a-secret";
const TEMPLATE: &str = "work_template";
const MIGRATIONS: &str = "/work/migrations";

/// A PostgreSQL 18 container with a template database; every [`Postgres::database`]
/// call returns a fresh copy of it, so tests stay independent (T-36 rule 7).
///
/// One instance per test process: under `cargo nextest` every test is its own
/// process, so the template is built once per test and copied per database.
pub struct Postgres {
    container: ContainerAsync<GenericImage>,
    host: String,
    port: u16,
    next: AtomicU32,
    copying: Mutex<()>,
}

impl std::fmt::Debug for Postgres {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Postgres")
            .field("container", &self.container.id())
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// One test's own database, copied from the template.
#[derive(Clone, PartialEq, Eq)]
pub struct TestDatabase {
    name: String,
    url: String,
}

impl std::fmt::Debug for TestDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestDatabase")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl TestDatabase {
    /// Database name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Connection URL for the superuser of the test container.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Postgres {
    /// Starts PostgreSQL with an empty template database.
    ///
    /// # Errors
    ///
    /// [`TestkitError`] if the image is not pinned or the container does not start.
    pub async fn start() -> Result<Self, TestkitError> {
        Self::start_inner(None).await
    }

    /// Starts PostgreSQL and applies the `*.sql` files of `dir`, in file name order,
    /// each in one transaction, to the template database.
    ///
    /// # Errors
    ///
    /// [`TestkitError`] if the directory cannot be read, the container does not
    /// start or a migration fails.
    pub async fn start_with_migrations(dir: &Path) -> Result<Self, TestkitError> {
        Self::start_inner(Some(dir)).await
    }

    async fn start_inner(dir: Option<&Path>) -> Result<Self, TestkitError> {
        let files = match dir {
            Some(d) => migration_files(d)?,
            None => Vec::new(),
        };
        let mut request = compose_image("postgres")?
            .generic()
            .with_exposed_port(PORT.tcp())
            .with_wait_for(WaitFor::healthcheck())
            .with_env_var("POSTGRES_USER", SUPERUSER)
            .with_env_var("POSTGRES_PASSWORD", PASSWORD)
            .with_env_var(
                "POSTGRES_INITDB_ARGS",
                "--auth=scram-sha-256 --data-checksums",
            )
            .with_health_check(
                Healthcheck::cmd([
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    SUPERUSER,
                    "-d",
                    "postgres",
                ])
                .with_interval(Duration::from_millis(250))
                .with_timeout(Duration::from_secs(3))
                .with_retries(240),
            );
        if let Some(d) = dir {
            request = request.with_copy_to(MIGRATIONS, d);
        }
        let container = request.start().await?;
        let host = container.get_host().await?.to_string();
        let port = container.get_host_port_ipv4(PORT.tcp()).await?;
        let pg = Self {
            container,
            host,
            port,
            next: AtomicU32::new(0),
            copying: Mutex::new(()),
        };
        pg.client(&["createdb", TEMPLATE]).await?;
        for file in files {
            pg.client(&[
                "psql",
                "-X",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "--single-transaction",
                "-d",
                TEMPLATE,
                "-f",
                &format!("{MIGRATIONS}/{file}"),
            ])
            .await?;
        }
        Ok(pg)
    }

    /// A new database copied from the template (`createdb --template`).
    ///
    /// # Errors
    ///
    /// [`TestkitError`] if the copy fails.
    pub async fn database(&self) -> Result<TestDatabase, TestkitError> {
        let n = self
            .next
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .ok_or(TestkitError::Exhausted)?;
        let name = format!("work_test_{n}");
        let _copying = self.copying.lock().await;
        self.client(&["createdb", "--template", TEMPLATE, &name])
            .await?;
        let url = format!(
            "postgres://{SUPERUSER}:{PASSWORD}@{}:{}/{name}",
            self.host, self.port
        );
        Ok(TestDatabase { name, url })
    }

    /// The major version of the running server's data directory (`PG_VERSION`).
    ///
    /// # Errors
    ///
    /// [`TestkitError`] if the file cannot be read.
    pub async fn server_major_version(&self) -> Result<String, TestkitError> {
        let out = self
            .exec(&["sh", "-c", "cat \"$PGDATA/PG_VERSION\""])
            .await?;
        Ok(out.trim().to_owned())
    }

    /// Host the server listens on, as seen from the test.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Host port mapped to the server's 5432.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Runs a PostgreSQL client program inside the container against the server
    /// over TCP as the superuser and returns its standard output.
    ///
    /// # Errors
    ///
    /// [`TestkitError::Exec`] if the program exits unsuccessfully.
    pub async fn client(&self, args: &[&str]) -> Result<String, TestkitError> {
        let mut cmd: Vec<&str> = Vec::with_capacity(args.len().saturating_add(4));
        cmd.extend(args.first());
        cmd.extend(["-h", "127.0.0.1", "-U", SUPERUSER]);
        cmd.extend(args.get(1..).unwrap_or_default());
        self.exec_env(&cmd, &[("PGPASSWORD", PASSWORD)]).await
    }

    async fn exec(&self, cmd: &[&str]) -> Result<String, TestkitError> {
        self.exec_env(cmd, &[]).await
    }

    async fn exec_env(&self, cmd: &[&str], env: &[(&str, &str)]) -> Result<String, TestkitError> {
        exec(&self.container, cmd, env).await
    }
}

pub(crate) async fn exec(
    container: &ContainerAsync<GenericImage>,
    cmd: &[&str],
    env: &[(&str, &str)],
) -> Result<String, TestkitError> {
    let mut result = container
        .exec(
            ExecCommand::new(cmd.iter().copied())
                .with_env_vars(env.iter().copied())
                .with_cmd_ready_condition(CmdWaitFor::exit()),
        )
        .await?;
    let stdout = result.stdout_to_vec().await?;
    let stderr = result.stderr_to_vec().await?;
    let code = result.exit_code().await?;
    if code != Some(0) {
        return Err(TestkitError::Exec {
            command: cmd.join(" "),
            code,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

fn migration_files(dir: &Path) -> Result<Vec<String>, TestkitError> {
    let err = |source| TestkitError::Migrations {
        path: dir.to_path_buf(),
        source,
    };
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(err)? {
        let entry = entry.map_err(err)?;
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "sql") {
            files.extend(entry.file_name().to_str().map(str::to_owned));
        }
    }
    files.sort();
    Ok(files)
}
