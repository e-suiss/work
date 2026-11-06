//! The Access pairing state (T-103 item 5, P-115, T-102 note): one OPERATIONAL row per tenant realm in `work.access_realm` and the one SSF push stream in `work.access_event_stream`. They belong to the installation's Access client, not to a ledger, so they are keyed by tenant and realm and are the second place besides the cross-ledger discovery where a statement runs without a ledger scope; only `work_access` writes them, the application role reads them, and nothing is deleted (Access OP-73): a realm that leaves the tenant snapshot is `retired`.

use sqlx::PgPool;

use crate::StoreError;
use crate::publisher::check_role;

/// The login role an [`AccessPool`] must have (T-103).
pub const ACCESS_ROLE: &str = "work_access";

/// Where a tenant realm stands with Work's pairing (T-103 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealmState {
    /// Seen in the snapshot or challenged; no Instance yet.
    Unpaired,
    /// Work's service Instance is open in the realm's governing domain.
    Paired,
    /// The authority plane refused the pairing; `refusal_code` says why.
    Refused,
    /// The realm left the tenant snapshot; the row stays (Access OP-73).
    Retired,
}

impl RealmState {
    /// The stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unpaired => "unpaired",
            Self::Paired => "paired",
            Self::Refused => "refused",
            Self::Retired => "retired",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        [Self::Unpaired, Self::Paired, Self::Refused, Self::Retired]
            .into_iter()
            .find(|s| s.as_str() == text)
            .ok_or(StoreError::Corrupt)
    }
}

/// One stored tenant realm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmRow {
    /// The Access tenant, `tnt_…`.
    pub tenant: String,
    /// The realm, a canonical lower-case UUID.
    pub realm: String,
    /// The realm issuer from the snapshot.
    pub issuer: String,
    /// The realm slug from the snapshot, the name attention items show.
    pub slug: String,
    /// The governing domain id, from the first challenge.
    pub domain: Option<[u8; 32]>,
    /// Work's service Party in the domain.
    pub party: Option<[u8; 16]>,
    /// Work's service Instance, once paired.
    pub instance: Option<[u8; 16]>,
    /// RFC 7638 thumbprint of the service key, base64url.
    pub kid: Option<String>,
    /// The pairing state.
    pub state: RealmState,
    /// Access's refusal code, while refused.
    pub refusal_code: Option<String>,
    /// Pairing runs in a row that did not end paired.
    pub failed_runs: u64,
    /// When the current Instance was first stored, Unix milliseconds.
    pub paired_at_ms: Option<u64>,
    /// The last change, Unix milliseconds.
    pub updated_at_ms: u64,
}

struct Raw {
    tenant: String,
    realm: String,
    issuer: String,
    slug: String,
    domain: Option<Vec<u8>>,
    party: Option<Vec<u8>>,
    instance: Option<Vec<u8>>,
    kid: Option<String>,
    state: String,
    refusal_code: Option<String>,
    failed_runs: i64,
    paired_at_ms: Option<i64>,
    updated_at_ms: i64,
}

fn fixed<const N: usize>(raw: Option<Vec<u8>>) -> Result<Option<[u8; N]>, StoreError> {
    raw.map(|b| <[u8; N]>::try_from(b.as_slice()).map_err(|_| StoreError::Corrupt))
        .transpose()
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

impl TryFrom<Raw> for RealmRow {
    type Error = StoreError;

    fn try_from(r: Raw) -> Result<Self, StoreError> {
        Ok(Self {
            tenant: r.tenant,
            realm: r.realm,
            issuer: r.issuer,
            slug: r.slug,
            domain: fixed(r.domain)?,
            party: fixed(r.party)?,
            instance: fixed(r.instance)?,
            kid: r.kid,
            state: RealmState::parse(&r.state)?,
            refusal_code: r.refusal_code,
            failed_runs: unsigned(r.failed_runs)?,
            paired_at_ms: r.paired_at_ms.map(unsigned).transpose()?,
            updated_at_ms: unsigned(r.updated_at_ms)?,
        })
    }
}

/// The last status Access reported for Work's SSF push stream (T-103 item 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Delivering.
    Enabled,
    /// Paused; Access has no resume endpoint.
    Paused,
    /// Disabled; Work opens it again.
    Disabled,
    /// Access gave up delivering after its retries.
    Unreachable,
    /// No stream is known or Access no longer has it.
    Missing,
}

impl StreamState {
    /// The stored name, Access's `status` spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Disabled => "disabled",
            Self::Unreachable => "unreachable",
            Self::Missing => "missing",
        }
    }

    /// The state of its stored name.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for another name.
    pub fn parse(text: &str) -> Result<Self, StoreError> {
        [
            Self::Enabled,
            Self::Paused,
            Self::Disabled,
            Self::Unreachable,
            Self::Missing,
        ]
        .into_iter()
        .find(|s| s.as_str() == text)
        .ok_or(StoreError::Corrupt)
    }
}

/// The stored stream row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRow {
    /// The stream id, a canonical lower-case UUID; `None` exactly when missing.
    pub stream_id: Option<String>,
    /// The last status read.
    pub state: StreamState,
    /// When it was last read, Unix milliseconds.
    pub checked_at_ms: u64,
    /// How often Work opened it again.
    pub recreated: u64,
}

/// A pool checked to act as `work_access`. It is not an executor; its statements are the
/// pairing reads and writes below, so an arbitrary query does not compile:
///
/// ```compile_fail
/// # async fn f(p: &work_store::AccessPool) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct AccessPool {
    pool: PgPool,
}

impl AccessPool {
    /// Over `pool` after checking that its role is `work_access` or holds its privileges.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        check_role(&pool, ACCESS_ROLE).await?;
        Ok(Self { pool })
    }

    pub(crate) const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The realms of `tenant`, retired ones included, by realm.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn realms(&self, tenant: &str) -> Result<Vec<RealmRow>, StoreError> {
        let rows = sqlx::query_as!(
            Raw,
            r#"SELECT tenant, realm::text AS "realm!", issuer, slug, domain, party, instance, kid,
                      state, refusal_code, failed_runs,
                      (extract(epoch FROM paired_at) * 1000)::bigint AS "paired_at_ms?",
                      (extract(epoch FROM updated_at) * 1000)::bigint AS "updated_at_ms!"
               FROM work.access_realm WHERE tenant = $1 ORDER BY realm"#,
            tenant
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(RealmRow::try_from).collect()
    }

    /// One realm of `tenant`.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row or realm id.
    pub async fn realm(&self, tenant: &str, realm: &str) -> Result<Option<RealmRow>, StoreError> {
        let row = sqlx::query_as!(
            Raw,
            r#"SELECT tenant, realm::text AS "realm!", issuer, slug, domain, party, instance, kid,
                      state, refusal_code, failed_runs,
                      (extract(epoch FROM paired_at) * 1000)::bigint AS "paired_at_ms?",
                      (extract(epoch FROM updated_at) * 1000)::bigint AS "updated_at_ms!"
               FROM work.access_realm WHERE tenant = $1 AND realm = $2::text::uuid"#,
            tenant,
            realm
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(RealmRow::try_from).transpose()
    }

    /// The live realm whose governing domain is `domain` (T-102 note, T-104 item 3).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn realm_of_domain(&self, domain: &[u8; 32]) -> Result<Option<RealmRow>, StoreError> {
        let row = sqlx::query_as!(
            Raw,
            r#"SELECT tenant, realm::text AS "realm!", issuer, slug, domain, party, instance, kid,
                      state, refusal_code, failed_runs,
                      (extract(epoch FROM paired_at) * 1000)::bigint AS "paired_at_ms?",
                      (extract(epoch FROM updated_at) * 1000)::bigint AS "updated_at_ms!"
               FROM work.access_realm WHERE domain = $1 AND state <> 'retired'"#,
            domain.as_slice()
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(RealmRow::try_from).transpose()
    }

    /// Stores a realm of the snapshot as `unpaired` unless it is stored already; a stored row
    /// keeps its issuer and slug.
    ///
    /// # Errors
    /// [`StoreError::Db`] for a value the schema refuses.
    pub async fn seen(
        &self,
        tenant: &str,
        realm: &str,
        issuer: &str,
        slug: &str,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO work.access_realm (tenant, realm, issuer, slug, state, updated_at)
             VALUES ($1, $2::text::uuid, $3, $4, 'unpaired',
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $5::bigint::double precision)
             ON CONFLICT (tenant, realm) DO NOTHING",
            tenant,
            realm,
            issuer,
            slug,
            signed(at_ms)?
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records a `paired` answer: the Party, Instance and `kid`, the domain when the row has
    /// none yet, no refusal and no failed runs. `paired_at` stays while the Instance does.
    /// `false` when the realm is not stored.
    ///
    /// # Errors
    /// [`StoreError::Db`] for a value the schema refuses.
    pub async fn paired(
        &self,
        tenant: &str,
        realm: &str,
        domain: Option<&[u8; 32]>,
        pairing: &Pairing,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "UPDATE work.access_realm
             SET state = 'paired',
                 domain = COALESCE(domain, $3),
                 party = $4,
                 instance = $5,
                 kid = $6,
                 refusal_code = NULL,
                 failed_runs = 0,
                 paired_at = CASE WHEN state = 'paired' AND instance = $5 THEN paired_at
                                  ELSE pg_catalog.to_timestamp(0) + interval '1 millisecond' * $7::bigint::double precision END,
                 updated_at = GREATEST(updated_at,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $7::bigint::double precision)
             WHERE tenant = $1 AND realm = $2::text::uuid",
            tenant,
            realm,
            domain.map(<[u8; 32]>::as_slice),
            pairing.party.as_slice(),
            pairing.instance.as_slice(),
            pairing.kid.as_str(),
            signed(at_ms)?
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Records an `unpaired` challenge: the domain when the row has none yet, the Party and the
    /// `kid` the challenge names, no Instance and no refusal. `false` when the realm is not
    /// stored.
    ///
    /// # Errors
    /// [`StoreError::Db`] for a value the schema refuses.
    pub async fn unpaired(
        &self,
        tenant: &str,
        realm: &str,
        domain: &[u8; 32],
        party: &[u8; 16],
        kid: &str,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "UPDATE work.access_realm
             SET state = 'unpaired',
                 domain = COALESCE(domain, $3),
                 party = $4,
                 kid = $5,
                 instance = NULL,
                 paired_at = NULL,
                 refusal_code = NULL,
                 updated_at = GREATEST(updated_at,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $6::bigint::double precision)
             WHERE tenant = $1 AND realm = $2::text::uuid",
            tenant,
            realm,
            domain.as_slice(),
            party.as_slice(),
            kid,
            signed(at_ms)?
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Records a refusal with its `code` (T-103 item 6): no Instance. `false` when the realm is
    /// not stored.
    ///
    /// # Errors
    /// [`StoreError::Db`] for a value the schema refuses.
    pub async fn refused(
        &self,
        tenant: &str,
        realm: &str,
        code: &str,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "UPDATE work.access_realm
             SET state = 'refused',
                 refusal_code = $3,
                 instance = NULL,
                 paired_at = NULL,
                 updated_at = GREATEST(updated_at,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $4::bigint::double precision)
             WHERE tenant = $1 AND realm = $2::text::uuid",
            tenant,
            realm,
            code,
            signed(at_ms)?
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Marks every live realm of `tenant` that `live` does not name `retired`; returns how many.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn retire_missing(
        &self,
        tenant: &str,
        live: &[String],
        at_ms: u64,
    ) -> Result<u64, StoreError> {
        let done = sqlx::query!(
            "UPDATE work.access_realm
             SET state = 'retired',
                 updated_at = GREATEST(updated_at,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $3::bigint::double precision)
             WHERE tenant = $1 AND state <> 'retired' AND NOT (realm::text = ANY ($2::text[]))",
            tenant,
            live,
            signed(at_ms)?
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Counts one more run of the realm that did not end paired; returns the count, `None` when
    /// the realm is not stored.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a negative count.
    pub async fn count_failure(
        &self,
        tenant: &str,
        realm: &str,
        at_ms: u64,
    ) -> Result<Option<u64>, StoreError> {
        let count = sqlx::query_scalar!(
            "UPDATE work.access_realm
             SET failed_runs = failed_runs + 1,
                 updated_at = GREATEST(updated_at,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $3::bigint::double precision)
             WHERE tenant = $1 AND realm = $2::text::uuid
             RETURNING failed_runs AS \"failed_runs!\"",
            tenant,
            realm,
            signed(at_ms)?
        )
        .fetch_optional(&self.pool)
        .await?;
        count.map(unsigned).transpose()
    }

    /// Sets the failed runs of the realm back to zero; `false` when the realm is not stored.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn reset_failures(
        &self,
        tenant: &str,
        realm: &str,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "UPDATE work.access_realm
             SET failed_runs = 0,
                 updated_at = GREATEST(updated_at,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $3::bigint::double precision)
             WHERE tenant = $1 AND realm = $2::text::uuid",
            tenant,
            realm,
            signed(at_ms)?
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// How many live realms of every tenant have at least `runs` failed runs in a row, the
    /// `work_access_unpaired_realms` gauge (T-103 item 4).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a negative count.
    pub async fn stalled(&self, runs: u64) -> Result<u64, StoreError> {
        let count = sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM work.access_realm
               WHERE state <> 'retired' AND failed_runs >= $1"#,
            signed(runs)?
        )
        .fetch_one(&self.pool)
        .await?;
        unsigned(count)
    }

    /// The stored stream row.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn stream(&self) -> Result<Option<StreamRow>, StoreError> {
        let row = sqlx::query!(
            r#"SELECT stream_id::text AS "stream_id?", state AS "state!",
                      (extract(epoch FROM checked_at) * 1000)::bigint AS "checked_at_ms!",
                      recreated AS "recreated!"
               FROM work.access_event_stream"#
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            Ok(StreamRow {
                stream_id: r.stream_id,
                state: StreamState::parse(&r.state)?,
                checked_at_ms: unsigned(r.checked_at_ms)?,
                recreated: unsigned(r.recreated)?,
            })
        })
        .transpose()
    }

    /// Records what was read of the stream; `recreated` counts one more reopening.
    ///
    /// # Errors
    /// [`StoreError::Db`] for a value the schema refuses, or [`StoreError::Corrupt`].
    pub async fn record_stream(
        &self,
        stream_id: Option<&str>,
        state: StreamState,
        recreated: bool,
        at_ms: u64,
    ) -> Result<StreamRow, StoreError> {
        let row = sqlx::query!(
            r#"INSERT INTO work.access_event_stream (singleton, stream_id, state, checked_at, recreated)
               VALUES (true, $1::text::uuid, $2,
                       pg_catalog.to_timestamp(0) + interval '1 millisecond' * $3::bigint::double precision,
                       CASE WHEN $4 THEN 1 ELSE 0 END)
               ON CONFLICT (singleton) DO UPDATE
               SET stream_id = EXCLUDED.stream_id,
                   state = EXCLUDED.state,
                   checked_at = GREATEST(work.access_event_stream.checked_at, EXCLUDED.checked_at),
                   recreated = work.access_event_stream.recreated + EXCLUDED.recreated
               RETURNING stream_id::text AS "stream_id?", state AS "state!",
                         (extract(epoch FROM checked_at) * 1000)::bigint AS "checked_at_ms!",
                         recreated AS "recreated!""#,
            stream_id,
            state.as_str(),
            signed(at_ms)?,
            recreated
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(StreamRow {
            stream_id: row.stream_id,
            state: StreamState::parse(&row.state)?,
            checked_at_ms: unsigned(row.checked_at_ms)?,
            recreated: unsigned(row.recreated)?,
        })
    }
}

/// What a `paired` answer names (T-103 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    /// Work's service Party.
    pub party: [u8; 16],
    /// Work's service Instance.
    pub instance: [u8; 16],
    /// RFC 7638 thumbprint of the service key, base64url.
    pub kid: String,
}
