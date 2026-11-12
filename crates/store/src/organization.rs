//! The organization map (E-3, T-96 item 4, T-102 item 5): one OPERATIONAL row per Access organization of a tenant in `work.access_organization`, keyed by the tenant and Access's own organization id, which is the Work organization's id too. A row is opened by the first `organization.*` event or by the tenant snapshot that lists the organization, a later event moves it to its Access position and never back, and nothing is deleted (Access OP-73). Only `work_access` writes it.

use crate::StoreError;
use crate::access::AccessPool;

/// How a mapped organization first reached Work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationOrigin {
    /// An `organization.*` event.
    Event,
    /// The tenant snapshot.
    Snapshot,
}

impl OrganizationOrigin {
    fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "event" => Ok(Self::Event),
            "snapshot" => Ok(Self::Snapshot),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// One mapped organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationRow {
    /// The Access tenant, `tnt_…`.
    pub tenant: String,
    /// The organization, a canonical lower-case UUID.
    pub organization: String,
    /// How it first reached Work.
    pub origin: OrganizationOrigin,
    /// The Access position `(pos, idx)` of the last event applied.
    pub position: Option<(u64, u64)>,
    /// Access's time of the last event applied, Unix milliseconds.
    pub changed_at_ms: Option<u64>,
    /// When Work mapped it, Unix milliseconds.
    pub mapped_at_ms: u64,
    /// The last change of the row, Unix milliseconds.
    pub updated_at_ms: u64,
}

/// What an `organization.*` event did to the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationWrite {
    /// The organization was not mapped; it is now.
    Mapped,
    /// The mapped organization moved to the event's position.
    Moved,
    /// The row is at this position or a later one; nothing changed.
    Stale,
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

impl AccessPool {
    /// The mapped organizations of `tenant`, by organization.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn organizations(&self, tenant: &str) -> Result<Vec<OrganizationRow>, StoreError> {
        let rows = sqlx::query!(
            r#"SELECT tenant, organization::text AS "organization!", origin, access_pos, access_idx,
                      (extract(epoch FROM changed_at) * 1000)::bigint AS "changed_at_ms?",
                      (extract(epoch FROM mapped_at) * 1000)::bigint AS "mapped_at_ms!",
                      (extract(epoch FROM updated_at) * 1000)::bigint AS "updated_at_ms!"
               FROM work.access_organization WHERE tenant = $1 ORDER BY organization"#,
            tenant
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|r| {
                let position = match (r.access_pos, r.access_idx) {
                    (Some(pos), Some(idx)) => Some((unsigned(pos)?, unsigned(idx)?)),
                    (None, None) => None,
                    _ => return Err(StoreError::Corrupt),
                };
                Ok(OrganizationRow {
                    tenant: r.tenant,
                    organization: r.organization,
                    origin: OrganizationOrigin::parse(&r.origin)?,
                    position,
                    changed_at_ms: r.changed_at_ms.map(unsigned).transpose()?,
                    mapped_at_ms: unsigned(r.mapped_at_ms)?,
                    updated_at_ms: unsigned(r.updated_at_ms)?,
                })
            })
            .collect()
    }

    /// Maps an organization the tenant snapshot lists unless it is mapped already; true when
    /// the row was opened.
    ///
    /// # Errors
    /// [`StoreError::Db`] for a value the schema refuses.
    pub async fn organization_listed(
        &self,
        tenant: &str,
        organization: &str,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "INSERT INTO work.access_organization (tenant, organization, origin, mapped_at, updated_at)
             VALUES ($1, $2::text::uuid, 'snapshot',
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $3::bigint::double precision,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $3::bigint::double precision)
             ON CONFLICT (tenant, organization) DO NOTHING",
            tenant,
            organization,
            signed(at_ms)?
        )
        .execute(self.pool())
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Applies an `organization.*` event at Access position `position` that Access dated
    /// `changed_at_ms`: maps the organization, or moves a mapped one forward to the position.
    ///
    /// # Errors
    /// [`StoreError::Db`] for a value the schema refuses, or [`StoreError::Corrupt`].
    pub async fn organization_event(
        &self,
        tenant: &str,
        organization: &str,
        position: (u64, u64),
        changed_at_ms: u64,
        at_ms: u64,
    ) -> Result<OrganizationWrite, StoreError> {
        let opened = sqlx::query!(
            "INSERT INTO work.access_organization
                 (tenant, organization, origin, access_pos, access_idx, changed_at, mapped_at, updated_at)
             VALUES ($1, $2::text::uuid, 'event', $3, $4,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $5::bigint::double precision,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $6::bigint::double precision,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $6::bigint::double precision)
             ON CONFLICT (tenant, organization) DO NOTHING",
            tenant,
            organization,
            signed(position.0)?,
            signed(position.1)?,
            signed(changed_at_ms)?,
            signed(at_ms)?
        )
        .execute(self.pool())
        .await?;
        if opened.rows_affected() == 1 {
            return Ok(OrganizationWrite::Mapped);
        }
        let moved = sqlx::query!(
            "UPDATE work.access_organization
             SET access_pos = $3,
                 access_idx = $4,
                 changed_at = pg_catalog.to_timestamp(0) + interval '1 millisecond' * $5::bigint::double precision,
                 updated_at = GREATEST(updated_at,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $6::bigint::double precision)
             WHERE tenant = $1 AND organization = $2::text::uuid
               AND (access_pos IS NULL OR (access_pos, access_idx) < ($3::bigint, $4::bigint))",
            tenant,
            organization,
            signed(position.0)?,
            signed(position.1)?,
            signed(changed_at_ms)?,
            signed(at_ms)?
        )
        .execute(self.pool())
        .await?;
        Ok(if moved.rows_affected() == 1 {
            OrganizationWrite::Moved
        } else {
            OrganizationWrite::Stale
        })
    }
}
