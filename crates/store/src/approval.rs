//! The approval `state`s Work sends to Access's Approval Surface (T-101 item 7, E-17): one OPERATIONAL row per pushed authority request in `work.approval_state`, keyed by the `state` and bound to the caller's tenant and Party, the pushed request's digest and the ledger it commits into. A `state` is issued once and used once: the row is inserted, then marked used, and never deleted (Access OP-73); only `work_access` reads and writes it.

use crate::{AccessPool, StoreError};

/// A `state` to issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewApprovalState<'a> {
    /// The `state`, 43 characters of unpadded base64url.
    pub state: &'a str,
    /// The caller's tenant.
    pub tenant: &'a str,
    /// The caller's Party.
    pub party: [u8; 16],
    /// The digest of the pushed request.
    pub digest: [u8; 32],
    /// The ledger the request commits into.
    pub ledger: [u8; 32],
    /// When it is issued, Unix milliseconds.
    pub issued_at_ms: u64,
    /// The last instant it is accepted, Unix milliseconds.
    pub expires_at_ms: u64,
}

/// A stored `state`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalStateRow {
    /// The `state`.
    pub state: String,
    /// The caller's tenant.
    pub tenant: String,
    /// The caller's Party.
    pub party: [u8; 16],
    /// The digest of the pushed request.
    pub digest: [u8; 32],
    /// The ledger the request commits into.
    pub ledger: [u8; 32],
    /// When it was issued, Unix milliseconds.
    pub issued_at_ms: u64,
    /// The last instant it is accepted, Unix milliseconds.
    pub expires_at_ms: u64,
    /// When it was used, Unix milliseconds.
    pub used_at_ms: Option<u64>,
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn fixed<const N: usize>(raw: &[u8]) -> Result<[u8; N], StoreError> {
    raw.try_into().map_err(|_| StoreError::Corrupt)
}

impl AccessPool {
    /// Issues `new`; `false` when the `state` is issued already, which leaves its row as it is.
    ///
    /// # Errors
    /// [`StoreError::Db`] for a value the schema refuses.
    pub async fn issue_approval_state(
        &self,
        new: &NewApprovalState<'_>,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "INSERT INTO work.approval_state
                 (state, tenant, party, digest, ledger, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $6::bigint::double precision,
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $7::bigint::double precision)
             ON CONFLICT (state) DO NOTHING",
            new.state,
            new.tenant,
            new.party.as_slice(),
            new.digest.as_slice(),
            new.ledger.as_slice(),
            signed(new.issued_at_ms)?,
            signed(new.expires_at_ms)?
        )
        .execute(self.pool())
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The stored `state`.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn approval_state(
        &self,
        state: &str,
    ) -> Result<Option<ApprovalStateRow>, StoreError> {
        let row = sqlx::query!(
            r#"SELECT state, tenant, party, digest, ledger,
                      (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at_ms!",
                      (extract(epoch FROM expires_at) * 1000)::bigint AS "expires_at_ms!",
                      (extract(epoch FROM used_at) * 1000)::bigint AS "used_at_ms?"
               FROM work.approval_state WHERE state = $1"#,
            state
        )
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| {
            Ok(ApprovalStateRow {
                state: r.state,
                tenant: r.tenant,
                party: fixed(&r.party)?,
                digest: fixed(&r.digest)?,
                ledger: fixed(&r.ledger)?,
                issued_at_ms: unsigned(r.issued_at_ms)?,
                expires_at_ms: unsigned(r.expires_at_ms)?,
                used_at_ms: r.used_at_ms.map(unsigned).transpose()?,
            })
        })
        .transpose()
    }

    /// Marks `state` used at `at_ms`; `false` when it is unknown, used already or expired at
    /// `at_ms`, so of two returns with one `state` at most one is `true`.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn use_approval_state(&self, state: &str, at_ms: u64) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "UPDATE work.approval_state
                SET used_at = pg_catalog.to_timestamp(0) + interval '1 millisecond' * $2::bigint::double precision
              WHERE state = $1 AND used_at IS NULL
                AND expires_at >= pg_catalog.to_timestamp(0) + interval '1 millisecond' * $2::bigint::double precision",
            state,
            signed(at_ms)?
        )
        .execute(self.pool())
        .await?;
        Ok(done.rows_affected() == 1)
    }
}
