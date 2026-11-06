//! The SEC-36 compromise window rows (WD-123): the ledgers of a tenant that hold a record of a window, read from `work.record_signer` over the `work_access` pool, and, inside one ledger's scope, the notices already written and those whose window holds a record's ledger time.

use crate::{AccessPool, LedgerTx, StoreError};

/// A record of a window: its ledger and the `kid` that signed it, or none for an unsigned
/// record of the compromised Party.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WindowHit {
    /// The ledger.
    pub ledger: [u8; 32],
    /// The `kid` of a signed record.
    pub kid: Option<[u8; 32]>,
}

/// A notice whose window holds a record's ledger time (C-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoticeView {
    /// The notice record.
    pub record: [u8; 32],
    /// Its position.
    pub pos: u64,
    /// The window's start, Unix milliseconds.
    pub window_from_ms: u64,
    /// The window's end, Unix milliseconds.
    pub window_to_ms: u64,
    /// The compromised kids.
    pub kids: Vec<[u8; 32]>,
    /// The compromised Party.
    pub party: Option<String>,
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn fixed(raw: &[u8]) -> Result<[u8; 32], StoreError> {
    raw.try_into().map_err(|_| StoreError::Corrupt)
}

impl AccessPool {
    /// The distinct ledgers and kids of `tenant`'s records recorded inside
    /// `from_ms..=to_ms` that one of `kids` signed or that `party` wrote unsigned (SEC-36
    /// item 3, WD-123 item 1).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn window_ledgers(
        &self,
        tenant: &str,
        kids: &[[u8; 32]],
        party: &str,
        from_ms: u64,
        to_ms: u64,
    ) -> Result<Vec<WindowHit>, StoreError> {
        let kids: Vec<Vec<u8>> = kids.iter().map(|k| k.to_vec()).collect();
        let rows = sqlx::query!(
            r#"SELECT DISTINCT ledger_id::bytea AS "ledger!", kid AS "kid?"
               FROM work.record_signer
               WHERE tenant = $1
                 AND recorded_at BETWEEN
                     pg_catalog.to_timestamp(0) + interval '1 millisecond' * $4::bigint::double precision
                 AND pg_catalog.to_timestamp(0) + interval '1 millisecond' * $5::bigint::double precision
                 AND (kid = ANY ($2::bytea[]) OR author::text = $3)
               ORDER BY 1, 2"#,
            tenant,
            kids.as_slice(),
            party,
            signed(from_ms)?,
            signed(to_ms)?
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(WindowHit {
                    ledger: fixed(&r.ledger)?,
                    kid: r.kid.as_deref().map(fixed).transpose()?,
                })
            })
            .collect()
    }
}

impl LedgerTx<'_> {
    /// Whether the ledger holds the notice of the event whose bytes have `event_digest`
    /// (SEC-36 item 4).
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn has_notice(&mut self, event_digest: &[u8; 32]) -> Result<bool, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let found = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM work.compromise_notice
               WHERE ledger_id = $1 AND event_digest = $2) AS "found!""#,
            ledger.as_slice(),
            event_digest.as_slice()
        )
        .fetch_one(self.conn())
        .await?;
        Ok(found)
    }

    /// The notices of the ledger whose window holds `recorded_at_ms`, in log order (C-4).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn notices_at(&mut self, recorded_at_ms: i64) -> Result<Vec<NoticeView>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let rows = sqlx::query!(
            r#"SELECT l.record_id::bytea AS "record!", n.pos::bigint AS "pos!",
                      (extract(epoch FROM n.window_from) * 1000)::bigint AS "window_from_ms!",
                      (extract(epoch FROM n.window_to) * 1000)::bigint AS "window_to_ms!",
                      n.kids AS "kids!", n.party::text AS "party?"
               FROM work.compromise_notice n
               JOIN ledger.log l ON l.ledger_id = n.ledger_id AND l.pos = n.pos
               WHERE n.ledger_id = $1
                 AND n.window_from <= pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $2::bigint::double precision
                 AND n.window_to >= pg_catalog.to_timestamp(0)
                     + interval '1 millisecond' * $2::bigint::double precision
               ORDER BY n.pos"#,
            ledger.as_slice(),
            recorded_at_ms
        )
        .fetch_all(self.conn())
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(NoticeView {
                    record: fixed(&r.record)?,
                    pos: unsigned(r.pos)?,
                    window_from_ms: unsigned(r.window_from_ms)?,
                    window_to_ms: unsigned(r.window_to_ms)?,
                    kids: r
                        .kids
                        .iter()
                        .map(|k| fixed(k.as_slice()))
                        .collect::<Result<_, _>>()?,
                    party: r.party,
                })
            })
            .collect()
    }
}
