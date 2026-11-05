//! What a rebuild reads and how its rows are compared (§18 OP-1 items 2 and 3, OP-2, T-10, T-11): [`CanonicalLog`] reads a ledger's canonical log, the log rows with the externally signed bytes each record was received as, and nothing derived from them; [`LedgerTx::snapshot`] reads every row the append writes beside the log in a form that compares row for row across databases, and [`diff`] names the rows one side lacks; the idempotency keys and inbound events, whose identity comes from the request rather than from the record, are checked against the log row they answer by [`LedgerTx::log_mismatches`].

use sqlx::PgPool;

use crate::publisher::check_role;
use crate::{LedgerId, LedgerTx, ReceivedKind, ReceivedRole, ReceivedRow, StoreError};

/// The login role a [`CanonicalLog`] must have; it only reads (T-79).
pub const REBUILD_ROLE: &str = "work_app";

/// The only tables a rebuild reads (§18 OP-1 item 3, OP-2, T-90).
pub const CANONICAL_INPUTS: [&str; 3] = ["ledger.log", "work.log_received", "work.received_bytes"];

pub(crate) const LOG_PAGE: &str = include_str!("../queries/rebuild/log_page.sql");

pub(crate) const RECEIVED_PAGE: &str = include_str!("../queries/rebuild/received_page.sql");

/// The statements of [`CanonicalLog`], the whole of what a rebuild reads.
pub const CANONICAL_READS: [&str; 2] = [LOG_PAGE, RECEIVED_PAGE];

/// The tables the append writes beside the log and a rebuild reconstructs, each with the
/// statement that reads its rows as text: without the ledger id and the leader epoch, times as
/// Unix milliseconds and the stored bytes of the log by their SHA-256 (T-10, T-89, T-90).
/// [`LedgerTx::snapshot`] runs the same files, checked at compile time, in this order.
const COMPARED: [(&str, &str); 14] = [
    (
        "ledger.head",
        include_str!("../queries/rebuild/ledger_head.sql"),
    ),
    (
        "ledger.log",
        include_str!("../queries/rebuild/ledger_log.sql"),
    ),
    (
        "ledger.version_activation",
        include_str!("../queries/rebuild/version_activation.sql"),
    ),
    (
        "work.ledger_profile",
        include_str!("../queries/rebuild/ledger_profile.sql"),
    ),
    (
        "work.received_bytes",
        include_str!("../queries/rebuild/received_bytes.sql"),
    ),
    (
        "work.log_received",
        include_str!("../queries/rebuild/log_received.sql"),
    ),
    (
        "work.record_header",
        include_str!("../queries/rebuild/record_header.sql"),
    ),
    (
        "work.work_root",
        include_str!("../queries/rebuild/work_root.sql"),
    ),
    (
        "work.log_concerns",
        include_str!("../queries/rebuild/log_concerns.sql"),
    ),
    (
        "work.log_basis",
        include_str!("../queries/rebuild/log_basis.sql"),
    ),
    (
        "work.log_relation",
        include_str!("../queries/rebuild/log_relation.sql"),
    ),
    (
        "work.body_commitment",
        include_str!("../queries/rebuild/body_commitment.sql"),
    ),
    (
        "work.item_head",
        include_str!("../queries/rebuild/item_head.sql"),
    ),
    (
        "work.one_time_flag",
        include_str!("../queries/rebuild/one_time_flag.sql"),
    ),
];

/// The tables whose rows carry what the request said and are checked against the log row they
/// answer instead of being rebuilt, each with the statement that reads the rows that do not
/// match it (OP-8, OP-36 item 1, OP-38 item 5, T-91 item 5). [`LedgerTx::log_mismatches`] runs
/// the same files, checked at compile time, in this order.
const CHECKED: [(&str, &str); 2] = [
    (
        "work.idempotency_key",
        include_str!("../queries/rebuild/idempotency_key.sql"),
    ),
    (
        "work.inbound_seen",
        include_str!("../queries/rebuild/inbound_seen.sql"),
    ),
];

/// The tables a rebuild-diff covers: the reconstructed ones, then the ones checked against the
/// log (T-10).
#[must_use]
pub fn covered_tables() -> Vec<&'static str> {
    COMPARED
        .iter()
        .chain(CHECKED.iter())
        .map(|(table, _)| *table)
        .collect()
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// One stored entry of the canonical log with the bytes its record was received as (P-5 item 4,
/// T-90).
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalEntry {
    /// Log position.
    pub pos: u64,
    /// Ledger time, Unix milliseconds.
    pub recorded_at_ms: u64,
    /// The stored record bytes; the genesis bytes at position 0.
    pub record_bytes: Vec<u8>,
    /// The stored envelope bytes.
    pub envelope_bytes: Vec<u8>,
    /// The externally signed bytes linked to the record, by role.
    pub received: Vec<ReceivedRow>,
}

impl std::fmt::Debug for CanonicalEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanonicalEntry")
            .field("pos", &self.pos)
            .field("recorded_at_ms", &self.recorded_at_ms)
            .field("record_bytes", &self.record_bytes.len())
            .field("envelope_bytes", &self.envelope_bytes.len())
            .field("received", &self.received)
            .finish()
    }
}

/// The canonical log as a rebuild reads it, over a pool logged in as `work_app`. It is not an
/// executor and has no statement but [`CANONICAL_READS`], so a rebuild cannot take a derived row
/// as input (§18 OP-1 item 3, T-11):
///
/// ```compile_fail
/// # async fn f(p: &work_store::CanonicalLog) {
/// sqlx::query("SELECT 1").execute(p).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct CanonicalLog {
    pool: PgPool,
}

impl CanonicalLog {
    /// Over `pool` after checking that its role is `work_app` or holds its privileges.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Role`] for any other role.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        check_role(&pool, REBUILD_ROLE).await?;
        Ok(Self { pool })
    }

    /// Up to `limit` entries of `ledger` from position `from` on, in position order, each with
    /// the received bytes linked to it.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-range or unknown value.
    pub async fn entries(
        &self,
        ledger: &LedgerId,
        from: u64,
        limit: u32,
    ) -> Result<Vec<CanonicalEntry>, StoreError> {
        let id = *ledger.as_bytes();
        let mut tx = LedgerTx::begin_snapshot(&self.pool, ledger).await?;
        let rows = sqlx::query_file!(
            "queries/rebuild/log_page.sql",
            id.as_slice(),
            signed(from)?,
            i64::from(limit)
        )
        .fetch_all(tx.conn())
        .await?;
        let mut out = rows
            .into_iter()
            .map(|r| {
                Ok(CanonicalEntry {
                    pos: unsigned(r.pos)?,
                    recorded_at_ms: unsigned(r.at)?,
                    record_bytes: r.record_bytes,
                    envelope_bytes: r.envelope_bytes,
                    received: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let span = out.first().map(|e| e.pos).zip(out.last().map(|e| e.pos));
        if let Some((first, last)) = span {
            let received = sqlx::query_file!(
                "queries/rebuild/received_page.sql",
                id.as_slice(),
                signed(first)?,
                signed(last)?
            )
            .fetch_all(tx.conn())
            .await?;
            for r in received {
                let (pos, role, kind, bytes) = (unsigned(r.pos)?, r.role, r.kind, r.bytes);
                let at = out
                    .binary_search_by_key(&pos, |e| e.pos)
                    .map_err(|_| StoreError::Corrupt)?;
                let entry = out.get_mut(at).ok_or(StoreError::Corrupt)?;
                entry.received.push(ReceivedRow {
                    kind: ReceivedKind::from_stored(&kind).ok_or(StoreError::Corrupt)?,
                    role: ReceivedRole::from_stored(&role).ok_or(StoreError::Corrupt)?,
                    bytes,
                });
            }
        }
        tx.rollback().await?;
        Ok(out)
    }
}

/// The rows of every table [`LedgerTx::snapshot`] reads, each table's rows as text in byte
/// order. A row names pseudonymous Party references, so `Debug` shows counts only.
#[derive(Clone, PartialEq, Eq)]
pub struct Snapshot {
    tables: Vec<(&'static str, Vec<String>)>,
}

impl Snapshot {
    /// From the rows of each table; the rows are sorted here.
    #[must_use]
    pub fn new(tables: Vec<(&'static str, Vec<String>)>) -> Self {
        let tables = tables
            .into_iter()
            .map(|(table, mut rows)| {
                rows.sort_unstable();
                (table, rows)
            })
            .collect();
        Self { tables }
    }

    /// The rows of `table`, `None` for a table the snapshot does not hold.
    #[must_use]
    pub fn rows(&self, table: &str) -> Option<&[String]> {
        self.tables
            .iter()
            .find(|(t, _)| *t == table)
            .map(|(_, rows)| rows.as_slice())
    }

    /// The tables, in reading order.
    pub fn tables(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.tables.iter().map(|(t, _)| *t)
    }
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.tables.iter().map(|(t, rows)| (t, rows.len())))
            .finish()
    }
}

/// The rows of one table that differ between the live database and its rebuild. A row names
/// pseudonymous Party references, so `Debug` shows counts only.
#[derive(Clone, PartialEq, Eq)]
pub struct TableDiff {
    /// The table.
    pub table: &'static str,
    /// Rows the rebuild has and the live database lacks.
    pub missing: Vec<String>,
    /// Rows the live database has and the rebuild does not, or that do not match the log.
    pub unexpected: Vec<String>,
}

impl std::fmt::Debug for TableDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TableDiff")
            .field("table", &self.table)
            .field("missing", &self.missing.len())
            .field("unexpected", &self.unexpected.len())
            .finish()
    }
}

/// The outcome of a rebuild-diff of one ledger (§18 OP-1 item 3): clean, or the tables whose rows
/// differ. Any difference is a sev-1 signal and the log decides: the live rows are wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildDiff {
    ledger: LedgerId,
    through: u64,
    tables: Vec<TableDiff>,
}

impl RebuildDiff {
    /// The outcome for `ledger` rebuilt through position `through`; tables without a difference
    /// are dropped.
    #[must_use]
    pub fn new(ledger: LedgerId, through: u64, tables: Vec<TableDiff>) -> Self {
        let tables = tables
            .into_iter()
            .filter(|t| !t.missing.is_empty() || !t.unexpected.is_empty())
            .collect();
        Self {
            ledger,
            through,
            tables,
        }
    }

    /// The ledger.
    #[must_use]
    pub const fn ledger(&self) -> &LedgerId {
        &self.ledger
    }

    /// The last position compared.
    #[must_use]
    pub const fn through(&self) -> u64 {
        self.through
    }

    /// Whether the live rows equal their rebuild.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.tables.is_empty()
    }

    /// The tables whose rows differ.
    #[must_use]
    pub fn tables(&self) -> &[TableDiff] {
        &self.tables
    }

    /// How many rows differ in all.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.tables.iter().fold(0_usize, |n, t| {
            n.saturating_add(t.missing.len())
                .saturating_add(t.unexpected.len())
        })
    }
}

/// The rows of `a` that `b` lacks and the rows of `b` that `a` lacks, counted as multisets; both
/// sorted.
fn sorted_difference(a: &[String], b: &[String]) -> (Vec<String>, Vec<String>) {
    let mut only_a = Vec::new();
    let mut only_b = Vec::new();
    let mut left = a.iter().peekable();
    let mut right = b.iter().peekable();
    loop {
        match (left.peek(), right.peek()) {
            (Some(x), Some(y)) => match x.cmp(y) {
                std::cmp::Ordering::Less => only_a.extend(left.next().cloned()),
                std::cmp::Ordering::Greater => only_b.extend(right.next().cloned()),
                std::cmp::Ordering::Equal => {
                    left.next();
                    right.next();
                }
            },
            (Some(_), None) => only_a.extend(left.next().cloned()),
            (None, Some(_)) => only_b.extend(right.next().cloned()),
            (None, None) => break,
        }
    }
    (only_a, only_b)
}

/// The tables whose rows differ between `live` and `rebuilt`, in reading order; a table one side
/// lacks counts as empty there (§18 OP-1 item 3).
#[must_use]
pub fn diff(live: &Snapshot, rebuilt: &Snapshot) -> Vec<TableDiff> {
    let mut tables: Vec<&'static str> = live.tables().collect();
    tables.extend(rebuilt.tables().filter(|t| live.rows(t).is_none()));
    tables
        .into_iter()
        .filter_map(|table| {
            let (unexpected, missing) = sorted_difference(
                live.rows(table).unwrap_or_default(),
                rebuilt.rows(table).unwrap_or_default(),
            );
            if missing.is_empty() && unexpected.is_empty() {
                None
            } else {
                Some(TableDiff {
                    table,
                    missing,
                    unexpected,
                })
            }
        })
        .collect()
}

impl LedgerTx<'_> {
    /// Every row of the ledger that the append writes beside the log and a rebuild
    /// reconstructs (§18 OP-1 items 2 and 3, T-89, T-90). Open the transaction with
    /// [`LedgerTx::begin_snapshot`] so the tables are read at one state.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn snapshot(&mut self) -> Result<Snapshot, StoreError> {
        let id = *self.ledger().as_bytes();
        let id = id.as_slice();
        let rows = [
            sqlx::query_file_scalar!("queries/rebuild/ledger_head.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/ledger_log.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/version_activation.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/ledger_profile.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/received_bytes.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/log_received.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/record_header.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/work_root.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/log_concerns.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/log_basis.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/log_relation.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/body_commitment.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/item_head.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/one_time_flag.sql", id)
                .fetch_all(self.conn())
                .await?,
        ];
        let tables = COMPARED.iter().map(|(table, _)| *table).zip(rows).collect();
        Ok(Snapshot::new(tables))
    }

    /// The idempotency keys and inbound events whose stored result does not match the log row
    /// it names: another record id, or a time other than that record's ledger time (OP-8,
    /// OP-38 item 5, T-91 item 5).
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn log_mismatches(&mut self) -> Result<Vec<TableDiff>, StoreError> {
        let id = *self.ledger().as_bytes();
        let id = id.as_slice();
        let rows = [
            sqlx::query_file_scalar!("queries/rebuild/idempotency_key.sql", id)
                .fetch_all(self.conn())
                .await?,
            sqlx::query_file_scalar!("queries/rebuild/inbound_seen.sql", id)
                .fetch_all(self.conn())
                .await?,
        ];
        Ok(CHECKED
            .iter()
            .zip(rows)
            .map(|(&(table, _), mut unexpected)| {
                unexpected.sort_unstable();
                TableDiff {
                    table,
                    missing: Vec::new(),
                    unexpected,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// The `COMMENT ON TABLE` label of every table the canonical migrations create.
    fn labels() -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for sql in crate::migrate::canonical_sql() {
            for line in sql.lines() {
                let Some(rest) = line.strip_prefix("COMMENT ON TABLE ") else {
                    continue;
                };
                let Some((table, comment)) = rest.split_once(" IS 'label=") else {
                    continue;
                };
                let label = comment.split(';').next().unwrap_or_default();
                out.insert(table.to_owned(), label.to_owned());
            }
        }
        out
    }

    /// The `schema.table` names a statement reads.
    fn tables_in(sql: &str) -> Vec<String> {
        sql.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .filter(|w| w.starts_with("ledger.") || w.starts_with("work."))
            .map(str::to_owned)
            .collect()
    }

    // OP-1 T-11 T-10 OP-2
    #[test]
    fn op_1_a_rebuild_reads_only_canonical_tables() {
        let labels = labels();
        let read: Vec<String> = CANONICAL_READS.iter().flat_map(|s| tables_in(s)).collect();
        assert_ne!(read.len(), 0);
        for table in &read {
            assert!(CANONICAL_INPUTS.contains(&table.as_str()), "{table}");
        }
        for table in CANONICAL_INPUTS {
            assert_eq!(
                labels.get(table).map(String::as_str),
                Some("CANONICAL"),
                "{table}"
            );
            assert!(read.iter().any(|r| r == table), "{table}");
        }
    }

    // T-10 P-2
    #[test]
    fn t_10_an_export_reads_only_canonical_tables() {
        let labels = labels();
        let read: Vec<String> = crate::EXPORT_READS
            .iter()
            .flat_map(|s| tables_in(s))
            .collect();
        for table in &read {
            assert!(crate::EXPORT_INPUTS.contains(&table.as_str()), "{table}");
        }
        for table in crate::EXPORT_INPUTS {
            assert_eq!(
                labels.get(table).map(String::as_str),
                Some("CANONICAL"),
                "{table}"
            );
            assert!(read.iter().any(|r| r == table), "{table}");
        }
        for table in CANONICAL_INPUTS {
            assert!(crate::EXPORT_INPUTS.contains(&table), "{table}");
        }
    }

    // T-10 OP-1 OP-2
    #[test]
    fn t_10_every_sync_derived_table_is_rebuilt_or_checked_against_the_log() {
        let labels = labels();
        let covered = covered_tables();
        for (table, label) in &labels {
            if label == "SYNC-DERIVED" && table != "ledger.outbox" {
                assert!(covered.contains(&table.as_str()), "{table}");
            }
        }
        for table in &covered {
            assert!(labels.contains_key(*table), "{table}");
        }
        assert!(!covered.contains(&"ledger.outbox"));
        for (table, sql) in COMPARED.iter().chain(CHECKED.iter()) {
            assert!(tables_in(sql).iter().any(|t| t == table), "{table}");
        }
    }

    // OP-45 OP-2 T-10
    #[test]
    fn op_45_body_tables_are_neither_rebuilt_nor_compared() {
        let labels = labels();
        let covered = covered_tables();
        for table in [
            "work.body_part",
            "work.body_part_key",
            "work.body_dek",
            "work.body_part_tombstone",
        ] {
            let label = labels.get(table).map(String::as_str);
            assert!(
                matches!(label, Some("CANONICAL" | "OPERATIONAL")),
                "{table}"
            );
            assert!(!covered.contains(&table), "{table}");
            assert!(!CANONICAL_INPUTS.contains(&table), "{table}");
        }
        assert!(covered.contains(&"work.body_commitment"));
    }

    fn rows(rows: &[&str]) -> Vec<String> {
        rows.iter().map(|r| (*r).to_owned()).collect()
    }

    // OP-1
    #[test]
    fn op_1_the_diff_names_each_missing_and_unexpected_row() {
        let live = Snapshot::new(vec![
            (
                "work.item_head",
                rows(&["(work,\\x01,3,9,)", "(work,\\x02,1,4,)"]),
            ),
            ("work.log_concerns", rows(&["(a,1)", "(a,1)", "(b,2)"])),
            ("work.one_time_flag", rows(&[])),
        ]);
        let rebuilt = Snapshot::new(vec![
            (
                "work.item_head",
                rows(&["(work,\\x02,1,4,)", "(work,\\x01,2,7,)"]),
            ),
            ("work.log_concerns", rows(&["(b,2)", "(a,1)"])),
            ("work.one_time_flag", rows(&[])),
        ]);
        assert_eq!(diff(&live, &live), Vec::<TableDiff>::new());
        assert_eq!(diff(&rebuilt, &rebuilt), Vec::<TableDiff>::new());
        let found = diff(&live, &rebuilt);
        assert_eq!(
            found,
            vec![
                TableDiff {
                    table: "work.item_head",
                    missing: rows(&["(work,\\x01,2,7,)"]),
                    unexpected: rows(&["(work,\\x01,3,9,)"]),
                },
                TableDiff {
                    table: "work.log_concerns",
                    missing: vec![],
                    unexpected: rows(&["(a,1)"]),
                },
            ]
        );
        let outcome = RebuildDiff::new(LedgerId::from_bytes([7; 32]), 9, found);
        assert!(!outcome.is_clean());
        assert_eq!(outcome.rows(), 3);
        assert_eq!(outcome.through(), 9);
        assert!(!format!("{outcome:?}").contains("work,"));
        let only_live = Snapshot::new(vec![("ledger.head", rows(&["(1)"]))]);
        let empty = Snapshot::new(vec![]);
        assert_eq!(diff(&only_live, &empty)[0].unexpected, rows(&["(1)"]));
        assert_eq!(diff(&empty, &only_live)[0].missing, rows(&["(1)"]));
        assert!(RebuildDiff::new(LedgerId::from_bytes([7; 32]), 9, vec![]).is_clean());
    }
}
