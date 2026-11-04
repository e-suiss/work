//! The retention rows of the shared contract (§18 OP-14, OP-30, Access OP-147): the eight OP-14
//! classes as `esuiss-retention` names them, the cache of Access holds in `work.retention_hold`
//! (only what Access sent: kind, scope, placement, exclusive end and the suspicious-activity flag),
//! and the active class DEKs with the ledger time of the newest record under each, which the
//! retention end job weighs. Writes and reads go through the erasure role.

use suiss_retention::{Class, Hold, HoldId, HoldKind, HoldScope, SubjectId, TenantId, Timestamp};

use crate::body::{RetentionClass, signed};
use crate::skeleton::refused;
use crate::{ErasurePool, LedgerId, LedgerTx, StoreError};

/// The eight OP-14 classes, as the shared contract names them (OP-14, OP-30 item 1).
pub const WORK_CLASSES: [Class; 8] = [
    Class::WorkRecord,
    Class::WorkEvidence,
    Class::WorkDraft,
    Class::AgentTrace,
    Class::Audit,
    Class::Traffic,
    Class::DsrLog,
    Class::ErasureLog,
];

/// The OP-14 class stored as `name`; `None` for any other text, a class of another product
/// included.
#[must_use]
pub fn work_class(name: &str) -> Option<Class> {
    WORK_CLASSES.into_iter().find(|c| c.name() == name)
}

impl RetentionClass {
    /// The shared contract's class of this body class (OP-14).
    #[must_use]
    pub const fn class(self) -> Class {
        match self {
            Self::WorkRecord => Class::WorkRecord,
            Self::WorkEvidence => Class::WorkEvidence,
            Self::WorkDraft => Class::WorkDraft,
            Self::AgentTrace => Class::AgentTrace,
        }
    }

    /// The body class of `class`; `None` for a class no body part is kept under.
    #[must_use]
    pub fn of(class: Class) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.class() == class)
    }
}

/// An active class DEK as the retention end job weighs it (OP-14, OP-45 item 5).
#[derive(Clone, PartialEq, Eq)]
pub struct ClassDek {
    /// `dek_id`, a UUID in text form.
    pub dek_id: String,
    /// The pseudonymous subject.
    pub subject: String,
    /// The body class.
    pub class: RetentionClass,
    /// The ledger time of the newest record with a part under the DEK, Unix milliseconds;
    /// `None` when no part is under it.
    pub newest_ms: Option<u64>,
}

impl std::fmt::Debug for ClassDek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClassDek")
            .field("dek_id", &self.dek_id)
            .field("class", &self.class)
            .field("newest_ms", &self.newest_ms)
            .finish_non_exhaustive()
    }
}

struct DekAge {
    dek_id: String,
    subject: String,
    class: String,
    newest: Option<i64>,
}

struct HoldTuple {
    hold_id: String,
    kind: String,
    scope: String,
    subject: Option<String>,
    classes: Option<Vec<String>>,
    suspicious: bool,
    placed_at: i64,
    until: Option<i64>,
}

fn unsigned(ms: i64) -> Result<u64, StoreError> {
    u64::try_from(ms).map_err(|_| StoreError::Corrupt)
}

const fn kind_name(kind: HoldKind) -> Option<&'static str> {
    match kind {
        HoldKind::Litigation => Some("litigation"),
        HoldKind::Regulator => Some("regulator"),
        HoldKind::LawEnforcement => Some("law_enforcement"),
        _ => None,
    }
}

fn kind_of(name: &str) -> Option<HoldKind> {
    [
        HoldKind::Litigation,
        HoldKind::Regulator,
        HoldKind::LawEnforcement,
    ]
    .into_iter()
    .find(|k| kind_name(*k) == Some(name))
}

/// One hold as stored: kind, scope, subject, classes.
type HoldColumns = (
    &'static str,
    &'static str,
    Option<String>,
    Option<Vec<String>>,
);

fn stored(hold: &Hold) -> Result<HoldColumns, StoreError> {
    let kind = kind_name(hold.kind).ok_or(StoreError::Corrupt)?;
    Ok(match &hold.scope {
        HoldScope::Subject(s) => (kind, "subject", Some(s.as_str().to_owned()), None),
        HoldScope::Classes(c) => (
            kind,
            "classes",
            None,
            Some(c.iter().map(|c| c.name().to_owned()).collect()),
        ),
        HoldScope::Tenant => (kind, "tenant", None, None),
        _ => return Err(StoreError::Corrupt),
    })
}

fn hold_of(t: HoldTuple, tenant: &TenantId) -> Result<Hold, StoreError> {
    let scope = match (t.scope.as_str(), t.subject, t.classes) {
        ("subject", Some(s), None) => HoldScope::Subject(SubjectId::new(s)),
        ("classes", None, Some(c)) => HoldScope::Classes(
            c.iter()
                .map(|n| n.parse::<Class>().map_err(|_| StoreError::Corrupt))
                .collect::<Result<_, _>>()?,
        ),
        ("tenant", None, None) => HoldScope::Tenant,
        _ => return Err(StoreError::Corrupt),
    };
    Ok(Hold {
        id: HoldId::new(t.hold_id),
        tenant: tenant.clone(),
        scope,
        placed_at: Timestamp::from_unix_millis(unsigned(t.placed_at)?),
        until: t
            .until
            .map(|u| unsigned(u).map(Timestamp::from_unix_millis))
            .transpose()?,
        kind: kind_of(&t.kind).ok_or(StoreError::Corrupt)?,
        suspicious_activity: t.suspicious,
    })
}

fn ms(at: Timestamp) -> Result<i64, StoreError> {
    i64::try_from(at.unix_millis()).map_err(|_| StoreError::Corrupt)
}

fn sorted(classes: Option<Vec<String>>) -> Option<Vec<String>> {
    classes.map(|mut c| {
        c.sort();
        c
    })
}

impl ErasurePool {
    /// Caches `hold` as Access sent it for `ledger` (OP-14 note, Access OP-147): written once,
    /// then only its end may be set, once. A hold already cached with another kind, scope,
    /// placement or flag, or whose end is set and would change, is refused.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] for a refused change; [`StoreError::Corrupt`] for a kind or
    /// scope the store does not know; [`StoreError::Db`] otherwise.
    pub async fn cache_hold(&self, ledger: &LedgerId, hold: &Hold) -> Result<(), StoreError> {
        let (kind, scope, subject, classes) = stored(hold)?;
        let placed_at = ms(hold.placed_at)?;
        let until = hold.until.map(ms).transpose()?;
        let id = ledger.as_bytes().as_slice();
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let cached = sqlx::query_as!(
            HoldTuple,
            r#"SELECT hold_id AS "hold_id!", hold_kind AS "kind!", scope AS "scope!",
                      subject_ref::text AS "subject?", retention_classes::text[] AS "classes?",
                      suspicious_activity AS "suspicious!",
                      (extract(epoch FROM placed_at) * 1000)::bigint AS "placed_at!",
                      (extract(epoch FROM released_at) * 1000)::bigint AS "until?"
               FROM work.retention_hold WHERE ledger_id = $1 AND hold_id = $2 FOR UPDATE"#,
            id,
            hold.id.as_str()
        )
        .fetch_optional(tx.conn())
        .await?;
        match cached {
            None => {
                sqlx::query!(
                    "INSERT INTO work.retention_hold
                     (ledger_id, hold_id, hold_kind, scope, subject_ref, retention_classes,
                      suspicious_activity, placed_at, state, released_at)
                     VALUES ($1, $2, $3, $4, $5::text, $6::text[]::work.snake_name[], $7,
                             'epoch'::timestamptz + $8::bigint * interval '1 millisecond',
                             CASE WHEN $9::bigint IS NULL THEN 'active' ELSE 'released' END,
                             'epoch'::timestamptz + $9::bigint * interval '1 millisecond')",
                    id,
                    hold.id.as_str(),
                    kind,
                    scope,
                    subject,
                    classes,
                    hold.suspicious_activity,
                    placed_at,
                    until
                )
                .execute(tx.conn())
                .await
                .map_err(refused)?;
            }
            Some(c) => {
                if c.kind != kind
                    || c.scope != scope
                    || c.subject != subject
                    || sorted(c.classes) != sorted(classes)
                    || c.suspicious != hold.suspicious_activity
                    || c.placed_at != placed_at
                {
                    return Err(StoreError::Constraint("hold_identity_immutable".to_owned()));
                }
                if c.until != until {
                    sqlx::query!(
                        "UPDATE work.retention_hold
                         SET state = CASE WHEN $3::bigint IS NULL THEN 'active' ELSE 'released' END,
                             released_at = 'epoch'::timestamptz + $3::bigint * interval '1 millisecond'
                         WHERE ledger_id = $1 AND hold_id = $2",
                        id,
                        hold.id.as_str(),
                        until
                    )
                    .execute(tx.conn())
                    .await
                    .map_err(refused)?;
                }
            }
        }
        tx.commit().await
    }

    /// Every hold cached for `ledger`, lifted ones included, as holds of `tenant`, the tenant
    /// the ledger belongs to (OP-14 note, Access OP-147).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn holds(
        &self,
        ledger: &LedgerId,
        tenant: &TenantId,
    ) -> Result<Vec<Hold>, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let rows = sqlx::query_as!(
            HoldTuple,
            r#"SELECT hold_id AS "hold_id!", hold_kind AS "kind!", scope AS "scope!",
                      subject_ref::text AS "subject?", retention_classes::text[] AS "classes?",
                      suspicious_activity AS "suspicious!",
                      (extract(epoch FROM placed_at) * 1000)::bigint AS "placed_at!",
                      (extract(epoch FROM released_at) * 1000)::bigint AS "until?"
               FROM work.retention_hold WHERE ledger_id = $1
               ORDER BY placed_at, hold_id"#,
            ledger.as_bytes().as_slice()
        )
        .fetch_all(tx.conn())
        .await?;
        tx.commit().await?;
        rows.into_iter().map(|t| hold_of(t, tenant)).collect()
    }

    /// One page of the active class DEKs of `ledger` after `after` in `dek_id` order, at most
    /// `limit`, each with the ledger time of its newest record (OP-14, OP-45 item 5).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a malformed row.
    pub async fn class_deks(
        &self,
        ledger: &LedgerId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ClassDek>, StoreError> {
        let mut tx = LedgerTx::begin(&self.pool, ledger).await?;
        let rows = sqlx::query_as!(
            DekAge,
            r#"SELECT d.dek_id::text AS "dek_id!", d.subject_ref::text AS "subject!",
                      d.retention_class::text AS "class!",
                      (extract(epoch FROM max(l.recorded_at)) * 1000)::bigint AS "newest?"
               FROM work.body_dek d
               LEFT JOIN work.body_part p ON p.ledger_id = d.ledger_id AND p.dek_id = d.dek_id
               LEFT JOIN ledger.log l ON l.ledger_id = p.ledger_id AND l.pos = p.pos
               WHERE d.ledger_id = $1 AND d.state = 'active'
                 AND ($2::text IS NULL OR d.dek_id > $2::text::uuid)
               GROUP BY d.ledger_id, d.dek_id, d.subject_ref, d.retention_class
               ORDER BY d.dek_id
               LIMIT $3"#,
            ledger.as_bytes().as_slice(),
            after,
            i64::from(limit)
        )
        .fetch_all(tx.conn())
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| {
                Ok(ClassDek {
                    dek_id: r.dek_id,
                    subject: r.subject,
                    class: RetentionClass::from_stored(&r.class).ok_or(StoreError::Corrupt)?,
                    newest_ms: r.newest.map(unsigned).transpose()?,
                })
            })
            .collect()
    }

    /// Destroys `dek` for the end of its retention (OP-12 item 4, OP-45 item 5) only while it is
    /// still the active DEK of its subject and class and the newest record under it is still
    /// the one weighed: otherwise, or under an active retention hold, nothing is removed or
    /// recorded and the next pass weighs it again.
    ///
    /// # Errors
    /// [`StoreError::Constraint`] when a hold appears concurrently; [`StoreError::Db`] otherwise.
    pub async fn expire_dek(
        &self,
        ledger: &LedgerId,
        dek: &ClassDek,
        settle: std::time::Duration,
    ) -> Result<crate::Erased<crate::DekRow>, StoreError> {
        let newest = dek.newest_ms.map(signed).transpose()?;
        self.destroy(
            ledger,
            &dek.subject,
            dek.class,
            crate::Shred::RetentionExpired,
            settle,
            Some((dek.dek_id.as_str(), newest)),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-14 OP-30
    #[test]
    fn op_14_the_eight_classes_are_the_shared_contract_classes() {
        let names: Vec<&str> = WORK_CLASSES.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            [
                "work_record",
                "work_evidence",
                "work_draft",
                "agent_trace",
                "audit",
                "traffic",
                "dsr_log",
                "erasure_log",
            ]
        );
        for c in WORK_CLASSES {
            assert_eq!(work_class(c.name()), Some(c));
        }
        assert_eq!(work_class("profile"), None);
        assert_eq!(work_class("one_memory"), None);
        for c in RetentionClass::ALL {
            assert_eq!(c.class().name(), c.as_str());
            assert_eq!(RetentionClass::of(c.class()), Some(c));
        }
        for c in [
            Class::Audit,
            Class::Traffic,
            Class::DsrLog,
            Class::ErasureLog,
        ] {
            assert_eq!(RetentionClass::of(c), None);
        }
    }

    // OP-14 Access OP-147
    #[test]
    fn op_14_hold_kinds_and_scopes_round_trip_their_stored_names() {
        let tenant = TenantId::new("tnt_a");
        for kind in [
            HoldKind::Litigation,
            HoldKind::Regulator,
            HoldKind::LawEnforcement,
        ] {
            assert_eq!(kind_name(kind).and_then(kind_of), Some(kind));
        }
        assert_eq!(kind_of("statutory"), None);
        for scope in [
            HoldScope::Subject(SubjectId::new("party:acme:alice")),
            HoldScope::Classes(vec![Class::WorkRecord, Class::Ledger]),
            HoldScope::Classes(vec![]),
            HoldScope::Tenant,
        ] {
            let hold = Hold {
                id: HoldId::new("hld_1"),
                tenant: tenant.clone(),
                scope,
                placed_at: Timestamp::from_unix_millis(1),
                until: Some(Timestamp::from_unix_millis(2)),
                kind: HoldKind::Regulator,
                suspicious_activity: true,
            };
            let (kind, scope, subject, classes) = stored(&hold).unwrap();
            let back = hold_of(
                HoldTuple {
                    hold_id: "hld_1".to_owned(),
                    kind: kind.to_owned(),
                    scope: scope.to_owned(),
                    subject,
                    classes,
                    suspicious: true,
                    placed_at: 1,
                    until: Some(2),
                },
                &tenant,
            )
            .unwrap();
            assert_eq!(back, hold);
        }
        let stray = HoldTuple {
            hold_id: "hld_2".to_owned(),
            kind: "litigation".to_owned(),
            scope: "classes".to_owned(),
            subject: None,
            classes: Some(vec!["not_a_class".to_owned()]),
            suspicious: false,
            placed_at: 1,
            until: None,
        };
        assert!(matches!(hold_of(stray, &tenant), Err(StoreError::Corrupt)));
    }
}
