//! The retention end job (§18 OP-14 note, OP-12 item 4, OP-30, OP-45 item 5, Access OP-147). It
//! is level-triggered: each pass weighs every active class DEK of a ledger as it stands, under
//! every schedule its class falls under (the tenant's from the Access policy snapshot, or
//! `Schedule::work_default` while the snapshot names none), with the Access holds cached for the
//! ledger and the snapshot's age at trusted time, and destroys the class DEK through the body
//! eraser only when the shared `may_destroy` answers `Destroy` for every one of them. `Retain`
//! and `Defer` do nothing; without a snapshot the answer is `Defer` and nothing is destroyed.
//! Only the record event Work knows, `Recorded`, is given a time; every other event is unknown.

use std::sync::Arc;
use std::time::Duration;

use suiss_retention::{
    Class, Decision, Defer, Event, Hold, Length, Occurrence, PolicyVersion, Record, Schedule,
    SubjectId, TenantId, Timestamp, may_destroy,
};
use work_store::{ClassDek, Erased, LedgerId};

use crate::body::{BodyEraser, BodyError};

/// Class DEKs one page of a pass weighs (T-83).
pub const RETENTION_PAGE: u32 = 256;

/// The tenant's retention policy as Access last gave it (Access OP-147): its schedules and the
/// trusted time it was taken at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    /// The tenant the snapshot is for.
    pub tenant: TenantId,
    /// When Access took it.
    pub taken_at: Timestamp,
    /// The tenant's schedules.
    pub schedules: Vec<Schedule>,
}

/// What one pass did (OP-14).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionPass {
    /// Class DEKs destroyed.
    pub destroyed: usize,
    /// Class DEKs still kept: a hold, a running period or an awaited event.
    pub retained: usize,
    /// Class DEKs whose state was not known well enough to destroy.
    pub deferred: usize,
    /// Class DEKs answered `Destroy` that changed or were held before the removal.
    pub skipped: usize,
}

/// The schedules a record of `class` falls under for `tenant`: every schedule of the class in
/// `snapshot`, or the Work default while it names none (OP-14 note). Classes without a Work
/// default (`audit`, `traffic`, `dsr_log`, `erasure_log`) have only the snapshot's.
#[must_use]
pub fn schedules_for(
    tenant: &TenantId,
    class: Class,
    snapshot: Option<&PolicySnapshot>,
) -> Vec<Schedule> {
    let from_access: Vec<Schedule> = snapshot
        .into_iter()
        .flat_map(|s| s.schedules.iter())
        .filter(|s| s.class == class)
        .cloned()
        .collect();
    if !from_access.is_empty() {
        return from_access;
    }
    Schedule::work_default(tenant.clone(), class, PolicyVersion::new(0))
        .into_iter()
        .collect()
}

fn occurrence(event: Event, newest: Option<Timestamp>) -> Occurrence {
    match (event, newest) {
        (Event::Recorded, Some(at)) => Occurrence::At(at),
        _ => Occurrence::Unknown,
    }
}

/// Whether `dek` of `tenant` may be destroyed at trusted time `now` (OP-14 note): the shared
/// decision under each schedule of its class, `Destroy` only when every one answers it. A
/// snapshot of another tenant, or taken after `now`, counts as none.
pub fn retention_decision(
    tenant: &TenantId,
    dek: &ClassDek,
    snapshot: Option<&PolicySnapshot>,
    holds: &[Hold],
    now: Timestamp,
) -> Decision {
    let snapshot = snapshot.filter(|s| s.tenant == *tenant);
    let age = snapshot
        .and_then(|s| now.unix_millis().checked_sub(s.taken_at.unix_millis()))
        .map(Duration::from_millis);
    let newest = dek.newest_ms.map(Timestamp::from_unix_millis);
    let subject = SubjectId::new(dek.subject.clone());
    let mut verdict = Decision::Defer(Defer::Mismatch);
    for schedule in schedules_for(tenant, dek.class.class(), snapshot) {
        let end = if let Length::Until(event) = schedule.length {
            occurrence(event, newest)
        } else {
            Occurrence::Unknown
        };
        let record = Record {
            tenant: tenant.clone(),
            class: schedule.class,
            subject: Some(subject.clone()),
            start: occurrence(schedule.start, newest),
            end,
        };
        let decision = may_destroy(&schedule, &record, holds, age, now);
        if !decision.is_destroy() {
            return decision;
        }
        verdict = decision;
    }
    verdict
}

/// The retention end job over one body eraser (OP-14 note).
#[derive(Debug, Clone)]
pub struct RetentionJob {
    eraser: Arc<BodyEraser>,
    page: u32,
}

impl RetentionJob {
    /// Over `eraser`, weighing [`RETENTION_PAGE`] class DEKs a page.
    #[must_use]
    pub fn new(eraser: Arc<BodyEraser>) -> Self {
        Self {
            eraser,
            page: RETENTION_PAGE,
        }
    }

    /// One pass over `ledger` of `tenant` at trusted time `now` with the Access policy
    /// `snapshot`, `None` while Access has given none (OP-14 note): every active class DEK is
    /// weighed with the cached holds and destroyed only on `Destroy`.
    ///
    /// # Errors
    /// [`BodyError`] from the store; class DEKs weighed before it keep their outcome.
    pub async fn pass(
        &self,
        ledger: &LedgerId,
        tenant: &TenantId,
        snapshot: Option<&PolicySnapshot>,
        now: Timestamp,
    ) -> Result<RetentionPass, BodyError> {
        let holds = self.eraser.holds(ledger, tenant).await?;
        let mut out = RetentionPass::default();
        let mut after: Option<String> = None;
        loop {
            let page = self
                .eraser
                .class_deks(ledger, after.as_deref(), self.page)
                .await?;
            for dek in &page {
                let decision = retention_decision(tenant, dek, snapshot, &holds, now);
                if decision.is_destroy() {
                    if let Erased::Shredded { .. } = self.eraser.expire(ledger, dek).await? {
                        out.destroyed = out.destroyed.saturating_add(1);
                    } else {
                        out.skipped = out.skipped.saturating_add(1);
                    }
                } else if matches!(decision, Decision::Retain(_)) {
                    out.retained = out.retained.saturating_add(1);
                } else {
                    out.deferred = out.deferred.saturating_add(1);
                }
            }
            let full = u32::try_from(page.len()).is_ok_and(|n| n >= self.page);
            match page.last() {
                Some(last) if full => after = Some(last.dek_id.clone()),
                _ => break,
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
