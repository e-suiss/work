use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::state::CommitmentState;
use super::view::CommitmentView;
use crate::catalog::NoticeType;
use crate::id::{PartyRef, RecordId};
use crate::ontology::Obligor;
use crate::reason::wire_enum;

wire_enum! {
    /// Why a sub-commitment raises a signal on the commitments it supports (CM-47); a clock warning or breach and a missed periodic report come from its time Conditions.
    SupportCause {
        /// The sub-commitment was cancelled.
        Cancelled => "cancelled",
        /// The sub-commitment was declined.
        Declined => "declined",
        /// The sub-commitment expired.
        Expired => "expired",
        /// Its obligor gave an `at_risk` notice.
        AtRisk => "at_risk",
        /// Its obligor gave a `cannot_complete` notice.
        CannotComplete => "cannot_complete",
        /// Its clock reached a warning tier (CM-50).
        ClockWarning => "clock_warning",
        /// Its clock breached (CM-50).
        ClockBreach => "clock_breach",
        /// A periodic report of it was missed (CM-53).
        ReportMissed => "report_missed",
    }
}

/// An attention signal for the obligor and the accountable Party of a supported commitment; it never changes the supported commitment's state (CM-47).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportSignal {
    /// The supported commitment.
    pub parent: RecordId,
    /// The sub-commitment.
    pub child: RecordId,
    /// Why.
    pub cause: SupportCause,
    /// The record that raised it.
    pub record: RecordId,
    /// The supported commitment's obligor, when a Party.
    pub notify: Option<PartyRef>,
}

/// The signals the sub-commitments in `children` raise on `parent` (CM-47): a child that supports it and has an item cancelled, declined or expired, or whose obligor gave an `at_risk` or `cannot_complete` notice; each raising record once, in child order.
#[must_use]
pub fn support_signals(parent: &CommitmentView, children: &[CommitmentView]) -> Vec<SupportSignal> {
    let notify = match &parent.obligor {
        Obligor::Party(p) => Some(p.clone()),
        Obligor::Queue(_) => None,
    };
    let mut out: Vec<SupportSignal> = Vec::new();
    let mut seen: BTreeSet<RecordId> = BTreeSet::new();
    for child in children
        .iter()
        .filter(|c| c.supports.contains(&parent.root))
    {
        let closings = child.items.iter().filter_map(|i| {
            let cause = match i.state {
                CommitmentState::Cancelled => SupportCause::Cancelled,
                CommitmentState::Declined => SupportCause::Declined,
                CommitmentState::Expired => SupportCause::Expired,
                _ => return None,
            };
            i.closing.map(|c| (c.record, cause))
        });
        let notices = child.notices.iter().filter_map(|n| match n.notice_type {
            NoticeType::AtRisk => Some((n.record, SupportCause::AtRisk)),
            NoticeType::CannotComplete => Some((n.record, SupportCause::CannotComplete)),
            NoticeType::ObsoleteSuggested => None,
        });
        for (record, cause) in closings.chain(notices) {
            if seen.insert(record) {
                out.push(SupportSignal {
                    parent: parent.root,
                    child: child.root,
                    cause,
                    record,
                    notify: notify.clone(),
                });
            }
        }
    }
    out
}

/// The commitments `from` supports, directly or through other commitments, nearest first, each once: the support chain from a supplier promise up to the outer promise (CM-46, CM-47).
#[must_use]
pub fn support_chain(views: &[CommitmentView], from: RecordId) -> Vec<RecordId> {
    let mut out: Vec<RecordId> = Vec::new();
    let mut frontier: Vec<RecordId> = alloc::vec![from];
    while let Some(current) = frontier.pop() {
        let Some(view) = views.iter().find(|v| v.root == current) else {
            continue;
        };
        for parent in &view.supports {
            if *parent != from && !out.contains(parent) {
                out.push(*parent);
                frontier.insert(0, *parent);
            }
        }
    }
    out
}
