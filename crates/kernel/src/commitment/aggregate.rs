use alloc::vec::Vec;

use super::state::CommitmentState;
use super::view::CommitmentView;
use crate::catalog::AggregationRule;
use crate::id::PartyRef;
use crate::reason::wire_enum;

/// A declared aggregation policy over per-participant commitments: the rule, its parameter, the optional "one rejection rejects" add-on and the participant set frozen at creation (CM-54, CM-55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregationPolicy {
    /// The rule.
    pub rule: AggregationRule,
    /// K for `k_of_n`, p for `percentage`; unused otherwise.
    pub threshold: u32,
    /// Whether any rejection makes the result unsatisfiable, added to the rule.
    pub veto: bool,
    /// The participants in order; N is their count.
    pub participants: Vec<PartyRef>,
}

wire_enum! {
    /// The four values of a participant's answer, and still open; no answer is never a yes (CM-55).
    Answer {
        /// Accepted.
        Accepted => "accepted",
        /// Rejected.
        Rejected => "rejected",
        /// Closed without an answer.
        ClosedWithoutAnswer => "closed_without_answer",
        /// Timed out.
        TimedOut => "timed_out",
        /// Still open.
        Pending => "pending",
    }
}

impl Answer {
    /// A participant's answer as its own commitment derives it: `accepted` counts, `declined` rejects, `expired` times out, every other terminal outcome closes without an answer (CM-55).
    #[must_use]
    pub fn of(view: &CommitmentView) -> Self {
        if !view.is_terminal() {
            return Self::Pending;
        }
        if view
            .items
            .iter()
            .all(|i| i.state == CommitmentState::Accepted)
        {
            return Self::Accepted;
        }
        let any = |s: CommitmentState| view.items.iter().any(|i| i.state == s);
        if any(CommitmentState::Declined) {
            Self::Rejected
        } else if any(CommitmentState::Expired) {
            Self::TimedOut
        } else {
            Self::ClosedWithoutAnswer
        }
    }
}

wire_enum! {
    /// The aggregate result over the participants (CM-54).
    AggregateStatus {
        /// The policy is satisfied.
        Satisfied => "satisfied",
        /// The policy can no longer be satisfied.
        Unsatisfiable => "unsatisfiable",
        /// Undecided.
        Pending => "pending",
    }
}

/// The aggregate result and its explanation: which answers and which policy decided it (CM-55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateOutcome {
    /// The result.
    pub status: AggregateStatus,
    /// The number of acceptances.
    pub accepted: u32,
    /// The acceptances needed.
    pub needed: u32,
    /// The participants, by index, whose answers decided the result.
    pub decisive: Vec<usize>,
    /// The participants still open once the result is decided early, whose requests close as `obsolete` with a notice (CM-55).
    pub to_close: Vec<usize>,
    /// Under `sequential`, the participant whose request may open now.
    pub next: Option<usize>,
}

/// Why an aggregation cannot be evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateError {
    /// The answers do not match the frozen participant set (CM-55).
    ParticipantMismatch,
    /// The threshold is outside the rule's range.
    Threshold,
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The acceptances a policy needs from N participants: N for `all` and `sequential`, 1 for `any`, K, or the ceiling of N times p percent (CM-54).
///
/// # Errors
///
/// [`AggregateError::Threshold`] when K is 0 or above N, or p is 0 or above 100.
pub fn needed(policy: &AggregationPolicy) -> Result<u32, AggregateError> {
    let n = count(policy.participants.len());
    match policy.rule {
        AggregationRule::All | AggregationRule::Sequential => Ok(n),
        AggregationRule::Any => Ok(1),
        AggregationRule::KOfN if (1..=n).contains(&policy.threshold) => Ok(policy.threshold),
        AggregationRule::Percentage if (1..=100).contains(&policy.threshold) => {
            let scaled = u64::from(n)
                .checked_mul(u64::from(policy.threshold))
                .ok_or(AggregateError::Threshold)?;
            let ceiling = scaled.div_ceil(100);
            u32::try_from(ceiling).map_err(|_| AggregateError::Threshold)
        }
        AggregationRule::KOfN | AggregationRule::Percentage => Err(AggregateError::Threshold),
    }
}

/// Evaluates a policy over the participants' answers, in participant order (CM-54, CM-55): only acceptances count; the result is unsatisfiable as soon as the open participants cannot reach the threshold, under `sequential` at the first answer that is not an acceptance, and under the veto at any rejection.
///
/// # Errors
///
/// [`AggregateError`] when the answers do not match the participants or the threshold is out of range.
pub fn aggregate(
    policy: &AggregationPolicy,
    answers: &[Answer],
) -> Result<AggregateOutcome, AggregateError> {
    if answers.len() != policy.participants.len() || answers.is_empty() {
        return Err(AggregateError::ParticipantMismatch);
    }
    let needed = needed(policy)?;
    let indexes = |pick: fn(Answer) -> bool| -> Vec<usize> {
        answers
            .iter()
            .enumerate()
            .filter(|(_, a)| pick(**a))
            .map(|(i, _)| i)
            .collect()
    };
    let accepted_at = indexes(|a| a == Answer::Accepted);
    let pending_at = indexes(|a| a == Answer::Pending);
    let rejected_at = indexes(|a| a == Answer::Rejected);
    let accepted = count(accepted_at.len());
    let reachable = accepted.saturating_add(count(pending_at.len()));
    let (status, decisive, next) = if policy.veto && !rejected_at.is_empty() {
        (AggregateStatus::Unsatisfiable, rejected_at, None)
    } else if policy.rule == AggregationRule::Sequential {
        sequential(answers)
    } else if accepted >= needed {
        (AggregateStatus::Satisfied, accepted_at, None)
    } else if reachable < needed {
        let closed = indexes(|a| a != Answer::Accepted && a != Answer::Pending);
        (AggregateStatus::Unsatisfiable, closed, None)
    } else {
        (AggregateStatus::Pending, Vec::new(), None)
    };
    let to_close = if status == AggregateStatus::Pending {
        Vec::new()
    } else {
        pending_at
    };
    Ok(AggregateOutcome {
        status,
        accepted,
        needed,
        decisive,
        to_close,
        next,
    })
}

fn sequential(answers: &[Answer]) -> (AggregateStatus, Vec<usize>, Option<usize>) {
    for (i, answer) in answers.iter().enumerate() {
        match answer {
            Answer::Accepted => {}
            Answer::Pending => return (AggregateStatus::Pending, Vec::new(), Some(i)),
            Answer::Rejected | Answer::ClosedWithoutAnswer | Answer::TimedOut => {
                return (AggregateStatus::Unsatisfiable, alloc::vec![i], None);
            }
        }
    }
    (
        AggregateStatus::Satisfied,
        (0..answers.len()).collect(),
        None,
    )
}
