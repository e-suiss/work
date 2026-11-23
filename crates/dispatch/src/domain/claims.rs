//! Pure logic of the `commitment_active` Claim delivery (E-8, E-12, T-21): its settings, the Claim a stored delivery row sends, the next attempt after a failure, exponential from `retry_min` to `retry_max` with a jitter drawn from the row's key so rows that failed together spread out, and the code a failed attempt is kept under.

use core::time::Duration;

use work_access_client::domain::AccessError;
use work_access_client::domain::commitments::Ended;
use work_access_client::domain::keys::{DomainId, KernelId};
use work_store::{ClaimDelivery, ClaimKey};

use crate::domain::ConfigError;

/// The delivery worker's settings; every value is a POLICY DEFAULT and configurable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimConfig {
    /// Ledgers with deliveries due discovered per poll.
    pub ledgers_per_poll: u32,
    /// Deliveries read per transaction.
    pub batch_size: u32,
    /// Upper bound on every database and Access call (T-32 rule 7).
    pub call_timeout: Duration,
    /// Wait between polls.
    pub poll_interval: Duration,
    /// First wait before a failed delivery is tried again.
    pub retry_min: Duration,
    /// Longest wait before a failed delivery is tried again.
    pub retry_max: Duration,
}

impl Default for ClaimConfig {
    fn default() -> Self {
        Self {
            ledgers_per_poll: 256,
            batch_size: 64,
            call_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_secs(1),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_mins(15),
        }
    }
}

impl ClaimConfig {
    /// Rejects a setting the worker cannot run with.
    ///
    /// # Errors
    /// [`ConfigError::Bounds`] for a zero discovery or batch bound, [`ConfigError::Timing`]
    /// for a zero timeout, interval or retry wait, or a shortest retry wait above the longest.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.ledgers_per_poll == 0 || self.batch_size == 0 {
            return Err(ConfigError::Bounds);
        }
        if self.call_timeout.is_zero()
            || self.poll_interval.is_zero()
            || self.retry_min.is_zero()
            || self.retry_max < self.retry_min
        {
            return Err(ConfigError::Timing);
        }
        Ok(())
    }
}

/// The Claim a stored delivery sends: always the same for the same row, issued at the ledger
/// time of the record that ended the commitment (E-12).
#[must_use]
pub const fn ended(row: &ClaimDelivery) -> Ended {
    Ended {
        domain: DomainId(row.claim.domain),
        issuer: KernelId(row.claim.issuer),
        subject: KernelId(row.claim.subject),
        commitment: row.claim.commitment,
        issued_at_ms: row.issued_at_ms,
        pep: row.claim.pep,
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn spread(key: &ClaimKey, attempts: u64) -> u64 {
    key.record
        .as_chunks::<8>()
        .0
        .iter()
        .chain(key.subject.as_chunks::<8>().0.iter())
        .fold(attempts, |acc, c| {
            (acc ^ u64::from_le_bytes(*c))
                .rotate_left(23)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        })
}

/// When a delivery that failed after `attempts` earlier attempts is next due, from `now_ms`:
/// the wait doubles from `min` per attempt up to `max`, and a jitter from the row's key puts
/// it between half the wait and the whole wait.
#[must_use]
pub fn retry_at(now_ms: u64, attempts: u64, key: &ClaimKey, min: Duration, max: Duration) -> u64 {
    let ceiling = millis(max);
    let shift = u32::try_from(attempts.min(63)).unwrap_or(63);
    let wait = millis(min)
        .checked_mul(1_u64.checked_shl(shift).unwrap_or(u64::MAX))
        .unwrap_or(ceiling)
        .min(ceiling);
    let half = wait.checked_div(2).unwrap_or(0);
    let jitter = spread(key, attempts)
        .checked_rem(half.saturating_add(1))
        .unwrap_or(0);
    now_ms.saturating_add(half).saturating_add(jitter)
}

/// The code a failed attempt is kept under: a short lower-case name of what kept the Claim
/// from Access.
#[must_use]
pub const fn error_code(error: &AccessError) -> &'static str {
    match error {
        AccessError::Transport(_) => "access_unreachable",
        AccessError::Timeout => "access_timeout",
        AccessError::Unavailable { .. } => "access_unavailable",
        AccessError::Refused { .. } => "access_refused",
        AccessError::Stale => "access_stale",
        AccessError::Unserved(_) => "access_unserved",
        AccessError::Expired => "pep_certificate_expired",
        AccessError::Disabled => "client_disabled",
        AccessError::Answer(_) => "access_answer",
        _ => "access_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> ClaimKey {
        ClaimKey {
            record: [n; 32],
            subject: [n.wrapping_add(1); 16],
        }
    }

    // E-12
    #[test]
    fn e_12_a_failed_claim_waits_longer_each_time_up_to_the_bound() {
        let min = Duration::from_secs(1);
        let max = Duration::from_mins(15);
        let now = 1_792_749_600_000;
        let mut last_floor = 0;
        for attempts in 0..40_u32 {
            let at = retry_at(now, u64::from(attempts), &key(7), min, max);
            let wait = at.checked_sub(now).unwrap();
            let full = 1000_u64
                .checked_mul(2_u64.checked_pow(attempts.min(20)).unwrap())
                .unwrap()
                .min(900_000);
            let floor = full.checked_div(2).unwrap();
            assert!(wait >= floor, "{attempts}: {wait}");
            assert!(wait <= full, "{attempts}: {wait}");
            assert!(floor >= last_floor);
            last_floor = floor;
        }
        assert_eq!(
            retry_at(now, 3, &key(7), min, max),
            retry_at(now, 3, &key(7), min, max)
        );
        let spread: std::collections::BTreeSet<u64> = (0..32)
            .map(|n| retry_at(now, 10, &key(n), min, max))
            .collect();
        assert!(spread.len() > 1);
        assert_eq!(retry_at(u64::MAX, 99, &key(1), min, max), u64::MAX);
    }

    // E-12
    #[test]
    fn e_12_the_settings_are_checked() {
        assert_eq!(ClaimConfig::default().validate(), Ok(()));
        let bad = ClaimConfig {
            retry_max: Duration::from_millis(10),
            ..ClaimConfig::default()
        };
        assert_eq!(bad.validate(), Err(ConfigError::Timing));
        let none = ClaimConfig {
            batch_size: 0,
            ..ClaimConfig::default()
        };
        assert_eq!(none.validate(), Err(ConfigError::Bounds));
        assert_eq!(error_code(&AccessError::Timeout), "access_timeout");
        assert_eq!(
            error_code(&AccessError::Transport("reset".to_owned())),
            "access_unreachable"
        );
    }
}
