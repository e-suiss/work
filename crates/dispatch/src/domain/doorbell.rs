//! Pure logic of the executor doorbell (E-39, T-105, T-21): its settings with the webhook each executor Party configured, the content-free body a doorbell carries, which names only the ledger and the cursor the executor pulls from, the next attempt after a failure, exponential from `retry_min` to `retry_max` with a jitter drawn from the delivery so doorbells that failed together spread out, and the code a failed attempt is kept under.

use core::time::Duration;
use std::collections::BTreeMap;

use work_kernel::id::{Digest, LedgerId as KernelLedger};
use work_proto::id::ExternalId as _;
use work_store::LedgerId;

use crate::domain::ConfigError;

/// The doorbell worker's settings; every bound is a POLICY DEFAULT and configurable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorbellConfig {
    /// The webhook URL of each executor Party, by its `PartyRef`; operator configuration, not a
    /// ledger write.
    pub webhooks: BTreeMap<String, String>,
    /// Ledgers with doorbells due discovered per poll.
    pub ledgers_per_poll: u32,
    /// Doorbells read per transaction.
    pub batch_size: u32,
    /// Upper bound on every database call and every webhook exchange (T-32 rule 7).
    pub call_timeout: Duration,
    /// Wait between polls.
    pub poll_interval: Duration,
    /// First wait before a failed doorbell is rung again.
    pub retry_min: Duration,
    /// Longest wait before a failed doorbell is rung again.
    pub retry_max: Duration,
}

impl Default for DoorbellConfig {
    fn default() -> Self {
        Self {
            webhooks: BTreeMap::new(),
            ledgers_per_poll: 256,
            batch_size: 64,
            call_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_secs(1),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_mins(15),
        }
    }
}

impl DoorbellConfig {
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

/// The body of a doorbell: `{"ledger":"led_…","cursor":"<seq>"}`, naming nothing of the
/// delivery but where to pull it (E-39).
#[must_use]
pub fn doorbell_body(ledger: &LedgerId, seq: u64) -> String {
    let ledger = KernelLedger(Digest::sha256(*ledger.as_bytes())).to_external();
    serde_json::json!({ "ledger": ledger, "cursor": seq.to_string() }).to_string()
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn spread(ledger: &LedgerId, seq: u64, attempts: u64) -> u64 {
    ledger
        .as_bytes()
        .as_chunks::<8>()
        .0
        .iter()
        .fold(attempts ^ seq, |acc, c| {
            (acc ^ u64::from_le_bytes(*c))
                .rotate_left(23)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        })
}

/// When a doorbell that failed after `attempts` earlier attempts is next due, from `now_ms`:
/// the wait doubles from `min` per attempt up to `max`, and a jitter from the delivery puts it
/// between half the wait and the whole wait (T-21).
#[must_use]
pub fn ring_again_at(
    now_ms: u64,
    attempts: u64,
    (ledger, seq): (&LedgerId, u64),
    min: Duration,
    max: Duration,
) -> u64 {
    let ceiling = millis(max);
    let shift = u32::try_from(attempts.min(63)).unwrap_or(63);
    let wait = millis(min)
        .checked_mul(1_u64.checked_shl(shift).unwrap_or(u64::MAX))
        .unwrap_or(ceiling)
        .min(ceiling);
    let half = wait.checked_div(2).unwrap_or(0);
    let jitter = spread(ledger, seq, attempts)
        .checked_rem(half.saturating_add(1))
        .unwrap_or(0);
    now_ms.saturating_add(half).saturating_add(jitter)
}

/// Why a doorbell did not ring.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RingError {
    /// The webhook could not be reached.
    #[error("webhook unreachable")]
    Unreachable,
    /// The exchange did not finish in time.
    #[error("webhook timed out")]
    Timeout,
    /// The webhook answered with a status other than 2xx.
    #[error("webhook answered {0}")]
    Status(u16),
    /// The URL is not one the client can ring.
    #[error("webhook url")]
    Url,
}

impl RingError {
    /// The code a failed attempt is kept under.
    #[must_use]
    pub fn code(&self) -> String {
        match self {
            Self::Unreachable => "webhook_unreachable".to_owned(),
            Self::Timeout => "webhook_timeout".to_owned(),
            Self::Status(status) => format!("webhook_status:{status}"),
            Self::Url => "webhook_url".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // E-39 T-105
    #[test]
    fn e_39_a_doorbell_names_only_the_ledger_and_the_cursor() {
        let ledger = LedgerId::from_bytes([0xab; 32]);
        let body: serde_json::Value = serde_json::from_str(&doorbell_body(&ledger, 17)).unwrap();
        let fields = body.as_object().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(body["cursor"], "17");
        assert!(body["ledger"].as_str().unwrap().starts_with("led_"));
    }

    // T-105 T-21
    #[test]
    fn t_105_a_failed_doorbell_waits_from_one_second_to_fifteen_minutes() {
        let config = DoorbellConfig::default();
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(config.retry_min, Duration::from_secs(1));
        assert_eq!(config.retry_max, Duration::from_mins(15));
        let ledger = LedgerId::from_bytes([7; 32]);
        let now = 1_792_749_600_000;
        let mut last_floor = 0;
        for attempts in 0..40_u32 {
            let at = ring_again_at(
                now,
                u64::from(attempts),
                (&ledger, 3),
                config.retry_min,
                config.retry_max,
            );
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
        assert_eq!(RingError::Status(503).code(), "webhook_status:503");
        let bad = DoorbellConfig {
            retry_max: Duration::from_millis(10),
            ..DoorbellConfig::default()
        };
        assert_eq!(bad.validate(), Err(ConfigError::Timing));
    }
}
