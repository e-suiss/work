//! Pure ledger time rules (OP-6, OP-32, OP-42, OP-43): ledger time is the last verified NTS
//! sample of each source carried forward by the monotonic clock and combined by the shared
//! `suiss-ledger` combiner; a Roughtime answer is never a sample, only a coarse bound that the
//! majority of the servers answering a round must confirm.

use suiss_ledger::time::{TimeError, TrustedClock};

/// Fewest NTS servers a configuration names (OP-32 item 4).
pub const MIN_NTS_SERVERS: usize = suiss_ledger::time::MIN_SOURCES;

/// Fewest Roughtime servers a configuration names (OP-43 item 3).
pub const MIN_ROUGHTIME_SERVERS: usize = 3;

/// NTS sampling interval in milliseconds (OP-32 item 2, PD).
pub const NTS_INTERVAL_MS: u64 = 64_000;

/// How long a sample stays usable without a newer one: eight sampling intervals, the reach of
/// the NTP reachability register.
pub const SAMPLE_LIFETIME_MS: u64 = 8 * NTS_INTERVAL_MS;

/// One verified NTS reading: the server's time in Unix milliseconds at monotonic time `mono_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtsSample {
    /// Server time, Unix milliseconds.
    pub unix_ms: u64,
    /// Monotonic time of the reading, milliseconds.
    pub mono_ms: u64,
}

/// A verified Roughtime answer (OP-42 item 1), received at monotonic time `mono_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoughtimeAnswer {
    /// `MIDP`, Unix milliseconds.
    pub midpoint_ms: u64,
    /// `RADI`, milliseconds.
    pub radius_ms: u64,
    /// Round-trip time of the query, milliseconds.
    pub rtt_ms: u64,
    /// Monotonic time the answer arrived, milliseconds.
    pub mono_ms: u64,
}

impl RoughtimeAnswer {
    /// Whether ledger time `at_ms` read at monotonic time `mono_ms` lies between
    /// `midpoint − (radius + rtt)` and `midpoint + (radius + rtt)`, both carried forward by the
    /// monotonic time since the answer (OP-42 item 1).
    #[must_use]
    pub fn covers(&self, at_ms: u64, mono_ms: u64) -> bool {
        let Some(elapsed) = mono_ms.checked_sub(self.mono_ms) else {
            return false;
        };
        let width = self.radius_ms.saturating_add(self.rtt_ms);
        let mid = self.midpoint_ms.saturating_add(elapsed);
        at_ms >= mid.saturating_sub(width) && at_ms <= mid.saturating_add(width)
    }
}

/// OP-43 item 4: the intervals of more than half of the answers of a round cover `at_ms`; with
/// one answer, that answer decides.
#[must_use]
pub fn majority_covers(answers: &[RoughtimeAnswer], at_ms: u64, mono_ms: u64) -> bool {
    let covering = answers.iter().filter(|a| a.covers(at_ms, mono_ms)).count();
    covering.saturating_mul(2) > answers.len()
}

/// Why no ledger time is given; nothing is committed (OP-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeFault {
    /// The NTS samples do not give trusted time (OP-32 item 2).
    #[error("NTS: {0}")]
    Nts(TimeError),
    /// Ledger time is outside the Roughtime interval of the majority of the servers that
    /// answered the last round (OP-42 item 1, OP-43 item 4).
    #[error("ledger time is outside the Roughtime bound")]
    OutsideRoughtime,
}

/// What a Roughtime round left in force (OP-43 items 1, 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Round {
    /// This many servers answered; their intervals bound ledger time until the next round.
    Answered(usize),
    /// No server answered; ledger time continues on NTS without the bound (OP-43 item 1).
    Unanswered,
}

/// The ledger time state: the last sample of each NTS source, the combiner and the Roughtime
/// answers of the last round.
#[derive(Debug, Clone)]
pub struct Discipline {
    combiner: TrustedClock,
    samples: Vec<Option<NtsSample>>,
    bound: Option<Vec<RoughtimeAnswer>>,
}

impl Discipline {
    /// A state for `nts_sources` sources, none sampled and no Roughtime bound yet.
    #[must_use]
    pub fn new(nts_sources: usize) -> Self {
        Self {
            combiner: TrustedClock::default(),
            samples: vec![None; nts_sources],
            bound: None,
        }
    }

    /// Records the latest verified sample of source `source`.
    pub fn record_sample(&mut self, source: usize, sample: NtsSample) {
        if let Some(slot) = self.samples.get_mut(source) {
            *slot = Some(sample);
        }
    }

    /// Drops the sample of source `source`, which lost its NTS session.
    pub fn lose_source(&mut self, source: usize) {
        if let Some(slot) = self.samples.get_mut(source) {
            *slot = None;
        }
    }

    /// Records a Roughtime round; an empty round lifts the bound (OP-43 item 1).
    pub fn record_round(&mut self, answers: Vec<RoughtimeAnswer>) -> Round {
        if answers.is_empty() {
            self.bound = None;
            Round::Unanswered
        } else {
            let n = answers.len();
            self.bound = Some(answers);
            Round::Answered(n)
        }
    }

    /// Whether a Roughtime bound is in force.
    #[must_use]
    pub const fn bounded(&self) -> bool {
        self.bound.is_some()
    }

    /// Ledger time in Unix milliseconds at monotonic time `mono_ms` (OP-32 item 1).
    ///
    /// # Errors
    /// [`TimeFault`]; the caller does not commit.
    pub fn now(&mut self, mono_ms: u64) -> Result<u64, TimeFault> {
        let readings: Vec<u64> = self
            .samples
            .iter()
            .flatten()
            .filter_map(|s| {
                let age = mono_ms.checked_sub(s.mono_ms)?;
                (age <= SAMPLE_LIFETIME_MS).then(|| s.unix_ms.saturating_add(age))
            })
            .collect();
        let at = self
            .combiner
            .read(&readings, mono_ms)
            .map_err(TimeFault::Nts)?;
        if let Some(answers) = &self.bound
            && !majority_covers(answers, at, mono_ms)
        {
            return Err(TimeFault::OutsideRoughtime);
        }
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    const T: u64 = 1_793_505_043_000;

    fn answer(midpoint_ms: u64) -> RoughtimeAnswer {
        RoughtimeAnswer {
            midpoint_ms,
            radius_ms: 1_000,
            rtt_ms: 40,
            mono_ms: 0,
        }
    }

    // OP-42
    #[test]
    fn op_42_the_interval_is_the_midpoint_widened_by_radius_and_round_trip() {
        let a = answer(T);
        assert!(a.covers(T - 1_040, 0));
        assert!(a.covers(T + 1_040, 0));
        assert!(!a.covers(T - 1_041, 0));
        assert!(!a.covers(T + 1_041, 0));
        assert!(a.covers(T + 60_000, 60_000));
        assert!(!a.covers(T, 60_000));
    }

    // OP-43
    #[test]
    fn op_43_the_majority_of_the_answers_decides() {
        let good = answer(T);
        let off = answer(T + 3_600_000);
        assert!(majority_covers(&[good, good, off], T, 0));
        assert!(!majority_covers(&[good, off, off], T, 0));
        assert!(majority_covers(&[good], T, 0));
        assert!(!majority_covers(&[off], T, 0));
        assert!(!majority_covers(&[good, off], T, 0));
        assert!(majority_covers(&[good, good], T, 0));
    }

    // OP-32
    #[test]
    fn op_32_ledger_time_is_the_last_sample_plus_the_monotonic_delta() {
        let mut d = Discipline::new(2);
        assert_eq!(d.now(0), Err(TimeFault::Nts(TimeError::TooFewSources)));
        d.record_sample(
            0,
            NtsSample {
                unix_ms: T,
                mono_ms: 1_000,
            },
        );
        assert_eq!(d.now(1_000), Err(TimeFault::Nts(TimeError::TooFewSources)));
        d.record_sample(
            1,
            NtsSample {
                unix_ms: T + 100,
                mono_ms: 1_100,
            },
        );
        assert_eq!(d.now(1_100), Ok(T + 100));
        assert_eq!(d.now(5_100), Ok(T + 4_100));
        d.lose_source(1);
        assert_eq!(d.now(5_200), Err(TimeFault::Nts(TimeError::TooFewSources)));
    }

    // OP-32
    #[test]
    fn op_32_sources_that_differ_by_more_than_u_stop_commits() {
        let mut d = Discipline::new(2);
        d.record_sample(
            0,
            NtsSample {
                unix_ms: T,
                mono_ms: 0,
            },
        );
        d.record_sample(
            1,
            NtsSample {
                unix_ms: T + 251,
                mono_ms: 0,
            },
        );
        assert_eq!(d.now(0), Err(TimeFault::Nts(TimeError::Disagree)));
        d.record_sample(
            1,
            NtsSample {
                unix_ms: T + 250,
                mono_ms: 0,
            },
        );
        assert_eq!(d.now(0), Ok(T));
    }

    // OP-32
    #[test]
    fn op_32_a_sample_older_than_its_lifetime_is_not_used() {
        let mut d = Discipline::new(2);
        d.record_sample(
            0,
            NtsSample {
                unix_ms: T,
                mono_ms: 0,
            },
        );
        d.record_sample(
            1,
            NtsSample {
                unix_ms: T,
                mono_ms: 0,
            },
        );
        assert!(d.now(SAMPLE_LIFETIME_MS).is_ok());
        assert_eq!(
            d.now(SAMPLE_LIFETIME_MS + 1),
            Err(TimeFault::Nts(TimeError::TooFewSources))
        );
    }

    // OP-42 OP-43
    #[test]
    fn op_42_ledger_time_outside_the_bound_stops_commits_and_an_empty_round_lifts_it() {
        let mut d = Discipline::new(2);
        d.record_sample(
            0,
            NtsSample {
                unix_ms: T,
                mono_ms: 0,
            },
        );
        d.record_sample(
            1,
            NtsSample {
                unix_ms: T,
                mono_ms: 0,
            },
        );
        assert_eq!(
            d.record_round(vec![answer(T), answer(T)]),
            Round::Answered(2)
        );
        assert_eq!(d.now(10), Ok(T + 10));
        let far = T + 10 * 60_000;
        assert_eq!(
            d.record_round(vec![answer(far), answer(far), answer(T)]),
            Round::Answered(3)
        );
        assert_eq!(d.now(20), Err(TimeFault::OutsideRoughtime));
        assert_eq!(d.record_round(Vec::new()), Round::Unanswered);
        assert!(!d.bounded());
        assert_eq!(d.now(30), Ok(T + 30));
    }
}
