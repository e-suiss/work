//! The process monotonic clock (T-32 rule 2): the reviewed adapter that reads
//! `std::time::Instant`, for the ledger time driver and the NTS timestamps.

use std::time::{Duration, Instant};

use crate::time::ports::Monotonic;

/// Monotonic time since the adapter was made.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMonotonic {
    start: Instant,
}

impl ProcessMonotonic {
    /// Starts the clock at zero now.
    #[must_use]
    #[allow(
        clippy::disallowed_methods,
        reason = "T-32: the reviewed monotonic clock adapter of the ledger time driver"
    )]
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Time since the start.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Monotonic for ProcessMonotonic {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}
