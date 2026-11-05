//! The command line's reviewed wall clock (T-32): `work-cli access pair` has no ledger time, and the only times it uses are the client assertion's `iat` and `exp` and the challenge's remaining validity, both of which Access checks against its own clock (T-101 note item 8, T-103).

use std::time::{SystemTime, UNIX_EPOCH};

use work_access_client::ports::Clock;

/// The operating system's wall clock, Unix milliseconds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Wall;

impl Clock for Wall {
    #[allow(
        clippy::disallowed_methods,
        reason = "T-32 T-103: the reviewed wall clock of `work-cli access pair`"
    )]
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or_default()
    }
}
