//! Component-specific pure logic; normative rules live in `work-kernel` (T-32).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use work_kernel::id::LedgerId;
use work_proto::position::Positions;

/// The `freshness` value of a read answered before its view reached the asked position
/// (T-97 item 3, T-14).
pub const STALE: &str = "stale";

/// Why a `Work-Min-Position` is refused before any wait (T-97 item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PositionRefusal {
    /// A token that does not open, of another tenant, of an unknown key or naming an unknown
    /// ledger: `read_position_invalid`.
    #[error("read position token is invalid")]
    Invalid,
    /// A position past the canonical head, which no wait can reach: `read_position_ahead`.
    #[error("read position is past the canonical head")]
    Ahead,
}

impl PositionRefusal {
    /// The RFC 9457 problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid => work_proto::position::INVALID,
            Self::Ahead => work_proto::position::AHEAD,
        }
    }
}

/// Checks `wanted` against the canonical heads: every ledger must be known, and its position
/// must not be past the head; `None` is a known ledger without a record yet.
///
/// # Errors
/// [`PositionRefusal::Invalid`] for an unknown ledger, [`PositionRefusal::Ahead`] for a position
/// past its head.
pub fn check_heads(
    wanted: &Positions,
    heads: &BTreeMap<LedgerId, Option<u64>>,
) -> Result<(), PositionRefusal> {
    for (ledger, pos) in wanted.entries() {
        match heads.get(ledger) {
            None => return Err(PositionRefusal::Invalid),
            Some(Some(head)) if pos <= head => {}
            Some(_) => return Err(PositionRefusal::Ahead),
        }
    }
    Ok(())
}

/// The bounded wait of a `Work-Min-Position` read (T-97 item 3): `Prefer: wait` asks for a wait,
/// the default applies without one, and no wait exceeds the maximum. POLICY DEFAULT 2 s and
/// 5 s; the maximum can be lowered, never raised above 5 s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "ReadWaitConfig")]
pub struct ReadWait {
    default: Duration,
    max: Duration,
}

/// Why a read wait configuration is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadWaitError {
    /// The maximum is zero or above the 5 s ceiling.
    #[error("read_position.wait_max_ms must be 1 to 5000")]
    Max,
    /// The default is above the maximum.
    #[error("read_position.wait_default_ms must not exceed wait_max_ms")]
    Default,
}

impl ReadWait {
    /// The default wait (T-97 item 3).
    pub const DEFAULT: Duration = Duration::from_secs(2);

    /// The ceiling every maximum stays under (T-97 item 3).
    pub const CEILING: Duration = Duration::from_secs(5);

    /// A default and a maximum wait.
    ///
    /// # Errors
    /// [`ReadWaitError::Max`] for a zero maximum or one above [`ReadWait::CEILING`],
    /// [`ReadWaitError::Default`] for a default above the maximum.
    pub fn new(default: Duration, max: Duration) -> Result<Self, ReadWaitError> {
        if max.is_zero() || max > Self::CEILING {
            return Err(ReadWaitError::Max);
        }
        if default > max {
            return Err(ReadWaitError::Default);
        }
        Ok(Self { default, max })
    }

    /// The default wait.
    #[must_use]
    pub const fn default_wait(&self) -> Duration {
        self.default
    }

    /// The maximum wait.
    #[must_use]
    pub const fn max_wait(&self) -> Duration {
        self.max
    }

    /// The wait applied to a request that asked for `requested`: the default when it asked for
    /// none, at most the maximum.
    #[must_use]
    pub fn applied(&self, requested: Option<Duration>) -> Duration {
        requested.unwrap_or(self.default).min(self.max)
    }
}

impl Default for ReadWait {
    fn default() -> Self {
        Self {
            default: Self::DEFAULT,
            max: Self::CEILING,
        }
    }
}

/// The `[read_position]` configuration section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadWaitConfig {
    /// The default wait in milliseconds.
    #[serde(default = "default_wait_ms")]
    pub wait_default_ms: u64,
    /// The maximum wait in milliseconds.
    #[serde(default = "max_wait_ms")]
    pub wait_max_ms: u64,
}

const fn default_wait_ms() -> u64 {
    2_000
}

const fn max_wait_ms() -> u64 {
    5_000
}

impl TryFrom<ReadWaitConfig> for ReadWait {
    type Error = ReadWaitError;

    fn try_from(config: ReadWaitConfig) -> Result<Self, Self::Error> {
        Self::new(
            Duration::from_millis(config.wait_default_ms),
            Duration::from_millis(config.wait_max_ms),
        )
    }
}

#[cfg(test)]
mod tests {
    use work_kernel::id::Digest;

    use super::*;

    fn ledger(byte: u8) -> LedgerId {
        LedgerId(Digest::sha256([byte; 32]))
    }

    // T-97
    #[test]
    fn t_97_a_position_past_the_head_is_ahead() {
        let wanted = Positions::new([(ledger(1), 4), (ledger(2), 0)]).unwrap();
        let heads = BTreeMap::from([(ledger(1), Some(4)), (ledger(2), Some(9))]);
        assert_eq!(check_heads(&wanted, &heads), Ok(()));
        let behind = BTreeMap::from([(ledger(1), Some(3)), (ledger(2), Some(9))]);
        assert_eq!(check_heads(&wanted, &behind), Err(PositionRefusal::Ahead));
        let empty = BTreeMap::from([(ledger(1), Some(4)), (ledger(2), None)]);
        assert_eq!(check_heads(&wanted, &empty), Err(PositionRefusal::Ahead));
        let unknown = BTreeMap::from([(ledger(1), Some(4))]);
        assert_eq!(
            check_heads(&wanted, &unknown),
            Err(PositionRefusal::Invalid)
        );
        assert_eq!(PositionRefusal::Ahead.code(), "read_position_ahead");
        assert_eq!(PositionRefusal::Invalid.code(), "read_position_invalid");
    }

    // T-97
    #[test]
    fn t_97_the_wait_defaults_to_two_seconds_and_never_exceeds_five() {
        let wait = ReadWait::default();
        assert_eq!(wait.default_wait(), Duration::from_secs(2));
        assert_eq!(wait.max_wait(), Duration::from_secs(5));
        assert_eq!(wait.applied(None), Duration::from_secs(2));
        assert_eq!(
            wait.applied(Some(Duration::from_secs(1))),
            Duration::from_secs(1)
        );
        assert_eq!(
            wait.applied(Some(Duration::from_secs(60))),
            Duration::from_secs(5)
        );
        let config: ReadWait = serde_json::from_str("{}").unwrap();
        assert_eq!(config, wait);
        let narrow: ReadWait =
            serde_json::from_str(r#"{"wait_default_ms": 500, "wait_max_ms": 1000}"#).unwrap();
        assert_eq!(narrow.applied(None), Duration::from_millis(500));
        assert_eq!(
            narrow.applied(Some(Duration::from_secs(3))),
            Duration::from_secs(1)
        );
        for refused in [
            r#"{"wait_max_ms": 5001}"#,
            r#"{"wait_max_ms": 0}"#,
            r#"{"wait_default_ms": 3000, "wait_max_ms": 2000}"#,
            r#"{"wait_ms": 1}"#,
        ] {
            assert!(
                serde_json::from_str::<ReadWait>(refused).is_err(),
                "{refused}"
            );
        }
        assert_eq!(
            ReadWait::new(Duration::ZERO, Duration::from_secs(6)),
            Err(ReadWaitError::Max)
        );
        assert_eq!(STALE, "stale");
    }
}
