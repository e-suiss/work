//! Rate limits with the standard `RateLimit-Policy` and `RateLimit` fields (P-54 item 9; IETF `draft-ietf-httpapi-ratelimit-headers`): one fixed window per caller, at most [`MAX_CALLERS`] callers counted apart in a window and the rest counted together, and `429 rate_limited` with `Retry-After` once a caller has spent its quota.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use axum::http::{HeaderName, HeaderValue};
use tokio::time::Instant;

/// The header naming the quota policy.
pub const RATELIMIT_POLICY: HeaderName = HeaderName::from_static("ratelimit-policy");

/// The header of what is left of the quota in the current window.
pub const RATELIMIT: HeaderName = HeaderName::from_static("ratelimit");

/// The name of the one policy.
pub const POLICY_NAME: &str = "default";

/// The most callers a window counts apart; the others share one count.
pub const MAX_CALLERS: usize = 65_536;

/// A quota of requests per window (P-54 item 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RatePolicy {
    quota: u32,
    window: Duration,
}

impl RatePolicy {
    /// The default quota (POLICY DEFAULT).
    pub const DEFAULT_QUOTA: u32 = 600;

    /// The default window (POLICY DEFAULT).
    pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

    /// `quota` requests per `window`; `None` for a zero quota or a window under one second.
    #[must_use]
    pub const fn new(quota: u32, window: Duration) -> Option<Self> {
        if quota == 0 || window.as_secs() == 0 {
            None
        } else {
            Some(Self { quota, window })
        }
    }

    /// The requests a caller may send in one window.
    #[must_use]
    pub const fn quota(&self) -> u32 {
        self.quota
    }

    /// The window.
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }

    /// The `RateLimit-Policy` value, such as `"default";q=600;w=60`.
    #[must_use]
    pub fn header(&self) -> HeaderValue {
        let (quota, window) = (self.quota, self.window.as_secs());
        let text = format!("\"{POLICY_NAME}\";q={quota};w={window}");
        HeaderValue::from_str(&text).unwrap_or_else(|_| HeaderValue::from_static(""))
    }
}

impl Default for RatePolicy {
    fn default() -> Self {
        Self {
            quota: Self::DEFAULT_QUOTA,
            window: Self::DEFAULT_WINDOW,
        }
    }
}

/// What one request leaves of its caller's quota.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// Whether the request is inside the quota.
    pub allowed: bool,
    /// Requests left in the window.
    pub remaining: u32,
    /// Time until the window starts again.
    pub reset: Duration,
}

impl Quota {
    /// Whole seconds until the window starts again, at least one.
    #[must_use]
    pub fn reset_secs(&self) -> u32 {
        let whole = self.reset.as_secs();
        let seconds = if self.reset.subsec_nanos() > 0 {
            whole.saturating_add(1)
        } else {
            whole
        };
        u32::try_from(seconds.max(1)).unwrap_or(u32::MAX)
    }

    /// The `RateLimit` value, such as `"default";r=599;t=60`.
    #[must_use]
    pub fn header(&self) -> HeaderValue {
        let (remaining, reset) = (self.remaining, self.reset_secs());
        let text = format!("\"{POLICY_NAME}\";r={remaining};t={reset}");
        HeaderValue::from_str(&text).unwrap_or_else(|_| HeaderValue::from_static(""))
    }
}

struct Window {
    started: Instant,
    used: HashMap<String, u32>,
}

/// The per-caller fixed windows of one process.
pub struct RateLimiter {
    policy: RatePolicy,
    window: Mutex<Window>,
}

impl RateLimiter {
    /// A limiter of `policy` whose first window starts now.
    #[must_use]
    pub fn new(policy: RatePolicy) -> Self {
        Self {
            policy,
            window: Mutex::new(Window {
                started: Instant::now(),
                used: HashMap::new(),
            }),
        }
    }

    /// The policy.
    #[must_use]
    pub const fn policy(&self) -> &RatePolicy {
        &self.policy
    }

    /// Counts one request of `caller` and answers what is left of its quota; a request past
    /// the quota is not counted.
    #[must_use]
    pub fn take(&self, caller: &str) -> Quota {
        let now = Instant::now();
        let lock = self.window.lock();
        let mut window = lock.unwrap_or_else(PoisonError::into_inner);
        if now.saturating_duration_since(window.started) >= self.policy.window {
            window.started = now;
            window.used.clear();
        }
        let elapsed = now.saturating_duration_since(window.started);
        let reset = self.policy.window.saturating_sub(elapsed);
        let known = window.used.contains_key(caller) || window.used.len() < MAX_CALLERS;
        let key = if known { caller } else { "" };
        let used = window.used.entry(key.to_owned()).or_insert(0);
        let allowed = *used < self.policy.quota;
        if allowed {
            *used = used.saturating_add(1);
        }
        Quota {
            allowed,
            remaining: self.policy.quota.saturating_sub(*used),
            reset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-54
    #[tokio::test(start_paused = true)]
    async fn p_54_a_caller_past_its_quota_waits_for_the_next_window() {
        let policy = RatePolicy::new(2, Duration::from_secs(10)).unwrap();
        assert_eq!(policy.header(), "\"default\";q=2;w=10");
        let limiter = RateLimiter::new(policy);
        let first = limiter.take("10.0.0.1");
        assert!(first.allowed);
        assert_eq!(first.header(), "\"default\";r=1;t=10");
        assert!(limiter.take("10.0.0.1").allowed);
        assert!(limiter.take("10.0.0.2").allowed);
        tokio::time::advance(Duration::from_millis(2_500)).await;
        let spent = limiter.take("10.0.0.1");
        assert!(!spent.allowed);
        assert_eq!((spent.remaining, spent.reset_secs()), (0, 8));
        tokio::time::advance(Duration::from_secs(8)).await;
        let again = limiter.take("10.0.0.1");
        assert!(again.allowed);
        assert_eq!(again.header(), "\"default\";r=1;t=10");
        assert_eq!(RatePolicy::default().header(), "\"default\";q=600;w=60");
        assert!(RatePolicy::new(0, Duration::from_secs(1)).is_none());
        assert!(RatePolicy::new(1, Duration::from_millis(999)).is_none());
    }
}
