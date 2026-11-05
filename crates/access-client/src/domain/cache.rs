//! The key lookup cache (T-101 item 4; Access OP-149 m.5, m.15 (d)): an entry lives as long as Access's `Cache-Control` says, a compromised key is never kept as immutable, an unknown kid is never cached, a newer answer is never replaced by one at a lower `ETag` position, and the cache is bounded.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::domain::keys::{AsOf, DomainId, Evidence, InstanceKey, KeyAnswer, KeyState, Kid};

/// Most cached keys (PD).
pub const CAPACITY: usize = 10_000;

/// What a `Cache-Control` header allows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CachePolicy {
    /// `max-age`, in milliseconds.
    pub max_age_ms: Option<u64>,
    /// `immutable`.
    pub immutable: bool,
    /// `no-store` or `no-cache`.
    pub no_store: bool,
}

impl CachePolicy {
    /// Reads a `Cache-Control` header; an absent or unreadable header allows nothing.
    #[must_use]
    pub fn parse(header: Option<&str>) -> Self {
        let mut out = Self::default();
        for d in header.unwrap_or_default().split(',').map(str::trim) {
            let lower = d.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("max-age=") {
                out.max_age_ms = v.parse::<u64>().ok().map(|s| s.saturating_mul(1000));
            } else if lower == "immutable" {
                out.immutable = true;
            } else if lower == "no-store" || lower == "no-cache" {
                out.no_store = true;
            }
        }
        out
    }

    /// How long a key in `state` may be kept, `None` for not at all. `immutable` holds only
    /// for an ended key; a compromised key keeps at most its `max-age`.
    #[must_use]
    pub fn lifetime(self, state: KeyState) -> Option<Lifetime> {
        if self.no_store {
            return None;
        }
        match (state, self.immutable, self.max_age_ms) {
            (KeyState::Ended, true, _) => Some(Lifetime::Forever),
            (_, _, Some(ms)) if ms > 0 => Some(Lifetime::For(ms)),
            _ => None,
        }
    }
}

/// How long an entry may be kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifetime {
    /// This many milliseconds.
    For(u64),
    /// For good: an ended key under `immutable`.
    Forever,
}

/// A cached key with the position and evidence of the answer it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedKey {
    /// The key.
    pub key: InstanceKey,
    /// The answer's position, its `ETag`.
    pub pos: u64,
    /// The answer's signed bytes.
    pub evidence: Arc<Evidence>,
    expires_ms: Option<u64>,
}

impl CachedKey {
    /// A key of a verified answer, as the cache would keep it.
    #[must_use]
    pub fn of(key: InstanceKey, answer: &KeyAnswer) -> Self {
        Self {
            key,
            pos: answer.pos,
            evidence: answer.evidence.clone(),
            expires_ms: None,
        }
    }
}

type Slot = (DomainId, Kid, AsOf);

/// Verified keys by domain, kid and `as_of`.
#[derive(Debug)]
pub struct KeyCache {
    entries: BTreeMap<Slot, CachedKey>,
    capacity: usize,
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::with_capacity(CAPACITY)
    }
}

impl KeyCache {
    /// An empty cache of at most `capacity` keys.
    #[must_use]
    pub const fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
        }
    }

    /// The fresh entry for `kid`, if any.
    #[must_use]
    pub fn get(&self, domain: DomainId, kid: Kid, as_of: &AsOf, now_ms: u64) -> Option<&CachedKey> {
        self.entries
            .get(&(domain, kid, as_of.clone()))
            .filter(|c| c.expires_ms.is_none_or(|e| now_ms < e))
    }

    /// Keeps the keys of a verified answer as `policy` allows.
    pub fn put(&mut self, answer: &KeyAnswer, as_of: &AsOf, policy: CachePolicy, now_ms: u64) {
        for key in &answer.keys {
            let Some(life) = policy.lifetime(key.state) else {
                continue;
            };
            let slot = (answer.domain, key.kid, as_of.clone());
            if self
                .get(answer.domain, key.kid, as_of, now_ms)
                .is_some_and(|c| c.pos > answer.pos)
            {
                continue;
            }
            self.entries.insert(
                slot,
                CachedKey {
                    key: key.clone(),
                    pos: answer.pos,
                    evidence: answer.evidence.clone(),
                    expires_ms: match life {
                        Lifetime::For(ms) => Some(now_ms.saturating_add(ms)),
                        Lifetime::Forever => None,
                    },
                },
            );
        }
        self.bound(now_ms);
    }

    /// Drops every entry of `kid` in `domain`, whatever its `as_of` (T-102 item 5, E-14).
    pub fn forget(&mut self, domain: DomainId, kid: Kid) {
        self.entries
            .retain(|(d, k, _), _| *d != domain || *k != kid);
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn bound(&mut self, now_ms: u64) {
        self.entries
            .retain(|_, c| c.expires_ms.is_none_or(|e| now_ms < e));
        while self.entries.len() > self.capacity {
            let soonest = self
                .entries
                .iter()
                .min_by_key(|(_, c)| c.expires_ms.unwrap_or(u64::MAX))
                .map(|(s, _)| s.clone());
            match soonest {
                Some(s) => {
                    self.entries.remove(&s);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::tests::{domain, token};
    use crate::domain::keys::verify_answer;

    // T-101
    #[test]
    fn t_101_a_compromised_key_is_never_cached_as_immutable() {
        let forever = CachePolicy::parse(Some("max-age=31536000, immutable"));
        assert_eq!(forever.lifetime(KeyState::Ended), Some(Lifetime::Forever));
        assert_eq!(
            forever.lifetime(KeyState::Compromised),
            Some(Lifetime::For(31_536_000_000))
        );
        let only_immutable = CachePolicy::parse(Some("immutable"));
        assert_eq!(only_immutable.lifetime(KeyState::Compromised), None);
        assert_eq!(only_immutable.lifetime(KeyState::Active), None);
        let minute = CachePolicy::parse(Some("max-age=60"));
        assert_eq!(
            minute.lifetime(KeyState::Active),
            Some(Lifetime::For(60_000))
        );
        assert_eq!(
            CachePolicy::parse(Some("no-store, max-age=60")).lifetime(KeyState::Active),
            None
        );
        assert_eq!(CachePolicy::parse(None).lifetime(KeyState::Active), None);

        let (_, store) = token("cache");
        let d = domain(&store);
        let m = d.read();
        let excerpt = d.excerpt("key-lookup");
        let sign1 = d.answer(vec![d.entry("compromised", true)], &[], 3);
        let answer = verify_answer(&m, &d.id, &[d.kid()], &sign1, &excerpt, Some(3)).unwrap();
        let mut cache = KeyCache::default();
        cache.put(&answer, &AsOf::Head, only_immutable, 0);
        assert!(cache.is_empty());
        cache.put(&answer, &AsOf::Head, forever, 0);
        assert!(
            cache
                .get(d.id, d.kid(), &AsOf::Head, 31_535_999_999)
                .is_some()
        );
        assert!(
            cache
                .get(d.id, d.kid(), &AsOf::Head, 31_536_000_000)
                .is_none()
        );
    }

    // E-14 T-9
    #[test]
    fn e_14_an_instance_termination_drops_its_cached_keys_at_once() {
        let (_, store) = token("forget");
        let d = domain(&store);
        let m = d.read();
        let excerpt = d.excerpt("key-lookup");
        let answer = verify_answer(
            &m,
            &d.id,
            &[d.kid()],
            &d.answer(vec![d.entry("active", false)], &[], 4),
            &excerpt,
            Some(4),
        )
        .unwrap();
        let minute = CachePolicy::parse(Some("max-age=60"));
        let mut cache = KeyCache::default();
        cache.put(&answer, &AsOf::Head, minute, 0);
        cache.put(&answer, &AsOf::Position(4), minute, 0);
        assert_eq!(cache.len(), 2);
        cache.forget(d.id, Kid([0; 32]));
        assert_eq!(cache.len(), 2);
        cache.forget(d.id, d.kid());
        assert!(cache.is_empty());
        assert!(cache.get(d.id, d.kid(), &AsOf::Head, 1).is_none());
    }

    // T-101
    #[test]
    fn t_101_cached_keys_follow_max_age_and_never_go_back_in_etag() {
        let (_, store) = token("etag");
        let d = domain(&store);
        let m = d.read();
        let excerpt = d.excerpt("key-lookup");
        let newer = verify_answer(
            &m,
            &d.id,
            &[d.kid()],
            &d.answer(vec![d.entry("active", false)], &[], 9),
            &excerpt,
            Some(9),
        )
        .unwrap();
        let older = verify_answer(
            &m,
            &d.id,
            &[d.kid()],
            &d.answer(vec![d.entry("active", false)], &[], 5),
            &excerpt,
            Some(5),
        )
        .unwrap();
        let minute = CachePolicy::parse(Some("max-age=60"));
        let mut cache = KeyCache::default();
        cache.put(&newer, &AsOf::Head, minute, 0);
        cache.put(&older, &AsOf::Head, minute, 1);
        assert_eq!(cache.get(d.id, d.kid(), &AsOf::Head, 2).unwrap().pos, 9);
        assert!(cache.get(d.id, d.kid(), &AsOf::Head, 60_000).is_none());
        assert!(cache.get(d.id, d.kid(), &AsOf::Position(9), 2).is_none());
        let mut small = KeyCache::with_capacity(0);
        small.put(&newer, &AsOf::Head, minute, 0);
        assert!(small.is_empty());
    }
}
