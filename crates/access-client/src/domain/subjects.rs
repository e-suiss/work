//! Between a realm's `PartyID`s and the pairwise `sub` one of its clients sees (T-101 item 2, Access OP-149 m.19 (g), MD-10): one direction per call and at most 100 values, every value asked answered once as a pair or as `unknown`, and a process cache, bounded and least recently used first out, keyed by tenant, realm, client and value. Neither direction expires, since an assigned pairwise `sub` never changes; `unknown` is never cached, and nothing of it is written to the database.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use work_proto::id::TenantId;

use crate::domain::{AccessError, b64url, fixed_b64url};

/// The most values one call asks for.
pub const MAX_SUBJECTS: usize = 100;

/// The most entries the cache holds (PD).
pub const CACHE_ENTRIES: usize = 100_000;

/// Which way a call resolves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// From `PartyID`s to the client's pairwise `sub`s.
    Parties,
    /// From the client's pairwise `sub`s to `PartyID`s.
    Subs,
}

impl Direction {
    const fn member(self) -> &'static str {
        match self {
            Self::Parties => "parties",
            Self::Subs => "subs",
        }
    }
}

/// True for a realm id as the tenant snapshot names it: a lower-case hyphenated UUID.
#[must_use]
pub fn is_realm_id(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    lengths == [8, 4, 4, 4, 12]
        && groups.iter().all(|g| {
            g.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

fn is_sub(text: &str) -> bool {
    fixed_b64url::<32>(text).is_ok()
}

fn is_party(text: &str) -> bool {
    fixed_b64url::<16>(text).is_ok()
}

/// The request body for `values` of `direction`.
///
/// # Errors
/// [`AccessError::Identifier`] for a realm that is not a realm id, no value, more than
/// [`MAX_SUBJECTS`], a repeated value or one of another form.
pub fn body(
    realm: &str,
    client_id: &str,
    direction: Direction,
    values: &[String],
) -> Result<Vec<u8>, AccessError> {
    if !is_realm_id(realm) || client_id.is_empty() {
        return Err(AccessError::Identifier("realm"));
    }
    let unique: BTreeSet<&String> = values.iter().collect();
    if values.is_empty() || values.len() > MAX_SUBJECTS || unique.len() != values.len() {
        return Err(AccessError::Identifier("subjects"));
    }
    let shaped = match direction {
        Direction::Parties => values.iter().all(|v| is_party(v)),
        Direction::Subs => values.iter().all(|v| is_sub(v)),
    };
    if !shaped {
        return Err(AccessError::Identifier("subjects"));
    }
    let mut body = serde_json::Map::new();
    body.insert("realm".to_owned(), realm.into());
    body.insert("client_id".to_owned(), client_id.into());
    body.insert(direction.member().to_owned(), values.into());
    serde_json::to_vec(&body).map_err(|_| AccessError::Identifier("subjects"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairWire {
    party: String,
    sub: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolutionWire {
    realm: String,
    client_id: String,
    resolved: Vec<PairWire>,
    unknown: Vec<String>,
    consistency_token: String,
}

/// One answer: the pairs and what did not resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// `PartyID` and pairwise `sub` of every value that resolved.
    pub pairs: Vec<([u8; 16], String)>,
    /// The values asked that did not resolve, as given.
    pub unknown: Vec<String>,
    /// Opaque; the governing domain's head before the read.
    pub consistency_token: String,
}

impl Resolution {
    /// Reads an answer to a call for `asked` of `direction`: it must name the realm and client
    /// asked, and answer every value asked as a pair or as `unknown`, none left out or repeated.
    ///
    /// # Errors
    /// [`AccessError::Answer`].
    pub fn from_json(
        body: &[u8],
        realm: &str,
        client_id: &str,
        direction: Direction,
        asked: &[String],
    ) -> Result<Self, AccessError> {
        let bad = || AccessError::Answer("subjects");
        let w: ResolutionWire = serde_json::from_slice(body).map_err(|_| bad())?;
        if w.realm != realm || w.client_id != client_id || w.consistency_token.is_empty() {
            return Err(bad());
        }
        let mut open: BTreeSet<&str> = asked.iter().map(String::as_str).collect();
        let mut pairs = Vec::with_capacity(w.resolved.len());
        for pair in w.resolved {
            let party = fixed_b64url::<16>(&pair.party).map_err(|_| bad())?;
            if !is_sub(&pair.sub) {
                return Err(bad());
            }
            let value = match direction {
                Direction::Parties => pair.party.as_str(),
                Direction::Subs => pair.sub.as_str(),
            };
            if !open.remove(value) {
                return Err(bad());
            }
            pairs.push((party, pair.sub));
        }
        for value in &w.unknown {
            if !open.remove(value.as_str()) {
                return Err(bad());
            }
        }
        if !open.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            pairs,
            unknown: w.unknown,
            consistency_token: w.consistency_token,
        })
    }
}

/// The cache key: tenant, realm, client, direction and the value asked.
type Key = (TenantId, String, String, Direction, String);

/// The bounded, least recently used cache of resolved values.
#[derive(Debug, Default)]
pub struct SubjectCache {
    entries: BTreeMap<Key, (String, u64)>,
    order: BTreeMap<u64, Key>,
    tick: u64,
    capacity: usize,
}

impl SubjectCache {
    /// A cache of at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.saturating_add(1);
        self.tick
    }

    /// The answer cached for `value`, marked as used.
    pub fn get(
        &mut self,
        tenant: &TenantId,
        realm: &str,
        client_id: &str,
        direction: Direction,
        value: &str,
    ) -> Option<String> {
        let key = (
            tenant.clone(),
            realm.to_owned(),
            client_id.to_owned(),
            direction,
            value.to_owned(),
        );
        let tick = self.next_tick();
        let (answer, used) = self.entries.get_mut(&key)?;
        let found = answer.clone();
        let before = core::mem::replace(used, tick);
        self.order.remove(&before);
        self.order.insert(tick, key);
        Some(found)
    }

    fn put(&mut self, key: Key, answer: String) {
        if self.capacity == 0 {
            return;
        }
        let tick = self.next_tick();
        if let Some((_, before)) = self.entries.insert(key.clone(), (answer, tick)) {
            self.order.remove(&before);
        }
        self.order.insert(tick, key);
        while self.entries.len() > self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    /// Keeps both directions of every pair of `resolution`; what did not resolve is not kept.
    pub fn keep(
        &mut self,
        tenant: &TenantId,
        realm: &str,
        client_id: &str,
        resolution: &Resolution,
    ) {
        for (party, sub) in &resolution.pairs {
            let key = |direction, value: &str| {
                (
                    tenant.clone(),
                    realm.to_owned(),
                    client_id.to_owned(),
                    direction,
                    value.to_owned(),
                )
            };
            let party = b64url(party);
            self.put(key(Direction::Parties, &party), sub.clone());
            self.put(key(Direction::Subs, sub), party);
        }
    }

    /// How many entries are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1";

    fn tenant() -> TenantId {
        TenantId::new("tnt_01").unwrap()
    }

    fn sub(n: u8) -> String {
        b64url(&[n; 32])
    }

    fn party(n: u8) -> String {
        b64url(&[n; 16])
    }

    fn answer(resolved: &[(String, String)], unknown: &[String]) -> Vec<u8> {
        let resolved: Vec<serde_json::Value> = resolved
            .iter()
            .map(|(p, s)| serde_json::json!({"party": p, "sub": s}))
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "realm": REALM,
            "client_id": "cli_web",
            "resolved": resolved,
            "unknown": unknown,
            "consistency_token": "ct-1",
        }))
        .unwrap()
    }

    // T-101 E-7
    #[test]
    fn t_101_one_call_resolves_one_direction_of_at_most_a_hundred_values() {
        let asked = vec![sub(1), sub(2)];
        let json: serde_json::Value =
            serde_json::from_slice(&body(REALM, "cli_web", Direction::Subs, &asked).unwrap())
                .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"realm": REALM, "client_id": "cli_web", "subs": [sub(1), sub(2)]})
        );
        let parties = body(REALM, "cli_web", Direction::Parties, &[party(1)]).unwrap();
        assert!(String::from_utf8(parties).unwrap().contains("\"parties\""));
        let many: Vec<String> = (0..=100).map(sub).collect();
        for (realm, values, direction) in [
            (
                "A1A1A1A1-A1A1-A1A1-A1A1-A1A1A1A1A1A1",
                asked.clone(),
                Direction::Subs,
            ),
            (REALM, Vec::new(), Direction::Subs),
            (REALM, many, Direction::Subs),
            (REALM, vec![sub(1), sub(1)], Direction::Subs),
            (REALM, vec![party(1)], Direction::Subs),
            (REALM, vec![sub(1)], Direction::Parties),
        ] {
            assert!(
                body(realm, "cli_web", direction, &values).is_err(),
                "{values:?}"
            );
        }
        assert!(is_realm_id(REALM));
    }

    // T-101 E-7
    #[test]
    fn t_101_every_value_asked_is_answered_once_as_a_pair_or_unknown() {
        let asked = vec![sub(1), sub(2)];
        let read =
            |body: &[u8]| Resolution::from_json(body, REALM, "cli_web", Direction::Subs, &asked);
        let ok = read(&answer(&[(party(7), sub(1))], &[sub(2)])).unwrap();
        assert_eq!(ok.pairs, vec![([7; 16], sub(1))]);
        assert_eq!(ok.unknown, vec![sub(2)]);
        assert_eq!(ok.consistency_token, "ct-1");
        for bad in [
            answer(&[(party(7), sub(1))], &[]),
            answer(&[(party(7), sub(1)), (party(8), sub(1))], &[sub(2)]),
            answer(&[(party(7), sub(3))], &[sub(1), sub(2)]),
            answer(&[(sub(7), sub(1))], &[sub(2)]),
            answer(&[], &[sub(1), sub(2), sub(3)]),
        ] {
            assert_eq!(read(&bad), Err(AccessError::Answer("subjects")));
        }
        let other = Resolution::from_json(
            &answer(&[], &asked),
            REALM,
            "cli_relay",
            Direction::Subs,
            &asked,
        );
        assert_eq!(other, Err(AccessError::Answer("subjects")));
    }

    // T-101 E-7
    #[test]
    fn t_101_the_cache_keeps_both_directions_and_drops_the_least_recently_used() {
        let mut cache = SubjectCache::new(4);
        let resolution = |n: u8| Resolution {
            pairs: vec![([n; 16], sub(n))],
            unknown: vec![sub(9)],
            consistency_token: "ct".to_owned(),
        };
        cache.keep(&tenant(), REALM, "cli_web", &resolution(1));
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache.get(&tenant(), REALM, "cli_web", Direction::Subs, &sub(1)),
            Some(party(1))
        );
        assert_eq!(
            cache.get(&tenant(), REALM, "cli_web", Direction::Parties, &party(1)),
            Some(sub(1))
        );
        assert_eq!(
            cache.get(&tenant(), REALM, "cli_web", Direction::Subs, &sub(9)),
            None
        );
        assert_eq!(
            cache.get(&tenant(), REALM, "cli_relay", Direction::Subs, &sub(1)),
            None
        );
        cache.keep(&tenant(), REALM, "cli_web", &resolution(2));
        assert_eq!(
            cache.get(&tenant(), REALM, "cli_web", Direction::Subs, &sub(1)),
            Some(party(1))
        );
        cache.keep(&tenant(), REALM, "cli_web", &resolution(3));
        assert_eq!(cache.len(), 4);
        assert_eq!(
            cache.get(&tenant(), REALM, "cli_web", Direction::Subs, &sub(1)),
            Some(party(1))
        );
        for n in [1, 2] {
            let gone = cache.get(&tenant(), REALM, "cli_web", Direction::Parties, &party(n));
            assert_eq!(gone, None, "{n}");
        }
        assert!(!cache.is_empty());
        let mut none = SubjectCache::new(0);
        none.keep(&tenant(), REALM, "cli_web", &resolution(1));
        assert!(none.is_empty());
    }
}
