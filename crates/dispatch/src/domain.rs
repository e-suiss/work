//! Pure publisher logic (T-32 rule 3): the T-76 stream settings and their checks, the stable
//! partition of a ledger, the subject of an event, the minimal CloudEvents envelope built only
//! from the committed log row and its outbox pointer (§15 P-35, P-42; §17 T-17, T-18), the
//! retry backoff of a NATS outage (T-21), and the consumer side: per-partition durable names and
//! filters (T-76 rules 5 and 6), the parsed [`Event`] and the bounded [`Seen`] set that drops
//! repeated event ids without relying on order (T-18).

use core::time::Duration;
use std::collections::{BTreeSet, VecDeque};

/// T-76 stream and subject schema; every value is a POLICY DEFAULT and configurable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSettings {
    /// Stream name (T-76 rule 1).
    pub name: String,
    /// Subject prefix; subjects are `<prefix>.<p>.<ledger>.<type>` (T-76 rule 1).
    pub subject_prefix: String,
    /// Partition count P (T-76 rule 1).
    pub partitions: u16,
    /// Limits retention age (T-76 rule 2).
    pub max_age: Duration,
    /// `Nats-Msg-Id` duplicate window (T-76 rule 3).
    pub duplicate_window: Duration,
    /// File-storage replicas: 1 on a single node, 3 in the multi-node profile.
    pub replicas: usize,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            name: "WORK_EVENTS".to_owned(),
            subject_prefix: "work.evt".to_owned(),
            partitions: 16,
            max_age: Duration::from_hours(7 * 24),
            duplicate_window: Duration::from_mins(2),
            replicas: 1,
        }
    }
}

impl StreamSettings {
    /// The defaults with 3 replicas, for the multi-node profile.
    #[must_use]
    pub fn multi_node() -> Self {
        Self {
            replicas: 3,
            ..Self::default()
        }
    }

    /// The stream's subject filter, `<prefix>.*.*.>`.
    #[must_use]
    pub fn filter(&self) -> String {
        format!("{}.*.*.>", self.subject_prefix)
    }

    /// The partition token of `p`: decimal, zero-padded to at least two digits (T-76 rule 1).
    #[must_use]
    pub fn partition_token(&self, p: u16) -> String {
        let width = partition_width(self.partitions);
        format!("{p:0width$}")
    }

    /// The subject filter of partition `p`, `<prefix>.<p>.*.>` (T-76 rules 5 and 6).
    #[must_use]
    pub fn partition_filter(&self, p: u16) -> String {
        format!("{}.{}.*.>", self.subject_prefix, self.partition_token(p))
    }

    /// The subject of an event of `event_type` in `ledger` (T-76 rules 1 and 4): only the
    /// partition, the opaque ledger digest in lower-case hex and the type.
    #[must_use]
    pub fn subject(&self, ledger: &[u8; 32], event_type: &str) -> String {
        let p = partition(ledger, self.partitions);
        let width = partition_width(self.partitions);
        format!(
            "{}.{p:0width$}.{}.{event_type}",
            self.subject_prefix,
            hex(ledger)
        )
    }
}

/// Publisher settings, checked once by [`PublisherConfig::validate`] (T-32 rule 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherConfig {
    /// The installation URI; an event's `source` is `<source>/ledgers/<ledger hex>` (§15 P-35).
    pub source: String,
    /// Stream and subject schema (T-76).
    pub stream: StreamSettings,
    /// Ledgers with pending pointers discovered per poll.
    pub ledgers_per_poll: u32,
    /// Pointers read per transaction.
    pub batch_size: u32,
    /// Publishes awaiting their JetStream ack at once (T-32 rule 7).
    pub max_in_flight: usize,
    /// Upper bound on every database and NATS call (T-32 rule 7).
    pub call_timeout: Duration,
    /// Wait between polls when nothing failed (T-21).
    pub poll_interval: Duration,
    /// First wait after a failure.
    pub backoff_min: Duration,
    /// Longest wait after repeated failures.
    pub backoff_max: Duration,
}

impl PublisherConfig {
    /// T-76 defaults for `source`.
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            stream: StreamSettings::default(),
            ledgers_per_poll: 1024,
            batch_size: 256,
            max_in_flight: 64,
            call_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_secs(1),
            backoff_min: Duration::from_millis(100),
            backoff_max: Duration::from_secs(30),
        }
    }

    /// Rejects a setting the publisher cannot run with.
    ///
    /// # Errors
    /// The first [`ConfigError`] found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let s = &self.stream;
        let host = self.source.strip_prefix("https://").unwrap_or_default();
        if host.is_empty()
            || host.ends_with('/')
            || self
                .source
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#'))
        {
            return Err(ConfigError::Source);
        }
        if s.name.is_empty()
            || !s
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        {
            return Err(ConfigError::StreamName);
        }
        if !s.subject_prefix.split('.').all(is_plain_token) {
            return Err(ConfigError::SubjectPrefix);
        }
        if s.partitions == 0 {
            return Err(ConfigError::Partitions);
        }
        if s.max_age.is_zero() || s.duplicate_window.is_zero() || s.duplicate_window > s.max_age {
            return Err(ConfigError::Retention);
        }
        if !(1..=MAX_REPLICAS).contains(&s.replicas) {
            return Err(ConfigError::Replicas);
        }
        if self.ledgers_per_poll == 0 || self.batch_size == 0 || self.max_in_flight == 0 {
            return Err(ConfigError::Bounds);
        }
        if self.call_timeout.is_zero()
            || self.poll_interval.is_zero()
            || self.backoff_min.is_zero()
            || self.backoff_min > self.backoff_max
        {
            return Err(ConfigError::Timing);
        }
        Ok(())
    }
}

/// Consumer settings, checked once by [`ConsumerConfig::validate`] (T-32 rule 8). The values
/// have no default: §18 OP-34 rule 7 sets only the publisher's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerConfig {
    /// Consumer group; the durable consumer of partition `p` is `<group>-p<p>` (T-76 rule 6).
    pub group: String,
    /// The partitions this instance consumes.
    pub partitions: Vec<u16>,
    /// Stream and subject schema (T-76).
    pub stream: StreamSettings,
    /// Messages pulled per fetch.
    pub batch_size: usize,
    /// Unacknowledged messages a durable consumer may hold (`max_ack_pending`).
    pub max_in_flight: usize,
    /// How long one fetch waits for messages.
    pub fetch_wait: Duration,
    /// How long JetStream waits for an ack before redelivering.
    pub ack_wait: Duration,
    /// Upper bound on every database and NATS call (T-32 rule 7).
    pub call_timeout: Duration,
    /// Wait between fallback scans while NATS is unreachable (T-21).
    pub fallback_interval: Duration,
    /// Ledgers with pending pointers discovered per fallback scan.
    pub ledgers_per_scan: u32,
    /// Event ids remembered to drop repeats.
    pub seen_capacity: usize,
}

impl ConsumerConfig {
    /// The durable consumer name of partition `p`, `<group>-p<p>` (T-76 rule 6).
    #[must_use]
    pub fn durable(&self, p: u16) -> String {
        format!("{}-p{}", self.group, self.stream.partition_token(p))
    }

    /// Rejects a setting the consumer cannot run with.
    ///
    /// # Errors
    /// The first [`ConfigError`] found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !is_plain_token(&self.group) {
            return Err(ConfigError::Group);
        }
        if self.stream.partitions == 0 {
            return Err(ConfigError::Partitions);
        }
        let mut owned = self.partitions.clone();
        owned.sort_unstable();
        owned.dedup();
        if owned.is_empty()
            || owned.len() != self.partitions.len()
            || owned.iter().any(|&p| p >= self.stream.partitions)
        {
            return Err(ConfigError::Owned);
        }
        if self.batch_size == 0
            || self.max_in_flight < self.batch_size
            || i64::try_from(self.max_in_flight).is_err()
            || self.ledgers_per_scan == 0
            || self.seen_capacity == 0
        {
            return Err(ConfigError::Bounds);
        }
        if self.fetch_wait.is_zero()
            || self.ack_wait.is_zero()
            || self.fallback_interval.is_zero()
            || self.fetch_wait >= self.call_timeout
        {
            return Err(ConfigError::Timing);
        }
        Ok(())
    }
}

/// The most replicas a JetStream stream can have.
pub const MAX_REPLICAS: usize = 5;

fn is_plain_token(t: &str) -> bool {
    !t.is_empty()
        && t.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A rejected [`PublisherConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// `source` is not an absolute `https` URI without a trailing slash, query or fragment.
    #[error("source must be an absolute https URI without a trailing slash, query or fragment")]
    Source,
    /// The stream name is empty or has characters NATS reserves.
    #[error("stream name must be non-empty ASCII letters, digits, `_` or `-`")]
    StreamName,
    /// A subject prefix token is empty or not `[a-z0-9_]+`.
    #[error("subject prefix must be dot-separated `[a-z0-9_]+` tokens")]
    SubjectPrefix,
    /// P is zero.
    #[error("partition count must be at least 1")]
    Partitions,
    /// A zero age or window, or a window longer than the age.
    #[error("max_age and duplicate_window must be positive and the window no longer than the age")]
    Retention,
    /// Replicas outside `1..=MAX_REPLICAS`.
    #[error("replicas must be between 1 and 5")]
    Replicas,
    /// A zero discovery, batch, in-flight or seen bound, or a consumer in-flight bound below its
    /// batch.
    #[error(
        "discovery, batch, in-flight and seen bounds must be at least 1, a consumer's in-flight at least its batch"
    )]
    Bounds,
    /// A zero timeout or interval, a minimum backoff above the maximum, or a fetch wait not
    /// below the call timeout.
    #[error(
        "timeouts and intervals must be positive, backoff_min at most backoff_max and fetch_wait below call_timeout"
    )]
    Timing,
    /// The consumer group is not a `[a-z0-9_]+` token.
    #[error("consumer group must be a `[a-z0-9_]+` token")]
    Group,
    /// No owned partition, a repeated one, or one not below P.
    #[error("owned partitions must be distinct, non-empty and below the partition count")]
    Owned,
}

/// `p = hash(ledger) mod P` (T-76 rule 1), where the hash is the ledger id itself: the
/// big-endian `u64` of the first 8 bytes of the genesis digest (P-67), already uniform; 0 for
/// P = 0.
#[must_use]
pub fn partition(ledger: &[u8; 32], partitions: u16) -> u16 {
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(ledger.get(..8).unwrap_or(&[0; 8]));
    u64::from_be_bytes(prefix)
        .checked_rem(u64::from(partitions))
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(0)
}

fn partition_width(partitions: u16) -> usize {
    let mut width = 1_usize;
    let mut rest = partitions.saturating_sub(1) / 10;
    while rest > 0 {
        width = width.saturating_add(1);
        rest /= 10;
    }
    width.max(2)
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            s.extend(DIGITS.get(usize::from(nibble)).map(|&c| char::from(c)));
        }
    }
    s
}

/// RFC 3339 UTC time with milliseconds (`YYYY-MM-DDTHH:MM:SS.mmmZ`) of Unix milliseconds;
/// `None` outside years 0000–9999.
#[must_use]
pub fn rfc3339_millis(ms: i64) -> Option<String> {
    const DAY_MS: i64 = 86_400_000;
    let days = ms.checked_div_euclid(DAY_MS)?;
    let of_day = ms.checked_rem_euclid(DAY_MS)?;
    let (y, m, d) = civil_from_days(days)?;
    if !(0..=9999).contains(&y) {
        return None;
    }
    let hh = of_day / 3_600_000;
    let mm = of_day % 3_600_000 / 60_000;
    let ss = of_day % 60_000 / 1000;
    let mmm = of_day % 1000;
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{mmm:03}Z"
    ))
}

fn civil_from_days(days: i64) -> Option<(i64, i64, i64)> {
    let z = days.checked_add(719_468)?;
    let era = z.checked_div_euclid(146_097)?;
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe / 1460)?
        .checked_add(doe / 36_524)?
        .checked_sub(doe / 146_096)?
        / 365;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe / 4)?
            .checked_sub(yoe / 100)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = yoe.checked_add(era.checked_mul(400)?)?;
    Some((y.checked_add(i64::from(m <= 2))?, m, d))
}

/// What the minimal event is built from: one outbox pointer and its committed log row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventFacts<'a> {
    /// Ledger digest.
    pub ledger: &'a [u8; 32],
    /// Log position the event reflects (T-18).
    pub pos: u64,
    /// CloudEvents `id`.
    pub event_id: &'a str,
    /// CloudEvents `type`.
    pub event_type: &'a str,
    /// W3C `traceparent` (§15 P-42).
    pub traceparent: &'a str,
    /// Digest of the record (`recordid`).
    pub record_id: &'a [u8; 32],
    /// `recorded_at` of the record, Unix milliseconds.
    pub recorded_at_ms: i64,
}

/// The event could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// `recorded_at` is outside the RFC 3339 range.
    #[error("recorded_at is outside the RFC 3339 range")]
    Time,
}

/// The `source` of events of `ledger` (§15 P-35 rule 2).
#[must_use]
pub fn source(installation: &str, ledger: &[u8; 32]) -> String {
    format!("{installation}/ledgers/{}", hex(ledger))
}

/// The structured-mode CloudEvents 1.0 JSON of the minimal event (§15 P-35, P-42; T-18):
/// `specversion`, `id`, `source`, `type`, `time` = the record's `recorded_at`, and the
/// extensions `traceparent`, `recordid`, `ledger` and `pos`; members in byte order, so equal
/// facts give equal bytes.
///
/// # Errors
/// [`EnvelopeError::Time`].
pub fn cloud_event(installation: &str, facts: &EventFacts<'_>) -> Result<Vec<u8>, EnvelopeError> {
    let time = rfc3339_millis(facts.recorded_at_ms).ok_or(EnvelopeError::Time)?;
    let event = serde_json::json!({
        "specversion": "1.0",
        "id": facts.event_id,
        "source": source(installation, facts.ledger),
        "type": facts.event_type,
        "time": time,
        "traceparent": facts.traceparent,
        "recordid": hex(facts.record_id),
        "ledger": hex(facts.ledger),
        "pos": facts.pos.to_string(),
    });
    Ok(event.to_string().into_bytes())
}

/// One event as a consumer sees it: what the minimal CloudEvents envelope carries (§15 P-35,
/// P-98; T-18), the same whether it came over NATS or from the fallback scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// CloudEvents `id`, the deduplication key with `ledger` (T-76 rule 3).
    pub id: String,
    /// CloudEvents `type`.
    pub event_type: String,
    /// Ledger digest.
    pub ledger: [u8; 32],
    /// Log position the event reflects (T-18).
    pub pos: u64,
    /// Digest of the record.
    pub record_id: [u8; 32],
    /// W3C `traceparent` (§15 P-42).
    pub traceparent: String,
}

impl Event {
    /// The event of `facts`, equal to [`parse_event`] of [`cloud_event`] of the same facts.
    #[must_use]
    pub fn from_facts(facts: &EventFacts<'_>) -> Self {
        Self {
            id: facts.event_id.to_owned(),
            event_type: facts.event_type.to_owned(),
            ledger: *facts.ledger,
            pos: facts.pos,
            record_id: *facts.record_id,
            traceparent: facts.traceparent.to_owned(),
        }
    }
}

/// A delivered payload is not a Work event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    /// Not a JSON object.
    #[error("event is not a JSON object")]
    Json,
    /// `specversion` is not `1.0`.
    #[error("event specversion is not 1.0")]
    SpecVersion,
    /// A required member is missing or not a non-empty string.
    #[error("event member `{0}` is missing or not a non-empty string")]
    Missing(&'static str),
    /// `ledger` or `recordid` is not 64 lower-case hex digits (P-98).
    #[error("event member `{0}` is not 64 lower-case hex digits")]
    Hex(&'static str),
    /// `pos` is not a decimal without sign or leading zero (P-98).
    #[error("event pos is not a canonical decimal")]
    Pos,
}

/// Parses the structured-mode CloudEvents JSON of a Work event (§15 P-35, P-98).
///
/// # Errors
/// [`EventError`].
pub fn parse_event(payload: &[u8]) -> Result<Event, EventError> {
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|_| EventError::Json)?;
    let object = value.as_object().ok_or(EventError::Json)?;
    let member = |name: &'static str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(EventError::Missing(name))
    };
    if member("specversion")? != "1.0" {
        return Err(EventError::SpecVersion);
    }
    Ok(Event {
        id: member("id")?.to_owned(),
        event_type: member("type")?.to_owned(),
        ledger: unhex32(member("ledger")?).ok_or(EventError::Hex("ledger"))?,
        pos: decimal(member("pos")?).ok_or(EventError::Pos)?,
        record_id: unhex32(member("recordid")?).ok_or(EventError::Hex("recordid"))?,
        traceparent: member("traceparent")?.to_owned(),
    })
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|d| d.checked_add(10)),
        _ => None,
    };
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if pairs.len() != 32 || !rest.is_empty() {
        return None;
    }
    let mut out = [0_u8; 32];
    for (o, [hi, lo]) in out.iter_mut().zip(pairs) {
        *o = digit(*hi)?.checked_shl(4)? | digit(*lo)?;
    }
    Some(out)
}

fn decimal(s: &str) -> Option<u64> {
    if !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

/// The event ids handled most recently, at most `capacity`, oldest forgotten first. It only
/// saves repeated work: a forgotten id is handled again, so handlers stay idempotent (T-18).
#[derive(Debug, Clone)]
pub struct Seen {
    capacity: usize,
    order: VecDeque<([u8; 32], String)>,
    set: BTreeSet<([u8; 32], String)>,
}

impl Seen {
    /// Empty, remembering up to `capacity` ids.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            set: BTreeSet::new(),
        }
    }

    /// Whether `id` of `ledger` was recorded and not yet forgotten.
    #[must_use]
    pub fn contains(&self, ledger: &[u8; 32], id: &str) -> bool {
        self.set.contains(&(*ledger, id.to_owned()))
    }

    /// Records `id` of `ledger`; `false` if it was already remembered.
    pub fn insert(&mut self, ledger: &[u8; 32], id: &str) -> bool {
        let key = (*ledger, id.to_owned());
        if self.set.contains(&key) || self.capacity == 0 {
            return false;
        }
        while self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.order.push_back(key.clone());
        self.set.insert(key);
        true
    }

    /// How many ids are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether no id is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Whether the NATS path of a consumer works (T-21, T-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Events arrive over JetStream.
    Live,
    /// NATS is unreachable; committed state is read by the fallback scan.
    Degraded,
}

/// Exponential backoff between `min` and `max`, doubling per failure (T-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    /// Starts at `min`.
    #[must_use]
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max,
            next: min,
        }
    }

    /// The wait after one more failure.
    pub fn fail(&mut self) -> Duration {
        let wait = self.next.min(self.max);
        self.next = wait.checked_mul(2).unwrap_or(self.max).min(self.max);
        wait
    }

    /// Back to `min` after a success.
    pub fn reset(&mut self) {
        self.next = self.min;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: [u8; 32] = [0xab; 32];

    fn facts() -> EventFacts<'static> {
        EventFacts {
            ledger: &L,
            pos: 7,
            event_id: "evt-0",
            event_type: "commitment.requested",
            traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            record_id: &[0x01; 32],
            recorded_at_ms: 1_792_749_600_123,
        }
    }

    #[test]
    fn t_76_defaults_are_the_policy_defaults() {
        let s = StreamSettings::default();
        assert_eq!(s.name, "WORK_EVENTS");
        assert_eq!(s.filter(), "work.evt.*.*.>");
        assert_eq!(s.partitions, 16);
        assert_eq!(s.max_age, Duration::from_hours(168));
        assert_eq!(s.duplicate_window, Duration::from_mins(2));
        assert_eq!(s.replicas, 1);
        assert_eq!(
            PublisherConfig::new("https://work.example").validate(),
            Ok(())
        );
    }

    #[test]
    fn t_76_multi_node_profile_keeps_three_replicas() {
        let s = StreamSettings::multi_node();
        assert_eq!(s.replicas, 3);
        assert_eq!(
            StreamSettings {
                replicas: 1,
                ..s.clone()
            },
            StreamSettings::default()
        );
        let config = PublisherConfig {
            stream: s,
            ..PublisherConfig::new("https://work.example")
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn t_76_partition_is_a_stable_hash_of_the_ledger_mod_p() {
        let mut id = [0_u8; 32];
        id[..8].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_be_bytes());
        id[8..].fill(0xff);
        assert_eq!(partition(&id, 16), 0x0f);
        assert_eq!(
            partition(&id, 10),
            u16::try_from(0x0123_4567_89ab_cdef_u64 % 10).unwrap()
        );
        assert_eq!(partition(&L, 16), partition(&L, 16));
        assert_eq!(partition(&L, 1), 0);
        assert_eq!(partition(&L, 0), 0);
        let spread: std::collections::BTreeSet<u16> =
            (0_u8..=255).map(|b| partition(&[b; 32], 16)).collect();
        assert_eq!(spread.len(), 16);
    }

    #[test]
    fn t_76_subject_carries_only_partition_ledger_and_type() {
        let s = StreamSettings::default();
        let subject = s.subject(&L, "commitment.requested");
        let p = partition(&L, 16);
        assert_eq!(
            subject,
            format!("work.evt.{p:02}.{}.commitment.requested", "ab".repeat(32))
        );
        let wide = StreamSettings {
            partitions: 1000,
            ..StreamSettings::default()
        };
        let token = wide.subject(&L, "work.opened");
        assert_eq!(token.split('.').nth(2).map(str::len), Some(3));
        assert!(subject.starts_with("work.evt."));
        assert_eq!(subject.split('.').count(), 6);
    }

    #[test]
    fn p_35_time_is_rfc3339_utc_milliseconds() {
        assert_eq!(
            rfc3339_millis(0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        assert_eq!(
            rfc3339_millis(1_792_749_600_123).as_deref(),
            Some("2026-10-23T10:00:00.123Z")
        );
        assert_eq!(
            rfc3339_millis(951_782_400_000).as_deref(),
            Some("2000-02-29T00:00:00.000Z")
        );
        assert_eq!(
            rfc3339_millis(-1).as_deref(),
            Some("1969-12-31T23:59:59.999Z")
        );
        assert_eq!(
            rfc3339_millis(253_402_300_799_999).as_deref(),
            Some("9999-12-31T23:59:59.999Z")
        );
        assert_eq!(rfc3339_millis(253_402_300_800_000), None);
        assert_eq!(rfc3339_millis(i64::MIN), None);
    }

    #[test]
    fn t_17_event_is_derived_deterministically_from_the_committed_row() {
        let a = cloud_event("https://work.example", &facts()).unwrap();
        let b = cloud_event("https://work.example", &facts()).unwrap();
        assert_eq!(a, b);
        let v: serde_json::Value = serde_json::from_slice(&a).unwrap();
        assert_eq!(v["specversion"], "1.0");
        assert_eq!(v["id"], "evt-0");
        assert_eq!(v["type"], "commitment.requested");
        assert_eq!(
            v["source"],
            format!("https://work.example/ledgers/{}", "ab".repeat(32))
        );
        assert_eq!(v["time"], "2026-10-23T10:00:00.123Z");
        assert_eq!(v["recordid"], "01".repeat(32));
        assert_eq!(v["ledger"], "ab".repeat(32));
        assert_eq!(v["pos"], "7");
        assert_eq!(v.as_object().map(serde_json::Map::len), Some(9));
    }

    #[test]
    fn p_98_pos_above_i32_is_a_decimal_string_and_hex_is_lower_case() {
        let f = EventFacts {
            pos: 1 << 33,
            ..facts()
        };
        let v: serde_json::Value =
            serde_json::from_slice(&cloud_event("https://w.example", &f).unwrap()).unwrap();
        assert_eq!(v["pos"], "8589934592");
        assert_eq!(v["ledger"], "ab".repeat(32));
        assert_eq!(v["recordid"], "01".repeat(32));
        assert_eq!(
            v["source"],
            format!("https://w.example/ledgers/{}", "ab".repeat(32))
        );
    }

    #[test]
    fn p_42_event_carries_the_pointer_traceparent() {
        let v: serde_json::Value =
            serde_json::from_slice(&cloud_event("https://w.example", &facts()).unwrap()).unwrap();
        assert_eq!(v["traceparent"], facts().traceparent);
    }

    #[test]
    fn p_35_out_of_range_time_is_an_error() {
        let f = EventFacts {
            recorded_at_ms: i64::MAX,
            ..facts()
        };
        assert_eq!(
            cloud_event("https://w.example", &f),
            Err(EnvelopeError::Time)
        );
    }

    #[test]
    fn t_32_invalid_publisher_settings_are_rejected() {
        let ok = PublisherConfig::new("https://work.example");
        let cases: [(PublisherConfig, ConfigError); 12] = [
            (
                PublisherConfig::new("http://work.example"),
                ConfigError::Source,
            ),
            (
                PublisherConfig::new("https://work.example/"),
                ConfigError::Source,
            ),
            (PublisherConfig::new("https://"), ConfigError::Source),
            (
                PublisherConfig {
                    stream: StreamSettings {
                        name: "WORK.EVENTS".to_owned(),
                        ..StreamSettings::default()
                    },
                    ..ok.clone()
                },
                ConfigError::StreamName,
            ),
            (
                PublisherConfig {
                    stream: StreamSettings {
                        subject_prefix: "work.*".to_owned(),
                        ..StreamSettings::default()
                    },
                    ..ok.clone()
                },
                ConfigError::SubjectPrefix,
            ),
            (
                PublisherConfig {
                    stream: StreamSettings {
                        partitions: 0,
                        ..StreamSettings::default()
                    },
                    ..ok.clone()
                },
                ConfigError::Partitions,
            ),
            (
                PublisherConfig {
                    stream: StreamSettings {
                        duplicate_window: Duration::from_hours(8 * 24),
                        ..StreamSettings::default()
                    },
                    ..ok.clone()
                },
                ConfigError::Retention,
            ),
            (
                PublisherConfig {
                    stream: StreamSettings {
                        replicas: 0,
                        ..StreamSettings::default()
                    },
                    ..ok.clone()
                },
                ConfigError::Replicas,
            ),
            (
                PublisherConfig {
                    stream: StreamSettings {
                        replicas: 6,
                        ..StreamSettings::default()
                    },
                    ..ok.clone()
                },
                ConfigError::Replicas,
            ),
            (
                PublisherConfig {
                    max_in_flight: 0,
                    ..ok.clone()
                },
                ConfigError::Bounds,
            ),
            (
                PublisherConfig {
                    ledgers_per_poll: 0,
                    ..ok.clone()
                },
                ConfigError::Bounds,
            ),
            (
                PublisherConfig {
                    backoff_min: Duration::from_secs(60),
                    ..ok.clone()
                },
                ConfigError::Timing,
            ),
        ];
        for (config, want) in cases {
            assert_eq!(config.validate(), Err(want), "{config:?}");
        }
    }

    #[test]
    fn t_21_backoff_doubles_up_to_the_maximum_and_resets() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(350));
        let waits: Vec<u128> = (0..4).map(|_| b.fail().as_millis()).collect();
        assert_eq!(waits, [100, 200, 350, 350]);
        b.reset();
        assert_eq!(b.fail(), Duration::from_millis(100));
    }

    fn consumer_config() -> ConsumerConfig {
        ConsumerConfig {
            group: "derive".to_owned(),
            partitions: vec![0, 7, 15],
            stream: StreamSettings::default(),
            batch_size: 8,
            max_in_flight: 16,
            fetch_wait: Duration::from_millis(500),
            ack_wait: Duration::from_secs(30),
            call_timeout: Duration::from_secs(5),
            fallback_interval: Duration::from_secs(1),
            ledgers_per_scan: 64,
            seen_capacity: 1024,
        }
    }

    #[test]
    fn t_76_consumers_are_durable_per_group_and_partition() {
        let c = consumer_config();
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.durable(0), "derive-p00");
        assert_eq!(c.durable(15), "derive-p15");
        assert_eq!(c.stream.partition_filter(7), "work.evt.07.*.>");
        let p = partition(&L, 16);
        let subject = c.stream.subject(&L, "work.opened");
        assert!(subject.starts_with(&format!("work.evt.{}.", c.stream.partition_token(p))));
        let wide = StreamSettings {
            partitions: 1000,
            ..StreamSettings::default()
        };
        assert_eq!(wide.partition_filter(7), "work.evt.007.*.>");
    }

    #[test]
    fn op_25_consumer_count_is_bounded_by_partitions_not_ledgers() {
        let c = ConsumerConfig {
            partitions: (0..16).collect(),
            ..consumer_config()
        };
        let names: std::collections::BTreeSet<String> =
            c.partitions.iter().map(|&p| c.durable(p)).collect();
        assert_eq!(names.len(), 16);
        let filters: std::collections::BTreeSet<String> = (0_u8..=255)
            .map(|b| c.stream.partition_filter(partition(&[b; 32], 16)))
            .collect();
        assert_eq!(filters.len(), 16);
    }

    #[test]
    fn t_32_invalid_consumer_settings_are_rejected() {
        let ok = consumer_config();
        let cases: [(ConsumerConfig, ConfigError); 9] = [
            (
                ConsumerConfig {
                    group: "derive.x".to_owned(),
                    ..ok.clone()
                },
                ConfigError::Group,
            ),
            (
                ConsumerConfig {
                    group: String::new(),
                    ..ok.clone()
                },
                ConfigError::Group,
            ),
            (
                ConsumerConfig {
                    partitions: Vec::new(),
                    ..ok.clone()
                },
                ConfigError::Owned,
            ),
            (
                ConsumerConfig {
                    partitions: vec![1, 1],
                    ..ok.clone()
                },
                ConfigError::Owned,
            ),
            (
                ConsumerConfig {
                    partitions: vec![16],
                    ..ok.clone()
                },
                ConfigError::Owned,
            ),
            (
                ConsumerConfig {
                    max_in_flight: 4,
                    ..ok.clone()
                },
                ConfigError::Bounds,
            ),
            (
                ConsumerConfig {
                    seen_capacity: 0,
                    ..ok.clone()
                },
                ConfigError::Bounds,
            ),
            (
                ConsumerConfig {
                    fetch_wait: Duration::from_secs(5),
                    ..ok.clone()
                },
                ConfigError::Timing,
            ),
            (
                ConsumerConfig {
                    stream: StreamSettings {
                        partitions: 0,
                        ..StreamSettings::default()
                    },
                    ..ok.clone()
                },
                ConfigError::Partitions,
            ),
        ];
        for (config, want) in cases {
            assert_eq!(config.validate(), Err(want), "{config:?}");
        }
    }

    #[test]
    fn t_18_a_published_event_parses_back_to_its_facts() {
        let bytes = cloud_event("https://work.example", &facts()).unwrap();
        let event = parse_event(&bytes).unwrap();
        assert_eq!(event, Event::from_facts(&facts()));
        assert_eq!(event.pos, 7);
        assert_eq!(event.ledger, L);
        let big = EventFacts {
            pos: 1 << 40,
            ..facts()
        };
        let bytes = cloud_event("https://work.example", &big).unwrap();
        assert_eq!(parse_event(&bytes).unwrap().pos, 1 << 40);
    }

    #[test]
    fn p_98_malformed_events_are_rejected() {
        let good: serde_json::Value =
            serde_json::from_slice(&cloud_event("https://w.example", &facts()).unwrap()).unwrap();
        let with = |name: &str, v: serde_json::Value| {
            let mut e = good.clone();
            e[name] = v;
            e.to_string().into_bytes()
        };
        assert_eq!(parse_event(b"[]"), Err(EventError::Json));
        assert_eq!(parse_event(b"{"), Err(EventError::Json));
        assert_eq!(
            parse_event(&with("specversion", "0.3".into())),
            Err(EventError::SpecVersion)
        );
        assert_eq!(
            parse_event(&with("id", "".into())),
            Err(EventError::Missing("id"))
        );
        assert_eq!(
            parse_event(&with("pos", 7.into())),
            Err(EventError::Missing("pos"))
        );
        for bad in ["07", "+7", "-1", "7a", "18446744073709551616"] {
            assert_eq!(
                parse_event(&with("pos", bad.into())),
                Err(EventError::Pos),
                "{bad}"
            );
        }
        assert_eq!(
            parse_event(&with("ledger", "AB".repeat(32).into())),
            Err(EventError::Hex("ledger"))
        );
        assert_eq!(
            parse_event(&with("recordid", "01".repeat(31).into())),
            Err(EventError::Hex("recordid"))
        );
    }

    #[test]
    fn t_18_seen_drops_repeats_in_any_order_and_stays_bounded() {
        let mut seen = Seen::new(2);
        assert!(seen.is_empty());
        assert!(seen.insert(&L, "b"));
        assert!(seen.insert(&L, "a"));
        assert!(!seen.insert(&L, "b"));
        assert!(seen.insert(&[0xcd; 32], "a"));
        assert_eq!(seen.len(), 2);
        assert!(!seen.contains(&L, "b"));
        assert!(seen.contains(&L, "a"));
        assert!(seen.insert(&L, "b"));
        assert!(!Seen::new(0).insert(&L, "a"));
    }
}
