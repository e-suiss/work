//! Idempotency keys (OP-8, OP-36, OP-38, P-54, P-96, P-97): the `Idempotency-Key` is a `UUIDv7` whose
//! timestamp places it inside or outside the hot window before any lookup, so a key from an
//! archived month is told apart from a new one without reaching the archive; a key inside the
//! window is looked up across every hot monthly partition in the caller's transaction.

use crate::{LedgerTx, StoreError};

/// The hot check window, 30 days in milliseconds (OP-36, POLICY DEFAULT).
pub const HOT_WINDOW_MS: i64 = 30 * 86_400_000;

/// The declared ledger clock uncertainty U in milliseconds (OP-32): a key may run this far
/// ahead of ledger time.
pub const CLOCK_UNCERTAINTY_MS: i64 = 250;

/// A well-formed `Idempotency-Key`: an RFC 9562 `UUIDv7`, stored in its lower-case
/// hyphenated form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdempotencyKey([u8; 16]);

impl IdempotencyKey {
    /// Parses the hyphenated 36-character form (hex digits in either case); `None` unless it is
    /// a UUID of version 7 and the RFC 9562 variant.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let raw = text.as_bytes();
        if raw.len() != 36 {
            return None;
        }
        let mut bytes = [0_u8; 16];
        let mut nibbles = raw
            .iter()
            .enumerate()
            .filter(|&(i, _)| !matches!(i, 8 | 13 | 18 | 23));
        for b in &mut bytes {
            let hi = nibble(*nibbles.next()?.1)?;
            let lo = nibble(*nibbles.next()?.1)?;
            *b = (hi << 4) | lo;
        }
        let hyphens = [8_usize, 13, 18, 23]
            .iter()
            .all(|&i| raw.get(i) == Some(&b'-'));
        let version = bytes.get(6).map(|b| b >> 4);
        let variant = bytes.get(8).map(|b| b >> 6);
        (hyphens && version == Some(7) && variant == Some(0b10)).then_some(Self(bytes))
    }

    /// The embedded Unix time in milliseconds (the leading 48 bits).
    #[must_use]
    pub fn unix_ms(&self) -> i64 {
        self.0
            .iter()
            .take(6)
            .fold(0_i64, |acc, &b| (acc << 8) | i64::from(b))
    }

    /// The lower-case hyphenated form, the value of `idem_key`.
    #[must_use]
    pub fn to_text(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(36);
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                s.push('-');
            }
            for n in [b >> 4, b & 0x0f] {
                s.extend(HEX.get(usize::from(n)).map(|&c| char::from(c)));
            }
        }
        s
    }

    /// Admits a raw header value at ledger time `now_ms` (OP-36, P-96): malformed unless it
    /// is a `UUIDv7` no more than [`CLOCK_UNCERTAINTY_MS`] ahead of `now_ms`, expired when more
    /// than [`HOT_WINDOW_MS`] behind it, otherwise hot.
    #[must_use]
    pub fn admit(text: &str, now_ms: i64) -> Admission {
        let Some(key) = Self::parse(text) else {
            return Admission::Malformed;
        };
        let at = key.unix_ms();
        if at.saturating_sub(now_ms) > CLOCK_UNCERTAINTY_MS {
            Admission::Malformed
        } else if now_ms.saturating_sub(at) > HOT_WINDOW_MS {
            Admission::Expired
        } else {
            Admission::Hot(key)
        }
    }
}

impl std::fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdempotencyKey({})", self.to_text())
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Where a raw key stands before any lookup (OP-36, P-96).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Inside the hot window: look it up.
    Hot(IdempotencyKey),
    /// Older than the hot window: `idempotency_key_expired`, no lookup.
    Expired,
    /// Not a `UUIDv7`, or ahead of ledger time beyond the clock uncertainty:
    /// `idempotency_key_malformed`, no lookup.
    Malformed,
}

/// The pseudonymous caller a key belongs to (`work.party_ref`, OP-14); its value is not
/// printed.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CallerRef(String);

impl CallerRef {
    /// `None` unless 1 to 255 bytes.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        (1..=255).contains(&value.len()).then_some(Self(value))
    }

    /// The reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CallerRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerRef(..)")
    }
}

/// The first result recorded under a key (OP-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredOutcome {
    /// The request was recorded at `pos` as `record_id`.
    Recorded {
        /// Log position.
        pos: u64,
        /// Record identifier.
        record_id: [u8; 32],
    },
    /// The request was rejected with a protocol reason code (P-93).
    Rejected {
        /// The reason code.
        reason: String,
    },
}

/// A key row (`work.idempotency_key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKey {
    /// Digest of the request the key was first used with.
    pub request_digest: [u8; 32],
    /// The first result.
    pub outcome: StoredOutcome,
    /// When the row was written, Unix milliseconds; it selects the monthly partition.
    pub created_at_ms: i64,
}

/// What a write request with a given key does next (OP-8, OP-36, P-96).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum IdempotencyDecision {
    /// Not seen in the hot window: sequence the request, then insert the key.
    Fresh(IdempotencyKey),
    /// Seen with the same request digest: return the stored result.
    Replay(StoredKey),
    /// Seen with another request digest: protocol error.
    Conflict,
    /// Older than the hot window: `idempotency_key_expired`.
    Expired,
    /// Not a valid key: `idempotency_key_malformed`.
    Malformed,
}

impl IdempotencyDecision {
    /// The protocol reason code of a rejection decided from the key alone (P-96, P-97); `None`
    /// for the other decisions.
    #[must_use]
    pub const fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::Expired => Some("idempotency_key_expired"),
            Self::Malformed => Some("idempotency_key_malformed"),
            Self::Fresh(_) | Self::Replay(_) | Self::Conflict => None,
        }
    }
}

type KeyRow = (
    Vec<u8>,
    String,
    Option<i64>,
    Option<Vec<u8>>,
    Option<String>,
    i64,
);

impl LedgerTx<'_> {
    /// Decides a write request carrying `raw_key` from `caller` with `request_digest` at ledger
    /// time `now_ms` (OP-8, OP-36): admission first, then the hot lookup.
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-model row.
    pub async fn idempotency(
        &mut self,
        caller: &CallerRef,
        raw_key: &str,
        request_digest: &[u8; 32],
        now_ms: i64,
    ) -> Result<IdempotencyDecision, StoreError> {
        let key = match IdempotencyKey::admit(raw_key, now_ms) {
            Admission::Hot(key) => key,
            Admission::Expired => return Ok(IdempotencyDecision::Expired),
            Admission::Malformed => return Ok(IdempotencyDecision::Malformed),
        };
        Ok(match self.idempotency_key(caller, &key).await? {
            None => IdempotencyDecision::Fresh(key),
            Some(row) if row.request_digest == *request_digest => IdempotencyDecision::Replay(row),
            Some(_) => IdempotencyDecision::Conflict,
        })
    }

    /// The earliest row of `caller`'s `key` across every hot partition (OP-36 rule 1), so the
    /// status of a request stays queryable (OP-8).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for an out-of-model row.
    pub async fn idempotency_key(
        &mut self,
        caller: &CallerRef,
        key: &IdempotencyKey,
    ) -> Result<Option<StoredKey>, StoreError> {
        let ledger = *self.ledger().as_bytes();
        let row: Option<KeyRow> = sqlx::query_as(
            "SELECT request_digest::bytea, outcome, result_pos::bigint, result_record_id::bytea, \
             reason::text, (extract(epoch FROM created_at) * 1000)::bigint \
             FROM work.idempotency_key \
             WHERE ledger_id = $1 AND caller_ref = $2 AND idem_key = $3 \
             ORDER BY created_at LIMIT 1",
        )
        .bind(ledger.as_slice())
        .bind(caller.as_str())
        .bind(key.to_text())
        .fetch_optional(self.conn())
        .await?;
        row.map(stored).transpose()
    }

    /// Inserts `caller`'s `key` with its first result at `created_at_ms` in this transaction
    /// (OP-8); the sequencer writes it in the batch that records the result (OP-5). A month
    /// without a partition is rejected by the database (OP-37).
    ///
    /// # Errors
    /// [`StoreError::Db`], or [`StoreError::Corrupt`] for a position beyond `bigint`.
    pub async fn insert_idempotency_key(
        &mut self,
        caller: &CallerRef,
        key: &IdempotencyKey,
        row: &StoredKey,
    ) -> Result<(), StoreError> {
        let ledger = *self.ledger().as_bytes();
        let (outcome, pos, record_id, reason) = match &row.outcome {
            StoredOutcome::Recorded { pos, record_id } => (
                "recorded",
                Some(i64::try_from(*pos).map_err(|_| StoreError::Corrupt)?),
                Some(record_id.as_slice()),
                None,
            ),
            StoredOutcome::Rejected { reason } => ("rejected", None, None, Some(reason.as_str())),
        };
        sqlx::query(
            "INSERT INTO work.idempotency_key \
             (ledger_id, caller_ref, idem_key, request_digest, outcome, result_pos, \
              result_record_id, reason, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, \
             pg_catalog.to_timestamp(0) + interval '1 millisecond' * $9::bigint::double precision)",
        )
        .bind(ledger.as_slice())
        .bind(caller.as_str())
        .bind(key.to_text())
        .bind(row.request_digest.as_slice())
        .bind(outcome)
        .bind(pos)
        .bind(record_id)
        .bind(reason)
        .bind(row.created_at_ms)
        .execute(self.conn())
        .await?;
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| StoreError::Corrupt)
}

fn stored(
    (request_digest, outcome, pos, record_id, reason, created_at_ms): KeyRow,
) -> Result<StoredKey, StoreError> {
    let outcome = match (outcome.as_str(), pos, record_id, reason) {
        ("recorded", Some(pos), Some(record_id), None) => StoredOutcome::Recorded {
            pos: u64::try_from(pos).map_err(|_| StoreError::Corrupt)?,
            record_id: digest(&record_id)?,
        },
        ("rejected", None, None, Some(reason)) => StoredOutcome::Rejected { reason },
        _ => return Err(StoreError::Corrupt),
    };
    Ok(StoredKey {
        request_digest: digest(&request_digest)?,
        outcome,
        created_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_761_650_000_123;

    fn key_at(ms: i64) -> String {
        let hex = format!("{ms:012x}");
        format!("{}-{}-7abc-9def-0123456789ab", &hex[..8], &hex[8..])
    }

    // P-54
    #[test]
    fn p_97_a_uuidv7_key_parses_round_trips_and_carries_its_time() {
        let text = "0199a0b1-c2d3-7e4f-8a5b-6c7d8e9f0a1b";
        let key = IdempotencyKey::parse(text).unwrap();
        assert_eq!(key.to_text(), text);
        assert_eq!(key.unix_ms(), 0x0199_a0b1_c2d3);
        let upper = IdempotencyKey::parse(&text.to_uppercase()).unwrap();
        assert_eq!(upper, key);
        assert_eq!(upper.to_text(), text);
        assert_eq!(IdempotencyKey::parse(&key_at(NOW)).unwrap().unix_ms(), NOW);
    }

    // P-54
    #[test]
    fn p_97_a_key_that_is_not_a_uuidv7_does_not_parse() {
        for bad in [
            "",
            "req-1",
            "0199a0b1-c2d3-4e4f-8a5b-6c7d8e9f0a1b",
            "0199a0b1-c2d3-7e4f-ca5b-6c7d8e9f0a1b",
            "0199a0b1-c2d3-7e4f-0a5b-6c7d8e9f0a1b",
            "0199a0b1c2d37e4f8a5b6c7d8e9f0a1b",
            "0199a0b1-c2d3-7e4f-8a5b-6c7d8e9f0a1",
            "0199a0b1-c2d3-7e4f-8a5b-6c7d8e9f0a1bc",
            "0199a0b1_c2d3-7e4f-8a5b-6c7d8e9f0a1b",
            "0199a0b1-c2d3-7e4f-8a5b-6c7d8e9f0a1g",
            "{199a0b1-c2d3-7e4f-8a5b-6c7d8e9f0a1b}",
            "0199a0b1-c2d3-7e4f-8a5b-6c7d8e9f0a\u{e9}",
        ] {
            assert_eq!(IdempotencyKey::parse(bad), None, "{bad}");
            assert_eq!(
                IdempotencyKey::admit(bad, NOW),
                Admission::Malformed,
                "{bad}"
            );
        }
    }

    // OP-36 OP-32 P-96 P-97
    #[test]
    fn op_38_admission_follows_the_hot_window_and_the_clock_uncertainty() {
        let hot = |ms: i64| {
            IdempotencyKey::parse(&key_at(ms))
                .map(Admission::Hot)
                .unwrap()
        };
        for (at, want) in [
            (NOW, hot(NOW)),
            (NOW - HOT_WINDOW_MS, hot(NOW - HOT_WINDOW_MS)),
            (NOW - HOT_WINDOW_MS - 1, Admission::Expired),
            (0, Admission::Expired),
            (NOW + CLOCK_UNCERTAINTY_MS, hot(NOW + CLOCK_UNCERTAINTY_MS)),
            (NOW + CLOCK_UNCERTAINTY_MS + 1, Admission::Malformed),
        ] {
            assert_eq!(IdempotencyKey::admit(&key_at(at), NOW), want, "{at}");
        }
        assert_eq!(
            IdempotencyKey::admit(&key_at(NOW), i64::MIN),
            Admission::Malformed
        );
        assert_eq!(
            IdempotencyKey::admit(&key_at(NOW), i64::MAX),
            Admission::Expired
        );
    }

    // OP-14
    #[test]
    fn op_8_a_caller_reference_is_bounded_and_not_printed() {
        assert!(CallerRef::new("").is_none());
        assert!(CallerRef::new("p".repeat(256)).is_none());
        let caller = CallerRef::new("party:alice").unwrap();
        assert_eq!(caller.as_str(), "party:alice");
        assert!(!format!("{caller:?}").contains("alice"));
    }

    #[test]
    fn op_8_a_stored_row_maps_to_one_outcome_or_is_corrupt() {
        let d = vec![7_u8; 32];
        let recorded = stored((
            d.clone(),
            "recorded".into(),
            Some(3),
            Some(d.clone()),
            None,
            9,
        ))
        .unwrap();
        assert_eq!(
            recorded.outcome,
            StoredOutcome::Recorded {
                pos: 3,
                record_id: [7; 32]
            }
        );
        let rejected = stored((
            d.clone(),
            "rejected".into(),
            None,
            None,
            Some("conflict".into()),
            9,
        ))
        .unwrap();
        assert_eq!(
            rejected.outcome,
            StoredOutcome::Rejected {
                reason: "conflict".into()
            }
        );
        for row in [
            (d.clone(), "recorded".into(), None, Some(d.clone()), None, 9),
            (
                d.clone(),
                "recorded".into(),
                Some(-1),
                Some(d.clone()),
                None,
                9,
            ),
            (
                d.clone(),
                "rejected".into(),
                Some(1),
                None,
                Some("x".into()),
                9,
            ),
            (d.clone(), "other".into(), None, None, None, 9),
            (
                vec![1; 31],
                "rejected".into(),
                None,
                None,
                Some("x".into()),
                9,
            ),
        ] {
            assert!(matches!(stored(row), Err(StoreError::Corrupt)));
        }
    }

    // P-96
    #[test]
    fn p_97_key_rejections_carry_their_reason_codes() {
        assert_eq!(
            IdempotencyDecision::Malformed.reason_code(),
            Some("idempotency_key_malformed")
        );
        assert_eq!(
            IdempotencyDecision::Expired.reason_code(),
            Some("idempotency_key_expired")
        );
        assert_eq!(IdempotencyDecision::Conflict.reason_code(), None);
    }
}
