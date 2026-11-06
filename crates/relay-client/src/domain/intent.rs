//! A notification intent (T-99, E-18, ST-40): what Work asks Relay to deliver, built only from a committed record, with the ledger time of the evaluation that raised it, the item it is about, the reason code, whether it blocks, and the Parties to reach; the idempotency key it is sent with derives from its ledger, log position and transition, never from content (T-12 item 6, T-99 item 10).

use sha2::{Digest as _, Sha256};
use work_proto::id::{Prefix, TenantId, parse};

/// The most recipients one Relay event takes.
pub const MAX_RECIPIENTS: usize = 100;

/// The domain tag of the idempotency key.
const KEY_TAG: &[u8] = b"work/relay/idempotency/v1\0";

/// The prefix of every idempotency key Work sends Relay.
pub const KEY_PREFIX: &str = "wrk-";

/// The committed record an intent comes from: never derived state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The ledger digest.
    pub ledger: [u8; 32],
    /// The record's log position.
    pub pos: u64,
    /// The record digest.
    pub record_id: [u8; 32],
    /// The record's ledger time, Unix milliseconds: the time of the evaluation.
    pub recorded_at_ms: i64,
    /// The W3C trace context of the committing request.
    pub traceparent: String,
}

/// What the notification asks of its recipients (ST-40).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Someone must act before the item can move on (ST-40 item 1, `action_required`).
    Blocking,
    /// Nobody needs to act (ST-40 item 2).
    Informational,
}

/// Why an intent cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IntentError {
    /// The item is not a Work, Commitment or Condition id.
    #[error("the item is not a work item id")]
    Item,
    /// The reason is not a catalogue code.
    #[error("the reason is not a code")]
    Reason,
    /// No recipient, or more than [`MAX_RECIPIENTS`].
    #[error("recipients: one to {MAX_RECIPIENTS}")]
    Recipients,
    /// The trace context is not a W3C `traceparent`.
    #[error("traceparent")]
    Traceparent,
    /// The realm is empty.
    #[error("realm")]
    Realm,
}

/// The idempotency key and `dedup_key` of one intent (T-99 item 10).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// The key of `transition` at `pos` of `ledger`.
    #[must_use]
    pub fn of(ledger: &[u8; 32], pos: u64, transition: &str) -> Self {
        let mut h = Sha256::new();
        h.update(KEY_TAG);
        h.update(ledger);
        h.update(pos.to_be_bytes());
        h.update(transition.as_bytes());
        Self(format!("{KEY_PREFIX}{}", hex(&h.finalize())))
    }

    /// The key of a batch of rows: the key of their keys, in order.
    #[must_use]
    pub fn of_batch(rows: &[&Self]) -> Self {
        let mut h = Sha256::new();
        h.update(KEY_TAG);
        h.update(b"batch\0");
        for row in rows {
            h.update(row.0.as_bytes());
            h.update([0]);
        }
        Self(format!("{KEY_PREFIX}{}", hex(&h.finalize())))
    }

    /// The key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn is_code(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && text.len() <= 64
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// A W3C `traceparent` of version `00`.
#[must_use]
pub fn is_traceparent(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    let hexes = |s: &str, n: usize| {
        s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    matches!(parts.as_slice(), [v, t, p, f] if *v == "00" && hexes(t, 32) && hexes(p, 16) && hexes(f, 2))
}

/// What an intent says, before it is checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    /// The transition that raised it, a snake-case code: part of the idempotency key.
    pub reason: String,
    /// Whether it blocks.
    pub class: Class,
    /// The external id of the item (`wrk_`, `cmt_` or `cnd_`).
    pub item: String,
    /// The tenant of the item.
    pub tenant: TenantId,
    /// The realm of the recipients, for their pairwise `sub`.
    pub realm: String,
    /// The recipients, as base64url `PartyID`s.
    pub parties: Vec<String>,
    /// The Access approval page of an authority gate, when the recipient approves there (E-26).
    pub approval: Option<String>,
}

/// A checked intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationIntent {
    committed: Committed,
    spec: Spec,
    key: IdempotencyKey,
}

impl NotificationIntent {
    /// The intent `spec` raised by the record `committed`; repeated recipients count once.
    ///
    /// # Errors
    /// [`IntentError`].
    pub fn new(committed: Committed, mut spec: Spec) -> Result<Self, IntentError> {
        let item_ok = [Prefix::Work, Prefix::Commitment, Prefix::Condition]
            .into_iter()
            .any(|p| parse(p, &spec.item).is_ok());
        if !item_ok {
            return Err(IntentError::Item);
        }
        if !is_code(&spec.reason) {
            return Err(IntentError::Reason);
        }
        if !is_traceparent(&committed.traceparent) {
            return Err(IntentError::Traceparent);
        }
        if spec.realm.is_empty() {
            return Err(IntentError::Realm);
        }
        let mut seen = std::collections::BTreeSet::new();
        spec.parties.retain(|p| seen.insert(p.clone()));
        if spec.parties.is_empty() || spec.parties.len() > MAX_RECIPIENTS {
            return Err(IntentError::Recipients);
        }
        let key = IdempotencyKey::of(&committed.ledger, committed.pos, &spec.reason);
        Ok(Self {
            committed,
            spec,
            key,
        })
    }

    /// The record it comes from.
    #[must_use]
    pub const fn committed(&self) -> &Committed {
        &self.committed
    }

    /// What it says.
    #[must_use]
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Its idempotency key.
    #[must_use]
    pub const fn key(&self) -> &IdempotencyKey {
        &self.key
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const TRACE: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    pub(crate) fn committed() -> Committed {
        Committed {
            ledger: [7; 32],
            pos: 42,
            record_id: [9; 32],
            recorded_at_ms: 1_793_000_000_000,
            traceparent: TRACE.to_owned(),
        }
    }

    pub(crate) fn spec() -> Spec {
        Spec {
            reason: "gate_waiting".to_owned(),
            class: Class::Blocking,
            item: format!("cnd_{}", "ab".repeat(32)),
            tenant: TenantId::new("tnt_acme").unwrap(),
            realm: "acme".to_owned(),
            parties: vec!["AAECAwQFBgcICQoLDA0ODw".to_owned()],
            approval: None,
        }
    }

    // T-12 T-99
    #[test]
    fn t_12_the_key_is_the_transition_at_its_ledger_position_and_never_content() {
        let a = NotificationIntent::new(committed(), spec()).unwrap();
        let mut other_content = committed();
        other_content.record_id = [1; 32];
        other_content.recorded_at_ms = 0;
        let b = NotificationIntent::new(
            other_content,
            Spec {
                parties: vec!["other".to_owned()],
                ..spec()
            },
        )
        .unwrap();
        assert_eq!(a.key(), b.key());
        assert!(a.key().as_str().starts_with(KEY_PREFIX));
        assert_eq!(a.key().as_str().len(), KEY_PREFIX.len() + 64);
        let mut later = committed();
        later.pos = 43;
        assert_ne!(
            NotificationIntent::new(later, spec()).unwrap().key(),
            a.key()
        );
        let other = Spec {
            reason: "gate_opened".to_owned(),
            ..spec()
        };
        assert_ne!(
            NotificationIntent::new(committed(), other).unwrap().key(),
            a.key()
        );
        let rows = [a.key(), b.key()];
        assert_eq!(
            IdempotencyKey::of_batch(&rows),
            IdempotencyKey::of_batch(&rows)
        );
        assert_ne!(
            IdempotencyKey::of_batch(&rows),
            IdempotencyKey::of_batch(&rows[..1])
        );
    }

    // T-99 E-18
    #[test]
    fn t_99_an_intent_names_a_work_item_a_code_and_one_to_a_hundred_parties() {
        let bad_item = Spec {
            item: format!("rec_{}", "ab".repeat(32)),
            ..spec()
        };
        assert_eq!(
            NotificationIntent::new(committed(), bad_item),
            Err(IntentError::Item)
        );
        let bad_reason = Spec {
            reason: "Gate waiting".to_owned(),
            ..spec()
        };
        assert_eq!(
            NotificationIntent::new(committed(), bad_reason),
            Err(IntentError::Reason)
        );
        let none = Spec {
            parties: Vec::new(),
            ..spec()
        };
        assert_eq!(
            NotificationIntent::new(committed(), none),
            Err(IntentError::Recipients)
        );
        let many = Spec {
            parties: (0..=MAX_RECIPIENTS).map(|n| n.to_string()).collect(),
            ..spec()
        };
        assert_eq!(
            NotificationIntent::new(committed(), many),
            Err(IntentError::Recipients)
        );
        let twice = Spec {
            parties: vec!["p".to_owned(), "p".to_owned()],
            ..spec()
        };
        assert_eq!(
            NotificationIntent::new(committed(), twice)
                .unwrap()
                .spec()
                .parties,
            ["p"]
        );
        let mut untraced = committed();
        untraced.traceparent = "00-zz".to_owned();
        assert_eq!(
            NotificationIntent::new(untraced, spec()),
            Err(IntentError::Traceparent)
        );
    }
}
