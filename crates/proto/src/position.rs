//! The read position token (T-97 item 1, T-14): `pos_` and unpadded base64url of a version byte `0x01`, a key id byte, a count `n` of 1 to 16 and `n` pairs of a 32-byte `LedgerID` digest and a big-endian `u64` position, ascending by ledger and without repeats, followed by the first 16 bytes of an HMAC-SHA-256 over `work/read-position/v1`, a zero byte, the tenant id bytes and every earlier token byte. The MAC key lives in PKCS#11 (T-56); this module only lays the bytes out, so the token carries no authority and is never parsed by a client (T-97 item 5).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use work_kernel::id::{Digest, LedgerId};

use crate::id::PositionToken;

/// The token format version.
pub const VERSION: u8 = 0x01;

/// The most ledgers one token names.
pub const MAX_LEDGERS: usize = 16;

/// The MAC bytes the token keeps, the first half of HMAC-SHA-256.
pub const TAG_LEN: usize = 16;

/// The MAC domain separator.
pub const CONTEXT: &[u8] = b"work/read-position/v1";

/// The problem code of a token that does not open (T-97 item 4).
pub const INVALID: &str = "read_position_invalid";

/// The problem code of a position past the canonical head (T-97 item 4).
pub const AHEAD: &str = "read_position_ahead";

const PAIR: usize = 40;
const HEAD: usize = 3;

/// Why a set of positions or a token is refused; each is `read_position_invalid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PositionError {
    /// No ledger, or more than [`MAX_LEDGERS`].
    #[error("a token names 1 to 16 ledgers")]
    Count,
    /// Not the token layout: version, length, order or repeats.
    #[error("malformed read position token")]
    Malformed,
}

/// The positions of 1 to 16 ledgers, ascending by ledger (T-97 item 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Positions(BTreeMap<LedgerId, u64>);

impl Positions {
    /// The positions of `entries`; a ledger named twice keeps its highest position, since a
    /// position only grows.
    ///
    /// # Errors
    /// [`PositionError::Count`] for no ledger or more than [`MAX_LEDGERS`].
    pub fn new(entries: impl IntoIterator<Item = (LedgerId, u64)>) -> Result<Self, PositionError> {
        let mut map = BTreeMap::new();
        for (ledger, pos) in entries {
            let slot = map.entry(ledger).or_insert(pos);
            *slot = (*slot).max(pos);
        }
        if map.is_empty() || map.len() > MAX_LEDGERS {
            return Err(PositionError::Count);
        }
        Ok(Self(map))
    }

    /// The ledgers and their positions, ascending by ledger.
    pub fn entries(&self) -> impl Iterator<Item = (&LedgerId, &u64)> {
        self.0.iter()
    }

    /// The position of `ledger`, if the token names it.
    #[must_use]
    pub fn get(&self, ledger: &LedgerId) -> Option<u64> {
        self.0.get(ledger).copied()
    }

    /// The number of ledgers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Never true: a token names at least one ledger.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True when every ledger of `self` is at least at its position in `other`'s view: `other`
    /// names it at that position or later.
    #[must_use]
    pub fn reached_by(&self, other: &BTreeMap<LedgerId, u64>) -> bool {
        self.0
            .iter()
            .all(|(ledger, pos)| other.get(ledger).is_some_and(|at| at >= pos))
    }
}

/// The token bytes the MAC covers after the context and tenant: version, key id, count, pairs.
#[must_use]
pub fn body(key_id: u8, positions: &Positions) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PAIR.saturating_mul(positions.len())
            .saturating_add(HEAD)
            .saturating_add(TAG_LEN),
    );
    out.push(VERSION);
    out.push(key_id);
    out.push(u8::try_from(positions.len()).unwrap_or(u8::MAX));
    for (ledger, pos) in positions.entries() {
        out.extend_from_slice(ledger.0.as_bytes());
        out.extend_from_slice(&pos.to_be_bytes());
    }
    out
}

/// The MAC input: the context, a zero byte, the tenant id bytes and the token body.
#[must_use]
pub fn mac_input(tenant: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CONTEXT
            .len()
            .saturating_add(1)
            .saturating_add(tenant.len())
            .saturating_add(body.len()),
    );
    out.extend_from_slice(CONTEXT);
    out.push(0);
    out.extend_from_slice(tenant);
    out.extend_from_slice(body);
    out
}

/// The token of `body` and its full HMAC-SHA-256 `mac`, cut to [`TAG_LEN`] bytes.
///
/// # Errors
/// [`PositionError::Malformed`] for an empty body.
pub fn seal(mut body: Vec<u8>, mac: &[u8; 32]) -> Result<PositionToken, PositionError> {
    if body.is_empty() {
        return Err(PositionError::Malformed);
    }
    body.extend_from_slice(mac.get(..TAG_LEN).unwrap_or_default());
    PositionToken::new(body).ok_or(PositionError::Malformed)
}

/// A token laid out but not yet checked: the MAC is checked by the key holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsealed {
    /// The key id byte.
    pub key_id: u8,
    /// The positions.
    pub positions: Positions,
    /// The bytes the MAC covers after the context and tenant.
    pub body: Vec<u8>,
    /// The kept MAC bytes.
    pub tag: [u8; TAG_LEN],
}

impl Unsealed {
    /// True when `mac`, the full HMAC-SHA-256 of [`mac_input`] under the key of
    /// [`Unsealed::key_id`], starts with the kept tag; compared in constant time.
    #[must_use]
    pub fn tag_matches(&self, mac: &[u8; 32]) -> bool {
        let difference = mac
            .iter()
            .zip(self.tag.iter())
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
        difference == 0
    }
}

/// The layout of `token`.
///
/// # Errors
/// [`PositionError::Malformed`] for another version, a length that is not the layout's, an
/// unordered or repeated ledger; [`PositionError::Count`] for a count outside 1 to 16.
pub fn unseal(token: &PositionToken) -> Result<Unsealed, PositionError> {
    let bytes = token.as_bytes();
    let (head, rest) = bytes
        .split_at_checked(HEAD)
        .ok_or(PositionError::Malformed)?;
    let [version, key_id, count] =
        <[u8; HEAD]>::try_from(head).map_err(|_| PositionError::Malformed)?;
    if version != VERSION {
        return Err(PositionError::Malformed);
    }
    let n = usize::from(count);
    if n == 0 || n > MAX_LEDGERS {
        return Err(PositionError::Count);
    }
    let pairs_len = PAIR.checked_mul(n).ok_or(PositionError::Malformed)?;
    if rest.len()
        != pairs_len
            .checked_add(TAG_LEN)
            .ok_or(PositionError::Malformed)?
    {
        return Err(PositionError::Malformed);
    }
    let (pairs, tag) = rest
        .split_at_checked(pairs_len)
        .ok_or(PositionError::Malformed)?;
    let mut entries: Vec<(LedgerId, u64)> = Vec::with_capacity(n);
    for pair in pairs.chunks_exact(PAIR) {
        let (ledger, pos) = pair.split_at_checked(32).ok_or(PositionError::Malformed)?;
        let ledger = LedgerId(Digest::sha256(
            ledger.try_into().map_err(|_| PositionError::Malformed)?,
        ));
        let pos = u64::from_be_bytes(pos.try_into().map_err(|_| PositionError::Malformed)?);
        if entries.last().is_some_and(|(last, _)| *last >= ledger) {
            return Err(PositionError::Malformed);
        }
        entries.push((ledger, pos));
    }
    let tag = tag.try_into().map_err(|_| PositionError::Malformed)?;
    let body_len = bytes
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(PositionError::Malformed)?;
    Ok(Unsealed {
        key_id,
        positions: Positions::new(entries)?,
        body: bytes
            .get(..body_len)
            .ok_or(PositionError::Malformed)?
            .to_vec(),
        tag,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::id::ExternalId as _;

    fn ledger(byte: u8) -> LedgerId {
        LedgerId(Digest::sha256([byte; 32]))
    }

    // T-97 P-112
    #[test]
    fn t_97_the_token_lays_out_version_key_count_pairs_and_a_16_byte_tag() {
        let positions =
            Positions::new([(ledger(2), 7), (ledger(1), u64::MAX), (ledger(2), 5)]).unwrap();
        assert_eq!(positions.get(&ledger(2)), Some(7));
        let body = body(9, &positions);
        assert_eq!(body.len(), 83);
        assert_eq!(body.get(..3), Some(&[VERSION, 9, 2][..]));
        assert_eq!(body.get(3..35), Some(&[1_u8; 32][..]));
        assert_eq!(body.get(35..43), Some(&u64::MAX.to_be_bytes()[..]));
        let mac = [0xa5; 32];
        let token = seal(body.clone(), &mac).unwrap();
        assert_eq!(token.as_bytes().len(), 99);
        assert!(token.to_external().starts_with("pos_"));
        let unsealed = unseal(&token).unwrap();
        assert_eq!((unsealed.key_id, &unsealed.positions), (9, &positions));
        assert_eq!(unsealed.body, body);
        assert!(unsealed.tag_matches(&mac));
        let mut other = mac;
        other[15] ^= 1;
        assert!(!unsealed.tag_matches(&other));
        other = mac;
        other[16] ^= 1;
        assert!(unsealed.tag_matches(&other));
        let input = mac_input(b"tenant-1", &body);
        assert_eq!(input.get(..22), Some(&b"work/read-position/v1\0"[..]));
        assert_eq!(input.get(22..30), Some(&b"tenant-1"[..]));
        assert_eq!(input.get(30..), Some(&body[..]));
    }

    // T-97
    #[test]
    fn t_97_a_malformed_token_is_read_position_invalid() {
        assert_eq!(Positions::new([]), Err(PositionError::Count));
        assert_eq!(
            Positions::new((0..17).map(|b| (ledger(b), 1))),
            Err(PositionError::Count)
        );
        assert!(Positions::new((0..16).map(|b| (ledger(b), 1))).is_ok());
        let good = seal(
            body(
                1,
                &Positions::new([(ledger(1), 1), (ledger(2), 2)]).unwrap(),
            ),
            &[0; 32],
        )
        .unwrap();
        let bytes = good.as_bytes().to_vec();
        let mut cases = vec![
            bytes.get(..bytes.len().saturating_sub(1)).unwrap().to_vec(),
            [bytes.clone(), vec![0]].concat(),
            vec![VERSION, 1],
        ];
        let mut version = bytes.clone();
        version[0] = 2;
        cases.push(version);
        let mut swapped = bytes.clone();
        swapped[3..35].copy_from_slice(&[3; 32]);
        cases.push(swapped);
        let mut repeated = bytes.clone();
        repeated[43..75].copy_from_slice(&[1; 32]);
        cases.push(repeated);
        for case in cases {
            assert_eq!(
                unseal(&PositionToken::new(case.clone()).unwrap()),
                Err(PositionError::Malformed),
                "{case:?}"
            );
        }
        let mut zero = bytes.clone();
        zero[2] = 0;
        assert_eq!(
            unseal(&PositionToken::new(zero).unwrap()),
            Err(PositionError::Count)
        );
        let mut many = bytes;
        many[2] = 17;
        assert_eq!(
            unseal(&PositionToken::new(many).unwrap()),
            Err(PositionError::Count)
        );
        assert_eq!(
            (INVALID, AHEAD),
            ("read_position_invalid", "read_position_ahead")
        );
    }

    // T-97
    #[test]
    fn t_97_a_view_reaches_a_token_only_at_every_ledger() {
        let wanted = Positions::new([(ledger(1), 5), (ledger(2), 3)]).unwrap();
        let mut view = BTreeMap::from([(ledger(1), 5)]);
        assert!(!wanted.reached_by(&view));
        view.insert(ledger(2), 2);
        assert!(!wanted.reached_by(&view));
        view.insert(ledger(2), 3);
        assert!(wanted.reached_by(&view));
        view.insert(ledger(3), 0);
        view.insert(ledger(1), 9);
        assert!(wanted.reached_by(&view));
    }
}
