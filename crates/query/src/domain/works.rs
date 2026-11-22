//! Opening a Work (C-8, PR-9, X-19, C-35): a Work is only an identity, so opening one asks for no field, no Practice, template, workflow or type, and writes nothing; the Work exists for the ledger once a record concerns it. The identity is a pure function of the caller's Party and the request's `Idempotency-Key`, so the same request answers the same Work without a stored key, two Parties never share one, and none encodes a place, region or tenant.

use suiss_crypto::digest::sha256;
use work_kernel::id::WorkId;

use crate::domain::caller::CallerParty;

const LABEL: &[u8] = b"work/open/v1";

/// Whether `key` is a `UUIDv7` in its hyphenated spelling (P-54 item 4).
#[must_use]
pub fn uuid_v7(key: &str) -> bool {
    let bytes = key.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            14 => *b == b'7',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b' | b'A' | b'B'),
            _ => b.is_ascii_hexdigit(),
        })
}

/// The Work `party` opens with `key`: the first 16 bytes of the SHA-256 of a fixed label, the
/// Party's 16-byte `PartyID` and the key.
#[must_use]
pub fn opened_work(party: &CallerParty, key: &str) -> WorkId {
    let mut input = Vec::with_capacity(
        LABEL
            .len()
            .saturating_add(party.id.len())
            .saturating_add(key.len()),
    );
    input.extend_from_slice(LABEL);
    input.extend_from_slice(&party.id);
    input.extend_from_slice(key.as_bytes());
    let digest = sha256(&input);
    WorkId::from_bytes(core::array::from_fn(|i| {
        digest.get(i).copied().unwrap_or_default()
    }))
}

#[cfg(test)]
mod tests {
    use work_kernel::id::PartyRef;

    use super::*;

    const KEY: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

    fn party(byte: u8) -> CallerParty {
        CallerParty {
            reference: PartyRef::new("AwMDAwMDAwMDAwMDAwMDAw").unwrap(),
            id: [byte; 16],
        }
    }

    // C-8 PR-9 C-35 P-54
    #[test]
    fn c_8_a_work_opens_from_the_caller_and_its_key_alone() {
        let first = opened_work(&party(3), KEY);
        assert_eq!(first, opened_work(&party(3), KEY));
        assert_ne!(first, opened_work(&party(4), KEY));
        assert_ne!(
            first,
            opened_work(&party(3), "01890a5d-ac96-774b-bcce-b302099a8058")
        );
        assert_ne!(first.as_bytes(), &[3; 16]);
    }

    // P-54
    #[test]
    fn p_54_the_opening_key_is_a_uuid_v7() {
        assert!(uuid_v7(KEY));
        assert!(uuid_v7("01890A5D-AC96-774B-BCCE-B302099A8057"));
        for bad in [
            "",
            "01890a5d-ac96-474b-bcce-b302099a8057",
            "01890a5d-ac96-774b-7cce-b302099a8057",
            "01890a5dac96774bbcceb302099a8057",
            "01890a5d-ac96-774b-bcce-b302099a805g",
            "01890a5d-ac96-774b-bcce-b302099a80577",
        ] {
            assert!(!uuid_v7(bad), "{bad}");
        }
    }
}
