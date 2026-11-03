use sha2::{Digest as _, Sha256};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::{Digest, leaf_hash};
use work_store::{Durability, Genesis, LedgerId};

use crate::LedgerError;
use crate::ports::{Rng, RngError, bytes32};

/// What a ledger opens with (P-100 item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisInput {
    /// The sequencer's trusted time, Unix milliseconds (P-27).
    pub recorded_at_ms: u64,
    /// `versions.protocol` as `[major, minor]` (P-18).
    pub protocol: (u64, u64),
    /// `versions.schema`: the SHA-256 of the protocol's normative CDDL bytes (P-100 item 7).
    pub schema: [u8; 32],
    /// 32 bytes from the `Rng` port (T-32 rule 2).
    pub nonce: [u8; 32],
}

impl GenesisInput {
    /// The input of a new ledger with a fresh nonce from `rng` (P-100 item 2, T-32 rule 2).
    ///
    /// # Errors
    /// [`RngError`]; no ledger opens without a nonce.
    pub fn fresh(
        rng: &(impl Rng + ?Sized),
        recorded_at_ms: u64,
        protocol: (u64, u64),
        schema: [u8; 32],
    ) -> Result<Self, RngError> {
        Ok(Self {
            recorded_at_ms,
            protocol,
            schema,
            nonce: bytes32(rng)?,
        })
    }
}

/// The genesis record for `input` (P-100): its det-CBOR bytes, the `LedgerID` as their unprefixed
/// SHA-256 and the leaf hash with prefix `0x00` (P-101).
///
/// # Errors
/// [`LedgerError::Encode`].
pub fn genesis(input: &GenesisInput, durability: Durability) -> Result<Genesis, LedgerError> {
    let versions = Value::Map(vec![
        (
            Value::text("protocol"),
            Value::Array(vec![
                Value::Unsigned(input.protocol.0),
                Value::Unsigned(input.protocol.1),
            ]),
        ),
        (Value::text("schema"), Digest(input.schema).to_value()),
    ]);
    let envelope = Value::Map(vec![
        (Value::text("pos"), Value::Unsigned(0)),
        (
            Value::text("recorded_at"),
            Value::Unsigned(input.recorded_at_ms),
        ),
        (Value::text("versions"), versions),
        (Value::text("nonce"), Value::Bytes(input.nonce.to_vec())),
    ]);
    let bytes = dcbor::encode(&envelope, Limits::CEILING)?;
    let ledger = LedgerId::from_bytes(Sha256::digest(&bytes).into());
    Ok(Genesis {
        ledger,
        recorded_at_ms: input.recorded_at_ms,
        leaf: leaf_hash(&bytes),
        bytes,
        durability,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    const GENESIS: &str = include_str!("../../../conformance/vectors/records/genesis.json");

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn bytes32(v: &serde_json::Value) -> [u8; 32] {
        <[u8; 32]>::try_from(hex(v.as_str().unwrap()).as_slice()).unwrap()
    }

    // P-100 P-101 P-67 Access CR-1
    #[test]
    fn p_100_genesis_matches_the_golden_vector() {
        let file: serde_json::Value = serde_json::from_str(GENESIS).unwrap();
        let case = &file["cases"][0];
        assert_eq!(case["id"], "genesis/accept");
        let d = &case["decoded"];
        let input = GenesisInput {
            recorded_at_ms: d["recorded_at"].as_u64().unwrap(),
            protocol: (
                d["versions"]["protocol"][0].as_u64().unwrap(),
                d["versions"]["protocol"][1].as_u64().unwrap(),
            ),
            schema: bytes32(&d["versions"]["schema"][1]),
            nonce: bytes32(&d["nonce"]),
        };
        let g = genesis(&input, Durability::SingleNode).unwrap();
        assert_eq!(g.bytes, hex(case["hex"].as_str().unwrap()));
        assert_eq!(
            g.ledger.as_bytes(),
            &bytes32(&case["ledger_id"]["digest_hex"])
        );
        assert_eq!(g.leaf, bytes32(&case["leaf_hash"]));
    }

    #[derive(Debug)]
    struct Empty;

    impl Rng for Empty {
        fn fill(&self, _out: &mut [u8]) -> Result<(), RngError> {
            Err(RngError)
        }
    }

    // P-100 T-32
    #[test]
    fn p_100_every_new_ledger_takes_a_fresh_nonce_from_the_rng_port() {
        let rng = crate::adapters::SeededRng::new([5; 32]);
        let first = GenesisInput::fresh(&rng, 1_000, (1, 0), [9; 32]).unwrap();
        let second = GenesisInput::fresh(&rng, 1_000, (1, 0), [9; 32]).unwrap();
        assert_ne!(first.nonce, second.nonce);
        let a = genesis(&first, Durability::SingleNode).unwrap();
        let b = genesis(&second, Durability::SingleNode).unwrap();
        assert_ne!(a.ledger, b.ledger);
        assert_eq!(
            GenesisInput::fresh(&Empty, 1_000, (1, 0), [9; 32]),
            Err(RngError)
        );
    }
}
