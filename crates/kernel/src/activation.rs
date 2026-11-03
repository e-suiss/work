//! The protocol version activations of a ledger (P-110, P-87, OP-28 items 2, 3): the genesis is the first and every later one is an `ActivationEnvelope`; each activates a version above the previous one, a version this kernel knows carries its own schema digest, and the active version of a position is the one the last earlier activation turned on.

use alloc::vec::Vec;

use crate::codec::ledger_id;
use crate::envelope::{Envelope, decode_envelope};
use crate::id::Digest;
use crate::reason::{EnvelopeField, Reason};
use crate::record::ProtocolVersion;
use crate::rules::RuleSet;

/// One activation entry of a ledger: where it is and the version it turns on (P-110).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activation {
    /// The log position; 0 for the genesis.
    pub position: u64,
    /// The activated protocol version.
    pub protocol: ProtocolVersion,
    /// The digest of the activated version's normative CDDL bytes.
    pub schema: Digest,
}

const BROKEN: Reason = Reason::EnvelopeMismatch(EnvelopeField::Activation);

fn schema_matches(a: &Activation) -> bool {
    RuleSet::for_version(a.protocol).is_none_or(|set| set.schema() == a.schema)
}

/// Checks the activation entries of one ledger, given as their envelope bytes in log order with the genesis first, and returns them (P-110 item 8, P-100): every later entry is an `ActivationEnvelope` of the genesis's ledger at a higher position, each activated version is above the previous one (major, then minor) and a version this kernel carries a rule set for has that version's schema digest; a version it does not know passes the sequence rule, since its schema cannot be checked. The sequencer, the rebuild and the bindings use this one function.
///
/// # Errors
///
/// A decoding reason of an entry, `envelope_mismatch:ledger` for an activation of another ledger, or `envelope_mismatch:activation` for an empty list, a first entry that is not a genesis, a later one that is not an activation, a position or version that does not rise, or a known version with another schema.
pub fn check_activations(entries: &[&[u8]]) -> Result<Vec<Activation>, Reason> {
    let (first, rest) = entries.split_first().ok_or(BROKEN)?;
    let Envelope::Genesis(genesis) = decode_envelope(first)? else {
        return Err(BROKEN);
    };
    let ledger = ledger_id(first);
    let mut out: Vec<Activation> = Vec::with_capacity(entries.len());
    let opening = Activation {
        position: 0,
        protocol: genesis.versions.protocol,
        schema: genesis.versions.schema,
    };
    if !schema_matches(&opening) {
        return Err(BROKEN);
    }
    out.push(opening);
    for bytes in rest {
        let Envelope::Activation(a) = decode_envelope(bytes)? else {
            return Err(BROKEN);
        };
        if a.ledger != ledger {
            return Err(Reason::EnvelopeMismatch(EnvelopeField::Ledger));
        }
        let next = Activation {
            position: a.position,
            protocol: a.activation.protocol,
            schema: a.activation.schema,
        };
        let rises = out
            .last()
            .is_some_and(|p| next.position > p.position && next.protocol > p.protocol);
        if !rises || !schema_matches(&next) {
            return Err(BROKEN);
        }
        out.push(next);
    }
    Ok(out)
}

/// The active protocol version of the record at `position`: the version of the last activation at a lower position, the genesis being the first; `None` when no activation precedes it (P-110 item 8, P-87 item 3).
#[must_use]
pub fn active_version(
    activations: &[(u64, ProtocolVersion)],
    position: u64,
) -> Option<ProtocolVersion> {
    activations
        .iter()
        .filter(|(at, _)| *at < position)
        .max_by_key(|(at, _)| *at)
        .map(|(_, version)| *version)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use suiss_crypto::dcbor::{self, Limits, Value};

    use super::*;
    use crate::codec::leaf_hash;
    use crate::id::canonical_text_cmp;

    const V0_9: ProtocolVersion = ProtocolVersion { major: 0, minor: 9 };
    const V1_0: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };
    const V1_1: ProtocolVersion = ProtocolVersion { major: 1, minor: 1 };
    const V1_2: ProtocolVersion = ProtocolVersion { major: 1, minor: 2 };
    const V2_0: ProtocolVersion = ProtocolVersion { major: 2, minor: 0 };
    const OTHER: Digest = Digest::sha256([5; 32]);

    fn digest(d: &Digest) -> Value {
        Value::Array(vec![Value::int(-16), Value::Bytes(d.as_bytes().to_vec())])
    }

    fn version(v: ProtocolVersion) -> Value {
        Value::Array(vec![Value::Unsigned(v.major), Value::Unsigned(v.minor)])
    }

    fn map(mut entries: Vec<(&str, Value)>) -> Value {
        entries.sort_by(|a, b| canonical_text_cmp(a.0, b.0));
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::text(k), v))
                .collect(),
        )
    }

    fn encode(v: &Value) -> Vec<u8> {
        dcbor::encode(v, Limits::CEILING).unwrap_or_default()
    }

    fn genesis(protocol: ProtocolVersion, schema: Digest) -> Vec<u8> {
        let versions = map(vec![
            ("protocol", version(protocol)),
            ("schema", digest(&schema)),
        ]);
        encode(&map(vec![
            ("pos", Value::Unsigned(0)),
            ("recorded_at", Value::Unsigned(1_000)),
            ("versions", versions),
            ("nonce", Value::Bytes(vec![9; 32])),
        ]))
    }

    fn activating(
        genesis: &[u8],
        position: u64,
        protocol: ProtocolVersion,
        schema: Digest,
    ) -> Vec<u8> {
        let context = map(vec![
            ("ref", digest(&Digest::sha256([4; 32]))),
            ("assurance", Value::text("aal2")),
            ("step_up", Value::Bool(true)),
        ]);
        let activated = map(vec![
            ("protocol", version(protocol)),
            ("schema", digest(&schema)),
        ]);
        encode(&map(vec![
            ("activation", activated),
            ("ledger", digest(&ledger_id(genesis).0)),
            ("pos", Value::Unsigned(position)),
            ("prev", digest(&leaf_hash(genesis))),
            ("recorded_at", Value::Unsigned(2_000)),
            ("auth_context", context),
        ]))
    }

    fn check(entries: &[&Vec<u8>]) -> Result<Vec<(u64, ProtocolVersion)>, Reason> {
        let slices: Vec<&[u8]> = entries.iter().copied().map(Vec::as_slice).collect();
        check_activations(&slices)
            .map(|a| a.iter().map(|x| (x.position, x.protocol)).collect())
    }

    // P-110 P-100 OP-28
    #[test]
    fn p_110_activations_rise_from_the_genesis_with_their_own_schema() {
        let g = genesis(V1_0, RuleSet::V1_0.schema());
        let up = activating(&g, 3, V1_1, RuleSet::TestV1_1.schema());
        assert_eq!(check(&[&g, &up]), Ok(vec![(0, V1_0), (3, V1_1)]));
        let unknown = activating(&g, 3, V2_0, OTHER);
        assert_eq!(check(&[&g, &unknown]), Ok(vec![(0, V1_0), (3, V2_0)]));
        let later = genesis(V1_1, RuleSet::TestV1_1.schema());
        assert_eq!(check(&[&later]), Ok(vec![(0, V1_1)]));
    }

    // P-110
    #[test]
    fn p_110_a_version_that_does_not_rise_or_a_wrong_schema_breaks_the_sequence() {
        let g = genesis(V1_0, RuleSet::V1_0.schema());
        let same = activating(&g, 3, V1_0, RuleSet::V1_0.schema());
        let older = activating(&g, 3, V0_9, OTHER);
        let wrong = activating(&g, 3, V1_1, RuleSet::V1_0.schema());
        let up = activating(&g, 3, V1_1, RuleSet::TestV1_1.schema());
        let back = activating(&g, 2, V1_2, OTHER);
        for entries in [
            vec![&g, &same],
            vec![&g, &older],
            vec![&g, &wrong],
            vec![&g, &up, &back],
            vec![],
            vec![&up],
            vec![&g, &g],
        ] {
            assert_eq!(check(&entries), Err(BROKEN));
        }
        let wrong_genesis = genesis(V1_0, OTHER);
        assert_eq!(check(&[&wrong_genesis]), Err(BROKEN));
        let other = genesis(V1_1, RuleSet::TestV1_1.schema());
        let foreign = activating(&other, 3, V1_2, OTHER);
        assert_eq!(
            check(&[&g, &foreign]),
            Err(Reason::EnvelopeMismatch(EnvelopeField::Ledger))
        );
    }

    // P-110 P-87
    #[test]
    fn p_110_the_active_version_of_a_position_is_the_last_earlier_activation() {
        let list = [(0, V1_0), (5, V1_1)];
        assert_eq!(active_version(&list, 1), Some(V1_0));
        assert_eq!(active_version(&list, 5), Some(V1_0));
        assert_eq!(active_version(&list, 6), Some(V1_1));
        assert_eq!(active_version(&list, 0), None);
        assert_eq!(active_version(&[], 3), None);
    }
}
