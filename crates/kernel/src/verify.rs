//! Verification results that state only "the author signature is valid" and "present in the ledger at this position", never truth or authorisation (SEC-5, P-22); signature checking is a port the shared crypto crate fills (P-8, [`crate::cose::AuthorKeys`]), and a stored ledger entry is verified from its bytes alone: the record ID, envelope binding and author binding are recomputed, never taken from the caller (T-10, P-11, P-75, P-79).

use crate::codec::{Decoded, decode_record, leaf_hash, ledger_id, proof_commit, record_id};
use crate::envelope::{Envelope, EnvelopeIngest, LedgerEnvelope, decode_envelope};
use crate::id::{Digest, LedgerId, PartyRef, RecordId, Time};
use crate::reason::{EnvelopeField, Reason, Schema};
use crate::validate::{ActorType, actor_rings};

/// How the author is bound to the record (P-20, P-21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorBinding {
    /// A `COSE_Sign1` author signature verified over the record bytes.
    SignatureValid,
    /// An unsigned human record admitted with an Access authentication context reference; not an author signature (P-21 item 3).
    AuthContext,
}

/// Where the ledger placed the record (P-11, P-27).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerInclusion {
    /// The ledger.
    pub ledger: LedgerId,
    /// The position in the ledger.
    pub position: u64,
    /// The trusted record time.
    pub recorded_at: Time,
}

/// What verification establishes; no field means "true" or "authorised" (SEC-5, P-22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    /// The record identifier.
    pub record: RecordId,
    /// The Party the record is attributed to.
    pub author: PartyRef,
    /// How the author is bound.
    pub binding: AuthorBinding,
    /// Ledger inclusion, when known.
    pub inclusion: Option<LedgerInclusion>,
}

/// The result of checking one `COSE_Sign1` author signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    /// The signature verifies under a key Access binds to `author`; `record` is the payload digest.
    Valid {
        /// The payload digest.
        record: RecordId,
        /// The signing Party.
        author: PartyRef,
    },
    /// The signature or its container is rejected: a `signature:*`, `schema:container` or CBOR reason (P-6, P-7).
    Rejected(Reason),
}

/// The signature port: implemented over the shared crypto crate's `no_std` verification (P-8, T-64); the kernel holds no second implementation.
pub trait SignatureVerifier {
    /// Checks the `COSE_Sign1` bytes exactly as received.
    fn check(&self, cose_sign1: &[u8]) -> SignatureCheck;
}

/// The verification decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Verification succeeded with this scope.
    Verified(Verification),
    /// Verification failed, with a reason.
    Rejected(Reason),
}

/// Verifies a signed record through the signature port.
pub fn verify_signed<V: SignatureVerifier + ?Sized>(
    verifier: &V,
    cose_sign1: &[u8],
    inclusion: Option<LedgerInclusion>,
) -> VerifyOutcome {
    match verifier.check(cose_sign1) {
        SignatureCheck::Valid { record, author } => VerifyOutcome::Verified(Verification {
            record,
            author,
            binding: AuthorBinding::SignatureValid,
            inclusion,
        }),
        SignatureCheck::Rejected(reason) => VerifyOutcome::Rejected(reason),
    }
}

/// Inputs for a record that arrived without a `COSE_Sign1` signature (P-21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedRecord {
    /// The record identifier ([`crate::codec::record_id`], P-79).
    pub record: RecordId,
    /// The author.
    pub author: PartyRef,
    /// The author's actor type from Access.
    pub actor_type: ActorType,
    /// Whether the record carries an Access authentication context reference.
    pub auth_context: bool,
}

/// Verifies an unsigned record: only a human author with an authentication context may be unsigned (P-21 items 2, 3).
#[must_use]
pub fn verify_unsigned(input: UnsignedRecord, inclusion: Option<LedgerInclusion>) -> VerifyOutcome {
    if input.actor_type != ActorType::Human {
        return VerifyOutcome::Rejected(Reason::AuthorSignatureMissing);
    }
    if !input.auth_context {
        return VerifyOutcome::Rejected(Reason::AuthContextMissing);
    }
    VerifyOutcome::Verified(Verification {
        record: input.record,
        author: input.author,
        binding: AuthorBinding::AuthContext,
        inclusion,
    })
}

/// One ledger entry as the log stores it: the envelope bytes, the `SignedRecord` bytes and, for a signed record, the `COSE_Sign1` bytes as received (P-5 item 4, P-11, P-75).
#[derive(Clone, Copy, Debug)]
pub struct StoredEntry<'a> {
    /// The `LedgerEnvelope` bytes.
    pub envelope: &'a [u8],
    /// The `SignedRecord` bytes.
    pub record: &'a [u8],
    /// The `COSE_Sign1` bytes, for a signed record.
    pub cose_sign1: Option<&'a [u8]>,
}

/// Where the next entry must continue the chain: the ledger and the leaf hash of the previous envelope (P-11, P-100).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainPoint {
    /// The ledger.
    pub ledger: LedgerId,
    /// The leaf hash of the previous envelope.
    pub prev: Digest,
}

impl ChainPoint {
    /// The chain point after the genesis bytes: their digest is the `LedgerID` and their leaf hash the first `prev` (P-100).
    ///
    /// # Errors
    ///
    /// A CBOR or schema reason of the genesis, or `schema:unknown_core_field` for an envelope at a position above 0.
    pub fn genesis(bytes: &[u8]) -> Result<Self, Reason> {
        match decode_envelope(bytes)? {
            Envelope::Genesis(_) => Ok(Self {
                ledger: ledger_id(bytes),
                prev: leaf_hash(bytes),
            }),
            Envelope::Ledger(_) => Err(Reason::Schema(Schema::UnknownCoreField)),
        }
    }
}

/// A stored ledger entry the kernel verified from its bytes (T-10, P-11, P-79): nothing in it comes from the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEntry {
    verification: Verification,
    envelope: LedgerEnvelope,
    record: Decoded,
    leaf: Digest,
}

impl VerifiedEntry {
    /// What verification establishes; the record ID is the digest of the stored record bytes.
    #[must_use]
    pub const fn verification(&self) -> &Verification {
        &self.verification
    }

    /// The decoded envelope.
    #[must_use]
    pub const fn envelope(&self) -> &LedgerEnvelope {
        &self.envelope
    }

    /// The decoded record.
    #[must_use]
    pub const fn record(&self) -> &Decoded {
        &self.record
    }

    /// The leaf hash of the envelope (P-101).
    #[must_use]
    pub const fn leaf(&self) -> Digest {
        self.leaf
    }

    /// The chain point the next entry continues.
    #[must_use]
    pub const fn next(&self) -> ChainPoint {
        ChainPoint {
            ledger: self.envelope.ledger,
            prev: self.leaf,
        }
    }
}

const fn mismatch(field: EnvelopeField) -> Reason {
    Reason::EnvelopeMismatch(field)
}

/// Verifies one stored ledger entry after `at`: the envelope names the ledger and the previous leaf, its `record` is the digest of the stored record bytes, a signed record's `proof_commit` is the digest of the `COSE_Sign1` bytes and its signature, through the port, covers exactly those record bytes, an unsigned record is a human record with an authentication context, and the `actor_type` annotation of an admitted or quarantined record of a known protocol has one entry per `on_behalf_of` ring and per evidence presenter (P-11, P-12, P-21, P-75, P-79, P-100, T-10, EV-35).
///
/// # Errors
///
/// `envelope_mismatch:ledger`, `envelope_mismatch:prev` (also for a genesis in place of an envelope), `envelope_mismatch:record`, `envelope_mismatch:proof_commit`, a decoding reason of the envelope or record, the port's rejection, a reason of [`verify_unsigned`], `protocol_version_unknown` for an unsigned record whose author cannot be read, or `envelope_mismatch:actor_type`.
pub fn verify_entry<V: SignatureVerifier + ?Sized>(
    verifier: &V,
    at: &ChainPoint,
    entry: &StoredEntry<'_>,
) -> Result<VerifiedEntry, Reason> {
    let Envelope::Ledger(envelope) = decode_envelope(entry.envelope)? else {
        return Err(mismatch(EnvelopeField::Prev));
    };
    if envelope.ledger != at.ledger {
        return Err(mismatch(EnvelopeField::Ledger));
    }
    if envelope.prev != at.prev {
        return Err(mismatch(EnvelopeField::Prev));
    }
    let id = record_id(entry.record);
    if envelope.record != id {
        return Err(mismatch(EnvelopeField::Record));
    }
    let record = decode_record(entry.record)?;
    let inclusion = Some(LedgerInclusion {
        ledger: envelope.ledger,
        position: envelope.position,
        recorded_at: envelope.recorded_at,
    });
    let verification = if let Some(cose_sign1) = entry.cose_sign1 {
        if envelope.proof_commit != Some(proof_commit(cose_sign1)) {
            return Err(mismatch(EnvelopeField::ProofCommit));
        }
        match verifier.check(cose_sign1) {
            SignatureCheck::Valid { record: signed, .. } if signed != id => {
                return Err(mismatch(EnvelopeField::Record));
            }
            SignatureCheck::Valid { author, .. } => Verification {
                record: id,
                author,
                binding: AuthorBinding::SignatureValid,
                inclusion,
            },
            SignatureCheck::Rejected(reason) => return Err(reason),
        }
    } else {
        if envelope.proof_commit.is_some() {
            return Err(mismatch(EnvelopeField::ProofCommit));
        }
        let Decoded::Record(decoded) = &record else {
            return Err(Reason::ProtocolVersionUnknown);
        };
        let input = UnsignedRecord {
            record: id,
            author: decoded.core().author.clone(),
            actor_type: envelope.actor_types.author.actor_type,
            auth_context: envelope.auth_context.is_some(),
        };
        match verify_unsigned(input, inclusion) {
            VerifyOutcome::Verified(verification) => verification,
            VerifyOutcome::Rejected(reason) => return Err(reason),
        }
    };
    if let Decoded::Record(decoded) = &record
        && !matches!(envelope.ingest, EnvelopeIngest::Rejected(_))
    {
        actor_rings(decoded.core(), &envelope.actor_types)?;
    }
    Ok(VerifiedEntry {
        verification,
        leaf: leaf_hash(entry.envelope),
        envelope,
        record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reason::Signature;

    struct Port(SignatureCheck);

    impl SignatureVerifier for Port {
        fn check(&self, _cose_sign1: &[u8]) -> SignatureCheck {
            self.0.clone()
        }
    }

    fn rid() -> RecordId {
        RecordId(Digest::sha256([9; 32]))
    }

    fn alice() -> PartyRef {
        PartyRef::new("party:acme:alice").unwrap()
    }

    fn inclusion() -> LedgerInclusion {
        LedgerInclusion {
            ledger: LedgerId(Digest::sha256([1; 32])),
            position: 41,
            recorded_at: Time(1_792_109_100_000),
        }
    }

    // SEC-5 P-22
    #[test]
    fn sec_5_p_22_verification_states_only_authorship_and_inclusion() {
        let port = Port(SignatureCheck::Valid {
            record: rid(),
            author: alice(),
        });
        let VerifyOutcome::Verified(v) = verify_signed(&port, &[], Some(inclusion())) else {
            panic!("expected verified");
        };
        let Verification {
            record,
            author,
            binding,
            inclusion: placed,
        } = v;
        assert_eq!(record, rid());
        assert_eq!(author, alice());
        assert_eq!(binding, AuthorBinding::SignatureValid);
        assert_eq!(placed, Some(inclusion()));
    }

    // P-6 P-7
    #[test]
    fn p_6_rejected_signature_carries_its_detail() {
        let reason = Reason::Signature(Signature::HighS);
        let port = Port(SignatureCheck::Rejected(reason));
        assert_eq!(
            verify_signed(&port, &[], None),
            VerifyOutcome::Rejected(reason)
        );
    }

    // P-21
    #[test]
    fn p_21_only_humans_with_auth_context_may_be_unsigned() {
        let base = UnsignedRecord {
            record: rid(),
            author: alice(),
            actor_type: ActorType::Human,
            auth_context: true,
        };
        assert!(matches!(
            verify_unsigned(base.clone(), None),
            VerifyOutcome::Verified(Verification {
                binding: AuthorBinding::AuthContext,
                ..
            })
        ));
        let agent = UnsignedRecord {
            actor_type: ActorType::Agent,
            ..base.clone()
        };
        assert_eq!(
            verify_unsigned(agent, None),
            VerifyOutcome::Rejected(Reason::AuthorSignatureMissing)
        );
        let without_context = UnsignedRecord {
            auth_context: false,
            ..base
        };
        assert_eq!(
            verify_unsigned(without_context, None),
            VerifyOutcome::Rejected(Reason::AuthContextMissing)
        );
    }
}
