//! Verification results that state only "the author signature is valid" and "present in the ledger at this position", never truth or authorisation (SEC-5, P-22); signature checking is a port the shared crypto crate fills (P-8, [`crate::cose::AuthorKeys`]).

use crate::id::{LedgerId, PartyRef, RecordId, Time};
use crate::reason::Reason;
use crate::validate::ActorType;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::Digest;
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
