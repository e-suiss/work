//! The `commitment_active` Claim Work hands Access when an obligor's commitment ends (E-8, E-12; Access §7.9.5.4, EI-5, L2-CLB-1, L2-CLM-5): an unsigned Claim over Work's PEP channel, whose issuer is Work's service Party, whose subject is the obligor, whose `value` is the body digest of `{commitment, active: false}` and whose body is disclosed beside it; Access then ends a Grant held while that commitment is active, and the Claim never starts one. It is issued at the ledger time of the record that ended the commitment, so the same end always gives the same Claim and handing it over again is answered as a replay.

use std::collections::BTreeMap;

use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::claim::{Channel, Statement, Unsigned};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::model::{EqValue, Id, Window};
use serde_json::{Value as Json, json};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::domain::AccessError;
use crate::domain::keys::{DomainId, KernelId};
use crate::domain::{b64url, from_b64url};

/// The Claim class of a coordinator's commitment state (Access OP-156 m.3 (b)).
pub const CLASS: &str = "commitment_active";

/// The end of one obligor's `commitment.active` as Work hands it to Access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    /// The governing domain of the tenant's realm.
    pub domain: DomainId,
    /// Work's service Party in that domain.
    pub issuer: KernelId,
    /// The obligor whose commitment ended.
    pub subject: KernelId,
    /// The commitment, by the digest of its `request`.
    pub commitment: [u8; 32],
    /// The ledger time of the record that ended it, Unix milliseconds.
    pub issued_at_ms: u64,
    /// The `x5t#S256` of Work's PEP certificate, the channel the Claim comes over.
    pub pep: [u8; 32],
}

/// The `commitment-active` body (Access CDDL `product-seam.cddl`).
#[must_use]
pub fn body(commitment: &[u8; 32], active: bool) -> Value {
    Value::Map(vec![
        (Value::text("active"), Value::Bool(active)),
        (Value::text("commitment"), Value::Bytes(commitment.to_vec())),
    ])
}

/// The `value` of a `commitment_active` Claim with `body(commitment, active)` (L2-CLB-1):
/// `SHA-256("access/claim-body/v1" ‖ 0x00 ‖ dCBOR(["commitment_active", body]))`.
///
/// # Errors
/// [`AccessError::Answer`] when the body cannot be encoded.
pub fn value_digest(commitment: &[u8; 32], active: bool) -> Result<[u8; 32], AccessError> {
    let tagged = dcbor::encode(
        &Value::Array(vec![Value::text(CLASS), body(commitment, active)]),
        Limits::CEILING,
    )
    .map_err(|_| AccessError::Answer("claim-body"))?;
    Ok(context_digest(BODY_CONTEXT, &tagged).0)
}

/// The unsigned Claim of `ended` (CDDL `unsigned-claim`).
///
/// # Errors
/// [`AccessError::Answer`] when it cannot be encoded.
pub fn claim_bytes(ended: &Ended) -> Result<Vec<u8>, AccessError> {
    let unsigned = Unsigned {
        statement: Statement {
            domain: Digest(ended.domain.0),
            issuer: Id(ended.issuer.0),
            subject: Id(ended.subject.0),
            class: CLASS.to_owned(),
            value: Some(EqValue::Bytes(
                value_digest(&ended.commitment, false)?.to_vec(),
            )),
            issued_at: ended.issued_at_ms,
            validity: Window {
                from: ended.issued_at_ms,
                until: u64::MAX,
            },
            assurance: BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        channel: Channel::Pep(ended.pep),
    };
    unsigned
        .to_bytes()
        .map_err(|_| AccessError::Answer("claim-payload"))
}

/// The `ClaimSubmission` body of `ended`: the unsigned Claim with its disclosed body.
///
/// # Errors
/// [`AccessError::Answer`] when it cannot be encoded.
pub fn submission(ended: &Ended) -> Result<Vec<u8>, AccessError> {
    let disclosed = dcbor::encode(&body(&ended.commitment, false), Limits::CEILING)
        .map_err(|_| AccessError::Answer("claim-body"))?;
    let doc = json!({
        "domain": format!("sha-256:{}", b64url(&ended.domain.0)),
        "carrier": "unsigned",
        "claim": b64url(&claim_bytes(ended)?),
        "body": b64url(&disclosed),
    });
    serde_json::to_vec(&doc).map_err(|_| AccessError::Answer("claim-submission"))
}

/// What Access did with a Claim (its `ClaimVerdict`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Admitted at `position`; `replayed` for a Claim admitted before.
    Admitted {
        /// The Claim, its `ClaimID`.
        claim: [u8; 16],
        /// The domain log position.
        position: u64,
        /// True for the same Claim handed over again.
        replayed: bool,
    },
    /// Held at `position` for `reason`, such as `source-not-accepted` while the domain does
    /// not accept Work as an issuer of the class.
    Quarantined {
        /// The Claim, its `ClaimID`.
        claim: [u8; 16],
        /// The domain log position.
        position: u64,
        /// Why.
        reason: String,
    },
}

impl Verdict {
    /// Reads Access's answer.
    ///
    /// # Errors
    /// [`AccessError::Answer`] for an answer outside the contract.
    pub fn from_json(body: &[u8]) -> Result<Self, AccessError> {
        let bad = || AccessError::Answer("claim-verdict");
        let v: Json = serde_json::from_slice(body).map_err(|_| bad())?;
        let claim = v
            .get("claim")
            .and_then(Json::as_str)
            .and_then(|c| from_b64url(c).ok())
            .and_then(|c| <[u8; 16]>::try_from(c).ok())
            .ok_or_else(bad)?;
        let position = v
            .get("position")
            .and_then(Json::as_str)
            .and_then(|p| p.parse().ok())
            .ok_or_else(bad)?;
        match v.get("disposition").and_then(Json::as_str) {
            Some("admit") => Ok(Self::Admitted {
                claim,
                position,
                replayed: v.get("replayed").and_then(Json::as_bool).unwrap_or(false),
            }),
            Some("quarantine") => Ok(Self::Quarantined {
                claim,
                position,
                reason: v
                    .get("reason")
                    .and_then(Json::as_str)
                    .ok_or_else(bad)?
                    .to_owned(),
            }),
            _ => Err(bad()),
        }
    }
}

#[cfg(test)]
mod tests {
    use access_kernel::claim::unsigned;

    use super::*;

    fn ended() -> Ended {
        Ended {
            domain: DomainId([1; 32]),
            issuer: KernelId([2; 16]),
            subject: KernelId([3; 16]),
            commitment: [4; 32],
            issued_at_ms: 1_792_749_600_123,
            pep: [5; 32],
        }
    }

    // E-12 E-8
    #[test]
    fn e_12_the_end_of_a_commitment_reads_back_as_an_unsigned_false_claim_over_work_s_pep() {
        let bytes = claim_bytes(&ended()).unwrap();
        let read = unsigned(&bytes, &Digest([1; 32]), &Channel::Pep([5; 32])).unwrap();
        let s = &read.statement;
        assert_eq!(s.class, CLASS);
        assert_eq!(s.issuer, Id([2; 16]));
        assert_eq!(s.subject, Id([3; 16]));
        assert_eq!(s.issued_at, 1_792_749_600_123);
        let ended_value = value_digest(&[4; 32], false).unwrap();
        assert_eq!(s.value, Some(EqValue::Bytes(ended_value.to_vec())));
        assert_ne!(ended_value, value_digest(&[4; 32], true).unwrap());
        assert!(unsigned(&bytes, &Digest([1; 32]), &Channel::Pep([6; 32])).is_err());
        assert_eq!(claim_bytes(&ended()).unwrap(), bytes);
        let sent: Json = serde_json::from_slice(&submission(&ended()).unwrap()).unwrap();
        assert_eq!(sent["carrier"], "unsigned");
        assert_eq!(sent["claim"], b64url(&bytes));
        let disclosed = from_b64url(sent["body"].as_str().unwrap()).unwrap();
        assert_eq!(
            dcbor::decode(&disclosed, Limits::CEILING).unwrap(),
            body(&[4; 32], false)
        );
        let held = br#"{"claim":"AQEBAQEBAQEBAQEBAQEBAQ","position":"9","disposition":"quarantine","reason":"source-not-accepted"}"#;
        assert_eq!(
            Verdict::from_json(held).unwrap(),
            Verdict::Quarantined {
                claim: [1; 16],
                position: 9,
                reason: "source-not-accepted".to_owned(),
            }
        );
        assert!(Verdict::from_json(br#"{"disposition":"admit"}"#).is_err());
    }
}
