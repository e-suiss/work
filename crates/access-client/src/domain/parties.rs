//! Party status lookup (Access OP-149 m.28 (c), `party-lookup.cddl`; Work WD-124 item 3): the batch request and the canonical `COSE_Sign1` answer verified under the domain's operational key with usage `party-lookup`, as the key lookup is, and checked entry by entry; each entry names the actor kind its Party's `party_register` recorded, which a record's `on_behalf_of` principals and evidence presenters are bound to (P-12, MD-7 item 3).

use std::collections::BTreeSet;
use std::sync::Arc;

use suiss_crypto::cose;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::Digest;
use suiss_crypto::sig::PureBackend;

use crate::domain::AccessError;
use crate::domain::keys::{
    ActorKind, AsOf, DomainId, Evidence, KernelId, LedgerPoint, bytes, iat_of, payload_error,
    point, uint,
};
use crate::domain::metadata::{
    DomainMetadata, Fields, KeyScopeError, KeyUsage, operational_key, unverified_payload,
};

/// Content type of the signed Party lookup payload.
pub const PARTY_CONTENT_TYPE: &str = "application/access-party-lookup+cbor";

/// Most Parties one batch asks for (Access OP-149 m.28 (c)).
pub const MAX_PARTIES: usize = 100;

/// The stable code of a single lookup's `404` for a Party not admitted at the position.
pub const PARTY_UNKNOWN: &str = "party-unknown";

/// One Party as the answer states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartyEntry {
    /// The Party.
    pub party: KernelId,
    /// What its `party_register` recorded.
    pub actor_kind: ActorKind,
    /// The record that admitted it.
    pub since: LedgerPoint,
    /// The record that ended it, once it has.
    pub ended: Option<LedgerPoint>,
}

/// A verified Party lookup answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyAnswer {
    /// The domain.
    pub domain: DomainId,
    /// The ledger position it was read at.
    pub pos: u64,
    /// Trusted time of the answer.
    pub iat: u64,
    /// The Parties admitted at `pos`.
    pub parties: Vec<PartyEntry>,
    /// The Parties not admitted at `pos`.
    pub unknown: Vec<KernelId>,
    /// The bytes it was verified from.
    pub evidence: Arc<Evidence>,
}

fn answer(code: &'static str) -> AccessError {
    AccessError::Answer(code)
}

fn metadata_error(e: KeyScopeError) -> AccessError {
    AccessError::Metadata(e.code())
}

/// The `POST parties:batchGet` body: the domain, the Parties without duplicates, `as_of`.
///
/// # Errors
/// [`AccessError::Answer`] for zero, more than [`MAX_PARTIES`] or repeated Parties.
pub fn batch_body(
    domain: &DomainId,
    parties: &[KernelId],
    as_of: &AsOf,
) -> Result<Vec<u8>, AccessError> {
    let unique: BTreeSet<&KernelId> = parties.iter().collect();
    if parties.is_empty() || parties.len() > MAX_PARTIES || unique.len() != parties.len() {
        return Err(answer("parties"));
    }
    let mut body = serde_json::json!({
        "domain": domain.text(),
        "parties": parties.iter().map(KernelId::text).collect::<Vec<_>>(),
    });
    if let (Some(t), serde_json::Value::Object(m)) = (as_of.text(), &mut body) {
        m.insert("as_of".to_owned(), t.into());
    }
    serde_json::to_vec(&body).map_err(|_| answer("parties"))
}

/// Verifies a `COSE_Sign1` Party lookup answer for `asked` in `domain`: the excerpt binds its
/// key to `metadata` with usage `party-lookup` at the answer's `iat`, the signature verifies,
/// the `ETag` is its position, it answers exactly the Parties asked, and every entry is
/// consistent.
///
/// # Errors
/// [`AccessError::Metadata`] or [`AccessError::Answer`].
pub fn verify_answer(
    metadata: &DomainMetadata,
    domain: &DomainId,
    asked: &[KernelId],
    sign1: &[u8],
    excerpt: &[u8],
    etag: Option<u64>,
) -> Result<PartyAnswer, AccessError> {
    let iat = iat_of(&unverified_payload(sign1).map_err(metadata_error)?)?;
    let key = operational_key(metadata, &domain.0, excerpt, KeyUsage::PartyLookup, iat)
        .map_err(metadata_error)?;
    let verified = cose::verify_sign1(&PureBackend, sign1, &key.key_set(), PARTY_CONTENT_TYPE)
        .map_err(|e| metadata_error(KeyScopeError::Signature(e)))?;
    let evidence = Arc::new(Evidence {
        sign1: sign1.to_vec(),
        excerpt: excerpt.to_vec(),
    });
    let out = decode_lookup(&verified.payload, evidence)?;
    if out.domain != *domain {
        return Err(answer("domain"));
    }
    if etag != Some(out.pos) {
        return Err(answer("etag"));
    }
    let mut seen = BTreeSet::new();
    for party in out.parties.iter().map(|p| &p.party).chain(&out.unknown) {
        if !seen.insert(*party) {
            return Err(answer("parties"));
        }
    }
    if seen != asked.iter().copied().collect::<BTreeSet<_>>() {
        return Err(answer("parties"));
    }
    for p in &out.parties {
        let ordered = p.since.pos <= out.pos
            && p.ended
                .is_none_or(|e| e.pos <= out.pos && e.pos >= p.since.pos);
        if !ordered {
            return Err(answer("party_state"));
        }
    }
    Ok(out)
}

fn entry(v: &Value) -> Result<PartyEntry, AccessError> {
    let f = Fields::of(v).map_err(payload_error)?;
    let req = |name: &str| f.req(name).map_err(payload_error);
    let actor_kind = match req("actor_kind")? {
        Value::Text(t) => ActorKind::from_wire_name(t),
        _ => None,
    }
    .ok_or_else(|| answer("actor_kind"))?;
    let out = PartyEntry {
        party: KernelId(bytes(req("party")?)?),
        actor_kind,
        since: point(req("since")?)?,
        ended: f.opt("ended").map(point).transpose()?,
    };
    f.done(&["party", "actor_kind", "since", "ended"])
        .map_err(payload_error)?;
    Ok(out)
}

/// Reads the payload of a Party lookup answer (`party-lookup.cddl`).
///
/// # Errors
/// [`AccessError::Answer`].
pub fn decode_lookup(payload: &[u8], evidence: Arc<Evidence>) -> Result<PartyAnswer, AccessError> {
    let v = dcbor::decode(payload, Limits::CEILING).map_err(|_| answer("payload"))?;
    let f = Fields::of(&v).map_err(payload_error)?;
    let req = |name: &str| f.req(name).map_err(payload_error);
    let domain = Digest::from_value(req("domain")?).ok_or_else(|| answer("domain"))?;
    let Value::Array(parties) = req("parties")? else {
        return Err(answer("payload"));
    };
    let Value::Array(unknown) = req("unknown")? else {
        return Err(answer("payload"));
    };
    let out = PartyAnswer {
        domain: DomainId(domain.0),
        pos: uint(req("pos")?)?,
        iat: uint(req("iat")?)?,
        parties: parties.iter().map(entry).collect::<Result<_, _>>()?,
        unknown: unknown
            .iter()
            .map(|p| bytes(p).map(KernelId))
            .collect::<Result<_, _>>()?,
        evidence,
    };
    f.done(&["domain", "pos", "iat", "parties", "unknown"])
        .map_err(payload_error)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::keys::tests::{IAT, domain, token};

    const VECTORS: &str = include_str!("../../../../conformance/vectors/access/party-lookup.json");

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn cases() -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        v["cases"].as_array().unwrap().clone()
    }

    fn vector(id: &str) -> Vec<u8> {
        let case = cases().into_iter().find(|c| c["id"] == id).unwrap();
        unhex(case["cbor"].as_str().unwrap())
    }

    fn none() -> Arc<Evidence> {
        Arc::new(Evidence {
            sign1: Vec::new(),
            excerpt: Vec::new(),
        })
    }

    fn with_iat(payload: &[u8], iat: u64) -> Vec<u8> {
        let mut v = dcbor::decode(payload, Limits::CEILING).unwrap();
        let Value::Map(top) = &mut v else {
            panic!("a map");
        };
        for (k, value) in top {
            if *k == Value::text("iat") {
                *value = Value::Unsigned(iat);
            }
        }
        dcbor::encode(&v, Limits::CEILING).unwrap()
    }

    // P-12 MD-7 T-101
    #[test]
    fn p_12_the_party_lookup_vectors_name_each_party_s_actor_kind() {
        let human = decode_lookup(&vector("human-party-admitted"), none()).unwrap();
        assert_eq!(human.pos, 9);
        assert_eq!(
            human.parties,
            vec![PartyEntry {
                party: KernelId([3; 16]),
                actor_kind: ActorKind::Human,
                since: LedgerPoint { pos: 5, at: 5000 },
                ended: None,
            }]
        );
        assert_eq!(human.unknown, vec![KernelId([8; 16])]);
        let departed = decode_lookup(&vector("system-party-departed"), none()).unwrap();
        assert_eq!(departed.parties[0].actor_kind, ActorKind::System);
        assert_eq!(
            departed.parties[0].ended,
            Some(LedgerPoint { pos: 9, at: 9000 })
        );
        assert_eq!(
            decode_lookup(&vector("nothing-known"), none())
                .unwrap()
                .parties,
            Vec::new()
        );
        for case in cases() {
            if case["valid"] == false {
                assert!(case.get("cbor").is_none(), "{case}");
            }
        }
    }

    // P-12 T-101
    #[test]
    fn p_12_a_party_lookup_answer_verifies_under_the_party_lookup_usage_only() {
        let (_, store) = token("parties");
        let d = domain(&store);
        let m = d.read();
        let payload = with_iat(&vector("human-party-admitted"), IAT);
        let sign1 = d.sign(PARTY_CONTENT_TYPE, &payload);
        let asked = [KernelId([3; 16]), KernelId([8; 16])];
        let excerpt = d.excerpt("party-lookup");
        let got = verify_answer(&m, &d.id, &asked, &sign1, &excerpt, Some(9)).unwrap();
        assert_eq!(got.parties[0].actor_kind, ActorKind::Human);
        assert_eq!(got.evidence.sign1, sign1);
        assert_eq!(
            verify_answer(&m, &d.id, &asked, &sign1, &d.excerpt("key-lookup"), Some(9)),
            Err(AccessError::Metadata("usage"))
        );
        assert_eq!(
            verify_answer(&m, &d.id, &asked, &sign1, &excerpt, Some(8)),
            Err(AccessError::Answer("etag"))
        );
        assert_eq!(
            verify_answer(&m, &d.id, &asked[..1], &sign1, &excerpt, Some(9)),
            Err(AccessError::Answer("parties"))
        );
        let other = d.sign("application/access-key-lookup+cbor", &payload);
        assert_eq!(
            verify_answer(&m, &d.id, &asked, &other, &excerpt, Some(9)),
            Err(AccessError::Metadata("signature"))
        );
    }

    // T-101
    #[test]
    fn t_101_the_party_batch_body_is_in_access_wire_form() {
        let domain = DomainId([1; 32]);
        let party = KernelId([3; 16]);
        let body: serde_json::Value =
            serde_json::from_slice(&batch_body(&domain, &[party], &AsOf::Position(7)).unwrap())
                .unwrap();
        assert_eq!(body["domain"], domain.text());
        assert_eq!(body["parties"][0], party.text());
        assert_eq!(body["as_of"], "7");
        assert!(batch_body(&domain, &[party, party], &AsOf::Head).is_err());
        assert!(batch_body(&domain, &[], &AsOf::Head).is_err());
        let many: Vec<KernelId> = (0..=100_u8).map(|i| KernelId([i; 16])).collect();
        assert!(batch_body(&domain, &many, &AsOf::Head).is_err());
        let head: serde_json::Value =
            serde_json::from_slice(&batch_body(&domain, &[party], &AsOf::Head).unwrap()).unwrap();
        assert!(head.get("as_of").is_none());
    }
}
