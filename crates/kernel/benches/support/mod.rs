//! Typed records and inputs for the kernel benchmarks, built directly from the record model so no parsing runs inside a measured loop (T-44).

#![allow(
    dead_code,
    clippy::expect_used,
    reason = "each bench binary uses a subset; fixture constants are valid by construction"
)]

use work_kernel::derive::{
    AuthorityIssuer, BusinessCalendar, DerivationInputs, Entry, Ingest, ProfileVersion,
    Restriction, TrustInputs,
};
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time, WorkId};
use work_kernel::limits::SemanticLimits;
use work_kernel::record::{
    Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Correlation, Declaration,
    PartName, ProducerRef, ProtocolVersion, Record, RecordCore, VersionVector, Visibility,
};
use work_kernel::relation::{Endpoint, Relation};
use work_kernel::uri::{ExternalRef, TypeUri};
use work_kernel::validate::{
    ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin, ValidationContext,
};

const PROMISE: &str = "https://suiss.app/ns/work/declaration/promise";
const AMEND: &str = "https://suiss.app/ns/work/declaration/amend";
const FULFILLS: &str = "https://suiss.app/ns/work/derived_from/fulfills";
const AGENT: &str = "party:acme:agent-procure-7";
const BUYER: &str = "party:acme:buyer-org";
const ALICE: &str = "party:acme:alice";

/// Chain lengths for the derivation benchmarks.
pub(crate) const CHAIN_LENGTHS: [u32; 3] = [1, 64, 1024];

fn digest(n: u8) -> Digest {
    Digest::sha256([n; 32])
}

fn indexed(i: u32) -> RecordId {
    let mut bytes = [0xa5_u8; 32];
    for (dst, src) in bytes.iter_mut().zip(i.to_be_bytes()) {
        *dst = src;
    }
    RecordId(Digest::sha256(bytes))
}

fn party(value: &str) -> PartyRef {
    PartyRef::new(value).expect("fixture party")
}

fn uri(value: &str) -> TypeUri {
    TypeUri::parse(value).expect("fixture uri")
}

fn work() -> WorkId {
    WorkId::from_bytes([
        0x01, 0x9a, 0x2f, 0x4c, 0x8e, 0x1b, 0x7c, 0x3d, 0xa5, 0xe6, 0xf7, 0x08, 0x12, 0x34, 0x56,
        0x78,
    ])
}

fn core(author: &str, schema: u8) -> RecordCore {
    RecordCore {
        author: party(author),
        on_behalf_of: None,
        capacity: Some(Capacity::Own),
        basis: Some(Vec::new()),
        visibility: Visibility {
            see: Audience::Work,
            search_excluded: false,
            agent_context_excluded: false,
        },
        ledger: LedgerId(digest(0xee)),
        concerns: vec![work()],
        relations: None,
        authority: Some(AuthorityRef {
            proof: AuthorityProofKind::DecisionReceipt,
            digest: digest(0x11),
        }),
        producer: None,
        correlation: None,
        evidence: None,
        body: None,
        params: None,
        versions: VersionVector {
            protocol: ProtocolVersion { major: 1, minor: 0 },
            schema: digest(schema),
            practices: None,
        },
        ext: None,
        critical: None,
    }
}

fn declaration(subtype: &str, core: RecordCore) -> Record {
    Record::Declaration(Declaration {
        subtype: uri(subtype),
        occurred_at: None,
        core,
    })
}

/// An agent promise on behalf of an organisation with producer, correlation and body: every Stage 1 record rule runs and accepts.
pub(crate) fn accepted() -> Record {
    declaration(
        PROMISE,
        RecordCore {
            on_behalf_of: Some(vec![party(BUYER)]),
            capacity: Some(Capacity::For(party(BUYER))),
            basis: Some(vec![RecordId(digest(0x10))]),
            producer: Some(ProducerRef {
                version: "procure-agent/3.2.0".to_owned(),
                config: digest(0x12),
                model: ExternalRef::parse("urn:example:model:m-2026-09"),
                toolset: None,
                instructions: None,
                attestation: None,
            }),
            correlation: Some(vec![Correlation {
                scheme: uri("https://a2a-protocol.org/context-id"),
                id: "ctx-8f2c".to_owned(),
            }]),
            body: Some(vec![BodyCommitment {
                part: PartName::parse("params").expect("fixture part"),
                commit: digest(0x13),
            }]),
            ..core(AGENT, 0x14)
        },
    )
}

/// The accepted promise without `authority`: rejected by a late rule (`authority_missing`).
pub(crate) fn rejected() -> Record {
    let mut record = accepted();
    if let Record::Declaration(d) = &mut record {
        d.core.authority = None;
    }
    record
}

fn bound(actor_type: ActorType) -> ActorTypeEntry {
    ActorTypeEntry {
        actor_type,
        source: ActorTypeSource::AccessBinding,
    }
}

/// Actor types for [`accepted`] and [`rejected`]: an agent author with one organisation ring.
pub(crate) fn actor_types() -> ActorTypes {
    ActorTypes {
        author: bound(ActorType::Agent),
        on_behalf_of: vec![bound(ActorType::Organization)],
    }
}

/// A direct-origin validation context with default limits.
pub(crate) fn context(actors: &ActorTypes) -> ValidationContext<'_> {
    ValidationContext {
        origin: Origin::Direct,
        actor_types: actors,
        understood_extensions: &[],
        limits: SemanticLimits::DEFAULT,
        recorded_at: None,
    }
}

/// One supersede chain of `len` Declarations by one author: a promise, then amendments that each supersede and cite the previous head.
pub(crate) fn chain(len: u32) -> Vec<(RecordId, Record)> {
    (0..len)
        .map(|i| {
            let id = indexed(i);
            let record = match i.checked_sub(1).map(indexed) {
                None => declaration(PROMISE, core(ALICE, 0x50)),
                Some(previous) => declaration(
                    AMEND,
                    RecordCore {
                        basis: Some(vec![previous]),
                        relations: Some(vec![Relation::Supersedes {
                            target: previous,
                            qualifier: None,
                        }]),
                        ..core(ALICE, 0x51)
                    },
                ),
            };
            (id, record)
        })
        .collect()
}

/// Ledger entries over `records` at contiguous positions with non-decreasing record time.
pub(crate) fn entries(records: &[(RecordId, Record)]) -> Vec<Entry<'_>> {
    records
        .iter()
        .zip(0_u64..)
        .map(|((id, record), position)| Entry {
            id: *id,
            record,
            position,
            recorded_at: Time(position),
            ingest: Ingest::Admitted,
            restriction: Restriction::NoObjection,
            issuer: AuthorityIssuer::Local,
        })
        .collect()
}

/// Derivation inputs at protocol 1.0 with no trusted publishers.
pub(crate) fn inputs() -> DerivationInputs<'static> {
    DerivationInputs {
        protocol: ProtocolVersion { major: 1, minor: 0 },
        profile: ProfileVersion(1),
        practices: &[],
        trust: TrustInputs {
            trusted_publishers: &[],
        },
        ledger_time: Time(u64::MAX),
        calendar: BusinessCalendar::Continuous,
    }
}

/// Decoded wire parts of one relation: name, source, target, qualifier.
pub(crate) type WireRelation = (
    &'static str,
    Option<Endpoint>,
    Endpoint,
    Option<&'static str>,
);

/// A `derived_from` relation with a core role, the relation with the most checks (C-27).
pub(crate) fn derived_from_wire() -> WireRelation {
    (
        "derived_from",
        None,
        Endpoint::Record(RecordId(digest(0x20))),
        Some(FULFILLS),
    )
}

/// An `engaged_in` relation with an explicit Party source (P-73).
pub(crate) fn engaged_in_wire() -> WireRelation {
    (
        "engaged_in",
        Some(Endpoint::Party(party(ALICE))),
        Endpoint::Work(work()),
        None,
    )
}

/// Parses one relation from its wire parts.
pub(crate) fn parse(wire: WireRelation) -> Option<Relation> {
    let (rel, source, target, qualifier) = wire;
    Relation::from_wire(rel, source, target, qualifier).ok()
}
