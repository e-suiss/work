//! Records mirroring the Stage 1 vector examples, built from the typed model.

#![allow(dead_code, reason = "each test binary uses a subset")]

use work_kernel::catalog::CoreDerivedRole;
use work_kernel::id::{Digest, LedgerId, PartyRef, RecordId, Time, WorkId};
use work_kernel::limits::SemanticLimits;
use work_kernel::record::{
    Act, Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Claim, ClaimType,
    Correlation, Declaration, EvidenceRef, EvidenceSubject, EvidenceType, ExtValue, Extension,
    PartName, PracticePin, ProducerRef, ProtocolVersion, Record, RecordCore, VersionVector,
    Visibility,
};
use work_kernel::relation::{DerivedRole, DerivedTarget, ReferenceTarget, Relation};
use work_kernel::uri::{ExtKey, ExternalRef, TypeUri};
use work_kernel::validate::{
    ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin, ValidationContext,
};

pub(crate) const CORE: &str = "https://suiss.app/ns/work/";
pub(crate) const PROC: &str = "https://procurement.example/ns/";
pub(crate) const CLINIC: &str = "https://clinic.example/ns/";
pub(crate) const ALICE: &str = "party:acme:alice";
pub(crate) const BUYER: &str = "party:acme:buyer-org";
pub(crate) const AGENT: &str = "party:acme:agent-procure-7";
pub(crate) const SUPPLIER: &str = "party:globex:supplier";
pub(crate) const SYS: &str = "party:acme:work-scheduler";

pub(crate) fn digest(n: u8) -> Digest {
    Digest::sha256([n; 32])
}

pub(crate) fn rid(n: u8) -> RecordId {
    RecordId(digest(n))
}

pub(crate) fn party(s: &str) -> PartyRef {
    PartyRef::new(s).unwrap()
}

pub(crate) fn uri(s: &str) -> TypeUri {
    TypeUri::parse(s).unwrap()
}

pub(crate) fn w1() -> WorkId {
    WorkId::from_bytes([
        0x01, 0x9a, 0x2f, 0x4c, 0x8e, 0x1b, 0x7c, 0x3d, 0xa5, 0xe6, 0xf7, 0x08, 0x12, 0x34, 0x56,
        0x78,
    ])
}

pub(crate) fn w2() -> WorkId {
    WorkId::from_bytes([
        0x01, 0x9a, 0x2f, 0x4c, 0x8e, 0x1b, 0x7c, 0x3d, 0xa5, 0xe6, 0xf7, 0x08, 0x87, 0x65, 0x43,
        0x21,
    ])
}

pub(crate) fn ledger() -> LedgerId {
    LedgerId(digest(0xee))
}

pub(crate) fn visibility(see: Audience) -> Visibility {
    Visibility {
        see,
        search_excluded: false,
        agent_context_excluded: false,
    }
}

pub(crate) fn versions(schema: u8) -> VersionVector {
    VersionVector {
        protocol: ProtocolVersion { major: 1, minor: 0 },
        schema: digest(schema),
        practices: None,
    }
}

pub(crate) fn pinned(schema: u8, namespace: &str) -> VersionVector {
    VersionVector {
        practices: Some(vec![PracticePin {
            namespace: uri(namespace),
            digest: digest(schema.wrapping_add(1)),
        }]),
        ..versions(schema)
    }
}

pub(crate) fn core(author: &str) -> RecordCore {
    RecordCore {
        author: party(author),
        on_behalf_of: None,
        capacity: None,
        basis: None,
        visibility: visibility(Audience::Work),
        ledger: ledger(),
        concerns: vec![],
        relations: None,
        authority: None,
        producer: None,
        correlation: None,
        evidence: None,
        body: None,
        params: None,
        versions: versions(0x50),
        ext: None,
        critical: None,
    }
}

pub(crate) fn authority(n: u8) -> AuthorityRef {
    AuthorityRef {
        proof: AuthorityProofKind::DecisionReceipt,
        digest: digest(n),
    }
}

pub(crate) fn body(part: &str, n: u8) -> BodyCommitment {
    BodyCommitment {
        part: PartName::parse(part).unwrap(),
        commit: digest(n),
    }
}

pub(crate) fn ext(key: &str, value: &[u8]) -> Extension {
    Extension {
        key: uri(key),
        value: ExtValue(value.to_vec()),
    }
}

pub(crate) fn declaration(subtype: &str, mut core: RecordCore) -> Record {
    core.basis.get_or_insert_with(Vec::new);
    Record::Declaration(Declaration {
        subtype: uri(subtype),
        occurred_at: None,
        core,
    })
}

pub(crate) fn promise() -> Record {
    declaration(
        &format!("{CORE}declaration/promise"),
        RecordCore {
            on_behalf_of: Some(vec![party(BUYER)]),
            capacity: Some(Capacity::For(party(BUYER))),
            basis: Some(vec![rid(0x10)]),
            concerns: vec![w1()],
            authority: Some(authority(0x11)),
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
            body: Some(vec![body("params", 0x13)]),
            versions: versions(0x14),
            ..core(AGENT)
        },
    )
}

pub(crate) fn delivery() -> Record {
    Record::Act(Act {
        subtype: uri(&format!("{CORE}act/action")),
        occurred_at: Time(1_792_108_800_000),
        core: RecordCore {
            capacity: Some(Capacity::Own),
            concerns: vec![w1()],
            relations: Some(vec![Relation::DerivedFrom {
                source: None,
                target: DerivedTarget::Record(rid(0x20)),
                role: DerivedRole::Core(CoreDerivedRole::Fulfills),
            }]),
            evidence: Some(vec![EvidenceRef {
                subject: EvidenceSubject::Digest(digest(0x21)),
                evidence_type: EvidenceType::from_uri(uri(&format!("{CORE}evidence/artifact"))),
                presenter: party(SUPPLIER),
                claimed_at: Some(Time(1_792_108_700_000)),
                source: None,
                observation: None,
                visibility: None,
                signature: digest(0x22),
            }]),
            versions: versions(0x23),
            ..core(SUPPLIER)
        },
    })
}

pub(crate) fn observation() -> Record {
    Record::Claim(Claim {
        subtype: ClaimType::from_uri(uri(&format!("{CORE}claim/observation"))),
        occurred_at: Time(1_792_109_000_000),
        core: RecordCore {
            basis: Some(vec![rid(0x30)]),
            visibility: Visibility {
                agent_context_excluded: true,
                ..visibility(Audience::Work)
            },
            concerns: vec![w1(), w2()],
            relations: Some(vec![Relation::References {
                source: None,
                target: ReferenceTarget::External(
                    ExternalRef::parse("https://erp.example/orders/PO-4471").unwrap(),
                ),
                qualifier: None,
            }]),
            versions: versions(0x31),
            ..core(SYS)
        },
    })
}

pub(crate) fn amend() -> Record {
    declaration(
        &format!("{CORE}declaration/amend"),
        RecordCore {
            capacity: Some(Capacity::Own),
            basis: Some(vec![rid(0x40), rid(0x41)]),
            concerns: vec![w1()],
            relations: Some(vec![Relation::Supersedes {
                target: rid(0x40),
                qualifier: None,
            }]),
            authority: Some(authority(0x42)),
            body: Some(vec![body("params", 0x43), body("terms", 0x44)]),
            versions: pinned(0x45, PROC),
            ext: Some(vec![ext(&format!("{PROC}ext/cost_center"), b"\x67CC-4410")]),
            ..core(ALICE)
        },
    )
}

pub(crate) fn comment() -> Record {
    Record::Claim(Claim {
        subtype: ClaimType::from_uri(uri(&format!("{PROC}claim/comment"))),
        occurred_at: Time(1_792_109_050_000),
        core: RecordCore {
            visibility: visibility(Audience::Author),
            versions: pinned(0x45, PROC),
            ..core(ALICE)
        },
    })
}

pub(crate) fn consent_key() -> ExtKey {
    uri(&format!("{CLINIC}ext/patient_consent"))
}

pub(crate) fn ward_key() -> ExtKey {
    uri(&format!("{CLINIC}ext/ward"))
}

pub(crate) fn care_note() -> Record {
    declaration(
        &format!("{CLINIC}declaration/care_note"),
        RecordCore {
            capacity: Some(Capacity::Own),
            visibility: Visibility {
                search_excluded: true,
                ..visibility(Audience::Work)
            },
            concerns: vec![w2()],
            authority: Some(authority(0x63)),
            body: Some(vec![body("note", 0x60)]),
            versions: pinned(0x61, CLINIC),
            ext: Some(vec![
                ext(ward_key().as_str(), b"\x62B-2"),
                ext(consent_key().as_str(), b"\x01"),
            ]),
            critical: Some(vec![consent_key()]),
            ..core(ALICE)
        },
    )
}

pub(crate) fn actor_type_of(author: &str) -> ActorType {
    match author {
        AGENT => ActorType::Agent,
        SUPPLIER | BUYER => ActorType::Organization,
        SYS => ActorType::System,
        _ => ActorType::Human,
    }
}

pub(crate) fn bound(actor_type: ActorType) -> ActorTypeEntry {
    ActorTypeEntry {
        actor_type,
        source: ActorTypeSource::AccessBinding,
    }
}

pub(crate) fn actor_types(record: &Record) -> ActorTypes {
    let core = record.core();
    ActorTypes {
        author: bound(actor_type_of(core.author.as_str())),
        on_behalf_of: core
            .on_behalf_of
            .iter()
            .flatten()
            .map(|p| bound(actor_type_of(p.as_str())))
            .collect(),
    }
}

pub(crate) fn ctx<'a>(
    origin: Origin,
    actors: &'a ActorTypes,
    understood: &'a [ExtKey],
) -> ValidationContext<'a> {
    ValidationContext {
        origin,
        actor_types: actors,
        understood_extensions: understood,
        limits: SemanticLimits::DEFAULT,
        recorded_at: None,
    }
}

pub(crate) fn core_mut(record: &mut Record) -> &mut RecordCore {
    match record {
        Record::Act(r) => &mut r.core,
        Record::Declaration(r) => &mut r.core,
        Record::Claim(r) => &mut r.core,
    }
}
