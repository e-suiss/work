//! The typed record model mirroring the normative CDDL: a record is exactly one of Act, Declaration or Claim (C-31, P-9) and carries the P-10 field set, with no confidence field (C-16).

mod parts;

use alloc::vec::Vec;

pub use parts::{
    Audience, AuthorityProofKind, AuthorityRef, BodyCommitment, Capacity, Correlation, EvidenceRef,
    EvidenceSubject, EvidenceType, ExtValue, Extension, Param, ParamName, ParamScalar, ParamValue,
    PartName, PracticePin, ProducerRef, ProtocolVersion, VersionVector, Visibility,
};

use crate::catalog::{ClaimSubtype, CoreEvidenceType};
use crate::id::{LedgerId, PartyRef, RecordId, Time, WorkId};
use crate::reason::wire_enum;
use crate::relation::Relation;
use crate::uri::{ExtKey, TypeUri};

wire_enum! {
    /// The three record kinds; there is no fourth (C-31, P-9).
    Kind {
        /// A report of an external action (C-14).
        Act => "act",
        /// A normative speech act (C-15).
        Declaration => "declaration",
        /// An assertion about the world (C-16).
        Claim => "claim",
    }
}

/// A signed Work record (C-31, P-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// An Act record.
    Act(Act),
    /// A Declaration record.
    Declaration(Declaration),
    /// A Claim record.
    Claim(Claim),
}

/// An Act: `occurred_at` is required (P-10, C-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Act {
    /// The record subtype (P-9).
    pub subtype: TypeUri,
    /// The author's claim of when it happened; not normative time (P-27).
    pub occurred_at: Time,
    /// The fields every record carries.
    pub core: RecordCore,
}

/// A Declaration: `occurred_at` is optional (P-10, C-15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    /// The record subtype (P-9).
    pub subtype: TypeUri,
    /// The author's claim of when it happened, if any.
    pub occurred_at: Option<Time>,
    /// The fields every record carries.
    pub core: RecordCore,
}

/// A Claim: `occurred_at` is required (P-10, C-16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The Claim subtype (C-16).
    pub subtype: ClaimType,
    /// The author's claim of when it happened; not normative time (P-27).
    pub occurred_at: Time,
    /// The fields every record carries.
    pub core: RecordCore,
}

/// A Claim subtype: one of the three core subtypes or a Practice subtype that maps to one (C-16, P-71).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimType {
    /// A core subtype.
    Core(ClaimSubtype),
    /// Any other URI; it must map to a core subtype (C-5).
    Extension(TypeUri),
}

impl ClaimType {
    /// Classifies a URI, recognising the three core subtypes.
    #[must_use]
    pub fn from_uri(uri: TypeUri) -> Self {
        ClaimSubtype::from_uri(uri.as_str()).map_or(Self::Extension(uri), Self::Core)
    }
}

/// The fields shared by all three kinds (P-10, C-32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordCore {
    /// The Party that wrote the record (INV-20).
    pub author: PartyRef,
    /// The principal chain from the author to the root (C-17, E-13); `Some` is never empty on the wire.
    pub on_behalf_of: Option<Vec<PartyRef>>,
    /// The single capacity the author uses (P-13).
    pub capacity: Option<Capacity>,
    /// Normative premises, sorted and duplicate-free (P-28, P-72); required on a Declaration and possibly empty, optional and never empty on an Act or Claim (P-81).
    pub basis: Option<Vec<RecordId>>,
    /// Declared visibility (EV-21).
    pub visibility: Visibility,
    /// The one ledger the record is recorded in (C-34).
    pub ledger: LedgerId,
    /// Works in the same ledger the record concerns, sorted and duplicate-free (C-34, P-72).
    pub concerns: Vec<WorkId>,
    /// Canonical relations in author order (P-14, P-73).
    pub relations: Option<Vec<Relation>>,
    /// Reference to the proof of exercised authority (P-13).
    pub authority: Option<AuthorityRef>,
    /// The producing agent, version and configuration (P-15).
    pub producer: Option<ProducerRef>,
    /// Correlation identifiers in author order (P-16).
    pub correlation: Option<Vec<Correlation>>,
    /// Typed evidence references in author order (EV-3).
    pub evidence: Option<Vec<EvidenceRef>>,
    /// Salted commitments of body parts in author order (P-17, P-68); never an input to derivation (P-80).
    pub body: Option<Vec<BodyCommitment>>,
    /// Typed normative parameters of the subtype, in map order (P-80).
    pub params: Option<Vec<Param>>,
    /// Protocol, schema and Practice versions (P-18).
    pub versions: VersionVector,
    /// Extension fields, preserved byte for byte (P-19, P-69).
    pub ext: Option<Vec<Extension>>,
    /// Keys of critical extensions, sorted and duplicate-free (P-69).
    pub critical: Option<Vec<ExtKey>>,
}

impl Record {
    /// The record kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Act(_) => Kind::Act,
            Self::Declaration(_) => Kind::Declaration,
            Self::Claim(_) => Kind::Claim,
        }
    }

    /// The shared fields.
    #[must_use]
    pub const fn core(&self) -> &RecordCore {
        match self {
            Self::Act(r) => &r.core,
            Self::Declaration(r) => &r.core,
            Self::Claim(r) => &r.core,
        }
    }

    /// The subtype URI, when it is not a core Claim subtype.
    #[must_use]
    pub const fn subtype_uri(&self) -> Option<&TypeUri> {
        match self {
            Self::Act(r) => Some(&r.subtype),
            Self::Declaration(r) => Some(&r.subtype),
            Self::Claim(Claim {
                subtype: ClaimType::Extension(uri),
                ..
            }) => Some(uri),
            Self::Claim(_) => None,
        }
    }

    /// The normative premises; empty when absent (P-81).
    #[must_use]
    pub fn basis(&self) -> &[RecordId] {
        self.core().basis.as_deref().unwrap_or_default()
    }

    /// The parameter with this name, if present (P-80).
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&ParamValue> {
        self.core()
            .params
            .iter()
            .flatten()
            .find(|p| p.name.as_str() == name)
            .map(|p| &p.value)
    }

    /// The typed effective time `params.effective_at` of a Declaration (P-80 item 4).
    #[must_use]
    pub fn effective_at(&self) -> Option<Time> {
        match (self, self.param("effective_at")) {
            (Self::Declaration(_), Some(ParamValue::Scalar(ParamScalar::Uint(t)))) => {
                Some(Time(*t))
            }
            _ => None,
        }
    }

    /// The records this record supersedes, in author order (P-24).
    pub fn supersedes(&self) -> impl Iterator<Item = &RecordId> {
        self.core()
            .relations
            .iter()
            .flatten()
            .filter_map(|r| match r {
                Relation::Supersedes { target, .. } => Some(target),
                _ => None,
            })
    }
}

impl EvidenceType {
    /// Classifies a URI, recognising the four core evidence types.
    #[must_use]
    pub fn from_uri(uri: TypeUri) -> Self {
        CoreEvidenceType::from_uri(uri.as_str()).map_or(Self::Extension(uri), Self::Core)
    }
}
