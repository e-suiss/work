//! Field types of a record: capacity, authority, visibility, producer, correlation, evidence, body, versions and extensions (P-10…P-19, EV-3, EV-21).

use alloc::string::String;
use alloc::vec::Vec;

use crate::catalog::CoreEvidenceType;
use crate::id::{Digest, PartyRef, Time, WorkId};
use crate::reason::wire_enum;
use crate::uri::{ExtKey, ExternalRef, NamespaceUri, TypeUri};

/// The capacity the author uses: their own, or for a principal (P-13, E-13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Capacity {
    /// `own`.
    Own,
    /// `["for", P]`.
    For(PartyRef),
}

wire_enum! {
    /// What kind of Access proof `authority` refers to (P-13, E-9).
    AuthorityProofKind {
        /// An Access decision receipt.
        DecisionReceipt => "decision_receipt",
        /// An Access portable authority proof.
        PortableAuthorityProof => "portable_authority_proof",
        /// An Access approval record at an authority gate.
        ApprovalActStatement => "approval_act_statement",
        /// An Access eligibility check at a coordination gate.
        EligibilityCheck => "eligibility_check",
    }
}

/// A reference to the proof of exercised authority; Work does not produce authority (P-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityRef {
    /// The proof kind.
    pub proof: AuthorityProofKind,
    /// The digest of the proof bytes kept verbatim (P-5).
    pub digest: Digest,
}

/// Who may see the record: the audience and the search and agent-context exclusions (EV-21, EV-24, EV-25, P-77).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Visibility {
    /// The audience.
    pub see: Audience,
    /// Excluded from search (`search: false`).
    pub search_excluded: bool,
    /// Excluded from agent context (`agent_context: false`).
    pub agent_context_excluded: bool,
}

/// The audience of a record (EV-21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Audience {
    /// Everyone engaged in the Work.
    Work,
    /// The author only.
    Author,
    /// The listed Parties, 1 to 256 on the wire, sorted and without the author or a principal (P-77).
    Parties(Vec<PartyRef>),
}

/// The agent, version and configuration that produced an agent-authored record; a declaration, not proof (P-15, C-23).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducerRef {
    /// The agent version, 1 to 255 bytes.
    pub version: String,
    /// Digest of the configuration.
    pub config: Digest,
    /// The model, as an external reference.
    pub model: Option<ExternalRef>,
    /// Digest of the toolset.
    pub toolset: Option<Digest>,
    /// Digest of the instruction set.
    pub instructions: Option<Digest>,
    /// Digest of a remote attestation.
    pub attestation: Option<Digest>,
}

/// A correlation identifier: scheme and value (P-16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Correlation {
    /// The identifier scheme.
    pub scheme: TypeUri,
    /// The identifier, 1 to 1024 bytes.
    pub id: String,
}

/// A typed evidence reference (EV-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRef {
    /// What the evidence is about.
    pub subject: EvidenceSubject,
    /// The evidence type (EV-4).
    pub evidence_type: EvidenceType,
    /// The presenting Party.
    pub presenter: PartyRef,
    /// The presenter's claim of when it was produced.
    pub claimed_at: Option<Time>,
    /// The source, as an external reference.
    pub source: Option<ExternalRef>,
    /// Digest of an Observation Claim.
    pub observation: Option<Digest>,
    /// Visibility of the evidence.
    pub visibility: Option<Visibility>,
    /// Digest of the presenter's `COSE_Sign1` over the statement (EV-8).
    pub signature: Digest,
}

/// The subject of evidence: a content digest or a stable identifier (EV-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceSubject {
    /// A content digest.
    Digest(Digest),
    /// A stable identifier, 1 to 1024 bytes.
    StableId(String),
}

/// An evidence type: one of the four core types or an extension that maps to one (EV-4, P-71).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceType {
    /// A core type.
    Core(CoreEvidenceType),
    /// Any other URI; it must map to a core type (C-5).
    Extension(TypeUri),
}

/// The name of a body part in its subtype schema: `[a-z][a-z0-9_]{0,63}` (P-68).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartName(String);

impl PartName {
    /// Parses a part name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let mut bytes = value.bytes();
        let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
        let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        (first_ok && rest_ok && value.len() <= 64).then(|| Self(String::from(value)))
    }

    /// The part name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A salted commitment of one body part; the commitment is computed by the shared crate (P-17, P-68).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyCommitment {
    /// The part name.
    pub part: PartName,
    /// The commitment digest.
    pub commit: Digest,
}

/// The protocol version a record is interpreted under (P-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
}

/// An adopted Practice pinned by namespace and schema digest (P-18, PR-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PracticePin {
    /// The Practice namespace.
    pub namespace: NamespaceUri,
    /// The Practice schema digest.
    pub digest: Digest,
}

/// The version vector the normative result depends on (P-18, P-31).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionVector {
    /// Protocol version.
    pub protocol: ProtocolVersion,
    /// Digest of the subtype schema.
    pub schema: Digest,
    /// Pinned Practices in map order; `Some` is never empty on the wire.
    pub practices: Option<Vec<PracticePin>>,
}

/// A parameter name: `[a-z][a-z0-9_]{0,63}` (P-80).
pub type ParamName = PartName;

/// One typed normative parameter (P-80).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    /// The parameter name.
    pub name: ParamName,
    /// The parameter value.
    pub value: ParamValue,
}

/// A parameter value: a scalar or a non-empty list of scalars (P-80).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamValue {
    /// One scalar.
    Scalar(ParamScalar),
    /// A list of 1 to 256 scalars.
    List(Vec<ParamScalar>),
}

/// A parameter scalar as decoded; the subtype schema says which form a key takes (P-80 item 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamScalar {
    /// An unsigned integer or a `Time`.
    Uint(u64),
    /// A boolean.
    Bool(bool),
    /// A digest.
    Digest(Digest),
    /// A Work identifier.
    WorkId(WorkId),
    /// A catalog wire name, a URI or a Party reference; never free text.
    Text(String),
}

/// An extension value: its CBOR encoding, preserved verbatim and never interpreted by the kernel (P-19).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtValue(pub Vec<u8>);

/// One extension field in `ext` (P-69).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    /// The extension key.
    pub key: ExtKey,
    /// The extension value.
    pub value: ExtValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-68
    #[test]
    fn p_68_part_names_are_lowercase_snake_case_up_to_64_bytes() {
        assert!(PartName::parse("params").is_some());
        assert!(PartName::parse("note_2").is_some());
        assert!(PartName::parse(&"a".repeat(64)).is_some());
        assert!(PartName::parse(&"a".repeat(65)).is_none());
        assert!(PartName::parse("2note").is_none());
        assert!(PartName::parse("Note").is_none());
        assert!(PartName::parse("").is_none());
    }
}
