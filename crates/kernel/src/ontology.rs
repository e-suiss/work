//! The nine canonical concepts with the identity each owns, the roles that live on Commitments and relations, the Party layers, the typed views of the three concepts a core Declaration opens (Commitment, Condition, Aim) without any stored state, split and merge continuity, and the canonical counterparts of capabilities that are no concept (C-1…C-4, C-8…C-13, C-18, C-30, C-36, C-40, C-43).

use alloc::vec::Vec;

use crate::catalog::{
    AimDuration, ClaimSubtype, ConditionClass, ConditionType, CoreDerivedRole, DeclarationSubtype,
};
use crate::id::{Digest, PartyRef, RecordId, WorkId};
use crate::reason::wire_enum;
use crate::record::{Capacity, Kind, ParamScalar, ParamValue, Record};
use crate::relation::{DerivedTarget, Relation, RelationName};
use crate::uri::TypeUri;

wire_enum! {
    /// The nine canonical concepts; there is no tenth, and an application, extension or Practice adds none (C-2, C-3).
    Concept {
        /// The identity anchor of lasting work (C-8).
        Work => "work",
        /// An identity that writes records and takes roles (C-9).
        Party => "party",
        /// A declared criterion of what counts as met (C-10).
        Aim => "aim",
        /// A two-sided obligation (C-11).
        Commitment => "commitment",
        /// A satisfiable predicate that blocks progress (C-12).
        Condition => "condition",
        /// The identity of something outside Work (C-13).
        Reference => "reference",
        /// The performer's report of an external action (C-14).
        Act => "act",
        /// The only record that changes normative state (C-15).
        Declaration => "declaration",
        /// A proposition without normative effect (C-16).
        Claim => "claim",
    }
}

/// What gives a concept its own identity, the first half of the canonical concept criterion (C-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Identity {
    /// An opaque 16-byte Work ID (C-8, C-35).
    Work,
    /// An Access Party reference (C-9).
    Party,
    /// An external reference (C-13).
    External,
    /// The ID of the record itself (P-79).
    Record,
    /// The ID of the Declaration that opened it (P-112).
    OpeningRecord,
}

impl Concept {
    /// The identity the concept owns (C-1).
    #[must_use]
    pub const fn identity(self) -> Identity {
        match self {
            Self::Work => Identity::Work,
            Self::Party => Identity::Party,
            Self::Reference => Identity::External,
            Self::Act | Self::Declaration | Self::Claim => Identity::Record,
            Self::Aim | Self::Commitment | Self::Condition => Identity::OpeningRecord,
        }
    }

    /// The concept a record of this kind is (C-31).
    #[must_use]
    pub const fn of_kind(kind: Kind) -> Self {
        match kind {
            Kind::Act => Self::Act,
            Kind::Declaration => Self::Declaration,
            Kind::Claim => Self::Claim,
        }
    }

    /// The concept a core Declaration opens: `request` a Commitment, `open_condition` a Condition, `aim` an Aim (C-10, C-11, C-12).
    #[must_use]
    pub fn opened_by(record: &Record) -> Option<Self> {
        match declaration_subtype(record)? {
            DeclarationSubtype::Request => Some(Self::Commitment),
            DeclarationSubtype::OpenCondition => Some(Self::Condition),
            DeclarationSubtype::Aim => Some(Self::Aim),
            _ => None,
        }
    }
}

wire_enum! {
    /// The roles of C-30; each lives on a Commitment or a relation and is never an attribute of the Party.
    Role {
        /// Who performs the work (RC-1).
        Performer => "performer",
        /// Who promised and carries the obligation (CM-5).
        Obligor => "obligor",
        /// In whose favour the commitment is (CM-5).
        Obligee => "obligee",
        /// On whose behalf it is made (CM-5).
        Principal => "principal",
        /// Who accepts or rejects the result (CM-5).
        Acceptor => "acceptor",
        /// Who owns the queue of a commitment without an obligor yet (RC-10).
        QueueOwner => "queue_owner",
        /// The single accountable end (RC-1).
        Accountable => "accountable",
    }
}

/// Where a role lives (C-30).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoleHome {
    /// On a Commitment.
    Commitment,
    /// On a relation.
    Relation(RelationName),
}

impl Role {
    /// Where the role lives (C-30, C-36).
    #[must_use]
    pub const fn home(self) -> RoleHome {
        match self {
            Self::Performer
            | Self::Obligor
            | Self::Obligee
            | Self::Acceptor
            | Self::Accountable => RoleHome::Commitment,
            Self::Principal => RoleHome::Relation(RelationName::OnBehalfOf),
            Self::QueueOwner => RoleHome::Relation(RelationName::EngagedIn),
        }
    }
}

wire_enum! {
    /// The layers of C-18; none stands in for another.
    PartyLayer {
        /// The attributable identity seen in Work.
        PartyIdentity => "party_identity",
        /// An agent's identity, which is its Party identity.
        AgentIdentity => "agent_identity",
        /// The controller that authorises the Party's key history.
        IdentityController => "identity_controller",
        /// The Party that runs an agent's runtime and configuration.
        Operator => "operator",
        /// On whose behalf an agent works.
        Principal => "principal",
        /// The model or infrastructure provider.
        Provider => "provider",
        /// How an agent works.
        ModelConfiguration => "model_configuration",
        /// The current process or binding.
        Runtime => "runtime",
        /// An interaction in one client.
        InteractionSession => "interaction_session",
        /// An executor's session for one commitment.
        ExecutionSession => "execution_session",
        /// The accountable end.
        Accountable => "accountable",
    }
}

/// Where a Party layer appears in Work (C-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LayerHome {
    /// A Party reference in an attributed slot (C-9, C-44).
    Party,
    /// Access's key history, never a record field (C-9).
    Access,
    /// The `on_behalf_of` chain and relation (C-17, E-13).
    OnBehalfOf,
    /// The record's `producer` (C-23).
    Producer,
    /// A Reference (C-13, C-22).
    Reference,
    /// Derived from the regime and the records (RC-1).
    Derived,
    /// Outside Work semantics.
    Outside,
}

impl PartyLayer {
    /// Where the layer appears (C-18).
    #[must_use]
    pub const fn home(self) -> LayerHome {
        match self {
            Self::PartyIdentity | Self::AgentIdentity | Self::Operator => LayerHome::Party,
            Self::IdentityController => LayerHome::Access,
            Self::Principal => LayerHome::OnBehalfOf,
            Self::ModelConfiguration => LayerHome::Producer,
            Self::Provider | Self::Runtime | Self::ExecutionSession => LayerHome::Reference,
            Self::Accountable => LayerHome::Derived,
            Self::InteractionSession => LayerHome::Outside,
        }
    }
}

/// The debtor side of a commitment: a Party, or a queue while no Party has promised (C-11, CM-4, RC-10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Obligor {
    /// The Party asked.
    Party(PartyRef),
    /// The `queue_definition` record of the pool.
    Queue(RecordId),
}

/// The core of a commitment, the same for every team and Practice: two sides, the principal chain, the Aim, the Conditions and the acceptor; it has no state field, the lifecycle derives it (C-7, C-11, C-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// In whose favour: the capacity principal, or the author (CM-5).
    pub obligee: PartyRef,
    /// The obligor or queue.
    pub obligor: Obligor,
    /// The `on_behalf_of` chain.
    pub principal: Vec<PartyRef>,
    /// The Aim it is about, if one is declared.
    pub aim: Option<RecordId>,
    /// The `open_condition` records it is under.
    pub conditions: Vec<RecordId>,
    /// Who accepts the result, written explicitly (CM-6).
    pub acceptor: PartyRef,
}

/// A Condition as declared when it opens: its type and the class the type maps to; the class of a Practice type is the Practice's mapping (C-12, C-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    /// The declared `condition_type`.
    pub declared: TypeUri,
    /// The class of a core type; `None` for a Practice type.
    pub class: Option<ConditionClass>,
}

/// How an Aim is judged met (C-10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evaluation {
    /// By the truth of evidence or a proposition.
    Truth,
    /// By a Declaration of the named Party.
    Judgment(PartyRef),
}

/// An Aim: how it is judged, how long it holds and its Practice criterion; it names no one who must do the work (C-10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aim {
    /// How it is judged met.
    pub evaluation: Evaluation,
    /// One shot or maintained.
    pub duration: AimDuration,
    /// The Practice criterion, if any.
    pub criterion: Option<TypeUri>,
}

fn declaration_subtype(record: &Record) -> Option<DeclarationSubtype> {
    match record {
        Record::Declaration(d) => DeclarationSubtype::from_uri(d.subtype.as_str()),
        Record::Act(_) | Record::Claim(_) => None,
    }
}

fn party_param(record: &Record, name: &str) -> Option<PartyRef> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Text(t)) => PartyRef::new(t),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

fn digest_param(record: &Record, name: &str) -> Option<Digest> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Digest(d)) => Some(*d),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

fn uri_param(record: &Record, name: &str) -> Option<TypeUri> {
    match record.param(name)? {
        ParamValue::Scalar(ParamScalar::Text(t)) => TypeUri::parse(t),
        ParamValue::Scalar(_) | ParamValue::List(_) => None,
    }
}

impl Commitment {
    /// The commitment a core `request` opens, read from its signed fields; `None` for any other record or a request without both sides and an acceptor, which the record rules reject (C-11, C-44).
    #[must_use]
    pub fn of(record: &Record) -> Option<Self> {
        if declaration_subtype(record)? != DeclarationSubtype::Request {
            return None;
        }
        let core = record.core();
        let obligor = match (
            party_param(record, "obligor"),
            digest_param(record, "queue"),
        ) {
            (Some(p), None) => Obligor::Party(p),
            (None, Some(q)) => Obligor::Queue(RecordId(q)),
            _ => return None,
        };
        let obligee = match &core.capacity {
            Some(Capacity::For(p)) => p.clone(),
            Some(Capacity::Own) | None => core.author.clone(),
        };
        let conditions = match record.param("conditions") {
            Some(ParamValue::List(items)) => items
                .iter()
                .filter_map(|s| match s {
                    ParamScalar::Digest(d) => Some(RecordId(*d)),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        Some(Self {
            obligee,
            obligor,
            principal: core.on_behalf_of.clone().unwrap_or_default(),
            aim: digest_param(record, "aim").map(RecordId),
            conditions,
            acceptor: party_param(record, "acceptor")?,
        })
    }
}

impl Condition {
    /// The Condition a core `open_condition` opens; the type is declared at creation and required (C-12, ST-12).
    #[must_use]
    pub fn of(record: &Record) -> Option<Self> {
        if declaration_subtype(record)? != DeclarationSubtype::OpenCondition {
            return None;
        }
        let declared = uri_param(record, "condition_type")?;
        let class = ConditionType::from_uri(declared.as_str()).map(ConditionType::class);
        Some(Self { declared, class })
    }
}

impl Aim {
    /// The Aim a core `aim` Declaration declares (C-10).
    #[must_use]
    pub fn of(record: &Record) -> Option<Self> {
        if declaration_subtype(record)? != DeclarationSubtype::Aim {
            return None;
        }
        let duration = match record.param("duration")? {
            ParamValue::Scalar(ParamScalar::Text(t)) => AimDuration::from_wire_name(t)?,
            ParamValue::Scalar(_) | ParamValue::List(_) => return None,
        };
        let evaluation =
            party_param(record, "judge").map_or(Evaluation::Truth, Evaluation::Judgment);
        Some(Self {
            evaluation,
            duration,
            criterion: uri_param(record, "criterion"),
        })
    }
}

/// The earlier Works a record continues after a split or a merge: its `derived_from` Work targets in the `source` role, in author order (C-43).
pub fn continued_works(record: &Record) -> impl Iterator<Item = &WorkId> {
    record
        .core()
        .relations
        .iter()
        .flatten()
        .filter_map(|r| match r {
            Relation::DerivedFrom {
                target: DerivedTarget::Work(w),
                ..
            } => Some(w),
            _ => None,
        })
}

/// The canonical form a capability takes instead of a new concept, table or relation (C-36).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Counterpart {
    /// A Commitment, or a typed one.
    Commitment,
    /// A Condition of the commitment.
    Condition,
    /// A typed Declaration.
    Declaration(DeclarationSubtype),
    /// A Claim of a core subtype.
    Claim(ClaimSubtype),
    /// A Reference.
    Reference,
    /// A relation, with its `derived_from` role.
    Relation(RelationName, Option<CoreDerivedRole>),
}

/// The canonical counterparts of C-36, by capability.
pub const COUNTERPARTS: &[(&str, Counterpart)] = &[
    (
        "queue",
        Counterpart::Relation(RelationName::EngagedIn, None),
    ),
    ("commitment_clock", Counterpart::Condition),
    ("budget", Counterpart::Condition),
    ("execution_attempt", Counterpart::Reference),
    (
        "decision_record",
        Counterpart::Declaration(DeclarationSubtype::GateDecision),
    ),
    (
        "handoff_note",
        Counterpart::Declaration(DeclarationSubtype::HandoffNote),
    ),
    ("follow_up", Counterpart::Commitment),
    ("periodic_update", Counterpart::Commitment),
    ("plan", Counterpart::Claim(ClaimSubtype::Assumption)),
    ("signal", Counterpart::Claim(ClaimSubtype::Observation)),
    ("agent_session", Counterpart::Reference),
    (
        "agent_approved_message",
        Counterpart::Claim(ClaimSubtype::Observation),
    ),
    (
        "capability_statement",
        Counterpart::Claim(ClaimSubtype::Observation),
    ),
    (
        "machine",
        Counterpart::Relation(RelationName::EngagedIn, None),
    ),
    (
        "role_name",
        Counterpart::Relation(RelationName::EngagedIn, None),
    ),
    ("wait_reason", Counterpart::Condition),
    ("multi_party_approval", Counterpart::Condition),
    (
        "sub_commitment",
        Counterpart::Relation(RelationName::DerivedFrom, Some(CoreDerivedRole::Supports)),
    ),
    (
        "fulfillment",
        Counterpart::Relation(RelationName::DerivedFrom, Some(CoreDerivedRole::Fulfills)),
    ),
    (
        "amendment",
        Counterpart::Declaration(DeclarationSubtype::Amend),
    ),
    (
        "control_lease",
        Counterpart::Declaration(DeclarationSubtype::ControlLease),
    ),
    (
        "participation_policy",
        Counterpart::Relation(RelationName::EngagedIn, None),
    ),
];

/// The concepts of C-40 that are derived from records or expressed by relations and roles, never stored as a canonical field (C-4).
pub const DERIVED: &[&str] = &[
    "status",
    "blocked",
    "progress",
    "attention",
    "next_move",
    "handoff",
    "control_lease_state",
    "clock_state",
    "budget_state",
    "wip",
    "context",
    "perspective",
    "trust",
    "evidence_assurance",
    "counterparty_state",
    "shared_work",
    "track_record",
    "support_chain",
    "ping_pong",
];
