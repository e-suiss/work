use super::state::CommitmentState;
use super::state::CommitmentState as S;
use crate::catalog::DeclarationSubtype;
use crate::reason::wire_enum;

wire_enum! {
    /// The commitment Declarations: the closed operation set of CM-17 and the implicit acceptance terms of CM-41; adding one is a protocol decision.
    Operation {
        /// Opens a commitment.
        Request => "request",
        /// Binds the obligor candidate.
        Promise => "promise",
        /// Binds the obligor candidate under a precondition.
        PromiseConditional => "promise_conditional",
        /// Declines before any promise.
        Decline => "decline",
        /// Offers changed terms.
        Counter => "counter",
        /// Accepts the obligor candidate's counter-offer.
        AcceptCounter => "accept_counter",
        /// States the work done.
        State => "state",
        /// Accepts the stated result.
        Accept => "accept",
        /// Rejects the stated result back to execution.
        Reject => "reject",
        /// The obligor's unilateral withdrawal.
        Cancel => "cancel",
        /// The obligee's release of the obligor.
        Release => "release",
        /// Hands the debt to a new obligor, in two records.
        Delegate => "delegate",
        /// Hands the claim to a new obligee, in two records.
        Assign => "assign",
        /// Disputes a rejection or a revocation of acceptance.
        Dispute => "dispute",
        /// Defers without changing the state.
        Defer => "defer",
        /// Closes an open deferral.
        Resume => "resume",
        /// Asks to withdraw the request.
        RevokeRequest => "revoke_request",
        /// Asks to withdraw the promise.
        RevokePromise => "revoke_promise",
        /// Asks to withdraw the statement.
        RevokeStatement => "revoke_statement",
        /// Asks to withdraw the acceptance.
        RevokeAcceptance => "revoke_acceptance",
        /// Allows an open revocation request.
        Allow => "allow",
        /// Refuses an open revocation request or a terms amendment.
        Refuse => "refuse",
        /// A new instruction or terms version.
        Amend => "amend",
        /// The obligor's notice; no state change.
        Notice => "notice",
        /// Closes as obsolete.
        DeclareObsolete => "declare_obsolete",
        /// Closes a declared validity that ran out.
        Expire => "expire",
        /// Closes administratively.
        AdministrativeClose => "administrative_close",
        /// The obligee's prior explicit terms for implicit acceptance.
        ImplicitAcceptanceTerms => "implicit_acceptance_terms",
    }
}

wire_enum! {
    /// Who may write an operation, by role on the commitment (CM-5, CM-17).
    Actor {
        /// The obligee, or a Party writing for it.
        Obligee => "obligee",
        /// The Party asked, or anyone eligible while a queue holds the debtor side (CM-13).
        ObligorCandidate => "obligor_candidate",
        /// The bound obligor.
        Obligor => "obligor",
        /// The acceptor (CM-37).
        Acceptor => "acceptor",
        /// A principal on the obligee side (CM-32, CM-56).
        Principal => "principal",
        /// The counterparty of an open revocation request (CM-35).
        Counterparty => "counterparty",
        /// The Party a delegation or assignment proposes (CM-43, CM-44).
        ProposedParty => "proposed_party",
        /// The Work service Party, an Access-bound system Party (CM-31, CM-41).
        WorkService => "work_service",
        /// A Party whose authority Access alone decides (CM-33).
        Authorised => "authorised",
    }
}

/// What an operation does to the states it applies to (CM-17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transition {
    /// The items it applies to move to this state.
    To(CommitmentState),
    /// No state changes; a marker, notice, deferral, version or term changes.
    Unchanged,
    /// Opens a request or proposal the other side answers; the state changes only with the answer.
    Opens,
    /// Answers an open request or proposal with the result its kind fixes.
    Answers,
}

wire_enum! {
    /// The content an operation must carry (CM-17).
    Content {
        /// The minimal fields of a commitment and the offer (CM-6, CM-7).
        MinimalFields => "minimal_fields",
        /// The precondition, an `open_condition` record (CM-22).
        Precondition => "precondition",
        /// The validity of a conditional promise (CM-22).
        ValidUntil => "valid_until",
        /// A reason code from the operation's closed list (CM-20, CM-30, CM-61).
        ReasonCode => "reason_code",
        /// The changed terms (CM-21, CM-56).
        ChangedTerms => "changed_terms",
        /// The counter-offer accepted (CM-21).
        CounterVersion => "counter_version",
        /// Fulfilment references with the `fulfills` role (CM-25).
        Fulfilment => "fulfilment",
        /// The statement accepted or rejected (CM-40).
        Statement => "statement",
        /// Evidence references when the criterion, policy or a truth-based Aim asks for them (CM-27).
        EvidenceWhenRequired => "evidence_when_required",
        /// The handover note (CM-45).
        HandoverNote => "handover_note",
        /// The new obligor or obligee (CM-43).
        NewParty => "new_party",
        /// The proposal accepted (CM-44).
        Proposal => "proposal",
        /// The disputed record (CM-36).
        DisputedRecord => "disputed_record",
        /// The deferral closed (CM-17).
        Deferral => "deferral",
        /// The revocation request answered (CM-35).
        Revocation => "revocation",
        /// The superseded version (CM-56).
        Supersedes => "supersedes",
        /// The notice type (CM-17).
        NoticeType => "notice_type",
        /// The parent Aim or commitment that went away (CM-32).
        Parent => "parent",
        /// The validity declaration in `basis` (CM-31).
        ValidityBasis => "validity_basis",
        /// A justification note (CM-33).
        Justification => "justification",
        /// The implicit acceptance window, or its withdrawal (CM-41).
        Window => "window",
    }
}

/// One permitted way to write an operation (CM-17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permit {
    /// The roles that may write it this way.
    pub by: &'static [Actor],
    /// The states it applies to; empty for `request`, which opens the commitment.
    pub from: &'static [CommitmentState],
    /// What it does.
    pub to: Transition,
}

/// One row of the operation table: author role, permitted state, result and required content (CM-17, CM-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationRule {
    /// The operation.
    pub operation: Operation,
    /// The permitted ways to write it.
    pub permits: &'static [Permit],
    /// The content it must carry.
    pub content: &'static [Content],
    /// Whether it applies to chosen items (CM-23); otherwise to every open item.
    pub per_item: bool,
}

const OPEN: &[S] = S::OPEN;
const OPEN_OR_ACCEPTED: &[S] = &[
    S::Requested,
    S::Countered,
    S::ConditionallyPromised,
    S::Promised,
    S::Stated,
    S::Accepted,
];
const BOUND: &[S] = &[S::ConditionallyPromised, S::Promised, S::Stated];
const BEFORE_STATED: &[S] = &[
    S::Requested,
    S::Countered,
    S::ConditionallyPromised,
    S::Promised,
];
const DELEGABLE: &[S] = &[S::ConditionallyPromised, S::Promised];
const ANSWERABLE: &[S] = &[S::Requested, S::Countered, S::ConditionallyPromised];

const fn permit(by: &'static [Actor], from: &'static [S], to: Transition) -> Permit {
    Permit { by, from, to }
}

const fn row(
    operation: Operation,
    permits: &'static [Permit],
    content: &'static [Content],
    per_item: bool,
) -> OperationRule {
    OperationRule {
        operation,
        permits,
        content,
        per_item,
    }
}

const OBLIGEE: &[Actor] = &[Actor::Obligee];
const CANDIDATE: &[Actor] = &[Actor::ObligorCandidate];
const OBLIGOR: &[Actor] = &[Actor::Obligor];
const ACCEPTOR: &[Actor] = &[Actor::Acceptor];
const SIDES: &[Actor] = &[Actor::Obligee, Actor::Obligor];
const OBLIGEE_SIDE: &[Actor] = &[Actor::Obligee, Actor::Principal];
const COUNTERPARTY: &[Actor] = &[Actor::Counterparty];
const PROPOSED: &[Actor] = &[Actor::ProposedParty];

/// The operation table (CM-17), one row per operation in [`Operation::ALL`] order.
pub const RULES: &[OperationRule] = &[
    row(
        Operation::Request,
        &[permit(OBLIGEE, &[], Transition::To(S::Requested))],
        &[Content::MinimalFields],
        false,
    ),
    row(
        Operation::Promise,
        &[
            permit(CANDIDATE, &[S::Requested], Transition::To(S::Promised)),
            permit(OBLIGOR, BOUND, Transition::Answers),
        ],
        &[],
        true,
    ),
    row(
        Operation::PromiseConditional,
        &[permit(
            CANDIDATE,
            &[S::Requested],
            Transition::To(S::ConditionallyPromised),
        )],
        &[Content::Precondition, Content::ValidUntil],
        true,
    ),
    row(
        Operation::Decline,
        &[permit(
            CANDIDATE,
            &[S::Requested],
            Transition::To(S::Declined),
        )],
        &[Content::ReasonCode],
        true,
    ),
    row(
        Operation::Counter,
        &[
            permit(CANDIDATE, &[S::Requested], Transition::To(S::Countered)),
            permit(OBLIGEE, &[S::Countered], Transition::To(S::Requested)),
            permit(OBLIGOR, BOUND, Transition::Opens),
        ],
        &[Content::ChangedTerms],
        false,
    ),
    row(
        Operation::AcceptCounter,
        &[
            permit(OBLIGEE, &[S::Countered], Transition::To(S::Promised)),
            permit(OBLIGEE, BOUND, Transition::Answers),
        ],
        &[Content::CounterVersion],
        false,
    ),
    row(
        Operation::State,
        &[permit(OBLIGOR, &[S::Promised], Transition::To(S::Stated))],
        &[Content::Fulfilment],
        true,
    ),
    row(
        Operation::Accept,
        &[permit(
            &[Actor::Acceptor, Actor::WorkService],
            &[S::Stated],
            Transition::To(S::Accepted),
        )],
        &[Content::Statement, Content::EvidenceWhenRequired],
        true,
    ),
    row(
        Operation::Reject,
        &[permit(ACCEPTOR, &[S::Stated], Transition::To(S::Promised))],
        &[Content::Statement, Content::ReasonCode],
        true,
    ),
    row(
        Operation::Cancel,
        &[permit(OBLIGOR, BOUND, Transition::To(S::Cancelled))],
        &[Content::ReasonCode],
        false,
    ),
    row(
        Operation::Release,
        &[permit(OBLIGEE, OPEN, Transition::To(S::Released))],
        &[],
        false,
    ),
    row(
        Operation::Delegate,
        &[
            permit(OBLIGOR, DELEGABLE, Transition::Opens),
            permit(PROPOSED, DELEGABLE, Transition::Answers),
        ],
        &[Content::HandoverNote, Content::NewParty, Content::Proposal],
        false,
    ),
    row(
        Operation::Assign,
        &[
            permit(OBLIGEE, OPEN, Transition::Opens),
            permit(PROPOSED, OPEN, Transition::Answers),
        ],
        &[Content::NewParty, Content::Proposal],
        false,
    ),
    row(
        Operation::Dispute,
        &[permit(
            OBLIGOR,
            &[S::Promised, S::Stated, S::Accepted],
            Transition::Unchanged,
        )],
        &[Content::DisputedRecord, Content::ReasonCode],
        false,
    ),
    row(
        Operation::Defer,
        &[permit(SIDES, BEFORE_STATED, Transition::Unchanged)],
        &[Content::ReasonCode],
        false,
    ),
    row(
        Operation::Resume,
        &[permit(
            &[Actor::Obligee, Actor::Obligor, Actor::WorkService],
            OPEN,
            Transition::Unchanged,
        )],
        &[Content::Deferral],
        false,
    ),
    row(
        Operation::RevokeRequest,
        &[permit(OBLIGEE, OPEN, Transition::Opens)],
        &[Content::ReasonCode],
        false,
    ),
    row(
        Operation::RevokePromise,
        &[permit(OBLIGOR, DELEGABLE, Transition::Opens)],
        &[Content::ReasonCode],
        false,
    ),
    row(
        Operation::RevokeStatement,
        &[permit(OBLIGOR, &[S::Stated], Transition::Opens)],
        &[Content::ReasonCode],
        false,
    ),
    row(
        Operation::RevokeAcceptance,
        &[permit(ACCEPTOR, &[S::Accepted], Transition::Opens)],
        &[Content::ReasonCode],
        false,
    ),
    row(
        Operation::Allow,
        &[permit(COUNTERPARTY, OPEN_OR_ACCEPTED, Transition::Answers)],
        &[Content::Revocation],
        false,
    ),
    row(
        Operation::Refuse,
        &[
            permit(COUNTERPARTY, OPEN_OR_ACCEPTED, Transition::Answers),
            permit(OBLIGOR, BOUND, Transition::Answers),
        ],
        &[Content::Revocation, Content::ReasonCode],
        false,
    ),
    row(
        Operation::Amend,
        &[
            permit(OBLIGEE_SIDE, OPEN, Transition::Unchanged),
            permit(
                OBLIGEE_SIDE,
                &[S::Requested, S::Countered],
                Transition::To(S::Requested),
            ),
            permit(OBLIGEE_SIDE, BOUND, Transition::Opens),
            permit(OBLIGOR, OPEN, Transition::Unchanged),
        ],
        &[Content::Supersedes],
        false,
    ),
    row(
        Operation::Notice,
        &[permit(OBLIGOR, OPEN, Transition::Unchanged)],
        &[Content::NoticeType],
        false,
    ),
    row(
        Operation::DeclareObsolete,
        &[permit(OBLIGEE_SIDE, OPEN, Transition::To(S::Obsolete))],
        &[Content::Parent],
        false,
    ),
    row(
        Operation::Expire,
        &[permit(
            &[Actor::WorkService],
            ANSWERABLE,
            Transition::To(S::Expired),
        )],
        &[Content::ValidityBasis],
        false,
    ),
    row(
        Operation::AdministrativeClose,
        &[permit(
            &[Actor::Authorised],
            OPEN,
            Transition::To(S::ClosedAdministratively),
        )],
        &[Content::Justification],
        false,
    ),
    row(
        Operation::ImplicitAcceptanceTerms,
        &[
            permit(OBLIGEE, BEFORE_STATED, Transition::Unchanged),
            permit(OBLIGEE, OPEN, Transition::Unchanged),
        ],
        &[Content::Window],
        false,
    ),
];

impl Operation {
    /// The closed operation set of CM-17, without the CM-41 terms.
    pub const CLOSED_SET: &'static [Self] = &[
        Self::Request,
        Self::Promise,
        Self::PromiseConditional,
        Self::Decline,
        Self::Counter,
        Self::AcceptCounter,
        Self::State,
        Self::Accept,
        Self::Reject,
        Self::Cancel,
        Self::Release,
        Self::Delegate,
        Self::Assign,
        Self::Dispute,
        Self::Defer,
        Self::Resume,
        Self::RevokeRequest,
        Self::RevokePromise,
        Self::RevokeStatement,
        Self::RevokeAcceptance,
        Self::Allow,
        Self::Refuse,
        Self::Amend,
        Self::Notice,
        Self::DeclareObsolete,
        Self::Expire,
        Self::AdministrativeClose,
    ];

    /// The operation a core Declaration subtype is, if it is one (P-71).
    #[must_use]
    pub const fn of(subtype: DeclarationSubtype) -> Option<Self> {
        use DeclarationSubtype as D;
        Some(match subtype {
            D::Request => Self::Request,
            D::Promise => Self::Promise,
            D::PromiseConditional => Self::PromiseConditional,
            D::Decline => Self::Decline,
            D::Counter => Self::Counter,
            D::AcceptCounter => Self::AcceptCounter,
            D::State => Self::State,
            D::Accept => Self::Accept,
            D::Reject => Self::Reject,
            D::Cancel => Self::Cancel,
            D::Release => Self::Release,
            D::Delegate => Self::Delegate,
            D::Assign => Self::Assign,
            D::Dispute => Self::Dispute,
            D::Defer => Self::Defer,
            D::Resume => Self::Resume,
            D::RevokeRequest => Self::RevokeRequest,
            D::RevokePromise => Self::RevokePromise,
            D::RevokeStatement => Self::RevokeStatement,
            D::RevokeAcceptance => Self::RevokeAcceptance,
            D::Allow => Self::Allow,
            D::Refuse => Self::Refuse,
            D::Amend => Self::Amend,
            D::Notice => Self::Notice,
            D::DeclareObsolete => Self::DeclareObsolete,
            D::Expire => Self::Expire,
            D::AdministrativeClose => Self::AdministrativeClose,
            D::ImplicitAcceptanceTerms => Self::ImplicitAcceptanceTerms,
            _ => return None,
        })
    }

    /// The core Declaration subtype of the operation (P-71).
    #[must_use]
    pub const fn subtype(self) -> DeclarationSubtype {
        use DeclarationSubtype as D;
        match self {
            Self::Request => D::Request,
            Self::Promise => D::Promise,
            Self::PromiseConditional => D::PromiseConditional,
            Self::Decline => D::Decline,
            Self::Counter => D::Counter,
            Self::AcceptCounter => D::AcceptCounter,
            Self::State => D::State,
            Self::Accept => D::Accept,
            Self::Reject => D::Reject,
            Self::Cancel => D::Cancel,
            Self::Release => D::Release,
            Self::Delegate => D::Delegate,
            Self::Assign => D::Assign,
            Self::Dispute => D::Dispute,
            Self::Defer => D::Defer,
            Self::Resume => D::Resume,
            Self::RevokeRequest => D::RevokeRequest,
            Self::RevokePromise => D::RevokePromise,
            Self::RevokeStatement => D::RevokeStatement,
            Self::RevokeAcceptance => D::RevokeAcceptance,
            Self::Allow => D::Allow,
            Self::Refuse => D::Refuse,
            Self::Amend => D::Amend,
            Self::Notice => D::Notice,
            Self::DeclareObsolete => D::DeclareObsolete,
            Self::Expire => D::Expire,
            Self::AdministrativeClose => D::AdministrativeClose,
            Self::ImplicitAcceptanceTerms => D::ImplicitAcceptanceTerms,
        }
    }

    /// The operation's row in [`RULES`].
    #[must_use]
    pub fn rule(self) -> Option<&'static OperationRule> {
        RULES.iter().find(|r| r.operation == self)
    }
}
