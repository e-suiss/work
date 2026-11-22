use crate::reason::wire_enum;

wire_enum! {
    /// The thirteen closed commitment states (CM-14); a domain label maps to one of them, and `promised` and `accepted` never share a name (CM-15).
    CommitmentState {
        /// The request is open; the obligor candidate or the queue answers.
        Requested => "requested",
        /// The obligor candidate offered other terms; the obligee answers.
        Countered => "countered",
        /// Promised under a declared precondition that is not met yet.
        ConditionallyPromised => "conditionally_promised",
        /// The obligor is bound; execution is expected or running.
        Promised => "promised",
        /// The obligor stated the work; the acceptor decides.
        Stated => "stated",
        /// The result was accepted, explicitly or implicitly.
        Accepted => "accepted",
        /// Declined before any promise.
        Declined => "declined",
        /// The counterparty allowed a revocation.
        Withdrawn => "withdrawn",
        /// The obligor withdrew unilaterally.
        Cancelled => "cancelled",
        /// The obligee released the obligor.
        Released => "released",
        /// The parent Aim or commitment went away; nobody is blamed.
        Obsolete => "obsolete",
        /// A declared validity ran out without an answer.
        Expired => "expired",
        /// Closed with reasons by an authorised Party outside the sides.
        ClosedAdministratively => "closed_administratively",
    }
}

impl CommitmentState {
    /// The five open states, in lifecycle order.
    pub const OPEN: &'static [Self] = &[
        Self::Requested,
        Self::Countered,
        Self::ConditionallyPromised,
        Self::Promised,
        Self::Stated,
    ];

    /// True for the eight terminal states, which never change (CM-14, CM-34).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(
            self,
            Self::Requested
                | Self::Countered
                | Self::ConditionallyPromised
                | Self::Promised
                | Self::Stated
        )
    }
}

/// The commitment-level summary of its items (CM-23): one state when every item is in it, otherwise `mixed`, which is a view and never a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Summary {
    /// Every item is in this state.
    Uniform(CommitmentState),
    /// The items differ; the per-item breakdown is the view.
    Mixed,
}

impl Summary {
    /// The `snake_case` wire name: the state's, or `mixed`.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Uniform(state) => state.wire_name(),
            Self::Mixed => "mixed",
        }
    }
}
