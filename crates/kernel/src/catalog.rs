//! The core identifier catalog: closed core values per extension point with their wire names (P-71, P-82…P-85); every Declaration is consequential and no Act or Claim is (P-83).

use crate::reason::wire_enum;
use crate::record::Record;
use crate::uri::CORE_ROOT;

wire_enum! {
    /// The three core Claim subtypes (C-16).
    ClaimSubtype {
        /// What was observed.
        Observation => "observation",
        /// A judgement.
        Assessment => "assessment",
        /// An assumption.
        Assumption => "assumption",
    }
}

wire_enum! {
    /// The four core evidence types (EV-4).
    CoreEvidenceType {
        /// An artifact.
        Artifact => "artifact",
        /// An external event.
        ExternalEvent => "external_event",
        /// A measurement.
        Measurement => "measurement",
        /// A human verification.
        HumanVerification => "human_verification",
    }
}

wire_enum! {
    /// The core `derived_from` roles, written as full URIs in `relations`; `basis` is the record field, not a relation role (C-27, P-81).
    CoreDerivedRole {
        /// Origin.
        Source => "source",
        /// Fulfilment of a commitment (C-29).
        Fulfills => "fulfills",
        /// Sub-commitment support (C-28).
        Supports => "supports",
    }
}

/// Whether a record is consequential under the closed P-13 list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consequence {
    /// Consequential: `authority` is required, whoever the author is (P-13, C-32).
    Consequential,
    /// Not consequential.
    NonConsequential,
}

wire_enum! {
    /// The single core Act subtype (P-82).
    ActSubtype {
        /// A report of an external action (C-14).
        Action => "action",
    }
}

wire_enum! {
    /// The closed core Declaration subtypes (P-71).
    DeclarationSubtype {
        /// `request` (CM-17).
        Request => "request",
        /// `promise` (CM-17).
        Promise => "promise",
        /// `promise_conditional` (CM-17).
        PromiseConditional => "promise_conditional",
        /// `decline` (CM-17).
        Decline => "decline",
        /// `counter` (CM-17).
        Counter => "counter",
        /// `accept_counter` (CM-17).
        AcceptCounter => "accept_counter",
        /// `state` (CM-17).
        State => "state",
        /// `accept` (CM-17).
        Accept => "accept",
        /// `reject` (CM-17).
        Reject => "reject",
        /// `cancel` (CM-17).
        Cancel => "cancel",
        /// `release` (CM-17).
        Release => "release",
        /// `delegate` (CM-17).
        Delegate => "delegate",
        /// `assign` (CM-17).
        Assign => "assign",
        /// `allow` (CM-17).
        Allow => "allow",
        /// `refuse` (CM-17).
        Refuse => "refuse",
        /// `amend` (CM-17).
        Amend => "amend",
        /// `declare_obsolete` (CM-17).
        DeclareObsolete => "declare_obsolete",
        /// `expire` (CM-17).
        Expire => "expire",
        /// `administrative_close` (CM-17).
        AdministrativeClose => "administrative_close",
        /// `dispute` (CM-17).
        Dispute => "dispute",
        /// `defer` (CM-17).
        Defer => "defer",
        /// `resume` (CM-17).
        Resume => "resume",
        /// `notice` (CM-17).
        Notice => "notice",
        /// `revoke_request` (CM-17).
        RevokeRequest => "revoke_request",
        /// `revoke_promise` (CM-17).
        RevokePromise => "revoke_promise",
        /// `revoke_statement` (CM-17).
        RevokeStatement => "revoke_statement",
        /// `revoke_acceptance` (CM-17).
        RevokeAcceptance => "revoke_acceptance",
        /// `claim` (RC-17).
        ClaimResponsibility => "claim",
        /// `unclaim` (RC-17).
        Unclaim => "unclaim",
        /// `forward` (RC-17).
        Forward => "forward",
        /// `nominate` (RC-17).
        Nominate => "nominate",
        /// `offer` (RC-17).
        Offer => "offer",
        /// `reassign` (RC-17).
        Reassign => "reassign",
        /// `renew_lease` (RC-17).
        RenewLease => "renew_lease",
        /// `gate_decision` (ST-25, ST-28).
        GateDecision => "gate_decision",
        /// `stop_request` (RC-36).
        StopRequest => "stop_request",
        /// `stop_response` (RC-36, P-84).
        StopResponse => "stop_response",
        /// `open_condition` (ST-12, P-84).
        OpenCondition => "open_condition",
        /// `withdraw_condition` (ST-25, P-84).
        WithdrawCondition => "withdraw_condition",
        /// `practice_adoption` (PR-13).
        PracticeAdoption => "practice_adoption",
        /// `disclosure` (SEC-14).
        Disclosure => "disclosure",
        /// `queue_definition` (RC-10).
        QueueDefinition => "queue_definition",
        /// `control_lease` (RC-33).
        ControlLease => "control_lease",
        /// `handoff_note` (RC-34).
        HandoffNote => "handoff_note",
        /// `conflict_resolution` (P-28).
        ConflictResolution => "conflict_resolution",
        /// `admission` (FD-21).
        Admission => "admission",
        /// `autonomy_policy` (RC-27).
        AutonomyPolicy => "autonomy_policy",
        /// `implicit_acceptance_terms` (CM-41).
        ImplicitAcceptanceTerms => "implicit_acceptance_terms",
        /// `resume_after_stop` (RC-40).
        ResumeAfterStop => "resume_after_stop",
        /// `waiver` (RC-9).
        Waiver => "waiver",
        /// `attention_request` (RC-31).
        AttentionRequest => "attention_request",
        /// `acknowledgement` (ST-48).
        Acknowledgement => "acknowledgement",
    }
}

wire_enum! {
    /// The core Condition types (ST-10).
    ConditionType {
        /// Waiting for information.
        Information => "information",
        /// Waiting for a commitment.
        Commitment => "commitment",
        /// Waiting for an external event.
        ExternalEvent => "external_event",
        /// Waiting for a time.
        Time => "time",
        /// Waiting for a third party.
        ThirdParty => "third_party",
        /// An authority gate.
        Authority => "authority",
        /// A decision gate.
        Decision => "decision",
        /// An acceptance gate.
        Acceptance => "acceptance",
        /// A resource gate.
        Resource => "resource",
    }
}

wire_enum! {
    /// The core dependency types (ST-21).
    DependencyType {
        /// Flow.
        Flow => "flow",
        /// Sharing.
        Sharing => "sharing",
        /// Fit.
        Fit => "fit",
        /// Part and whole.
        PartWhole => "part_whole",
    }
}

wire_enum! {
    /// Reasons for `decline` (CM-20, P-85).
    DeclineReason {
        /// No capacity.
        NoCapacity => "no_capacity",
        /// No authority.
        NoAuthority => "no_authority",
        /// Out of scope.
        OutOfScope => "out_of_scope",
        /// Missing information.
        MissingInformation => "missing_information",
        /// Unacceptable terms.
        UnacceptableTerms => "unacceptable_terms",
        /// Other.
        Other => "other",
    }
}

wire_enum! {
    /// Reasons for `cancel` (CM-30).
    CancelReason {
        /// Could not be completed.
        CannotComplete => "cannot_complete",
        /// Tried and failed.
        Failed => "failed",
        /// Abandoned.
        Abandoned => "abandoned",
        /// Other.
        Other => "other",
    }
}

wire_enum! {
    /// Types of `notice` (CM-17).
    NoticeType {
        /// At risk.
        AtRisk => "at_risk",
        /// Cannot complete.
        CannotComplete => "cannot_complete",
        /// Obsolete suggested.
        ObsoleteSuggested => "obsolete_suggested",
    }
}

wire_enum! {
    /// Types of `stop_request` (RC-36, P-85).
    StopType {
        /// Stop at once.
        Immediate => "immediate",
        /// Finish, then stop.
        FinishThenStop => "finish_then_stop",
        /// Pause.
        Pause => "pause",
    }
}

wire_enum! {
    /// Answers in `stop_response` (RC-36, P-85).
    StopAnswer {
        /// Accept.
        Accept => "accept",
        /// Finish, then stop.
        FinishThenStop => "finish_then_stop",
        /// Refuse.
        Refuse => "refuse",
    }
}

wire_enum! {
    /// Why a Condition waits (ST-11, P-85).
    WaitReason {
        /// Internal hold.
        Internal => "internal",
        /// External suspension.
        External => "external",
    }
}

wire_enum! {
    /// Forms of a gate (ST-27, P-85).
    GateForm {
        /// Approval.
        Approval => "approval",
        /// Pre-action review.
        PreActionReview => "pre_action_review",
        /// Delivery acceptance.
        DeliveryAcceptance => "delivery_acceptance",
    }
}

const DECLARATION_POINT: &str = "declaration/";
const ACT_POINT: &str = "act/";
const CLAIM_POINT: &str = "claim/";
const EVIDENCE_POINT: &str = "evidence/";
const ROLE_POINT: &str = "derived_from/";
const CONDITION_POINT: &str = "condition/";
const DEPENDENCY_POINT: &str = "dependency/";

fn core_name<'a>(uri: &'a str, point: &str) -> Option<&'a str> {
    uri.strip_prefix(CORE_ROOT)?.strip_prefix(point)
}

macro_rules! from_uri {
    ($name:ident, $point:ident) => {
        impl $name {
            /// The core value a URI names, if any (P-70, P-71).
            #[must_use]
            pub fn from_uri(uri: &str) -> Option<Self> {
                core_name(uri, $point).and_then(Self::from_wire_name)
            }
        }
    };
}

from_uri!(ActSubtype, ACT_POINT);
from_uri!(DeclarationSubtype, DECLARATION_POINT);
from_uri!(ClaimSubtype, CLAIM_POINT);
from_uri!(CoreEvidenceType, EVIDENCE_POINT);
from_uri!(CoreDerivedRole, ROLE_POINT);
from_uri!(ConditionType, CONDITION_POINT);
from_uri!(DependencyType, DEPENDENCY_POINT);

/// The wire URI of the `basis` role, which `relations` never carries (P-81).
pub const BASIS_ROLE_URI: &str = "https://suiss.app/ns/work/derived_from/basis";

impl DeclarationSubtype {
    /// True for operations that close a commitment in a terminal state from any state they apply to (CM-14, CM-34); a placeholder until the Stage 5 lifecycle.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Accept
                | Self::Decline
                | Self::Cancel
                | Self::Release
                | Self::DeclareObsolete
                | Self::Expire
                | Self::AdministrativeClose
        )
    }
}

/// Classifies a record: `kind = declaration` is consequential, Acts and Claims are not (P-83, P-13, C-32).
#[must_use]
pub const fn consequence(record: &Record) -> Consequence {
    match record {
        Record::Declaration(_) => Consequence::Consequential,
        Record::Act(_) | Record::Claim(_) => Consequence::NonConsequential,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-71 P-83
    #[test]
    fn p_71_core_declaration_catalog_is_closed() {
        assert_eq!(DeclarationSubtype::ALL.len(), 52);
        assert_eq!(
            DeclarationSubtype::from_uri("https://suiss.app/ns/work/declaration/promise"),
            Some(DeclarationSubtype::Promise)
        );
        assert_eq!(
            DeclarationSubtype::from_uri("https://suiss.app/ns/work/declaration/approve"),
            None
        );
        assert_eq!(
            DeclarationSubtype::from_uri("https://suiss.app/ns/work/declaration/declare-obsolete"),
            None
        );
    }

    // P-82
    #[test]
    fn p_82_the_only_core_act_subtype_is_action() {
        assert_eq!(ActSubtype::ALL, &[ActSubtype::Action]);
        assert_eq!(
            ActSubtype::from_uri("https://suiss.app/ns/work/act/action"),
            Some(ActSubtype::Action)
        );
        assert_eq!(
            ActSubtype::from_uri("https://suiss.app/ns/work/act/delivery"),
            None
        );
    }

    // P-81 C-27
    #[test]
    fn p_81_core_roles_are_full_uris_and_basis_is_not_one() {
        assert_eq!(
            CoreDerivedRole::from_uri("https://suiss.app/ns/work/derived_from/fulfills"),
            Some(CoreDerivedRole::Fulfills)
        );
        assert_eq!(CoreDerivedRole::from_uri("fulfills"), None);
        assert_eq!(CoreDerivedRole::from_uri(BASIS_ROLE_URI), None);
    }

    // C-16 EV-4 ST-10 ST-21
    #[test]
    fn c_16_closed_core_lists_have_their_sizes() {
        assert_eq!(ClaimSubtype::ALL.len(), 3);
        assert_eq!(CoreEvidenceType::ALL.len(), 4);
        assert_eq!(ConditionType::ALL.len(), 9);
        assert_eq!(DependencyType::ALL.len(), 4);
        assert_eq!(
            ClaimSubtype::from_uri("https://suiss.org/work/claim/observation"),
            None
        );
        assert_eq!(
            CoreEvidenceType::from_uri("https://suiss.app/ns/work/evidence/external_event"),
            Some(CoreEvidenceType::ExternalEvent)
        );
    }

    // P-85
    #[test]
    fn p_85_wire_names_have_no_hyphen() {
        let names = DeclarationSubtype::ALL
            .iter()
            .map(|d| d.wire_name())
            .chain(GateForm::ALL.iter().map(|g| g.wire_name()))
            .chain(StopType::ALL.iter().map(|g| g.wire_name()))
            .chain(DeclineReason::ALL.iter().map(|g| g.wire_name()));
        for name in names {
            assert!(!name.contains('-'), "{name}");
        }
    }
}
