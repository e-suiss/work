//! The Access action catalog of Work operations (E-45): one Schema Publication Package in the `work` namespace with 23 actions, each with its Access `effect_class`; every API operation names exactly one of them (`x-work-action`, T-98), and a coordination gate decision names none (E-9).

/// The Access namespace of the package (E-45 item 1).
pub const NAMESPACE: &str = "work";

/// The catalog version of the package (E-45 items 1 and 7).
pub const CATALOG_VERSION: u32 = 1;

/// The major version of every action (E-45 item 1).
pub const ACTION_MAJOR: u32 = 1;

/// The Access `effect_class` of an action (E-45 item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectClass {
    /// `none`: reads.
    None,
    /// `reversible`.
    Reversible,
    /// `irreversible`.
    Irreversible,
}

impl EffectClass {
    /// The Access wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Reversible => "reversible",
            Self::Irreversible => "irreversible",
        }
    }
}

/// The one parameter an action carries (E-45 item 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Param {
    /// `reason` (`text`, the P-111 classes) of `work:redact`.
    Reason,
    /// `recipient` (`id`) of `work:disclose`.
    Recipient,
}

impl Param {
    /// The parameter name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reason => "reason",
            Self::Recipient => "recipient",
        }
    }
}

/// One action of the catalog (E-45 item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// `work:read`.
    Read,
    /// `work:write`.
    Write,
    /// `work:commit`.
    Commit,
    /// `work:close`.
    Close,
    /// `work:four_eyes_approve`.
    FourEyesApprove,
    /// `work:administrative_close`.
    AdministrativeClose,
    /// `work:claim`.
    Claim,
    /// `work:assign`.
    Assign,
    /// `work:condition`.
    Condition,
    /// `work:stop_request`.
    StopRequest,
    /// `work:stop_respond`.
    StopRespond,
    /// `work:control`.
    Control,
    /// `work:autonomy_policy_set`.
    AutonomyPolicySet,
    /// `work:escalation_policy_set`.
    EscalationPolicySet,
    /// `work:agent_ceiling_decide`.
    AgentCeilingDecide,
    /// `work:practice_adopt`.
    PracticeAdopt,
    /// `work:executor_dispatch`.
    ExecutorDispatch,
    /// `work:disclose`.
    Disclose,
    /// `work:admit`.
    Admit,
    /// `work:redact`.
    Redact,
    /// `work:version_activate`.
    VersionActivate,
    /// `work:import`.
    Import,
    /// `work:export`.
    Export,
}

impl Action {
    /// Every action, in the order of the E-45 table.
    pub const ALL: [Self; 23] = [
        Self::Read,
        Self::Write,
        Self::Commit,
        Self::Close,
        Self::FourEyesApprove,
        Self::AdministrativeClose,
        Self::Claim,
        Self::Assign,
        Self::Condition,
        Self::StopRequest,
        Self::StopRespond,
        Self::Control,
        Self::AutonomyPolicySet,
        Self::EscalationPolicySet,
        Self::AgentCeilingDecide,
        Self::PracticeAdopt,
        Self::ExecutorDispatch,
        Self::Disclose,
        Self::Admit,
        Self::Redact,
        Self::VersionActivate,
        Self::Import,
        Self::Export,
    ];

    /// The qualified name, `work:<name>`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "work:read",
            Self::Write => "work:write",
            Self::Commit => "work:commit",
            Self::Close => "work:close",
            Self::FourEyesApprove => "work:four_eyes_approve",
            Self::AdministrativeClose => "work:administrative_close",
            Self::Claim => "work:claim",
            Self::Assign => "work:assign",
            Self::Condition => "work:condition",
            Self::StopRequest => "work:stop_request",
            Self::StopRespond => "work:stop_respond",
            Self::Control => "work:control",
            Self::AutonomyPolicySet => "work:autonomy_policy_set",
            Self::EscalationPolicySet => "work:escalation_policy_set",
            Self::AgentCeilingDecide => "work:agent_ceiling_decide",
            Self::PracticeAdopt => "work:practice_adopt",
            Self::ExecutorDispatch => "work:executor_dispatch",
            Self::Disclose => "work:disclose",
            Self::Admit => "work:admit",
            Self::Redact => "work:redact",
            Self::VersionActivate => "work:version_activate",
            Self::Import => "work:import",
            Self::Export => "work:export",
        }
    }

    /// The name inside the namespace, an Access `ident`.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.as_str().strip_prefix("work:").unwrap_or_default()
    }

    /// The action of a qualified name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.as_str() == text)
    }

    /// The Access `effect_class` (E-45 item 2).
    #[must_use]
    pub const fn effect_class(self) -> EffectClass {
        match self {
            Self::Read | Self::Export => EffectClass::None,
            Self::Close
            | Self::FourEyesApprove
            | Self::AdministrativeClose
            | Self::Disclose
            | Self::Redact
            | Self::VersionActivate => EffectClass::Irreversible,
            Self::Write
            | Self::Commit
            | Self::Claim
            | Self::Assign
            | Self::Condition
            | Self::StopRequest
            | Self::StopRespond
            | Self::Control
            | Self::AutonomyPolicySet
            | Self::EscalationPolicySet
            | Self::AgentCeilingDecide
            | Self::PracticeAdopt
            | Self::ExecutorDispatch
            | Self::Admit
            | Self::Import => EffectClass::Reversible,
        }
    }

    /// The parameter the action carries; only `work:redact` and `work:disclose` carry one
    /// (E-45 item 5).
    #[must_use]
    pub const fn param(self) -> Option<Param> {
        match self {
            Self::Redact => Some(Param::Reason),
            Self::Disclose => Some(Param::Recipient),
            _ => None,
        }
    }
}

/// The Access resource types of the actions (E-45 item 5).
pub const RESOURCE_TYPES: [&str; 4] = [
    "work.ledger",
    "work.work",
    "work.commitment",
    "work.condition",
];

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn is_ident(name: &str) -> bool {
        let mut chars = name.chars();
        chars.next().is_some_and(|c| c.is_ascii_lowercase())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && name.len() <= 63
    }

    // E-45
    #[test]
    fn e_45_the_catalog_is_the_23_actions_of_the_work_namespace() {
        assert_eq!(Action::ALL.len(), 23);
        for (i, action) in Action::ALL.into_iter().enumerate() {
            assert_eq!(Action::parse(action.as_str()), Some(action));
            assert_eq!(
                action.as_str().split_once(':'),
                Some((NAMESPACE, action.name()))
            );
            assert!(is_ident(action.name()), "{action:?}");
            assert!(
                Action::ALL
                    .iter()
                    .skip(i.saturating_add(1))
                    .all(|other| other != &action),
                "{action:?} repeats"
            );
        }
        assert_eq!(Action::parse("work:gate_decision"), None);
        assert_eq!(Action::parse("read"), None);
        assert_eq!((CATALOG_VERSION, ACTION_MAJOR), (1, 1));
    }

    // E-45
    #[test]
    fn e_45_effect_classes_and_params_follow_the_table() {
        let irreversible: Vec<&str> = Action::ALL
            .into_iter()
            .filter(|a| a.effect_class() == EffectClass::Irreversible)
            .map(Action::name)
            .collect();
        assert_eq!(
            irreversible,
            [
                "close",
                "four_eyes_approve",
                "administrative_close",
                "disclose",
                "redact",
                "version_activate"
            ]
        );
        let none: Vec<&str> = Action::ALL
            .into_iter()
            .filter(|a| a.effect_class() == EffectClass::None)
            .map(Action::name)
            .collect();
        assert_eq!(none, ["read", "export"]);
        let params: Vec<(&str, &str)> = Action::ALL
            .into_iter()
            .filter_map(|a| a.param().map(|p| (a.name(), p.name())))
            .collect();
        assert_eq!(params, [("disclose", "recipient"), ("redact", "reason")]);
        assert_eq!(EffectClass::Reversible.as_str(), "reversible");
    }
}
