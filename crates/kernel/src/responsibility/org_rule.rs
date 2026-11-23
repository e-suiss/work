use alloc::string::String;
use alloc::vec::Vec;

use super::accountability::Directory;
use super::chains;
use crate::catalog::DeclarationSubtype;
use crate::commitment::params;
use crate::derive::{Derivation, Entry};
use crate::id::{PartyRef, RecordId};
use crate::reason::wire_enum;
use crate::record::{ParamScalar, ParamValue, Record};
use crate::validate::ActorType;

wire_enum! {
    /// Which Parties a regime counts as the accountable end: `default` humans and organisations, `organization` only the organisation Party with humans as intermediate links; an agent is never an end (RC-6, RC-48).
    Regime {
        /// Humans and organisations are accountable.
        Default => "default",
        /// The chain ends only in the organisation Party.
        Organization => "organization",
    }
}

impl Regime {
    /// Whether a Party of this actor type can be the accountable end under the regime; an agent, a system or a machine never can (RC-6).
    #[must_use]
    pub const fn ends_in(self, actor: ActorType) -> bool {
        match self {
            Self::Default => matches!(actor, ActorType::Human | ActorType::Organization),
            Self::Organization => matches!(actor, ActorType::Organization),
        }
    }
}

/// How a group or role resolves to one Party: a fixed Party, or an Access role that must have exactly one member (RC-1, RC-48).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// A fixed Party.
    Party(PartyRef),
    /// A single-member Access role.
    Role(String),
}

/// An organisation rule: the group resolutions, the mandatory fallback Party and the regime of one Access organisation (RC-48).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgRule {
    /// The organisation Party the rule speaks for.
    pub organization: PartyRef,
    /// The Party that becomes accountable when nothing else resolves.
    pub fallback: PartyRef,
    /// The regime.
    pub regime: Regime,
    /// Group or role reference to its resolution, in author order.
    pub groups: Vec<(String, Resolution)>,
}

fn texts(record: &Record, name: &str) -> Option<Vec<String>> {
    match record.param(name)? {
        ParamValue::List(items) => items
            .iter()
            .map(|s| match s {
                ParamScalar::Text(t) => Some(String::from(t.as_str())),
                _ => None,
            })
            .collect(),
        ParamValue::Scalar(_) => None,
    }
}

fn pairs(record: &Record, keys: &str, values: &str) -> Option<Vec<(String, String)>> {
    match (texts(record, keys), texts(record, values)) {
        (None, None) => Some(Vec::new()),
        (Some(k), Some(v)) if k.len() == v.len() => Some(k.into_iter().zip(v).collect()),
        _ => None,
    }
}

impl OrgRule {
    /// The rule a core `org_rule` declares; `None` for any other record or one whose group lists do not pair up, which the record rules reject (RC-48).
    #[must_use]
    pub fn of(record: &Record) -> Option<Self> {
        if chains::subtype_of(record)? != DeclarationSubtype::OrgRule {
            return None;
        }
        let mut groups: Vec<(String, Resolution)> = Vec::new();
        for (group, party) in pairs(record, "party_groups", "parties")? {
            groups.push((group, Resolution::Party(PartyRef::new(&party)?)));
        }
        for (group, role) in pairs(record, "role_groups", "roles")? {
            groups.push((group, Resolution::Role(role)));
        }
        Some(Self {
            organization: params::party(record, "organization")?,
            fallback: params::party(record, "fallback")?,
            regime: params::text(record, "regime")
                .and_then(Regime::from_wire_name)
                .unwrap_or(Regime::Default),
            groups,
        })
    }
}

/// The organisation rule in force for one organisation: the chain root, the version record every resolution names, and the rule (RC-48).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgRuleVersion {
    /// The root of the rule chain.
    pub chain: RecordId,
    /// The version in force.
    pub version: RecordId,
    /// The rule.
    pub rule: OrgRule,
}

/// The rule in force per organisation: one chain per organisation, the first chain to name it; its latest version with normative effect (RC-48).
#[must_use]
pub fn org_rules(entries: &[Entry<'_>], derivation: &Derivation) -> Vec<OrgRuleVersion> {
    let mut out: Vec<OrgRuleVersion> = Vec::new();
    for v in chains::versions(entries, derivation, DeclarationSubtype::OrgRule) {
        let Some(rule) = OrgRule::of(v.record) else {
            continue;
        };
        match out
            .iter_mut()
            .find(|r| r.rule.organization == rule.organization)
        {
            Some(current) if current.chain == v.root => {
                current.version = v.id;
                current.rule = rule;
            }
            Some(_) => {}
            None => out.push(OrgRuleVersion {
                chain: v.root,
                version: v.id,
                rule,
            }),
        }
    }
    out
}

/// The rule in force for `organization`.
#[must_use]
pub fn rule_for<'a>(
    rules: &'a [OrgRuleVersion],
    organization: &PartyRef,
) -> Option<&'a OrgRuleVersion> {
    rules.iter().find(|r| &r.rule.organization == organization)
}

/// A group resolved to one Party, naming the rule version it used (RC-1, RC-48).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupResolution {
    /// The Party.
    pub party: PartyRef,
    /// Whether the rule resolved the group; otherwise the Party is the fallback.
    pub resolved: bool,
    /// The rule version used; `None` when there is no rule and the organisation itself is the fallback.
    pub rule: Option<RecordId>,
}

/// Resolves a group or role to one Party under the rule in force: a fixed Party, or a role with exactly one member in Access; a role without exactly one member, an unknown group or a missing rule falls to the fallback Party, which is the organisation itself when there is no rule (RC-1, RC-48).
#[must_use]
pub fn resolve_group(
    rule: Option<&OrgRuleVersion>,
    organization: &PartyRef,
    group: &str,
    directory: &dyn Directory,
) -> GroupResolution {
    let Some(rule) = rule else {
        return GroupResolution {
            party: organization.clone(),
            resolved: false,
            rule: None,
        };
    };
    let found = rule
        .rule
        .groups
        .iter()
        .find(|(g, _)| g == group)
        .and_then(|(_, resolution)| match resolution {
            Resolution::Party(p) => Some(p.clone()),
            Resolution::Role(r) => match directory.members(r).as_deref() {
                Some([only]) => Some(only.clone()),
                _ => None,
            },
        });
    GroupResolution {
        resolved: found.is_some(),
        party: found.unwrap_or_else(|| rule.rule.fallback.clone()),
        rule: Some(rule.version),
    }
}
