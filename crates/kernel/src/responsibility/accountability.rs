use alloc::string::String;
use alloc::vec::Vec;

use super::org_rule::{OrgRuleVersion, Regime, resolve_group, rule_for};
use super::queue::QueueVersion;
use crate::commitment::{CommitmentView, Proposal, params};
use crate::id::{PartyRef, RecordId};
use crate::ontology::Obligor;
use crate::reason::wire_enum;
use crate::record::Record;
use crate::validate::ActorType;

/// What Access says about Parties, as derivation input: the actor type, whether the Party is disabled, and the members of a group or role; Work defines no membership and never records a Party as disabled (RC-1, RC-7, RC-48, P-12).
pub trait Directory {
    /// The Party's Access actor type, if Access knows it.
    fn actor(&self, party: &PartyRef) -> Option<ActorType>;
    /// Whether Access reports the Party as disabled.
    fn disabled(&self, party: &PartyRef) -> bool;
    /// The members of an Access group or role, if Access knows it.
    fn members(&self, group: &str) -> Option<Vec<PartyRef>>;
}

wire_enum! {
    /// Where the accountable Party comes from: an explicit field, an explicit taking-over or an accepted transfer, an `on_behalf_of` delegation, an accepted obligor or owner role, the requester while no Party is bound, or the organisation rule (RC-5, RC-48).
    AccountabilitySource {
        /// The `accountable` field of the request, or a group it names resolved by the organisation rule.
        Explicit => "explicit",
        /// An explicit taking-over by the Party itself.
        TakenOver => "taken_over",
        /// A transfer the new Party explicitly accepted.
        Transferred => "transferred",
        /// A principal on an `on_behalf_of` chain.
        OnBehalfOf => "on_behalf_of",
        /// The accepted obligor role.
        Obligor => "obligor",
        /// The owner role of the queue.
        QueueOwner => "queue_owner",
        /// The requester, while no Party is bound.
        Requester => "requester",
        /// The organisation rule's fallback Party or the organisation itself.
        OrgRule => "org_rule",
    }
}

/// The explicit accountable Party in force on a commitment, with the record and source that made it (RC-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explicit {
    /// The Party.
    pub party: PartyRef,
    /// The record that made it accountable.
    pub record: RecordId,
    /// How.
    pub source: AccountabilitySource,
}

/// The accountability a commitment's records declare: the explicit Party or a group to resolve, and an open transfer; the previous accountable stays responsible until the new Party accepts (RC-5, RC-7).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Accountable {
    /// The explicit accountable Party in force.
    pub explicit: Option<Explicit>,
    /// A group or role the request names, which only the organisation rule resolves to one Party (RC-1).
    pub group: Option<String>,
    /// An open transfer proposal and the Party proposed.
    pub transfer: Option<Proposal>,
}

impl Accountable {
    /// What a `request` declares: its `accountable` Party or its `accountable_group` (RC-1, RC-5).
    #[must_use]
    pub fn of(request: &Record, id: RecordId) -> Self {
        Self {
            explicit: params::party(request, "accountable").map(|party| Explicit {
                party,
                record: id,
                source: AccountabilitySource::Explicit,
            }),
            group: params::text(request, "accountable_group").map(String::from),
            transfer: None,
        }
    }
}

/// The single accountable Party of a commitment or queue as derived: where it comes from, whether it was derived rather than declared, the "no one responsible" signal when a disabled Party fell away, the organisation rule version a resolution used, the internal responsible under the `organization` regime and an open transfer (RC-1, RC-5, RC-6, RC-7, RC-48).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accountability {
    /// The accountable Party.
    pub party: PartyRef,
    /// Where it comes from.
    pub source: AccountabilitySource,
    /// Derived rather than declared or accepted; shown as derived (RC-5).
    pub derived: bool,
    /// A Party Access reports disabled fell away; the work carries the "no one responsible" signal until a new Party accepts (RC-7).
    pub unowned: bool,
    /// The organisation rule version the derivation used.
    pub rule: Option<RecordId>,
    /// The first human or organisation link under the `organization` regime, which ends in the organisation Party (RC-1, RC-48).
    pub internal: Option<PartyRef>,
    /// An open transfer; the accountable Party stays until the new one accepts (RC-7).
    pub transfer: Option<Proposal>,
}

struct Link {
    party: PartyRef,
    source: AccountabilitySource,
    rule: Option<RecordId>,
    declared: bool,
}

fn link(party: &PartyRef, source: AccountabilitySource) -> Link {
    Link {
        party: party.clone(),
        source,
        rule: None,
        declared: false,
    }
}

fn walk(
    links: Vec<Link>,
    organization: &PartyRef,
    rule: Option<&OrgRuleVersion>,
    directory: &dyn Directory,
    transfer: Option<Proposal>,
) -> Accountability {
    let regime = rule.map_or(Regime::Default, |r| r.rule.regime);
    let mut unowned = false;
    let mut internal: Option<PartyRef> = None;
    let mut chosen: Option<Link> = None;
    for l in links {
        if directory.disabled(&l.party) {
            unowned = true;
            continue;
        }
        let actor = directory.actor(&l.party);
        if internal.is_none() && actor.is_some_and(|a| Regime::Default.ends_in(a)) {
            internal = Some(l.party.clone());
        }
        if actor.is_some_and(|a| regime.ends_in(a)) {
            chosen = Some(l);
            break;
        }
    }
    let rule_version = rule.map(|r| r.version);
    match (regime, chosen) {
        (Regime::Default, Some(l)) => Accountability {
            party: l.party,
            source: l.source,
            derived: !l.declared,
            unowned,
            rule: l.rule,
            internal: None,
            transfer,
        },
        (Regime::Organization, Some(l)) => Accountability {
            party: l.party,
            source: l.source,
            derived: !l.declared,
            unowned,
            rule: rule_version,
            internal,
            transfer,
        },
        (regime, None) => Accountability {
            party: match (regime, rule) {
                (Regime::Organization, _) | (_, None) => organization.clone(),
                (Regime::Default, Some(r)) => r.rule.fallback.clone(),
            },
            source: AccountabilitySource::OrgRule,
            derived: true,
            unowned,
            rule: rule_version,
            internal: if regime == Regime::Organization {
                internal
            } else {
                None
            },
            transfer,
        },
    }
}

fn explicit_links(
    view: &CommitmentView,
    organization: &PartyRef,
    rule: Option<&OrgRuleVersion>,
    directory: &dyn Directory,
) -> Option<Link> {
    if let Some(e) = &view.accountability.explicit {
        return Some(Link {
            party: e.party.clone(),
            source: e.source,
            rule: None,
            declared: true,
        });
    }
    let group = view.accountability.group.as_deref()?;
    let resolution = resolve_group(rule, organization, group, directory);
    Some(Link {
        party: resolution.party,
        source: if resolution.resolved {
            AccountabilitySource::Explicit
        } else {
            AccountabilitySource::OrgRule
        },
        rule: resolution.rule,
        declared: resolution.resolved,
    })
}

/// Derives the single accountable Party of a commitment: the explicit Party (or the group the organisation rule resolves) first; otherwise, by the derived chain, the queue owner while the work is pooled, the bound obligor and the principals of its binding record, or the requester and its principals while no Party is bound; the first link that is not disabled in Access and that the regime counts as an end is accountable; a chain that ends nowhere falls to the rule's fallback Party, or to the organisation itself; under the `organization` regime the end is always the organisation Party. An agent is never the end, and a derived result is marked derived (RC-1, RC-5, RC-6, RC-7, RC-48).
#[must_use]
pub fn accountability(
    view: &CommitmentView,
    organization: &PartyRef,
    rules: &[OrgRuleVersion],
    directory: &dyn Directory,
) -> Accountability {
    let rule = rule_for(rules, organization);
    let mut links: Vec<Link> = Vec::new();
    links.extend(explicit_links(view, organization, rule, directory));
    match (&view.obligor, &view.assignment.hold) {
        (Obligor::Queue(_), _) => {
            if let Some(q) = &view.assignment.definition {
                links.push(link(&q.definition.owner, AccountabilitySource::QueueOwner));
                for p in q.author_chain.iter().filter(|p| **p != q.definition.owner) {
                    links.push(link(p, AccountabilitySource::OnBehalfOf));
                }
            }
        }
        (Obligor::Party(obligor), Some(hold)) => {
            links.push(link(obligor, AccountabilitySource::Obligor));
            for p in hold.chain.iter().filter(|p| *p != obligor) {
                links.push(link(p, AccountabilitySource::OnBehalfOf));
            }
        }
        (Obligor::Party(_), None) => {}
    }
    if view.assignment.hold.is_none() {
        links.push(link(&view.obligee, AccountabilitySource::Requester));
        for p in view
            .requester
            .iter()
            .chain(&view.principal)
            .filter(|p| **p != view.obligee)
        {
            links.push(link(p, AccountabilitySource::OnBehalfOf));
        }
    }
    walk(
        links,
        organization,
        rule,
        directory,
        view.accountability.transfer.clone(),
    )
}

/// Derives the single accountable Party of a queue: its owner, then the author chain of the definition in force, then the organisation rule's fallback; a queue is never ownerless (RC-7, RC-12, RC-48).
#[must_use]
pub fn queue_accountability(
    queue: &QueueVersion,
    organization: &PartyRef,
    rules: &[OrgRuleVersion],
    directory: &dyn Directory,
) -> Accountability {
    let owner = Link {
        party: queue.definition.owner.clone(),
        source: AccountabilitySource::QueueOwner,
        rule: None,
        declared: true,
    };
    let links: Vec<Link> = core::iter::once(owner)
        .chain(
            queue
                .author_chain
                .iter()
                .filter(|p| **p != queue.definition.owner)
                .map(|p| link(p, AccountabilitySource::OnBehalfOf)),
        )
        .collect();
    walk(
        links,
        organization,
        rule_for(rules, organization),
        directory,
        None,
    )
}
