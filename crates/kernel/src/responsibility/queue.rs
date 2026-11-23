use alloc::string::String;
use alloc::vec::Vec;

use super::chains;
use crate::catalog::DeclarationSubtype;
use crate::commitment::params;
use crate::derive::{Derivation, Entry};
use crate::id::{PartyRef, RecordId};
use crate::reason::wire_enum;
use crate::record::{ParamScalar, ParamValue, Record};
use crate::uri::TypeUri;

wire_enum! {
    /// The four distribution methods of a versioned distribution policy; `pull` when none is declared (RC-11, RC-21).
    DistributionMethod {
        /// The queue owner or a rule offers the work to a named Party.
        Push => "push",
        /// Candidates claim the work.
        Pull => "pull",
        /// Candidates bid; the choice is an offer whose acceptance binds.
        Bid => "bid",
        /// A rule offers by capability statements and open workload.
        Skill => "skill",
    }
}

wire_enum! {
    /// What happens when an ownership lease runs out (RC-18).
    LeaseExpiry {
        /// The Work service Party writes an `unclaim` and the work returns to the pool.
        ReturnToPool => "return_to_pool",
        /// The lease is kept and the queue owner gets an attention signal.
        KeepAndSignal => "keep_and_signal",
    }
}

/// The candidate set of a queue: named Parties, or an Access group or role whose membership Access holds (RC-11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Candidates {
    /// The Parties listed.
    Parties(Vec<PartyRef>),
    /// An Access group or role reference.
    Group(String),
}

/// A declared ownership lease: its length in milliseconds and what its end does (RC-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    /// The lease length in milliseconds.
    pub duration: u64,
    /// What happens when it runs out.
    pub expiry: LeaseExpiry,
}

/// A queue definition: a typed Declaration and never a new concept, with its owner, candidates, distribution policy, start deadline, lease, excluded Parties, ping-pong threshold, WIP limit and required skills (RC-10, RC-11, RC-12, RC-21, RC-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueDefinition {
    /// The single Party responsible for the work in the queue (RC-12).
    pub owner: PartyRef,
    /// Who may take work from it.
    pub candidates: Candidates,
    /// The distribution method; `pull` when none is declared.
    pub distribution: DistributionMethod,
    /// How long pooled work may wait to be taken, in milliseconds (RC-13).
    pub start_within: Option<u64>,
    /// The ownership lease (RC-18).
    pub lease: Option<Lease>,
    /// Parties that may not take work from it, for separation of duties.
    pub excluded: Vec<PartyRef>,
    /// The forwarding count above which the owner gets an attention signal (RC-14).
    pub ping_pong_threshold: Option<u64>,
    /// The open workload above which a Party is overloaded (RC-24).
    pub wip_limit: Option<u64>,
    /// The capabilities a skill-based policy matches against capability statements (RC-21, RC-23).
    pub skills: Vec<TypeUri>,
}

fn uris(record: &Record, name: &str) -> Vec<TypeUri> {
    match record.param(name) {
        Some(ParamValue::List(items)) => items
            .iter()
            .filter_map(|s| match s {
                ParamScalar::Text(t) => TypeUri::parse(t),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

impl QueueDefinition {
    /// The definition a core `queue_definition` declares; `None` for any other record or one without its owner and exactly one candidate set, which the record rules reject (RC-11, RC-12).
    #[must_use]
    pub fn of(record: &Record) -> Option<Self> {
        if chains::subtype_of(record)? != DeclarationSubtype::QueueDefinition {
            return None;
        }
        let candidates = match (
            params::parties(record, "candidates"),
            params::text(record, "candidate_group"),
        ) {
            (Some(p), None) => Candidates::Parties(p),
            (None, Some(g)) => Candidates::Group(String::from(g)),
            _ => return None,
        };
        let expiry = params::text(record, "lease_expiry").and_then(LeaseExpiry::from_wire_name);
        let lease = match (params::uint(record, "lease"), expiry) {
            (Some(duration), Some(expiry)) => Some(Lease { duration, expiry }),
            (None, None) => None,
            _ => return None,
        };
        Some(Self {
            owner: params::party(record, "owner")?,
            candidates,
            distribution: params::text(record, "distribution")
                .and_then(DistributionMethod::from_wire_name)
                .unwrap_or(DistributionMethod::Pull),
            start_within: params::uint(record, "start_within"),
            lease,
            excluded: params::parties(record, "excluded").unwrap_or_default(),
            ping_pong_threshold: params::uint(record, "ping_pong_threshold"),
            wip_limit: params::uint(record, "wip_limit"),
            skills: uris(record, "skills"),
        })
    }

    /// Whether `party` may take work from the queue as far as the records tell: `Some(false)` when it is excluded or outside a Party list, `None` when an Access group decides; taking work also needs Access (RC-11, RC-20).
    #[must_use]
    pub fn admits(&self, party: &PartyRef) -> Option<bool> {
        if self.excluded.contains(party) {
            return Some(false);
        }
        match &self.candidates {
            Candidates::Parties(p) => Some(p.contains(party)),
            Candidates::Group(_) => None,
        }
    }
}

/// One version of a queue definition: the chain root is the queue's identity and the version record names the policy version every assignment records (RC-10, RC-19, RC-22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueVersion {
    /// The queue: the root of the definition chain.
    pub queue: RecordId,
    /// This version's record.
    pub version: RecordId,
    /// Its ledger position.
    pub position: u64,
    /// The author, its `on_behalf_of` rings and capacity principal, the upper links of the queue's accountability (RC-7).
    pub author_chain: Vec<PartyRef>,
    /// The definition.
    pub definition: QueueDefinition,
}

/// Every queue definition version with normative effect, in ledger order; a new version supersedes the previous one and the queue keeps its identity (RC-10).
#[must_use]
pub fn queue_versions(entries: &[Entry<'_>], derivation: &Derivation) -> Vec<QueueVersion> {
    chains::versions(entries, derivation, DeclarationSubtype::QueueDefinition)
        .into_iter()
        .filter_map(|v| {
            QueueDefinition::of(v.record).map(|definition| QueueVersion {
                queue: v.root,
                version: v.id,
                position: v.position,
                author_chain: params::chain(v.record),
                definition,
            })
        })
        .collect()
}

/// The version of `queue` in force before ledger position `before` (RC-19).
#[must_use]
pub fn in_force(versions: &[QueueVersion], queue: RecordId, before: u64) -> Option<&QueueVersion> {
    versions
        .iter()
        .rev()
        .find(|v| v.queue == queue && v.position < before)
}
