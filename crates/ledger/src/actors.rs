//! Actor types at admission (P-12, C-17, INV-18, EV-35; MD-7 item 3): the ledger derives the actor type of a record's author, of every `on_behalf_of` ring and of every evidence presenter from the Access identity binding of its Party, the `actor_kind` of that Party's signed key lookup entry, and writes it into the envelope; the request only declares a type, which the envelope carries as `declared_unverified` for a Party without a binding, and never names a source.

use std::collections::BTreeMap;

use work_kernel::id::PartyRef;
use work_kernel::record::RecordCore;
use work_kernel::validate::{ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes};

/// The actor types Access's identity bindings name, Party by Party (P-12): each from the
/// `actor_kind` of a signed key lookup entry of that Party, which Access never changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActorBindings(BTreeMap<PartyRef, ActorType>);

/// Access named two actor types for one Party.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Access named two actor types for one Party")]
pub struct BindingConflict;

impl ActorBindings {
    /// No bindings: every Party is `declared_unverified`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that Access binds `party` to `actor_type`.
    ///
    /// # Errors
    /// [`BindingConflict`] when Access already named another type for `party`.
    pub fn bind(&mut self, party: PartyRef, actor_type: ActorType) -> Result<(), BindingConflict> {
        match self.0.get(&party) {
            Some(bound) if *bound != actor_type => Err(BindingConflict),
            Some(_) => Ok(()),
            None => {
                self.0.insert(party, actor_type);
                Ok(())
            }
        }
    }

    /// The type Access binds `party` to.
    #[must_use]
    pub fn of(&self, party: &PartyRef) -> Option<ActorType> {
        self.0.get(party).copied()
    }

    fn entry(&self, declared: &Declared) -> ActorTypeEntry {
        self.of(&declared.party).map_or(
            ActorTypeEntry {
                actor_type: declared.actor_type,
                source: ActorTypeSource::DeclaredUnverified,
            },
            |actor_type| ActorTypeEntry {
                actor_type,
                source: ActorTypeSource::AccessBinding,
            },
        )
    }
}

/// A Party of the record and the actor type the request declares for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared {
    /// The Party, as the record names it.
    pub party: PartyRef,
    /// The declared type, written only when Access has no binding for the Party.
    pub actor_type: ActorType,
}

/// What a request declares for the author, every `on_behalf_of` ring in chain order and every
/// evidence presenter in `evidence` order (P-12, EV-35).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredActors {
    /// The author.
    pub author: Declared,
    /// One per `on_behalf_of` ring.
    pub on_behalf_of: Vec<Declared>,
    /// One per evidence presenter.
    pub evidence: Vec<Declared>,
}

impl DeclaredActors {
    /// The envelope annotation: each Party's type from `bindings`, `access_binding`, or the
    /// declared type, `declared_unverified`.
    #[must_use]
    pub fn derive(&self, bindings: &ActorBindings) -> ActorTypes {
        ActorTypes {
            author: bindings.entry(&self.author),
            on_behalf_of: self
                .on_behalf_of
                .iter()
                .map(|d| bindings.entry(d))
                .collect(),
            evidence: self.evidence.iter().map(|d| bindings.entry(d)).collect(),
        }
    }

    /// Whether the declared Parties are the record's, in its order.
    #[must_use]
    pub fn names(&self, core: &RecordCore) -> bool {
        let rings = core.on_behalf_of.as_deref().unwrap_or_default();
        let presenters = core.evidence.as_deref().unwrap_or_default();
        self.author.party == core.author
            && self.on_behalf_of.len() == rings.len()
            && self.evidence.len() == presenters.len()
            && self
                .on_behalf_of
                .iter()
                .zip(rings)
                .all(|(d, p)| d.party == *p)
            && self
                .evidence
                .iter()
                .zip(presenters)
                .all(|(d, e)| d.party == e.presenter)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn party(s: &str) -> PartyRef {
        PartyRef::new(s).unwrap()
    }

    fn declared(s: &str, actor_type: ActorType) -> Declared {
        Declared {
            party: party(s),
            actor_type,
        }
    }

    // P-12 C-17 MD-7
    #[test]
    fn p_12_a_bound_party_takes_access_s_type_and_an_unbound_one_is_declared_unverified() {
        let mut bindings = ActorBindings::new();
        bindings
            .bind(party("party:acme:agent"), ActorType::Agent)
            .unwrap();
        bindings
            .bind(party("party:acme:buyer"), ActorType::Organization)
            .unwrap();
        let actors = DeclaredActors {
            author: declared("party:acme:agent", ActorType::Human),
            on_behalf_of: vec![declared("party:acme:buyer", ActorType::Human)],
            evidence: vec![declared("party:acme:camera", ActorType::Machine)],
        };
        let derived = actors.derive(&bindings);
        assert_eq!(
            derived.author,
            ActorTypeEntry {
                actor_type: ActorType::Agent,
                source: ActorTypeSource::AccessBinding,
            }
        );
        assert_eq!(
            derived.on_behalf_of,
            [ActorTypeEntry {
                actor_type: ActorType::Organization,
                source: ActorTypeSource::AccessBinding,
            }]
        );
        assert_eq!(
            derived.evidence,
            [ActorTypeEntry {
                actor_type: ActorType::Machine,
                source: ActorTypeSource::DeclaredUnverified,
            }]
        );
        let unbound = actors.derive(&ActorBindings::new());
        assert_eq!(
            unbound.author,
            ActorTypeEntry {
                actor_type: ActorType::Human,
                source: ActorTypeSource::DeclaredUnverified,
            }
        );
    }

    // C-17 P-12
    #[test]
    fn c_17_access_names_one_type_per_party() {
        let mut bindings = ActorBindings::new();
        let agent = party("party:acme:agent");
        bindings.bind(agent.clone(), ActorType::Agent).unwrap();
        bindings.bind(agent.clone(), ActorType::Agent).unwrap();
        assert_eq!(
            bindings.bind(agent.clone(), ActorType::Human),
            Err(BindingConflict)
        );
        assert_eq!(bindings.of(&agent), Some(ActorType::Agent));
    }
}
