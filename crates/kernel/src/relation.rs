//! The eight canonical relations as a map of `rel`, optional `source`, `target` and optional `qualifier` (C-25, P-14, P-73); there is no `depends_on` (C-26) and a qualifier belongs to exactly one relation (C-27).

use crate::catalog::{BASIS_ROLE_URI, CoreDerivedRole};
use crate::id::{Digest, PartyRef, RecordId, WorkId};
use crate::reason::{Reason, Schema, wire_enum};
use crate::uri::{ExternalRef, TypeUri};

wire_enum! {
    /// The eight canonical relation names (C-25, P-14).
    RelationName {
        /// A Party takes part in a Work.
        EngagedIn => "engaged_in",
        /// A record or external object falls within a Work.
        Concerns => "concerns",
        /// Work composition.
        PartOf => "part_of",
        /// A record serves another.
        Serves => "serves",
        /// Correction by a new record (P-24).
        Supersedes => "supersedes",
        /// Lineage with a typed role (C-27).
        DerivedFrom => "derived_from",
        /// Representation between Parties (E-13).
        OnBehalfOf => "on_behalf_of",
        /// A plain reference (C-13).
        References => "references",
    }
}

/// A typed relation endpoint on the wire (P-73).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// `["record", Digest]`.
    Record(RecordId),
    /// `["work", WorkID]`.
    Work(WorkId),
    /// `["party", PartyRef]`.
    Party(PartyRef),
    /// `["external", ExternalRef]`.
    External(ExternalRef),
    /// `["evidence", Digest]`.
    Evidence(Digest),
}

/// The source of a `concerns` relation (C-34).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConcernsSource {
    /// A record.
    Record(RecordId),
    /// An external object.
    External(ExternalRef),
}

/// The target of a `derived_from` relation (C-27, EV-2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerivedTarget {
    /// A record.
    Record(RecordId),
    /// Evidence.
    Evidence(Digest),
    /// An external object.
    External(ExternalRef),
}

/// The target of a `references` relation (C-13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceTarget {
    /// An external object.
    External(ExternalRef),
    /// A record.
    Record(RecordId),
}

/// The typed role of a `derived_from` relation (C-27).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerivedRole {
    /// A core role.
    Core(CoreDerivedRole),
    /// A Practice role; it must map to a core role (C-5).
    Extension(TypeUri),
}

/// A canonical relation; the source and target types each relation allows are fixed here (C-25, P-73).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Relation {
    /// `engaged_in`: Party to Work.
    EngagedIn {
        /// The Party.
        source: PartyRef,
        /// The Work.
        target: WorkId,
        /// A Practice qualifier such as a role label.
        qualifier: Option<TypeUri>,
    },
    /// `concerns`: record or external object to Work.
    Concerns {
        /// The record or external object.
        source: ConcernsSource,
        /// The Work.
        target: WorkId,
        /// A Practice qualifier.
        qualifier: Option<TypeUri>,
    },
    /// `part_of`: Work to Work.
    PartOf {
        /// The part.
        source: WorkId,
        /// The whole.
        target: WorkId,
        /// A Practice qualifier.
        qualifier: Option<TypeUri>,
    },
    /// `serves`: record to record; no source means this record.
    Serves {
        /// The serving record.
        source: Option<RecordId>,
        /// The served record.
        target: RecordId,
        /// A Practice qualifier.
        qualifier: Option<TypeUri>,
    },
    /// `supersedes`: this record replaces the target (P-24).
    Supersedes {
        /// The superseded record.
        target: RecordId,
        /// A Practice qualifier.
        qualifier: Option<TypeUri>,
    },
    /// `derived_from` with its required role (C-27).
    DerivedFrom {
        /// The derived record; no source means this record.
        source: Option<RecordId>,
        /// The origin.
        target: DerivedTarget,
        /// The role.
        role: DerivedRole,
    },
    /// `on_behalf_of`: Party to Party (E-13).
    OnBehalfOf {
        /// The representative.
        source: PartyRef,
        /// The principal.
        target: PartyRef,
        /// A Practice qualifier.
        qualifier: Option<TypeUri>,
    },
    /// `references`: record to external object or record.
    References {
        /// The referring record; no source means this record.
        source: Option<RecordId>,
        /// The referenced object.
        target: ReferenceTarget,
        /// A Practice qualifier.
        qualifier: Option<TypeUri>,
    },
}

const MISMATCH: Reason = Reason::Schema(Schema::Relation);

impl Relation {
    /// Builds a relation from its decoded wire parts, rejecting a ninth name, an endpoint type the relation does not allow and a qualifier that belongs to another relation (C-25, C-26, C-27, P-14, P-73).
    ///
    /// # Errors
    ///
    /// Returns `schema:relation` as the reason the record is rejected.
    pub fn from_wire(
        rel: &str,
        source: Option<Endpoint>,
        target: Endpoint,
        qualifier: Option<&str>,
    ) -> Result<Self, Reason> {
        let name = RelationName::from_wire_name(rel).ok_or(MISMATCH)?;
        if name == RelationName::DerivedFrom {
            let role = derived_role(qualifier.ok_or(MISMATCH)?)?;
            let source = optional_record(source.as_ref())?;
            let target = match target {
                Endpoint::Record(r) => DerivedTarget::Record(r),
                Endpoint::Evidence(d) => DerivedTarget::Evidence(d),
                Endpoint::External(e) => DerivedTarget::External(e),
                Endpoint::Work(_) | Endpoint::Party(_) => return Err(MISMATCH),
            };
            return Ok(Self::DerivedFrom {
                source,
                target,
                role,
            });
        }
        let qualifier = qualifier
            .map(|q| TypeUri::parse(q).ok_or(MISMATCH))
            .transpose()?;
        match (name, source, target) {
            (RelationName::EngagedIn, Some(Endpoint::Party(source)), Endpoint::Work(target)) => {
                Ok(Self::EngagedIn {
                    source,
                    target,
                    qualifier,
                })
            }
            (RelationName::Concerns, Some(source), Endpoint::Work(target)) => {
                let source = match source {
                    Endpoint::Record(r) => ConcernsSource::Record(r),
                    Endpoint::External(e) => ConcernsSource::External(e),
                    _ => return Err(MISMATCH),
                };
                Ok(Self::Concerns {
                    source,
                    target,
                    qualifier,
                })
            }
            (RelationName::PartOf, Some(Endpoint::Work(source)), Endpoint::Work(target)) => {
                Ok(Self::PartOf {
                    source,
                    target,
                    qualifier,
                })
            }
            (RelationName::Serves, source, Endpoint::Record(target)) => Ok(Self::Serves {
                source: optional_record(source.as_ref())?,
                target,
                qualifier,
            }),
            (RelationName::Supersedes, None, Endpoint::Record(target)) => {
                Ok(Self::Supersedes { target, qualifier })
            }
            (RelationName::OnBehalfOf, Some(Endpoint::Party(source)), Endpoint::Party(target)) => {
                Ok(Self::OnBehalfOf {
                    source,
                    target,
                    qualifier,
                })
            }
            (RelationName::References, source, target) => {
                let target = match target {
                    Endpoint::External(e) => ReferenceTarget::External(e),
                    Endpoint::Record(r) => ReferenceTarget::Record(r),
                    _ => return Err(MISMATCH),
                };
                Ok(Self::References {
                    source: optional_record(source.as_ref())?,
                    target,
                    qualifier,
                })
            }
            _ => Err(MISMATCH),
        }
    }

    /// The relation name.
    #[must_use]
    pub const fn name(&self) -> RelationName {
        match self {
            Self::EngagedIn { .. } => RelationName::EngagedIn,
            Self::Concerns { .. } => RelationName::Concerns,
            Self::PartOf { .. } => RelationName::PartOf,
            Self::Serves { .. } => RelationName::Serves,
            Self::Supersedes { .. } => RelationName::Supersedes,
            Self::DerivedFrom { .. } => RelationName::DerivedFrom,
            Self::OnBehalfOf { .. } => RelationName::OnBehalfOf,
            Self::References { .. } => RelationName::References,
        }
    }
}

fn optional_record(source: Option<&Endpoint>) -> Result<Option<RecordId>, Reason> {
    match source {
        None => Ok(None),
        Some(Endpoint::Record(r)) => Ok(Some(*r)),
        Some(_) => Err(MISMATCH),
    }
}

fn derived_role(qualifier: &str) -> Result<DerivedRole, Reason> {
    if let Some(core) = CoreDerivedRole::from_uri(qualifier) {
        return Ok(DerivedRole::Core(core));
    }
    if qualifier == BASIS_ROLE_URI {
        return Err(MISMATCH);
    }
    TypeUri::parse(qualifier)
        .map(DerivedRole::Extension)
        .ok_or(MISMATCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::Digest;

    const FULFILLS: &str = "https://suiss.app/ns/work/derived_from/fulfills";

    fn record() -> Endpoint {
        Endpoint::Record(RecordId(Digest::sha256([1; 32])))
    }

    fn work() -> Endpoint {
        Endpoint::Work(WorkId::from_bytes([2; 16]))
    }

    fn party() -> Endpoint {
        Endpoint::Party(PartyRef::new("party:acme:alice").unwrap())
    }

    // C-25 P-14
    #[test]
    fn c_25_p_14_exactly_eight_relation_names() {
        assert_eq!(RelationName::ALL.len(), 8);
        for name in RelationName::ALL {
            assert_eq!(RelationName::from_wire_name(name.wire_name()), Some(*name));
        }
        assert_eq!(
            Relation::from_wire("derived-from", None, record(), Some(FULFILLS)),
            Err(MISMATCH)
        );
    }

    // C-26
    #[test]
    fn c_26_depends_on_is_not_a_relation() {
        assert_eq!(
            Relation::from_wire("depends_on", None, record(), None),
            Err(MISMATCH)
        );
    }

    // C-27 P-81
    #[test]
    fn c_27_p_81_derived_from_requires_a_full_uri_role_and_basis_is_not_one() {
        assert_eq!(
            Relation::from_wire("derived_from", None, record(), None),
            Err(MISMATCH)
        );
        assert_eq!(
            Relation::from_wire("derived_from", None, record(), Some(BASIS_ROLE_URI)),
            Err(MISMATCH)
        );
        assert_eq!(
            Relation::from_wire("derived_from", None, record(), Some("fulfills")),
            Err(MISMATCH)
        );
        assert!(matches!(
            Relation::from_wire("derived_from", None, record(), Some(FULFILLS)),
            Ok(Relation::DerivedFrom {
                role: DerivedRole::Core(CoreDerivedRole::Fulfills),
                ..
            })
        ));
        assert!(matches!(
            Relation::from_wire(
                "derived_from",
                None,
                record(),
                Some("https://procurement.example/ns/role/backs")
            ),
            Ok(Relation::DerivedFrom {
                role: DerivedRole::Extension(_),
                ..
            })
        ));
    }

    // C-27 P-14
    #[test]
    fn c_27_p_14_core_roles_belong_only_to_derived_from() {
        assert_eq!(
            Relation::from_wire("serves", None, record(), Some("supports")),
            Err(MISMATCH)
        );
        assert_eq!(
            Relation::from_wire("derived_from", None, record(), Some("supports")),
            Err(MISMATCH)
        );
        assert!(
            Relation::from_wire(
                "engaged_in",
                Some(party()),
                work(),
                Some("https://procurement.example/ns/role/buyer")
            )
            .is_ok()
        );
    }

    // P-73
    #[test]
    fn p_73_each_relation_allows_only_its_endpoint_types() {
        assert!(Relation::from_wire("part_of", Some(work()), work(), None).is_ok());
        assert_eq!(
            Relation::from_wire("part_of", Some(work()), record(), None),
            Err(MISMATCH)
        );
        assert_eq!(
            Relation::from_wire("concerns", None, work(), None),
            Err(MISMATCH)
        );
        assert!(Relation::from_wire("concerns", Some(record()), work(), None).is_ok());
        assert_eq!(
            Relation::from_wire("supersedes", Some(record()), record(), None),
            Err(MISMATCH)
        );
        assert!(Relation::from_wire("on_behalf_of", Some(party()), party(), None).is_ok());
        assert_eq!(
            Relation::from_wire("engaged_in", None, work(), None),
            Err(MISMATCH)
        );
        assert_eq!(
            Relation::from_wire("references", None, work(), None),
            Err(MISMATCH)
        );
        assert_eq!(
            Relation::from_wire("derived_from", None, work(), Some(FULFILLS)),
            Err(MISMATCH)
        );
    }
}
