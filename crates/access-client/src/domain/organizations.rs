//! The organization map (E-3, T-96 item 4, Access E42): an Access organization is the Work organization of the same tenant under Access's own id, a lower-case UUID that Work keeps in Access's spelling. An `organization.created` or `organization.updated` event maps it or moves it to the event's Access position, never back; the tenant snapshot maps every organization it lists, and an organization Work knows that a snapshot with a list no longer names is reported, never removed.

use std::collections::BTreeSet;

use crate::domain::AccessError;
use crate::domain::pairing::is_uuid;

/// An Access organization id.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrganizationId(String);

impl OrganizationId {
    /// Reads a canonical lower-case UUID.
    ///
    /// # Errors
    /// [`AccessError::Identifier`].
    pub fn parse(text: &str) -> Result<Self, AccessError> {
        if is_uuid(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(AccessError::Identifier("organization"))
        }
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where an event stands in Access's log, `access_position`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccessPosition {
    /// The log position.
    pub pos: u64,
    /// The index inside the position.
    pub idx: u64,
}

/// One change to the map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrganizationChange {
    /// The tenant snapshot lists the organization.
    Listed {
        /// The organization.
        organization: OrganizationId,
    },
    /// An `organization.*` event names it.
    Event {
        /// The organization.
        organization: OrganizationId,
        /// The event's Access position.
        position: AccessPosition,
        /// Access's time of the event, Unix milliseconds.
        at_ms: u64,
    },
}

impl OrganizationChange {
    /// The organization the change is about.
    #[must_use]
    pub const fn organization(&self) -> &OrganizationId {
        match self {
            Self::Listed { organization } | Self::Event { organization, .. } => organization,
        }
    }
}

/// What a change did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrganizationOutcome {
    /// The organization was not mapped; it is now.
    Mapped,
    /// A mapped organization moved to a later Access position.
    Moved,
    /// Nothing changed: it is mapped already, at this position or a later one.
    Known,
}

/// The mapped organizations a snapshot's list no longer names. An empty list names nothing and
/// reports nothing: Access serves the list empty until its snapshot carries organizations.
#[must_use]
pub fn unlisted(known: &[OrganizationId], listed: &[OrganizationId]) -> Vec<OrganizationId> {
    if listed.is_empty() {
        return Vec::new();
    }
    let listed: BTreeSet<&OrganizationId> = listed.iter().collect();
    known
        .iter()
        .filter(|o| !listed.contains(o))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "019a0000-0000-7000-8000-0000000000b1";
    const B: &str = "019a0000-0000-7000-8000-0000000000b2";

    // E-3
    #[test]
    fn e_3_an_organization_id_is_access_s_lower_case_uuid() {
        assert_eq!(OrganizationId::parse(A).unwrap().as_str(), A);
        for bad in [
            "",
            "org_01HZ",
            "019A0000-0000-7000-8000-0000000000B1",
            "019a0000-0000-7000-8000-0000000000b",
            "019a0000000070008000000000000b1",
        ] {
            assert!(OrganizationId::parse(bad).is_err(), "{bad}");
        }
    }

    // E-3
    #[test]
    fn e_3_an_organization_a_listing_snapshot_drops_is_reported_and_an_empty_list_reports_nothing()
    {
        let a = OrganizationId::parse(A).unwrap();
        let b = OrganizationId::parse(B).unwrap();
        let known = [a.clone(), b.clone()];
        assert_eq!(unlisted(&known, std::slice::from_ref(&a)), vec![b.clone()]);
        assert_eq!(unlisted(&known, &known), Vec::new());
        assert_eq!(unlisted(&known, &[]), Vec::new());
        assert_eq!(unlisted(&[], std::slice::from_ref(&a)), Vec::new());
        let change = OrganizationChange::Event {
            organization: b.clone(),
            position: AccessPosition { pos: 42, idx: 0 },
            at_ms: 1,
        };
        assert_eq!(change.organization(), &b);
        assert_eq!(
            OrganizationChange::Listed {
                organization: a.clone()
            }
            .organization(),
            &a
        );
        assert!(AccessPosition { pos: 42, idx: 1 } > AccessPosition { pos: 42, idx: 0 });
        assert!(AccessPosition { pos: 43, idx: 0 } > AccessPosition { pos: 42, idx: 9 });
    }
}
