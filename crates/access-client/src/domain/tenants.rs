//! Tenant snapshots and their reconciliation (T-96 item 4 and note; Access OP-149 m.4, m.15 (i), (j)): Access tenant ids are kept opaque in Access's spelling, a snapshot whose `version` did not change is no work, organizations stay unread until Access's organization model, and a tenant Work knows that Access no longer lists is reported, never removed.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use work_proto::id::TenantId;

use crate::domain::AccessError;
use crate::domain::discovery::{Issuer, Template};
use crate::domain::pairing::RealmId;

/// How often the reconciliation runs, besides at start (T-96 item 4).
pub const RECONCILE_INTERVAL_MS: u64 = 60 * 60 * 1000;

/// Most pages one reconciliation reads (PD); a longer list is not reconciled at all.
pub const MAX_PAGES: usize = 10_000;

/// A tenant's lifecycle state in Access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantStatus {
    /// Being set up.
    Provisioning,
    /// In use.
    Active,
    /// Suspended.
    Suspended,
    /// Deleted.
    Deleted,
}

#[derive(Deserialize)]
struct RealmWire {
    id: String,
    issuer: String,
    slug: String,
}

#[derive(Deserialize)]
struct SnapshotWire {
    tenant: String,
    organizations: Vec<String>,
    #[serde(default)]
    realms: Vec<RealmWire>,
    region: String,
    status: String,
    version: String,
}

/// A live realm of a tenant (Access OP-149 m.19 (b), P-115 note).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRealm {
    /// The realm id.
    pub id: RealmId,
    /// The realm issuer, checked in the P-116 `realm` check.
    pub issuer: String,
    /// The slug attention items show.
    pub slug: String,
}

fn realm(w: RealmWire) -> Result<SnapshotRealm, AccessError> {
    Issuer::parse(&w.issuer).map_err(|_| AccessError::Answer("realm issuer"))?;
    if w.slug.is_empty() || w.slug.len() > 255 {
        return Err(AccessError::Answer("realm slug"));
    }
    Ok(SnapshotRealm {
        id: RealmId::parse(&w.id)?,
        issuer: w.issuer,
        slug: w.slug,
    })
}

#[derive(Deserialize)]
struct PageWire {
    tenants: Vec<SnapshotWire>,
    #[serde(default)]
    next_cursor: Option<String>,
}

/// One tenant's snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantSnapshot {
    /// The opaque `tnt_…` id.
    pub tenant: TenantId,
    /// The deployment's region.
    pub region: String,
    /// State.
    pub status: TenantStatus,
    /// Changes exactly when the snapshot does.
    pub version: String,
    /// Organization count; empty until Access's organization model, and unread by Work.
    pub organizations: usize,
    /// The tenant's live realms; every realm Work pairs with (T-103).
    pub realms: Vec<SnapshotRealm>,
}

impl TenantSnapshot {
    /// Whether Work pairs with the tenant: it is `active` and of Work's `region` (T-103 item 1,
    /// E-4).
    #[must_use]
    pub fn pairable(&self, region: &str) -> bool {
        self.status == TenantStatus::Active && self.region == region
    }
}

fn snapshot(w: SnapshotWire) -> Result<TenantSnapshot, AccessError> {
    let status = match w.status.as_str() {
        "provisioning" => TenantStatus::Provisioning,
        "active" => TenantStatus::Active,
        "suspended" => TenantStatus::Suspended,
        "deleted" => TenantStatus::Deleted,
        _ => return Err(AccessError::Answer("status")),
    };
    if w.version.is_empty() || w.region.is_empty() {
        return Err(AccessError::Answer("tenant"));
    }
    Ok(TenantSnapshot {
        tenant: TenantId::new(&w.tenant).ok_or(AccessError::Answer("tenant"))?,
        region: w.region,
        status,
        version: w.version,
        organizations: w.organizations.len(),
        realms: w.realms.into_iter().map(realm).collect::<Result<_, _>>()?,
    })
}

impl TenantSnapshot {
    /// Reads `GET /access/v1/tenants/{tenant}/snapshot`.
    ///
    /// # Errors
    /// [`AccessError::Answer`].
    pub fn from_json(body: &[u8]) -> Result<Self, AccessError> {
        snapshot(serde_json::from_slice(body).map_err(|_| AccessError::Answer("tenant"))?)
    }
}

/// One page of `GET /access/v1/tenants`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantPage {
    /// The snapshots.
    pub tenants: Vec<TenantSnapshot>,
    /// The cursor of the next page; absent on the last.
    pub next_cursor: Option<String>,
}

impl TenantPage {
    /// Reads a page.
    ///
    /// # Errors
    /// [`AccessError::Answer`].
    pub fn from_json(body: &[u8]) -> Result<Self, AccessError> {
        let w: PageWire =
            serde_json::from_slice(body).map_err(|_| AccessError::Answer("tenants"))?;
        if w.next_cursor.as_deref() == Some("") {
            return Err(AccessError::Answer("next_cursor"));
        }
        Ok(Self {
            tenants: w
                .tenants
                .into_iter()
                .map(snapshot)
                .collect::<Result<_, _>>()?,
            next_cursor: w.next_cursor,
        })
    }
}

/// The list URL, the `tenant_snapshot` template without its `/{tenant}/snapshot` tail: Access
/// serves the list beside the snapshot and does not name it in discovery.
///
/// # Errors
/// [`AccessError::Endpoint`] for a template of another shape.
pub fn list_url(snapshot: &Template, cursor: Option<&str>) -> Result<String, AccessError> {
    let base = snapshot
        .as_str()
        .strip_suffix("/{tenant}/snapshot")
        .ok_or_else(|| AccessError::Endpoint("tenant_snapshot".to_owned()))?;
    Ok(match cursor {
        Some(c) => format!("{base}?cursor={}", crate::domain::discovery::percent(c)),
        None => base.to_owned(),
    })
}

/// What one reconciliation changes in Work's tenant map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantChange {
    /// A tenant Work does not know yet; Work maps it and opens its service Party.
    Opened(TenantSnapshot),
    /// A known tenant whose snapshot changed.
    Changed(TenantSnapshot),
    /// A known tenant Access no longer lists; reported to the operator, never removed.
    Missing(TenantId),
}

/// The changes `seen`, the full list, makes to `known`, Work's tenants and the snapshot version
/// each was last reconciled at. A tenant of another region is left out (E-4); an unchanged
/// version is no work.
#[must_use]
pub fn plan(
    known: &BTreeMap<TenantId, String>,
    seen: &[TenantSnapshot],
    region: &str,
) -> Vec<TenantChange> {
    let mut out = Vec::new();
    let mut listed = BTreeSet::new();
    for s in seen.iter().filter(|s| s.region == region) {
        listed.insert(&s.tenant);
        match known.get(&s.tenant) {
            None => out.push(TenantChange::Opened(s.clone())),
            Some(v) if *v != s.version => out.push(TenantChange::Changed(s.clone())),
            Some(_) => {}
        }
    }
    out.extend(
        known
            .keys()
            .filter(|t| !listed.contains(t))
            .map(|t| TenantChange::Missing(t.clone())),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::discovery::Endpoints;

    fn tenant(id: &str, version: &str, region: &str) -> TenantSnapshot {
        TenantSnapshot {
            tenant: TenantId::new(id).unwrap(),
            region: region.to_owned(),
            status: TenantStatus::Active,
            version: version.to_owned(),
            organizations: 0,
            realms: Vec::new(),
        }
    }

    // T-96
    #[test]
    fn t_96_tenant_ids_stay_opaque_and_organizations_unread() {
        let page = TenantPage::from_json(
            br#"{"tenants": [{"tenant": "tnt_01HZ", "organizations": [], "region": "eu-central", "status": "active", "version": "v1", "retention": {}}], "next_cursor": "tnt_01HZ"}"#,
        )
        .unwrap();
        assert_eq!(page.tenants[0].tenant.as_str(), "tnt_01HZ");
        assert_eq!(page.next_cursor.as_deref(), Some("tnt_01HZ"));
        let one = TenantSnapshot::from_json(
            br#"{"tenant": "tnt_02", "organizations": [], "region": "eu-central", "status": "suspended", "version": "v2", "retention": {}}"#,
        )
        .unwrap();
        assert_eq!(one.status, TenantStatus::Suspended);
        assert!(TenantSnapshot::from_json(br#"{"tenant": "tnt_02", "organizations": [], "region": "eu-central", "status": "gone", "version": "v2", "retention": {}}"#).is_err());
        let last = TenantPage::from_json(br#"{"tenants": []}"#).unwrap();
        assert_eq!(last.next_cursor, None);
    }

    // E-43 E-3
    #[test]
    fn e_43_a_personal_tenant_is_mapped_like_every_other_tenant() {
        let household = TenantSnapshot::from_json(
            br#"{"tenant": "tnt_home", "organizations": [], "realms": [], "region": "eu-central", "status": "active", "version": "v1", "retention": {}}"#,
        )
        .unwrap();
        assert_eq!(household.tenant.as_str(), "tnt_home");
        assert_eq!(household.organizations, 0);
        let company = tenant("tnt_acme", "v1", "eu-central");
        assert_eq!(
            plan(
                &BTreeMap::new(),
                &[household.clone(), company.clone()],
                "eu-central"
            ),
            vec![
                TenantChange::Opened(household.clone()),
                TenantChange::Opened(company)
            ]
        );
        let known = BTreeMap::from([(household.tenant.clone(), "v1".to_owned())]);
        assert_eq!(
            plan(&known, std::slice::from_ref(&household), "eu-central"),
            Vec::new()
        );
    }

    // T-96
    #[test]
    fn t_96_the_list_is_found_beside_the_snapshot_template() {
        let e = Endpoints::from_pairs([(
            "tenant_snapshot",
            "https://access.example/access/v1/tenants/{tenant}/snapshot",
        )])
        .unwrap();
        let t = e
            .get(crate::domain::discovery::Endpoint::TenantSnapshot)
            .unwrap();
        assert_eq!(
            list_url(t, None).unwrap(),
            "https://access.example/access/v1/tenants"
        );
        assert_eq!(
            list_url(t, Some("tnt_01")).unwrap(),
            "https://access.example/access/v1/tenants?cursor=tnt_01"
        );
    }

    // T-96
    #[test]
    fn t_96_reconciliation_maps_new_and_changed_tenants_and_reports_missing_ones() {
        let known = BTreeMap::from([
            (TenantId::new("tnt_a").unwrap(), "v1".to_owned()),
            (TenantId::new("tnt_b").unwrap(), "v1".to_owned()),
            (TenantId::new("tnt_gone").unwrap(), "v1".to_owned()),
        ]);
        let seen = [
            tenant("tnt_a", "v1", "eu-central"),
            tenant("tnt_b", "v2", "eu-central"),
            tenant("tnt_c", "v1", "eu-central"),
            tenant("tnt_x", "v1", "us-east"),
        ];
        assert_eq!(
            plan(&known, &seen, "eu-central"),
            vec![
                TenantChange::Changed(tenant("tnt_b", "v2", "eu-central")),
                TenantChange::Opened(tenant("tnt_c", "v1", "eu-central")),
                TenantChange::Missing(TenantId::new("tnt_gone").unwrap()),
            ]
        );
        let unchanged = [tenant("tnt_a", "v1", "eu-central")];
        let only_a = BTreeMap::from([(TenantId::new("tnt_a").unwrap(), "v1".to_owned())]);
        assert_eq!(plan(&only_a, &unchanged, "eu-central"), Vec::new());
    }

    // T-103
    #[test]
    fn t_103_the_snapshot_names_its_live_realms_and_only_active_tenants_of_the_region_pair() {
        let one = TenantSnapshot::from_json(
            br#"{"tenant": "tnt_01", "organizations": [], "realms": [{"id": "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1", "issuer": "https://shop1.id.example", "slug": "shop1"}], "region": "eu-central", "status": "active", "retention": {}, "version": "v1"}"#,
        )
        .unwrap();
        assert_eq!(one.realms.len(), 1);
        assert_eq!(
            one.realms[0].id.as_str(),
            "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1"
        );
        assert_eq!(one.realms[0].slug, "shop1");
        assert!(one.pairable("eu-central"));
        assert!(!one.pairable("us-east"));
        let suspended = TenantSnapshot {
            status: TenantStatus::Suspended,
            ..one.clone()
        };
        assert!(!suspended.pairable("eu-central"));
        for bad in [
            r#""id": "A1A1A1A1-a1a1-a1a1-a1a1-a1a1a1a1a1a1", "issuer": "https://shop1.id.example", "slug": "shop1""#,
            r#""id": "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1", "issuer": "http://shop1.id.example", "slug": "shop1""#,
            r#""id": "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1", "issuer": "https://shop1.id.example", "slug": """#,
        ] {
            let doc = format!(
                r#"{{"tenant": "tnt_01", "organizations": [], "realms": [{{{bad}}}], "region": "eu-central", "status": "active", "version": "v1"}}"#
            );
            assert!(TenantSnapshot::from_json(doc.as_bytes()).is_err(), "{bad}");
        }
    }
}
