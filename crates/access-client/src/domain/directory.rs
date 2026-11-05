//! The realms a caller's token may come from (T-96 item 4, P-116 item 4; Access OP-149 m.19 (b)): every live realm of every active tenant of Work's region that the tenant list names, by its issuer, with the tenant and the realm id. A token whose `iss` is not one of them names no caller.

use std::collections::BTreeMap;

use serde::Deserialize;
use work_proto::id::TenantId;

use crate::domain::AccessError;
use crate::domain::subjects::is_realm_id;

/// One realm a caller may come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownRealm {
    /// The tenant that holds it.
    pub tenant: TenantId,
    /// The realm id, a UUID in Access's spelling.
    pub realm: String,
    /// Its issuer.
    pub issuer: String,
    /// Its slug.
    pub slug: String,
}

#[derive(Deserialize)]
struct RealmWire {
    id: String,
    issuer: String,
    slug: String,
}

#[derive(Deserialize)]
struct TenantWire {
    tenant: String,
    region: String,
    status: String,
    #[serde(default)]
    realms: Vec<RealmWire>,
}

#[derive(Deserialize)]
struct PageWire {
    tenants: Vec<TenantWire>,
    #[serde(default)]
    next_cursor: Option<String>,
}

/// The realms of one page of the tenant list, and the cursor of the next page.
///
/// # Errors
/// [`AccessError::Answer`] for a page that does not parse, an empty cursor, or a realm whose id
/// is not a realm id or whose issuer is not an `https` URL.
pub fn page_realms(
    body: &[u8],
    region: &str,
) -> Result<(Vec<KnownRealm>, Option<String>), AccessError> {
    let bad = || AccessError::Answer("tenants");
    let page: PageWire = serde_json::from_slice(body).map_err(|_| bad())?;
    if page.next_cursor.as_deref() == Some("") {
        return Err(AccessError::Answer("next_cursor"));
    }
    let mut out = Vec::new();
    for t in page.tenants {
        if t.status != "active" || t.region != region {
            continue;
        }
        let tenant = TenantId::new(&t.tenant).ok_or_else(bad)?;
        for r in t.realms {
            if !is_realm_id(&r.id) || !r.issuer.starts_with("https://") || r.slug.is_empty() {
                return Err(bad());
            }
            out.push(KnownRealm {
                tenant: tenant.clone(),
                realm: r.id,
                issuer: r.issuer,
                slug: r.slug,
            });
        }
    }
    Ok((out, page.next_cursor))
}

/// The realms by issuer; an issuer two tenants name is held by neither, since it would not say
/// which tenant a caller is of.
#[must_use]
pub fn by_issuer(realms: Vec<KnownRealm>) -> BTreeMap<String, KnownRealm> {
    let mut out: BTreeMap<String, KnownRealm> = BTreeMap::new();
    let mut doubled = Vec::new();
    for realm in realms {
        if out.contains_key(&realm.issuer) {
            doubled.push(realm.issuer.clone());
        } else {
            out.insert(realm.issuer.clone(), realm);
        }
    }
    for issuer in doubled {
        out.remove(&issuer);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1";
    const B: &str = "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2";

    // T-96 E-7 P-116
    #[test]
    fn t_96_only_live_realms_of_active_tenants_of_the_region_name_callers() {
        let body = serde_json::json!({
            "tenants": [
                {"tenant": "tnt_01", "organizations": [], "region": "eu", "status": "active", "version": "v1",
                 "realms": [{"id": A, "issuer": "https://access.example/realms/acme", "slug": "acme"}]},
                {"tenant": "tnt_02", "organizations": [], "region": "eu", "status": "suspended", "version": "v1",
                 "realms": [{"id": B, "issuer": "https://access.example/realms/globex", "slug": "globex"}]},
                {"tenant": "tnt_03", "organizations": [], "region": "us", "status": "active", "version": "v1",
                 "realms": [{"id": B, "issuer": "https://access.example/realms/initech", "slug": "initech"}]},
            ],
            "next_cursor": "c2"
        });
        let (realms, next) = page_realms(&serde_json::to_vec(&body).unwrap(), "eu").unwrap();
        assert_eq!(next.as_deref(), Some("c2"));
        assert_eq!(
            realms,
            vec![KnownRealm {
                tenant: TenantId::new("tnt_01").unwrap(),
                realm: A.to_owned(),
                issuer: "https://access.example/realms/acme".to_owned(),
                slug: "acme".to_owned(),
            }]
        );
        let bad = serde_json::json!({"tenants": [{"tenant": "tnt_01", "region": "eu", "status": "active",
            "realms": [{"id": "A1", "issuer": "https://a.example", "slug": "a"}]}]});
        assert!(page_realms(&serde_json::to_vec(&bad).unwrap(), "eu").is_err());
        let empty = br#"{"tenants": [], "next_cursor": ""}"#;
        assert_eq!(
            page_realms(empty, "eu"),
            Err(AccessError::Answer("next_cursor"))
        );
        let mut twice = realms.clone();
        twice.push(KnownRealm {
            tenant: TenantId::new("tnt_09").unwrap(),
            ..realms[0].clone()
        });
        assert!(by_issuer(twice).is_empty());
        assert_eq!(by_issuer(realms).len(), 1);
    }
}
