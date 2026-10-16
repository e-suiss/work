//! Namespaced identifiers on the wire: absolute HTTPS URIs only, compared bytewise without normalisation (P-70), and external references (C-13).

use alloc::string::String;
use core::cmp::Ordering;

use crate::id::canonical_text_cmp;

/// The Work core namespace root (P-70).
pub const CORE_ROOT: &str = "https://suiss.app/ns/work/";

/// An absolute HTTPS URI naming a subtype, qualifier, scheme or extension key (P-70).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TypeUri(String);

/// The key of an extension field in `ext` (P-19, P-69).
pub type ExtKey = TypeUri;

/// The namespace URI of a Practice pinned in `versions` (P-18).
pub type NamespaceUri = TypeUri;

impl TypeUri {
    /// Parses `https://host[:port]/path` with a lowercase host and printable ASCII path.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let rest = value.strip_prefix("https://")?;
        let slash = rest.find('/')?;
        let (authority, path) = rest.split_at(slash);
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        (host_ok && port_ok && path.bytes().all(is_printable)).then(|| Self(String::from(value)))
    }

    /// The URI text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when the URI lies under the Work core root.
    #[must_use]
    pub fn is_core(&self) -> bool {
        self.0.starts_with(CORE_ROOT)
    }

    /// True when the URI lies under `namespace`, compared bytewise (P-70).
    #[must_use]
    pub fn is_under(&self, namespace: &Self) -> bool {
        self.0.starts_with(namespace.as_str())
    }

    /// Canonical CBOR order of two URIs (P-72).
    #[must_use]
    pub fn canonical_cmp(&self, other: &Self) -> Ordering {
        canonical_text_cmp(&self.0, &other.0)
    }
}

/// A reference to something outside Work: `scheme:rest` with printable ASCII (C-13).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExternalRef(String);

impl ExternalRef {
    /// Parses `[a-z][a-z0-9+.-]*:[!-~]+`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let (scheme, rest) = value.split_once(':')?;
        let mut bytes = scheme.bytes();
        let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
        let scheme_ok = bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        });
        (first_ok && scheme_ok && !rest.is_empty() && rest.bytes().all(is_printable))
            .then(|| Self(String::from(value)))
    }

    /// The reference text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_printable(b: u8) -> bool {
    (b'!'..=b'~').contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-70
    #[test]
    fn p_70_only_absolute_https_uris_parse() {
        assert!(TypeUri::parse("https://suiss.app/ns/work/claim/observation").is_some());
        assert!(TypeUri::parse("https://procurement.example:8443/ns/").is_some());
        assert!(TypeUri::parse("http://procurement.example/ns/declaration/comment").is_none());
        assert!(TypeUri::parse("com.example.procurement/declaration/comment").is_none());
        assert!(TypeUri::parse("https://Procurement.example/ns/").is_none());
        assert!(TypeUri::parse("https://procurement.example").is_none());
        assert!(TypeUri::parse("https://procurement.example/a b").is_none());
        assert!(TypeUri::parse("https://host:/x").is_none());
    }

    // P-70
    #[test]
    fn p_70_core_root_is_suiss_app_work() {
        let core = TypeUri::parse("https://suiss.app/ns/work/declaration/promise");
        assert!(core.is_some_and(|u| u.is_core()));
        let old = TypeUri::parse("https://suiss.org/work/claim/observation");
        assert!(old.is_some_and(|u| !u.is_core()));
    }

    // C-13
    #[test]
    fn c_13_external_reference_has_a_scheme() {
        assert!(ExternalRef::parse("urn:example:model:m-2026-09").is_some());
        assert!(ExternalRef::parse("https://erp.example/orders/PO-4471").is_some());
        assert!(ExternalRef::parse("Urn:x").is_none());
        assert!(ExternalRef::parse("urn:").is_none());
        assert!(ExternalRef::parse("no-scheme").is_none());
    }
}
