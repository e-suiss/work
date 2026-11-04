//! Pure rules of the Access client: what a discovery document, a signed key lookup answer, an eligibility answer and a tenant snapshot must be before Work uses them, and the stable codes of every refusal.

pub mod cache;
pub mod discovery;
pub mod eligibility;
pub mod keys;
pub mod metadata;
pub mod relay;
pub mod tenants;
pub mod x509;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::domain::discovery::Endpoint;

/// Why the client does not use what Access or Relay answered. A consequential action that
/// depends on it is refused fail-closed (T-28).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AccessError {
    /// The `[suiss] access` setting is not an `https` URL with a host and without a trailing
    /// slash, query or fragment (T-96 item 1).
    #[error("the Access issuer setting is malformed")]
    Setting,
    /// A document or answer does not parse.
    #[error("the {0} document does not parse")]
    Document(&'static str),
    /// `suiss_configuration_version` is not 1.
    #[error("the Suiss configuration version is not 1")]
    Version,
    /// A document names another issuer than the one Work is bound to.
    #[error("the {0} document names another issuer")]
    Issuer(&'static str),
    /// A document names another region than Work's (E-4).
    #[error("the {0} document names another region")]
    Region(&'static str),
    /// An endpoint is unknown or not an `https` URL of the expected template.
    #[error("endpoint {0} is malformed or unknown")]
    Endpoint(String),
    /// A capability needed at start is not offered.
    #[error("capability {0} is not offered")]
    Capability(String),
    /// Relay does not support the dated contract version Work speaks (T-99 item 2).
    #[error("contract version {0} is not supported")]
    ContractVersion(String),
    /// Access does not serve the endpoint; the action that needs it is refused.
    #[error("Access does not serve {}", .0.name())]
    Unserved(Endpoint),
    /// The signed discovery of Domain Metadata and the Suiss configuration disagree.
    #[error("the signed discovery disagrees on {}", .0.name())]
    DiscoveryMismatch(Endpoint),
    /// Domain Metadata or the operational key of an answer is not accepted.
    #[error("Domain Metadata: {0}")]
    Metadata(&'static str),
    /// A key lookup, eligibility or tenant answer breaks its contract.
    #[error("answer: {0}")]
    Answer(&'static str),
    /// An identifier is not in Access's wire form.
    #[error("identifier: {0}")]
    Identifier(&'static str),
    /// The PEP certificate does not fit its key or does not parse.
    #[error("PEP certificate: {0}")]
    Certificate(&'static str),
    /// The PEP certificate has expired (T-101 item 2).
    #[error("the PEP certificate has expired")]
    Expired,
    /// Access or Relay refused the call.
    #[error("the peer answered {status} {code}")]
    Refused {
        /// HTTP status.
        status: u16,
        /// The problem `code`, when the answer carried one.
        code: String,
    },
    /// The connection or the exchange failed.
    #[error("transport: {0}")]
    Transport(String),
    /// The call ran past its bound.
    #[error("the call timed out")]
    Timeout,
    /// The PKCS#11 token refused (T-56).
    #[error("key store: {0}")]
    KeyStore(String),
}

impl AccessError {
    /// The stable code: start-time refusals are `start_refused`, everything a consequential
    /// action depends on is `authority_unverifiable` (T-28, T-96 note).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Setting
            | Self::Version
            | Self::Issuer(_)
            | Self::Region(_)
            | Self::Capability(_)
            | Self::ContractVersion(_) => "start_refused",
            _ => "authority_unverifiable",
        }
    }
}

/// Unpadded base64url, as Access writes kernel identifiers on the wire (Access OP-149 m.16).
#[must_use]
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The bytes of canonical unpadded base64url text.
///
/// # Errors
/// [`AccessError::Identifier`] for other text.
pub fn from_b64url(text: &str) -> Result<Vec<u8>, AccessError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| AccessError::Identifier("base64url"))?;
    if b64url(&bytes) == text {
        Ok(bytes)
    } else {
        Err(AccessError::Identifier("base64url"))
    }
}

/// The `N` bytes of canonical unpadded base64url text.
///
/// # Errors
/// [`AccessError::Identifier`] for other text or another length.
pub fn fixed_b64url<const N: usize>(text: &str) -> Result<[u8; N], AccessError> {
    <[u8; N]>::try_from(from_b64url(text)?).map_err(|_| AccessError::Identifier("length"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The bytes of lower- or upper-case hex text.
    pub(crate) fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    // T-96
    #[test]
    fn t_96_start_refusals_and_fail_closed_refusals_have_their_codes() {
        assert_eq!(AccessError::Version.code(), "start_refused");
        assert_eq!(
            AccessError::Capability("urn:suiss:access:adp:1".to_owned()).code(),
            "start_refused"
        );
        assert_eq!(
            AccessError::Unserved(Endpoint::KeyLookup).code(),
            "authority_unverifiable"
        );
        assert_eq!(AccessError::Expired.code(), "authority_unverifiable");
    }

    // T-101
    #[test]
    fn t_101_kernel_identifiers_are_canonical_unpadded_base64url() {
        let id = [7_u8; 16];
        let text = b64url(&id);
        assert_eq!(fixed_b64url::<16>(&text).unwrap(), id);
        assert!(fixed_b64url::<16>(&format!("{text}=")).is_err());
        assert!(fixed_b64url::<16>(&format!("ins_{text}")).is_err());
        assert!(fixed_b64url::<32>(&text).is_err());
    }
}
