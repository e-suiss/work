//! The caller of an API request (C-9, E-7, SEC-18, T-28): an Access Party, named by the Access access token and `DPoP` proof the request carries and nothing else, so a transport identity, an address or a client certificate never becomes a Party. The Party is Access's `PartyID` in the realm the token's issuer is; the kernel's `PartyRef` is its unpadded base64url, Access's own spelling, until the kernel takes Access's 16-byte `party-ref` (P-112 note, §20 OQ-34). A request that names no caller is `unauthenticated`; one whose caller cannot be checked because Access does not answer is `authority_unverifiable`, never a caller.

use std::collections::BTreeMap;

use work_access_client::domain::token::{PROOF_WINDOW_MS, TokenRefusal};
use work_kernel::id::PartyRef;
use work_proto::id::TenantId;

/// The authorization scheme of an Access access token (RFC 9449 section 7.1); there is no
/// bearer token.
pub const SCHEME: &str = "DPoP";

/// The most proofs the replay cache holds at once (PD); a full cache refuses new callers until
/// proofs leave their window.
pub const REPLAY_ENTRIES: usize = 65_536;

/// The caller of a request: an Access Party in a realm of a tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The tenant the realm belongs to.
    pub tenant: TenantId,
    /// The realm id, a UUID in Access's spelling.
    pub realm: String,
    /// The realm issuer the token came from.
    pub issuer: String,
    /// The client the token was issued to.
    pub client_id: String,
    /// The Party as the kernel names it.
    pub party: PartyRef,
    /// Access's 16-byte `PartyID`.
    pub party_id: [u8; 16],
}

/// Why a request names no caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CallerRefusal {
    /// No valid Access access token and proof: `401 unauthenticated`.
    #[error("unauthenticated: {0}")]
    Unauthenticated(&'static str),
    /// Access cannot be reached or answered unusably, so the caller cannot be checked:
    /// `503 authority_unverifiable` (T-28).
    #[error("authority unverifiable: {0}")]
    Unverifiable(&'static str),
}

impl CallerRefusal {
    /// The stable code, for the log.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated(code) | Self::Unverifiable(code) => code,
        }
    }
}

impl From<TokenRefusal> for CallerRefusal {
    fn from(refusal: TokenRefusal) -> Self {
        Self::Unauthenticated(refusal.code())
    }
}

/// What a request presents: its `Authorization` and `DPoP` headers, each only when sent a single time,
/// its method and its target URI.
#[derive(Clone, Copy, Debug)]
pub struct Presented<'a> {
    /// The single `Authorization` value.
    pub authorization: Option<&'a str>,
    /// The single `DPoP` value.
    pub dpop: Option<&'a str>,
    /// The HTTP method.
    pub method: &'a str,
    /// The absolute target URI.
    pub url: &'a str,
}

/// The access token of an `Authorization: DPoP <token>` value; the scheme is matched without
/// regard to case (RFC 9110 section 11.1).
///
/// # Errors
/// [`CallerRefusal::Unauthenticated`] for a missing value, another scheme such as `Bearer`, or
/// an empty token.
pub fn dpop_token(authorization: Option<&str>) -> Result<&str, CallerRefusal> {
    let value = authorization.ok_or(CallerRefusal::Unauthenticated("token_missing"))?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(CallerRefusal::Unauthenticated("token_scheme"))?;
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return Err(CallerRefusal::Unauthenticated("token_scheme"));
    }
    let token = token.trim();
    if token.is_empty() || token.contains(' ') {
        return Err(CallerRefusal::Unauthenticated("token_format"));
    }
    Ok(token)
}

/// The proofs seen within their window, by key thumbprint and `jti` (RFC 9449 section 11.1):
/// a proof is accepted once.
#[derive(Debug)]
pub struct ReplayCache {
    seen: BTreeMap<([u8; 32], String), u64>,
    capacity: usize,
}

impl ReplayCache {
    /// A cache of at most `capacity` proofs.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            seen: BTreeMap::new(),
            capacity,
        }
    }

    /// Accepts the proof `jti` of key `jkt` made at `iat_ms`, at `now_ms`.
    ///
    /// # Errors
    /// [`CallerRefusal::Unauthenticated`] for a proof seen before within its window;
    /// [`CallerRefusal::Unverifiable`] when the cache is full of live proofs.
    pub fn admit(
        &mut self,
        jkt: [u8; 32],
        jti: &str,
        iat_ms: u64,
        now_ms: u64,
    ) -> Result<(), CallerRefusal> {
        let key = (jkt, jti.to_owned());
        if self.seen.get(&key).is_some_and(|until| *until >= now_ms) {
            return Err(TokenRefusal::Replayed.into());
        }
        if self.seen.len() >= self.capacity {
            self.seen.retain(|_, until| *until >= now_ms);
        }
        if self.seen.len() >= self.capacity {
            return Err(CallerRefusal::Unverifiable("replay_cache_full"));
        }
        let until = iat_ms.saturating_add(PROOF_WINDOW_MS);
        self.seen.insert(key, until);
        Ok(())
    }

    /// How many proofs are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when no proof is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SEC-18 E-7 T-10
    #[test]
    fn sec_18_only_a_dpop_access_token_names_a_caller() {
        assert_eq!(dpop_token(Some("DPoP eyJ.e30.sig")), Ok("eyJ.e30.sig"));
        assert_eq!(dpop_token(Some("dpop  eyJ.e30.sig ")), Ok("eyJ.e30.sig"));
        for (value, code) in [
            (None, "token_missing"),
            (Some("Bearer eyJ.e30.sig"), "token_scheme"),
            (Some("Basic dXNlcjpwYXNz"), "token_scheme"),
            (Some("DPoP"), "token_scheme"),
            (Some("DPoP "), "token_format"),
            (Some("DPoP a b"), "token_format"),
        ] {
            assert_eq!(
                dpop_token(value),
                Err(CallerRefusal::Unauthenticated(code)),
                "{value:?}"
            );
        }
        assert_eq!(
            CallerRefusal::from(TokenRefusal::Audience).code(),
            "token_audience"
        );
    }

    // SEC-18 E-7
    #[test]
    fn sec_18_a_dpop_proof_is_accepted_once_within_its_window() {
        let mut cache = ReplayCache::new(2);
        assert_eq!(cache.admit([1; 32], "a", 1_000, 1_000), Ok(()));
        assert_eq!(
            cache.admit([1; 32], "a", 1_000, 2_000),
            Err(CallerRefusal::Unauthenticated("dpop_proof_replayed"))
        );
        assert_eq!(cache.admit([2; 32], "a", 1_000, 2_000), Ok(()));
        assert_eq!(
            cache.admit([3; 32], "b", 1_000, 2_000),
            Err(CallerRefusal::Unverifiable("replay_cache_full"))
        );
        let later = 1_000_u64.saturating_add(PROOF_WINDOW_MS).saturating_add(1);
        assert_eq!(cache.admit([3; 32], "b", later, later), Ok(()));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
    }
}
