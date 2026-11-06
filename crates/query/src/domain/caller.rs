//! The caller of an API request (C-9, E-7, SEC-18, T-28; Access OP-149 m.31 (a), m.34): an Access Party, or a tenant realm's API client without one, named by the Access access token and `DPoP` proof the request carries and nothing else, so a transport identity, an address or a client certificate never becomes a Party. A user's token names its user; a platform product's or a tenant API client's identity-assertion service token names that caller and carries no authority, so whatever it does that is consequential still needs an Exercise, as a user's does. The Party is Access's `PartyID` in the realm the token's issuer is; the kernel's `PartyRef` is its unpadded base64url, Access's own spelling, until the kernel takes Access's 16-byte `party-ref` (P-112 note, §20 OQ-34). A request that names no caller is `unauthenticated`; one whose caller cannot be checked because Access does not answer is `authority_unverifiable`, never a caller.

use std::collections::BTreeMap;

use work_access_client::domain::fixed_b64url;
use work_access_client::domain::subjects::Subject;
pub use work_access_client::domain::token::TokenKind as CallerKind;
use work_access_client::domain::token::{PROOF_WINDOW_MS, TokenRefusal};
use work_kernel::id::PartyRef;
use work_proto::id::TenantId;

/// The authorization scheme of an Access access token (RFC 9449 section 7.1); there is no
/// bearer token.
pub const SCHEME: &str = "DPoP";

/// The most proofs the replay cache holds at once (PD); a full cache refuses new callers until
/// proofs leave their window.
pub const REPLAY_ENTRIES: usize = 65_536;

/// The Party a caller is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerParty {
    /// The Party as the kernel names it.
    pub reference: PartyRef,
    /// Access's 16-byte `PartyID`.
    pub id: [u8; 16],
}

/// The caller of a request: an Access Party, or an API client without one, in a realm of a
/// tenant.
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
    /// A user's token or a service token.
    pub kind: CallerKind,
    /// The Party; absent for a tenant API client without one (Access OP-149 m.34 (b)), which
    /// sees and writes nothing a Party does.
    pub party: Option<CallerParty>,
}

impl Caller {
    /// The caller's Party.
    ///
    /// # Errors
    /// `caller_party`, the code of the refusal, for an API client without a Party.
    pub fn party(&self) -> Result<&CallerParty, &'static str> {
        self.party.as_ref().ok_or("caller_party")
    }
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

/// Whether the token's `access_tenant` `claimed` is the tenant of the realm that issued it
/// (Access OP-149 m.34): a user's token names the caller's tenant, and a service token's issuer
/// is one of the realms of the tenant it names.
///
/// # Errors
/// [`CallerRefusal::Unauthenticated`] (`token_tenant`) for another tenant or none.
pub fn same_tenant(claimed: Option<&str>, realm: &TenantId) -> Result<(), CallerRefusal> {
    if claimed == Some(realm.as_str()) {
        Ok(())
    } else {
        Err(CallerRefusal::Unauthenticated("token_tenant"))
    }
}

/// The pairwise sector of a token's `sub` (MD-10; Access OP-149 m.31 (a), m.34 (b)): the
/// token's client for a user's token, Work's own `client_id`, `audience`, for a service token.
#[must_use]
pub fn sector<'a>(kind: CallerKind, client_id: &'a str, audience: &'a str) -> &'a str {
    match kind {
        CallerKind::User => client_id,
        CallerKind::Service => audience,
    }
}

/// The caller's Party from what Access resolved the token's `sub` to: a Party, or, for a service
/// token only, no Party when the `sub` names the token's own client (Access OP-149 m.34 (b)).
///
/// # Errors
/// [`CallerRefusal::Unauthenticated`] (`subject_unknown`) for a `sub` Access does not know or
/// that names another client or, in a user's token, any client;
/// [`CallerRefusal::Unverifiable`] (`access_answer`) for a Party Access misspelled.
pub fn party_of(
    subject: Option<Subject>,
    kind: CallerKind,
    client_id: &str,
) -> Result<Option<CallerParty>, CallerRefusal> {
    let unknown = CallerRefusal::Unauthenticated("subject_unknown");
    match subject.ok_or(unknown)? {
        Subject::Party(party) => Ok(Some(CallerParty {
            id: fixed_b64url::<16>(&party)
                .map_err(|_| CallerRefusal::Unverifiable("access_answer"))?,
            reference: PartyRef::new(&party).ok_or(CallerRefusal::Unverifiable("access_answer"))?,
        })),
        Subject::Client(client) if kind == CallerKind::Service && client.as_str() == client_id => {
            Ok(None)
        }
        Subject::Client(_) => Err(unknown),
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

    // E-7 T-99 T-104
    #[test]
    fn e_7_a_service_token_names_its_caller_in_work_s_sector_and_only_in_its_tenant() {
        let acme = TenantId::new("tnt_acme").unwrap();
        assert_eq!(same_tenant(Some("tnt_acme"), &acme), Ok(()));
        for claimed in [None, Some("tnt_globex"), Some("")] {
            assert_eq!(
                same_tenant(claimed, &acme),
                Err(CallerRefusal::Unauthenticated("token_tenant")),
                "{claimed:?}"
            );
        }
        assert_eq!(sector(CallerKind::User, "cli_web", "cli_work"), "cli_web");
        assert_eq!(
            sector(CallerKind::Service, "cli_relay", "cli_work"),
            "cli_work"
        );
        let party = "EREREREREREREREREREREQ";
        for kind in [CallerKind::User, CallerKind::Service] {
            let named = party_of(Some(Subject::Party(party.to_owned())), kind, "cli_relay")
                .unwrap()
                .unwrap();
            assert_eq!(named.id, [0x11; 16]);
            assert_eq!(named.reference.as_str(), party);
            assert_eq!(
                party_of(None, kind, "cli_relay"),
                Err(CallerRefusal::Unauthenticated("subject_unknown"))
            );
            assert_eq!(
                party_of(
                    Some(Subject::Client("cli_other".to_owned())),
                    kind,
                    "cli_backend"
                ),
                Err(CallerRefusal::Unauthenticated("subject_unknown"))
            );
        }
        let client = || Some(Subject::Client("cli_backend".to_owned()));
        assert_eq!(
            party_of(client(), CallerKind::Service, "cli_backend"),
            Ok(None)
        );
        assert_eq!(
            party_of(client(), CallerKind::User, "cli_backend"),
            Err(CallerRefusal::Unauthenticated("subject_unknown"))
        );
        assert_eq!(
            party_of(
                Some(Subject::Party("short".to_owned())),
                CallerKind::User,
                "cli_web"
            ),
            Err(CallerRefusal::Unverifiable("access_answer"))
        );
        let caller = Caller {
            tenant: acme,
            realm: "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1".to_owned(),
            issuer: "https://access.example/realms/acme".to_owned(),
            client_id: "cli_backend".to_owned(),
            kind: CallerKind::Service,
            party: None,
        };
        assert_eq!(caller.party(), Err("caller_party"));
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
