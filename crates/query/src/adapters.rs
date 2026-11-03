//! Port implementations (T-32).

use suiss_crypto::pkcs11::{HsmError, HsmMac, KeyStore};
use work_proto::id::{PositionToken, TenantId};
use work_proto::position::{self, PositionError, Positions};

use crate::domain::PositionRefusal;

/// The PKCS#11 label of the read position MAC key with id `key_id` (T-97 item 1, T-56).
#[must_use]
pub fn position_key_label(key_id: u8) -> String {
    format!("work-read-position-{key_id}")
}

/// The read position MAC keys in the PKCS#11 token (T-97 item 1, T-56): the current key seals,
/// and the current and at most one previous key open, so a key rotates without refusing the
/// tokens clients hold.
pub struct PositionKeys {
    current: (u8, HsmMac),
    previous: Option<(u8, HsmMac)>,
}

/// Why sealing or opening a token failed in the key store, not in the token.
#[derive(Debug, thiserror::Error)]
pub enum PositionKeyError {
    /// The token refused the MAC.
    #[error("read position key: {0}")]
    Hsm(#[from] HsmError),
    /// The positions cannot be laid out as a token.
    #[error("read position layout: {0}")]
    Layout(#[from] PositionError),
}

/// Why a `Work-Min-Position` token does not open.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The token is refused: `read_position_invalid` (T-97 item 4).
    #[error("{0}")]
    Refused(PositionRefusal),
    /// The key store failed; nothing is known about the token.
    #[error(transparent)]
    Key(#[from] PositionKeyError),
}

impl PositionKeys {
    /// The keys labelled for `current` and `previous` in `store`.
    ///
    /// # Errors
    /// [`HsmError`] when a key is missing; a previous id equal to the current one is ignored.
    pub fn open(store: &KeyStore, current: u8, previous: Option<u8>) -> Result<Self, HsmError> {
        let previous = match previous.filter(|id| *id != current) {
            Some(id) => Some((id, store.mac(&position_key_label(id))?)),
            None => None,
        };
        Ok(Self {
            current: (current, store.mac(&position_key_label(current))?),
            previous,
        })
    }

    fn key(&self, key_id: u8) -> Option<&HsmMac> {
        if self.current.0 == key_id {
            return Some(&self.current.1);
        }
        self.previous
            .as_ref()
            .filter(|(id, _)| *id == key_id)
            .map(|(_, key)| key)
    }

    /// The `Work-Position` token of `positions` for `tenant`, under the current key.
    ///
    /// # Errors
    /// [`PositionKeyError`] when the token refuses the MAC.
    pub fn seal(
        &self,
        tenant: &TenantId,
        positions: &Positions,
    ) -> Result<PositionToken, PositionKeyError> {
        let (key_id, key) = &self.current;
        let body = position::body(*key_id, positions);
        let mac = key.mac(&position::mac_input(tenant.as_bytes(), &body))?;
        Ok(position::seal(body, &mac)?)
    }

    /// The positions of a `Work-Min-Position` token for `tenant`.
    ///
    /// # Errors
    /// [`OpenError::Refused`] for a malformed token, an unknown key id, or a MAC that does not
    /// match, which is also the answer to another tenant's token; [`OpenError::Key`] when the
    /// key store fails.
    pub fn open_token(
        &self,
        tenant: &TenantId,
        token: &PositionToken,
    ) -> Result<Positions, OpenError> {
        let refused = || OpenError::Refused(PositionRefusal::Invalid);
        let unsealed = position::unseal(token).map_err(|_| refused())?;
        let key = self.key(unsealed.key_id).ok_or_else(refused)?;
        let mac = key
            .mac(&position::mac_input(tenant.as_bytes(), &unsealed.body))
            .map_err(PositionKeyError::from)?;
        if unsealed.tag_matches(&mac) {
            Ok(unsealed.positions)
        } else {
            Err(refused())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use suiss_crypto::secret::Secret;
    use work_kernel::id::{Digest, LedgerId};
    use work_proto::id::ExternalId as _;

    use super::*;

    const PIN: &str = "4711";

    fn module() -> PathBuf {
        std::env::var_os("PKCS11_MODULE").map_or_else(
            || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
            PathBuf::from,
        )
    }

    /// A `SoftHSM` token of the test's own with MAC keys 1 and 2 (T-56): no KMS mock.
    fn store(test: &str) -> KeyStore {
        let label = format!("position-{test}-{}", std::process::id());
        let init = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                &label,
                "--so-pin",
                "12345678",
                "--pin",
                PIN,
            ])
            .output()
            .expect("softhsm2-util runs (T-56)");
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let store = KeyStore::open(&module(), &label, &Secret::new(PIN.to_owned())).unwrap();
        for id in [1, 2] {
            store.generate_mac(&position_key_label(id)).unwrap();
        }
        store
    }

    fn ledger(byte: u8) -> LedgerId {
        LedgerId(Digest::sha256([byte; 32]))
    }

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).unwrap()
    }

    fn invalid(result: Result<Positions, OpenError>) -> bool {
        matches!(result, Err(OpenError::Refused(PositionRefusal::Invalid)))
    }

    // T-97 P-112
    #[test]
    fn t_97_a_sealed_token_opens_only_for_its_tenant() {
        let store = store("tenant");
        let keys = PositionKeys::open(&store, 1, None).unwrap();
        let positions = Positions::new([(ledger(1), 7), (ledger(2), 3)]).unwrap();
        let token = keys.seal(&tenant("t-1"), &positions).unwrap();
        assert!(token.to_external().starts_with("pos_"));
        assert_eq!(keys.open_token(&tenant("t-1"), &token).unwrap(), positions);
        assert_eq!(keys.seal(&tenant("t-1"), &positions).unwrap(), token);
        assert!(invalid(keys.open_token(&tenant("t-2"), &token)));
    }

    // T-97
    #[test]
    fn t_97_a_token_of_another_tenant_is_invalid() {
        let store = store("other");
        let keys = PositionKeys::open(&store, 1, None).unwrap();
        let positions = Positions::new([(ledger(9), 1)]).unwrap();
        let token = keys.seal(&tenant("acme"), &positions).unwrap();
        assert!(invalid(keys.open_token(&tenant("acme2"), &token)));
        assert!(invalid(keys.open_token(&tenant("acm"), &token)));
    }

    // T-97
    #[test]
    fn t_97_a_forged_token_is_read_position_invalid() {
        let store = store("forged");
        let keys = PositionKeys::open(&store, 1, None).unwrap();
        let positions = Positions::new([(ledger(1), 5)]).unwrap();
        let token = keys.seal(&tenant("t"), &positions).unwrap();
        let mut forged = token.as_bytes().to_vec();
        forged[38] ^= 0x01;
        let forged = PositionToken::new(forged).unwrap();
        assert!(invalid(keys.open_token(&tenant("t"), &forged)));
        let mut unknown_key = token.as_bytes().to_vec();
        unknown_key[1] = 3;
        let unknown_key = PositionToken::new(unknown_key).unwrap();
        assert!(invalid(keys.open_token(&tenant("t"), &unknown_key)));
        let tag = token.as_bytes().len().saturating_sub(1);
        let mut tag_flip = token.as_bytes().to_vec();
        tag_flip[tag] ^= 0x80;
        let tag_flip = PositionToken::new(tag_flip).unwrap();
        assert!(invalid(keys.open_token(&tenant("t"), &tag_flip)));
        let short = PositionToken::new(vec![1, 1, 1]).unwrap();
        assert!(invalid(keys.open_token(&tenant("t"), &short)));
    }

    // T-97
    #[test]
    fn t_97_a_rotated_key_opens_tokens_of_the_previous_key() {
        let store = store("rotation");
        let old = PositionKeys::open(&store, 1, None).unwrap();
        let positions = Positions::new([(ledger(4), 2)]).unwrap();
        let held = old.seal(&tenant("t"), &positions).unwrap();
        let rotated = PositionKeys::open(&store, 2, Some(1)).unwrap();
        assert_eq!(rotated.open_token(&tenant("t"), &held).unwrap(), positions);
        let fresh = rotated.seal(&tenant("t"), &positions).unwrap();
        assert_eq!(fresh.as_bytes().get(1), Some(&2));
        assert!(invalid(old.open_token(&tenant("t"), &fresh)));
        let retired = PositionKeys::open(&store, 2, None).unwrap();
        assert!(invalid(retired.open_token(&tenant("t"), &held)));
        assert!(matches!(
            PositionKeys::open(&store, 3, None),
            Err(HsmError::Key(_))
        ));
    }
}
