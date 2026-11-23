//! The executor's reviewed wall clock and randomness (T-32): it has no ledger time; the times it writes are its own claims (`occurred_at`, heartbeats) and the times Access checks (assertions, proofs, statements) are checked against Access's own clock, and its random bytes are salts, nonces and assertion `jti`s.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use work_access_client::domain::AccessError;
use work_access_client::ports::{Clock, Random};

/// The operating system's wall clock, Unix milliseconds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Wall;

impl Clock for Wall {
    #[allow(
        clippy::disallowed_methods,
        reason = "T-32 T-105: the reviewed wall clock of the test executor"
    )]
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or_default()
    }
}

/// The operating system's CSPRNG.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Os;

impl Random for Os {
    #[allow(
        clippy::disallowed_methods,
        reason = "T-32 T-105: the reviewed Rng adapter of the test executor over the operating system's CSPRNG"
    )]
    fn fill(&self, out: &mut [u8]) -> Result<(), AccessError> {
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(out)
            .map_err(|_| AccessError::KeyStore("no randomness".to_owned()))
    }
}

impl Os {
    /// `N` random bytes.
    pub(crate) fn bytes<const N: usize>(self) -> Result<[u8; N], AccessError> {
        let mut out = [0_u8; N];
        self.fill(&mut out)?;
        Ok(out)
    }

    /// An RFC 9562 version 7 UUID of `ms`, for an `Idempotency-Key`.
    pub(crate) fn uuid7(self, ms: u64) -> Result<String, AccessError> {
        let mut b: [u8; 16] = self.bytes()?;
        for (to, from) in b.iter_mut().zip(ms.to_be_bytes().iter().skip(2)) {
            *to = *from;
        }
        if let Some(v) = b.get_mut(6) {
            *v = (*v & 0x0f) | 0x70;
        }
        if let Some(v) = b.get_mut(8) {
            *v = (*v & 0x3f) | 0x80;
        }
        let hex = b.iter().fold(String::with_capacity(32), |mut out, x| {
            let _ = write!(out, "{x:02x}");
            out
        });
        Ok(format!(
            "{}-{}-{}-{}-{}",
            hex.get(..8).unwrap_or_default(),
            hex.get(8..12).unwrap_or_default(),
            hex.get(12..16).unwrap_or_default(),
            hex.get(16..20).unwrap_or_default(),
            hex.get(20..).unwrap_or_default()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-105 OP-8
    #[test]
    fn t_105_an_idempotency_key_is_a_version_7_uuid_of_its_time() {
        let key = Os.uuid7(0x0189_0a5d_ac96).unwrap();
        assert_eq!(key.len(), 36);
        assert!(key.starts_with("01890a5d-ac96-7"), "{key}");
        assert!(
            matches!(key.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "{key}"
        );
        assert_ne!(Os.uuid7(1).unwrap(), Os.uuid7(1).unwrap());
    }
}
