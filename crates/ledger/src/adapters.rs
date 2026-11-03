//! The `Rng` adapter (T-32 rule 2): the operating system's CSPRNG through aws-lc-rs, the random
//! source the process already uses for TLS; tests use a generator on a fixed seed instead.

use crate::ports::{Rng, RngError};

/// The operating system's CSPRNG.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemRng;

impl Rng for SystemRng {
    #[allow(
        clippy::disallowed_methods,
        reason = "T-32: the reviewed Rng adapter over the operating system's CSPRNG"
    )]
    fn fill(&self, out: &mut [u8]) -> Result<(), RngError> {
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(out)
            .map_err(|_| RngError)
    }
}

/// A generator on a fixed seed: block `n` is `SHA-256(seed ‖ n)` (T-32 rule 2).
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct SeededRng {
    seed: [u8; 32],
    next: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl SeededRng {
    pub(crate) const fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            next: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
impl Rng for SeededRng {
    fn fill(&self, out: &mut [u8]) -> Result<(), RngError> {
        use sha2::Digest as _;
        for chunk in out.chunks_mut(32) {
            let n = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let block = sha2::Sha256::new()
                .chain_update(self.seed)
                .chain_update(n.to_be_bytes())
                .finalize();
            for (o, b) in chunk.iter_mut().zip(block.iter()) {
                *o = *b;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::ports::bytes32;

    // T-32
    #[test]
    fn t_32_the_system_rng_draws_fresh_bytes_through_the_port() {
        let a = bytes32(&SystemRng).unwrap();
        let b = bytes32(&SystemRng).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }

    // T-32
    #[test]
    fn t_32_a_fixed_seed_gives_the_same_bytes_and_never_repeats_a_block() {
        let one = SeededRng::new([7; 32]);
        let two = SeededRng::new([7; 32]);
        let first = bytes32(&one).unwrap();
        assert_eq!(first, bytes32(&two).unwrap());
        assert_ne!(first, bytes32(&one).unwrap());
        let mut long = [0_u8; 40];
        SeededRng::new([7; 32]).fill(&mut long).unwrap();
        assert_eq!(long.get(..32), Some(first.as_slice()));
        assert_ne!(bytes32(&SeededRng::new([8; 32])).unwrap(), first);
    }
}
