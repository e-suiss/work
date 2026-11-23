//! Work kernel (T-4): deterministic derivation over records, without I/O.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod activation;
pub mod budget;
pub mod calendar;
pub mod catalog;
pub mod clock;
pub mod codec;
pub mod commitment;
pub mod commitment_time;
pub mod compromise;
pub mod cose;
pub mod currency;
pub mod derive;
pub mod envelope;
pub mod explanation;
pub mod id;
pub mod items;
pub mod limits;
pub mod ontology;
pub mod policy_default;
pub mod proof;
pub mod reason;
pub mod record;
pub mod relation;
pub mod rrule;
pub mod rules;
pub mod tz;
pub mod uri;
pub mod validate;
pub mod verify;

/// Version of the kernel public API (T-4 rule 4).
pub const API_VERSION: ApiVersion = ApiVersion {
    major: 0,
    minor: 16,
};

/// A kernel public API version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVersion {
    /// Incremented on breaking changes.
    pub major: u16,
    /// Incremented on additive changes.
    pub minor: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-4
    #[test]
    fn t_4_api_versions_order_by_major_then_minor() {
        let a = ApiVersion {
            major: 0,
            minor: 16,
        };
        let b = ApiVersion { major: 1, minor: 0 };
        assert!(a < b);
        assert!(API_VERSION <= a);
    }
}
