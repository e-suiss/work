//! Work kernel (T-4): deterministic derivation over records, without I/O.

#![no_std]
#![forbid(unsafe_code)]

/// Version of the kernel public API (T-4 rule 4).
pub const API_VERSION: ApiVersion = ApiVersion { major: 0, minor: 0 };

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
        let a = ApiVersion { major: 0, minor: 9 };
        let b = ApiVersion { major: 1, minor: 0 };
        assert!(a < b);
        assert!(API_VERSION <= a);
    }
}
