//! uniffi binding of the Work kernel for Swift and Kotlin (T-5): a thin mapping of the kernel API, with no logic of its own.

#![forbid(unsafe_code)]

use core::cmp::Ordering;

use work_kernel::ApiVersion;
use work_kernel::policy_default::{
    ChangeOutcome, Direction, PolicyDefault, Stricter, SwitchBasis, SwitchOutcome,
};

uniffi::setup_scaffolding!();

#[uniffi::remote(Record)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}

#[uniffi::remote(Enum)]
pub enum Stricter {
    Higher,
    Lower,
}

#[uniffi::remote(Enum)]
pub enum Direction {
    TightenOnly(Stricter),
    ExtendOnly,
    Bounded,
}

#[uniffi::remote(Record)]
pub struct PolicyDefault {
    pub direction: Direction,
    pub min: u64,
    pub max: u64,
}

#[uniffi::remote(Enum)]
pub enum ChangeOutcome {
    Allowed,
    OutOfBounds,
    Loosens,
    Shortens,
}

#[uniffi::remote(Enum)]
pub enum SwitchBasis {
    RecordedDeclaration,
    Unrecorded,
}

#[uniffi::remote(Enum)]
pub enum SwitchOutcome {
    Allowed,
    RequiresRecordedDeclaration,
}

/// How one API version orders against another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum VersionOrder {
    /// The first version is older.
    Less,
    /// Both versions are the same.
    Equal,
    /// The first version is newer.
    Greater,
}

/// Kernel public API version.
#[uniffi::export]
#[must_use]
pub fn api_version() -> ApiVersion {
    work_kernel::API_VERSION
}

/// Orders API version `a` against `b`, major first.
#[uniffi::export]
#[must_use]
pub fn compare_api_versions(a: ApiVersion, b: ApiVersion) -> VersionOrder {
    match a.cmp(&b) {
        Ordering::Less => VersionOrder::Less,
        Ordering::Equal => VersionOrder::Equal,
        Ordering::Greater => VersionOrder::Greater,
    }
}

/// Evaluates moving `policy` from `current` to `proposed` (F-26).
#[uniffi::export]
#[must_use]
pub fn evaluate_policy_change(policy: PolicyDefault, current: u64, proposed: u64) -> ChangeOutcome {
    policy.evaluate(current, proposed)
}

/// Evaluates turning a security switch from `current` to `proposed` (`true` is on; F-26).
#[uniffi::export]
#[must_use]
pub fn evaluate_security_switch(
    current: bool,
    proposed: bool,
    basis: SwitchBasis,
) -> SwitchOutcome {
    work_kernel::policy_default::evaluate_security_switch(current, proposed, basis)
}
