//! WebAssembly binding of the Work kernel (T-5): a thin mapping of the kernel API to JavaScript, with no logic of its own.

#![forbid(unsafe_code)]

use core::cmp::Ordering;
use core::fmt::Write as _;

use wasm_bindgen::prelude::wasm_bindgen;
use work_kernel::ApiVersion;
use work_kernel::policy_default as kernel;

pub use js::{ChangeOutcome, PolicyDirection, SwitchBasis, SwitchOutcome, VersionOrder};

#[allow(
    missing_docs,
    reason = "wasm-bindgen adds undocumented hidden items to string enums"
)]
mod js {
    use wasm_bindgen::prelude::wasm_bindgen;

    /// How one API version orders against another.
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum VersionOrder {
        /// The first version is older.
        Less = "less",
        /// Both versions are the same.
        Equal = "equal",
        /// The first version is newer.
        Greater = "greater",
    }

    /// The kind of a numeric policy default and its permitted direction of change (F-26).
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PolicyDirection {
        /// Security value where a larger value is stricter.
        TightenOnlyHigher = "tighten_only_higher",
        /// Security value where a smaller value is stricter.
        TightenOnlyLower = "tighten_only_lower",
        /// Retention period.
        ExtendOnly = "extend_only",
        /// Operational value.
        Bounded = "bounded",
    }

    /// Outcome of a proposed policy default change (F-26).
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ChangeOutcome {
        /// The change is permitted.
        Allowed = "allowed",
        /// The proposed value is outside the declared bounds.
        OutOfBounds = "out_of_bounds",
        /// The change loosens a security or accountability value.
        Loosens = "loosens",
        /// The change shortens a retention period.
        Shortens = "shortens",
    }

    /// What backs a request to turn off a security default (F-26).
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SwitchBasis {
        /// An explicit, recorded and attributable declaration.
        RecordedDeclaration = "recorded_declaration",
        /// A setting, an import or an implicit default.
        Unrecorded = "unrecorded",
    }

    /// Outcome of changing a security switch (F-26).
    #[wasm_bindgen]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SwitchOutcome {
        /// The change is permitted.
        Allowed = "allowed",
        /// Turning the switch off needs a recorded declaration.
        RequiresRecordedDeclaration = "requires_recorded_declaration",
    }
}

/// Kernel public API version as `"major.minor"`.
#[wasm_bindgen(js_name = apiVersion)]
#[must_use]
pub fn api_version() -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{}.{}",
        work_kernel::API_VERSION.major,
        work_kernel::API_VERSION.minor
    );
    out
}

/// Orders API version `a` against `b`, major first.
#[wasm_bindgen(js_name = compareApiVersions)]
#[must_use]
pub fn compare_api_versions(
    a_major: u16,
    a_minor: u16,
    b_major: u16,
    b_minor: u16,
) -> VersionOrder {
    let a = ApiVersion {
        major: a_major,
        minor: a_minor,
    };
    let b = ApiVersion {
        major: b_major,
        minor: b_minor,
    };
    match a.cmp(&b) {
        Ordering::Less => VersionOrder::Less,
        Ordering::Equal => VersionOrder::Equal,
        Ordering::Greater => VersionOrder::Greater,
    }
}

/// Evaluates moving a policy default from `current` to `proposed` inside `[min, max]` (F-26);
/// `undefined` when `direction` is not one of the declared values.
#[wasm_bindgen(js_name = evaluatePolicyChange)]
#[must_use]
pub fn evaluate_policy_change(
    direction: PolicyDirection,
    min: u64,
    max: u64,
    current: u64,
    proposed: u64,
) -> Option<ChangeOutcome> {
    let direction = match direction {
        PolicyDirection::TightenOnlyHigher => {
            kernel::Direction::TightenOnly(kernel::Stricter::Higher)
        }
        PolicyDirection::TightenOnlyLower => {
            kernel::Direction::TightenOnly(kernel::Stricter::Lower)
        }
        PolicyDirection::ExtendOnly => kernel::Direction::ExtendOnly,
        PolicyDirection::Bounded => kernel::Direction::Bounded,
        PolicyDirection::__Invalid => return None,
    };
    let policy = kernel::PolicyDefault {
        direction,
        min,
        max,
    };
    Some(match policy.evaluate(current, proposed) {
        kernel::ChangeOutcome::Allowed => ChangeOutcome::Allowed,
        kernel::ChangeOutcome::OutOfBounds => ChangeOutcome::OutOfBounds,
        kernel::ChangeOutcome::Loosens => ChangeOutcome::Loosens,
        kernel::ChangeOutcome::Shortens => ChangeOutcome::Shortens,
    })
}

/// Evaluates turning a security switch from `current` to `proposed` (`true` is on);
/// `undefined` when `basis` is not one of the declared values.
#[wasm_bindgen(js_name = evaluateSecuritySwitch)]
#[must_use]
pub fn evaluate_security_switch(
    current: bool,
    proposed: bool,
    basis: SwitchBasis,
) -> Option<SwitchOutcome> {
    let basis = match basis {
        SwitchBasis::RecordedDeclaration => kernel::SwitchBasis::RecordedDeclaration,
        SwitchBasis::Unrecorded => kernel::SwitchBasis::Unrecorded,
        SwitchBasis::__Invalid => return None,
    };
    Some(
        match kernel::evaluate_security_switch(current, proposed, basis) {
            kernel::SwitchOutcome::Allowed => SwitchOutcome::Allowed,
            kernel::SwitchOutcome::RequiresRecordedDeclaration => {
                SwitchOutcome::RequiresRecordedDeclaration
            }
        },
    )
}
