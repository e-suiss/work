//! Direction rules for changing a POLICY DEFAULT value (F-26).

/// Which way a security or accountability value becomes stricter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stricter {
    /// A larger value is stricter, such as a gate threshold.
    Higher,
    /// A smaller value is stricter, such as a maximum delay before escalation.
    Lower,
}

/// The kind of a numeric policy default and the direction it may move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Security and accountability values: lower scopes only tighten.
    TightenOnly(Stricter),
    /// Retention periods: templates and tenants only extend.
    ExtendOnly,
    /// Operational values: either way inside the bounds.
    Bounded,
}

/// A numeric policy default with its declared bounds (inclusive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyDefault {
    /// Permitted direction of change.
    pub direction: Direction,
    /// Lowest permitted value.
    pub min: u64,
    /// Highest permitted value.
    pub max: u64,
}

/// Outcome of a proposed change. A rejection is a decision, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeOutcome {
    /// The change is permitted.
    Allowed,
    /// The proposed value is outside the declared bounds.
    OutOfBounds,
    /// The change loosens a security or accountability value.
    Loosens,
    /// The change shortens a retention period.
    Shortens,
}

impl PolicyDefault {
    /// Evaluates moving the effective value from `current` to `proposed`.
    #[must_use]
    pub fn evaluate(&self, current: u64, proposed: u64) -> ChangeOutcome {
        if proposed < self.min || proposed > self.max {
            return ChangeOutcome::OutOfBounds;
        }
        match self.direction {
            Direction::TightenOnly(Stricter::Higher) if proposed < current => {
                ChangeOutcome::Loosens
            }
            Direction::TightenOnly(Stricter::Lower) if proposed > current => ChangeOutcome::Loosens,
            Direction::ExtendOnly if proposed < current => ChangeOutcome::Shortens,
            _ => ChangeOutcome::Allowed,
        }
    }
}

/// What backs a request to turn off a security default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchBasis {
    /// An explicit, recorded and attributable declaration that stays visible on the work.
    RecordedDeclaration,
    /// Anything else: a setting, an import, an implicit default.
    Unrecorded,
}

/// Outcome of changing a security switch such as four-eyes acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchOutcome {
    /// The change is permitted.
    Allowed,
    /// Turning the switch off needs a recorded declaration.
    RequiresRecordedDeclaration,
}

/// Evaluates turning a security switch from `current` to `proposed` (`true` is on).
#[must_use]
pub fn evaluate_security_switch(
    current: bool,
    proposed: bool,
    basis: SwitchBasis,
) -> SwitchOutcome {
    if current && !proposed && basis == SwitchBasis::Unrecorded {
        SwitchOutcome::RequiresRecordedDeclaration
    } else {
        SwitchOutcome::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD: PolicyDefault = PolicyDefault {
        direction: Direction::TightenOnly(Stricter::Higher),
        min: 1,
        max: 5,
    };

    // F-26
    #[test]
    fn f_26_security_values_only_tighten() {
        assert_eq!(THRESHOLD.evaluate(2, 3), ChangeOutcome::Allowed);
        assert_eq!(THRESHOLD.evaluate(3, 2), ChangeOutcome::Loosens);
        let delay = PolicyDefault {
            direction: Direction::TightenOnly(Stricter::Lower),
            min: 60,
            max: 86_400,
        };
        assert_eq!(delay.evaluate(3_600, 600), ChangeOutcome::Allowed);
        assert_eq!(delay.evaluate(600, 3_600), ChangeOutcome::Loosens);
    }

    // F-26 MD-16
    #[test]
    fn f_26_retention_only_extends() {
        let retention = PolicyDefault {
            direction: Direction::ExtendOnly,
            min: 30,
            max: u64::MAX,
        };
        assert_eq!(retention.evaluate(400, 800), ChangeOutcome::Allowed);
        assert_eq!(retention.evaluate(800, 400), ChangeOutcome::Shortens);
    }

    // F-26
    #[test]
    fn f_26_operational_values_move_both_ways_inside_bounds() {
        let interval = PolicyDefault {
            direction: Direction::Bounded,
            min: 10,
            max: 100,
        };
        assert_eq!(interval.evaluate(50, 20), ChangeOutcome::Allowed);
        assert_eq!(interval.evaluate(50, 90), ChangeOutcome::Allowed);
        assert_eq!(interval.evaluate(50, 101), ChangeOutcome::OutOfBounds);
        assert_eq!(THRESHOLD.evaluate(5, 6), ChangeOutcome::OutOfBounds);
    }

    // F-26 MD-5
    #[test]
    fn f_26_security_switch_turns_off_only_with_a_recorded_declaration() {
        assert_eq!(
            evaluate_security_switch(true, false, SwitchBasis::Unrecorded),
            SwitchOutcome::RequiresRecordedDeclaration
        );
        assert_eq!(
            evaluate_security_switch(true, false, SwitchBasis::RecordedDeclaration),
            SwitchOutcome::Allowed
        );
        assert_eq!(
            evaluate_security_switch(false, true, SwitchBasis::Unrecorded),
            SwitchOutcome::Allowed
        );
    }
}
