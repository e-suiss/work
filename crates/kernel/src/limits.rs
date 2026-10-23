//! Work-specific semantic limits with kernel defaults that an installation or ledger may only narrow (P-33, T-65, SEC-18).

use crate::reason::Limit;

/// Semantic limits on one record; constructed only from the defaults by narrowing (T-65).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemanticLimits {
    basis: usize,
    on_behalf_of: usize,
    relations: usize,
    concerns: usize,
}

/// Why a limit cannot be narrowed to a configured value (T-65).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NarrowError {
    /// The value is wider than the current maximum.
    Widens {
        /// The limit that would widen.
        limit: Limit,
        /// The current maximum.
        max: usize,
        /// The requested value.
        requested: usize,
    },
    /// The limit is structural and belongs to the shared crate, not to these semantic limits.
    Structural(Limit),
}

impl NarrowError {
    /// The stable `snake_case` code of the error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Widens { .. } => "widens_limit",
            Self::Structural(_) => "structural_limit",
        }
    }
}

impl SemanticLimits {
    /// The kernel defaults: basis 64, `on_behalf_of` 8, relations 256, concerns 64 (P-33).
    pub const DEFAULT: Self = Self {
        basis: 64,
        on_behalf_of: 8,
        relations: 256,
        concerns: 64,
    };

    /// Narrows one limit.
    ///
    /// # Errors
    ///
    /// Returns [`NarrowError::Widens`] when `value` exceeds the current maximum and [`NarrowError::Structural`] when `limit` is not a semantic limit.
    pub fn narrow(self, limit: Limit, value: usize) -> Result<Self, NarrowError> {
        let mut out = self;
        let slot = match limit {
            Limit::Basis => &mut out.basis,
            Limit::OnBehalfOf => &mut out.on_behalf_of,
            Limit::Relations => &mut out.relations,
            Limit::Concerns => &mut out.concerns,
            Limit::Depth | Limit::Items | Limit::String | Limit::Request => {
                return Err(NarrowError::Structural(limit));
            }
        };
        if value > *slot {
            return Err(NarrowError::Widens {
                limit,
                max: *slot,
                requested: value,
            });
        }
        *slot = value;
        Ok(out)
    }

    /// The maximum for a semantic limit; `None` for structural limits, which belong to the shared crate.
    #[must_use]
    pub const fn max(&self, limit: Limit) -> Option<usize> {
        match limit {
            Limit::Basis => Some(self.basis),
            Limit::OnBehalfOf => Some(self.on_behalf_of),
            Limit::Relations => Some(self.relations),
            Limit::Concerns => Some(self.concerns),
            Limit::Depth | Limit::Items | Limit::String | Limit::Request => None,
        }
    }
}

impl Default for SemanticLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-65 P-33
    #[test]
    fn t_65_defaults_match_the_p_33_table() {
        let l = SemanticLimits::default();
        assert_eq!(l.max(Limit::Basis), Some(64));
        assert_eq!(l.max(Limit::OnBehalfOf), Some(8));
        assert_eq!(l.max(Limit::Relations), Some(256));
        assert_eq!(l.max(Limit::Concerns), Some(64));
        assert_eq!(l.max(Limit::Request), None);
    }

    // T-65
    #[test]
    fn t_65_limits_only_narrow() {
        let narrowed = SemanticLimits::DEFAULT.narrow(Limit::Basis, 10).unwrap();
        assert_eq!(narrowed.max(Limit::Basis), Some(10));
        assert_eq!(
            narrowed.narrow(Limit::Basis, 11),
            Err(NarrowError::Widens {
                limit: Limit::Basis,
                max: 10,
                requested: 11
            })
        );
        assert!(SemanticLimits::DEFAULT.narrow(Limit::Concerns, 65).is_err());
        assert!(
            SemanticLimits::DEFAULT
                .narrow(Limit::OnBehalfOf, 9)
                .is_err()
        );
        assert!(
            SemanticLimits::DEFAULT
                .narrow(Limit::Relations, 257)
                .is_err()
        );
        for structural in [Limit::Depth, Limit::Items, Limit::String, Limit::Request] {
            let error = SemanticLimits::DEFAULT.narrow(structural, 1);
            assert_eq!(error, Err(NarrowError::Structural(structural)));
            assert_eq!(error.err().map(NarrowError::code), Some("structural_limit"));
        }
        let all = SemanticLimits::DEFAULT
            .narrow(Limit::OnBehalfOf, 2)
            .and_then(|l| l.narrow(Limit::Relations, 3))
            .and_then(|l| l.narrow(Limit::Concerns, 4))
            .unwrap();
        assert_eq!(all.max(Limit::OnBehalfOf), Some(2));
        assert_eq!(all.max(Limit::Relations), Some(3));
        assert_eq!(all.max(Limit::Concerns), Some(4));
    }
}
