//! ISO 4217 currencies (CM-62): the alphabetic codes and minor unit exponents of SIX's List One, pinned in the repository with its publication date and compiled into the kernel, so the list version shows in the kernel version and never in a record; a money budget refuses a code without a minor unit (`N.A.`) and a fund code.

mod list_one;

/// The publication date of the List One the kernel was built with.
pub const LIST_ONE_PUBLISHED: &str = list_one::PUBLISHED;

/// One List One code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Currency {
    code: &'static str,
    numeric: u16,
    minor_units: Option<u8>,
    fund: bool,
}

impl Currency {
    pub(crate) const fn new(
        code: &'static str,
        numeric: u16,
        minor_units: Option<u8>,
        fund: bool,
    ) -> Self {
        Self {
            code,
            numeric,
            minor_units,
            fund,
        }
    }

    /// The alphabetic code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// The numeric code.
    #[must_use]
    pub const fn numeric(self) -> u16 {
        self.numeric
    }

    /// The minor unit exponent; `None` where the list writes `N.A.`.
    #[must_use]
    pub const fn minor_units(self) -> Option<u8> {
        self.minor_units
    }

    /// Whether SIX marks the code a fund.
    #[must_use]
    pub const fn is_fund(self) -> bool {
        self.fund
    }
}

/// Why a code is not a money budget currency (CM-62).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrencyError {
    /// Not an alphabetic code of the pinned List One.
    Unknown,
    /// The list has no minor unit for the code (`N.A.`): metals, special drawing rights, the testing and the no-currency codes.
    NoMinorUnit,
    /// A fund code.
    Fund,
}

impl core::fmt::Display for CurrencyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "not an ISO 4217 List One code",
            Self::NoMinorUnit => "the code has no minor unit",
            Self::Fund => "the code is a fund code",
        })
    }
}

impl core::error::Error for CurrencyError {}

/// The List One entry of an alphabetic code.
#[must_use]
pub fn lookup(code: &str) -> Option<Currency> {
    list_one::ENTRIES
        .binary_search_by(|e| e.code.cmp(code))
        .ok()
        .and_then(|i| list_one::ENTRIES.get(i))
        .copied()
}

/// The currency of a money budget or consumption (CM-62).
///
/// # Errors
/// [`CurrencyError`] for an unknown code, a code without a minor unit and a fund code.
pub fn money(code: &str) -> Result<Currency, CurrencyError> {
    let found = lookup(code).ok_or(CurrencyError::Unknown)?;
    if found.fund {
        return Err(CurrencyError::Fund);
    }
    if found.minor_units.is_none() {
        return Err(CurrencyError::NoMinorUnit);
    }
    Ok(found)
}
