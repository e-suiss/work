//! The budget of a commitment (CM-48, CM-49, E-35): a resource Condition in effort time, money (a List One currency and an integer amount in its minor unit) or an operation or token count, with optional warning tiers; consumption is measured by the Executor and arrives as `budget.consumption` observation Claims (CM-63, there is no Pay path), sub-commitment consumption rolls up into the parent's view, an exhausted budget asks the accountable Party to continue, reshape or drop and never extends or cancels by itself, and a budget is not authority: it never widens an Access limit.

use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;

use crate::commitment_time::{self, BodyError, members, push_warnings, uint, warnings};
use crate::currency::{self, Currency};
use crate::id::PartyRef;

/// The extension key a `budget.consumption` observation Claim carries its [`Amount`] body under (CM-63).
pub const CONSUMPTION_EXT_KEY: &str = "https://suiss.app/ns/work/budget.consumption/1";

/// The Condition type a budget is declared with (WD-146).
pub const CONDITION_TYPE: &str = crate::commitment_time::TimeCondition::Budget.uri();

/// What a budget measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measure {
    /// Effort time in milliseconds, apart from the deadline.
    Effort,
    /// Money in the minor unit of a List One currency (CM-62).
    Money(Currency),
    /// A count of operations.
    Operations,
    /// A count of tokens.
    Tokens,
}

impl Measure {
    fn name(self) -> &'static str {
        match self {
            Self::Effort => "effort",
            Self::Money(_) => "money",
            Self::Operations => "operations",
            Self::Tokens => "tokens",
        }
    }

    fn read(value: &Value) -> Result<Self, BodyError> {
        let given = value.get("currency");
        let measure = match value.get("measure") {
            Some(Value::Text(t)) => t.as_str(),
            _ => return Err(BodyError("measure")),
        };
        let plain = match measure {
            "effort" => Self::Effort,
            "operations" => Self::Operations,
            "tokens" => Self::Tokens,
            "money" => {
                let Some(Value::Text(code)) = given else {
                    return Err(BodyError("currency"));
                };
                let found = currency::money(code).map_err(|_| BodyError("currency"))?;
                return Ok(Self::Money(found));
            }
            _ => return Err(BodyError("measure")),
        };
        if given.is_some() {
            return Err(BodyError("currency"));
        }
        Ok(plain)
    }

    fn write(self, entries: &mut Vec<(Value, Value)>) {
        entries.push((Value::text("measure"), Value::text(self.name())));
        if let Self::Money(c) = self {
            entries.push((Value::text("currency"), Value::text(c.code())));
        }
    }
}

/// A budget Condition body (CM-48).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Budget {
    /// What it measures.
    pub measure: Measure,
    /// The limit, at least 1, in the measure's unit.
    pub limit: u64,
    /// Warning tiers in permille of the limit, ascending.
    pub warnings: Vec<u16>,
}

impl Budget {
    /// Checks `value` against the `budget` rule: a List One money currency with a minor unit and not a fund (CM-62), a limit of at least 1 and ascending warning tiers.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Result<Self, BodyError> {
        members(value, &["measure", "currency", "limit", "warnings"])?;
        let measure = Measure::read(value)?;
        let limit = uint(value, "limit")?;
        if limit == 0 {
            return Err(BodyError("limit"));
        }
        Ok(Self {
            measure,
            limit,
            warnings: warnings(value)?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = Vec::new();
        self.measure.write(&mut entries);
        entries.push((Value::text("limit"), Value::Unsigned(self.limit)));
        push_warnings(&mut entries, &self.warnings);
        Value::Map(entries)
    }

    /// Reads deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        Self::from_value(&commitment_time::decode(bytes)?)
    }

    /// The deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`BodyError`] for a body [`Budget::from_value`] would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, BodyError> {
        let value = self.to_value();
        Self::from_value(&value)?;
        commitment_time::encode(&value)
    }
}

/// A measured amount: the body of a `budget.consumption` Claim and the total of a sub-commitment's budget view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Amount {
    /// What was measured.
    pub measure: Measure,
    /// The amount in the measure's unit.
    pub amount: u64,
}

impl Amount {
    /// Checks `value` against the `consumption` rule.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Result<Self, BodyError> {
        members(value, &["measure", "currency", "amount"])?;
        Ok(Self {
            measure: Measure::read(value)?,
            amount: uint(value, "amount")?,
        })
    }

    /// The body as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = Vec::new();
        self.measure.write(&mut entries);
        entries.push((Value::text("amount"), Value::Unsigned(self.amount)));
        Value::Map(entries)
    }

    /// Reads deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        Self::from_value(&commitment_time::decode(bytes)?)
    }

    /// The deterministic CBOR bytes of the body.
    ///
    /// # Errors
    /// [`BodyError`] for a body [`Amount::from_value`] would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, BodyError> {
        let value = self.to_value();
        Self::from_value(&value)?;
        commitment_time::encode(&value)
    }
}

/// One `budget.consumption` Claim: its author and its body (CM-63).
#[derive(Clone, Copy, Debug)]
pub struct Consumption<'a> {
    /// The Claim's author.
    pub source: &'a PartyRef,
    /// The measured amount.
    pub amount: Amount,
}

/// An Access limit for one measure, as Access states it; Work only compares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessLimit {
    /// What it limits.
    pub measure: Measure,
    /// The limit in the measure's unit.
    pub limit: u64,
}

/// Why a budget cannot be evaluated or declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// A sum left the integer range.
    Overflow,
    /// The budget is above the Access limit of its measure (CM-49).
    WidensAccessLimit,
    /// An Access limit names another currency; Work does not convert money (CM-49).
    IncomparableAccessLimit,
}

impl core::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Overflow => "budget arithmetic overflow",
            Self::WidensAccessLimit => "the budget is above the Access limit",
            Self::IncomparableAccessLimit => "the Access limit is in another currency",
        })
    }
}

impl core::error::Error for BudgetError {}

/// One choice of the exhausted budget decision (CM-49).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Continue: raise the budget.
    Continue,
    /// Reshape: change the scope or the terms.
    Reshape,
    /// Drop the work.
    Drop,
}

/// The side of the commitment the accountable Party decides for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The creditor's side.
    Creditor,
    /// The obligor's side.
    Obligor,
}

/// The commitment operation a choice is carried out with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// `amend`.
    Amend,
    /// `release`, on the creditor's side.
    Release,
    /// `cancel`, on the obligor's side.
    Cancel,
}

impl Choice {
    /// The three choices, in the order they are offered.
    pub const ALL: [Self; 3] = [Self::Continue, Self::Reshape, Self::Drop];

    /// The operation that carries the choice out on `side`.
    #[must_use]
    pub const fn operation(self, side: Side) -> Operation {
        match (self, side) {
            (Self::Continue | Self::Reshape, _) => Operation::Amend,
            (Self::Drop, Side::Creditor) => Operation::Release,
            (Self::Drop, Side::Obligor) => Operation::Cancel,
        }
    }
}

/// The decision an exhausted budget asks of the accountable Party: a resource-decision wait addressed to it with three choices; nothing changes until one is recorded (CM-49).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The choices offered.
    pub choices: [Choice; 3],
}

/// The derived view of a budget; never stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetView {
    /// Consumption from the commitment's own Executors.
    pub own: u64,
    /// Consumption rolled up from sub-commitments in the same measure.
    pub children: u64,
    /// `own` plus `children`.
    pub consumed: u64,
    /// What is left of the limit, zero once exhausted.
    pub remaining: u64,
    /// The highest warning tier reached, in permille.
    pub warning: Option<u16>,
    /// Whether consumption reached the limit.
    pub exhausted: bool,
    /// The decision asked of the accountable Party once exhausted.
    pub decision: Option<Decision>,
    /// Consumption Claims not counted: from a Party that is not an Executor of the commitment, or in another measure.
    pub ignored: usize,
    /// Sub-commitment totals not counted, in another measure.
    pub unmatched: usize,
}

impl Budget {
    /// The view of the budget from the consumption Claims of the commitment, counting only those whose author is among `executors` and whose measure is the budget's, and from the totals of its sub-commitments in the same measure (CM-48); an exhausted budget yields a [`Decision`] and changes nothing else (CM-49).
    ///
    /// # Errors
    /// [`BudgetError::Overflow`] when a sum leaves the integer range.
    pub fn evaluate(
        &self,
        executors: &[PartyRef],
        consumption: &[Consumption<'_>],
        children: &[Amount],
    ) -> Result<BudgetView, BudgetError> {
        let mut own: u64 = 0;
        let mut ignored: usize = 0;
        for c in consumption {
            if executors.contains(c.source) && c.amount.measure == self.measure {
                own = own
                    .checked_add(c.amount.amount)
                    .ok_or(BudgetError::Overflow)?;
            } else {
                ignored = ignored.saturating_add(1);
            }
        }
        let mut rolled: u64 = 0;
        let mut unmatched: usize = 0;
        for child in children {
            if child.measure == self.measure {
                rolled = rolled
                    .checked_add(child.amount)
                    .ok_or(BudgetError::Overflow)?;
            } else {
                unmatched = unmatched.saturating_add(1);
            }
        }
        let consumed = own.checked_add(rolled).ok_or(BudgetError::Overflow)?;
        let exhausted = consumed >= self.limit;
        let reached = u128::from(consumed)
            .checked_mul(1_000)
            .ok_or(BudgetError::Overflow)?;
        let mut warning = None;
        for tier in &self.warnings {
            let line = u128::from(self.limit)
                .checked_mul(u128::from(*tier))
                .ok_or(BudgetError::Overflow)?;
            if reached >= line {
                warning = Some(*tier);
            }
        }
        Ok(BudgetView {
            own,
            children: rolled,
            consumed,
            remaining: self.limit.saturating_sub(consumed),
            warning,
            exhausted,
            decision: exhausted.then_some(Decision {
                choices: Choice::ALL,
            }),
            ignored,
            unmatched,
        })
    }

    /// The total this budget's view contributes to its parent's roll-up.
    ///
    /// # Errors
    /// [`BudgetError::Overflow`] as [`Budget::evaluate`].
    pub fn total(
        &self,
        executors: &[PartyRef],
        consumption: &[Consumption<'_>],
        children: &[Amount],
    ) -> Result<Amount, BudgetError> {
        let view = self.evaluate(executors, consumption, children)?;
        Ok(Amount {
            measure: self.measure,
            amount: view.consumed,
        })
    }

    /// Checks that the budget does not widen the Access limits of its measure (CM-49): a limit in the same measure must be at least the budget, and a money limit in another currency cannot be compared; an effort budget has no Access counterpart.
    ///
    /// # Errors
    /// [`BudgetError::WidensAccessLimit`] or [`BudgetError::IncomparableAccessLimit`].
    pub fn within_access_limits(&self, limits: &[AccessLimit]) -> Result<(), BudgetError> {
        for limit in limits {
            match (self.measure, limit.measure) {
                (Measure::Money(mine), Measure::Money(theirs)) if mine != theirs => {
                    return Err(BudgetError::IncomparableAccessLimit);
                }
                (mine, theirs) if mine == theirs && self.limit > limit.limit => {
                    return Err(BudgetError::WidensAccessLimit);
                }
                _ => {}
            }
        }
        Ok(())
    }
}
