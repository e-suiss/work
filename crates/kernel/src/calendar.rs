//! Civil dates and the business calendar of a commitment clock (CM-64): an explicit declaration inside the clock definition of an IANA time zone, working intervals for each weekday in local time at minute resolution and holidays as local dates, with no outside holiday source; counted time over a calendar is the overlap with its working intervals in the zone's local time.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;

use crate::commitment_time::{BodyError, members, text};
use crate::id::Time;
use crate::tz::Zone;

/// Seconds in a civil day.
pub const SECONDS_PER_DAY: i64 = 86_400;

/// Minutes in a civil day; an interval may end at it.
pub const MINUTES_PER_DAY: u16 = 1_440;

/// Most local days one counting step walks: about ten years.
pub const MAX_DAYS: i64 = 3_660;

/// Most working intervals of one weekday.
pub const MAX_INTERVALS: usize = 8;

/// Most holidays of one calendar.
pub const MAX_HOLIDAYS: usize = 256;

const fn is_leap(year: i32) -> bool {
    let by4 = matches!(year.checked_rem(4), Some(0));
    let by100 = matches!(year.checked_rem(100), Some(0));
    let by400 = matches!(year.checked_rem(400), Some(0));
    by4 && (!by100 || by400)
}

/// Days of a month, for months 1 to 12.
#[must_use]
pub const fn days_in_month(year: i32, month: u8) -> Option<u8> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

/// Days from 1970-01-01 to a valid date of the years 1 to 9999.
#[must_use]
pub fn days_from_civil(year: i32, month: u8, day: u8) -> Option<i64> {
    let last = days_in_month(year, month)?;
    if !(1..=9999).contains(&year) || day < 1 || day > last {
        return None;
    }
    let y = i64::from(year).checked_sub(i64::from(month <= 2))?;
    let era = y.checked_div(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let m = i64::from(month);
    let shifted = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = shifted
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(i64::from(day))?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// The date of a day count from 1970-01-01, for the years 1 to 9999.
#[must_use]
pub fn civil_from_days(days: i64) -> Option<(i32, u8, u8)> {
    let z = days.checked_add(719_468)?;
    if z < 0 {
        return None;
    }
    let era = z.checked_div(146_097)?;
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1_460)?)?
        .checked_add(doe.checked_div(36_524)?)?
        .checked_sub(doe.checked_div(146_096)?)?
        .checked_div(365)?;
    let y = yoe.checked_add(era.checked_mul(400)?)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let year = i32::try_from(y.checked_add(i64::from(m <= 2))?).ok()?;
    if !(1..=9999).contains(&year) {
        return None;
    }
    Some((year, u8::try_from(m).ok()?, u8::try_from(d).ok()?))
}

/// The ISO weekday of a day count, Monday 0 to Sunday 6.
#[must_use]
pub fn weekday(days: i64) -> Option<u8> {
    u8::try_from(days.checked_add(3)?.checked_rem_euclid(7)?).ok()
}

fn digits(text: &str, from: usize, len: usize) -> Option<u32> {
    let part = text.get(from..from.checked_add(len)?)?;
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}

/// A local calendar date of the years 1 to 9999.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    /// The year.
    pub year: i32,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month.
    pub day: u8,
}

impl Date {
    /// A valid date.
    #[must_use]
    pub fn new(year: i32, month: u8, day: u8) -> Option<Self> {
        days_from_civil(year, month, day)?;
        Some(Self { year, month, day })
    }

    /// Reads `YYYY-MM-DD`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
            return None;
        }
        let year = i32::try_from(digits(text, 0, 4)?).ok()?;
        let month = u8::try_from(digits(text, 5, 2)?).ok()?;
        let day = u8::try_from(digits(text, 8, 2)?).ok()?;
        Self::new(year, month, day)
    }

    /// Writes `YYYY-MM-DD`.
    #[must_use]
    pub fn to_text(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// Days from 1970-01-01.
    #[must_use]
    pub fn days(self) -> Option<i64> {
        days_from_civil(self.year, self.month, self.day)
    }

    /// The date of a day count from 1970-01-01.
    #[must_use]
    pub fn from_days(days: i64) -> Option<Self> {
        let (year, month, day) = civil_from_days(days)?;
        Some(Self { year, month, day })
    }
}

/// A local date and time at second resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalDateTime {
    /// The date.
    pub date: Date,
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minute, 0 to 59.
    pub minute: u8,
    /// The second, 0 to 59.
    pub second: u8,
}

impl LocalDateTime {
    /// A valid local date and time.
    #[must_use]
    pub const fn new(date: Date, hour: u8, minute: u8, second: u8) -> Option<Self> {
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Some(Self {
            date,
            hour,
            minute,
            second,
        })
    }

    /// Reads the RFC 5545 local form `YYYYMMDDTHHMMSS`.
    #[must_use]
    pub fn parse_basic(text: &str) -> Option<Self> {
        if text.len() != 15 || text.as_bytes().get(8) != Some(&b'T') {
            return None;
        }
        let date = Date::new(
            i32::try_from(digits(text, 0, 4)?).ok()?,
            u8::try_from(digits(text, 4, 2)?).ok()?,
            u8::try_from(digits(text, 6, 2)?).ok()?,
        )?;
        Self::new(
            date,
            u8::try_from(digits(text, 9, 2)?).ok()?,
            u8::try_from(digits(text, 11, 2)?).ok()?,
            u8::try_from(digits(text, 13, 2)?).ok()?,
        )
    }

    /// Writes the RFC 5545 local form `YYYYMMDDTHHMMSS`.
    #[must_use]
    pub fn to_basic(self) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}",
            self.date.year, self.date.month, self.date.day, self.hour, self.minute, self.second
        )
    }

    /// Local seconds from `1970-01-01T00:00:00`, as if the local time were UTC.
    #[must_use]
    pub fn seconds(self) -> Option<i64> {
        let clock = i64::from(self.hour)
            .checked_mul(3_600)?
            .checked_add(i64::from(self.minute).checked_mul(60)?)?
            .checked_add(i64::from(self.second))?;
        self.date
            .days()?
            .checked_mul(SECONDS_PER_DAY)?
            .checked_add(clock)
    }

    /// The local date and time of local seconds from `1970-01-01T00:00:00`.
    #[must_use]
    pub fn from_seconds(seconds: i64) -> Option<Self> {
        let days = seconds.checked_div_euclid(SECONDS_PER_DAY)?;
        let rest = seconds.checked_rem_euclid(SECONDS_PER_DAY)?;
        let hour = u8::try_from(rest.checked_div(3_600)?).ok()?;
        let minute = u8::try_from(rest.checked_rem(3_600)?.checked_div(60)?).ok()?;
        let second = u8::try_from(rest.checked_rem(60)?).ok()?;
        Self::new(Date::from_days(days)?, hour, minute, second)
    }
}

/// A working interval of a weekday in local minutes, `start` inclusive and `end` exclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interval {
    /// First working minute, 0 to 1439.
    pub start: u16,
    /// The minute work stops, 1 to 1440.
    pub end: u16,
}

/// Why counted time cannot be computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalendarError {
    /// The calendar's zone is not among the supplied tzdb zones, or its rules cannot place the time.
    Zone,
    /// The span is longer than [`MAX_DAYS`] local days.
    Span,
    /// The calendar has no working interval on any weekday.
    NoWorkingTime,
    /// A time outside the representable range.
    Range,
}

impl core::fmt::Display for CalendarError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Zone => "the calendar zone is not available",
            Self::Span => "the span is too long",
            Self::NoWorkingTime => "the calendar has no working time",
            Self::Range => "time out of range",
        })
    }
}

impl core::error::Error for CalendarError {}

/// A business calendar (CM-64).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkCalendar {
    /// The IANA zone name.
    pub zone: String,
    /// Working intervals from Monday to Sunday, each ascending and without overlap.
    pub week: [Vec<Interval>; 7],
    /// Holidays as local dates, ascending without repeats; a holiday has no working time.
    pub holidays: Vec<Date>,
}

fn day_intervals(day: &Value) -> Result<Vec<Interval>, BodyError> {
    let Value::Array(items) = day else {
        return Err(BodyError("week"));
    };
    if items.len() > MAX_INTERVALS {
        return Err(BodyError("week"));
    }
    let mut out: Vec<Interval> = Vec::with_capacity(items.len());
    for item in items {
        let Value::Array(pair) = item else {
            return Err(BodyError("week"));
        };
        let (start, end) = match pair.as_slice() {
            [Value::Unsigned(s), Value::Unsigned(e)] => (
                u16::try_from(*s).map_err(|_| BodyError("week"))?,
                u16::try_from(*e).map_err(|_| BodyError("week"))?,
            ),
            _ => return Err(BodyError("week")),
        };
        let after_previous = out.last().is_none_or(|p| p.end <= start);
        if start >= end || end > MINUTES_PER_DAY || !after_previous {
            return Err(BodyError("week"));
        }
        out.push(Interval { start, end });
    }
    Ok(out)
}

fn holidays(value: &Value) -> Result<Vec<Date>, BodyError> {
    let Some(found) = value.get("holidays") else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = found else {
        return Err(BodyError("holidays"));
    };
    if items.is_empty() || items.len() > MAX_HOLIDAYS {
        return Err(BodyError("holidays"));
    }
    let mut out: Vec<Date> = Vec::with_capacity(items.len());
    for item in items {
        let date = match item {
            Value::Text(t) => Date::parse(t).ok_or(BodyError("holidays"))?,
            _ => return Err(BodyError("holidays")),
        };
        if out.last().is_some_and(|p| *p >= date) {
            return Err(BodyError("holidays"));
        }
        out.push(date);
    }
    Ok(out)
}

fn ms(seconds: i64) -> Result<u64, CalendarError> {
    u64::try_from(seconds)
        .ok()
        .and_then(|s| s.checked_mul(1_000))
        .ok_or(CalendarError::Range)
}

fn local_day(zone: &Zone, at: Time) -> Result<i64, CalendarError> {
    zone.local_seconds(at)
        .map_err(|_| CalendarError::Zone)?
        .checked_div_euclid(SECONDS_PER_DAY)
        .ok_or(CalendarError::Range)
}

fn boundary(zone: &Zone, day: i64, minute: u16) -> Result<u64, CalendarError> {
    let local = day
        .checked_mul(SECONDS_PER_DAY)
        .and_then(|s| s.checked_add(i64::from(minute).checked_mul(60)?))
        .ok_or(CalendarError::Range)?;
    ms(zone.to_utc(local).map_err(|_| CalendarError::Zone)?)
}

impl WorkCalendar {
    /// Checks `value` against the `calendar` rule.
    ///
    /// # Errors
    /// [`BodyError`] naming the member that does not fit.
    pub fn from_value(value: &Value) -> Result<Self, BodyError> {
        members(value, &["zone", "week", "holidays"])?;
        let zone = String::from(text(value, "zone", 64)?);
        let Some(Value::Array(days)) = value.get("week") else {
            return Err(BodyError("week"));
        };
        if days.len() != 7 {
            return Err(BodyError("week"));
        }
        let mut week: Vec<Vec<Interval>> = Vec::with_capacity(7);
        for day in days {
            week.push(day_intervals(day)?);
        }
        let week: [Vec<Interval>; 7] = week.try_into().map_err(|_| BodyError("week"))?;
        Ok(Self {
            zone,
            week,
            holidays: holidays(value)?,
        })
    }

    /// The calendar as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let week = self
            .week
            .iter()
            .map(|day| {
                Value::Array(
                    day.iter()
                        .map(|i| {
                            Value::Array(alloc::vec![
                                Value::Unsigned(u64::from(i.start)),
                                Value::Unsigned(u64::from(i.end)),
                            ])
                        })
                        .collect(),
                )
            })
            .collect();
        let mut entries = alloc::vec![
            (Value::text("zone"), Value::text(&self.zone)),
            (Value::text("week"), Value::Array(week)),
        ];
        if !self.holidays.is_empty() {
            entries.push((
                Value::text("holidays"),
                Value::Array(
                    self.holidays
                        .iter()
                        .map(|d| Value::Text(d.to_text()))
                        .collect(),
                ),
            ));
        }
        Value::Map(entries)
    }

    fn intervals(&self, day: i64) -> Result<&[Interval], CalendarError> {
        let date = Date::from_days(day).ok_or(CalendarError::Range)?;
        if self.holidays.binary_search(&date).is_ok() {
            return Ok(&[]);
        }
        let wd = weekday(day).ok_or(CalendarError::Range)?;
        self.week
            .get(usize::from(wd))
            .map(Vec::as_slice)
            .ok_or(CalendarError::Range)
    }

    fn elapsed(&self, zone: &Zone, from: Time, to: Time) -> Result<u64, CalendarError> {
        if to <= from {
            return Ok(0);
        }
        let first = local_day(zone, from)?;
        let last = local_day(zone, to)?;
        if last.checked_sub(first).is_none_or(|span| span > MAX_DAYS) {
            return Err(CalendarError::Span);
        }
        let mut total: u64 = 0;
        let mut day = first;
        while day <= last {
            for i in self.intervals(day)? {
                let lo = boundary(zone, day, i.start)?.max(from.0);
                let hi = boundary(zone, day, i.end)?.min(to.0);
                if let Some(overlap) = hi.checked_sub(lo) {
                    total = total.checked_add(overlap).ok_or(CalendarError::Range)?;
                }
            }
            day = day.checked_add(1).ok_or(CalendarError::Range)?;
        }
        Ok(total)
    }

    fn advance(&self, zone: &Zone, from: Time, amount: u64) -> Result<Time, CalendarError> {
        if amount == 0 {
            return Ok(from);
        }
        if self.week.iter().all(Vec::is_empty) {
            return Err(CalendarError::NoWorkingTime);
        }
        let first = local_day(zone, from)?;
        let mut left = amount;
        for offset in 0..=MAX_DAYS {
            let day = first.checked_add(offset).ok_or(CalendarError::Range)?;
            for i in self.intervals(day)? {
                let lo = boundary(zone, day, i.start)?.max(from.0);
                let hi = boundary(zone, day, i.end)?;
                let Some(available) = hi.checked_sub(lo) else {
                    continue;
                };
                if left <= available {
                    return lo.checked_add(left).map(Time).ok_or(CalendarError::Range);
                }
                left = left.checked_sub(available).ok_or(CalendarError::Range)?;
            }
        }
        Err(CalendarError::Span)
    }
}

/// How a clock counts time: every instant, or the working time of a business calendar in its zone.
#[derive(Clone, Copy, Debug)]
pub enum Counting<'a> {
    /// Every instant counts.
    Continuous,
    /// Only the calendar's working time counts.
    Calendar(&'a WorkCalendar, &'a Zone),
}

impl<'a> Counting<'a> {
    /// Counting over `calendar`, its zone looked up by name among `zones`; continuous without a calendar.
    ///
    /// # Errors
    /// [`CalendarError::Zone`] when no supplied zone has the calendar's name.
    pub fn of(
        calendar: Option<&'a WorkCalendar>,
        zones: &'a [Zone],
    ) -> Result<Self, CalendarError> {
        let Some(calendar) = calendar else {
            return Ok(Self::Continuous);
        };
        zones
            .iter()
            .find(|z| z.name() == calendar.zone)
            .map(|zone| Self::Calendar(calendar, zone))
            .ok_or(CalendarError::Zone)
    }

    /// The zone counted in, if any.
    #[must_use]
    pub const fn zone(self) -> Option<&'a Zone> {
        match self {
            Self::Continuous => None,
            Self::Calendar(_, zone) => Some(zone),
        }
    }

    /// Counted milliseconds from `from` to `to`; zero when `to` is not after `from`.
    ///
    /// # Errors
    /// [`CalendarError`] when the zone cannot place a boundary or the span is too long.
    pub fn elapsed(self, from: Time, to: Time) -> Result<u64, CalendarError> {
        match self {
            Self::Continuous => Ok(to.0.saturating_sub(from.0)),
            Self::Calendar(calendar, zone) => calendar.elapsed(zone, from, to),
        }
    }

    /// The instant at which `amount` counted milliseconds after `from` have passed.
    ///
    /// # Errors
    /// [`CalendarError`] when the calendar has no working time, the zone cannot place a boundary or the instant lies beyond [`MAX_DAYS`].
    pub fn advance(self, from: Time, amount: u64) -> Result<Time, CalendarError> {
        match self {
            Self::Continuous => from
                .0
                .checked_add(amount)
                .map(Time)
                .ok_or(CalendarError::Range),
            Self::Calendar(calendar, zone) => calendar.advance(zone, from, amount),
        }
    }
}
