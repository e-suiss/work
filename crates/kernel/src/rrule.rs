//! The recurrence rule subset of commitment calendars (CM-64, RFC 5545): `FREQ` of `DAILY`, `WEEKLY`, `MONTHLY` or `YEARLY`, `INTERVAL`, `BYDAY` (with an ordinal only in monthly and yearly rules), `BYMONTHDAY`, `BYMONTH`, `BYHOUR`, `BYMINUTE`, `COUNT` or `UNTIL` but not both, and `WKST`, over a local `DTSTART` in a named zone; `BYSETPOS`, `BYWEEKNO`, `BYYEARDAY`, `BYSECOND`, sub-daily frequencies and `EXDATE`/`RDATE` are refused, and occurrences take the gap and fold rule of the zone.

use alloc::vec::Vec;

use crate::calendar::{
    Date, LocalDateTime, SECONDS_PER_DAY, days_from_civil, days_in_month, weekday,
};
use crate::id::Time;
use crate::tz::Zone;

/// Longest accepted rule text, in bytes.
pub const MAX_TEXT: usize = 512;

/// Most values of one list part.
pub const MAX_LIST: usize = 64;

/// Most periods one expansion walks before it gives up.
pub const MAX_PERIODS: u32 = 100_000;

const DAYS: [&str; 7] = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"];

const REFUSED: [&str; 6] = [
    "BYSETPOS",
    "BYWEEKNO",
    "BYYEARDAY",
    "BYSECOND",
    "EXDATE",
    "RDATE",
];

/// Why a rule is refused or cannot be expanded, naming the part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleError(pub &'static str);

impl core::fmt::Display for RuleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "recurrence rule: {}", self.0)
    }
}

impl core::error::Error for RuleError {}

const RANGE: RuleError = RuleError("range");

/// The frequency of a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freq {
    /// Every `INTERVAL` days.
    Daily,
    /// Every `INTERVAL` weeks.
    Weekly,
    /// Every `INTERVAL` months.
    Monthly,
    /// Every `INTERVAL` years.
    Yearly,
}

/// One `BYDAY` value: an ISO weekday, Monday 0 to Sunday 6, and an ordinal, 0 for every such weekday.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByDay {
    /// The ordinal: positive from the start of the month or year, negative from its end.
    pub ordinal: i8,
    /// The weekday.
    pub weekday: u8,
}

/// How a rule ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// It does not end.
    Never,
    /// After this many occurrences.
    Count(u32),
    /// With the last occurrence at or before this instant.
    Until(Time),
}

/// A parsed rule of the subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The frequency.
    pub freq: Freq,
    /// The interval, at least 1.
    pub interval: u16,
    /// `BYDAY`, ascending.
    pub by_day: Vec<ByDay>,
    /// `BYMONTHDAY`, ascending; negative counts from the month's end.
    pub by_month_day: Vec<i8>,
    /// `BYMONTH`, ascending.
    pub by_month: Vec<u8>,
    /// `BYHOUR`, ascending.
    pub by_hour: Vec<u8>,
    /// `BYMINUTE`, ascending.
    pub by_minute: Vec<u8>,
    /// `COUNT` or `UNTIL`.
    pub end: End,
    /// `WKST` as an ISO weekday; Monday by default.
    pub week_start: u8,
}

fn number<T: core::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn signed(text: &str) -> Option<i8> {
    if let Some(rest) = text.strip_prefix('-') {
        return number::<i8>(rest)?.checked_neg();
    }
    number::<i8>(text.strip_prefix('+').unwrap_or(text))
}

fn day_index(text: &str) -> Option<u8> {
    DAYS.iter()
        .position(|d| *d == text)
        .and_then(|p| u8::try_from(p).ok())
}

fn by_day(text: &str) -> Option<ByDay> {
    let split = text.len().checked_sub(2)?;
    let weekday = day_index(text.get(split..)?)?;
    let prefix = text.get(..split)?;
    let ordinal = if prefix.is_empty() {
        0
    } else {
        signed(prefix).filter(|n| *n != 0)?
    };
    Some(ByDay { ordinal, weekday })
}

fn list<T: Ord>(
    text: &str,
    part: &'static str,
    read: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>, RuleError> {
    let mut out = Vec::new();
    for item in text.split(',') {
        if out.len() == MAX_LIST {
            return Err(RuleError(part));
        }
        out.push(read(item).ok_or(RuleError(part))?);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn until(text: &str) -> Option<Time> {
    let local = LocalDateTime::parse_basic(text.strip_suffix('Z')?)?;
    let seconds = u64::try_from(local.seconds()?).ok()?;
    seconds.checked_mul(1_000).map(Time)
}

fn ranged(text: &str, max: u8) -> Option<u8> {
    number::<u8>(text).filter(|n| *n <= max)
}

#[derive(Default)]
struct Parts<'a> {
    seen: Vec<&'a str>,
    freq: Option<Freq>,
    interval: Option<u16>,
    by_day: Vec<ByDay>,
    by_month_day: Vec<i8>,
    by_month: Vec<u8>,
    by_hour: Vec<u8>,
    by_minute: Vec<u8>,
    count: Option<u32>,
    until: Option<Time>,
    week_start: u8,
}

impl<'a> Parts<'a> {
    fn read(&mut self, key: &'a str, value: &str) -> Result<(), RuleError> {
        if let Some(refused) = REFUSED.iter().find(|r| **r == key) {
            return Err(RuleError(*refused));
        }
        if self.seen.contains(&key) {
            return Err(RuleError("duplicate"));
        }
        self.seen.push(key);
        match key {
            "FREQ" => {
                self.freq = Some(match value {
                    "DAILY" => Freq::Daily,
                    "WEEKLY" => Freq::Weekly,
                    "MONTHLY" => Freq::Monthly,
                    "YEARLY" => Freq::Yearly,
                    _ => return Err(RuleError("FREQ")),
                });
            }
            "INTERVAL" => {
                let n = number::<u16>(value).filter(|n| *n >= 1);
                self.interval = Some(n.ok_or(RuleError("INTERVAL"))?);
            }
            "BYDAY" => self.by_day = list(value, "BYDAY", by_day)?,
            "BYMONTHDAY" => {
                self.by_month_day = list(value, "BYMONTHDAY", |v| {
                    signed(v).filter(|n| (1..=31).contains(&n.unsigned_abs()))
                })?;
            }
            "BYMONTH" => {
                self.by_month = list(value, "BYMONTH", |v| ranged(v, 12).filter(|n| *n >= 1))?;
            }
            "BYHOUR" => self.by_hour = list(value, "BYHOUR", |v| ranged(v, 23))?,
            "BYMINUTE" => self.by_minute = list(value, "BYMINUTE", |v| ranged(v, 59))?,
            "COUNT" => {
                let n = number::<u32>(value).filter(|n| *n >= 1);
                self.count = Some(n.ok_or(RuleError("COUNT"))?);
            }
            "UNTIL" => self.until = Some(until(value).ok_or(RuleError("UNTIL"))?),
            "WKST" => self.week_start = day_index(value).ok_or(RuleError("WKST"))?,
            _ => return Err(RuleError("key")),
        }
        Ok(())
    }
}

impl Rule {
    /// Reads a rule value, the text after `RRULE:`.
    ///
    /// # Errors
    /// [`RuleError`] naming the refused part: an unknown, repeated or refused key, a value out of range, a sub-daily or missing `FREQ`, both `COUNT` and `UNTIL` (named `COUNT`), a `BYDAY` ordinal in a daily or weekly rule or beyond 5 in a monthly one, and `BYMONTHDAY` in a weekly rule.
    pub fn parse(text: &str) -> Result<Self, RuleError> {
        if text.is_empty() || text.len() > MAX_TEXT {
            return Err(RuleError("rule"));
        }
        let mut parts = Parts::default();
        for part in text.split(';') {
            let (key, value) = part.split_once('=').ok_or(RuleError("rule"))?;
            if value.is_empty() {
                return Err(RuleError("rule"));
            }
            parts.read(key, value)?;
        }
        let freq = parts.freq.ok_or(RuleError("FREQ"))?;
        let end = match (parts.count, parts.until) {
            (Some(_), Some(_)) => return Err(RuleError("COUNT")),
            (Some(n), None) => End::Count(n),
            (None, Some(t)) => End::Until(t),
            (None, None) => End::Never,
        };
        let ordinal_max = match freq {
            Freq::Daily | Freq::Weekly => 0,
            Freq::Monthly => 5,
            Freq::Yearly => 53,
        };
        if parts
            .by_day
            .iter()
            .any(|d| d.ordinal.unsigned_abs() > ordinal_max)
        {
            return Err(RuleError("BYDAY"));
        }
        if freq == Freq::Weekly && !parts.by_month_day.is_empty() {
            return Err(RuleError("BYMONTHDAY"));
        }
        Ok(Self {
            freq,
            interval: parts.interval.unwrap_or(1),
            by_day: parts.by_day,
            by_month_day: parts.by_month_day,
            by_month: parts.by_month,
            by_hour: parts.by_hour,
            by_minute: parts.by_minute,
            end,
            week_start: parts.week_start,
        })
    }

    fn month_day_ok(&self, day: u8, len: u8) -> bool {
        self.by_month_day.is_empty()
            || self.by_month_day.iter().any(|n| {
                if *n > 0 {
                    n.unsigned_abs() == day
                } else {
                    len.checked_add(1)
                        .and_then(|l| l.checked_sub(n.unsigned_abs()))
                        .is_some_and(|d| d == day)
                }
            })
    }

    fn weekday_ok(&self, day: i64, index: u16, len: u16) -> bool {
        let Some(wd) = weekday(day) else {
            return false;
        };
        self.by_day.is_empty()
            || self.by_day.iter().any(|b| {
                let from_start = index.checked_sub(1).and_then(|i| i.checked_div(7));
                let from_end = len.checked_sub(index).and_then(|i| i.checked_div(7));
                let nth = if b.ordinal > 0 { from_start } else { from_end };
                b.weekday == wd
                    && (b.ordinal == 0
                        || nth
                            .and_then(|n| n.checked_add(1))
                            .is_some_and(|n| n == u16::from(b.ordinal.unsigned_abs())))
            })
    }

    fn month_days(
        &self,
        start: LocalDateTime,
        year: i32,
        month: u8,
    ) -> Result<Vec<i64>, RuleError> {
        let len = days_in_month(year, month).ok_or(RANGE)?;
        let first = days_from_civil(year, month, 1).ok_or(RANGE)?;
        let mut out = Vec::new();
        if self.by_day.is_empty() && self.by_month_day.is_empty() {
            if start.date.day <= len {
                out.push(
                    first
                        .checked_add(i64::from(start.date.day))
                        .and_then(|d| d.checked_sub(1))
                        .ok_or(RANGE)?,
                );
            }
            return Ok(out);
        }
        for d in 1..=len {
            let day = first
                .checked_add(i64::from(d))
                .and_then(|x| x.checked_sub(1))
                .ok_or(RANGE)?;
            if self.month_day_ok(d, len) && self.weekday_ok(day, u16::from(d), u16::from(len)) {
                out.push(day);
            }
        }
        Ok(out)
    }

    fn year_days(&self, start: LocalDateTime, year: i32) -> Result<Vec<i64>, RuleError> {
        let mut out = Vec::new();
        if !self.by_day.is_empty() && self.by_month.is_empty() {
            let first = days_from_civil(year, 1, 1).ok_or(RANGE)?;
            let next = days_from_civil(year.checked_add(1).ok_or(RANGE)?, 1, 1).ok_or(RANGE)?;
            let len = u16::try_from(next.checked_sub(first).ok_or(RANGE)?).map_err(|_| RANGE)?;
            for index in 1..=len {
                let day = first
                    .checked_add(i64::from(index))
                    .and_then(|x| x.checked_sub(1))
                    .ok_or(RANGE)?;
                let date = Date::from_days(day).ok_or(RANGE)?;
                let month_len = days_in_month(date.year, date.month).ok_or(RANGE)?;
                if self.month_day_ok(date.day, month_len) && self.weekday_ok(day, index, len) {
                    out.push(day);
                }
            }
            return Ok(out);
        }
        let all: Vec<u8> = (1..=12).collect();
        let months: &[u8] = if self.by_month.is_empty() {
            if self.by_month_day.is_empty() {
                core::slice::from_ref(&start.date.month)
            } else {
                &all
            }
        } else {
            &self.by_month
        };
        for month in months {
            out.extend(self.month_days(start, year, *month)?);
        }
        Ok(out)
    }

    fn period_days(
        &self,
        start: LocalDateTime,
        period: u32,
    ) -> Result<Option<Vec<i64>>, RuleError> {
        let step = i64::from(period)
            .checked_mul(i64::from(self.interval))
            .ok_or(RANGE)?;
        let start_day = start.date.days().ok_or(RANGE)?;
        let month_ok = |date: Date| self.by_month.is_empty() || self.by_month.contains(&date.month);
        match self.freq {
            Freq::Daily => {
                let day = start_day.checked_add(step).ok_or(RANGE)?;
                let Some(date) = Date::from_days(day) else {
                    return Ok(None);
                };
                let len = days_in_month(date.year, date.month).ok_or(RANGE)?;
                let keep = month_ok(date)
                    && self.month_day_ok(date.day, len)
                    && self.weekday_ok(day, 1, 1);
                Ok(Some(if keep { alloc::vec![day] } else { Vec::new() }))
            }
            Freq::Weekly => {
                let start_weekday = weekday(start_day).ok_or(RANGE)?;
                let back = i64::from(start_weekday)
                    .checked_sub(i64::from(self.week_start))
                    .and_then(|d| d.checked_rem_euclid(7))
                    .ok_or(RANGE)?;
                let first = start_day
                    .checked_sub(back)
                    .and_then(|d| d.checked_add(step.checked_mul(7)?))
                    .ok_or(RANGE)?;
                let mut out = Vec::new();
                for i in 0..7 {
                    let day = first.checked_add(i).ok_or(RANGE)?;
                    let Some(date) = Date::from_days(day) else {
                        return Ok(None);
                    };
                    let wd = weekday(day).ok_or(RANGE)?;
                    let on_day = if self.by_day.is_empty() {
                        wd == start_weekday
                    } else {
                        self.by_day.iter().any(|b| b.weekday == wd)
                    };
                    if on_day && month_ok(date) && day >= start_day {
                        out.push(day);
                    }
                }
                Ok(Some(out))
            }
            Freq::Monthly => {
                let index = i64::from(start.date.year)
                    .checked_mul(12)
                    .and_then(|m| m.checked_add(i64::from(start.date.month)))
                    .and_then(|m| m.checked_sub(1))
                    .and_then(|m| m.checked_add(step))
                    .ok_or(RANGE)?;
                let year = i32::try_from(index.checked_div(12).ok_or(RANGE)?).map_err(|_| RANGE)?;
                let month = u8::try_from(
                    index
                        .checked_rem(12)
                        .ok_or(RANGE)?
                        .checked_add(1)
                        .ok_or(RANGE)?,
                )
                .map_err(|_| RANGE)?;
                if year > 9999 {
                    return Ok(None);
                }
                if !self.by_month.is_empty() && !self.by_month.contains(&month) {
                    return Ok(Some(Vec::new()));
                }
                self.month_days(start, year, month).map(Some)
            }
            Freq::Yearly => {
                let year = i64::from(start.date.year).checked_add(step).ok_or(RANGE)?;
                match i32::try_from(year) {
                    Ok(y) if y <= 9999 => self.year_days(start, y).map(Some),
                    _ => Ok(None),
                }
            }
        }
    }

    /// The first `max` occurrence instants in `[from, to)` of the rule over the local `start` in `zone`; occurrences before `start` are not produced, and `COUNT` counts from `start`.
    ///
    /// # Errors
    /// [`RuleError`] named `periods` when the walk reaches [`MAX_PERIODS`] before the window ends or `max` occurrences are found, and `range` when the zone cannot place a time.
    pub fn occurrences(
        &self,
        start: LocalDateTime,
        zone: &Zone,
        from: Time,
        to: Time,
        max: usize,
    ) -> Result<Vec<Time>, RuleError> {
        let first = start.seconds().ok_or(RANGE)?;
        let hours: &[u8] = if self.by_hour.is_empty() {
            core::slice::from_ref(&start.hour)
        } else {
            &self.by_hour
        };
        let minutes: &[u8] = if self.by_minute.is_empty() {
            core::slice::from_ref(&start.minute)
        } else {
            &self.by_minute
        };
        let mut out = Vec::new();
        if max == 0 {
            return Ok(out);
        }
        let mut produced: u32 = 0;
        for period in 0..MAX_PERIODS {
            let Some(days) = self.period_days(start, period)? else {
                return Ok(out);
            };
            for day in days {
                for hour in hours {
                    for minute in minutes {
                        let clock = i64::from(*hour)
                            .checked_mul(3_600)
                            .and_then(|s| s.checked_add(i64::from(*minute).checked_mul(60)?))
                            .and_then(|s| s.checked_add(i64::from(start.second)))
                            .ok_or(RANGE)?;
                        let local = day
                            .checked_mul(SECONDS_PER_DAY)
                            .and_then(|s| s.checked_add(clock))
                            .ok_or(RANGE)?;
                        if local < first {
                            continue;
                        }
                        let utc = zone.to_utc(local).map_err(|_| RANGE)?;
                        let at = u64::try_from(utc)
                            .ok()
                            .and_then(|s| s.checked_mul(1_000))
                            .map(Time)
                            .ok_or(RANGE)?;
                        if matches!(self.end, End::Until(u) if at > u) || at >= to {
                            return Ok(out);
                        }
                        produced = produced.checked_add(1).ok_or(RANGE)?;
                        if at >= from {
                            out.push(at);
                            if out.len() >= max {
                                return Ok(out);
                            }
                        }
                        if matches!(self.end, End::Count(n) if produced >= n) {
                            return Ok(out);
                        }
                    }
                }
            }
        }
        Err(RuleError("periods"))
    }
}
