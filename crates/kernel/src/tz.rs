//! Time zones from tzdb (CM-64): the kernel stays pure and takes the zone rules as input, the `TZif` bytes (RFC 8536, version 2 or later, without leap seconds) of a pinned tzdb version that every projection reports; a nonexistent local time is shifted forward with the offset before the gap and an ambiguous local time takes its first occurrence (RFC 5545 section 3.3.5).

use alloc::string::String;
use alloc::vec::Vec;

use crate::calendar::{
    LocalDateTime, SECONDS_PER_DAY, civil_from_days, days_from_civil, days_in_month,
};
use crate::id::Time;

/// Longest accepted zone name, in bytes.
pub const MAX_NAME: usize = 64;

/// Longest accepted tzdb version, in bytes.
pub const MAX_VERSION: usize = 16;

/// Most local time types of one zone.
pub const MAX_TYPES: usize = 256;

/// Largest UTC offset magnitude a zone may declare, 26 hours.
pub const MAX_OFFSET: i32 = 93_600;

/// Why zone data is refused or a time cannot be placed, naming what failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TzError(pub &'static str);

impl core::fmt::Display for TzError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "time zone: {}", self.0)
    }
}

impl core::error::Error for TzError {}

const TRUNCATED: TzError = TzError("truncated");
const RANGE: TzError = TzError("range");
const FOOTER: TzError = TzError("footer");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleDate {
    Julian1(u16),
    Julian0(u16),
    Month { month: u8, week: u8, weekday: u8 },
}

impl RuleDate {
    fn day(self, year: i32) -> Option<i64> {
        match self {
            Self::Julian1(n) => {
                let mut left = n;
                for month in 1..=12_u8 {
                    let len = u16::from(days_in_month(2001, month)?);
                    if left <= len {
                        return days_from_civil(year, month, u8::try_from(left).ok()?);
                    }
                    left = left.checked_sub(len)?;
                }
                None
            }
            Self::Julian0(n) => days_from_civil(year, 1, 1)?.checked_add(i64::from(n)),
            Self::Month {
                month,
                week,
                weekday,
            } => {
                let first = days_from_civil(year, month, 1)?;
                let first_weekday = first.checked_add(4)?.checked_rem_euclid(7)?;
                let delta = i64::from(weekday)
                    .checked_sub(first_weekday)?
                    .checked_rem_euclid(7)?;
                let mut day = delta
                    .checked_add(1)?
                    .checked_add(i64::from(week).checked_sub(1)?.checked_mul(7)?)?;
                let len = i64::from(days_in_month(year, month)?);
                while day > len {
                    day = day.checked_sub(7)?;
                }
                first.checked_add(day)?.checked_sub(1)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Change {
    date: RuleDate,
    time: i32,
}

impl Change {
    fn local_seconds(self, year: i32) -> Option<i64> {
        self.date
            .day(year)?
            .checked_mul(SECONDS_PER_DAY)?
            .checked_add(i64::from(self.time))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Footer {
    Fixed(i32),
    Dst {
        std: i32,
        dst: i32,
        start: Change,
        end: Change,
    },
}

impl Footer {
    fn offset_at(self, t: i64) -> Option<i32> {
        match self {
            Self::Fixed(offset) => Some(offset),
            Self::Dst {
                std,
                dst,
                start,
                end,
            } => {
                let local = t.checked_add(i64::from(std))?;
                let (year, _, _) = civil_from_days(local.checked_div_euclid(SECONDS_PER_DAY)?)?;
                let on = start.local_seconds(year)?.checked_sub(i64::from(std))?;
                let off = end.local_seconds(year)?.checked_sub(i64::from(dst))?;
                let summer = if on < off {
                    on <= t && t < off
                } else {
                    !(off <= t && t < on)
                };
                Some(if summer { dst } else { std })
            }
        }
    }
}

struct Posix<'a> {
    s: &'a [u8],
    at: usize,
}

impl Posix<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn bump(&mut self) {
        self.at = self.at.saturating_add(1);
    }

    fn eat(&mut self, c: u8) -> bool {
        let found = self.peek() == Some(c);
        if found {
            self.bump();
        }
        found
    }

    fn name(&mut self) -> Result<(), TzError> {
        let mut len: usize = 0;
        if self.eat(b'<') {
            while let Some(c) = self.peek().filter(|c| *c != b'>') {
                if !(c.is_ascii_alphanumeric() || c == b'+' || c == b'-') {
                    return Err(FOOTER);
                }
                self.bump();
                len = len.saturating_add(1);
            }
            if !self.eat(b'>') {
                return Err(FOOTER);
            }
        } else {
            while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
                self.bump();
                len = len.saturating_add(1);
            }
        }
        if len < 3 { Err(FOOTER) } else { Ok(()) }
    }

    fn number(&mut self, max: u32) -> Result<u32, TzError> {
        let mut value: u32 = 0;
        let mut count: usize = 0;
        while let Some(c) = self.peek().filter(u8::is_ascii_digit) {
            let digit = u32::from(c.checked_sub(b'0').ok_or(FOOTER)?);
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit))
                .ok_or(FOOTER)?;
            count = count.saturating_add(1);
            self.bump();
        }
        if count == 0 || count > 3 || value > max {
            return Err(FOOTER);
        }
        Ok(value)
    }

    fn hms(&mut self, max_hours: u32) -> Result<i32, TzError> {
        let negative = if self.eat(b'-') {
            true
        } else {
            self.eat(b'+');
            false
        };
        let mut total = self.number(max_hours)?.checked_mul(3_600).ok_or(FOOTER)?;
        if self.eat(b':') {
            let minutes = self.number(59)?.checked_mul(60).ok_or(FOOTER)?;
            total = total.checked_add(minutes).ok_or(FOOTER)?;
            if self.eat(b':') {
                total = total.checked_add(self.number(59)?).ok_or(FOOTER)?;
            }
        }
        let total = i32::try_from(total).map_err(|_| FOOTER)?;
        if negative {
            total.checked_neg().ok_or(FOOTER)
        } else {
            Ok(total)
        }
    }

    fn date(&mut self) -> Result<RuleDate, TzError> {
        let small = |n: u32| u16::try_from(n).map_err(|_| FOOTER);
        let byte = |n: u32| u8::try_from(n).map_err(|_| FOOTER);
        if self.eat(b'J') {
            let n = self.number(365)?;
            if n == 0 {
                return Err(FOOTER);
            }
            return Ok(RuleDate::Julian1(small(n)?));
        }
        if self.eat(b'M') {
            let month = self.number(12)?;
            if month == 0 || !self.eat(b'.') {
                return Err(FOOTER);
            }
            let week = self.number(5)?;
            if week == 0 || !self.eat(b'.') {
                return Err(FOOTER);
            }
            let weekday = self.number(6)?;
            return Ok(RuleDate::Month {
                month: byte(month)?,
                week: byte(week)?,
                weekday: byte(weekday)?,
            });
        }
        Ok(RuleDate::Julian0(small(self.number(365)?)?))
    }

    fn change(&mut self) -> Result<Change, TzError> {
        let date = self.date()?;
        let time = if self.eat(b'/') {
            self.hms(167)?
        } else {
            7_200
        };
        Ok(Change { date, time })
    }

    fn parse(mut self) -> Result<Footer, TzError> {
        self.name()?;
        let std = self.hms(24)?.checked_neg().ok_or(FOOTER)?;
        if self.peek().is_none() {
            return Ok(Footer::Fixed(std));
        }
        self.name()?;
        let dst = if matches!(self.peek(), Some(b',') | None) {
            std.checked_add(3_600).ok_or(FOOTER)?
        } else {
            self.hms(24)?.checked_neg().ok_or(FOOTER)?
        };
        if !self.eat(b',') {
            return Err(FOOTER);
        }
        let start = self.change()?;
        if !self.eat(b',') {
            return Err(FOOTER);
        }
        let end = self.change()?;
        let too_far = |o: i32| o.checked_abs().is_none_or(|a| a > MAX_OFFSET);
        if self.peek().is_some() || too_far(std) || too_far(dst) {
            return Err(FOOTER);
        }
        Ok(Footer::Dst {
            std,
            dst,
            start,
            end,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TzError> {
        let end = self.at.checked_add(n).ok_or(TRUNCATED)?;
        let out = self.bytes.get(self.at..end).ok_or(TRUNCATED)?;
        self.at = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TzError> {
        self.take(N)?.try_into().map_err(|_| TRUNCATED)
    }

    fn count(&mut self) -> Result<usize, TzError> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| TzError("count"))
    }

    fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.at..).unwrap_or_default()
    }
}

struct Counts {
    isut: usize,
    isstd: usize,
    leap: usize,
    time: usize,
    kind: usize,
    chars: usize,
}

impl Counts {
    fn block(&self, time_size: usize) -> Option<usize> {
        self.time
            .checked_mul(time_size.checked_add(1)?)?
            .checked_add(self.kind.checked_mul(6)?)?
            .checked_add(self.chars)?
            .checked_add(self.leap.checked_mul(time_size.checked_add(4)?)?)?
            .checked_add(self.isstd)?
            .checked_add(self.isut)
    }
}

fn header(r: &mut Reader<'_>) -> Result<(u8, Counts), TzError> {
    if r.take(4)? != b"TZif" {
        return Err(TzError("magic"));
    }
    let [version] = r.array::<1>()?;
    r.take(15)?;
    let counts = Counts {
        isut: r.count()?,
        isstd: r.count()?,
        leap: r.count()?,
        time: r.count()?,
        kind: r.count()?,
        chars: r.count()?,
    };
    Ok((version, counts))
}

fn footer(rest: &[u8]) -> Result<Option<Footer>, TzError> {
    let inner = rest
        .strip_prefix(b"\n")
        .and_then(|s| s.strip_suffix(b"\n"))
        .ok_or(FOOTER)?;
    if inner.is_empty() {
        return Ok(None);
    }
    if inner.contains(&b'\n') {
        return Err(FOOTER);
    }
    Posix { s: inner, at: 0 }.parse().map(Some)
}

/// The rules of one IANA zone from one tzdb version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    name: String,
    version: String,
    transitions: Vec<i64>,
    kinds: Vec<u8>,
    offsets: Vec<i32>,
    footer: Option<Footer>,
}

impl Zone {
    /// Reads the `TZif` bytes of the zone `name` from tzdb `version`.
    ///
    /// # Errors
    /// [`TzError`] for a name or version outside 1 to 64 and 1 to 16 bytes, data before version 2, leap seconds, inconsistent counts, unordered transitions, an offset beyond 26 hours, or a footer outside the POSIX TZ form.
    pub fn from_tzif(name: &str, version: &str, bytes: &[u8]) -> Result<Self, TzError> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(TzError("name"));
        }
        if version.is_empty() || version.len() > MAX_VERSION {
            return Err(TzError("version"));
        }
        let mut r = Reader { bytes, at: 0 };
        let (v, first) = header(&mut r)?;
        if v < b'2' {
            return Err(TzError("version"));
        }
        r.take(first.block(4).ok_or(TRUNCATED)?)?;
        let (_, c) = header(&mut r)?;
        if c.leap != 0 {
            return Err(TzError("leap"));
        }
        let typed = |n: usize| n == 0 || n == c.kind;
        if c.kind == 0 || c.kind > MAX_TYPES || !typed(c.isstd) || !typed(c.isut) {
            return Err(TzError("count"));
        }
        if r.rest().len() < c.block(8).ok_or(TRUNCATED)? {
            return Err(TRUNCATED);
        }
        let mut transitions = Vec::with_capacity(c.time);
        for _ in 0..c.time {
            transitions.push(i64::from_be_bytes(r.array()?));
        }
        if !transitions.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
            return Err(TzError("transitions"));
        }
        let mut kinds = Vec::with_capacity(c.time);
        for _ in 0..c.time {
            let [k] = r.array::<1>()?;
            if usize::from(k) >= c.kind {
                return Err(TzError("type"));
            }
            kinds.push(k);
        }
        let mut offsets = Vec::with_capacity(c.kind);
        for _ in 0..c.kind {
            let offset = i32::from_be_bytes(r.array()?);
            r.take(2)?;
            if offset.checked_abs().is_none_or(|a| a > MAX_OFFSET) {
                return Err(TzError("type"));
            }
            offsets.push(offset);
        }
        r.take(c.chars)?;
        r.take(c.isstd)?;
        r.take(c.isut)?;
        Ok(Self {
            name: String::from(name),
            version: String::from(version),
            transitions,
            kinds,
            offsets,
            footer: footer(r.rest())?,
        })
    }

    /// The IANA zone name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The tzdb version the rules come from.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    fn type_offset(&self, kind: Option<&u8>) -> Result<i32, TzError> {
        kind.and_then(|k| self.offsets.get(usize::from(*k)))
            .copied()
            .ok_or(TzError("type"))
    }

    /// The UTC offset in seconds at Unix second `t`.
    ///
    /// # Errors
    /// [`TzError`] when the footer rule cannot place `t` in the years 1 to 9999.
    pub fn offset_at(&self, t: i64) -> Result<i32, TzError> {
        let after = self.transitions.partition_point(|x| *x <= t);
        let past_last = after == self.transitions.len();
        if let (true, Some(rule)) = (past_last, self.footer) {
            return rule.offset_at(t).ok_or(RANGE);
        }
        if after == 0 {
            return self.offsets.first().copied().ok_or(TzError("type"));
        }
        self.type_offset(self.kinds.get(after.checked_sub(1).ok_or(RANGE)?))
    }

    /// The Unix second of local seconds `local`; a nonexistent local time takes the offset before the gap, an ambiguous one its first occurrence.
    ///
    /// # Errors
    /// [`TzError`] when the rules cannot place the time.
    pub fn to_utc(&self, local: i64) -> Result<i64, TzError> {
        let before = self.offset_at(local.checked_sub(SECONDS_PER_DAY).ok_or(RANGE)?)?;
        let after = self.offset_at(local.checked_add(SECONDS_PER_DAY).ok_or(RANGE)?)?;
        let early = local.checked_sub(i64::from(before)).ok_or(RANGE)?;
        let late = local.checked_sub(i64::from(after)).ok_or(RANGE)?;
        let early_holds = self.offset_at(early)? == before;
        let late_holds = self.offset_at(late)? == after;
        Ok(match (early_holds, late_holds) {
            (true, true) => early.min(late),
            (false, true) => late,
            (_, false) => early,
        })
    }

    /// Local seconds of instant `at`.
    ///
    /// # Errors
    /// [`TzError`] when the rules cannot place the time.
    pub fn local_seconds(&self, at: Time) -> Result<i64, TzError> {
        let t = i64::try_from(at.0.checked_div(1_000).ok_or(RANGE)?).map_err(|_| RANGE)?;
        t.checked_add(i64::from(self.offset_at(t)?)).ok_or(RANGE)
    }

    /// The local date and time of instant `at`, to the second.
    ///
    /// # Errors
    /// [`TzError`] when the rules cannot place the time.
    pub fn local(&self, at: Time) -> Result<LocalDateTime, TzError> {
        LocalDateTime::from_seconds(self.local_seconds(at)?).ok_or(RANGE)
    }

    /// The instant of a local date and time, with the gap and fold rule of [`Zone::to_utc`].
    ///
    /// # Errors
    /// [`TzError`] when the rules cannot place the time or it is before 1970.
    pub fn instant(&self, local: LocalDateTime) -> Result<Time, TzError> {
        let utc = self.to_utc(local.seconds().ok_or(RANGE)?)?;
        u64::try_from(utc)
            .ok()
            .and_then(|s| s.checked_mul(1_000))
            .map(Time)
            .ok_or(RANGE)
    }
}
