//! Deprecation inside a major version (P-54 item 1, T-35 rule 3): a major version changes only by addition, and a route about to go is announced on every answer with `Deprecation` (RFC 9745, a structured date) and, once its end is set, `Sunset` (RFC 8594, an HTTP date); it is removed only with the next major version.

use axum::Router;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::Response;

/// The RFC 9745 header.
pub const DEPRECATION: HeaderName = HeaderName::from_static("deprecation");

/// The RFC 8594 header.
pub const SUNSET: HeaderName = HeaderName::from_static("sunset");

/// The last second an HTTP date can name, 9999-12-31T23:59:59Z.
pub const MAX_UNIX: i64 = 253_402_300_799;

const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// When a route was deprecated and when it goes, in Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deprecated {
    since: i64,
    sunset: Option<i64>,
}

impl Deprecated {
    /// Deprecated since `since`, going at `sunset`; `None` for a time outside 1970 to 9999 or a
    /// sunset that is not after the deprecation.
    #[must_use]
    pub fn new(since: i64, sunset: Option<i64>) -> Option<Self> {
        let valid = |t: i64| (0..=MAX_UNIX).contains(&t);
        let ordered = sunset.is_none_or(|end| valid(end) && end > since);
        (valid(since) && ordered).then_some(Self { since, sunset })
    }

    /// Writes `Deprecation` and, with a sunset, `Sunset` into `headers`.
    pub fn apply(&self, headers: &mut HeaderMap) {
        if let Ok(value) = HeaderValue::from_str(&format!("@{}", self.since)) {
            headers.insert(DEPRECATION, value);
        }
        let sunset = self.sunset.and_then(http_date);
        if let Some(value) = sunset.and_then(|date| HeaderValue::from_str(&date).ok()) {
            headers.insert(SUNSET, value);
        }
    }

    /// `router` with the headers of this deprecation on every answer.
    #[must_use]
    pub fn announce(self, router: Router) -> Router {
        let layer = axum::middleware::map_response(move |mut response: Response| async move {
            self.apply(response.headers_mut());
            response
        });
        router.layer(layer)
    }
}

fn civil_from_days(days: i64) -> Option<(i64, i64, i64)> {
    let z = days.checked_add(719_468)?;
    let era = z.checked_div_euclid(146_097)?;
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe / 1460)?
        .checked_add(doe / 36_524)?
        .checked_sub(doe / 146_096)?
        / 365;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe / 4)?
            .checked_sub(yoe / 100)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = yoe.checked_add(era.checked_mul(400)?)?;
    Some((y.checked_add(i64::from(m <= 2))?, m, d))
}

/// The RFC 9110 IMF-fixdate of Unix second `unix`, such as `Sun, 06 Nov 1994 08:49:37 GMT`;
/// `None` outside 1970 to 9999.
#[must_use]
pub fn http_date(unix: i64) -> Option<String> {
    if !(0..=MAX_UNIX).contains(&unix) {
        return None;
    }
    let days = unix / 86_400;
    let of_day = unix % 86_400;
    let (y, m, d) = civil_from_days(days)?;
    let day = DAYS.get(usize::try_from(days % 7).ok()?)?;
    let month = MONTHS.get(usize::try_from(m.checked_sub(1)?).ok()?)?;
    let (hh, mm, ss) = (of_day / 3600, of_day % 3600 / 60, of_day % 60);
    Some(format!(
        "{day}, {d:02} {month} {y:04} {hh:02}:{mm:02}:{ss:02} GMT"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-54 T-35
    #[test]
    fn p_54_a_deprecated_route_announces_deprecation_and_sunset() {
        assert_eq!(
            http_date(784_111_777).as_deref(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
        assert_eq!(
            http_date(0).as_deref(),
            Some("Thu, 01 Jan 1970 00:00:00 GMT")
        );
        assert_eq!(
            http_date(MAX_UNIX).as_deref(),
            Some("Fri, 31 Dec 9999 23:59:59 GMT")
        );
        assert_eq!(http_date(-1), None);
        let deprecated = Deprecated::new(1_688_169_599, Some(1_767_225_600)).unwrap();
        let mut headers = HeaderMap::new();
        deprecated.apply(&mut headers);
        assert_eq!(headers.get(DEPRECATION).unwrap(), "@1688169599");
        assert_eq!(
            headers.get(SUNSET).unwrap(),
            "Thu, 01 Jan 2026 00:00:00 GMT"
        );
        let open = Deprecated::new(1_688_169_599, None).unwrap();
        let mut headers = HeaderMap::new();
        open.apply(&mut headers);
        assert!(headers.get(SUNSET).is_none());
        assert!(Deprecated::new(10, Some(10)).is_none());
        assert!(Deprecated::new(-1, None).is_none());
    }
}
