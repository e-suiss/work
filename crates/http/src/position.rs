//! The read freshness headers (T-97 items 2 and 3): `Work-Position` carries the token of the positions an answer reflects, `Work-Min-Position` asks a derived read to wait for a token, `Prefer: wait=<seconds>` (RFC 7240) asks for the length of that wait and `Preference-Applied` answers the wait applied.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use work_proto::id::{ExternalId as _, PositionToken};
use work_query::app::Freshness;
use work_query::domain::{PositionRefusal, ReadWait, STALE};

use crate::problem::{Problem, ProblemCode};

/// The header of the positions an answer reflects.
pub const WORK_POSITION: HeaderName = HeaderName::from_static("work-position");

/// The header of the positions a derived read waits for.
pub const WORK_MIN_POSITION: HeaderName = HeaderName::from_static("work-min-position");

/// The RFC 7240 request header.
pub const PREFER: HeaderName = HeaderName::from_static("prefer");

/// The RFC 7240 answer header.
pub const PREFERENCE_APPLIED: HeaderName = HeaderName::from_static("preference-applied");

/// The `Work-Min-Position` token of a request, if it sends one.
///
/// # Errors
/// [`PositionRefusal::Invalid`], answered by [`refusal`], for a header that is not one `pos_`
/// token.
pub fn min_position(headers: &HeaderMap) -> Result<Option<PositionToken>, PositionRefusal> {
    let mut values = headers.get_all(&WORK_MIN_POSITION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(PositionRefusal::Invalid);
    }
    value
        .to_str()
        .ok()
        .and_then(|text| PositionToken::parse_external(text.trim()).ok())
        .map(Some)
        .ok_or(PositionRefusal::Invalid)
}

/// The wait a request asked for with `Prefer: wait=<seconds>`, if any; other preferences and a
/// malformed `wait` are ignored, as RFC 7240 asks.
#[must_use]
pub fn requested_wait(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get_all(&PREFER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|preference| {
            let first = preference.split(';').next()?.trim();
            let (name, value) = first.split_once('=')?;
            if !name.trim().eq_ignore_ascii_case("wait") {
                return None;
            }
            value
                .trim()
                .trim_matches('"')
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
        })
}

/// The wait applied to a request under `wait`, and its `Preference-Applied` value.
#[must_use]
pub fn applied_wait(headers: &HeaderMap, wait: &ReadWait) -> (Duration, HeaderValue) {
    let applied = wait.applied(requested_wait(headers));
    let seconds = applied.as_secs();
    let value = HeaderValue::from_str(&format!("wait={seconds}"))
        .unwrap_or_else(|_| HeaderValue::from_static("wait=0"));
    (applied, value)
}

/// The `Work-Position` value of `token`.
#[must_use]
pub fn position_header(token: &PositionToken) -> HeaderValue {
    HeaderValue::from_str(&token.to_external()).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// The `freshness` member of a derived answer that waited for a position (T-14, T-97 item 3):
/// `stale` when the wait ran out before the view reached it, absent otherwise. A stale answer
/// reports where the view stands and never that an item is still under way.
#[must_use]
pub const fn freshness(answer: &Freshness) -> Option<&'static str> {
    if answer.is_stale() { Some(STALE) } else { None }
}

/// Writes the `Work-Position` of `token` and the applied wait into the headers of an answer.
pub fn answer(headers: &mut HeaderMap, token: &PositionToken, applied: HeaderValue) {
    headers.insert(WORK_POSITION, position_header(token));
    headers.insert(PREFERENCE_APPLIED, applied);
}

/// The problem of a refused `Work-Min-Position` (T-97 item 4).
#[must_use]
pub fn refusal(refusal: PositionRefusal) -> Problem {
    Problem::new(match refusal {
        PositionRefusal::Invalid => ProblemCode::ReadPositionInvalid,
        PositionRefusal::Ahead => ProblemCode::ReadPositionAhead,
    })
}

#[cfg(test)]
mod tests {
    use work_proto::id::ExternalId;
    use work_proto::position::Positions;

    use super::*;

    fn headers(pairs: &[(&HeaderName, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append((*name).clone(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    // T-97 P-112
    #[test]
    fn t_97_work_min_position_is_one_pos_token() {
        assert_eq!(min_position(&HeaderMap::new()).unwrap(), None);
        let token = PositionToken::new(vec![1, 2, 3]).unwrap();
        let text = token.to_external();
        assert_eq!(
            min_position(&headers(&[(&WORK_MIN_POSITION, &text)])).unwrap(),
            Some(token.clone())
        );
        for bad in [
            vec![(&WORK_MIN_POSITION, "cur_AQID")],
            vec![(&WORK_MIN_POSITION, "pos_")],
            vec![(&WORK_MIN_POSITION, "pos_AQID=")],
            vec![
                (&WORK_MIN_POSITION, text.as_str()),
                (&WORK_MIN_POSITION, text.as_str()),
            ],
        ] {
            let refused = min_position(&headers(&bad)).unwrap_err();
            assert_eq!(refused, PositionRefusal::Invalid, "{bad:?}");
            assert_eq!(refusal(refused).code, ProblemCode::ReadPositionInvalid);
        }
        assert_eq!(position_header(&token), text.as_str());
        assert_eq!(
            refusal(PositionRefusal::Ahead).code,
            ProblemCode::ReadPositionAhead
        );
    }

    // T-97
    #[test]
    fn t_97_prefer_wait_is_applied_up_to_the_maximum() {
        let wait = ReadWait::default();
        let (applied, value) = applied_wait(&HeaderMap::new(), &wait);
        assert_eq!(
            (applied, value.to_str().unwrap()),
            (Duration::from_secs(2), "wait=2")
        );
        let asked = headers(&[(&PREFER, "respond-async, wait=1")]);
        assert_eq!(requested_wait(&asked), Some(Duration::from_secs(1)));
        assert_eq!(applied_wait(&asked, &wait).0, Duration::from_secs(1));
        let long = headers(&[(&PREFER, "return=minimal"), (&PREFER, "WAIT = 30")]);
        let (applied, value) = applied_wait(&long, &wait);
        assert_eq!(
            (applied, value.to_str().unwrap()),
            (Duration::from_secs(5), "wait=5")
        );
        let malformed = headers(&[(&PREFER, "wait=soon")]);
        assert_eq!(requested_wait(&malformed), None);
        assert_eq!(applied_wait(&malformed, &wait).0, Duration::from_secs(2));
    }

    // T-14 T-97
    #[test]
    fn t_14_a_stale_answer_says_so_and_carries_the_position_it_reflects() {
        let ledger = ExternalId::parse_external(&format!("led_{}", "ab".repeat(32))).unwrap();
        let at = Positions::new([(ledger, 3)]).unwrap();
        assert_eq!(freshness(&Freshness::Stale(at.clone())), Some("stale"));
        assert_eq!(freshness(&Freshness::Fresh(at)), None);
        let token = PositionToken::new(vec![7, 7]).unwrap();
        let mut headers = HeaderMap::new();
        answer(&mut headers, &token, HeaderValue::from_static("wait=5"));
        let text = token.to_external();
        assert_eq!(headers.get(WORK_POSITION).unwrap(), text.as_str());
        assert_eq!(headers.get(PREFERENCE_APPLIED).unwrap(), "wait=5");
    }
}
