//! The headers of a changing request (P-54 items 4 and 5, P-97, P-99): `Idempotency-Key` is required and sent once, the key itself is admitted against ledger time by the write path, whose reason codes are the problems of the same name; the item version is the strong `ETag`, a change sends it back in `If-Match`, a missing `If-Match` is `428 precondition_required`, another version is `412 precondition_failed`, and the version the change was made against becomes the Declaration's `basis`, the heads the item had at that version.

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

use crate::problem::{Problem, ProblemCode};

/// The idempotency header (P-54 item 4).
pub const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// The one `Idempotency-Key` value of a changing request.
///
/// # Errors
/// `idempotency_key_missing` without the header, `idempotency_key_malformed` for more than one
/// value or one that is not text.
pub fn idempotency_key(headers: &HeaderMap) -> Result<&str, Problem> {
    let mut values = headers.get_all(&IDEMPOTENCY_KEY).iter();
    let Some(value) = values.next() else {
        return Err(Problem::new(ProblemCode::IdempotencyKeyMissing));
    };
    if values.next().is_some() {
        return Err(Problem::new(ProblemCode::IdempotencyKeyMalformed));
    }
    value
        .to_str()
        .map(str::trim)
        .map_err(|_| Problem::new(ProblemCode::IdempotencyKeyMalformed))
}

/// The problem of an idempotency refusal by its reason code (P-96, P-97, P-54 item 4); a code
/// outside the idempotency family is `invalid_request`.
#[must_use]
pub fn idempotency_refusal(reason: &str) -> Problem {
    let code = ProblemCode::parse(reason)
        .filter(|code| code.as_str().starts_with("idempotency_key_"))
        .unwrap_or(ProblemCode::InvalidRequest);
    Problem::new(code)
}

/// The strong `ETag` of item version `version`.
#[must_use]
pub fn etag(version: u64) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{version}\""))
        .unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn version(text: &str) -> Option<u64> {
    let digits = text.strip_prefix('"')?.strip_suffix('"')?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if canonical { digits.parse().ok() } else { None }
}

fn malformed() -> Problem {
    Problem::new(ProblemCode::InvalidRequest).with_detail("If-Match takes one strong ETag")
}

/// The item version a change was made against, from its one strong `If-Match`.
///
/// # Errors
/// `precondition_required` without `If-Match`; `invalid_request` for more than one value, a
/// list, `*`, a weak or a malformed tag.
pub fn if_match(headers: &HeaderMap) -> Result<u64, Problem> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Err(Problem::new(ProblemCode::PreconditionRequired));
    };
    if values.next().is_some() {
        return Err(malformed());
    }
    value
        .to_str()
        .ok()
        .and_then(|text| version(text.trim()))
        .ok_or_else(malformed)
}

/// The `basis` of a change made against version `asked` of an item now at `current` with
/// `heads`.
///
/// # Errors
/// `precondition_failed` when the item is no longer at the asked version.
pub fn basis<T: Clone>(asked: u64, current: u64, heads: &[T]) -> Result<Vec<T>, Problem> {
    if asked == current {
        Ok(heads.to_vec())
    } else {
        Err(Problem::new(ProblemCode::PreconditionFailed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(name: &HeaderName, values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(name.clone(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    const MALFORMED_TAGS: [&str; 7] = [
        "W/\"7\"",
        "*",
        "\"7\", \"8\"",
        "7",
        "\"07\"",
        "\"\"",
        "\"-1\"",
    ];

    fn code<T: core::fmt::Debug>(result: Result<T, Problem>) -> ProblemCode {
        result.unwrap_err().code
    }

    // P-54 P-99 P-97
    #[test]
    fn p_54_a_changing_request_sends_one_idempotency_key() {
        let uuid = "01890a5d-ac96-774b-bcce-b302099a8057";
        let one = headers(&IDEMPOTENCY_KEY, &[uuid]);
        assert_eq!(idempotency_key(&one).unwrap(), uuid);
        let missing = code(idempotency_key(&HeaderMap::new()));
        assert_eq!(missing, ProblemCode::IdempotencyKeyMissing);
        let two = code(idempotency_key(&headers(&IDEMPOTENCY_KEY, &[uuid, uuid])));
        assert_eq!(two, ProblemCode::IdempotencyKeyMalformed);
        for code in ProblemCode::ALL {
            let refused = idempotency_refusal(code.as_str()).code;
            if code.as_str().starts_with("idempotency_key_") {
                assert_eq!(refused, code);
            } else {
                assert_eq!(refused, ProblemCode::InvalidRequest);
            }
        }
        let unknown = idempotency_refusal("unknown").code;
        assert_eq!(unknown, ProblemCode::InvalidRequest);
        assert_eq!(idempotency_refusal("idempotency_key_conflict").status, 422);
    }

    // P-54
    #[test]
    fn p_54_if_match_is_the_item_version_and_becomes_the_basis() {
        assert_eq!(etag(7), "\"7\"");
        let tagged = headers(&header::IF_MATCH, &["\"7\""]);
        assert_eq!(if_match(&tagged).unwrap(), 7);
        let required = code(if_match(&HeaderMap::new()));
        assert_eq!(required, ProblemCode::PreconditionRequired);
        for bad in MALFORMED_TAGS {
            let refused = code(if_match(&headers(&header::IF_MATCH, &[bad])));
            assert_eq!(refused, ProblemCode::InvalidRequest, "{bad}");
        }
        let twice = headers(&header::IF_MATCH, &["\"7\"", "\"7\""]);
        assert_eq!(code(if_match(&twice)), ProblemCode::InvalidRequest);
        let heads = ["rec-a", "rec-b"];
        assert_eq!(basis(7, 7, &heads).unwrap(), heads);
        let moved = basis(7, 8, &heads).unwrap_err();
        assert_eq!(moved.code, ProblemCode::PreconditionFailed);
        assert_eq!(moved.status, 412);
    }
}
