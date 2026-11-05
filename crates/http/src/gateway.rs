//! The request limits of the API gateway (P-33, SEC-18, T-10): a body above 262 144 bytes, body parts excluded, or a JSON body nested deeper or holding more values than the complexity limit is refused with `413 request_too_large` before any handler sees it, so nothing is queued before the check; an installation may narrow a limit, never widen it.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, header};

use crate::problem::{Problem, ProblemCode};

/// The largest request body, body parts excluded (P-33, Access SI-20).
pub const MAX_REQUEST_BYTES: usize = 262_144;

/// The deepest nesting of a JSON body (P-33, POLICY DEFAULT).
pub const MAX_JSON_DEPTH: usize = 32;

/// The most values a JSON body holds, counted as containers plus separators (P-33, POLICY
/// DEFAULT).
pub const MAX_JSON_VALUES: usize = 16_384;

/// Why the gateway refused a request (P-33).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The body is above the byte limit.
    TooLarge,
    /// The JSON body is nested deeper than the depth limit.
    TooDeep,
    /// The JSON body holds more values than the value limit.
    TooManyValues,
}

impl Refusal {
    /// The reason given in the problem's `detail`.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::TooLarge => "the request body is above the request limit",
            Self::TooDeep => "the JSON body is nested deeper than the complexity limit",
            Self::TooManyValues => "the JSON body holds more values than the complexity limit",
        }
    }

    /// The `413 request_too_large` problem of the refusal.
    #[must_use]
    pub fn problem(self) -> Problem {
        Problem::new(ProblemCode::RequestTooLarge).with_detail(self.detail())
    }
}

/// The limits one installation applies (P-33, P-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    bytes: usize,
    depth: usize,
    values: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: MAX_REQUEST_BYTES,
            depth: MAX_JSON_DEPTH,
            values: MAX_JSON_VALUES,
        }
    }
}

/// The nesting depth and the value count of a JSON text, read outside its strings.
#[must_use]
pub fn json_complexity(body: &[u8]) -> (usize, usize) {
    let (mut depth, mut deepest, mut values) = (0_usize, 0_usize, 0_usize);
    let (mut in_string, mut escaped) = (false, false);
    for &b in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth = depth.saturating_add(1);
                deepest = deepest.max(depth);
                values = values.saturating_add(1);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            b',' => values = values.saturating_add(1),
            _ => {}
        }
    }
    (deepest, values)
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|v| v.trim().to_ascii_lowercase())
        .is_some_and(|v| v == "application/json" || v.ends_with("+json"))
}

impl Limits {
    /// Limits no wider than the defaults; `None` for a zero limit or one above its default.
    #[must_use]
    pub fn new(bytes: usize, depth: usize, values: usize) -> Option<Self> {
        let within = |value: usize, max: usize| (1..=max).contains(&value);
        let fits = within(bytes, MAX_REQUEST_BYTES)
            && within(depth, MAX_JSON_DEPTH)
            && within(values, MAX_JSON_VALUES);
        fits.then_some(Self {
            bytes,
            depth,
            values,
        })
    }

    /// The largest request body.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Checks a JSON body against the complexity limit.
    ///
    /// # Errors
    /// [`Refusal::TooDeep`] or [`Refusal::TooManyValues`].
    pub fn check_json(&self, body: &[u8]) -> Result<(), Refusal> {
        let (depth, values) = json_complexity(body);
        if depth > self.depth {
            Err(Refusal::TooDeep)
        } else if values > self.values {
            Err(Refusal::TooManyValues)
        } else {
            Ok(())
        }
    }

    /// The request with its whole body read and checked, or the refusal: a declared length
    /// above the limit is refused before the body is read.
    ///
    /// # Errors
    /// The [`Refusal`] of a body above the byte limit or of a JSON body above the complexity
    /// limit.
    pub async fn hold(&self, request: Request) -> Result<Request, Refusal> {
        let declared = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let limit = u64::try_from(self.bytes).unwrap_or(u64::MAX);
        if declared.is_some_and(|length| length > limit) {
            return Err(Refusal::TooLarge);
        }
        let json = is_json(request.headers());
        let (parts, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, self.bytes)
            .await
            .map_err(|_| Refusal::TooLarge)?;
        if json {
            self.check_json(&bytes)?;
        }
        Ok(Request::from_parts(parts, Body::from(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn request(body: Vec<u8>, content_type: &str) -> Request {
        let mut request = Request::new(Body::from(body));
        let value = HeaderValue::from_str(content_type).unwrap();
        request.headers_mut().insert(header::CONTENT_TYPE, value);
        request
    }

    fn nested(depth: usize) -> Vec<u8> {
        let mut body = "[".repeat(depth);
        body.push_str(&"]".repeat(depth));
        body.into_bytes()
    }

    // P-33 SEC-18 T-10
    #[tokio::test]
    async fn p_33_a_request_above_256_kib_is_refused_before_any_handler() {
        let limits = Limits::default();
        assert_eq!(limits.bytes(), 262_144);
        let at = vec![b'a'; MAX_REQUEST_BYTES];
        let held = limits.hold(request(at, "text/plain")).await.unwrap();
        let body = axum::body::to_bytes(held.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.len(), MAX_REQUEST_BYTES);
        let over = vec![b'a'; MAX_REQUEST_BYTES.saturating_add(1)];
        let refused = limits.hold(request(over, "text/plain")).await.unwrap_err();
        assert_eq!(refused, Refusal::TooLarge);
        assert_eq!(refused.problem().code, ProblemCode::RequestTooLarge);
        let mut declared = request(Vec::new(), "application/json");
        let length = HeaderValue::from_static("262145");
        let headers = declared.headers_mut();
        headers.insert(header::CONTENT_LENGTH, length);
        assert_eq!(limits.hold(declared).await.unwrap_err(), Refusal::TooLarge);
    }

    // P-33 SEC-18
    #[tokio::test]
    async fn p_33_a_json_body_above_the_complexity_limit_is_refused() {
        let limits = Limits::default();
        let sample = br#"{"a": "[[[,,,", "b": [1, 2]}"#;
        assert_eq!(json_complexity(sample), (2, 4));
        let deep = request(nested(MAX_JSON_DEPTH), "application/json");
        assert!(limits.hold(deep).await.is_ok());
        let deeper = nested(MAX_JSON_DEPTH.saturating_add(1));
        let refused = limits.hold(request(deeper.clone(), "application/problem+json"));
        assert_eq!(refused.await.unwrap_err(), Refusal::TooDeep);
        assert!(limits.hold(request(deeper, "text/plain")).await.is_ok());
        let wide = format!("[{}]", "0,".repeat(MAX_JSON_VALUES)).into_bytes();
        let refused = limits.hold(request(wide, "application/json; charset=utf-8"));
        assert_eq!(refused.await.unwrap_err(), Refusal::TooManyValues);
    }

    // P-33 P-7
    #[test]
    fn p_33_an_installation_narrows_a_limit_and_never_widens_it() {
        let narrow = Limits::new(1024, 8, 64).unwrap();
        assert_eq!(narrow.bytes(), 1024);
        assert_eq!(narrow.check_json(&nested(9)), Err(Refusal::TooDeep));
        assert!(Limits::new(MAX_REQUEST_BYTES.saturating_add(1), 8, 64).is_none());
        assert!(Limits::new(1024, MAX_JSON_DEPTH.saturating_add(1), 64).is_none());
        assert!(Limits::new(1024, 8, 0).is_none());
        assert_eq!(
            Limits::new(MAX_REQUEST_BYTES, MAX_JSON_DEPTH, MAX_JSON_VALUES),
            Some(Limits::default())
        );
    }
}
