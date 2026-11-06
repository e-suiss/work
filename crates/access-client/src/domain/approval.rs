//! The Access approval call (T-101 item 7 and its note, E-17, E-26; Access OP-149 m.9, OP-150 m.3 (r)): Work never approves anything itself. It pushes the typed authority request it holds to Access, sends the user's browser to Access's hosted Approval Surface with the request, Work's registered `redirect_uri` and a `state`, and on the way back reads only the `exercise`, `render_digest` and `state` Access put on the redirect; the Exercise is then confirmed with the Exercise query. Both Access endpoints come from discovery like every other one; while Access does not publish them the authority gate waits.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::domain::discovery::{Template, percent};
use crate::domain::exercise::ExerciseId;
use crate::domain::{AccessError, b64url, fixed_b64url};

/// The prefix of a pushed request's URI (RFC 9126 section 2.2).
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Longest `state` Access echoes.
pub const MAX_STATE: usize = 512;

/// The request the Approval Surface shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalRequest {
    /// The digest of the pushed request bytes (`access/authority-request-bytes/v1`).
    Digest([u8; 32]),
    /// The `request_uri` Access gave for the pushed request.
    Pushed(String),
}

impl ApprovalRequest {
    /// The `request` parameter.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Digest(d) => b64url(d),
            Self::Pushed(uri) => uri.clone(),
        }
    }
}

/// A `state`: 1 to 512 printable ASCII characters that Access echoes unchanged.
#[derive(Clone, PartialEq, Eq)]
pub struct State(String);

impl State {
    /// Wraps `text`.
    ///
    /// # Errors
    /// [`AccessError::Answer`] (`state`) for an empty, longer or non-printable value.
    pub fn new(text: &str) -> Result<Self, AccessError> {
        let printable = text.bytes().all(|b| (b' '..=b'~').contains(&b));
        if text.is_empty() || text.len() > MAX_STATE || !printable {
            return Err(AccessError::Answer("state"));
        }
        Ok(Self(text.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// The Approval Surface URL for `request`, `redirect_uri` and `state`, below the `approval`
/// endpoint discovery publishes.
///
/// # Errors
/// [`AccessError::Answer`] (`redirect_uri`) for a redirect that is not an `https` URL without a
/// fragment, (`request`) for a pushed request whose URI is not a `request_uri`.
pub fn approval_url(
    endpoint: &Template,
    request: &ApprovalRequest,
    redirect_uri: &str,
    state: &State,
) -> Result<String, AccessError> {
    let host = redirect_uri.strip_prefix("https://").unwrap_or_default();
    if host.is_empty() || redirect_uri.contains('#') {
        return Err(AccessError::Answer("redirect_uri"));
    }
    if let ApprovalRequest::Pushed(uri) = request
        && uri
            .strip_prefix(REQUEST_URI_PREFIX)
            .is_none_or(str::is_empty)
    {
        return Err(AccessError::Answer("request"));
    }
    let base = endpoint.expand("");
    let joiner = if base.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{base}{joiner}request={}&redirect_uri={}&state={}",
        percent(&request.text()),
        percent(redirect_uri),
        percent(state.as_str())
    ))
}

/// What Access put on the redirect back to Work after an approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalReturn {
    /// The Exercise to confirm with the Exercise query.
    pub exercise: ExerciseId,
    /// The digest of the render the user approved.
    pub render_digest: [u8; 32],
}

fn unpercent(text: &str) -> Option<String> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = char::from(bytes.next()?).to_digit(16)?;
            let lo = char::from(bytes.next()?).to_digit(16)?;
            out.push(u8::try_from(hi.checked_mul(16)?.checked_add(lo)?).ok()?);
        } else if b == b'+' {
            out.push(b' ');
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).ok()
}

impl ApprovalReturn {
    /// Reads the query of the redirect: exactly one `exercise`, `render_digest` and `state`,
    /// whose `state` is the one Work sent.
    ///
    /// # Errors
    /// [`AccessError::Answer`]: `state` when the state is missing or another one, `exercise` or
    /// `render_digest` for a missing, repeated or malformed value.
    pub fn parse(query: &str, sent: &State) -> Result<Self, AccessError> {
        let (mut exercise, mut render, mut state) = (None, None, None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = unpercent(value).ok_or(AccessError::Answer("query"))?;
            let (slot, code) = match name {
                "exercise" => (&mut exercise, "exercise"),
                "render_digest" => (&mut render, "render_digest"),
                "state" => (&mut state, "state"),
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(AccessError::Answer(code));
            }
        }
        if state.as_deref() != Some(sent.as_str()) {
            return Err(AccessError::Answer("state"));
        }
        let exercise = exercise
            .and_then(|e| ExerciseId::parse(&e).ok())
            .ok_or(AccessError::Answer("exercise"))?;
        let render_digest = render
            .and_then(|r| fixed_b64url::<32>(&r).ok())
            .ok_or(AccessError::Answer("render_digest"))?;
        Ok(Self {
            exercise,
            render_digest,
        })
    }
}

/// The body that pushes a typed authority request with the approver's pre-signed contribution
/// (`POST` to the `approval_requests` endpoint).
///
/// # Errors
/// [`AccessError::Answer`] (`request`) when either part is not a JSON object.
pub fn push_body(request: &Value, contribution: &Value) -> Result<Vec<u8>, AccessError> {
    if !request.is_object() || !contribution.is_object() {
        return Err(AccessError::Answer("request"));
    }
    serde_json::to_vec(&json!({"request": request, "contribution": contribution}))
        .map_err(|_| AccessError::Answer("request"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushedWire {
    request_uri: String,
    digest: String,
    expires_at: String,
}

/// A pushed request as Access names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pushed {
    /// The `request_uri` to open the surface with.
    pub request_uri: String,
    /// The digest of the pushed bytes; `request=<digest>` opens it too.
    pub digest: [u8; 32],
    /// When the surface stops showing it, RFC 3339.
    pub expires_at: String,
}

impl Pushed {
    /// Reads the `201` answer.
    ///
    /// # Errors
    /// [`AccessError::Answer`] (`pushed`).
    pub fn from_json(body: &[u8]) -> Result<Self, AccessError> {
        let bad = || AccessError::Answer("pushed");
        let wire: PushedWire = serde_json::from_slice(body).map_err(|_| bad())?;
        if !wire.request_uri.starts_with(REQUEST_URI_PREFIX) {
            return Err(bad());
        }
        Ok(Self {
            request_uri: wire.request_uri,
            digest: fixed_b64url(&wire.digest).map_err(|_| bad())?,
            expires_at: wire.expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::discovery::{Endpoint, Endpoints};

    fn endpoint() -> Template {
        Endpoints::from_pairs([("approval", "https://acme.id.example/approve")])
            .unwrap()
            .get(Endpoint::Approval)
            .unwrap()
            .clone()
    }

    // T-101 E-17 E-26
    #[test]
    fn e_17_work_only_sends_the_user_to_the_access_approval_surface() {
        let state = State::new("s 1").unwrap();
        let url = approval_url(
            &endpoint(),
            &ApprovalRequest::Digest([1; 32]),
            "https://work.example/v1/access/approval",
            &state,
        )
        .unwrap();
        assert_eq!(
            url,
            format!(
                "https://acme.id.example/approve?request={}&redirect_uri=https%3A%2F%2Fwork.example%2Fv1%2Faccess%2Fapproval&state=s%201",
                b64url(&[1; 32])
            )
        );
        let pushed = ApprovalRequest::Pushed(format!("{REQUEST_URI_PREFIX}abc"));
        let url = approval_url(&endpoint(), &pushed, "https://w.example/r", &state).unwrap();
        assert!(url.contains("request=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc"));
        let bare = ApprovalRequest::Pushed("abc".to_owned());
        assert_eq!(
            approval_url(&endpoint(), &bare, "https://w.example/r", &state),
            Err(AccessError::Answer("request"))
        );
        for redirect in ["http://w.example/r", "https://", "https://w.example/r#f"] {
            assert_eq!(
                approval_url(&endpoint(), &pushed, redirect, &state),
                Err(AccessError::Answer("redirect_uri")),
                "{redirect}"
            );
        }
        for bad in [String::new(), "x".repeat(513), "a\nb".to_owned()] {
            assert!(State::new(&bad).is_err());
        }
        assert!(State::new(&"x".repeat(512)).is_ok());
    }

    // T-101 E-17
    #[test]
    fn t_101_the_return_names_the_exercise_only_for_the_state_work_sent() {
        let sent = State::new("st/1").unwrap();
        let exercise = ExerciseId([4; 32]);
        let query = format!(
            "exercise={}&render_digest={}&state=st%2F1",
            exercise.text(),
            b64url(&[5; 32])
        );
        let got = ApprovalReturn::parse(&query, &sent).unwrap();
        assert_eq!(got.exercise, exercise);
        assert_eq!(got.render_digest, [5; 32]);
        let other = State::new("st/2").unwrap();
        assert_eq!(
            ApprovalReturn::parse(&query, &other),
            Err(AccessError::Answer("state"))
        );
        let twice = format!("{query}&exercise={}", exercise.text());
        assert_eq!(
            ApprovalReturn::parse(&twice, &sent),
            Err(AccessError::Answer("exercise"))
        );
        let missing = format!("render_digest={}&state=st%2F1", b64url(&[5; 32]));
        assert_eq!(
            ApprovalReturn::parse(&missing, &sent),
            Err(AccessError::Answer("exercise"))
        );
    }

    // T-101 E-17
    #[test]
    fn t_101_a_pushed_request_is_named_by_its_request_uri_and_digest() {
        let body = push_body(&json!({"v": 1}), &json!({"c": 1})).unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, json!({"request": {"v": 1}, "contribution": {"c": 1}}));
        assert!(push_body(&json!([]), &json!({})).is_err());
        let answer = json!({
            "request_uri": format!("{REQUEST_URI_PREFIX}r1"),
            "digest": b64url(&[6; 32]),
            "expires_at": "2026-11-06T12:00:00Z",
        });
        let pushed = Pushed::from_json(answer.to_string().as_bytes()).unwrap();
        assert_eq!(pushed.digest, [6; 32]);
        let mut other = answer;
        other["request_uri"] = json!("r1");
        assert!(Pushed::from_json(other.to_string().as_bytes()).is_err());
    }
}
