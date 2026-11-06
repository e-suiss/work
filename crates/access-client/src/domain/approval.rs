//! The Access approval call (T-101 item 7 and its note, E-17, E-26; Access OP-149 m.9, OP-150 m.3 (r)): Work never approves anything itself. It pushes the typed authority request it holds to Access, sends the user's browser to Access's hosted Approval Surface with the request, Work's registered `redirect_uri` and a `state`, and on the way back reads only the `exercise`, `render_digest` and `state` Access put on the redirect; the Exercise is then confirmed with the Exercise query. Both Access endpoints come from discovery like every other one; while Access does not publish them the authority gate waits.

use access_kernel::ais::Statement as Ais;
use access_kernel::codec::Canonical as _;
use access_kernel::contribution::contribute_intent;
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::model::Window;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::domain::discovery::{Template, percent};
use crate::domain::exercise::ExerciseId;
use crate::domain::keys::{DomainId, KernelId};
use crate::domain::metadata::unverified_payload;
use crate::domain::pairing::rfc3339_ms;
use crate::domain::{AccessError, b64url, fixed_b64url, from_b64url};

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

/// Whether `uri` is a redirect Access registers: an `https` URL, or an `http` URL of a loopback
/// address (RFC 8252 section 7.3), with a host and without a fragment.
#[must_use]
pub fn redirect_target(uri: &str) -> bool {
    let authority = |rest: &str| {
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        rest.get(..end).unwrap_or_default().to_owned()
    };
    if uri.contains('#') || uri.contains('@') {
        return false;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        return !authority(rest).is_empty();
    }
    uri.strip_prefix("http://").is_some_and(|rest| {
        let a = authority(rest);
        let host = if a.ends_with(']') {
            a.as_str()
        } else {
            a.rsplit_once(':').map_or(a.as_str(), |(h, _)| h)
        };
        matches!(host, "127.0.0.1" | "[::1]")
    })
}

/// The Approval Surface URL for `request`, `redirect_uri` and `state`, below the `approval`
/// endpoint discovery publishes.
///
/// # Errors
/// [`AccessError::Answer`] (`redirect_uri`) for a redirect that is not a [`redirect_target`],
/// (`request`) for a pushed request whose URI is not a `request_uri`.
pub fn approval_url(
    endpoint: &Template,
    request: &ApprovalRequest,
    redirect_uri: &str,
    state: &State,
) -> Result<String, AccessError> {
    if !redirect_target(redirect_uri) {
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
    /// The approver's `authentication` Claim the passkey assertion made, which the next commit
    /// names as `claim_ref` when Access asked for a step-up (Access OP-149 m.33 (c)).
    pub claim: Option<KernelId>,
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
    /// The one `state` the query of the redirect carries, to look up the one Work sent.
    ///
    /// # Errors
    /// [`AccessError::Answer`]: `state` for a missing, repeated or malformed `state`, `query`
    /// for a value that does not decode.
    pub fn state(query: &str) -> Result<State, AccessError> {
        let mut found = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if name != "state" {
                continue;
            }
            let value = unpercent(value).ok_or(AccessError::Answer("query"))?;
            if found.replace(value).is_some() {
                return Err(AccessError::Answer("state"));
            }
        }
        State::new(&found.ok_or(AccessError::Answer("state"))?)
    }

    /// Reads the query of the redirect: exactly one `exercise`, `render_digest` and `state`,
    /// whose `state` is the one Work sent, and at most one `claim`.
    ///
    /// # Errors
    /// [`AccessError::Answer`]: `state` when the state is missing or another one, `exercise` or
    /// `render_digest` for a missing, repeated or malformed value, `claim` for a repeated or
    /// malformed one.
    pub fn parse(query: &str, sent: &State) -> Result<Self, AccessError> {
        let (mut exercise, mut render, mut state, mut claim) = (None, None, None, None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = unpercent(value).ok_or(AccessError::Answer("query"))?;
            let (slot, code) = match name {
                "exercise" => (&mut exercise, "exercise"),
                "render_digest" => (&mut render, "render_digest"),
                "state" => (&mut state, "state"),
                "claim" => (&mut claim, "claim"),
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
        let claim = claim
            .map(|c| KernelId::parse(&c).map_err(|_| AccessError::Answer("claim")))
            .transpose()?;
        Ok(Self {
            exercise,
            render_digest,
            claim,
        })
    }
}

/// The contribute class of an approval (Access §9.14.1).
pub const APPROVE_CLASS: &str = "approve";

/// The digest of the `contribute` intent an approver's device signs for a contribution of
/// `class` to the intent `target` over `[from_ms, until_ms]` (Access L0-META-30,
/// `contribution::contribute_intent`).
///
/// # Errors
/// [`AccessError::Answer`] (`contribution`) for an empty window or an intent beyond the
/// structural limits.
pub fn contribution_intent(
    target: &[u8; 32],
    class: &str,
    from_ms: u64,
    until_ms: u64,
) -> Result<[u8; 32], AccessError> {
    let bad = || AccessError::Answer("contribution");
    if until_ms < from_ms {
        return Err(bad());
    }
    let window = Window {
        from: from_ms,
        until: until_ms,
    };
    let intent = contribute_intent(Digest(*target), class, window).ok_or_else(bad)?;
    intent_digest(&intent).map(|d| d.0).map_err(|_| bad())
}

/// The digest of the `contribute` intent the approver's pre-signed `contribution` states for
/// an approval of the intent `target` in `domain` (Access §9.14.1 A step 4, OP-149 m.9): an
/// `approve` whose Actor Intent Statement names the domain and exactly the `contribute` intent
/// of `target` over the contribution's `valid_from` and `valid_until`. Its signature is
/// Access's to verify; Work keeps the digest to check the contribution Exercise the Approval
/// Surface returns against.
///
/// # Errors
/// [`AccessError::Answer`]: `contribution` for a body outside the push contract or another
/// class, `contribution-intent` for a statement of another intent or domain.
pub fn presigned_intent(
    contribution: &Value,
    target: &[u8; 32],
    domain: &DomainId,
) -> Result<[u8; 32], AccessError> {
    let bad = || AccessError::Answer("contribution");
    let text = |name: &str| {
        contribution
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(bad)
    };
    if text("class")? != APPROVE_CLASS {
        return Err(bad());
    }
    let from = rfc3339_ms(text("valid_from")?).ok_or_else(bad)?;
    let until = rfc3339_ms(text("valid_until")?).ok_or_else(bad)?;
    let digest = contribution_intent(target, APPROVE_CLASS, from, until)?;
    let ais = from_b64url(text("ais")?).map_err(|_| bad())?;
    let payload = unverified_payload(&ais).map_err(|_| bad())?;
    let stated = Ais::from_bytes(&payload).map_err(|_| bad())?;
    if stated.intent.0 != digest || stated.domain.0 != domain.0 {
        return Err(AccessError::Answer("contribution-intent"));
    }
    Ok(digest)
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
        for redirect in [
            "http://w.example/r",
            "http://127.0.0.2:8190/r",
            "http://127.0.0.1@w.example/r",
            "https://",
            "https://w.example/r#f",
        ] {
            assert_eq!(
                approval_url(&endpoint(), &pushed, redirect, &state),
                Err(AccessError::Answer("redirect_uri")),
                "{redirect}"
            );
        }
        for loopback in [
            "http://127.0.0.1:8190/v1/access/approval",
            "http://[::1]/v1/access/approval",
        ] {
            assert!(approval_url(&endpoint(), &pushed, loopback, &state).is_ok());
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
        assert_eq!(got.claim, None);
        let claimed = format!("{query}&claim={}", KernelId([8; 16]).text());
        assert_eq!(
            ApprovalReturn::parse(&claimed, &sent).unwrap().claim,
            Some(KernelId([8; 16]))
        );
        for bad in [
            format!("{claimed}&claim={}", KernelId([8; 16]).text()),
            format!("{query}&claim={}", b64url(&[8; 32])),
        ] {
            assert_eq!(
                ApprovalReturn::parse(&bad, &sent),
                Err(AccessError::Answer("claim")),
                "{bad}"
            );
        }
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
        assert_eq!(ApprovalReturn::state(&query).unwrap(), sent);
        assert_eq!(ApprovalReturn::state(&missing).unwrap(), sent);
        for bad in [
            format!("{query}&state=st%2F1"),
            format!("exercise={}", exercise.text()),
            "state=".to_owned(),
        ] {
            assert_eq!(
                ApprovalReturn::state(&bad),
                Err(AccessError::Answer("state")),
                "{bad}"
            );
        }
        assert_eq!(
            ApprovalReturn::state("state=%zz"),
            Err(AccessError::Answer("query"))
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

    const CONTRIBUTE: &str =
        include_str!("../../../../conformance/vectors/access/contribute-intent.json");

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
            .collect()
    }

    // E-17 T-101
    #[test]
    fn e_17_work_derives_access_s_contribute_intent_of_an_approval() {
        use access_kernel::codec::Canonical as _;
        let file: Value = serde_json::from_str(CONTRIBUTE).unwrap();
        let cases = file["cases"].as_array().unwrap();
        let mut derived = 0_u32;
        for case in cases {
            let Some(cbor) = case["cbor"].as_str() else {
                assert_eq!(case["valid"], false);
                continue;
            };
            let envelope = access_kernel::intent::IntentEnvelope::from_bytes(&unhex(cbor)).unwrap();
            let Some(target) = case["target"].as_str() else {
                assert!(envelope.opaque.is_empty());
                continue;
            };
            let target: [u8; 32] = unhex(target).try_into().unwrap();
            let class = case["class"].as_str().unwrap();
            let digest = contribution_intent(
                &target,
                class,
                envelope.validity.from,
                envelope.validity.until,
            )
            .unwrap();
            assert_eq!(
                digest.to_vec(),
                unhex(case["intent_digest"].as_str().unwrap())
            );
            assert_eq!(
                intent_digest(&envelope).unwrap().0,
                digest,
                "{}",
                case["id"]
            );
            assert_ne!(
                contribution_intent(
                    &[0; 32],
                    class,
                    envelope.validity.from,
                    envelope.validity.until
                )
                .unwrap(),
                digest
            );
            derived = derived.saturating_add(1);
        }
        assert_eq!(derived, 1);
        assert_eq!(
            contribution_intent(&[4; 32], APPROVE_CLASS, 2, 1),
            Err(AccessError::Answer("contribution"))
        );
    }

    fn sign1(payload: &[u8]) -> Vec<u8> {
        use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
        let protected = dcbor::encode(
            &Cbor::Map(vec![(Cbor::Unsigned(1), Cbor::int(-19))]),
            Limits::CEILING,
        )
        .unwrap();
        let message = Cbor::Tag(
            18,
            Box::new(Cbor::Array(vec![
                Cbor::Bytes(protected),
                Cbor::Map(Vec::new()),
                Cbor::Bytes(payload.to_vec()),
                Cbor::Bytes(vec![0; 64]),
            ])),
        );
        dcbor::encode(&message, Limits::CEILING).unwrap()
    }

    // E-17 T-101
    #[test]
    fn e_17_a_pushed_contribution_states_the_approval_of_work_s_request_and_nothing_else() {
        use crate::domain::adp::{Holding, Statement};
        use crate::domain::exercise::Capacity;
        let domain = DomainId([3; 32]);
        let target = [4; 32];
        let (from, until) = (1_767_225_540_000, 1_767_226_200_000);
        let digest = contribution_intent(&target, APPROVE_CLASS, from, until).unwrap();
        let contribution = |intent: &[u8; 32], domain: &DomainId, class: &str| {
            let basis = Holding {
                grant: KernelId([1; 16]),
                holder: KernelId([2; 16]),
                since: 4,
            };
            let statement = Statement {
                domain,
                nonce: &[5; 16],
                intent,
                pep: "identity",
                capacity: Capacity::Own,
                basis,
            };
            json!({
                "nonce": b64url(&[5; 16]),
                "class": class,
                "basis": basis.json()["holding"],
                "valid_from": "2025-12-31T23:59:00Z",
                "valid_until": "2026-01-01T00:10:00.000Z",
                "ais": b64url(&sign1(&statement.to_sign(1_767_225_600_000).unwrap())),
            })
        };
        let good = contribution(&digest, &domain, APPROVE_CLASS);
        assert_eq!(presigned_intent(&good, &target, &domain), Ok(digest));
        assert_eq!(
            presigned_intent(&good, &[9; 32], &domain),
            Err(AccessError::Answer("contribution-intent"))
        );
        assert_eq!(
            presigned_intent(&good, &target, &DomainId([7; 32])),
            Err(AccessError::Answer("contribution-intent"))
        );
        let witness = contribution(&digest, &domain, "witness");
        assert_eq!(
            presigned_intent(&witness, &target, &domain),
            Err(AccessError::Answer("contribution"))
        );
        let mut late = good.clone();
        late["valid_until"] = json!("2026-01-01T00:11:00Z");
        assert_eq!(
            presigned_intent(&late, &target, &domain),
            Err(AccessError::Answer("contribution-intent"))
        );
        for member in ["ais", "valid_from", "class"] {
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove(member);
            assert_eq!(
                presigned_intent(&missing, &target, &domain),
                Err(AccessError::Answer("contribution")),
                "{member}"
            );
        }
    }
}
