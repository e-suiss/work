//! What a caller asks Work's PEP to commit at Access before a `work:commit` (T-101 item 2 and its note, E-7, E-17, P-13, P-116 item 6): the canonical intent, the Exercise nonce, the holding basis and the Actor Intent Statement the caller's own device Instance signed, the contribution Exercises of the approvals it relies on, the reason Work shows and, for a push, the approver's pre-signed contribution. The answer is the Exercise Access allowed with its verified receipt, or the `REQUIRE_ACTION` with the step-up Access names, the typed authority request and the Approval Surface URL. Work signs nothing for the caller and approves nothing: every proof comes from the caller's device and from Access.

use serde_json::Value;
use suiss_crypto::digest::sha256;
pub use work_access_client::domain::adp::Holding;
use work_access_client::domain::b64url;
use work_access_client::domain::exercise::ExerciseId;
pub use work_access_client::domain::exercise::VerifiedExercise;
use work_access_client::domain::keys::KernelId;

/// How long a pushed authority request waits on the Approval Surface at most, Unix
/// milliseconds (PD); never past the intent's validity.
pub const REQUEST_TTL_MS: u64 = 60 * 60 * 1000;

/// One authority request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAsk {
    /// The canonical `IntentEnvelope` bytes.
    pub intent: Vec<u8>,
    /// The Exercise nonce, 16 to 64 bytes.
    pub nonce: Vec<u8>,
    /// The caller's holding of the Grant.
    pub basis: Holding,
    /// The Actor Intent Statement, a tagged `COSE_Sign1` by the caller's device Instance key.
    pub ais: Vec<u8>,
    /// The contribution Exercises of the approvals the commit relies on.
    pub contributions: Vec<ExerciseId>,
    /// Why, as the Approval Surface shows it.
    pub reason: String,
    /// The approver's pre-signed contribution, to push the request with.
    pub contribution: Option<Value>,
    /// The `Idempotency-Key`.
    pub idempotency_key: String,
}

/// A request pushed to the Approval Surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    /// Where the caller's browser goes: the Approval Surface with the request, Work's
    /// `redirect_uri` and a `state`.
    pub url: String,
    /// The `request_uri` Access gave.
    pub request_uri: String,
    /// When the surface stops showing it, RFC 3339.
    pub expires_at: String,
}

/// What Access answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityAnswer {
    /// Allowed: the Exercise with its verified decision receipt.
    Allowed(Box<VerifiedExercise>),
    /// Not yet.
    RequireAction {
        /// The unmet terms, as Access showed them to the requester.
        unmet: Vec<Value>,
        /// The authentication terms among them: the step-up the caller meets at Access first.
        step_up: Vec<Value>,
        /// The typed authority request, when Access asks for an approval.
        request: Option<Value>,
        /// The pushed request, when the caller sent the approver's contribution.
        approval: Option<Approval>,
    },
}

fn derived(context: &str, caller: &str, value: &[u8]) -> String {
    let mut input = Vec::with_capacity(
        context
            .len()
            .saturating_add(caller.len())
            .saturating_add(value.len())
            .saturating_add(2),
    );
    input.extend_from_slice(context.as_bytes());
    input.push(0);
    input.extend_from_slice(caller.as_bytes());
    input.push(0);
    input.extend_from_slice(value);
    b64url(&sha256(&input))
}

/// The `Idempotency-Key` Work's PEP sends Access for the `step` (`evaluation` or `push`) of
/// the caller's request under `key`: one Access key per caller, key and step, so a request sent
/// again is answered again and no two callers share one.
#[must_use]
pub fn forwarded_key(step: &str, caller: &str, key: &str) -> String {
    derived(
        &format!("work/authority-request/{step}/v1"),
        caller,
        key.as_bytes(),
    )
}

/// The `state` of the approval call for `caller` and the pushed request's digest (T-101 item
/// 7): bound to both and nothing else.
#[must_use]
pub fn approval_state(caller: &str, digest: &[u8; 32]) -> String {
    derived("work/approval-state/v1", caller, digest)
}

/// The holding of `grant` by `holder` since `since`, each id as unpadded base64url of its 16
/// bytes; `None` for an id that is not.
#[must_use]
pub fn holding(grant: &str, holder: &str, since: u64) -> Option<Holding> {
    Some(Holding {
        grant: KernelId::parse(grant).ok()?,
        holder: KernelId::parse(holder).ok()?,
        since,
    })
}

/// The unpadded base64url of `bytes`, as an answer spells every byte string.
#[must_use]
pub fn base64url_text(bytes: &[u8]) -> String {
    b64url(bytes)
}

/// The expiry of a pushed request: [`REQUEST_TTL_MS`] after `now_ms`, never past the intent's
/// last valid instant.
#[must_use]
pub fn expires_at(now_ms: u64, valid_until_ms: u64) -> u64 {
    now_ms.saturating_add(REQUEST_TTL_MS).min(valid_until_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-101 E-17
    #[test]
    fn t_101_a_request_s_access_keys_and_state_are_its_caller_s_alone() {
        let a = forwarded_key("evaluation", "party-a", "key-1");
        assert_eq!(a, forwarded_key("evaluation", "party-a", "key-1"));
        assert_ne!(a, forwarded_key("evaluation", "party-b", "key-1"));
        assert_ne!(a, forwarded_key("evaluation", "party-a", "key-2"));
        assert_ne!(a, forwarded_key("push", "party-a", "key-1"));
        assert_eq!(a.len(), 43);
        let s = approval_state("party-a", &[1; 32]);
        assert_ne!(s, approval_state("party-b", &[1; 32]));
        assert_ne!(s, approval_state("party-a", &[2; 32]));
        assert_eq!(expires_at(1_000, u64::MAX), 3_601_000);
        assert_eq!(expires_at(1_000, 5_000), 5_000);
    }
}
