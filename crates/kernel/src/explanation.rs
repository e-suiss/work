//! The decision explanation shared with Access (Access E43, `explanation.cddl`; PR-11, PR-17): the one format in which a Suiss product says why an outcome was reached, what blocks it and what is still missing. A value is checked against the CDDL when it is built or decoded; arrays are non-empty, `unmet` and `relied_on` are in the order of their members' canonical encodings and nothing repeats. A restriction rule set's result shows in it as Access shows it: `NO_OBJECTION` adds nothing, `DENY` is one `restricted` blocker at `domain-policy` and `REQUIRE` is one unmet term per requirement term at `domain-policy`.

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

/// The JSON Schema of the JSON form (Access `explanation.schema.json`).
pub const SCHEMA: &str = "urn:suiss:access:schema:explanation:1";

/// The subcode prefix of a restriction rule set's `DENY` (Access L0-EVAL-18).
pub const RESTRICTED_POLICY: &str = "restricted/policy:";

const OUTCOMES: &[&str] = &["allow", "deny", "require_action"];
const CLASSES: &[&str] = &[
    "no-covering-authority",
    "outside-instance-limits",
    "restricted",
    "budget-exhausted",
    "ended",
    "capacity-mismatch",
    "source-not-accepted",
    "schema-not-accepted",
    "nonce-closed",
    "foreign-status-unavailable",
];
const POSITIONS: &[&str] = &[
    "instance",
    "anchor",
    "domain-policy",
    "foreign",
    "actor-side",
];
const RESOLVERS: &[&str] = &[
    "root",
    "restriction-owner",
    "issuer",
    "domain-admin",
    "actor",
    "actor-party",
    "time",
];
const REMEDIATIONS: &[&str] = &[
    "route-to-coordinator",
    "refresh-claim",
    "self-authenticate",
    "not-satisfiable-by-actor",
    "new-request-required",
];
const PROOF_KINDS: &[&str] = &[
    "claim",
    "contribution",
    "authentication",
    "foreign_authority",
];
const BINDINGS: &[&str] = &["actor_instance", "intent_digest", "resource"];
const DISTINCT: &[&str] = &["party", "instance", "issuer"];
const LEVELS: &[&str] = &["aal", "loa_eidas"];
const FLAGS: &[&str] = &[
    "phishing_resistant",
    "hardware_bound",
    "non_custodial",
    "uv",
    "human_presence",
    "app_controlled_factor",
    "synced",
];
const TOP: &[&str] = &["outcome", "blockers", "unmet", "relied_on"];
const BLOCKER: &[&str] = &["class", "subcode", "position", "resolver", "remediation"];
const UNMET: &[&str] = &["term", "missing", "position", "satisfiable_by_actor"];
const TERM: &[&str] = &[
    "proof_kind",
    "class",
    "count",
    "binding",
    "freshness_ms",
    "independence",
    "consumption",
    "source",
    "assurance",
];
const SHA256_ALG: u64 = 15;

/// Why a value is not an explanation, naming the member it refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExplanationError(pub &'static str);

impl core::fmt::Display for ExplanationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not an explanation: {}", self.0)
    }
}

impl core::error::Error for ExplanationError {}

type Checked<T = ()> = Result<T, ExplanationError>;

/// A decision explanation, checked against `explanation.cddl`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation(Value);

fn encoded(v: &Value) -> Checked<Vec<u8>> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| ExplanationError("encoding"))
}

fn entries<'a>(
    v: &'a Value,
    allowed: &[&str],
    required: &[&str],
    what: &'static str,
) -> Checked<&'a [(Value, Value)]> {
    let Value::Map(entries) = v else {
        return Err(ExplanationError(what));
    };
    let mut seen: Vec<&str> = Vec::with_capacity(entries.len());
    for (k, _) in entries {
        let Value::Text(k) = k else {
            return Err(ExplanationError(what));
        };
        if !allowed.contains(&k.as_str()) || seen.contains(&k.as_str()) {
            return Err(ExplanationError(what));
        }
        seen.push(k);
    }
    if required.iter().any(|r| !seen.contains(r)) {
        return Err(ExplanationError(what));
    }
    Ok(entries.as_slice())
}

fn one_of(v: &Value, names: &[&str], what: &'static str) -> Checked {
    match v {
        Value::Text(t) if names.contains(&t.as_str()) => Ok(()),
        _ => Err(ExplanationError(what)),
    }
}

fn uint(v: &Value, what: &'static str) -> Checked<u64> {
    match v {
        Value::Unsigned(n) => Ok(*n),
        _ => Err(ExplanationError(what)),
    }
}

fn single<'a>(v: &'a Value, key: &str, what: &'static str) -> Checked<&'a Value> {
    match v {
        Value::Map(entries) => match entries.as_slice() {
            [(Value::Text(k), inner)] if k == key => Ok(inner),
            _ => Err(ExplanationError(what)),
        },
        _ => Err(ExplanationError(what)),
    }
}

/// Whether `s` is a CDDL `ident`: `[a-z][a-z0-9_]{0,62}`.
#[must_use]
pub fn is_ident(s: &str) -> bool {
    let mut chars = s.bytes();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && s.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn ident(v: &Value, what: &'static str) -> Checked {
    match v {
        Value::Text(t) if is_ident(t) => Ok(()),
        _ => Err(ExplanationError(what)),
    }
}

fn id(v: &Value, what: &'static str) -> Checked {
    match v {
        Value::Bytes(b) if b.len() == 16 => Ok(()),
        _ => Err(ExplanationError(what)),
    }
}

fn digest(v: &Value) -> Checked {
    match v {
        Value::Array(items) => match items.as_slice() {
            [Value::Negative(SHA256_ALG), Value::Bytes(b)] if b.len() == 32 => Ok(()),
            _ => Err(ExplanationError("digest")),
        },
        _ => Err(ExplanationError("digest")),
    }
}

fn position(v: &Value) -> Checked {
    if matches!(v, Value::Text(_)) {
        return one_of(v, POSITIONS, "position");
    }
    uint(single(v, "hop", "position")?, "position").map(|_| ())
}

fn resolver(v: &Value) -> Checked {
    if matches!(v, Value::Text(_)) {
        return one_of(v, RESOLVERS, "resolver");
    }
    uint(single(v, "grantor_of_hop", "resolver")?, "resolver").map(|_| ())
}

fn remediation(v: &Value) -> Checked {
    if matches!(v, Value::Text(_)) {
        return one_of(v, REMEDIATIONS, "remediation");
    }
    uint(single(v, "wait_until", "remediation")?, "remediation").map(|_| ())
}

fn blocker(v: &Value) -> Checked {
    let e = entries(v, BLOCKER, &["class", "resolver", "remediation"], "blocker")?;
    for (k, value) in e {
        match k {
            Value::Text(k) if k == "class" => one_of(value, CLASSES, "blocker.class")?,
            Value::Text(k) if k == "subcode" => {
                if !matches!(value, Value::Text(_)) {
                    return Err(ExplanationError("blocker.subcode"));
                }
            }
            Value::Text(k) if k == "position" => position(value)?,
            Value::Text(k) if k == "resolver" => resolver(value)?,
            _ => remediation(value)?,
        }
    }
    Ok(())
}

fn conjunct(v: &Value) -> Checked {
    let e = entries(v, &["claim_class", "value"], &["claim_class"], "conjunct")?;
    for (k, value) in e {
        match k {
            Value::Text(k) if k == "claim_class" => ident(value, "conjunct.claim_class")?,
            _ => {
                if !matches!(
                    value,
                    Value::Text(_)
                        | Value::Bytes(_)
                        | Value::Unsigned(_)
                        | Value::Negative(_)
                        | Value::Bool(_)
                ) {
                    return Err(ExplanationError("conjunct.value"));
                }
            }
        }
    }
    Ok(())
}

fn selector(v: &Value) -> Checked {
    if let Value::Text(t) = v {
        return if t == "public" {
            Ok(())
        } else {
            Err(ExplanationError("source"))
        };
    }
    let Value::Map(e) = v else {
        return Err(ExplanationError("source"));
    };
    match e.as_slice() {
        [(Value::Text(k), party)] if k == "party" => id(party, "source.party"),
        [(Value::Text(k), Value::Array(pred))] if k == "pred" && !pred.is_empty() => {
            pred.iter().try_for_each(conjunct)
        }
        [(Value::Text(k), foreign)] if k == "foreign" => {
            let f = entries(
                foreign,
                &["domain", "authority_class"],
                &["domain", "authority_class"],
                "source.foreign",
            )?;
            for (k, value) in f {
                match k {
                    Value::Text(k) if k == "domain" => digest(value)?,
                    _ => ident(value, "source.foreign.authority_class")?,
                }
            }
            Ok(())
        }
        _ => Err(ExplanationError("source")),
    }
}

fn assurance(v: &Value) -> Checked {
    let Value::Map(e) = v else {
        return Err(ExplanationError("assurance"));
    };
    if e.is_empty() {
        return Err(ExplanationError("assurance"));
    }
    let mut keys: Vec<&str> = Vec::with_capacity(e.len());
    for (k, value) in e {
        let (Value::Text(k), Value::Unsigned(level)) = (k, value) else {
            return Err(ExplanationError("assurance"));
        };
        let fits = if LEVELS.contains(&k.as_str()) {
            (1..=3).contains(level)
        } else {
            FLAGS.contains(&k.as_str()) && *level <= 1
        };
        if !fits || keys.contains(&k.as_str()) {
            return Err(ExplanationError("assurance"));
        }
        keys.push(k);
    }
    Ok(())
}

/// Checks one CDDL `requirement-term`.
///
/// # Errors
/// [`ExplanationError`] naming the member that does not fit.
pub fn check_term(v: &Value) -> Checked {
    let e = entries(v, TERM, &["proof_kind", "class"], "term")?;
    for (k, value) in e {
        let Value::Text(k) = k else {
            return Err(ExplanationError("term"));
        };
        match k.as_str() {
            "proof_kind" => one_of(value, PROOF_KINDS, "term.proof_kind")?,
            "class" => ident(value, "term.class")?,
            "count" => {
                if uint(value, "term.count")? < 2 {
                    return Err(ExplanationError("term.count"));
                }
            }
            "binding" => one_of(value, BINDINGS, "term.binding")?,
            "freshness_ms" => uint(value, "term.freshness_ms").map(|_| ())?,
            "independence" => one_of(
                single(value, "distinct", "term.independence")?,
                DISTINCT,
                "term.independence",
            )?,
            "consumption" => one_of(value, &["single_use"], "term.consumption")?,
            "source" => selector(value)?,
            _ => assurance(value)?,
        }
    }
    Ok(())
}

fn unmet(v: &Value) -> Checked {
    let e = entries(v, UNMET, UNMET, "unmet")?;
    for (k, value) in e {
        let Value::Text(k) = k else {
            return Err(ExplanationError("unmet"));
        };
        match k.as_str() {
            "term" => check_term(value)?,
            "missing" => {
                if uint(value, "unmet.missing")? < 1 {
                    return Err(ExplanationError("unmet.missing"));
                }
            }
            "position" => position(value)?,
            _ => {
                if !matches!(value, Value::Bool(_)) {
                    return Err(ExplanationError("unmet.satisfiable_by_actor"));
                }
            }
        }
    }
    Ok(())
}

fn items<'a>(v: &'a Value, what: &'static str) -> Checked<&'a [Value]> {
    match v {
        Value::Array(items) if !items.is_empty() => Ok(items),
        _ => Err(ExplanationError(what)),
    }
}

fn distinct(items: &[Value], what: &'static str) -> Checked {
    let mut seen: Vec<Vec<u8>> = Vec::with_capacity(items.len());
    for item in items {
        let bytes = encoded(item)?;
        if seen.contains(&bytes) {
            return Err(ExplanationError(what));
        }
        seen.push(bytes);
    }
    Ok(())
}

fn ordered(items: &[Value], what: &'static str) -> Checked {
    let mut last: Option<Vec<u8>> = None;
    for item in items {
        let bytes = encoded(item)?;
        if last.as_ref().is_some_and(|l| *l >= bytes) {
            return Err(ExplanationError(what));
        }
        last = Some(bytes);
    }
    Ok(())
}

fn sorted(items: Vec<Value>) -> Checked<Vec<Value>> {
    let mut keyed: Vec<(Vec<u8>, Value)> = Vec::with_capacity(items.len());
    for item in items {
        keyed.push((encoded(&item)?, item));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    Ok(keyed.into_iter().map(|(_, v)| v).collect())
}

fn canonical(value: Value) -> Value {
    match encoded(&value)
        .ok()
        .and_then(|b| dcbor::decode(&b, Limits::CEILING).ok())
    {
        Some(c) => c,
        None => value,
    }
}

fn entry(key: &str, value: Value) -> (Value, Value) {
    (Value::text(key), value)
}

fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().saturating_mul(4).div_ceil(3));
    let mut push = |six: u32| {
        let index = usize::try_from(six & 0x3f).unwrap_or_default();
        out.extend(ALPHABET.get(index).map(|&c| char::from(c)));
    };
    for chunk in bytes.chunks(3) {
        let [a, b, c] = match *chunk {
            [a] => [a, 0, 0],
            [a, b] => [a, b, 0],
            [a, b, c, ..] => [a, b, c],
            [] => continue,
        };
        let n = u32::from_be_bytes([0, a, b, c]);
        push(n >> 18);
        push(n >> 12);
        if chunk.len() > 1 {
            push(n >> 6);
        }
        if chunk.len() > 2 {
            push(n);
        }
    }
    out
}

impl Explanation {
    /// Checks `value` against `explanation.cddl`; its maps are kept in canonical key order.
    ///
    /// # Errors
    /// [`ExplanationError`] naming the member that does not fit.
    pub fn from_value(value: Value) -> Result<Self, ExplanationError> {
        let e = entries(&value, TOP, &["outcome"], "explanation")?;
        for (k, v) in e {
            let Value::Text(k) = k else {
                return Err(ExplanationError("explanation"));
            };
            match k.as_str() {
                "outcome" => one_of(v, OUTCOMES, "outcome")?,
                "blockers" => {
                    let blockers = items(v, "blockers")?;
                    blockers.iter().try_for_each(blocker)?;
                    distinct(blockers, "blockers")?;
                }
                "unmet" => {
                    let terms = items(v, "unmet")?;
                    terms.iter().try_for_each(unmet)?;
                    ordered(terms, "unmet")?;
                }
                _ => {
                    let ids = items(v, "relied_on")?;
                    ids.iter().try_for_each(|i| id(i, "relied_on"))?;
                    ordered(ids, "relied_on")?;
                }
            }
        }
        Ok(Self(canonical(value)))
    }

    /// Decodes and checks the CBOR form.
    ///
    /// # Errors
    /// [`ExplanationError`]: `cbor` for bytes that are not deterministic CBOR, otherwise the
    /// member that does not fit.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExplanationError> {
        let value = dcbor::decode(bytes, Limits::CEILING).map_err(|_| ExplanationError("cbor"))?;
        Self::from_value(value)
    }

    /// The canonical CBOR form.
    ///
    /// # Errors
    /// [`ExplanationError`] `encoding` when the value is over the structural limits.
    pub fn encode(&self) -> Result<Vec<u8>, ExplanationError> {
        encoded(&self.0)
    }

    /// The checked value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.0
    }

    /// The outcome: `allow`, `deny` or `require_action`.
    #[must_use]
    pub fn outcome(&self) -> &str {
        match self.0.get("outcome") {
            Some(Value::Text(t)) => t,
            _ => "",
        }
    }

    /// A restriction rule set's `DENY` (Access L0-EVAL-18, L0-EVAL-40): one `restricted`
    /// blocker at `domain-policy` for the restriction owner, not satisfiable by the actor, whose
    /// subcode names the rule set's 16-byte reference when it has one.
    #[must_use]
    pub fn restricted(reference: Option<&[u8; 16]>) -> Self {
        let mut blocker = Vec::with_capacity(5);
        blocker.push(entry("class", Value::text("restricted")));
        if let Some(r) = reference {
            let mut subcode = String::from(RESTRICTED_POLICY);
            subcode.push_str(&b64url(r));
            blocker.push(entry("subcode", Value::Text(subcode)));
        }
        blocker.push(entry("position", Value::text("domain-policy")));
        blocker.push(entry("resolver", Value::text("restriction-owner")));
        blocker.push(entry(
            "remediation",
            Value::text("not-satisfiable-by-actor"),
        ));
        Self(canonical(Value::Map(Vec::from([
            entry("outcome", Value::text("deny")),
            entry("blockers", Value::Array(Vec::from([Value::Map(blocker)]))),
        ]))))
    }

    /// A restriction rule set's `REQUIRE` (Access L0-EVAL-18): each requirement term unmet at
    /// `domain-policy` with nothing presented, so `missing` is its `count` (one by default); a
    /// rule set evaluated alone names no actor kind, so every term is satisfiable by the actor.
    ///
    /// # Errors
    /// [`ExplanationError`] for no terms or a term that does not fit.
    pub fn required<'a>(
        terms: impl IntoIterator<Item = &'a Value>,
    ) -> Result<Self, ExplanationError> {
        let mut unmet = Vec::new();
        for term in terms {
            check_term(term)?;
            let missing = match term.get("count") {
                Some(Value::Unsigned(n)) => *n,
                _ => 1,
            };
            unmet.push(Value::Map(Vec::from([
                entry("term", term.clone()),
                entry("missing", Value::Unsigned(missing)),
                entry("position", Value::text("domain-policy")),
                entry("satisfiable_by_actor", Value::Bool(true)),
            ])));
        }
        if unmet.is_empty() {
            return Err(ExplanationError("unmet"));
        }
        Ok(Self(canonical(Value::Map(Vec::from([
            entry("outcome", Value::text("require_action")),
            entry("unmet", Value::Array(sorted(unmet)?)),
        ])))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PR-11 PR-17
    #[test]
    fn pr_11_pr_17_a_rule_set_deny_is_a_restricted_blocker_at_domain_policy() {
        let named = Explanation::restricted(Some(&[0x33; 16]));
        assert_eq!(named.outcome(), "deny");
        let again = Explanation::from_value(named.value().clone()).unwrap();
        assert_eq!(again, named);
        let blocker = match named.value().get("blockers") {
            Some(Value::Array(b)) => b.first().cloned().unwrap(),
            _ => Value::Bool(false),
        };
        assert_eq!(
            blocker.get("subcode"),
            Some(&Value::text("restricted/policy:MzMzMzMzMzMzMzMzMzMzMw"))
        );
        assert_eq!(blocker.get("position"), Some(&Value::text("domain-policy")));
        assert_eq!(
            blocker.get("resolver"),
            Some(&Value::text("restriction-owner"))
        );
        let anonymous = Explanation::restricted(None);
        assert!(Explanation::from_value(anonymous.value().clone()).is_ok());
        assert_ne!(anonymous.encode().unwrap(), named.encode().unwrap());
    }

    // PR-11 PR-17
    #[test]
    fn pr_11_pr_17_a_rule_set_require_is_one_unmet_term_per_requirement_in_canonical_order() {
        let term = |class: &str| {
            Value::Map(Vec::from([
                entry("proof_kind", Value::text("claim")),
                entry("class", Value::text(class)),
            ]))
        };
        let pair = Value::Map(Vec::from([
            entry("proof_kind", Value::text("contribution")),
            entry("class", Value::text("four_eyes")),
            entry("count", Value::Unsigned(2)),
        ]));
        let (zeta, alpha) = (term("zeta"), term("alpha"));
        let made = Explanation::required([&zeta, &pair, &alpha, &zeta]).unwrap();
        assert_eq!(made.outcome(), "require_action");
        let Some(Value::Array(unmet)) = made.value().get("unmet") else {
            panic!("no unmet");
        };
        assert_eq!(unmet.len(), 3);
        assert!(
            unmet
                .iter()
                .any(|u| u.get("missing") == Some(&Value::Unsigned(2)))
        );
        assert_eq!(Explanation::decode(&made.encode().unwrap()).unwrap(), made);
        assert!(Explanation::required([]).is_err());
        assert_eq!(
            Explanation::required([&term("Not-An-Ident")]),
            Err(ExplanationError("term.class"))
        );
    }

    // PR-11
    #[test]
    fn pr_11_what_explanation_cddl_refuses_is_refused() {
        let base = |extra: (Value, Value)| {
            Value::Map(Vec::from([entry("outcome", Value::text("deny")), extra]))
        };
        for (bad, why) in [
            (
                Value::Map(Vec::from([entry("outcome", Value::text("no_objection"))])),
                "outcome",
            ),
            (
                base(entry("blockers", Value::Array(Vec::new()))),
                "blockers",
            ),
            (base(entry("reason", Value::text("x"))), "explanation"),
            (
                base(entry(
                    "relied_on",
                    Value::Array(Vec::from([Value::Bytes(Vec::from([1; 8]))])),
                )),
                "relied_on",
            ),
            (
                base(entry(
                    "relied_on",
                    Value::Array(Vec::from([
                        Value::Bytes(Vec::from([2; 16])),
                        Value::Bytes(Vec::from([1; 16])),
                    ])),
                )),
                "relied_on",
            ),
        ] {
            assert_eq!(Explanation::from_value(bad), Err(ExplanationError(why)));
        }
        assert!(is_ident("a_1") && !is_ident("1a") && !is_ident("") && !is_ident("a-b"));
        assert_eq!(b64url(&[0xff, 0xee]), "_-4");
    }
}
