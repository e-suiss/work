//! The cost limits of restriction rules (PR-23): the `esuiss-restriction` defaults, which are the Access OP-104 values, narrowed in two places only: one rule set carries at most 64 policies and one transition evaluates at most 16 rule sets. Configuration can lower both and widens nothing; a rule set that does not compile is `restriction_compile_refused` with the crate's code, and an input over a limit, an evaluation error or more rule sets than the limit are `DENY` with an attention signal. A verdict explains itself in the format shared with Access (PR-11, PR-17): every `@require` reference of a rule set names its requirement terms, or the rule set is `restriction_compile_refused` with `policy-require`, as Access refuses it.

use serde::Deserialize;
use suiss_restriction::{CompileError, Denial, Engine, InputRejected, Limits, Narrow, Outcome};
use work_kernel::explanation::{Explanation, ExplanationError};
use work_proto::explanation::{Requirements, RuleOutcome, explain};

/// The most policies one rule set carries (PR-23 item 2 (a)).
pub const RULE_SET_POLICIES: usize = 64;

/// The most rule sets one transition evaluates (PR-23 item 2 (b)).
pub const TRANSITION_RULE_SETS: usize = 16;

/// The problem code of a rule set that does not compile (PR-23 item 3).
pub const COMPILE_REFUSED: &str = "restriction_compile_refused";

/// The `code_detail` of a rule set with an `@require` reference that names no requirement terms
/// (Access `policy-require`).
pub const REQUIRE_UNNAMED: &str = "policy-require";

/// Whether every `@require` reference of `engine` names terms in `requirements` (PR-11, PR-17).
#[must_use]
pub fn requirements_named(engine: &Engine, requirements: &Requirements) -> bool {
    engine.policies().is_some_and(|policies| {
        policies
            .iter()
            .all(|p| p.require.is_none_or(|r| requirements.names(r)))
    })
}

/// The `[restriction]` configuration section; both values can only be lowered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictionConfig {
    /// Policies per rule set, 1 to 64.
    #[serde(default = "rule_set_policies")]
    pub policies_per_rule_set: usize,
    /// Rule sets per transition, 1 to 16.
    #[serde(default = "transition_rule_sets")]
    pub rule_sets_per_transition: usize,
}

const fn rule_set_policies() -> usize {
    RULE_SET_POLICIES
}

const fn transition_rule_sets() -> usize {
    TRANSITION_RULE_SETS
}

impl Default for RestrictionConfig {
    fn default() -> Self {
        Self {
            policies_per_rule_set: RULE_SET_POLICIES,
            rule_sets_per_transition: TRANSITION_RULE_SETS,
        }
    }
}

/// Why a restriction configuration is refused: it would widen a limit or set it to zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    /// Policies per rule set outside 1 to 64.
    #[error("restriction.policies_per_rule_set must be 1 to 64")]
    Policies,
    /// Rule sets per transition outside 1 to 16.
    #[error("restriction.rule_sets_per_transition must be 1 to 16")]
    RuleSets,
}

/// The limits every rule set compiles and every transition evaluates under (PR-23).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RestrictionConfig")]
pub struct RestrictionLimits {
    rule_set: Limits,
    rule_sets: usize,
}

impl TryFrom<RestrictionConfig> for RestrictionLimits {
    type Error = LimitsError;

    fn try_from(config: RestrictionConfig) -> Result<Self, Self::Error> {
        if !(1..=RULE_SET_POLICIES).contains(&config.policies_per_rule_set) {
            return Err(LimitsError::Policies);
        }
        if !(1..=TRANSITION_RULE_SETS).contains(&config.rule_sets_per_transition) {
            return Err(LimitsError::RuleSets);
        }
        let rule_set = Limits::default()
            .narrowed(Narrow::Policies(config.policies_per_rule_set))
            .map_err(|_| LimitsError::Policies)?;
        Ok(Self {
            rule_set,
            rule_sets: config.rule_sets_per_transition,
        })
    }
}

impl Default for RestrictionLimits {
    fn default() -> Self {
        Self::try_from(RestrictionConfig::default()).unwrap_or(Self {
            rule_set: Limits::default(),
            rule_sets: TRANSITION_RULE_SETS,
        })
    }
}

/// A transition asks for more rule sets than the limit; it is `DENY` without evaluation
/// (PR-23 item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a transition evaluates at most {limit} rule sets, this one asks for {asked}")]
pub struct TooManyRuleSets {
    /// The limit.
    pub limit: usize,
    /// The rule sets the transition would evaluate.
    pub asked: usize,
}

/// What one rule set says about a transition (PR-17 item 3, PR-23 item 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleVerdict {
    /// No objection.
    NoObjection,
    /// Allowed once these requirement references are met.
    Require(Vec<String>),
    /// `DENY`; `attention` is set when the cause is an input over a limit, an evaluation error,
    /// an engine state or too many rule sets, which raise an attention signal.
    Deny {
        /// The matching `forbid` policies, empty when the cause is not a policy.
        policies: Vec<String>,
        /// Whether the denial raises an attention signal.
        attention: bool,
    },
}

impl RuleVerdict {
    /// The verdict of an engine answer.
    #[must_use]
    pub fn of(answer: Result<Outcome, InputRejected>) -> Self {
        match answer {
            Ok(Outcome::NoObjection) => Self::NoObjection,
            Ok(Outcome::Require(refs)) => Self::Require(refs),
            Ok(Outcome::Deny(Denial::Forbid { policies, .. })) => Self::Deny {
                policies,
                attention: false,
            },
            Ok(Outcome::Deny(Denial::EvaluationError | Denial::Internal)) | Err(InputRejected) => {
                Self::Deny {
                    policies: Vec::new(),
                    attention: true,
                }
            }
        }
    }

    /// The explanation of this verdict in the format shared with Access (PR-11, PR-17, Access
    /// E43): none for no objection, the `restricted` blocker of the rule set named by `reference`
    /// for `DENY`, and the terms its references name in `requirements` for `REQUIRE`.
    ///
    /// # Errors
    /// [`ExplanationError`] for a reference `requirements` does not name, which
    /// [`requirements_named`] refuses at adoption.
    pub fn explanation(
        &self,
        reference: Option<&[u8; 16]>,
        requirements: &Requirements,
    ) -> Result<Option<Explanation>, ExplanationError> {
        let outcome = match self {
            Self::NoObjection => RuleOutcome::NoObjection,
            Self::Require(refs) => RuleOutcome::Require(refs),
            Self::Deny { .. } => RuleOutcome::Deny,
        };
        explain(outcome, reference, requirements)
    }

    /// The verdict of a transition refused for its rule set count.
    #[must_use]
    pub const fn too_many_rule_sets() -> Self {
        Self::Deny {
            policies: Vec::new(),
            attention: true,
        }
    }
}

impl RestrictionLimits {
    /// The limits one rule set compiles under: the crate defaults with at most
    /// [`RULE_SET_POLICIES`] policies.
    #[must_use]
    pub const fn rule_set(&self) -> Limits {
        self.rule_set
    }

    /// The most rule sets one transition evaluates.
    #[must_use]
    pub const fn rule_sets_per_transition(&self) -> usize {
        self.rule_sets
    }

    /// Compiles a rule set at adoption or policy writing (PR-23 item 3).
    ///
    /// # Errors
    /// The crate's [`CompileError`]; its `code()` goes into the problem's `code_detail`.
    pub fn compile(&self, schema: &str, source: &str) -> Result<Engine, CompileError> {
        Engine::compile(schema, source, self.rule_set)
    }

    /// Checks that a transition stays within the rule set limit before anything is evaluated.
    ///
    /// # Errors
    /// [`TooManyRuleSets`], answered as [`RuleVerdict::too_many_rule_sets`].
    pub const fn admit_transition(&self, rule_sets: usize) -> Result<(), TooManyRuleSets> {
        if rule_sets > self.rule_sets {
            return Err(TooManyRuleSets {
                limit: self.rule_sets,
                asked: rule_sets,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use suiss_restriction::RequestJson;

    use super::*;

    const SCHEMA: &str = r"
entity Actor { tenant: String };
entity Resource { tenant: String };
type Ctx = { note: String };
action write appliesTo { principal: [Actor], resource: [Resource], context: Ctx };
";

    fn rule_set(policies: usize) -> String {
        let mut source = String::new();
        for i in 0..policies {
            let _ = writeln!(
                source,
                r#"@id("p{i}") forbid(principal, action, resource) when {{ principal.tenant != resource.tenant }};"#
            );
        }
        source
    }

    fn request<'a>(context: &'a str, entities: &'a str) -> RequestJson<'a> {
        RequestJson {
            principal: r#"Actor::"a1""#,
            action: r#"Action::"write""#,
            resource: r#"Resource::"r1""#,
            context,
            entities,
        }
    }

    fn entities(resource_tenant: &str) -> String {
        format!(
            r#"[{{"uid":{{"type":"Actor","id":"a1"}},"attrs":{{"tenant":"t1"}},"parents":[]}},{{"uid":{{"type":"Resource","id":"r1"}},"attrs":{{"tenant":"{resource_tenant}"}},"parents":[]}}]"#
        )
    }

    // PR-23
    #[test]
    fn pr_23_limits_are_the_access_defaults() {
        let limits = RestrictionLimits::default();
        assert_eq!(
            limits.rule_set(),
            Limits::default().narrowed(Narrow::Policies(64)).unwrap()
        );
        assert_ne!(limits.rule_set(), Limits::default());
        assert_eq!(limits.rule_sets_per_transition(), 16);
        let config: RestrictionLimits = serde_json::from_str("{}").unwrap();
        assert_eq!(config, limits);
        let narrow: RestrictionLimits =
            serde_json::from_str(r#"{"policies_per_rule_set": 8, "rule_sets_per_transition": 4}"#)
                .unwrap();
        assert_eq!(
            narrow.rule_set(),
            Limits::default().narrowed(Narrow::Policies(8)).unwrap()
        );
        for wider in [
            r#"{"policies_per_rule_set": 65}"#,
            r#"{"policies_per_rule_set": 0}"#,
            r#"{"rule_sets_per_transition": 17}"#,
            r#"{"rule_sets_per_transition": 0}"#,
            r#"{"policy_cost": 1}"#,
        ] {
            assert!(
                serde_json::from_str::<RestrictionLimits>(wider).is_err(),
                "{wider}"
            );
        }
        assert!(Limits::default().narrowed(Narrow::Policies(257)).is_err());
    }

    // PR-23
    #[test]
    fn pr_23_a_rule_set_over_64_policies_is_refused_at_adoption() {
        let limits = RestrictionLimits::default();
        assert!(limits.compile(SCHEMA, &rule_set(64)).is_ok());
        let refused = limits.compile(SCHEMA, &rule_set(65)).err().unwrap();
        assert_eq!(refused, CompileError::TooManyPolicies);
        assert_eq!(refused.code(), "policy-too-many-policies");
        assert!(Engine::compile(SCHEMA, &rule_set(65), Limits::default()).is_ok());
        assert_eq!(COMPILE_REFUSED, "restriction_compile_refused");
    }

    // PR-23 T-33
    #[test]
    fn pr_23_a_transition_over_16_rule_sets_is_deny() {
        let limits = RestrictionLimits::default();
        assert_eq!(limits.admit_transition(16), Ok(()));
        assert_eq!(
            limits.admit_transition(17),
            Err(TooManyRuleSets {
                limit: 16,
                asked: 17
            })
        );
        assert_eq!(
            RuleVerdict::too_many_rule_sets(),
            RuleVerdict::Deny {
                policies: Vec::new(),
                attention: true
            }
        );
    }

    // PR-11 PR-17
    #[test]
    fn pr_11_pr_17_a_require_reference_without_terms_is_refused_and_a_verdict_explains_itself() {
        let limits = RestrictionLimits::default();
        let source = r#"@id("p") @require("rs-a") forbid(principal, action, resource) when { principal.tenant != resource.tenant };"#;
        let engine = limits.compile(SCHEMA, source).unwrap();
        assert!(!requirements_named(&engine, &Requirements::default()));
        let named = Requirements::from_json(&serde_json::json!({
            "rs-a": [{"proof_kind": "claim", "class": "kyc"}]
        }))
        .unwrap();
        assert!(requirements_named(&engine, &named));
        let plain = limits.compile(SCHEMA, &rule_set(1)).unwrap();
        assert!(requirements_named(&plain, &Requirements::default()));
        let verdict =
            RuleVerdict::of(engine.evaluate(&request(r#"{"note":"ok"}"#, &entities("t2"))));
        assert_eq!(verdict, RuleVerdict::Require(vec!["rs-a".to_owned()]));
        let explained = verdict.explanation(None, &named).unwrap().unwrap();
        assert_eq!(explained.outcome(), "require_action");
        assert!(verdict.explanation(None, &Requirements::default()).is_err());
        assert_eq!(RuleVerdict::NoObjection.explanation(None, &named), Ok(None));
        let denied = RuleVerdict::too_many_rule_sets()
            .explanation(Some(&[1; 16]), &named)
            .unwrap()
            .unwrap();
        assert_eq!(denied, Explanation::restricted(Some(&[1; 16])));
        assert_eq!(REQUIRE_UNNAMED, "policy-require");
    }

    // PR-23 T-33
    #[test]
    fn pr_23_input_rejected_is_deny_with_an_attention_signal() {
        let engine = RestrictionLimits::default()
            .compile(SCHEMA, &rule_set(2))
            .unwrap();
        let same = entities("t1");
        let other = entities("t2");
        assert_eq!(
            RuleVerdict::of(engine.evaluate(&request(r#"{"note":"ok"}"#, &same))),
            RuleVerdict::NoObjection
        );
        assert_eq!(
            RuleVerdict::of(engine.evaluate(&request(r#"{"note":"ok"}"#, &other))),
            RuleVerdict::Deny {
                policies: vec!["p0".to_owned(), "p1".to_owned()],
                attention: false
            }
        );
        let long = format!(r#"{{"note":"{}"}}"#, "x".repeat(257));
        let rejected = engine.evaluate(&request(&long, &same));
        assert_eq!(rejected, Err(InputRejected));
        assert_eq!(
            RuleVerdict::of(rejected),
            RuleVerdict::Deny {
                policies: Vec::new(),
                attention: true
            }
        );
    }
}
