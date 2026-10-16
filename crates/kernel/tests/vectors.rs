//! The native kernel against the shared vectors in `conformance/vectors/kernel`, which the WebAssembly binding also runs (T-5, T-37).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use core::cmp::Ordering;

use serde::Deserialize;
use work_kernel::policy_default::{
    ChangeOutcome, Direction, PolicyDefault, Stricter, SwitchBasis, SwitchOutcome,
    evaluate_security_switch,
};
use work_kernel::{API_VERSION, ApiVersion};

const API_VECTORS: &str = include_str!("../../../conformance/vectors/kernel/api-version.json");
const POLICY_VECTORS: &str =
    include_str!("../../../conformance/vectors/kernel/policy-default.json");

#[derive(Deserialize)]
struct ApiVectors {
    api_version: String,
    compare: Vec<CompareCase>,
}

#[derive(Deserialize)]
struct Version {
    major: u16,
    minor: u16,
}

#[derive(Deserialize)]
struct CompareCase {
    id: String,
    a: Version,
    b: Version,
    expected: String,
}

#[derive(Deserialize)]
struct PolicyVectors {
    change: Vec<ChangeCase>,
    switch: Vec<SwitchCase>,
}

#[derive(Deserialize)]
struct ChangeCase {
    id: String,
    direction: String,
    min: String,
    max: String,
    current: String,
    proposed: String,
    expected: String,
}

#[derive(Deserialize)]
struct SwitchCase {
    id: String,
    current: bool,
    proposed: bool,
    basis: String,
    expected: String,
}

fn version(v: &Version) -> ApiVersion {
    ApiVersion {
        major: v.major,
        minor: v.minor,
    }
}

fn direction(name: &str) -> Direction {
    match name {
        "tighten_only_higher" => Direction::TightenOnly(Stricter::Higher),
        "tighten_only_lower" => Direction::TightenOnly(Stricter::Lower),
        "extend_only" => Direction::ExtendOnly,
        "bounded" => Direction::Bounded,
        other => panic!("unknown direction {other}"),
    }
}

fn change_name(outcome: ChangeOutcome) -> &'static str {
    match outcome {
        ChangeOutcome::Allowed => "allowed",
        ChangeOutcome::OutOfBounds => "out_of_bounds",
        ChangeOutcome::Loosens => "loosens",
        ChangeOutcome::Shortens => "shortens",
    }
}

fn switch_name(outcome: SwitchOutcome) -> &'static str {
    match outcome {
        SwitchOutcome::Allowed => "allowed",
        SwitchOutcome::RequiresRecordedDeclaration => "requires_recorded_declaration",
    }
}

// T-5 T-37
#[test]
fn t_5_t_37_native_api_version_matches_shared_vectors() {
    let vectors: ApiVectors = serde_json::from_str(API_VECTORS).unwrap();
    let actual = format!("{}.{}", API_VERSION.major, API_VERSION.minor);
    assert_eq!(actual, vectors.api_version);
    for case in &vectors.compare {
        let actual = match version(&case.a).cmp(&version(&case.b)) {
            Ordering::Less => "less",
            Ordering::Equal => "equal",
            Ordering::Greater => "greater",
        };
        assert_eq!(actual, case.expected, "{}", case.id);
    }
}

// T-5 T-37 F-26
#[test]
fn t_5_t_37_native_policy_defaults_match_shared_vectors() {
    let vectors: PolicyVectors = serde_json::from_str(POLICY_VECTORS).unwrap();
    assert!(!vectors.change.is_empty() && !vectors.switch.is_empty());
    for case in &vectors.change {
        let policy = PolicyDefault {
            direction: direction(&case.direction),
            min: case.min.parse().unwrap(),
            max: case.max.parse().unwrap(),
        };
        let outcome = policy.evaluate(
            case.current.parse().unwrap(),
            case.proposed.parse().unwrap(),
        );
        assert_eq!(change_name(outcome), case.expected, "{}", case.id);
    }
    for case in &vectors.switch {
        let basis = match case.basis.as_str() {
            "recorded_declaration" => SwitchBasis::RecordedDeclaration,
            "unrecorded" => SwitchBasis::Unrecorded,
            other => panic!("unknown basis {other}"),
        };
        let outcome = evaluate_security_switch(case.current, case.proposed, basis);
        assert_eq!(switch_name(outcome), case.expected, "{}", case.id);
    }
}
