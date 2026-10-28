//! The local OpenTelemetry Collector redacts with the same pattern set as the in-process secret
//! scanner and the same field names as the content guard (SEC-35 rule 4, OP-19, P-43, T-57).
//! `WORK_BLESS=1` rewrites the generated block of the collector configuration.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::fmt::Write as _;

use regex::Regex;
use serde::Deserialize;
use work_telemetry::{CONTENT_PAIRS, CONTENT_WORDS, GENAI_PREFIX, forbidden_field};

const COLLECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/compose/observability/otel-collector.yaml"
);
const GITLEAKS: &str = include_str!("../../parse/vendor/gitleaks-8.30.1/gitleaks.toml");
const WORK_RULES: &str = include_str!("../../parse/rules/work-secrets.toml");
const START: &str = "  redaction:\n";
const END: &str = "\nexporters:\n";

#[derive(Deserialize)]
struct Rules {
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
struct Rule {
    regex: Option<String>,
}

fn quoted(pattern: &str) -> String {
    format!("'{}'", pattern.replace('\'', "''"))
}

fn key_patterns() -> Vec<String> {
    let sep = "[._-]";
    let words = CONTENT_WORDS.join("|");
    let pairs: Vec<String> = CONTENT_PAIRS
        .iter()
        .map(|(a, b)| format!("{a}{sep}+{b}"))
        .collect();
    vec![
        format!("(?i)(?:^|{sep})(?:{words})(?:$|{sep})"),
        format!("(?i)(?:^|{sep})(?:{})(?:$|{sep})", pairs.join("|")),
        format!("(?i)^{GENAI_PREFIX}(?:$|{sep})"),
    ]
}

fn value_patterns() -> Vec<String> {
    [GITLEAKS, WORK_RULES]
        .iter()
        .flat_map(|file| toml::from_str::<Rules>(file).unwrap().rules)
        .filter_map(|r| r.regex)
        .collect()
}

fn block() -> String {
    let mut out = String::from(START);
    out.push_str("    allow_all_keys: true\n    summary: info\n    blocked_key_patterns:\n");
    for p in key_patterns() {
        writeln!(out, "      - {}", quoted(&p)).unwrap();
    }
    out.push_str("    blocked_values:\n");
    for p in value_patterns() {
        writeln!(out, "      - {}", quoted(&p)).unwrap();
    }
    out
}

fn generated(config: &str) -> Option<(usize, usize)> {
    let start = config.find(START)?;
    let end = start.checked_add(config[start..].find(END)?)?;
    Some((start, end))
}

// SEC-35 OP-19 T-57
#[test]
fn sec_35_collector_redacts_with_the_scanner_pattern_set() {
    let config = std::fs::read_to_string(COLLECTOR).unwrap();
    let (start, end) = generated(&config).expect("redaction processor right before `exporters:`");
    let expected = block();
    if std::env::var("WORK_BLESS").is_ok_and(|v| v == "1") {
        let mut blessed = config.clone();
        blessed.replace_range(start..end, &expected);
        std::fs::write(COLLECTOR, blessed).unwrap();
        return;
    }
    assert!(
        config[start..end] == expected,
        "collector redaction drifted from the scanner rules; run `WORK_BLESS=1 cargo test -p work-telemetry --test collector_redaction`"
    );
    for pipeline in ["traces", "metrics", "logs"] {
        let at = config.find(&format!("    {pipeline}:\n")).unwrap();
        let processors = config[at..]
            .lines()
            .find(|l| l.contains("processors:"))
            .unwrap();
        assert!(
            processors.contains("[redaction, batch]"),
            "{pipeline}: {processors}"
        );
    }
}

// OP-19 P-43
#[test]
fn op_19_collector_key_patterns_agree_with_the_content_guard() {
    let patterns: Vec<Regex> = key_patterns()
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect();
    let mut names: Vec<String> = Vec::new();
    for w in CONTENT_WORDS {
        for n in [
            (*w).to_owned(),
            format!("record.{w}"),
            format!("{w}_hash"),
            format!("x-{w}-y"),
            format!("{w}s"),
            format!("pre{w}"),
            w.to_ascii_uppercase(),
        ] {
            names.push(n);
        }
    }
    for (a, b) in CONTENT_PAIRS {
        names.extend([
            format!("{a}_{b}"),
            format!("x.{a}-{b}.y"),
            format!("{a}__{b}"),
            format!("{a}{b}x"),
        ]);
    }
    names.extend(
        [
            "gen_ai",
            "gen_ai.request.model",
            "GEN_AI-system",
            "gen_aix",
            "x.gen_ai",
            "record",
            "record_id",
            "correlation",
            "trace_id",
            "idempotency_key",
            "tokenizer_width",
            "panel",
            "key",
            "api",
        ]
        .map(str::to_owned),
    );
    for name in names {
        let redacted = patterns.iter().any(|p| p.is_match(&name));
        assert_eq!(
            redacted,
            forbidden_field(&name).is_some(),
            "{name}: collector and guard disagree"
        );
    }
}
