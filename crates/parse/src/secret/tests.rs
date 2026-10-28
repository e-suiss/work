use super::*;

fn scanner() -> SecretScanner {
    SecretScanner::builtin().unwrap()
}

fn name(s: &str) -> PartName {
    PartName::parse(s).unwrap()
}

fn scan_text(s: &SecretScanner, text: &str) -> ScanOutcome {
    let part = name("note");
    s.scan(&[ScanPart::new(&part, text.as_bytes())]).unwrap()
}

fn detected_rule(outcome: &ScanOutcome) -> Option<&str> {
    match outcome {
        ScanOutcome::Detected { rule_id, .. } => Some(rule_id.as_str()),
        ScanOutcome::Clean => None,
    }
}

fn fake(prefix: &str, filler: &str) -> String {
    [prefix, filler].concat()
}

const FILL36: &str = "Zq8kR2mN4vX7bT1yW9cL3pH6dF0sJ5gA2eUo";
const FILL16_BASE32: &str = "Q7M2ZR4XK6WT3NBV";
const FILL20: &str = "aB3dE5gH7jK9mN1pQ2sT";

fn true_positives() -> Vec<(&'static str, String)> {
    let pem = [
        "-----BEGIN ",
        "RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Zq8kR2mN4vX7bT1yW9cL3pH6dF0sJ5gA2eUoFAKEFAKE\n-----END RSA ",
        "PRIVATE KEY-----",
    ]
    .concat();
    let jwt = [
        "eyJhbGciOiJIUzI1NiJ9",
        ".eyJzdWIiOiJ0ZXN0LW9ubHkifQ",
        ".c2lnbmF0dXJlLWZvci10ZXN0cw",
    ]
    .concat();
    vec![
        ("github-pat", fake("ghp_", FILL36)),
        ("aws-access-token", fake("AKIA", FILL16_BASE32)),
        ("gitlab-pat", fake("glpat-", FILL20)),
        (
            "slack-bot-token",
            fake("xoxb-", "1234567890-0987654321-Zq8kR2mN4vX7bT1y"),
        ),
        (
            "stripe-access-token",
            fake("sk_test_", "Zq8kR2mN4vX7bT1yW9cL"),
        ),
        ("jwt", jwt),
        ("work-pem-private-key", pem),
        (
            "generic-api-key",
            ["api", "_key = \"q8Z3vT7mK2xW9pL4rB6n\""].concat(),
        ),
        ("work-pan", "card 4111 1111 1111 1111 on file".into()),
        ("work-pan", "5555555555554444".into()),
        ("work-pan", "amex 3782-822463-10005".into()),
    ]
}

#[test]
fn sec_35_detects_a_sample_of_rule_families() {
    let s = scanner();
    for (rule, text) in true_positives() {
        let out = scan_text(&s, &format!("Please use this: {text}\nthanks"));
        assert_eq!(detected_rule(&out), Some(rule), "{rule}");
    }
}

#[test]
fn sec_35_clean_text_and_known_examples_pass() {
    let s = scanner();
    let clean = [
        "The commitment is due on Friday; ping the reviewer before the gate closes.",
        "Order 1000000000000008 shipped at 1730000000000 to rec_0b6f2c9e.",
        "card 4111 1111 1111 1112 failed the check",
        &fake("AKIAIOSFODNN7", "EXAMPLE"),
        "password = ${DB_PASSWORD}",
        "api_key = changeme",
        "wrk_01jb2v3x4y5z6a7b8c9d0e1f2g and 0190a6b2-7c3d-7e4f-8a9b-0c1d2e3f4a5b",
        "sha256:e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf",
        "",
    ];
    for text in clean {
        assert_eq!(scan_text(&s, text), ScanOutcome::Clean, "{text}");
    }
}

#[test]
fn sec_35_account_numbers_need_a_brand_and_the_luhn_check() {
    assert!(pan::luhn(b"1000000000000008"));
    assert!(!pan::is_pan(b"1000000000000008"));
    assert!(!pan::is_pan(b"4111111111111112"));
    assert!(pan::is_pan(b"4111-1111-1111-1111"));
    assert!(pan::is_pan(b"378282246310005"));
    assert!(!pan::is_pan(b"41111111111111"));
}

#[test]
fn sec_35_gitleaks_allow_marker_is_not_honoured() {
    let s = scanner();
    let text = format!("{} // gitleaks:allow", fake("ghp_", FILL36));
    assert_eq!(detected_rule(&scan_text(&s, &text)), Some("github-pat"));
}

#[test]
fn sec_35_reports_the_first_matching_part() {
    let s = scanner();
    let (a, b, c) = (name("summary"), name("details"), name("notes"));
    let secret = fake("ghp_", FILL36);
    let parts = [
        ScanPart::new(&a, b"nothing here"),
        ScanPart::new(&b, secret.as_bytes()),
        ScanPart::new(&c, b"5555555555554444"),
    ];
    let out = s.scan(&parts).unwrap();
    assert_eq!(
        out,
        ScanOutcome::Detected {
            rule_id: RuleId("github-pat".into()),
            part: b,
        }
    );
}

#[test]
fn sec_35_binary_and_non_utf8_parts_are_scanned() {
    let s = scanner();
    let part = name("attachment");
    let mut content = vec![0xff, 0xfe, 0x00, b'\n'];
    content.extend_from_slice(fake("ghp_", FILL36).as_bytes());
    content.extend_from_slice(&[0x00, 0xc3]);
    let out = s.scan(&[ScanPart::new(&part, &content)]).unwrap();
    assert_eq!(detected_rule(&out), Some("github-pat"));
}

#[test]
fn p_95_detection_rejects_on_the_api_path_and_quarantines_otherwise() {
    let s = scanner();
    let out = scan_text(&s, &fake("ghp_", FILL36));
    assert_eq!(out.reason_code(), Some("secret_detected"));
    assert_eq!(out.disposition(Ingress::Api), Disposition::Reject);
    assert_eq!(
        out.disposition(Ingress::Federation),
        Disposition::Quarantine
    );
    assert_eq!(
        out.disposition(Ingress::OfflineSigned),
        Disposition::Quarantine
    );
    assert_eq!(Disposition::Quarantine.ingest_state(), "quarantined");
    assert_eq!(Disposition::Reject.ingest_state(), "rejected");

    let clean = scan_text(&s, "fine");
    assert_eq!(clean.reason_code(), None);
    for ingress in [Ingress::Api, Ingress::Federation, Ingress::OfflineSigned] {
        assert_eq!(clean.disposition(ingress), Disposition::Admit);
    }
    assert_eq!(Disposition::Admit.ingest_state(), "admitted");
}

#[test]
fn p_95_the_outcome_carries_only_the_rule_id_and_the_part_name() {
    let s = scanner();
    for (_, text) in true_positives() {
        let out = scan_text(&s, &text);
        let shown = [format!("{out}"), format!("{out:?}")];
        for view in shown {
            assert!(view.contains("secret_detected") || view.contains("Detected"));
            assert!(view.contains("note"));
            assert!(!view.contains(&text), "{view}");
            for token in text.split_whitespace().filter(|t| t.len() >= 8) {
                assert!(!view.contains(token), "{view}");
            }
        }
    }
}

#[test]
fn sec_13_scanned_content_is_redacted_in_debug_output() {
    let part = name("note");
    let secret = fake("ghp_", FILL36);
    let p = ScanPart::new(&part, secret.as_bytes());
    let shown = format!("{p:?}");
    assert!(!shown.contains(&secret));
    assert!(!shown.contains(FILL36));
    assert!(shown.contains("<redacted>"));
    assert!(shown.contains("note"));
    assert_eq!(p.len(), secret.len());

    let s = scanner();
    let big = vec![b'x'; 300 * 1024];
    let err = s.scan(&[ScanPart::new(&part, &big)]).unwrap_err();
    assert!(!format!("{err} {err:?}").contains("xxxxxxxx"));
    assert!(!format!("{s:?}").contains("ghp_"));
}

#[test]
fn sec_35_parts_over_the_limits_are_refused_before_scanning() {
    let s = SecretScanner::with_limits(ScanLimits::new(64, 100)).unwrap();
    let (a, b) = (name("a"), name("b"));
    let at_limit = vec![b'x'; 64];
    let over = vec![b'x'; 65];
    assert_eq!(
        s.scan(&[ScanPart::new(&a, &at_limit)]).unwrap(),
        ScanOutcome::Clean
    );
    assert_eq!(
        s.scan(&[ScanPart::new(&a, &over)]).unwrap_err(),
        ScanError::PartTooLarge {
            part: a.clone(),
            size: 65,
            limit: 64
        }
    );
    let secret = fake("ghp_", FILL36);
    let mut tail = vec![b'x'; 60];
    tail.extend_from_slice(secret.as_bytes());
    assert!(matches!(
        s.scan(&[ScanPart::new(&a, &tail)]),
        Err(ScanError::PartTooLarge { .. })
    ));
    assert_eq!(
        s.scan(&[ScanPart::new(&a, &at_limit), ScanPart::new(&b, &at_limit)])
            .unwrap_err(),
        ScanError::TotalTooLarge { limit: 100 }
    );
    assert_eq!(ScanLimits::default().max_part_bytes(), 256 * 1024);
    assert_eq!(ScanLimits::default().max_total_bytes(), 256 * 1024);
}

#[test]
fn sec_35_a_large_part_scans_within_the_default_limit() {
    let s = scanner();
    let part = name("note");
    let mut text = "token key secret password api auth access ".repeat(6000);
    text.truncate(ScanLimits::DEFAULT.max_part_bytes());
    assert_eq!(
        s.scan(&[ScanPart::new(&part, text.as_bytes())]).unwrap(),
        ScanOutcome::Clean
    );
}

#[test]
fn sec_35_rule_counts_are_pinned() {
    let r = scanner().report().clone();
    assert_eq!(r.gitleaks_rules, 222);
    assert_eq!(r.gitleaks_active, 217);
    assert_eq!(r.work_rules, 2);
    assert_eq!(r.converted_regexes, 4);
    assert_eq!(r.skipped.len(), 5);
    assert_eq!(r.skipped_for(SkipReason::PathScoped), 4);
    assert_eq!(r.skipped_for(SkipReason::PathOnly), 1);
    assert_eq!(r.skipped_for(SkipReason::UnsupportedSyntax), 0);
    assert_eq!(r.skipped_for(SkipReason::SizeLimit), 0);
    let ids: Vec<&str> = r.skipped.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "freemius-secret-key",
            "hashicorp-tf-password",
            "kubernetes-secret-yaml",
            "nuget-config-password",
            "pkcs12-file",
        ]
    );
}

#[test]
fn sec_35_rule_set_digest_is_stable() {
    let a = scanner().rule_set();
    let b = scanner().rule_set();
    assert_eq!(a, b);
    assert!(!a.requires_rescan(&b));
    assert_eq!(a.gitleaks_version(), "8.30.1");
    assert_eq!(
        a.to_string(),
        "gitleaks-8.30.1+sha256:0d44e2ff47cb452f920d42f4bc8d1b575e361b4dc605dcebf8379dc79d04aacb"
    );
}

#[test]
fn sec_35_a_rule_change_changes_the_digest() {
    let base = rules::load(GITLEAKS_CONFIG, WORK_RULES, ENGINE_REVISION).unwrap();
    let extra = format!(
        "{WORK_RULES}\n[[rules]]\nid = \"work-extra\"\ndescription = \"x\"\nregex = '''zz[0-9]{{40}}'''\n"
    );
    let changed = rules::load(GITLEAKS_CONFIG, &extra, ENGINE_REVISION).unwrap();
    let engine = rules::load(GITLEAKS_CONFIG, WORK_RULES, ENGINE_REVISION + 1).unwrap();
    let id = |d| RuleSetId { digest: d };
    assert!(id(changed.digest).requires_rescan(&id(base.digest)));
    assert!(id(engine.digest).requires_rescan(&id(base.digest)));
}

#[test]
fn sec_35_vendored_rule_file_is_checked_against_its_recorded_digest() {
    let tampered = GITLEAKS_CONFIG.replacen("ghp_", "ghx_", 1);
    assert!(matches!(
        rules::load(&tampered, WORK_RULES, ENGINE_REVISION),
        Err(BuildError::VendoredDigest { .. })
    ));
}

#[test]
fn sec_35_work_rule_ids_may_not_shadow_gitleaks_rules() {
    let dup = format!(
        "{WORK_RULES}\n[[rules]]\nid = \"github-pat\"\ndescription = \"x\"\nregex = '''zz'''\n"
    );
    assert_eq!(
        rules::load(GITLEAKS_CONFIG, &dup, ENGINE_REVISION).err(),
        Some(BuildError::DuplicateRule("github-pat".into()))
    );
    let typo = format!("{WORK_RULES}\n[[rules]]\nid = \"w\"\ndescription = \"x\"\nregx = 'a'\n");
    assert!(matches!(
        rules::load(GITLEAKS_CONFIG, &typo, ENGINE_REVISION),
        Err(BuildError::RuleFile { .. })
    ));
}

#[test]
fn sec_35_go_regex_syntax_is_converted() {
    assert_eq!(rules::from_go(r"^\$(?:\d+|{\d+})$"), r"^\$(?:\d+|\{\d+})$");
    assert_eq!(rules::from_go(r"^\{\{[ \t]*}}$"), r"^\{\{[ \t]*}}$");
    assert_eq!(rules::from_go(r"a{2}b{2,}c{2,5}"), r"a{2}b{2,}c{2,5}");
    assert_eq!(rules::from_go(r"[{}]{1,2}"), r"[{}]{1,2}");
    assert_eq!(rules::from_go(r"[[:alnum:]{]x{,3}"), r"[[:alnum:]{]x\{,3}");
    assert_eq!(rules::from_go(r"[]{]"), r"[]{]");
    assert_eq!(rules::from_go(r"[[a]"), r"[\[a]");
    assert_eq!(rules::from_go(r"[a&&b~~c]"), r"[a\&&b\~~c]");
    for go in [r"[[a]", r"[a&&b~~c]"] {
        assert!(
            regex::bytes::Regex::new(&rules::from_go(go)).is_ok(),
            "{go}"
        );
    }
}

#[test]
fn sec_35_entropy_matches_gitleaks() {
    assert!(rules::shannon_entropy(b"").abs() < f64::EPSILON);
    assert!(rules::shannon_entropy(b"aaaa").abs() < f64::EPSILON);
    assert!((rules::shannon_entropy(b"ab") - 1.0).abs() < 1e-12);
    assert!((rules::shannon_entropy(b"abcd") - 2.0).abs() < 1e-12);
}
