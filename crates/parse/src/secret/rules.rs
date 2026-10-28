//! Loading the gitleaks and Work rule files and the gitleaks matching semantics: keyword prefilter, secret group, Shannon entropy threshold and allowlists targeting the secret, the match or the line; path and commit conditions never hold for a body part, and the `gitleaks:allow` marker is not honoured.

use std::collections::{BTreeMap, BTreeSet};

use aho_corasick::{AhoCorasick, MatchKind};
use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::pan;
use super::{
    BuildError, BuildReport, DFA_SIZE_LIMIT, GITLEAKS_CONFIG_SHA256, REGEX_SIZE_LIMIT, RuleId,
    SkipReason, SkippedRule,
};

#[derive(Deserialize)]
struct GitleaksFile {
    #[serde(default)]
    allowlist: Option<RawAllowlist>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
    #[serde(default)]
    rules: Vec<GitleaksRule>,
}

#[derive(Deserialize)]
struct GitleaksRule {
    id: String,
    #[serde(default)]
    regex: Option<String>,
    #[serde(default, rename = "secretGroup")]
    secret_group: Option<usize>,
    #[serde(default)]
    entropy: Option<f64>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
}

#[derive(Deserialize)]
struct RawAllowlist {
    #[serde(default)]
    condition: Option<String>,
    #[serde(default, rename = "regexTarget")]
    regex_target: Option<String>,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    commits: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkFile {
    rules: Vec<WorkRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkRule {
    id: String,
    #[serde(rename = "description")]
    _description: String,
    regex: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    entropy: Option<f64>,
    #[serde(default)]
    validate: Option<Validator>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Validator {
    Pan,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Secret,
    Match,
    Line,
}

pub(super) struct Allowlist {
    target: Target,
    and: bool,
    regexes: Vec<Regex>,
    stopwords: Vec<String>,
    unmatchable: bool,
}

pub(super) struct Rule {
    pub(super) id: RuleId,
    regex: Regex,
    secret_group: usize,
    entropy: Option<f64>,
    keywords: Vec<usize>,
    allowlists: Vec<Allowlist>,
    validator: Option<Validator>,
}

pub(super) struct RuleSet {
    pub(super) rules: Vec<Rule>,
    pub(super) global: Vec<Allowlist>,
    pub(super) keywords: AhoCorasick,
    pub(super) keyword_count: usize,
    pub(super) digest: [u8; 32],
    pub(super) report: BuildReport,
}

/// Rewrites Go RE2 syntax the `regex` crate reads differently: a `{` that does not open a counted repetition, and `[`, `&&` and `~~` inside a class, are literals in RE2 and are escaped.
pub(super) fn from_go(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut class = false;
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        let next = i.saturating_add(1);
        match c {
            '\\' => {
                out.push(c);
                if let Some(&e) = chars.get(next) {
                    out.push(e);
                }
                i = i.saturating_add(2);
                continue;
            }
            '[' if !class => {
                class = true;
                out.push(c);
                let mut j = next;
                if chars.get(j) == Some(&'^') {
                    out.push('^');
                    j = j.saturating_add(1);
                }
                if chars.get(j) == Some(&']') {
                    out.push(']');
                    j = j.saturating_add(1);
                }
                i = j;
                continue;
            }
            '[' if chars.get(next) == Some(&':') => {
                let rest: String = chars.get(i..).unwrap_or_default().iter().collect();
                if let Some(end) = rest.find(":]") {
                    let named = rest.get(..end.saturating_add(2)).unwrap_or_default();
                    out.push_str(named);
                    i = i.saturating_add(named.chars().count());
                    continue;
                }
                out.push(c);
            }
            '[' if class => out.push_str("\\["),
            '&' | '~' if class && chars.get(next) == Some(&c) => {
                out.push('\\');
                out.push(c);
            }
            ']' if class => {
                class = false;
                out.push(c);
            }
            '{' if !class && !counted(chars.get(next..).unwrap_or_default()) => out.push_str("\\{"),
            _ => out.push(c),
        }
        i = next;
    }
    out
}

fn counted(rest: &[char]) -> bool {
    let digits = |s: &[char]| s.iter().take_while(|c| c.is_ascii_digit()).count();
    let n = digits(rest);
    if n == 0 {
        return false;
    }
    let after = rest.get(n..).unwrap_or_default();
    match after.first() {
        Some('}') => true,
        Some(',') => {
            let tail = after.get(1..).unwrap_or_default();
            let m = digits(tail);
            tail.get(m) == Some(&'}')
        }
        _ => false,
    }
}

fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(&from_go(pattern))
        .unicode(false)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
}

fn skip_reason(e: &regex::Error) -> SkipReason {
    match e {
        regex::Error::CompiledTooBig(_) => SkipReason::SizeLimit,
        _ => SkipReason::UnsupportedSyntax,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl Allowlist {
    fn compile(raw: &RawAllowlist) -> Result<Self, regex::Error> {
        let target = match raw.regex_target.as_deref() {
            Some("match") => Target::Match,
            Some("line") => Target::Line,
            _ => Target::Secret,
        };
        let and = raw
            .condition
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case("and"));
        let regexes = raw
            .regexes
            .iter()
            .map(|r| compile(r))
            .collect::<Result<_, _>>()?;
        let stopwords = raw.stopwords.iter().map(|s| s.to_lowercase()).collect();
        Ok(Self {
            target,
            and,
            regexes,
            stopwords,
            unmatchable: !raw.paths.is_empty() || !raw.commits.is_empty(),
        })
    }

    fn allows(&self, secret: &[u8], matched: &[u8], line: &[u8]) -> bool {
        let target = match self.target {
            Target::Secret => secret,
            Target::Match => matched,
            Target::Line => line,
        };
        let regex_ok = !target.is_empty() && self.regexes.iter().any(|r| r.is_match(target));
        let stop_ok = !secret.is_empty() && {
            let lower = secret.to_ascii_lowercase();
            self.stopwords
                .iter()
                .any(|w| contains_bytes(&lower, w.as_bytes()))
        };
        if self.and {
            !self.unmatchable
                && (!self.regexes.is_empty() || !self.stopwords.is_empty())
                && (self.regexes.is_empty() || regex_ok)
                && (self.stopwords.is_empty() || stop_ok)
        } else {
            regex_ok || stop_ok
        }
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

fn trim_newlines(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| *b != b'\n')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| *b != b'\n')
        .map_or(start, |p| p.saturating_add(1));
    bytes.get(start..end).unwrap_or_default()
}

fn line_of(content: &[u8], start: usize, end: usize) -> &[u8] {
    let head = content.get(..start).unwrap_or_default();
    let line_start = head
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |p| p.saturating_add(1));
    let tail = content.get(end..).unwrap_or_default();
    let line_end = tail
        .iter()
        .position(|b| *b == b'\n')
        .map_or(content.len(), |p| end.saturating_add(p));
    content.get(line_start..line_end).unwrap_or_default()
}

/// Shannon entropy in bits per byte, as gitleaks computes it for ASCII secrets.
pub(super) fn shannon_entropy(data: &[u8]) -> f64 {
    let Ok(len) = u32::try_from(data.len()) else {
        return f64::MAX;
    };
    if len == 0 {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        if let Some(c) = counts.get_mut(usize::from(*b)) {
            *c = c.saturating_add(1);
        }
    }
    let inv = 1.0 / f64::from(len);
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) * inv;
            -p * p.log2()
        })
        .sum()
}

impl Rule {
    pub(super) fn wanted(&self, present: &[bool]) -> bool {
        self.keywords.is_empty()
            || self
                .keywords
                .iter()
                .any(|k| present.get(*k).copied().unwrap_or(false))
    }

    pub(super) fn detects(&self, content: &[u8], global: &[Allowlist]) -> bool {
        self.regex.captures_iter(content).any(|caps| {
            let Some(whole) = caps.get(0) else {
                return false;
            };
            let matched = trim_newlines(whole.as_bytes());
            let secret = if self.secret_group > 0 {
                caps.get(self.secret_group)
                    .map_or(&[][..], |m| m.as_bytes())
            } else {
                caps.iter()
                    .skip(1)
                    .flatten()
                    .map(|m| m.as_bytes())
                    .find(|s| !s.is_empty())
                    .unwrap_or(matched)
            };
            if self
                .entropy
                .is_some_and(|e| e != 0.0 && shannon_entropy(secret) <= e)
            {
                return false;
            }
            if self.validator == Some(Validator::Pan) && !pan::is_pan(secret) {
                return false;
            }
            let line = line_of(content, whole.start(), whole.end());
            !global
                .iter()
                .chain(&self.allowlists)
                .any(|a| a.allows(secret, matched, line))
        })
    }
}

struct Builder {
    keywords: BTreeMap<String, usize>,
    rules: Vec<Rule>,
    ids: BTreeSet<String>,
}

impl Builder {
    fn keyword_ids(&mut self, words: &[String]) -> Vec<usize> {
        words
            .iter()
            .map(|w| {
                let next = self.keywords.len();
                *self.keywords.entry(w.to_lowercase()).or_insert(next)
            })
            .collect()
    }

    fn push(&mut self, rule: Rule) -> Result<(), BuildError> {
        if !self.ids.insert(rule.id.as_str().to_owned()) {
            return Err(BuildError::DuplicateRule(rule.id.as_str().to_owned()));
        }
        self.rules.push(rule);
        Ok(())
    }
}

fn gitleaks_rule(raw: &GitleaksRule) -> Result<(Regex, Vec<Allowlist>), SkipReason> {
    let Some(pattern) = raw.regex.as_deref() else {
        return Err(SkipReason::PathOnly);
    };
    if raw.path.is_some() {
        return Err(SkipReason::PathScoped);
    }
    let regex = compile(pattern).map_err(|e| skip_reason(&e))?;
    let allowlists = raw
        .allowlists
        .iter()
        .map(Allowlist::compile)
        .collect::<Result<_, _>>()
        .map_err(|e| skip_reason(&e))?;
    Ok((regex, allowlists))
}

fn rule_set_digest(gitleaks: &str, work: &str, engine: u32, rules: &[Rule]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"work-secret-scan\0");
    h.update(engine.to_be_bytes());
    for part in [gitleaks.as_bytes(), work.as_bytes()] {
        h.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        h.update(part);
    }
    for rule in rules {
        h.update(rule.id.as_str().as_bytes());
        h.update([0]);
    }
    h.finalize().into()
}

fn converted(gl: &GitleaksFile) -> usize {
    gl.rules
        .iter()
        .flat_map(|r| {
            r.regex
                .iter()
                .chain(r.allowlists.iter().flat_map(|a| &a.regexes))
        })
        .chain(
            gl.allowlist
                .iter()
                .chain(&gl.allowlists)
                .flat_map(|a| &a.regexes),
        )
        .filter(|p| from_go(p) != **p)
        .count()
}

pub(super) fn load(gitleaks: &str, work: &str, engine: u32) -> Result<RuleSet, BuildError> {
    let actual = hex(&Sha256::digest(gitleaks.as_bytes()));
    if actual != GITLEAKS_CONFIG_SHA256 {
        return Err(BuildError::VendoredDigest { actual });
    }
    let gl: GitleaksFile = toml::from_str(gitleaks).map_err(|e| BuildError::RuleFile {
        source_name: "gitleaks",
        message: e.message().to_owned(),
    })?;
    let wk: WorkFile = toml::from_str(work).map_err(|e| BuildError::RuleFile {
        source_name: "work",
        message: e.message().to_owned(),
    })?;

    let mut b = Builder {
        keywords: BTreeMap::new(),
        rules: Vec::new(),
        ids: BTreeSet::new(),
    };
    for raw in &wk.rules {
        let regex = compile(&raw.regex).map_err(|e| BuildError::WorkRule {
            id: raw.id.clone(),
            message: e.to_string(),
        })?;
        let keywords = b.keyword_ids(&raw.keywords);
        b.push(Rule {
            id: RuleId(raw.id.as_str().into()),
            regex,
            secret_group: 0,
            entropy: raw.entropy,
            keywords,
            allowlists: Vec::new(),
            validator: raw.validate,
        })?;
    }
    let mut skipped = Vec::new();
    for raw in &gl.rules {
        match gitleaks_rule(raw) {
            Ok((regex, allowlists)) => {
                let keywords = b.keyword_ids(&raw.keywords);
                b.push(Rule {
                    id: RuleId(raw.id.as_str().into()),
                    regex,
                    secret_group: raw.secret_group.unwrap_or(0),
                    entropy: raw.entropy,
                    keywords,
                    allowlists,
                    validator: None,
                })?;
            }
            Err(reason) => skipped.push(SkippedRule {
                id: RuleId(raw.id.as_str().into()),
                reason,
            }),
        }
    }
    let global = gl
        .allowlist
        .iter()
        .chain(&gl.allowlists)
        .map(Allowlist::compile)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| BuildError::GlobalAllowlist(e.to_string()))?;

    let mut words: Vec<(usize, &str)> = b.keywords.iter().map(|(w, i)| (*i, w.as_str())).collect();
    words.sort_unstable();
    let keyword_count = words.len();
    let keywords = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::Standard)
        .build(words.iter().map(|(_, w)| *w))
        .map_err(|e| BuildError::Keywords(e.to_string()))?;

    let digest = rule_set_digest(gitleaks, work, engine, &b.rules);

    let converted_regexes = converted(&gl);
    let work_rules = wk.rules.len();
    let report = BuildReport {
        gitleaks_rules: gl.rules.len(),
        gitleaks_active: b.rules.len().saturating_sub(work_rules),
        work_rules,
        converted_regexes,
        skipped,
    };
    Ok(RuleSet {
        rules: b.rules,
        global,
        keywords,
        keyword_count,
        digest,
        report,
    })
}
