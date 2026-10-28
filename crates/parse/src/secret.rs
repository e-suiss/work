//! In-process secret scanning of decoded body parts in the parser worker (SEC-35, P-95, SEC-13, SEC-24): the vendored gitleaks default rule data at a pinned release plus Work's own patterns, compiled with the `regex` crate under size limits, scanned under per-part and per-record byte limits; the outcome carries only the rule id and the part name, never the matched value.

mod pan;
mod rules;

use std::fmt;

use aho_corasick::AhoCorasick;
use work_kernel::record::PartName;

use rules::{Rule, RuleSet};

/// The gitleaks release whose default rule file is vendored (SEC-35 rule 1, T-60).
pub const GITLEAKS_VERSION: &str = "8.30.1";

/// SHA-256 of the vendored `config/gitleaks.toml` of [`GITLEAKS_VERSION`], checked when a scanner is built (T-60).
pub const GITLEAKS_CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";

/// The reason code of a detection; it has no detail (P-95 rule 1, P-93 rule 2).
pub const REASON_CODE: &str = "secret_detected";

/// Compiled program size limit for one rule regex, in bytes (SEC-18).
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Lazy DFA cache limit for one rule regex, in bytes (SEC-18).
pub const DFA_SIZE_LIMIT: usize = 1 << 18;

/// Revision of the matching semantics; part of the rule set digest so an engine change triggers a rescan (SEC-35 rule 3).
const ENGINE_REVISION: u32 = 1;

const GITLEAKS_CONFIG: &str = include_str!("../vendor/gitleaks-8.30.1/gitleaks.toml");

const WORK_RULES: &str = include_str!("../rules/work-secrets.toml");

/// The identifier of a rule: a gitleaks rule id or a `work-` rule id.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(Box<str>);

impl RuleId {
    /// The rule id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a record came from; it decides between rejection and quarantine (P-95 rule 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ingress {
    /// An unsigned or online record through the API.
    Api,
    /// A record from a federation peer.
    Federation,
    /// A record signed offline.
    OfflineSigned,
}

/// What the ingest path does with a record after the scan (P-95 rule 2, P-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// No secret was found.
    Admit,
    /// The record is rejected and never enters the log.
    Reject,
    /// The record is admitted without effect as `["quarantined", "secret_detected"]`.
    Quarantine,
}

impl Disposition {
    /// The envelope `ingest` state name (P-11, FD-19).
    #[must_use]
    pub const fn ingest_state(self) -> &'static str {
        match self {
            Self::Admit => "admitted",
            Self::Reject => "rejected",
            Self::Quarantine => "quarantined",
        }
    }
}

/// The result of a scan; it never holds the matched value (P-95 rule 1).
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum ScanOutcome {
    /// No rule matched.
    Clean,
    /// A rule matched in a part.
    Detected {
        /// The matching rule, for the RFC 9457 extension field.
        rule_id: RuleId,
        /// The part that matched, for the RFC 9457 extension field.
        part: PartName,
    },
}

impl ScanOutcome {
    /// `secret_detected` for a detection.
    #[must_use]
    pub const fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::Clean => None,
            Self::Detected { .. } => Some(REASON_CODE),
        }
    }

    /// Rejection on the API path, quarantine for federated and offline-signed records (P-95 rule 2).
    #[must_use]
    pub const fn disposition(&self, ingress: Ingress) -> Disposition {
        match (self, ingress) {
            (Self::Clean, _) => Disposition::Admit,
            (Self::Detected { .. }, Ingress::Api) => Disposition::Reject,
            (Self::Detected { .. }, Ingress::Federation | Ingress::OfflineSigned) => {
                Disposition::Quarantine
            }
        }
    }
}

impl fmt::Display for ScanOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => f.write_str("clean"),
            Self::Detected { rule_id, part } => {
                write!(f, "{REASON_CODE} (rule {rule_id}, part {})", part.as_str())
            }
        }
    }
}

/// One decoded plain-text body part or field to scan; `Debug` shows only the name and the length.
#[derive(Clone, Copy)]
pub struct ScanPart<'a> {
    name: &'a PartName,
    content: &'a [u8],
}

impl<'a> ScanPart<'a> {
    /// A part with its schema name and decoded bytes.
    #[must_use]
    pub const fn new(name: &'a PartName, content: &'a [u8]) -> Self {
        Self { name, content }
    }

    /// The part name.
    #[must_use]
    pub const fn name(&self) -> &PartName {
        self.name
    }

    /// The content length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.content.len()
    }

    /// Whether the content is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

impl fmt::Debug for ScanPart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanPart")
            .field("name", &self.name.as_str())
            .field("len", &self.content.len())
            .field("content", &"<redacted>")
            .finish()
    }
}

/// Byte limits of one scan, so the scanner is not a resource exhaustion vector (SEC-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanLimits {
    max_part_bytes: usize,
    max_total_bytes: usize,
}

impl ScanLimits {
    /// 256 KiB per part and per scan, the request limit of P-33.
    pub const DEFAULT: Self = Self {
        max_part_bytes: 256 * 1024,
        max_total_bytes: 256 * 1024,
    };

    /// Limits per part and per scan.
    #[must_use]
    pub const fn new(max_part_bytes: usize, max_total_bytes: usize) -> Self {
        Self {
            max_part_bytes,
            max_total_bytes,
        }
    }

    /// The largest part scanned.
    #[must_use]
    pub const fn max_part_bytes(self) -> usize {
        self.max_part_bytes
    }

    /// The largest sum of part lengths in one scan.
    #[must_use]
    pub const fn max_total_bytes(self) -> usize {
        self.max_total_bytes
    }
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A scan that did not run to the end; the caller fails closed (SEC-18).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// A part is longer than the per-part limit.
    #[error("part {} has {size} bytes, over the scan limit of {limit}", part.as_str())]
    PartTooLarge {
        /// The part.
        part: PartName,
        /// Its length.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The parts together are longer than the per-scan limit.
    #[error("the parts exceed the scan limit of {limit} bytes")]
    TotalTooLarge {
        /// The limit.
        limit: usize,
    },
}

/// Why a scanner could not be built.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// The vendored gitleaks file does not have the recorded digest.
    #[error(
        "vendored gitleaks config digest {actual} differs from the recorded {GITLEAKS_CONFIG_SHA256}"
    )]
    VendoredDigest {
        /// The digest of the embedded file.
        actual: String,
    },
    /// A rule file is not valid TOML of the expected shape.
    #[error("{source_name}: {message}")]
    RuleFile {
        /// `gitleaks` or `work`.
        source_name: &'static str,
        /// The parser message.
        message: String,
    },
    /// A Work rule does not compile; Work rules are never skipped.
    #[error("work rule {id}: {message}")]
    WorkRule {
        /// The rule id.
        id: String,
        /// Why.
        message: String,
    },
    /// A global allowlist regex does not compile.
    #[error("global allowlist: {0}")]
    GlobalAllowlist(String),
    /// Two rules share an id.
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
    /// The keyword automaton could not be built.
    #[error("keyword automaton: {0}")]
    Keywords(String),
}

/// Why a gitleaks rule is not active in the scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SkipReason {
    /// The rule matches file names only; body parts have no path.
    PathOnly,
    /// The rule applies only to some file paths; body parts have no path.
    PathScoped,
    /// The regex or an allowlist regex uses syntax the `regex` crate rejects.
    UnsupportedSyntax,
    /// The compiled regex exceeds [`REGEX_SIZE_LIMIT`].
    SizeLimit,
}

/// A gitleaks rule that is not active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedRule {
    /// The rule id.
    pub id: RuleId,
    /// Why it is skipped.
    pub reason: SkipReason,
}

/// What a scanner was built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildReport {
    /// Rules in the vendored gitleaks file.
    pub gitleaks_rules: usize,
    /// Gitleaks rules that are active.
    pub gitleaks_active: usize,
    /// Work rules, all active.
    pub work_rules: usize,
    /// Gitleaks regexes (rules and allowlists) rewritten from Go RE2 syntax before compiling.
    pub converted_regexes: usize,
    /// Gitleaks rules that are not active, in file order.
    pub skipped: Vec<SkippedRule>,
}

impl BuildReport {
    /// The number of skipped rules with `reason`.
    #[must_use]
    pub fn skipped_for(&self, reason: SkipReason) -> usize {
        self.skipped.iter().filter(|s| s.reason == reason).count()
    }
}

/// The version of the active rule set; a change triggers the asynchronous rescan of stored bodies (SEC-35 rule 3).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleSetId {
    digest: [u8; 32],
}

impl RuleSetId {
    /// The gitleaks release of the rule data.
    #[must_use]
    pub const fn gitleaks_version(&self) -> &'static str {
        GITLEAKS_VERSION
    }

    /// SHA-256 over the engine revision, both rule files and the active rule ids.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Whether bodies scanned under `previous` need a rescan.
    #[must_use]
    pub fn requires_rescan(&self, previous: &Self) -> bool {
        self != previous
    }
}

impl fmt::Display for RuleSetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gitleaks-{GITLEAKS_VERSION}+sha256:")?;
        self.digest.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for RuleSetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RuleSetId({self})")
    }
}

/// The compiled scanner; build once per worker and share.
pub struct SecretScanner {
    rules: Vec<Rule>,
    global: Vec<rules::Allowlist>,
    keywords: AhoCorasick,
    keyword_count: usize,
    limits: ScanLimits,
    id: RuleSetId,
    report: BuildReport,
}

impl SecretScanner {
    /// The built-in rule set with [`ScanLimits::DEFAULT`].
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the embedded rule data is damaged.
    pub fn builtin() -> Result<Self, BuildError> {
        Self::with_limits(ScanLimits::DEFAULT)
    }

    /// The built-in rule set with `limits`.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the embedded rule data is damaged.
    pub fn with_limits(limits: ScanLimits) -> Result<Self, BuildError> {
        let RuleSet {
            rules,
            global,
            keywords,
            keyword_count,
            digest,
            report,
        } = rules::load(GITLEAKS_CONFIG, WORK_RULES, ENGINE_REVISION)?;
        Ok(Self {
            rules,
            global,
            keywords,
            keyword_count,
            limits,
            id: RuleSetId { digest },
            report,
        })
    }

    /// The rule set version.
    #[must_use]
    pub const fn rule_set(&self) -> RuleSetId {
        self.id
    }

    /// What the scanner was built from.
    #[must_use]
    pub const fn report(&self) -> &BuildReport {
        &self.report
    }

    /// The scan limits.
    #[must_use]
    pub const fn limits(&self) -> ScanLimits {
        self.limits
    }

    /// Scans the parts in order and stops at the first detection.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError`] before scanning anything when a limit is exceeded.
    pub fn scan(&self, parts: &[ScanPart<'_>]) -> Result<ScanOutcome, ScanError> {
        let mut total = 0usize;
        for part in parts {
            if part.content.len() > self.limits.max_part_bytes {
                return Err(ScanError::PartTooLarge {
                    part: part.name.clone(),
                    size: part.content.len(),
                    limit: self.limits.max_part_bytes,
                });
            }
            total = total
                .checked_add(part.content.len())
                .filter(|t| *t <= self.limits.max_total_bytes)
                .ok_or(ScanError::TotalTooLarge {
                    limit: self.limits.max_total_bytes,
                })?;
        }
        for part in parts {
            if let Some(rule_id) = self.first_match(part.content) {
                return Ok(ScanOutcome::Detected {
                    rule_id,
                    part: part.name.clone(),
                });
            }
        }
        Ok(ScanOutcome::Clean)
    }

    fn first_match(&self, content: &[u8]) -> Option<RuleId> {
        if content.is_empty() {
            return None;
        }
        let mut present = vec![false; self.keyword_count];
        for m in self.keywords.find_overlapping_iter(content) {
            if let Some(slot) = present.get_mut(m.pattern().as_usize()) {
                *slot = true;
            }
        }
        self.rules
            .iter()
            .filter(|r| r.wanted(&present))
            .find(|r| r.detects(content, &self.global))
            .map(|r| r.id.clone())
    }
}

impl fmt::Debug for SecretScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretScanner")
            .field("rule_set", &self.id)
            .field("rules", &self.rules.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
