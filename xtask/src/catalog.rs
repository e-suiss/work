//! Tracked rule catalog (T-46, T-47, T-49): generated from the local spec,
//! committed under `conformance/catalog/` with a digest of its rendered files,
//! and checked by CI for hand edits, drift from the local spec, format, rule
//! coverage, the threat model, forbidden claims and the maintainer watchlist.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{Check, Violation};

#[path = "catalog_claims.rs"]
mod claims;
#[path = "catalog_ids.rs"]
pub(crate) mod ids;
#[path = "catalog_scan.rs"]
mod scan;
#[path = "catalog_spec.rs"]
mod spec;
#[path = "catalog_titles.rs"]
mod titles;
#[path = "catalog_watchlist.rs"]
mod watchlist;

use ids::{FAMILIES, family, number};

/// Catalog directory, relative to the workspace root.
pub(crate) const DIR: &str = "conformance/catalog";
const CONFIG_FILE: &str = "catalog.toml";
const INVARIANTS_FILE: &str = "invariants.toml";
const DECISIONS_FILE: &str = "decisions.toml";
const MUST_NEVER_FILE: &str = "must-never.toml";
const GUARANTEES_FILE: &str = "guarantees.toml";
const THREAT_FILE: &str = "threat-model.toml";

const STATUSES: &[&str] = &[
    "canonical-invariant",
    "central-decision",
    "frozen-product",
    "frozen-technical",
    "frozen-protocol",
    "policy-default",
    "engineering-assumption",
    "watch",
    "out-of-scope",
];
const CLASSES: &[&str] = &["BS", "UDC", "NG", "PU"];
const TURKISH_LETTERS: &str = "çğıöşüÇĞİÖŞÜ";
const TURKISH_WORDS: &[&str] = &[
    "ve", "bir", "ile", "için", "değil", "olarak", "veya", "bu", "hiçbir", "yalnız", "madde",
];
const MAX_TITLE_WORDS: usize = 16;
const LAST_STAGE: u8 = 14;
const HEADER: &str = "# T-46\n";

/// `conformance/catalog/catalog.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// The Ek B stage under construction; earlier stages are complete.
    pub(crate) current_stage: u8,
    /// Families whose staged rules need tests.
    pub(crate) enforced_families: Vec<String>,
    /// Directories scanned for Rust tests.
    pub(crate) test_roots: Vec<String>,
    #[serde(default)]
    pub(crate) stage_overrides: Vec<StageOverride>,
    #[serde(default)]
    pub(crate) value_stages: Vec<ValueStage>,
    /// Rules whose last test was removed on purpose, with the reason (T-47).
    #[serde(default)]
    pub(crate) test_removals: Vec<TestRemoval>,
    /// SHA-256 of the rendered catalog files; `cargo xtask catalog` writes it.
    #[serde(default)]
    pub(crate) catalog_digest: String,
}

/// A rule that lost all its tests on purpose (T-47).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestRemoval {
    pub(crate) id: String,
    pub(crate) reason: String,
}

/// The stage whose feature first depends on a PD/EA value, when it differs from
/// the rule's own stage (F-27).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValueStage {
    pub(crate) id: String,
    pub(crate) stage: u8,
    pub(crate) reason: String,
}

/// A family-wide stage decided outside the Ek B text, with its reason.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageOverride {
    pub(crate) family: String,
    pub(crate) stage: u8,
    pub(crate) reason: String,
}

/// One register row in the catalog.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub(crate) id: String,
    pub(crate) family: String,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) class: Option<String>,
    #[serde(default)]
    pub(crate) stage: Option<u8>,
    #[serde(default)]
    pub(crate) acceptance: Option<String>,
    #[serde(default)]
    pub(crate) pd: Option<String>,
    pub(crate) title: String,
    pub(crate) tests: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

/// One F-9 must-never item.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Item {
    pub(crate) rule: String,
    pub(crate) number: u32,
    pub(crate) title: String,
    pub(crate) rules: Vec<String>,
    pub(crate) tests: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MustNeverFile {
    #[serde(default)]
    item: Vec<Item>,
}

/// One guarantee matrix item (SEC-31, SEC-32, SEC-33).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Guarantee {
    pub(crate) rule: String,
    pub(crate) number: u32,
    pub(crate) class: String,
    pub(crate) title: String,
    pub(crate) tests: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuaranteeFile {
    #[serde(default)]
    guarantee: Vec<Guarantee>,
}

/// One threat-model cell: the rules that answer it and the tests that prove it.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cell {
    pub(crate) rules: Vec<String>,
    pub(crate) tests: Vec<String>,
}

/// One threat (SEC-21, T-49).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Threat {
    pub(crate) key: String,
    pub(crate) title: String,
    pub(crate) prevent: Cell,
    pub(crate) limit: Cell,
    pub(crate) detect: Cell,
    pub(crate) recover: Cell,
}

impl Threat {
    fn cells(&self) -> [(&'static str, &Cell); 4] {
        [
            ("prevent", &self.prevent),
            ("limit", &self.limit),
            ("detect", &self.detect),
            ("recover", &self.recover),
        ]
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreatFile {
    #[serde(default)]
    threat: Vec<Threat>,
}

/// The committed catalog.
#[derive(Debug, Default)]
pub(crate) struct Catalog {
    pub(crate) rules: Vec<Rule>,
    pub(crate) must_never: Vec<Item>,
    pub(crate) guarantees: Vec<Guarantee>,
    pub(crate) threats: Vec<Threat>,
}

impl Catalog {
    pub(crate) fn ids(&self) -> BTreeSet<String> {
        self.rules.iter().map(|r| r.id.clone()).collect()
    }
}

fn read_toml<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub(crate) fn load_config(root: &Path) -> Result<Config, String> {
    let path = root.join(DIR).join(CONFIG_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn load(root: &Path) -> Result<Catalog, String> {
    let dir = root.join(DIR);
    let mut catalog = Catalog::default();
    for file in [INVARIANTS_FILE, DECISIONS_FILE] {
        let parsed: RuleFile = read_toml(&dir.join(file))?;
        catalog.rules.extend(parsed.rule);
    }
    catalog.must_never = read_toml::<MustNeverFile>(&dir.join(MUST_NEVER_FILE))?.item;
    catalog.guarantees = read_toml::<GuaranteeFile>(&dir.join(GUARANTEES_FILE))?.guarantee;
    catalog.threats = read_toml::<ThreatFile>(&dir.join(THREAT_FILE))?.threat;
    Ok(catalog)
}

fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn list(items: &[String]) -> String {
    match items {
        [] => "[]".to_owned(),
        many if many.iter().map(String::len).sum::<usize>() < 60 => format!(
            "[{}]",
            many.iter().map(|s| quote(s)).collect::<Vec<_>>().join(", ")
        ),
        many => {
            let mut out = String::from("[\n");
            for s in many {
                let _ = writeln!(out, "  {},", quote(s));
            }
            out.push(']');
            out
        }
    }
}

fn inline_list(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| quote(s))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn render_rules(rules: &[Rule]) -> String {
    let mut out = String::from(HEADER);
    for r in rules {
        let _ = write!(
            out,
            "\n[[rule]]\nid = {}\nfamily = {}\nstatus = {}\n",
            quote(&r.id),
            quote(&r.family),
            quote(&r.status)
        );
        if let Some(c) = &r.class {
            let _ = writeln!(out, "class = {}", quote(c));
        }
        if let Some(s) = r.stage {
            let _ = writeln!(out, "stage = {s}");
        }
        if let Some(a) = &r.acceptance {
            let _ = writeln!(out, "acceptance = {}", quote(a));
        }
        if let Some(p) = &r.pd {
            let _ = writeln!(out, "pd = {}", quote(p));
        }
        let _ = writeln!(out, "title = {}", quote(&r.title));
        let _ = writeln!(out, "tests = {}", list(&r.tests));
    }
    out
}

fn render_must_never(items: &[Item]) -> String {
    let mut out = format!("{HEADER}# F-9\n");
    for i in items {
        let _ = write!(
            out,
            "\n[[item]]\nrule = {}\nnumber = {}\ntitle = {}\nrules = {}\ntests = {}\n",
            quote(&i.rule),
            i.number,
            quote(&i.title),
            list(&i.rules),
            list(&i.tests)
        );
    }
    out
}

fn render_guarantees(items: &[Guarantee]) -> String {
    let mut out = format!("{HEADER}# SEC-31 SEC-32 SEC-33\n");
    for g in items {
        let _ = write!(
            out,
            "\n[[guarantee]]\nrule = {}\nnumber = {}\nclass = {}\ntitle = {}\ntests = {}\n",
            quote(&g.rule),
            g.number,
            quote(&g.class),
            quote(&g.title),
            list(&g.tests)
        );
    }
    out
}

fn render_threats(threats: &[Threat]) -> String {
    let mut out = format!("{HEADER}# T-49 SEC-21\n");
    for t in threats {
        let _ = write!(
            out,
            "\n[[threat]]\nkey = {}\ntitle = {}\n",
            quote(&t.key),
            quote(&t.title)
        );
        for (name, cell) in t.cells() {
            let _ = writeln!(
                out,
                "{name} = {{ rules = {}, tests = {} }}",
                inline_list(&cell.rules),
                inline_list(&cell.tests)
            );
        }
    }
    out
}

fn sort_key(r: &Rule) -> (usize, u32) {
    (
        FAMILIES
            .iter()
            .position(|f| *f == r.family)
            .unwrap_or(usize::MAX),
        number(&r.id),
    )
}

/// Lowers `stage` to each family override, never raises it.
fn apply_overrides(rules: &mut [Rule], overrides: &[StageOverride]) {
    for r in rules.iter_mut().filter(|r| r.status != "out-of-scope") {
        for o in overrides.iter().filter(|o| o.family == r.family) {
            r.stage = Some(r.stage.map_or(o.stage, |s| s.min(o.stage)));
        }
    }
}

fn tests_of(found: &BTreeMap<String, BTreeSet<String>>, id: &str) -> Vec<String> {
    found
        .get(id)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default()
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The generated catalog files and their text, in a fixed order.
pub(crate) fn render_all(catalog: &Catalog) -> Vec<(&'static str, String)> {
    let mut rules = catalog.rules.clone();
    rules.sort_by_key(sort_key);
    let (inv, dec): (Vec<Rule>, Vec<Rule>) = rules
        .into_iter()
        .partition(|r| r.status == "canonical-invariant");
    vec![
        (INVARIANTS_FILE, render_rules(&inv)),
        (DECISIONS_FILE, render_rules(&dec)),
        (MUST_NEVER_FILE, render_must_never(&catalog.must_never)),
        (GUARANTEES_FILE, render_guarantees(&catalog.guarantees)),
        (THREAT_FILE, render_threats(&catalog.threats)),
    ]
}

/// SHA-256 over the generated files, each as its name, a newline and its text.
pub(crate) fn digest_of(files: &[(&str, String)]) -> String {
    let mut all = String::new();
    for (name, text) in files {
        all.push_str(name);
        all.push('\n');
        all.push_str(text);
    }
    crate::sha256::hex_digest(all.as_bytes())
}

const DIGEST_KEY: &str = "catalog_digest";

/// `catalog.toml` with its digest line set to `digest`.
pub(crate) fn with_digest(config: &str, digest: &str) -> String {
    let line = format!("{DIGEST_KEY} = \"{digest}\"");
    let mut out: Vec<String> = Vec::new();
    let mut placed = false;
    for l in config.lines() {
        if l.trim_start().starts_with(DIGEST_KEY) {
            if !placed {
                out.push(line.clone());
                placed = true;
            }
        } else {
            if !placed && l.trim_start().starts_with("current_stage") {
                out.push(line.clone());
                out.push(String::new());
                placed = true;
            }
            out.push(l.to_owned());
        }
    }
    if !placed {
        out.push(line);
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

fn write_catalog(root: &Path, catalog: &Catalog) -> Result<(), String> {
    let dir = root.join(DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let files = render_all(catalog);
    for (name, text) in &files {
        write(&dir.join(name), text)?;
    }
    let config_path = dir.join(CONFIG_FILE);
    let config = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("{}: {e}", config_path.display()))?;
    write(&config_path, &with_digest(&config, &digest_of(&files)))
}

/// Builds the catalog the local spec and the test scan produce.
fn from_spec(root: &Path, spec_dir: &Path, config: &Config) -> Result<Catalog, String> {
    let spec = spec::parse(spec_dir)?;
    let known: BTreeSet<String> = spec.rules.iter().map(|r| r.id.clone()).collect();
    let found = scan::scan(root, &config.test_roots, &known)?.found;
    for id in &spec.unknown_stage_ids {
        println!("catalog: stage boundary {id} has no register row");
    }
    build(&spec, &found, config)
}

/// Builds the catalog from the parsed spec, the curated text and the test scan.
fn build(
    spec: &spec::Spec,
    found: &BTreeMap<String, BTreeSet<String>>,
    config: &Config,
) -> Result<Catalog, String> {
    if titles::MUST_NEVER.len() != spec.must_never {
        return Err(format!(
            "the spec has {} must-never items, xtask/src/catalog_titles.rs curates {}; curate them first",
            spec.must_never,
            titles::MUST_NEVER.len()
        ));
    }
    if titles::THREATS.len() != spec.threats {
        return Err(format!(
            "the spec threat table has {} rows, xtask/src/catalog_titles.rs curates {}; curate them first",
            spec.threats,
            titles::THREATS.len()
        ));
    }
    let mut rules: Vec<Rule> = spec
        .rules
        .iter()
        .map(|s| Rule {
            id: s.id.clone(),
            family: family(&s.id).unwrap_or_default().to_owned(),
            status: s.status.clone(),
            class: s.class.clone(),
            stage: spec.stages.get(&s.id).copied(),
            acceptance: s.acceptance.clone(),
            pd: s.pd.clone(),
            title: titles::title(&s.id).to_owned(),
            tests: tests_of(found, &s.id),
        })
        .collect();
    apply_overrides(&mut rules, &config.stage_overrides);
    let must_never = titles::MUST_NEVER
        .iter()
        .zip(1_u32..)
        .map(|(title, n)| Item {
            rule: "F-9".to_owned(),
            number: n,
            title: (*title).to_owned(),
            rules: titles::MUST_NEVER_RULES
                .iter()
                .find(|(k, _)| *k == n)
                .map(|(_, r)| r.iter().map(|s| (*s).to_owned()).collect())
                .unwrap_or_default(),
            tests: Vec::new(),
        })
        .collect();
    let mut guarantees = Vec::new();
    for (rule, classes) in &spec.guarantees {
        let curated = titles::GUARANTEES
            .iter()
            .find(|(r, _)| r == rule)
            .map_or(&[][..], |(_, t)| *t);
        if curated.len() != classes.len() {
            return Err(format!(
                "the spec lists {} {rule} items, xtask/src/catalog_titles.rs curates {}; curate them first",
                classes.len(),
                curated.len()
            ));
        }
        for ((title, class), n) in curated.iter().zip(classes).zip(1_u32..) {
            guarantees.push(Guarantee {
                rule: rule.clone(),
                number: n,
                class: class.clone(),
                title: (*title).to_owned(),
                tests: Vec::new(),
            });
        }
    }
    let owned = |ids: &[&str]| ids.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let threats = titles::THREATS
        .iter()
        .map(|t| Threat {
            key: t.key.to_owned(),
            title: t.title.to_owned(),
            prevent: Cell {
                rules: owned(t.prevent),
                tests: Vec::new(),
            },
            limit: Cell {
                rules: owned(t.limit),
                tests: Vec::new(),
            },
            detect: Cell {
                rules: owned(t.detect),
                tests: Vec::new(),
            },
            recover: Cell {
                rules: owned(t.recover),
                tests: Vec::new(),
            },
        })
        .collect();
    Ok(Catalog {
        rules,
        must_never,
        guarantees,
        threats,
    })
}

/// `cargo xtask catalog`: regenerates the catalog from the local spec; with
/// `links_only`, refreshes only the test links from the committed catalog.
pub(crate) fn generate(root: &Path, links_only: bool) -> Result<(), String> {
    let config = load_config(root)?;
    let catalog = if links_only {
        let mut catalog = load(root)?;
        let found = scan::scan(root, &config.test_roots, &catalog.ids())?.found;
        for r in &mut catalog.rules {
            r.tests = tests_of(&found, &r.id);
        }
        catalog
    } else {
        let spec_dir = root.join(crate::SPEC_DIR);
        if !spec_dir.is_dir() {
            return Err(format!(
                "{} not found; the catalog is generated from the local spec (T-46). CI checks the committed catalog; `--links-only` refreshes test links without the spec.",
                spec_dir.display()
            ));
        }
        from_spec(root, &spec_dir, &config)?
    };
    write_catalog(root, &catalog)?;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &catalog.rules {
        let n = counts.entry(r.family.as_str()).or_default();
        *n = n.saturating_add(1);
    }
    let summary: Vec<String> = counts.iter().map(|(f, n)| format!("{f} {n}")).collect();
    println!(
        "catalog: {} rules ({}), {} must-never items, {} guarantees, {} threats",
        catalog.rules.len(),
        summary.join(", "),
        catalog.must_never.len(),
        catalog.guarantees.len(),
        catalog.threats.len()
    );
    Ok(())
}

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "catalog-format",
            run: check_format,
        },
        Check {
            name: "rule-coverage",
            run: check_coverage,
        },
        Check {
            name: "threat-model",
            run: check_threat_model,
        },
        Check {
            name: "forbidden-claims",
            run: claims::check,
        },
        Check {
            name: "maintainer-watchlist",
            run: watchlist::check,
        },
    ]
}

fn violation(rule: &'static str, file: &str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(DIR).join(file),
        message,
    }
}

fn title_problem(title: &str, required: bool) -> Option<String> {
    if title.trim().is_empty() {
        return required.then(|| "missing English title".to_owned());
    }
    let turkish_word = title
        .split(|c: char| !c.is_alphanumeric())
        .any(|w| TURKISH_WORDS.contains(&w.to_lowercase().as_str()));
    if title.chars().any(|c| TURKISH_LETTERS.contains(c)) || turkish_word {
        return Some(format!("title is not English: {title:?}"));
    }
    let words = title.split_whitespace().count();
    (words > MAX_TITLE_WORDS).then(|| format!("title has {words} words (max {MAX_TITLE_WORDS})"))
}

fn file_of(rule: &Rule) -> &'static str {
    if rule.status == "canonical-invariant" {
        INVARIANTS_FILE
    } else {
        DECISIONS_FILE
    }
}

fn contiguous(numbers: &[u32]) -> bool {
    numbers.iter().zip(1_u32..).all(|(n, want)| *n == want)
}

/// Pure format validation.
pub(crate) fn format_violations(catalog: &Catalog, config: &Config) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for r in &catalog.rules {
        let file = file_of(r);
        let mut bad =
            |m: String| out.push(violation("catalog-format", file, format!("{}: {m}", r.id)));
        if !seen.insert(r.id.clone()) {
            bad("duplicate ID".to_owned());
        }
        if family(&r.id) != Some(r.family.as_str()) {
            bad(format!("family {:?} does not match the ID", r.family));
        }
        if !STATUSES.contains(&r.status.as_str()) {
            bad(format!("unknown status {:?}", r.status));
        }
        if let Some(c) = &r.class
            && !CLASSES.contains(&c.as_str())
        {
            bad(format!("unknown guarantee class {c:?}"));
        }
        if r.stage.is_some_and(|s| s > LAST_STAGE) {
            bad("stage outside Ek B stages 0–14".to_owned());
        }
        let needs = spec::needs_acceptance(&r.id, &r.status);
        match (&r.acceptance, needs) {
            (Some(a), true) if a == "filled" || a == "to-fill" => {}
            (None, false) => {}
            (Some(a), true) => bad(format!("acceptance {a:?} is not \"filled\" or \"to-fill\"")),
            (None, true) => bad("needs an acceptance state (F-21)".to_owned()),
            (Some(_), false) => {
                bad("only frozen technical, protocol and MKT rows carry acceptance".to_owned());
            }
        }
        if let Some(p) = &r.pd
            && p != "set"
            && p != "unset"
        {
            bad(format!("pd {p:?} is not \"set\" or \"unset\""));
        }
        let required = titles::REQUIRED_TITLES.contains(&r.id.as_str())
            || r.stage.is_some_and(|s| s <= config.current_stage);
        if let Some(p) = title_problem(&r.title, required) {
            bad(p);
        }
    }
    out.extend(item_violations(catalog, &seen));
    out.extend(config_violations(config));
    out
}

fn item_violations(catalog: &Catalog, seen: &BTreeSet<String>) -> Vec<Violation> {
    let mut out = Vec::new();
    let numbers: Vec<u32> = catalog.must_never.iter().map(|i| i.number).collect();
    if catalog.must_never.is_empty() || !contiguous(&numbers) {
        out.push(violation(
            "catalog-format",
            MUST_NEVER_FILE,
            "must-never items are numbered 1…n (F-9)".to_owned(),
        ));
    }
    for i in &catalog.must_never {
        if let Some(p) = title_problem(&i.title, true) {
            out.push(violation(
                "catalog-format",
                MUST_NEVER_FILE,
                format!("item {}: {p}", i.number),
            ));
        }
        for r in i.rules.iter().filter(|r| !seen.contains(*r)) {
            out.push(violation(
                "catalog-format",
                MUST_NEVER_FILE,
                format!("item {}: rule {r} is not in the catalog", i.number),
            ));
        }
    }
    for rule in ["SEC-31", "SEC-32", "SEC-33"] {
        let numbers: Vec<u32> = catalog
            .guarantees
            .iter()
            .filter(|g| g.rule == rule)
            .map(|g| g.number)
            .collect();
        if numbers.is_empty() || !contiguous(&numbers) {
            out.push(violation(
                "catalog-format",
                GUARANTEES_FILE,
                format!("{rule} items are numbered 1…n"),
            ));
        }
    }
    for g in &catalog.guarantees {
        if !CLASSES.contains(&g.class.as_str()) {
            out.push(violation(
                "catalog-format",
                GUARANTEES_FILE,
                format!("{} #{}: unknown class {:?}", g.rule, g.number, g.class),
            ));
        }
        if let Some(p) = title_problem(&g.title, true) {
            out.push(violation(
                "catalog-format",
                GUARANTEES_FILE,
                format!("{} #{}: {p}", g.rule, g.number),
            ));
        }
    }
    out
}

fn config_violations(config: &Config) -> Vec<Violation> {
    let mut out = Vec::new();
    for v in &config.value_stages {
        if v.reason.trim().is_empty() || v.stage > LAST_STAGE {
            out.push(violation(
                "catalog-format",
                CONFIG_FILE,
                format!("value stage for {} needs a stage 0–14 and a reason", v.id),
            ));
        }
    }
    for o in &config.stage_overrides {
        if o.reason.trim().is_empty()
            || o.stage > LAST_STAGE
            || !FAMILIES.contains(&o.family.as_str())
        {
            out.push(violation(
                "catalog-format",
                CONFIG_FILE,
                format!(
                    "stage override for {:?} needs a known family, a stage 0–14 and a reason",
                    o.family
                ),
            ));
        }
    }
    for f in config
        .enforced_families
        .iter()
        .filter(|f| !FAMILIES.contains(&f.as_str()))
    {
        out.push(violation(
            "catalog-format",
            CONFIG_FILE,
            format!("unknown enforced family {f:?}"),
        ));
    }
    out
}

fn stale_links(root: &Path, catalog: &Catalog) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut check = |owner: String, tests: &[String], file: &'static str| {
        for t in tests.iter().filter(|t| !scan::link_exists(root, t)) {
            out.push(violation(
                "catalog-format",
                file,
                format!("{owner}: test link {t:?} does not resolve"),
            ));
        }
    };
    for r in &catalog.rules {
        check(r.id.clone(), &r.tests, file_of(r));
    }
    for i in &catalog.must_never {
        check(format!("F-9 #{}", i.number), &i.tests, MUST_NEVER_FILE);
    }
    for g in &catalog.guarantees {
        check(
            format!("{} #{}", g.rule, g.number),
            &g.tests,
            GUARANTEES_FILE,
        );
    }
    for t in &catalog.threats {
        for (name, cell) in t.cells() {
            check(format!("{} {name}", t.key), &cell.tests, THREAT_FILE);
        }
    }
    out
}

/// Hand edits: committed files that are not in rendered form, and a digest that
/// does not match the committed files (T-46).
pub(crate) fn hand_edit_violations(
    committed: &[(&str, String)],
    rendered: &[(&str, String)],
    digest: &str,
) -> Vec<Violation> {
    let mut out = Vec::new();
    for ((name, have), (_, want)) in committed.iter().zip(rendered) {
        if have != want {
            out.push(violation(
                "catalog-format",
                name,
                "not in generated form; the catalog is written by `cargo xtask catalog` only (T-46)"
                    .to_owned(),
            ));
        }
    }
    if digest_of(committed) != digest {
        out.push(violation(
            "catalog-format",
            CONFIG_FILE,
            "catalog_digest does not match the catalog files; they were edited by hand. Regenerate with `cargo xtask catalog` (T-46)"
                .to_owned(),
        ));
    }
    out
}

/// Generated files whose committed text differs from a fresh generation (T-46).
pub(crate) fn drift_violations(
    committed: &[(&str, String)],
    fresh: &[(&str, String)],
) -> Vec<Violation> {
    committed
        .iter()
        .zip(fresh)
        .filter(|((_, have), (_, want))| have != want)
        .map(|((name, _), _)| {
            violation(
                "catalog-format",
                name,
                "differs from the catalog the local spec generates; run `cargo xtask catalog` (T-46)"
                    .to_owned(),
            )
        })
        .collect()
}

fn committed_files(root: &Path) -> Result<Vec<(&'static str, String)>, String> {
    let dir = root.join(DIR);
    [
        INVARIANTS_FILE,
        DECISIONS_FILE,
        MUST_NEVER_FILE,
        GUARANTEES_FILE,
        THREAT_FILE,
    ]
    .into_iter()
    .map(|name| {
        let path = dir.join(name);
        std::fs::read_to_string(&path)
            .map(|text| (name, text))
            .map_err(|e| format!("{}: {e}", path.display()))
    })
    .collect()
}

fn check_format(root: &Path) -> Result<Vec<Violation>, String> {
    let config = load_config(root)?;
    let catalog = load(root)?;
    if catalog.rules.is_empty() {
        return Ok(vec![violation(
            "catalog-format",
            DECISIONS_FILE,
            "catalog is empty; run `cargo xtask catalog`".to_owned(),
        )]);
    }
    let mut out = format_violations(&catalog, &config);
    out.extend(stale_links(root, &catalog));
    let committed = committed_files(root)?;
    out.extend(hand_edit_violations(
        &committed,
        &render_all(&catalog),
        &config.catalog_digest,
    ));
    let spec_dir = root.join(crate::SPEC_DIR);
    if spec_dir.is_dir() {
        let fresh = from_spec(root, &spec_dir, &config)?;
        out.extend(drift_violations(&committed, &render_all(&fresh)));
    }
    Ok(out)
}

/// True when the release gate applies (`XTASK_RELEASE=1`, T-46).
fn release() -> bool {
    std::env::var("XTASK_RELEASE").is_ok_and(|v| v == "1")
}

/// The three T-46 reports and the violations they cause.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Coverage {
    pub(crate) untested: Vec<String>,
    pub(crate) to_fill: Vec<String>,
    pub(crate) unset_values: Vec<String>,
    pub(crate) violations: Vec<String>,
}

/// Coverage over the catalog and a test scan.
pub(crate) fn coverage(
    catalog: &Catalog,
    config: &Config,
    found: &scan::Scan,
    release: bool,
) -> Coverage {
    let mut cov = Coverage::default();
    for (location, id) in &found.unknown {
        cov.violations.push(format!(
            "{location} cites {id}, which is not in the catalog (T-47)"
        ));
    }
    for r in &catalog.rules {
        let scanned = tests_of(&found.found, &r.id);
        if r.tests != scanned {
            cov.violations.push(format!(
                "{}: catalog test links are stale; run `cargo xtask catalog --links-only` (T-47)",
                r.id
            ));
        }
        let Some(stage) = r.stage else { continue };
        let reached = stage <= config.current_stage;
        let completed = stage < config.current_stage || release;
        if reached
            && r.status != "out-of-scope"
            && config.enforced_families.contains(&r.family)
            && scanned.is_empty()
        {
            cov.untested.push(r.id.clone());
            if completed {
                cov.violations.push(format!(
                    "{} is a stage {stage} boundary (current {}) and no test cites it (T-37, T-46)",
                    r.id, config.current_stage
                ));
            }
        }
        if reached && r.acceptance.as_deref() == Some("to-fill") {
            cov.to_fill.push(r.id.clone());
        }
        if r.pd.as_deref() == Some("unset") {
            let value_stage = config
                .value_stages
                .iter()
                .find(|v| v.id == r.id)
                .map_or(stage, |v| v.stage);
            cov.unset_values
                .push(format!("{} (stage {value_stage})", r.id));
            if release && value_stage <= config.current_stage {
                cov.violations.push(format!(
                    "{} has no PD/EA value and its stage ships in this release (F-27, T-46)",
                    r.id
                ));
            }
        }
    }
    for r in catalog
        .rules
        .iter()
        .filter(|r| r.stage.is_none() && r.pd.as_deref() == Some("unset"))
    {
        cov.unset_values.push(format!("{} (unstaged)", r.id));
    }
    cov
}

/// Rules that had tests in the base catalog and have none in the scan, unless a
/// reasoned `test_removals` entry names them (T-47).
pub(crate) fn lost_tests(base: &[Rule], found: &scan::Scan, config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for r in base.iter().filter(|r| !r.tests.is_empty()) {
        if found.found.get(&r.id).is_some_and(|t| !t.is_empty()) {
            continue;
        }
        let removed = config
            .test_removals
            .iter()
            .any(|t| t.id == r.id && !t.reason.trim().is_empty());
        if !removed {
            out.push(format!(
                "{} lost all its tests (it had {}); restore a test or add a reasoned `test_removals` entry (T-47)",
                r.id,
                r.tests.len()
            ));
        }
    }
    for t in config
        .test_removals
        .iter()
        .filter(|t| t.reason.trim().is_empty())
    {
        out.push(format!("test removal for {} needs a reason (T-47)", t.id));
    }
    out
}

/// The rules of the catalog committed at `XTASK_CATALOG_BASE` (default `HEAD`);
/// none when git has no such commit and no base was requested.
fn base_rules(root: &Path) -> Result<Vec<Rule>, String> {
    let requested = std::env::var("XTASK_CATALOG_BASE")
        .ok()
        .filter(|b| !b.is_empty());
    let base = requested.clone().unwrap_or_else(|| "HEAD".to_owned());
    let mut rules = Vec::new();
    for file in [INVARIANTS_FILE, DECISIONS_FILE] {
        let output = std::process::Command::new("git")
            .args(["show", &format!("{base}:{DIR}/{file}")])
            .current_dir(root)
            .output()
            .map_err(|e| format!("git show: {e}"))?;
        if !output.status.success() {
            if requested.is_some() {
                return Err(format!(
                    "XTASK_CATALOG_BASE={base}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            return Ok(Vec::new());
        }
        let parsed: RuleFile = toml::from_str(&String::from_utf8_lossy(&output.stdout))
            .map_err(|e| format!("{base}:{DIR}/{file}: {e}"))?;
        rules.extend(parsed.rule);
    }
    Ok(rules)
}

fn check_coverage(root: &Path) -> Result<Vec<Violation>, String> {
    let config = load_config(root)?;
    let catalog = load(root)?;
    let found = scan::scan(root, &config.test_roots, &catalog.ids())?;
    let mut cov = coverage(&catalog, &config, &found, release());
    cov.violations
        .extend(lost_tests(&base_rules(root)?, &found, &config));
    let staged = catalog
        .rules
        .iter()
        .filter(|r| r.stage.is_some_and(|s| s <= config.current_stage))
        .count();
    let all_to_fill = catalog
        .rules
        .iter()
        .filter(|r| r.acceptance.as_deref() == Some("to-fill"))
        .count();
    println!(
        "      rule-coverage: stage {} — {}/{staged} boundary rules cited by tests",
        config.current_stage,
        staged.saturating_sub(cov.untested.len())
    );
    if !cov.untested.is_empty() {
        println!("      (1) untested: {}", cov.untested.join(", "));
    }
    println!(
        "      (2) acceptance to fill: {} of {all_to_fill} rows reached by stage {}{}",
        cov.to_fill.len(),
        config.current_stage,
        if cov.to_fill.is_empty() {
            String::new()
        } else {
            format!(": {}", cov.to_fill.join(", "))
        }
    );
    println!(
        "      (3) unset PD/EA values: {}",
        cov.unset_values.join(", ")
    );
    Ok(cov
        .violations
        .into_iter()
        .map(|m| violation("rule-coverage", CONFIG_FILE, m))
        .collect())
}

/// Threat-model problems (T-49).
pub(crate) fn threat_violations(catalog: &Catalog) -> Vec<Violation> {
    let ids = catalog.ids();
    let mut out = Vec::new();
    let mut keys = BTreeSet::new();
    if catalog.threats.is_empty() {
        out.push(violation(
            "threat-model",
            THREAT_FILE,
            "no threats".to_owned(),
        ));
    }
    for want in titles::THREATS {
        if !catalog.threats.iter().any(|t| t.key == want.key) {
            out.push(violation(
                "threat-model",
                THREAT_FILE,
                format!("{}: the SEC-21 threat is missing (T-49)", want.key),
            ));
        }
    }
    for t in &catalog.threats {
        let mut bad = |m: String| {
            out.push(violation(
                "threat-model",
                THREAT_FILE,
                format!("{}: {m}", t.key),
            ));
        };
        if !titles::THREATS.iter().any(|w| w.key == t.key) {
            bad("not a SEC-21 threat (T-49)".to_owned());
        }
        if !keys.insert(t.key.clone()) {
            bad("duplicate key".to_owned());
        }
        if let Some(p) = title_problem(&t.title, true) {
            bad(p);
        }
        for (name, cell) in t.cells() {
            if cell.rules.is_empty() {
                bad(format!("the {name} cell links no rule (T-49)"));
            }
            for r in cell.rules.iter().filter(|r| !ids.contains(*r)) {
                bad(format!(
                    "the {name} cell links {r}, which is not in the catalog (T-49)"
                ));
            }
        }
    }
    out
}

fn check_threat_model(root: &Path) -> Result<Vec<Violation>, String> {
    let catalog = load(root)?;
    let mut out = threat_violations(&catalog);
    let tested = catalog
        .threats
        .iter()
        .flat_map(|t| t.cells().map(|(_, c)| !c.tests.is_empty()))
        .filter(|t| *t)
        .count();
    println!(
        "      threat-model: {} threats, {tested} of {} cells with tests",
        catalog.threats.len(),
        catalog.threats.len().saturating_mul(4)
    );
    out.extend(
        stale_links(
            root,
            &Catalog {
                threats: catalog.threats,
                ..Catalog::default()
            },
        )
        .into_iter()
        .map(|mut v| {
            v.rule = "threat-model";
            v
        }),
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, status: &str, title: &str) -> Rule {
        Rule {
            id: id.to_owned(),
            family: family(id).unwrap_or_default().to_owned(),
            status: status.to_owned(),
            acceptance: spec::needs_acceptance(id, status).then(|| "filled".to_owned()),
            title: title.to_owned(),
            ..Rule::default()
        }
    }

    fn config(stage: u8) -> Config {
        Config {
            current_stage: stage,
            enforced_families: FAMILIES.iter().map(|f| (*f).to_owned()).collect(),
            test_roots: vec![],
            stage_overrides: vec![],
            value_stages: vec![],
            test_removals: vec![],
            catalog_digest: String::new(),
        }
    }

    fn found(pairs: &[(&str, &str)]) -> scan::Scan {
        let mut s = scan::Scan::default();
        for (id, loc) in pairs {
            s.found
                .entry((*id).to_owned())
                .or_default()
                .insert((*loc).to_owned());
        }
        s
    }

    // T-46
    #[test]
    fn t_46_catalog_format_rejects_duplicates_unknown_status_and_turkish_titles() {
        let mut bad = rule("INV-2", "maybe", "Tek yazım yolu");
        bad.stage = Some(0);
        let catalog = Catalog {
            rules: vec![
                rule("INV-2", "canonical-invariant", "Single write path"),
                bad,
            ],
            ..Catalog::default()
        };
        let msgs: Vec<String> = format_violations(&catalog, &config(0))
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert!(msgs.iter().any(|m| m.contains("duplicate")), "{msgs:?}");
        assert!(
            msgs.iter().any(|m| m.contains("unknown status")),
            "{msgs:?}"
        );
        assert!(msgs.iter().any(|m| m.contains("not English")), "{msgs:?}");
    }

    // T-46 F-21
    #[test]
    fn t_46_frozen_technical_rows_need_an_acceptance_state() {
        let mut r = rule("T-46", "frozen-technical", "Tracked rule catalog");
        r.acceptance = None;
        let mut extra = rule("INV-2", "canonical-invariant", "Single write path");
        extra.acceptance = Some("filled".into());
        let catalog = Catalog {
            rules: vec![r, extra],
            ..Catalog::default()
        };
        assert_eq!(
            format_violations(&catalog, &config(0))
                .iter()
                .filter(|v| v.message.contains("acceptance"))
                .count(),
            2
        );
    }

    // T-46
    #[test]
    fn t_46_stage_rows_and_curated_rows_need_titles() {
        let mut staged = rule("T-8", "canonical-invariant", "");
        staged.stage = Some(0);
        let later = rule("INV-3", "canonical-invariant", "");
        let curated = rule("T-29", "frozen-technical", "");
        let catalog = Catalog {
            rules: vec![staged, later, curated],
            ..Catalog::default()
        };
        let missing = format_violations(&catalog, &config(0))
            .iter()
            .filter(|v| v.message.contains("missing English title"))
            .count();
        assert_eq!(missing, 2);
    }

    // T-37 T-46
    #[test]
    fn t_37_untested_boundary_fails_only_for_completed_stages_or_release() {
        let mut now = rule("T-31", "frozen-technical", "x");
        now.stage = Some(1);
        let mut done = rule("T-36", "frozen-technical", "x");
        done.stage = Some(0);
        let mut later = rule("T-37", "frozen-technical", "x");
        later.stage = Some(3);
        let catalog = Catalog {
            rules: vec![now, done, later],
            ..Catalog::default()
        };
        let open = coverage(&catalog, &config(1), &found(&[]), false);
        assert_eq!(open.untested, ["T-31", "T-36"]);
        assert_eq!(open.violations.len(), 1);
        assert!(open.violations[0].contains("T-36"));
        let rel = coverage(&catalog, &config(1), &found(&[]), true);
        assert_eq!(rel.violations.len(), 2);
    }

    // F-21 T-46
    #[test]
    fn f_21_to_fill_acceptance_rows_are_reported_not_failed() {
        let mut r = rule("T-61", "frozen-technical", "x");
        r.stage = Some(0);
        r.acceptance = Some("to-fill".into());
        r.tests = vec!["a.rs::t_61_x".into()];
        let catalog = Catalog {
            rules: vec![r],
            ..Catalog::default()
        };
        let cov = coverage(
            &catalog,
            &config(0),
            &found(&[("T-61", "a.rs::t_61_x")]),
            true,
        );
        assert_eq!(cov.to_fill, ["T-61"]);
        assert!(cov.violations.is_empty(), "{:?}", cov.violations);
    }

    // F-27 OP-26
    #[test]
    fn f_27_op_26_unset_values_block_only_the_release() {
        let mut r = rule("OP-26", "engineering-assumption", "x");
        r.stage = Some(0);
        r.pd = Some("unset".into());
        r.tests = vec!["a.rs::op_26_x".into()];
        let catalog = Catalog {
            rules: vec![r],
            ..Catalog::default()
        };
        let scan = found(&[("OP-26", "a.rs::op_26_x")]);
        let open = coverage(&catalog, &config(0), &scan, false);
        assert_eq!(open.unset_values, ["OP-26 (stage 0)"]);
        assert!(open.violations.is_empty());
        assert_eq!(
            coverage(&catalog, &config(0), &scan, true).violations.len(),
            1
        );
        let mut deferred = config(0);
        deferred.value_stages.push(ValueStage {
            id: "OP-26".into(),
            stage: 14,
            reason: "capacity budgets are measured in stage 14".into(),
        });
        let released = coverage(&catalog, &deferred, &scan, true);
        assert!(released.violations.is_empty(), "{:?}", released.violations);
        assert_eq!(released.unset_values, ["OP-26 (stage 14)"]);
    }

    // T-47
    #[test]
    fn t_47_unknown_ids_and_stale_links_fail() {
        let catalog = Catalog {
            rules: vec![rule("T-47", "frozen-technical", "x")],
            ..Catalog::default()
        };
        let mut scan = found(&[("T-47", "a.rs::t_47_x")]);
        scan.unknown.push(("a.rs::t_99_x".into(), "T-99".into()));
        let cov = coverage(&catalog, &config(0), &scan, false);
        assert_eq!(cov.violations.len(), 2, "{:?}", cov.violations);
    }

    // T-49 SEC-21
    #[test]
    fn t_49_threat_cell_without_known_rule_is_reported() {
        let cell = |r: &[&str]| Cell {
            rules: r.iter().map(|s| (*s).to_owned()).collect(),
            tests: vec![],
        };
        let t = Threat {
            key: "secret-leakage".into(),
            title: "Secret leakage".into(),
            prevent: cell(&["SEC-24"]),
            limit: cell(&[]),
            detect: cell(&["SEC-99"]),
            recover: cell(&["SEC-24"]),
        };
        let mut threats: Vec<Threat> = titles::THREATS
            .iter()
            .filter(|w| w.key != "secret-leakage")
            .map(|w| Threat {
                key: w.key.to_owned(),
                title: w.title.to_owned(),
                prevent: cell(&["SEC-24"]),
                limit: cell(&["SEC-24"]),
                detect: cell(&["SEC-24"]),
                recover: cell(&["SEC-24"]),
            })
            .collect();
        threats.push(t);
        let catalog = Catalog {
            rules: vec![rule("SEC-24", "canonical-invariant", "x")],
            threats,
            ..Catalog::default()
        };
        let msgs: Vec<String> = threat_violations(&catalog)
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("limit cell links no rule")));
        assert!(msgs.iter().any(|m| m.contains("SEC-99")));
    }

    // T-49
    #[test]
    fn t_49_curated_threat_model_has_four_linked_cells_per_threat() {
        for t in titles::THREATS {
            for cell in [t.prevent, t.limit, t.detect, t.recover] {
                assert!(!cell.is_empty(), "{}", t.key);
            }
        }
        assert_eq!(titles::THREATS.len(), 7);
    }

    // T-46
    #[test]
    fn t_46_family_stage_override_lowers_but_never_raises_stage() {
        let mut later = rule("SEC-3", "canonical-invariant", "x");
        later.stage = Some(5);
        let unstaged = rule("SEC-4", "canonical-invariant", "x");
        let out_of_scope = rule("SEC-5", "out-of-scope", "x");
        let mut rules = [
            later,
            unstaged,
            out_of_scope,
            rule("INV-2", "canonical-invariant", "x"),
        ];
        let o = StageOverride {
            family: "SEC".into(),
            stage: 0,
            reason: "test".into(),
        };
        apply_overrides(&mut rules, &[o]);
        let stages: Vec<_> = rules.iter().map(|r| r.stage).collect();
        assert_eq!(stages, [Some(0), Some(0), None, None]);
    }

    // T-46
    #[test]
    fn t_46_rendered_files_parse_back_identically() {
        let mut r = rule("T-46", "frozen-technical", "Tracked \"rule\" catalog");
        r.stage = Some(0);
        r.class = Some("UDC".into());
        r.pd = Some("set".into());
        r.tests = vec![
            "xtask/src/catalog.rs::t_46_a".into(),
            "xtask/src/catalog.rs::t_46_b".into(),
        ];
        let parsed: RuleFile = toml::from_str(&render_rules(std::slice::from_ref(&r))).unwrap();
        assert_eq!(parsed.rule, [r]);
        let item = Item {
            rule: "F-9".into(),
            number: 1,
            title: "Never creates authority".into(),
            rules: vec!["MD-15".into()],
            tests: vec![],
        };
        let parsed: MustNeverFile =
            toml::from_str(&render_must_never(std::slice::from_ref(&item))).unwrap();
        assert_eq!(parsed.item, [item]);
        let g = Guarantee {
            rule: "SEC-33".into(),
            number: 3,
            class: "PU".into(),
            title: "Proving a signed Claim is true".into(),
            tests: vec![],
        };
        let parsed: GuaranteeFile =
            toml::from_str(&render_guarantees(std::slice::from_ref(&g))).unwrap();
        assert_eq!(parsed.guarantee, [g]);
        let cell = Cell {
            rules: vec!["SEC-24".into(), "SEC-25".into()],
            tests: vec![],
        };
        let t = Threat {
            key: "secret-leakage".into(),
            title: "Secret leakage".into(),
            prevent: cell.clone(),
            limit: cell.clone(),
            detect: cell.clone(),
            recover: cell,
        };
        let parsed: ThreatFile = toml::from_str(&render_threats(std::slice::from_ref(&t))).unwrap();
        assert_eq!(parsed.threat, [t]);
    }

    // T-49 SEC-21
    #[test]
    fn t_49_every_curated_threat_key_is_required() {
        let cell = Cell {
            rules: vec!["SEC-24".into()],
            tests: vec![],
        };
        let threat = |key: &str| Threat {
            key: key.to_owned(),
            title: "Some threat".into(),
            prevent: cell.clone(),
            limit: cell.clone(),
            detect: cell.clone(),
            recover: cell.clone(),
        };
        let mut threats: Vec<Threat> = titles::THREATS
            .iter()
            .skip(1)
            .map(|w| threat(w.key))
            .collect();
        threats.push(threat("invented-threat"));
        let catalog = Catalog {
            rules: vec![rule("SEC-24", "canonical-invariant", "x")],
            threats,
            ..Catalog::default()
        };
        let msgs: Vec<String> = threat_violations(&catalog)
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("missing")));
        assert!(msgs.iter().any(|m| m.contains("invented-threat")));
    }

    // T-47
    #[test]
    fn t_47_rule_losing_all_tests_against_the_base_catalog_fails() {
        let mut had = rule("T-31", "frozen-technical", "x");
        had.tests = vec!["a.rs::t_31_a".into()];
        let mut kept = rule("T-36", "frozen-technical", "x");
        kept.tests = vec!["a.rs::t_36_a".into()];
        let never = rule("T-37", "frozen-technical", "x");
        let base = [had, kept, never];
        let scan = found(&[("T-36", "b.rs::t_36_b")]);
        let lost = lost_tests(&base, &scan, &config(0));
        assert_eq!(lost.len(), 1, "{lost:?}");
        assert!(lost[0].starts_with("T-31"));
        let mut acknowledged = config(0);
        acknowledged.test_removals.push(TestRemoval {
            id: "T-31".into(),
            reason: "the rule moved to Semgrep".into(),
        });
        assert!(lost_tests(&base, &scan, &acknowledged).is_empty());
        acknowledged.test_removals[0].reason = String::new();
        assert_eq!(lost_tests(&base, &scan, &acknowledged).len(), 2);
    }

    // T-46
    #[test]
    fn t_46_hand_edits_and_spec_drift_are_rejected() {
        let mut r = rule("T-46", "frozen-technical", "Tracked rule catalog");
        r.stage = Some(0);
        let catalog = Catalog {
            rules: vec![r],
            ..Catalog::default()
        };
        let rendered = render_all(&catalog);
        let digest = digest_of(&rendered);
        assert!(hand_edit_violations(&rendered, &rendered, &digest).is_empty());
        let mut edited = rendered.clone();
        if let Some((_, text)) = edited.get_mut(1) {
            text.push_str("# note\n");
        }
        assert_eq!(hand_edit_violations(&edited, &rendered, &digest).len(), 2);
        let mut retitled = catalog.rules.clone();
        retitled[0].title = "Rule catalog".into();
        let reparsed = render_all(&Catalog {
            rules: retitled,
            ..Catalog::default()
        });
        assert_eq!(hand_edit_violations(&reparsed, &reparsed, &digest).len(), 1);
        assert_eq!(drift_violations(&rendered, &reparsed).len(), 1);
        let config = "# T-46\n\ncurrent_stage = 0\n";
        let once = with_digest(config, "abc");
        assert_eq!(
            once,
            "# T-46\n\ncatalog_digest = \"abc\"\n\ncurrent_stage = 0\n"
        );
        assert_eq!(
            with_digest(&once, "def").matches("catalog_digest").count(),
            1
        );
        assert!(with_digest(&once, "def").contains("\"def\""));
    }
}
