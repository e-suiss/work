//! Derived-concept storage ban (T-75, C-40, C-4): a lint over the migrations
//! under `crates/store/` that rejects derived-concept column names in canonical
//! tables unless a reviewed exception lists them, keeps projection tables in the
//! derived database with a `_vN` suffix, and requires every table to carry its
//! T-10 component label in `COMMENT ON TABLE`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::catalog::ids::family;
use crate::rules::files::{read, read_optional, rel, walk};

const RULE: &str = "derived-columns";

/// The reviewed exception list (T-75 rule 2).
pub(crate) const EXCEPTIONS_FILE: &str = "xtask/derived-column-exceptions.toml";

const STORE_DIR: &str = "crates/store/";

/// English names of the C-40 concepts (T-75 rule 2), most specific first.
pub(crate) const FORBIDDEN: &[&str] = &[
    "lease_state",
    "clock_state",
    "budget_state",
    "counterparty_state",
    "next_move",
    "shared_work",
    "track_record",
    "support_chain",
    "ping_pong",
    "pingpong",
    "status",
    "state",
    "summary",
    "blocked",
    "blocker",
    "blocking",
    "waiting",
    "progress",
    "attention",
    "handoff",
    "wip",
    "context",
    "perspective",
    "trust",
    "assurance",
];

/// T-10 component labels.
const LABELS: &[&str] = &[
    "CANONICAL",
    "SYNC-DERIVED",
    "DERIVED",
    "PROJECTION",
    "OPERATIONAL",
];

const GUARDS: &[&str] = &["append_only", "mutable", "job_queue"];

const DERIVED_SCHEMAS: &[&str] = &["derived", "projection"];

const ELEMENT_KEYWORDS: &[&str] = &[
    "constraint",
    "primary",
    "unique",
    "check",
    "foreign",
    "exclude",
    "like",
];

/// The database a table lives in (T-73 rule 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Db {
    Canonical,
    Derived,
}

impl Db {
    fn name(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Derived => "derived",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word { text: String, quoted: bool },
    Str(String),
    Punct(char),
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    line: usize,
}

fn find_seq(chars: &[char], from: usize, tag: &[char]) -> Option<usize> {
    if tag.is_empty() {
        return None;
    }
    chars
        .get(from..)?
        .windows(tag.len())
        .position(|w| w == tag)
        .map(|p| p.saturating_add(from))
}

/// Cursor over SQL characters that yields tokens; comments are skipped and
/// dollar-quoted bodies become opaque strings.
struct Lexer {
    chars: Vec<char>,
    i: usize,
    line: usize,
    out: Vec<Token>,
}

impl Lexer {
    fn at(&self, k: usize) -> Option<char> {
        self.chars.get(k).copied()
    }

    fn cur(&self) -> Option<char> {
        self.at(self.i)
    }

    fn next(&self) -> Option<char> {
        self.at(self.i.saturating_add(1))
    }

    fn advance(&mut self, n: usize) {
        for k in 0..n {
            if self.at(self.i.saturating_add(k)) == Some('\n') {
                self.line = self.line.saturating_add(1);
            }
        }
        self.i = self.i.saturating_add(n);
    }

    fn push(&mut self, tok: Tok, line: usize) {
        self.out.push(Token { tok, line });
    }

    fn block_comment(&mut self) {
        let mut depth = 0_usize;
        loop {
            match (self.cur(), self.next()) {
                (None, _) => break,
                (Some('/'), Some('*')) => {
                    depth = depth.saturating_add(1);
                    self.advance(2);
                }
                (Some('*'), Some('/')) => {
                    depth = depth.saturating_sub(1);
                    self.advance(2);
                    if depth == 0 {
                        break;
                    }
                }
                _ => self.advance(1),
            }
        }
    }

    fn quoted(&mut self, quote: char) {
        let start = self.line;
        let mut text = String::new();
        self.advance(1);
        while let Some(d) = self.cur() {
            if d == quote {
                if self.next() == Some(quote) {
                    text.push(quote);
                    self.advance(2);
                    continue;
                }
                self.advance(1);
                break;
            }
            text.push(d);
            self.advance(1);
        }
        let tok = if quote == '\'' {
            Tok::Str(text)
        } else {
            Tok::Word { text, quoted: true }
        };
        self.push(tok, start);
    }

    fn dollar(&mut self) {
        let mut j = self.i.saturating_add(1);
        while self.at(j).is_some_and(|d| d.is_alphanumeric() || d == '_') {
            j = j.saturating_add(1);
        }
        let tagged = self.at(j) == Some('$') && !self.next().is_some_and(|d| d.is_ascii_digit());
        let tag: Vec<char> = self
            .chars
            .get(self.i..=j)
            .map(<[char]>::to_vec)
            .unwrap_or_default();
        let body_start = j.saturating_add(1);
        let line = self.line;
        if let Some(end) = find_seq(&self.chars, body_start, &tag).filter(|_| tagged) {
            let body: String = self
                .chars
                .get(body_start..end)
                .unwrap_or_default()
                .iter()
                .collect();
            self.push(Tok::Str(body), line);
            self.advance(end.saturating_add(tag.len()).saturating_sub(self.i));
        } else {
            self.push(Tok::Punct('$'), line);
            self.advance(1);
        }
    }

    fn word(&mut self) {
        let line = self.line;
        let mut text = String::new();
        while let Some(d) = self
            .cur()
            .filter(|d| d.is_alphanumeric() || *d == '_' || *d == '$')
        {
            text.extend(d.to_lowercase());
            self.advance(1);
        }
        self.push(
            Tok::Word {
                text,
                quoted: false,
            },
            line,
        );
    }

    fn run(mut self) -> Vec<Token> {
        while let Some(c) = self.cur() {
            let next = self.next();
            if c.is_whitespace() {
                self.advance(1);
            } else if c == '-' && next == Some('-') {
                while self.cur().is_some_and(|d| d != '\n') {
                    self.advance(1);
                }
            } else if c == '/' && next == Some('*') {
                self.block_comment();
            } else if c == '\'' || c == '"' {
                self.quoted(c);
            } else if c == '$' {
                self.dollar();
            } else if c.is_alphanumeric() || c == '_' {
                self.word();
            } else {
                let line = self.line;
                self.push(Tok::Punct(c), line);
                self.advance(1);
            }
        }
        self.out
    }
}

fn tokenize(sql: &str) -> Vec<Token> {
    Lexer {
        chars: sql.chars().collect(),
        i: 0,
        line: 1,
        out: Vec::new(),
    }
    .run()
}

fn statements(tokens: Vec<Token>) -> Vec<Vec<Token>> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for t in tokens {
        if t.tok == Tok::Punct(';') {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else {
            current.push(t);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// A cursor over one statement.
struct Cursor<'a> {
    toks: &'a [Token],
    k: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.k).map(|t| &t.tok)
    }

    fn line(&self) -> usize {
        self.toks
            .get(self.k)
            .or_else(|| self.toks.last())
            .map_or(1, |t| t.line)
    }

    fn bump(&mut self) {
        self.k = self.k.saturating_add(1);
    }

    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word { text, quoted: false }) if text == kw)
    }

    fn eat(&mut self, kw: &str) -> bool {
        let hit = self.is_kw(kw);
        if hit {
            self.bump();
        }
        hit
    }

    fn eat_all(&mut self, kws: &[&str]) -> bool {
        let start = self.k;
        if kws.iter().all(|kw| self.eat(kw)) {
            true
        } else {
            self.k = start;
            false
        }
    }

    fn punct(&self, p: char) -> bool {
        self.peek() == Some(&Tok::Punct(p))
    }

    fn word(&mut self) -> Option<String> {
        match self.peek() {
            Some(Tok::Word { text, .. }) => {
                let text = text.clone();
                self.bump();
                Some(text)
            }
            _ => None,
        }
    }

    fn name(&mut self) -> Option<Name> {
        let first = self.word()?;
        if self.punct('.') {
            self.bump();
            let table = self.word()?;
            return Some(Name {
                schema: Some(first),
                table,
            });
        }
        Some(Name {
            schema: None,
            table: first,
        })
    }

    /// Splits the parenthesised list that starts at the cursor into its
    /// top-level elements and moves past the closing parenthesis.
    fn paren_elements(&mut self) -> Vec<&'a [Token]> {
        let mut out = Vec::new();
        if !self.punct('(') {
            return out;
        }
        self.bump();
        let mut depth = 0_usize;
        let mut start = self.k;
        while let Some(tok) = self.peek() {
            match tok {
                Tok::Punct('(') => depth = depth.saturating_add(1),
                Tok::Punct(')') if depth == 0 => {
                    out.push(self.toks.get(start..self.k).unwrap_or_default());
                    self.bump();
                    return out;
                }
                Tok::Punct(')') => depth = depth.saturating_sub(1),
                Tok::Punct(',') if depth == 0 => {
                    out.push(self.toks.get(start..self.k).unwrap_or_default());
                    start = self.k.saturating_add(1);
                }
                _ => {}
            }
            self.bump();
        }
        out.push(self.toks.get(start..).unwrap_or_default());
        out
    }

    fn rest_split_by_commas(&self) -> Vec<&'a [Token]> {
        let rest = self.toks.get(self.k..).unwrap_or_default();
        let mut out = Vec::new();
        let mut depth = 0_usize;
        let mut start = 0_usize;
        for (n, t) in rest.iter().enumerate() {
            match t.tok {
                Tok::Punct('(') => depth = depth.saturating_add(1),
                Tok::Punct(')') => depth = depth.saturating_sub(1),
                Tok::Punct(',') if depth == 0 => {
                    out.push(rest.get(start..n).unwrap_or_default());
                    start = n.saturating_add(1);
                }
                _ => {}
            }
        }
        out.push(rest.get(start..).unwrap_or_default());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Name {
    schema: Option<String>,
    table: String,
}

impl Name {
    fn key(&self) -> String {
        match &self.schema {
            Some(s) => format!("{s}.{}", self.table),
            None => self.table.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct Site {
    file: String,
    line: usize,
}

#[derive(Debug, Clone)]
struct Column {
    name: String,
    site: Site,
}

#[derive(Debug)]
struct Table {
    name: Name,
    created: Option<Site>,
    file_db: Option<Db>,
    columns: Vec<Column>,
    comment: Option<String>,
}

impl Table {
    fn new(name: Name) -> Self {
        Self {
            name,
            created: None,
            file_db: None,
            columns: Vec::new(),
            comment: None,
        }
    }

    fn home(&self) -> Db {
        match self.name.schema.as_deref() {
            Some(s) if DERIVED_SCHEMAS.contains(&s) => Db::Derived,
            Some(_) => Db::Canonical,
            None => self.file_db.unwrap_or(Db::Canonical),
        }
    }
}

/// The database a migration file belongs to, from a directory under
/// `migrations/` named after it.
pub(crate) fn file_db(rel_path: &str) -> Option<Db> {
    let after = rel_path.split_once("/migrations/")?.1;
    let mut dirs: Vec<&str> = after.split('/').collect();
    dirs.pop();
    dirs.iter().find_map(|d| match *d {
        "derived" | "work_derived" => Some(Db::Derived),
        "canonical" | "work" => Some(Db::Canonical),
        _ => None,
    })
}

/// True for a migration the lint reads: an `.sql` file under a `migrations/`
/// directory of `crates/store/`.
pub(crate) fn is_migration(rel_path: &str) -> bool {
    rel_path.starts_with(STORE_DIR)
        && rel_path.contains("/migrations/")
        && rel_path.to_ascii_lowercase().ends_with(".sql")
}

/// The schema model built from migrations applied in order.
#[derive(Debug, Default)]
pub(crate) struct Schema {
    tables: BTreeMap<String, Table>,
}

impl Schema {
    fn entry(&mut self, name: &Name, db: Option<Db>) -> &mut Table {
        let key = name.key();
        self.tables.entry(key).or_insert_with(|| {
            let mut t = Table::new(name.clone());
            t.file_db = db;
            t
        })
    }

    /// Applies one migration file.
    pub(crate) fn apply(&mut self, rel_path: &str, sql: &str) {
        let db = file_db(rel_path);
        for stmt in statements(tokenize(sql)) {
            let mut c = Cursor { toks: &stmt, k: 0 };
            let site = |c: &Cursor<'_>| Site {
                file: rel_path.to_owned(),
                line: c.line(),
            };
            if c.eat("create") {
                for kw in ["global", "local", "temporary", "temp", "unlogged"] {
                    c.eat(kw);
                }
                if !c.eat("table") {
                    continue;
                }
                c.eat_all(&["if", "not", "exists"]);
                let at = site(&c);
                let Some(name) = c.name() else { continue };
                let table = self.entry(&name, db);
                table.created = Some(at);
                table.file_db = db;
                if c.punct('(') {
                    for element in c.paren_elements() {
                        let first = element.first();
                        if let Some(Token {
                            tok: Tok::Word { text, quoted },
                            line,
                        }) = first
                            && (*quoted || !ELEMENT_KEYWORDS.contains(&text.as_str()))
                        {
                            table.columns.push(Column {
                                name: text.clone(),
                                site: Site {
                                    file: rel_path.to_owned(),
                                    line: *line,
                                },
                            });
                        }
                    }
                }
            } else if c.eat_all(&["alter", "table"]) {
                c.eat_all(&["if", "exists"]);
                c.eat("only");
                let Some(name) = c.name() else { continue };
                if c.punct('*') {
                    c.bump();
                }
                self.alter(&name, db, rel_path, &c);
            } else if c.eat_all(&["comment", "on", "table"]) {
                let Some(name) = c.name() else { continue };
                if !c.eat("is") {
                    continue;
                }
                let comment = match c.peek() {
                    Some(Tok::Str(s)) => Some(s.clone()),
                    _ => None,
                };
                self.entry(&name, db).comment = comment;
            }
        }
    }

    fn alter(&mut self, name: &Name, db: Option<Db>, rel_path: &str, c: &Cursor<'_>) {
        let mut key = name.key();
        for action in c.rest_split_by_commas() {
            let mut a = Cursor { toks: action, k: 0 };
            if a.eat("add") {
                if ELEMENT_KEYWORDS.iter().any(|kw| a.is_kw(kw)) {
                    continue;
                }
                a.eat("column");
                a.eat_all(&["if", "not", "exists"]);
                let line = a.line();
                if let Some(col) = a.word() {
                    let table = self.entry(name, db);
                    table.columns.push(Column {
                        name: col,
                        site: Site {
                            file: rel_path.to_owned(),
                            line,
                        },
                    });
                }
            } else if a.eat("rename") {
                if a.eat("to") {
                    let Some(new) = a.word() else { continue };
                    if let Some(mut table) = self.tables.remove(&key) {
                        table.name.table = new;
                        key = table.name.key();
                        self.tables.insert(key.clone(), table);
                    }
                    continue;
                }
                if a.eat("constraint") {
                    continue;
                }
                a.eat("column");
                let _old = a.word();
                if !a.eat("to") {
                    continue;
                }
                let line = a.line();
                if let Some(new) = a.word()
                    && let Some(table) = self.tables.get_mut(&key)
                {
                    table.columns.push(Column {
                        name: new,
                        site: Site {
                            file: rel_path.to_owned(),
                            line,
                        },
                    });
                }
            } else if a.eat_all(&["set", "schema"]) {
                let Some(schema) = a.word() else { continue };
                if let Some(mut table) = self.tables.remove(&key) {
                    table.name.schema = Some(schema);
                    key = table.name.key();
                    self.tables.insert(key.clone(), table);
                }
            }
        }
    }
}

/// The C-40 concept a column name spells, matching whole `_`-separated words
/// and their plurals.
pub(crate) fn forbidden_concept(column: &str) -> Option<&'static str> {
    let lower = column.to_lowercase();
    let words: Vec<&str> = lower.split('_').collect();
    FORBIDDEN.iter().copied().find(|term| {
        let parts: Vec<&str> = term.split('_').collect();
        words.windows(parts.len()).any(|w| {
            w.iter().zip(&parts).all(|(word, part)| {
                *word == *part
                    || word
                        .strip_prefix(part)
                        .is_some_and(|rest| rest == "s" || rest == "es")
            })
        })
    })
}

/// True for a `_vN` versioned projection name (N ≥ 1).
pub(crate) fn has_version_suffix(table: &str) -> bool {
    table.rsplit_once("_v").is_some_and(|(stem, n)| {
        !stem.is_empty()
            && !n.is_empty()
            && !n.starts_with('0')
            && n.bytes().all(|b| b.is_ascii_digit())
    })
}

/// A reviewed exception to the forbidden column names (T-75 rule 2).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Exception {
    pub(crate) table: String,
    pub(crate) column: String,
    pub(crate) spec: String,
    pub(crate) reason: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exceptions {
    #[serde(default)]
    exception: Vec<Exception>,
}

/// Parses the exception file.
pub(crate) fn parse_exceptions(text: &str) -> Result<Vec<Exception>, String> {
    toml::from_str::<Exceptions>(text)
        .map(|e| e.exception)
        .map_err(|e| format!("{EXCEPTIONS_FILE}: {e}"))
}

fn violation(path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(format!("{path}:{line}")),
        message,
    }
}

fn at(site: &Site, message: String) -> Violation {
    violation(&site.file, site.line, message)
}

fn label_violations(table: &Table, site: &Site) -> Vec<Violation> {
    let key = table.name.key();
    let Some(comment) = &table.comment else {
        return vec![at(
            site,
            format!(
                "table `{key}` has no `COMMENT ON TABLE` with its T-10 label (`label=…; home=…; guard=…; erasure=…`) (T-75 rule 1, T-10)"
            ),
        )];
    };
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for part in comment.split(';') {
        if let Some((k, v)) = part.split_once('=') {
            fields.insert(k.trim(), v.trim());
        }
    }
    let mut out = Vec::new();
    let mut bad = |msg: String| out.push(at(site, format!("table `{key}`: {msg} (T-75 rule 1)")));
    let home = table.home();
    let label = fields.get("label").copied().unwrap_or_default();
    if !LABELS.contains(&label) {
        bad(format!(
            "label `{label}` is not a T-10 label ({})",
            LABELS.join(", ")
        ));
    }
    match fields.get("home").copied() {
        Some(h) if h == home.name() => {}
        Some(h) => bad(format!(
            "comment says `home={h}` but the table lives in the {} database",
            home.name()
        )),
        None => bad("comment has no `home=`".to_owned()),
    }
    let guard = fields.get("guard").copied().unwrap_or_default();
    if !GUARDS.contains(&guard) {
        bad(format!(
            "guard `{guard}` is not one of {}",
            GUARDS.join(", ")
        ));
    }
    if fields.get("erasure").is_none_or(|e| e.is_empty()) {
        bad("comment has no `erasure=`".to_owned());
    }
    match (label, home) {
        ("DERIVED" | "PROJECTION", Db::Canonical) => bad(format!(
            "{label} tables live only in the derived database (T-73)"
        )),
        ("DERIVED" | "PROJECTION", Db::Derived) if !has_version_suffix(&table.name.table) => {
            bad(format!(
                "{label} table names carry a `_vN` version suffix (OP-11)"
            ));
        }
        ("CANONICAL" | "SYNC-DERIVED", Db::Derived) => bad(format!(
            "{label} tables live only in the canonical database (T-73)"
        )),
        _ => {}
    }
    out
}

/// Violations of the schema built from all migrations.
pub(crate) fn schema_violations(schema: &Schema, exceptions: &[Exception]) -> Vec<Violation> {
    let mut out = Vec::new();
    for (key, table) in &schema.tables {
        let home = table.home();
        if let Some(site) = &table.created {
            if let Some(db) = table.file_db
                && db != home
            {
                out.push(at(
                    site,
                    format!(
                        "table `{key}` belongs to the {} database but its migration is under the {} migrations (T-75 rule 1, T-73)",
                        home.name(),
                        db.name()
                    ),
                ));
            }
            if home == Db::Canonical && has_version_suffix(&table.name.table) {
                out.push(at(
                    site,
                    format!(
                        "`{key}` is named like a projection; projection tables live only in the derived database (T-75 rule 1, OP-11)"
                    ),
                ));
            }
            out.extend(label_violations(table, site));
        }
        if home != Db::Canonical {
            continue;
        }
        for col in &table.columns {
            let Some(concept) = forbidden_concept(&col.name) else {
                continue;
            };
            let excepted = exceptions
                .iter()
                .any(|e| e.table == *key && e.column == col.name);
            if !excepted {
                out.push(at(
                    &col.site,
                    format!(
                        "canonical column `{key}.{}` stores the derived concept `{concept}`; derive it from records or list a reviewed exception in {EXCEPTIONS_FILE} (T-75 rule 2, C-40, C-4)",
                        col.name
                    ),
                ));
            }
        }
    }
    out
}

/// Problems in the exception list itself: missing reason, unknown spec ID,
/// a column the lint would not reject, or an exception for a defined table that
/// has no such column.
pub(crate) fn exception_violations(
    schema: &Schema,
    exceptions: &[Exception],
    known_ids: &std::collections::BTreeSet<String>,
) -> Vec<Violation> {
    let mut out = Vec::new();
    for e in exceptions {
        let name = format!("`{}.{}`", e.table, e.column);
        let mut bad =
            |msg: String| out.push(violation(EXCEPTIONS_FILE, 1, format!("{name}: {msg}")));
        if e.reason.trim().is_empty() {
            bad("exception has no reason (T-75 rule 2)".to_owned());
        }
        if family(&e.spec).is_none() || !known_ids.contains(&e.spec) {
            bad(format!(
                "spec ID `{}` is not in the rule catalog (T-75 rule 2)",
                e.spec
            ));
        }
        if forbidden_concept(&e.column).is_none() {
            bad("column is not a forbidden name; remove the exception".to_owned());
        }
        if let Some(table) = schema.tables.get(&e.table)
            && table.created.is_some()
            && !table.columns.iter().any(|c| c.name == e.column)
        {
            bad("table has no such column; remove the stale exception".to_owned());
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let exceptions = match read_optional(&root.join(EXCEPTIONS_FILE))? {
        Some(text) => parse_exceptions(&text)?,
        None => Vec::new(),
    };
    let mut schema = Schema::default();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if is_migration(&rel_path) {
            schema.apply(&rel_path, &read(&path)?);
        }
    }
    let known = crate::catalog::load(root)?.ids();
    let mut out = exception_violations(&schema, &exceptions, &known);
    out.extend(schema_violations(&schema, &exceptions));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lint(files: &[(&str, &str)], exceptions: &[Exception]) -> Vec<String> {
        let mut schema = Schema::default();
        for (path, sql) in files {
            schema.apply(path, sql);
        }
        schema_violations(&schema, exceptions)
            .into_iter()
            .map(|v| format!("{}: {}", v.path.display(), v.message))
            .collect()
    }

    const CANON: &str = "crates/store/migrations/0001_canon.sql";
    const DERIVED: &str = "crates/store/migrations/0101_derived.sql";

    const GOOD_CANONICAL: &str = "
-- OP-2
CREATE TABLE work.record_header (
    ledger_id ledger.digest32 NOT NULL,
    pos       bigint          NOT NULL,
    ingest    text            NOT NULL, -- state is derived
    CONSTRAINT record_header_pk PRIMARY KEY (ledger_id, pos),
    CONSTRAINT record_header_ingest_ck CHECK (ingest IN ('admitted', 'rejected'))
);
CREATE FUNCTION work.f() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('CREATE TABLE %s (status text)', 'x');
    RETURN NULL;
END
$$;
COMMENT ON TABLE work.record_header IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=pseudonymous_skeleton';
";

    const GOOD_DERIVED: &str = "
CREATE TABLE derived.timer_v1 (
    ledger_id ledger.digest32 NOT NULL,
    state     text            NOT NULL,
    CONSTRAINT timer_v1_state_ck CHECK (state IN ('pending', 'fired'))
);
CREATE TABLE derived.reconcile_queue (ledger_id ledger.digest32 NOT NULL, status text);
COMMENT ON TABLE derived.timer_v1 IS 'label=DERIVED; home=derived; guard=mutable; erasure=none';
COMMENT ON TABLE derived.reconcile_queue IS 'label=OPERATIONAL; home=derived; guard=job_queue; erasure=none';
";

    // T-75 C-40
    #[test]
    fn t_75_labelled_canonical_and_derived_migrations_pass() {
        let v = lint(&[(CANON, GOOD_CANONICAL), (DERIVED, GOOD_DERIVED)], &[]);
        assert!(v.is_empty(), "{v:?}");
    }

    // T-75 C-40 C-4
    #[test]
    fn t_75_derived_concept_columns_in_canonical_tables_are_rejected() {
        let sql = "
CREATE TABLE IF NOT EXISTS work.commitment (
    ledger_id   ledger.digest32 NOT NULL,
    \"Status\"  text,
    lease_state text,
    next_move_party text,
    ping_pong_count integer,
    blocked     boolean,
    waiting_on  text
);
ALTER TABLE ONLY work.commitment ADD COLUMN IF NOT EXISTS progress numeric, ADD CONSTRAINT x CHECK (true);
ALTER TABLE work.commitment RENAME COLUMN waiting_on TO trust_level;
COMMENT ON TABLE work.commitment IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=none';
";
        let v = lint(&[(CANON, sql)], &[]);
        let concepts = [
            "status`",
            "lease_state",
            "next_move",
            "ping_pong",
            "blocked",
            "waiting",
            "progress",
            "trust",
        ];
        assert_eq!(v.len(), concepts.len(), "{v:?}");
        for (found, concept) in v.iter().zip(concepts) {
            assert!(found.contains(concept), "{found} lacks {concept}");
        }
        assert!(
            v.iter().any(|f| f.starts_with(&format!("{CANON}:11:"))),
            "{v:?}"
        );
    }

    // T-75 C-40
    #[test]
    fn t_75_forbidden_names_match_whole_words_and_plurals_only() {
        assert_eq!(forbidden_concept("state"), Some("state"));
        assert_eq!(forbidden_concept("statuses"), Some("status"));
        assert_eq!(forbidden_concept("auth_context_ref"), Some("context"));
        assert_eq!(forbidden_concept("budget_state"), Some("budget_state"));
        assert_eq!(forbidden_concept("statement_id"), None);
        assert_eq!(forbidden_concept("estate"), None);
        assert_eq!(forbidden_concept("trustee"), None);
        assert_eq!(forbidden_concept("ingest"), None);
    }

    // T-75 C-40
    #[test]
    fn t_75_listed_exception_allows_one_canonical_column() {
        let sql = "
CREATE TABLE work.body_dek (ledger_id ledger.digest32 NOT NULL, state text NOT NULL);
CREATE TABLE work.retention_hold (ledger_id ledger.digest32 NOT NULL, state text NOT NULL);
COMMENT ON TABLE work.body_dek IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
COMMENT ON TABLE work.retention_hold IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
";
        let exception = Exception {
            table: "work.body_dek".into(),
            column: "state".into(),
            spec: "OP-15".into(),
            reason: "terminal key destruction marker".into(),
        };
        let v = lint(&[(CANON, sql)], &[exception]);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("work.retention_hold.state"), "{v:?}");
    }

    // T-75 T-10
    #[test]
    fn t_75_tables_without_a_valid_label_are_rejected() {
        let sql = "
CREATE TABLE work.a (ledger_id ledger.digest32);
CREATE TABLE work.b (ledger_id ledger.digest32);
CREATE TABLE work.c (ledger_id ledger.digest32);
CREATE TABLE work.d (ledger_id ledger.digest32) PARTITION BY RANGE (ledger_id);
CREATE TABLE work.d_2026_10 PARTITION OF work.d FOR VALUES FROM ('a') TO ('b');
COMMENT ON TABLE work.b IS 'label=MAYBE; home=canonical; guard=mutable; erasure=none';
COMMENT ON TABLE work.c IS 'label=CANONICAL; home=derived; guard=sometimes';
COMMENT ON TABLE work.d IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=none';
";
        let v = lint(&[(CANON, sql)], &[]);
        assert_eq!(v.len(), 6, "{v:?}");
        assert!(v[0].contains("`work.a` has no `COMMENT ON TABLE`"), "{v:?}");
        assert!(v[1].contains("label `MAYBE`"), "{v:?}");
        assert!(v[2].contains("home=derived"), "{v:?}");
        assert!(v[3].contains("guard `sometimes`"), "{v:?}");
        assert!(v[4].contains("erasure="), "{v:?}");
        assert!(v[5].contains("`work.d_2026_10` has no"), "{v:?}");
    }

    // T-75 T-73 OP-11
    #[test]
    fn t_75_projection_tables_live_only_in_the_derived_database_with_a_version() {
        let canonical = "
CREATE TABLE work.attention_v1 (ledger_id ledger.digest32);
COMMENT ON TABLE work.attention_v1 IS 'label=PROJECTION; home=canonical; guard=mutable; erasure=none';
CREATE TABLE work.view (ledger_id ledger.digest32);
COMMENT ON TABLE work.view IS 'label=DERIVED; home=canonical; guard=mutable; erasure=none';
";
        let derived = "
CREATE TABLE projection.work_view (ledger_id ledger.digest32);
COMMENT ON TABLE projection.work_view IS 'label=PROJECTION; home=derived; guard=mutable; erasure=none';
CREATE TABLE derived.item (ledger_id ledger.digest32);
COMMENT ON TABLE derived.item IS 'label=CANONICAL; home=derived; guard=append_only; erasure=none';
";
        let v = lint(&[(CANON, canonical), (DERIVED, derived)], &[]);
        assert_eq!(v.len(), 5, "{v:?}");
        assert!(
            v.iter()
                .any(|f| f.contains("`derived.item`") && f.contains("canonical database"))
        );
        assert!(
            v.iter()
                .any(|f| f.contains("`projection.work_view`") && f.contains("_vN"))
        );
        assert!(
            v.iter()
                .any(|f| f.contains("`work.attention_v1` is named like a projection"))
        );
        assert!(
            v.iter()
                .any(|f| f.contains("`work.attention_v1`") && f.contains("only in the derived"))
        );
        assert!(
            v.iter()
                .any(|f| f.contains("`work.view`") && f.contains("only in the derived"))
        );
    }

    // T-75 T-73
    #[test]
    fn t_75_migration_directory_must_match_the_table_database() {
        let path = "crates/store/migrations/work_derived/0001.sql";
        assert_eq!(file_db(path), Some(Db::Derived));
        assert_eq!(
            file_db("crates/store/migrations/work/0001.sql"),
            Some(Db::Canonical)
        );
        assert_eq!(file_db(CANON), None);
        let sql = "
CREATE TABLE work.item_head (ledger_id ledger.digest32);
COMMENT ON TABLE work.item_head IS 'label=SYNC-DERIVED; home=canonical; guard=mutable; erasure=none';
CREATE TABLE timer_v2 (state text);
COMMENT ON TABLE timer_v2 IS 'label=DERIVED; home=derived; guard=mutable; erasure=none';
";
        let v = lint(&[(path, sql)], &[]);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("under the derived migrations"), "{v:?}");
    }

    // T-75 T-73
    #[test]
    fn t_75_renamed_tables_are_judged_by_their_final_name() {
        let sql = "
CREATE TABLE work.timer (ledger_id ledger.digest32);
COMMENT ON TABLE work.timer IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
ALTER TABLE work.timer RENAME TO timer_v1;
";
        let v = lint(&[(CANON, sql)], &[]);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(
            v[0].contains("`work.timer_v1` is named like a projection"),
            "{v:?}"
        );
    }

    // T-75
    #[test]
    fn t_75_exceptions_need_a_catalog_id_a_reason_and_a_live_column() {
        let mut schema = Schema::default();
        schema.apply(
            CANON,
            "CREATE TABLE work.body_dek (state text); CREATE TABLE work.hold (kind text);",
        );
        let ids = ["OP-15".to_owned()].into_iter().collect();
        let entry = |table: &str, column: &str, spec: &str, reason: &str| Exception {
            table: table.into(),
            column: column.into(),
            spec: spec.into(),
            reason: reason.into(),
        };
        let good = [
            entry("work.body_dek", "state", "OP-15", "key destruction marker"),
            entry(
                "work.later",
                "state",
                "OP-15",
                "table comes in a later migration",
            ),
        ];
        assert!(exception_violations(&schema, &good, &ids).is_empty());
        let bad = [
            entry("work.body_dek", "state", "OP-999", " "),
            entry("work.hold", "kind", "OP-15", "not forbidden"),
            entry("work.hold", "state", "OP-15", "stale"),
        ];
        assert_eq!(exception_violations(&schema, &bad, &ids).len(), 4);
    }

    // T-75
    #[test]
    fn t_75_no_migrations_and_the_committed_exception_file_pass() {
        assert!(lint(&[], &[]).is_empty());
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let text = std::fs::read_to_string(root.join(EXCEPTIONS_FILE)).unwrap();
        let exceptions = parse_exceptions(&text).unwrap();
        assert!(!exceptions.is_empty());
        assert!(parse_exceptions("[[exception]]\ntable = \"a\"\n").is_err());
    }
}
