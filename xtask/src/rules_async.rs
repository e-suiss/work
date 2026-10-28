//! Async and unit-of-work rules (T-32 rules 4, 7): no external call between a transaction's
//! `begin` and its `commit` or inside a function that holds one (`no-external-call-in-transaction`),
//! and every NATS, HTTP, Access or Relay client call runs under a timeout
//! (`external-call-timeout`), both heuristics over the code view with a reviewed allowlist.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{is_test_file, read, read_optional, rel, walk};
use crate::rules::lex::{find_token, in_regions, lex, line_at, test_regions};
use crate::rules::source::is_rule_definition;

const IN_TX: &str = "no-external-call-in-transaction";
const TIMEOUT: &str = "external-call-timeout";

/// Reviewed exceptions to both rules.
pub(crate) const ALLOWLIST_FILE: &str = "xtask/external-call-allowlist.toml";

/// Types that hold an open database transaction.
const TX_TYPES: &[&str] = &["LedgerTx", "Transaction", "PgTransaction"];

/// Calls that open a transaction; the scope runs to the next [`TX_ENDS`] call.
const TX_BEGINS: &[&str] = &[".begin(", "::begin("];

const TX_ENDS: &[&str] = &[".commit(", ".rollback("];

/// Crate paths of external clients: NATS, HTTP, gRPC, Access, Relay and the key store.
const CLIENT_CRATES: &[&str] = &[
    "async_nats",
    "jetstream",
    "reqwest",
    "hyper",
    "hyper_util",
    "tonic",
    "work_access_client",
    "work_relay_client",
    "cryptoki",
];

/// Method calls that reach a NATS server or an HTTP peer.
const CLIENT_CALLS: &[&str] = &[
    ".publish(",
    ".publish_with_headers(",
    ".publish_with_reply(",
    ".send_publish(",
    ".request(",
    ".request_with_headers(",
    ".subscribe(",
    ".queue_subscribe(",
    ".flush(",
    ".connect(",
    "::connect(",
    ".create_stream(",
    ".create_or_update_stream(",
    ".get_or_create_stream(",
    ".get_stream(",
    ".update_stream(",
    ".create_consumer(",
    ".get_or_create_consumer(",
    ".create_key_value(",
    ".get_key_value(",
    ".send()",
];

/// Port receivers of the external collaborators T-32 rule 4 names.
const PORT_RECEIVERS: &[&str] = &[
    "access.",
    "relay.",
    "bus.",
    "executor.",
    "peer.",
    "federation.",
    "keystore.",
];

/// Calls that bound the future they wrap.
const TIMEOUT_WRAPPERS: &[&str] = &["timeout", "timeout_at"];

/// Client builder settings that give every request of the client a timeout.
const CONFIGURED_TIMEOUTS: &[&str] = &[".timeout(", ".set_timeout(", ".request_timeout("];

/// The reviewed exceptions of [`ALLOWLIST_FILE`], one list per rule.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Allowlist {
    #[serde(default)]
    pub(crate) timeout: Vec<Allowed>,
    #[serde(default)]
    pub(crate) transaction: Vec<Allowed>,
}

/// A reviewed exception: a file (or a directory ending in `/`) and optionally one function.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Allowed {
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) function: Option<String>,
    pub(crate) id: String,
    pub(crate) reason: String,
}

impl Allowed {
    fn covers(&self, hit: &Hit) -> bool {
        let path = if self.path.ends_with('/') {
            hit.path.starts_with(&self.path)
        } else {
            hit.path == self.path
        };
        path && self.function.as_ref().is_none_or(|f| *f == hit.function)
    }
}

/// One finding before the allowlist: file, enclosing function, line and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hit {
    pub(crate) path: String,
    pub(crate) function: String,
    pub(crate) line: usize,
    pub(crate) message: String,
}

/// A function in the code view: its name, the byte range of its signature and of its body
/// (between the braces), and whether it sits in an `impl` of a transaction type.
#[derive(Debug)]
struct Function {
    name: String,
    signature: (usize, usize),
    body: (usize, usize),
    in_tx_impl: bool,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The offset of the brace matching the `{` at `open`.
fn matching_brace(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (i, &b) in code.iter().enumerate().skip(open) {
        match b {
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// The first `{` or `;` after `from` outside parentheses and brackets.
fn header_end(code: &[u8], from: usize) -> Option<(usize, u8)> {
    let mut depth = 0_usize;
    for (i, &b) in code.iter().enumerate().skip(from) {
        match b {
            b'(' | b'[' => depth = depth.saturating_add(1),
            b')' | b']' => depth = depth.saturating_sub(1),
            b'{' | b';' if depth == 0 => return Some((i, b)),
            _ => {}
        }
    }
    None
}

fn contains_any(text: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|t| !find_token(text, t).is_empty())
}

/// Every `fn` item with a body.
fn functions(code: &str) -> Vec<Function> {
    let bytes = code.as_bytes();
    let tx_impls: Vec<(usize, usize)> = find_token(code, "impl")
        .into_iter()
        .filter_map(|at| {
            let (open, b) = header_end(bytes, at)?;
            let header = code.get(at..open)?;
            (b == b'{' && contains_any(header, TX_TYPES))
                .then(|| matching_brace(bytes, open).map(|close| (open, close)))?
        })
        .collect();
    find_token(code, "fn")
        .into_iter()
        .filter_map(|at| {
            let rest = code.get(at.saturating_add(2)..)?;
            let skipped = rest.len().saturating_sub(rest.trim_start().len());
            let name_at = at.saturating_add(2).saturating_add(skipped);
            let name_len = bytes
                .get(name_at..)?
                .iter()
                .take_while(|&&b| is_ident(b))
                .count();
            if name_len == 0 {
                return None;
            }
            let name = code.get(name_at..name_at.saturating_add(name_len))?;
            let (open, b) = header_end(bytes, name_at)?;
            if b != b'{' {
                return None;
            }
            let close = matching_brace(bytes, open)?;
            Some(Function {
                name: name.to_owned(),
                signature: (at, open),
                body: (open.saturating_add(1), close),
                in_tx_impl: tx_impls.iter().any(|&(a, b)| a < at && at < b),
            })
        })
        .collect()
}

/// The innermost function whose body holds `at`.
fn enclosing(fns: &[Function], at: usize) -> Option<&Function> {
    fns.iter()
        .filter(|f| f.body.0 <= at && at < f.body.1)
        .min_by_key(|f| f.body.1.saturating_sub(f.body.0))
}

/// Byte ranges of `f`'s body in which a transaction is open.
fn tx_scopes(code: &str, f: &Function) -> Vec<(usize, usize)> {
    let signature = code.get(f.signature.0..f.signature.1).unwrap_or_default();
    if f.in_tx_impl || contains_any(signature, TX_TYPES) {
        return vec![f.body];
    }
    let body = code.get(f.body.0..f.body.1).unwrap_or_default();
    let mut begins: Vec<usize> = TX_BEGINS.iter().flat_map(|t| find_token(body, t)).collect();
    begins.sort_unstable();
    let ends: Vec<usize> = TX_ENDS.iter().flat_map(|t| find_token(body, t)).collect();
    begins
        .into_iter()
        .map(|b| {
            let end = ends
                .iter()
                .copied()
                .filter(|&e| e > b)
                .min()
                .unwrap_or(body.len());
            (f.body.0.saturating_add(b), f.body.0.saturating_add(end))
        })
        .collect()
}

/// External calls in the code view, as (byte offset, what).
fn external_calls(code: &str, client_file: bool) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    for t in CLIENT_CRATES {
        out.extend(
            find_token(code, &format!("{t}::"))
                .into_iter()
                .map(|at| (at, (*t).to_owned())),
        );
    }
    for t in PORT_RECEIVERS {
        out.extend(find_token(code, t).into_iter().filter_map(|at| {
            let after = code.get(at.saturating_add(t.len())..)?;
            let method: String = after
                .bytes()
                .take_while(|&b| is_ident(b))
                .map(char::from)
                .collect();
            (!method.is_empty()).then(|| (at, format!("{t}{method}")))
        }));
    }
    if client_file {
        for t in CLIENT_CALLS {
            out.extend(
                find_token(code, t)
                    .into_iter()
                    .map(|at| (at, t.trim_end_matches('(').to_owned())),
            );
        }
    }
    out.sort();
    out.dedup_by_key(|(at, _)| *at);
    out
}

fn client_file(code: &str) -> bool {
    CLIENT_CRATES
        .iter()
        .any(|t| !find_token(code, &format!("{t}::")).is_empty())
}

/// Calls of external clients and ports inside an open transaction.
pub(crate) fn transaction_hits(rel_path: &str, src: &str) -> Vec<Hit> {
    let lexed = lex(src);
    let code = &lexed.code;
    let tests = test_regions(code);
    let fns = functions(code);
    let calls = external_calls(code, client_file(code));
    let mut out = Vec::new();
    for f in &fns {
        for (a, b) in tx_scopes(code, f) {
            for (at, what) in calls.iter().filter(|(at, _)| a <= *at && *at < b) {
                let line = line_at(code, *at);
                let innermost = enclosing(&fns, *at).is_some_and(|g| std::ptr::eq(g, f));
                if innermost && !in_regions(&tests, line) {
                    out.push(Hit {
                        path: rel_path.to_owned(),
                        function: f.name.clone(),
                        line,
                        message: format!(
                            "`{what}` inside an open database transaction in `{}`; external effects leave through the outbox after commit (T-32 rule 4, OP-3)",
                            f.name
                        ),
                    });
                }
            }
        }
    }
    out
}

/// True if the call at `at` is an argument of a `timeout(…)` call within `body`.
fn under_timeout(code: &str, body: (usize, usize), at: usize) -> bool {
    let bytes = code.as_bytes();
    let mut depth = 0_usize;
    let mut i = at;
    while i > body.0 {
        i = i.saturating_sub(1);
        match bytes.get(i) {
            Some(b')' | b'}' | b']') => depth = depth.saturating_add(1),
            Some(&b @ (b'(' | b'{' | b'[')) => {
                if depth > 0 {
                    depth = depth.saturating_sub(1);
                    continue;
                }
                if b != b'(' {
                    continue;
                }
                let before = code.get(..i).unwrap_or_default().trim_end();
                let start = before
                    .bytes()
                    .rposition(|c| !is_ident(c))
                    .map_or(0, |p| p.saturating_add(1));
                if TIMEOUT_WRAPPERS.contains(&before.get(start..).unwrap_or_default()) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// External client calls that run without a timeout.
pub(crate) fn timeout_hits(rel_path: &str, src: &str) -> Vec<Hit> {
    let lexed = lex(src);
    let code = &lexed.code;
    if !client_file(code) || contains_any(code, CONFIGURED_TIMEOUTS) {
        return Vec::new();
    }
    let tests = test_regions(code);
    let fns = functions(code);
    let mut out = Vec::new();
    for t in CLIENT_CALLS {
        for at in find_token(code, t) {
            let line = line_at(code, at);
            let Some(f) = enclosing(&fns, at) else {
                continue;
            };
            if in_regions(&tests, line) || under_timeout(code, f.body, at) {
                continue;
            }
            out.push(Hit {
                path: rel_path.to_owned(),
                function: f.name.clone(),
                line,
                message: format!(
                    "`{}` in `{}` runs without a timeout; wrap it in `tokio::time::timeout` or configure the client's request timeout (T-32 rule 7)",
                    t.trim_end_matches('('),
                    f.name
                ),
            });
        }
    }
    out.sort_by_key(|h| h.line);
    out
}

/// Parses the allowlist.
pub(crate) fn parse_allowlist(text: &str) -> Result<Allowlist, String> {
    toml::from_str(text).map_err(|e| format!("{ALLOWLIST_FILE}: {e}"))
}

fn violation(rule: &'static str, path: String, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

/// Entries without a spec ID or a reason.
pub(crate) fn unreasoned(rule: &'static str, allow: &[Allowed]) -> Vec<Violation> {
    allow
        .iter()
        .filter(|a| a.id.trim().is_empty() || a.reason.trim().is_empty())
        .map(|a| {
            violation(
                rule,
                ALLOWLIST_FILE.to_owned(),
                format!(
                    "the `{rule}` entry for `{}` needs an id and a reason",
                    a.path
                ),
            )
        })
        .collect()
}

/// Hits not covered by `allow`, then allowlist entries that cover no hit.
pub(crate) fn apply(rule: &'static str, hits: &[Hit], allow: &[Allowed]) -> Vec<Violation> {
    let mut out: Vec<Violation> = hits
        .iter()
        .filter(|h| !allow.iter().any(|a| a.covers(h)))
        .map(|h| violation(rule, format!("{}:{}", h.path, h.line), h.message.clone()))
        .collect();
    out.extend(
        allow
            .iter()
            .filter(|a| !hits.iter().any(|h| a.covers(h)))
            .map(|a| {
                violation(
                    rule,
                    ALLOWLIST_FILE.to_owned(),
                    format!(
                        "the `{rule}` entry for `{}`{} matches nothing; remove it",
                        a.path,
                        a.function
                            .as_ref()
                            .map(|f| format!(" `{f}`"))
                            .unwrap_or_default()
                    ),
                )
            }),
    );
    out
}

fn scanned(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if path.extension().is_some_and(|e| e == "rs")
            && !is_test_file(&rel_path)
            && !is_rule_definition(&rel_path)
        {
            out.push((rel_path, read(&path)?));
        }
    }
    Ok(out)
}

fn allowlist(root: &Path) -> Result<Allowlist, String> {
    parse_allowlist(&read_optional(&root.join(ALLOWLIST_FILE))?.unwrap_or_default())
}

fn run(
    root: &Path,
    rule: &'static str,
    allow: &[Allowed],
    hits: fn(&str, &str) -> Vec<Hit>,
) -> Result<Vec<Violation>, String> {
    let found: Vec<Hit> = scanned(root)?
        .iter()
        .flat_map(|(p, s)| hits(p, s))
        .collect();
    let mut out = unreasoned(rule, allow);
    out.extend(apply(rule, &found, allow));
    Ok(out)
}

pub(crate) fn check_transaction(root: &Path) -> Result<Vec<Violation>, String> {
    run(root, IN_TX, &allowlist(root)?.transaction, transaction_hits)
}

pub(crate) fn check_timeout(root: &Path) -> Result<Vec<Violation>, String> {
    run(root, TIMEOUT, &allowlist(root)?.timeout, timeout_hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NATS_IN_TX: &str = r#"
use async_nats::jetstream;

pub async fn record(pool: &Pool, js: &jetstream::Context) -> Result<(), E> {
    let mut tx = pool.begin(&ledger).await?;
    tx.append(&rec).await?;
    js.send_publish("work.x", msg).await?;
    tx.commit().await?;
    Ok(())
}
"#;

    const NATS_AFTER_COMMIT: &str = r#"
use async_nats::jetstream;

pub async fn record(pool: &Pool, js: &jetstream::Context) -> Result<(), E> {
    let mut tx = pool.begin(&ledger).await?;
    tx.append(&rec).await?;
    tx.commit().await?;
    tokio::time::timeout(WAIT, js.send_publish("work.x", msg)).await??;
    Ok(())
}
"#;

    const PORT_IN_TX_PARAMETER: &str = r"
impl<A: Access> Service<A> {
    async fn grant(&self, tx: &mut LedgerTx<'_>, who: &PartyId) -> Result<(), E> {
        let ctx = self.access.authority(who).await?;
        tx.append(&ctx.into()).await
    }

    async fn ask(&self, who: &PartyId) -> Result<(), E> {
        self.access.authority(who).await?;
        Ok(())
    }
}
";

    const TX_IMPL: &str = r"
impl LedgerTx<'_> {
    pub async fn announce(&mut self) -> Result<(), E> {
        self.bus.publish(event).await
    }
}
";

    const NATS_WITHOUT_TIMEOUT: &str = r#"
use async_nats::jetstream;

impl Bus for JetStreamBus {
    async fn ensure(&self) -> Result<(), E> {
        self.js.create_or_update_stream(cfg).await?;
        Ok(())
    }

    async fn publish(&self, e: Outbound) -> Result<(), E> {
        tokio::time::timeout(self.wait, async {
            self.js.send_publish(e.subject, e.message).await
        })
        .await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    async fn drive(js: &async_nats::jetstream::Context) {
        js.get_stream("x").await.unwrap();
    }
}
"#;

    const CONFIGURED_CLIENT: &str = r"
pub fn context(client: async_nats::Client, wait: Duration) -> async_nats::jetstream::Context {
    async_nats::jetstream::ContextBuilder::new().timeout(wait).build(client)
}

pub async fn ensure(js: &async_nats::jetstream::Context) -> Result<(), E> {
    js.create_or_update_stream(cfg).await?;
    Ok(())
}
";

    fn lines(hits: &[Hit]) -> Vec<(String, usize)> {
        hits.iter().map(|h| (h.function.clone(), h.line)).collect()
    }

    // T-32
    #[test]
    fn t_32_nats_publish_between_begin_and_commit_is_rejected() {
        let hits = transaction_hits("crates/x/src/app.rs", NATS_IN_TX);
        assert_eq!(lines(&hits), vec![("record".to_owned(), 7)], "{hits:?}");
        assert!(hits.iter().all(|h| h.message.contains("T-32 rule 4")));
        assert!(transaction_hits("crates/x/src/app.rs", NATS_AFTER_COMMIT).is_empty());
    }

    // T-32
    #[test]
    fn t_32_port_call_in_a_function_holding_a_transaction_is_rejected() {
        let hits = transaction_hits("crates/x/src/app.rs", PORT_IN_TX_PARAMETER);
        assert_eq!(lines(&hits), vec![("grant".to_owned(), 4)], "{hits:?}");
        let hits = transaction_hits("crates/store/src/x.rs", TX_IMPL);
        assert_eq!(lines(&hits), vec![("announce".to_owned(), 4)], "{hits:?}");
    }

    // T-32
    #[test]
    fn t_32_external_call_without_timeout_is_rejected() {
        let hits = timeout_hits("crates/x/src/adapters.rs", NATS_WITHOUT_TIMEOUT);
        assert_eq!(lines(&hits), vec![("ensure".to_owned(), 6)], "{hits:?}");
        assert!(hits[0].message.contains("T-32 rule 7"));
    }

    // T-32
    #[test]
    fn t_32_client_with_configured_request_timeout_passes() {
        assert!(timeout_hits("crates/x/src/adapters.rs", CONFIGURED_CLIENT).is_empty());
        assert!(timeout_hits("crates/x/src/app.rs", "fn f() { a.flush().await; }").is_empty());
    }

    // T-32
    #[test]
    fn t_32_allowlist_entries_need_a_reason_and_must_match() {
        let timeout = parse_allowlist(
            "[[timeout]]\npath = \"crates/x/src/adapters.rs\"\nfunction = \"ensure\"\nid = \"T-32\"\nreason = \"\"\n",
        )
        .unwrap()
        .timeout;
        assert_eq!(unreasoned(TIMEOUT, &timeout).len(), 1);
        let hits = timeout_hits("crates/x/src/adapters.rs", NATS_WITHOUT_TIMEOUT);
        assert!(apply(TIMEOUT, &hits, &timeout).is_empty());
        let other = Allowed {
            function: Some("gone".to_owned()),
            ..timeout[0].clone()
        };
        let found = apply(TIMEOUT, &hits, &[other]);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[1].message.contains("matches nothing"));
        let dir = Allowed {
            path: "crates/x/".to_owned(),
            function: None,
            ..timeout[0].clone()
        };
        assert!(apply(TIMEOUT, &hits, &[dir]).is_empty());
    }

    // T-32
    #[test]
    fn t_32_repository_allowlist_parses_with_reasons() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let text = std::fs::read_to_string(root.join(ALLOWLIST_FILE)).unwrap();
        let list = parse_allowlist(&text).unwrap();
        assert!(unreasoned(TIMEOUT, &list.timeout).is_empty());
        assert!(unreasoned(IN_TX, &list.transaction).is_empty());
    }
}
