//! A small YAML subset reader for workflow and compose files: block mappings,
//! block sequences, flow sequences and mappings of scalars, quoted scalars, block
//! scalars and comments; anchors are dropped and aliases stay scalars.

/// A YAML node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    Scalar(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

impl Node {
    /// The value under `key` when this is a mapping.
    pub(crate) fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The mapping entries, or none.
    pub(crate) fn entries(&self) -> &[(String, Node)] {
        match self {
            Node::Map(entries) => entries,
            _ => &[],
        }
    }

    /// The scalar text, if this is a scalar.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Node::Scalar(s) => Some(s),
            _ => None,
        }
    }

    /// Every scalar in this node, depth first (mapping keys excluded).
    pub(crate) fn scalars(&self) -> Vec<&str> {
        match self {
            Node::Scalar(s) => vec![s.as_str()],
            Node::Seq(items) => items.iter().flat_map(Node::scalars).collect(),
            Node::Map(entries) => entries.iter().flat_map(|(_, v)| v.scalars()).collect(),
        }
    }

    /// The keys of a mapping, the scalars of a sequence, or the scalar itself.
    pub(crate) fn names(&self) -> Vec<&str> {
        match self {
            Node::Scalar(s) => vec![s.as_str()],
            Node::Seq(items) => items.iter().filter_map(Node::as_str).collect(),
            Node::Map(entries) => entries.iter().map(|(k, _)| k.as_str()).collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct Line {
    indent: usize,
    text: String,
}

/// Removes a trailing comment: a `#` at the start or after whitespace, outside quotes.
pub(crate) fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' && prev_space => return line.get(..i).unwrap_or(line),
            _ => {}
        }
        prev_space = c.is_whitespace();
    }
    line
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    let quoted = t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')));
    if quoted {
        t.get(1..t.len().saturating_sub(1))
            .unwrap_or_default()
            .to_owned()
    } else {
        t.to_owned()
    }
}

fn split_flow(inner: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0_usize;
    let mut quote: Option<char> = None;
    let mut cur = String::new();
    for c in inner.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '\'' => quote = Some(c),
                '[' | '{' => depth = depth.saturating_add(1),
                ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    parts.push(std::mem::take(&mut cur));
                    continue;
                }
                _ => {}
            },
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts.into_iter().map(|p| p.trim().to_owned()).collect()
}

fn inline(value: &str) -> Node {
    let v = value.trim();
    if let Some(inner) = v.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return Node::Seq(split_flow(inner).iter().map(|p| inline(p)).collect());
    }
    if let Some(inner) = v.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
        return Node::Map(
            split_flow(inner)
                .iter()
                .filter_map(|p| split_key(p))
                .map(|(k, rest)| (k, inline(&rest)))
                .collect(),
        );
    }
    Node::Scalar(unquote(v))
}

fn split_key(text: &str) -> Option<(String, String)> {
    let mut quote: Option<char> = None;
    let mut depth = 0_usize;
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    for (k, &(i, c)) in chars.iter().enumerate() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '\'' if i == 0 => quote = Some(c),
                '[' | '{' => depth = depth.saturating_add(1),
                ']' | '}' => depth = depth.saturating_sub(1),
                ':' if depth == 0 => {
                    let next = chars.get(k.saturating_add(1)).map(|&(_, n)| n);
                    if next.is_none_or(char::is_whitespace) {
                        let key = unquote(text.get(..i).unwrap_or_default());
                        let rest = text.get(i.saturating_add(1)..).unwrap_or_default().trim();
                        return Some((key, rest.to_owned()));
                    }
                }
                _ => {}
            },
        }
    }
    None
}

fn is_block_scalar(rest: &str) -> bool {
    let r = rest.trim();
    r.starts_with('|') || r.starts_with('>')
}

fn drop_anchor(rest: &str) -> &str {
    let r = rest.trim();
    if r.starts_with('&') {
        r.split_once(char::is_whitespace)
            .map_or("", |(_, v)| v.trim())
    } else {
        r
    }
}

struct Parser {
    lines: Vec<Line>,
    numbers: Vec<usize>,
    raw: Vec<(usize, String)>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Line> {
        self.lines.get(self.i)
    }

    fn is_item(text: &str) -> bool {
        text == "-" || text.starts_with("- ")
    }

    fn block(&mut self, indent: usize) -> Node {
        match self.peek() {
            Some(l) if l.indent == indent && Self::is_item(&l.text) => self.seq(indent),
            Some(l) if l.indent == indent => self.map(indent),
            _ => Node::Scalar(String::new()),
        }
    }

    fn value_after_key(&mut self, indent: usize, rest: &str, raw_line: usize) -> Node {
        let rest = drop_anchor(rest);
        if is_block_scalar(rest) {
            return Node::Scalar(self.block_scalar(indent, raw_line));
        }
        if !rest.is_empty() {
            return inline(rest);
        }
        match self.peek() {
            Some(l) if l.indent > indent => {
                let child = l.indent;
                self.block(child)
            }
            Some(l) if l.indent == indent && Self::is_item(&l.text) => self.seq(indent),
            _ => Node::Scalar(String::new()),
        }
    }

    fn block_scalar(&mut self, indent: usize, raw_line: usize) -> String {
        let mut text = Vec::new();
        let start = self
            .raw
            .iter()
            .position(|(n, _)| *n > raw_line)
            .unwrap_or(self.raw.len());
        let mut last = raw_line;
        for (n, line) in self.raw.iter().skip(start) {
            let blank = line.trim().is_empty();
            let ind = line.len().saturating_sub(line.trim_start().len());
            if !blank && ind <= indent {
                break;
            }
            text.push(line.trim().to_owned());
            last = *n;
        }
        while self.i < self.lines.len() && self.line_no(self.i) <= last {
            self.i = self.i.saturating_add(1);
        }
        text.join("\n").trim().to_owned()
    }

    fn line_no(&self, idx: usize) -> usize {
        self.numbers.get(idx).copied().unwrap_or(usize::MAX)
    }

    fn map(&mut self, indent: usize) -> Node {
        let mut entries = Vec::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent != indent || Self::is_item(&line.text) {
                break;
            }
            let raw_line = self.line_no(self.i);
            self.i = self.i.saturating_add(1);
            let Some((key, rest)) = split_key(&line.text) else {
                continue;
            };
            let value = self.value_after_key(indent, &rest, raw_line);
            entries.push((key, value));
        }
        Node::Map(entries)
    }

    fn seq(&mut self, indent: usize) -> Node {
        let mut items = Vec::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent != indent || !Self::is_item(&line.text) {
                break;
            }
            let rest = line.text.get(1..).unwrap_or_default();
            let content = rest.trim_start();
            let offset = line.text.len().saturating_sub(content.len());
            if content.is_empty() {
                self.i = self.i.saturating_add(1);
                let item = match self.peek() {
                    Some(l) if l.indent > indent => {
                        let child = l.indent;
                        self.block(child)
                    }
                    _ => Node::Scalar(String::new()),
                };
                items.push(item);
            } else if split_key(content).is_some()
                && !content.starts_with('[')
                && !content.starts_with('{')
            {
                let child = indent.saturating_add(offset);
                if let Some(l) = self.lines.get_mut(self.i) {
                    *l = Line {
                        indent: child,
                        text: content.to_owned(),
                    };
                }
                items.push(self.map(child));
            } else {
                self.i = self.i.saturating_add(1);
                items.push(inline(content));
            }
        }
        Node::Seq(items)
    }
}

/// Parses a YAML document into a [`Node`].
pub(crate) fn parse(text: &str) -> Node {
    let raw: Vec<(usize, String)> = text
        .lines()
        .enumerate()
        .map(|(n, l)| (n, l.to_owned()))
        .collect();
    let mut lines = Vec::new();
    let mut numbers = Vec::new();
    for (n, l) in &raw {
        let stripped = strip_comment(l).trim_end();
        let content = stripped.trim_start();
        if content.is_empty() || content == "---" || content == "..." {
            continue;
        }
        lines.push(Line {
            indent: stripped.len().saturating_sub(content.len()),
            text: content.to_owned(),
        });
        numbers.push(*n);
    }
    let indent = lines.first().map_or(0, |l| l.indent);
    let mut parser = Parser {
        lines,
        raw,
        i: 0,
        numbers,
    };
    parser.block(indent)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKFLOW: &str = r##"
name: bench # T-62
on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:
jobs:
  wallclock:
    runs-on: [self-hosted, bench]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
      - name: Run
        run: |
          cargo bench # not a key: value
          echo "#done"
"##;

    // T-52
    #[test]
    fn t_52_workflow_structure_is_read() {
        let doc = parse(WORKFLOW);
        assert_eq!(doc.get("name").and_then(Node::as_str), Some("bench"));
        let on = doc.get("on").unwrap();
        assert_eq!(on.names(), ["schedule", "workflow_dispatch"]);
        let job = doc.get("jobs").and_then(|j| j.get("wallclock")).unwrap();
        assert_eq!(
            job.get("runs-on").unwrap().scalars(),
            ["self-hosted", "bench"]
        );
        assert_eq!(
            job.get("if").and_then(Node::as_str),
            Some("github.ref == 'refs/heads/main'")
        );
        let steps = job.get("steps").unwrap();
        let Node::Seq(items) = steps else { panic!() };
        assert_eq!(items.len(), 2);
        let run = items[1].get("run").and_then(Node::as_str).unwrap();
        assert!(run.contains("cargo bench"));
        assert!(run.contains("echo"));
    }

    // T-52
    #[test]
    fn t_52_compose_services_profiles_and_anchors_are_read() {
        let doc = parse(
            "x-h: &h\n  restart: always\nservices:\n  access:\n    <<: *h\n    image: \"ghcr.io/e-suiss/access:unpublished\"\n    profiles: [access]\n  nats:\n    image: nats@sha256:ab # 2.15\n    command:\n      - --config\n",
        );
        let services = doc.get("services").unwrap();
        let access = services.get("access").unwrap();
        assert_eq!(
            access.get("image").and_then(Node::as_str),
            Some("ghcr.io/e-suiss/access:unpublished")
        );
        assert_eq!(access.get("profiles").unwrap().scalars(), ["access"]);
        assert_eq!(
            services
                .get("nats")
                .and_then(|n| n.get("image"))
                .and_then(Node::as_str),
            Some("nats@sha256:ab")
        );
        assert_eq!(
            doc.get("x-h")
                .and_then(|h| h.get("restart"))
                .and_then(Node::as_str),
            Some("always")
        );
    }

    // T-52
    #[test]
    fn t_52_scalar_and_flow_triggers_are_read() {
        assert_eq!(parse("on: push\n").get("on").unwrap().names(), ["push"]);
        assert_eq!(
            parse("on: [push, pull_request]\n")
                .get("on")
                .unwrap()
                .names(),
            ["push", "pull_request"]
        );
    }
}
