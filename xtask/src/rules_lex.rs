//! A small Rust lexer for the source rules.

/// A string literal and the line it starts on (1-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lit {
    pub(crate) line: usize,
    pub(crate) text: String,
}

/// The views of one Rust source file.
#[derive(Debug, Default)]
pub(crate) struct Lexed {
    /// The source with comments and string/char literal contents replaced by
    /// spaces. Newlines are kept, so `code.lines()` lines up with the source.
    pub(crate) code: String,
    /// String literal contents (normal, byte, C and raw strings).
    pub(crate) strings: Vec<Lit>,
    /// Comment texts, including doc comments.
    pub(crate) comments: Vec<Lit>,
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Cursor over the source characters that fills the three views.
struct Lexer {
    chars: Vec<char>,
    i: usize,
    line: usize,
    out: Lexed,
}

impl Lexer {
    fn at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.i.saturating_add(offset)).copied()
    }

    fn prev(&self, back: usize) -> Option<char> {
        self.i
            .checked_sub(back)
            .and_then(|p| self.chars.get(p))
            .copied()
    }

    /// Consumes one character into `text` (if any) and blanks it in the code view.
    fn take_blank(&mut self, text: Option<&mut String>) {
        if let Some(c) = self.at(0) {
            if c == '\n' {
                self.line = self.line.saturating_add(1);
                self.out.code.push('\n');
            } else {
                self.out.code.push(' ');
            }
            if let Some(t) = text {
                t.push(c);
            }
        }
        self.i = self.i.saturating_add(1);
    }

    fn line_comment(&mut self) {
        let line = self.line;
        let mut text = String::new();
        while self.at(0).is_some_and(|c| c != '\n') {
            self.take_blank(Some(&mut text));
        }
        self.out.comments.push(Lit { line, text });
    }

    fn block_comment(&mut self) {
        let line = self.line;
        let mut text = String::new();
        let mut depth = 0_usize;
        while self.at(0).is_some() {
            let pair = (self.at(0), self.at(1));
            if pair == (Some('/'), Some('*')) {
                depth = depth.saturating_add(1);
            } else if pair == (Some('*'), Some('/')) {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    self.take_blank(Some(&mut text));
                    self.take_blank(Some(&mut text));
                    break;
                }
            }
            self.take_blank(Some(&mut text));
        }
        self.out.comments.push(Lit { line, text });
    }

    /// At an `r`: if it starts a raw string (`r"`, `r#"`, `br"`, `cr#"`), the
    /// number of `#`s; otherwise `None`.
    fn raw_string_hashes(&self) -> Option<usize> {
        let prefix_ok = match self.prev(1) {
            Some('b' | 'c') => !self.prev(2).is_some_and(is_ident),
            Some(p) => !is_ident(p),
            None => true,
        };
        if !prefix_ok {
            return None;
        }
        let mut hashes = 0_usize;
        while self.at(hashes.saturating_add(1)) == Some('#') {
            hashes = hashes.saturating_add(1);
        }
        (self.at(hashes.saturating_add(1)) == Some('"')).then_some(hashes)
    }

    fn raw_string(&mut self, hashes: usize) {
        let line = self.line;
        for _ in 0..hashes.saturating_add(2) {
            self.take_blank(None);
        }
        let mut text = String::new();
        while let Some(c) = self.at(0) {
            if c == '"' && (1..=hashes).all(|k| self.at(k) == Some('#')) {
                for _ in 0..=hashes {
                    self.take_blank(None);
                }
                break;
            }
            self.take_blank(Some(&mut text));
        }
        self.out.strings.push(Lit { line, text });
    }

    fn string(&mut self) {
        let line = self.line;
        self.take_blank(None);
        let mut text = String::new();
        while let Some(c) = self.at(0) {
            if c == '"' {
                self.take_blank(None);
                break;
            }
            if c == '\\' {
                self.take_blank(Some(&mut text));
            }
            self.take_blank(Some(&mut text));
        }
        self.out.strings.push(Lit { line, text });
    }

    /// At a `'`: the length of a char literal ('x' or '\..'), or `None` for a
    /// lifetime or label.
    fn char_literal_len(&self) -> Option<usize> {
        if self.at(1) == Some('\\') {
            (2..self.chars.len().saturating_sub(self.i))
                .find(|&k| self.at(k) == Some('\''))
                .map(|end| end.saturating_add(1))
        } else if self.at(2) == Some('\'') {
            Some(3)
        } else {
            None
        }
    }

    fn run(mut self) -> Lexed {
        while let Some(c) = self.at(0) {
            match (c, self.at(1)) {
                ('/', Some('/')) => self.line_comment(),
                ('/', Some('*')) => self.block_comment(),
                ('"', _) => self.string(),
                ('r', _) if self.raw_string_hashes().is_some() => {
                    let hashes = self.raw_string_hashes().unwrap_or_default();
                    self.raw_string(hashes);
                }
                ('\'', _) if self.char_literal_len().is_some() => {
                    for _ in 0..self.char_literal_len().unwrap_or_default() {
                        self.take_blank(None);
                    }
                }
                _ => {
                    if c == '\n' {
                        self.line = self.line.saturating_add(1);
                    }
                    self.out.code.push(c);
                    self.i = self.i.saturating_add(1);
                }
            }
        }
        self.out
    }
}

/// Splits Rust source into code, string literal and comment views.
pub(crate) fn lex(src: &str) -> Lexed {
    Lexer {
        chars: src.chars().collect(),
        i: 0,
        line: 1,
        out: Lexed::default(),
    }
    .run()
}

/// Returns the 1-based line ranges (inclusive) of test-only code in the code view:
/// items annotated with `#[cfg(test)]` or `#[test]`.
pub(crate) fn test_regions(code: &str) -> Vec<(usize, usize)> {
    let chars: Vec<char> = code.chars().collect();
    let squeezed: Vec<(usize, char)> = chars
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, c)| !c.is_whitespace())
        .collect();
    let line_of = |pos: usize| -> usize {
        chars
            .iter()
            .take(pos)
            .filter(|&&c| c == '\n')
            .count()
            .saturating_add(1)
    };
    let mut regions = Vec::new();
    for marker in ["#[cfg(test)]", "#[test]"] {
        let needle: Vec<char> = marker.chars().collect();
        let mut k = 0_usize;
        while k.saturating_add(needle.len()) <= squeezed.len() {
            let matches = needle
                .iter()
                .enumerate()
                .all(|(n, ch)| squeezed.get(k.saturating_add(n)).map(|&(_, c)| c) == Some(*ch));
            if !matches {
                k = k.saturating_add(1);
                continue;
            }
            let Some(&(start, _)) = squeezed.get(k) else {
                break;
            };
            let after = squeezed
                .get(k.saturating_add(needle.len()).saturating_sub(1))
                .map_or(start, |&(p, _)| p.saturating_add(1));
            let end = item_end(&chars, after);
            regions.push((line_of(start), line_of(end)));
            k = k.saturating_add(needle.len());
        }
    }
    regions
}

/// Finds the end of the item starting at `from`: the matching `}` of its first
/// brace block, or the first `;` if that comes first.
fn item_end(chars: &[char], from: usize) -> usize {
    let mut depth = 0_usize;
    let mut i = from;
    while let Some(&c) = chars.get(i) {
        match c {
            ';' if depth == 0 => return i,
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    chars.len().saturating_sub(1)
}

/// True if `line` falls in one of `regions`.
pub(crate) fn in_regions(regions: &[(usize, usize)], line: usize) -> bool {
    regions.iter().any(|&(a, b)| a <= line && line <= b)
}

/// Finds `needle` in `hay` at identifier boundaries (the characters around the
/// match are not identifier characters where the needle itself starts or ends
/// with one). Returns byte offsets.
pub(crate) fn find_token(hay: &str, needle: &str) -> Vec<usize> {
    let starts_ident = needle.chars().next().is_some_and(is_ident);
    let ends_ident = needle.chars().last().is_some_and(is_ident);
    hay.match_indices(needle)
        .filter(|&(at, _)| {
            let before = hay.get(..at).and_then(|s| s.chars().last());
            let after = hay
                .get(at.saturating_add(needle.len())..)
                .and_then(|s| s.chars().next());
            (!starts_ident || !before.is_some_and(is_ident))
                && (!ends_ident || !after.is_some_and(is_ident))
        })
        .map(|(at, _)| at)
        .collect()
}

/// The 1-based line number of byte offset `at` in `text`.
pub(crate) fn line_at(text: &str, at: usize) -> usize {
    text.get(..at)
        .map_or(0, |s| s.matches('\n').count())
        .saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_52_comments_and_strings_are_blanked_in_code_view() {
        let l = lex("let a = \"std::fs\"; // std::net\nlet b = 1;");
        assert!(!l.code.contains("std::fs"));
        assert!(!l.code.contains("std::net"));
        assert_eq!(
            l.strings,
            vec![Lit {
                line: 1,
                text: "std::fs".into()
            }]
        );
        assert_eq!(l.comments.len(), 1);
        assert_eq!(l.code.lines().count(), 2);
    }

    #[test]
    fn t_52_raw_strings_and_lifetimes_are_lexed() {
        let l = lex("fn f<'a>(x: &'a str) { let q = r#\"say \"hi\" t\"#; let c = '}'; }");
        assert_eq!(l.strings.len(), 1);
        assert!(l.strings.first().is_some_and(|s| s.text.contains("hi")));
        assert!(l.code.contains("<'a>"));
        assert_eq!(l.code.matches('}').count(), 1);
    }

    #[test]
    fn t_52_nested_block_comments_end_at_the_outer_close() {
        let l = lex("/* a /* b */ c */ code");
        assert!(l.code.contains("code"));
        assert!(!l.code.contains('c') || l.code.trim() == "code");
    }

    #[test]
    fn t_52_cfg_test_module_is_a_test_region() {
        let src = "fn real() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn after() {}\n";
        let regions = test_regions(&lex(src).code);
        assert_eq!(regions, vec![(2, 5)]);
        assert!(!in_regions(&regions, 6));
    }

    #[test]
    fn t_52_tokens_match_only_at_identifier_boundaries() {
        assert_eq!(find_token("unsafe_code unsafe {", "unsafe"), vec![12]);
        assert_eq!(find_token("my_tokio::x", "tokio::"), Vec::<usize>::new());
    }
}
