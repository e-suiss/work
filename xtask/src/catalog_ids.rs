//! Work rule ID recognition shared by the spec reader, the test scanner and the
//! comment rule (T-46, T-47, T-53).

/// Work ID families (Ek A); every ID is `FAMILY-<number>`.
pub(crate) const FAMILIES: &[&str] = &[
    "MD", "F", "L", "MKT", "C", "INV", "E", "X", "CM", "RC", "ST", "EV", "FD", "SEC", "P", "PR",
    "T", "OP", "OQ",
];

/// Product names that prefix IDs of other Suiss specs ("Access OP-73").
pub(crate) const PRODUCTS: &[&str] = &["Access", "Relay", "One"];

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The Work family of `id`, or `None` when it is not a Work ID.
pub(crate) fn family(id: &str) -> Option<&'static str> {
    let (prefix, rest) = id.split_once('-')?;
    if !all_digits(rest) || rest.starts_with('0') {
        return None;
    }
    FAMILIES.iter().find(|f| **f == prefix).copied()
}

/// The number of a Work ID.
pub(crate) fn number(id: &str) -> u32 {
    id.rsplit('-')
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// One ID-shaped token with its byte span; `foreign` when another product prefixes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) text: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) foreign: bool,
}

fn previous_word(text: &str, at: usize) -> &str {
    let before = text.get(..at).unwrap_or_default().trim_end();
    let start = before
        .rfind(|c: char| !c.is_alphanumeric())
        .map_or(0, |p| p.saturating_add(1));
    before.get(start..).unwrap_or_default()
}

/// Every Work-family-shaped token in `text`, in order.
pub(crate) fn ids_in(text: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'-';
    let mut i = 0;
    while i < bytes.len() {
        if !bytes.get(i).copied().is_some_and(is_word) {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        while bytes.get(i).copied().is_some_and(is_word) {
            i = i.saturating_add(1);
        }
        let raw = text.get(start..i).unwrap_or_default();
        let trimmed = raw.trim_matches('-');
        let offset = raw.len().saturating_sub(raw.trim_start_matches('-').len());
        let tstart = start.saturating_add(offset);
        if family(trimmed).is_some() {
            out.push(Token {
                text: trimmed.to_owned(),
                start: tstart,
                end: tstart.saturating_add(trimmed.len()),
                foreign: PRODUCTS.contains(&previous_word(text, tstart)),
            });
        }
    }
    out
}

/// Work IDs in `text` (not other products'), with ranges such as `INV-1…INV-35`
/// expanded.
pub(crate) fn work_ids_expanded(text: &str) -> Vec<String> {
    let tokens: Vec<Token> = ids_in(text).into_iter().filter(|t| !t.foreign).collect();
    let mut out = Vec::new();
    let mut k = 0;
    while let Some(t) = tokens.get(k) {
        let next = tokens.get(k.saturating_add(1));
        let between = next.map(|n| text.get(t.end..n.start).unwrap_or_default().trim());
        if let (Some(n), Some("…" | "–" | "..." | "—")) = (next, between) {
            out.extend(expand_range(&t.text, &n.text));
            k = k.saturating_add(2);
            continue;
        }
        out.push(t.text.clone());
        k = k.saturating_add(1);
    }
    out
}

/// Expands `INV-1`…`INV-3` into its members when both ends share a family.
pub(crate) fn expand_range(from: &str, to: &str) -> Vec<String> {
    match (family(from), family(to)) {
        (Some(a), Some(b)) if a == b => {
            let (lo, hi) = (number(from), number(to));
            if lo <= hi && hi.saturating_sub(lo) < 200 {
                (lo..=hi).map(|n| format!("{a}-{n}")).collect()
            } else {
                vec![from.to_owned(), to.to_owned()]
            }
        }
        _ => vec![from.to_owned(), to.to_owned()],
    }
}

/// The IDs a test function name cites: the leading run of `family_number`
/// segments (`md_15_f_9_p_2_paid_feature_is_rejected` → MD-15, F-9, P-2).
pub(crate) fn name_ids(name: &str) -> Vec<String> {
    let segs: Vec<&str> = name.split('_').collect();
    let mut out = Vec::new();
    let mut k = 0;
    while let (Some(f), Some(n)) = (segs.get(k), segs.get(k.saturating_add(1))) {
        let fam = f.to_ascii_uppercase();
        let id = format!("{fam}-{n}");
        if family(&id).is_none() {
            break;
        }
        out.push(id);
        k = k.saturating_add(2);
    }
    out
}

/// True if a token can be another product's ID (`OP-73`, `E7`, `TI-9`, `B21`).
fn foreign_id(token: &str) -> bool {
    let t = token.trim_end_matches([',', ';', ')']);
    t.starts_with('§')
        || (t.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && t.chars().any(|c| c.is_ascii_digit())
            && t.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '.'))
}

/// True if a comment body is only spec IDs: `T-31`, `T-36 OP-12`, `T-31 (rule 4)`,
/// `F-9 #15`, `Access OP-72`, `Relay T-72`.
pub(crate) fn is_bare_id_line(body: &str) -> bool {
    let tokens: Vec<&str> = body
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '/')
        .filter(|t| !t.is_empty())
        .collect();
    let mut has_id = false;
    let mut k = 0;
    while let Some(tok) = tokens.get(k) {
        let t = tok.trim_start_matches('(').trim_end_matches(')');
        if family(t).is_some() {
            has_id = true;
        } else if PRODUCTS.contains(&t) {
            let Some(next) = tokens.get(k.saturating_add(1)) else {
                return false;
            };
            if !foreign_id(next) {
                return false;
            }
            has_id = true;
            k = k.saturating_add(1);
        } else if !(matches!(t, "rule" | "rules" | "item")
            || all_digits(t)
            || t.strip_prefix('#').is_some_and(all_digits))
        {
            return false;
        }
        k = k.saturating_add(1);
    }
    has_id
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-47
    #[test]
    fn t_47_work_families_are_recognised() {
        assert_eq!(family("INV-2"), Some("INV"));
        assert_eq!(family("T-47"), Some("T"));
        assert_eq!(family("MKT-1"), Some("MKT"));
        for word in ["INV", "UTF-8", "TI-9", "G38", "T-0", "SA-21", "X-L1"] {
            assert_eq!(family(word), None, "{word}");
        }
    }

    // T-47
    #[test]
    fn t_47_foreign_ids_are_marked() {
        let found: Vec<(String, bool)> = ids_in("T-36 (Access OP-73), Relay T-72; OP-12")
            .into_iter()
            .map(|t| (t.text, t.foreign))
            .collect();
        assert_eq!(
            found,
            [
                ("T-36".to_owned(), false),
                ("OP-73".to_owned(), true),
                ("T-72".to_owned(), true),
                ("OP-12".to_owned(), false)
            ]
        );
    }

    // T-46
    #[test]
    fn t_46_ranges_expand_within_one_family() {
        assert_eq!(
            work_ids_expanded("INV-1…INV-3, T-31"),
            ["INV-1", "INV-2", "INV-3", "T-31"]
        );
        assert_eq!(expand_range("T-1", "OP-3"), ["T-1", "OP-3"]);
    }

    // T-47
    #[test]
    fn t_47_test_names_cite_their_leading_ids() {
        assert_eq!(
            name_ids("md_15_f_9_p_2_paid_feature_is_rejected"),
            ["MD-15", "F-9", "P-2"]
        );
        assert_eq!(
            name_ids("t_47_unknown_rule_id_in_test_is_rejected"),
            ["T-47"]
        );
        assert!(name_ids("parse_x_values").is_empty());
        assert!(name_ids("utf_8_text").is_empty());
    }

    // T-53
    #[test]
    fn t_53_bare_id_lines_are_recognised() {
        for ok in [
            "T-31",
            "T-36 OP-12",
            "T-31, T-54",
            "T-31 (rule 4)",
            "F-9 #15",
            "Access OP-72",
            "Relay T-72 T-41",
            "T-51, E-2, MD-3",
        ] {
            assert!(is_bare_id_line(ok), "{ok}");
        }
        for bad in [
            "",
            "Access",
            "T-31 keeps the kernel pure",
            "see T-31",
            "Default owner for the whole repository.",
        ] {
            assert!(!is_bare_id_line(bad), "{bad}");
        }
    }
}
