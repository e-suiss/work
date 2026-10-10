//! `no-dev-mode` (T-32 rule 9, T-41 rule 3, T-45): no development or test mode
//! and no switch that skips signing, verification, Access, Relay or the key store.
//! Identifiers and string literals in non-test Rust code, and keys and values in
//! configuration files, must not name one.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, lex, test_regions};

const RULE: &str = "no-dev-mode";

/// Reviewed exceptions: (relative path, matched phrase, reason). Empty on purpose.
const ALLOWLIST: &[(&str, &str, &str)] = &[];

const SELF_PATH: &str = "xtask/src/rules_switches.rs";

const CONFIG_EXTENSIONS: &[&str] = &["toml", "yml", "yaml", "json", "env", "ini", "conf", "cfg"];

const CONFIG_SKIP_PREFIXES: &[&str] = &["supply-chain/", "conformance/catalog/"];

const GUARDED: &[&str] = &[
    "signature",
    "signatures",
    "signing",
    "sign",
    "verify",
    "verification",
    "verifier",
    "access",
    "relay",
    "hsm",
    "pkcs11",
    "auth",
    "authz",
    "authorization",
    "authentication",
    "tls",
    "checks",
    "check",
];

/// Splits an identifier or literal into lower-case words.
pub(crate) fn words(atom: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = atom.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let prev = i.checked_sub(1).and_then(|p| chars.get(p)).copied();
        let next = chars.get(i.saturating_add(1)).copied();
        let boundary = c.is_uppercase()
            && prev.is_some_and(|p| {
                p.is_lowercase() || (p.is_uppercase() && next.is_some_and(char::is_lowercase))
            });
        if boundary && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn guarded(word: &str) -> bool {
    GUARDED.contains(&word) || word.starts_with("verif") || word.starts_with("auth")
}

/// The forbidden phrase in an atom, if any.
pub(crate) fn forbidden_phrase(atom: &str) -> Option<String> {
    let w = words(atom);
    for (i, word) in w.iter().enumerate() {
        let next = w.get(i.saturating_add(1)).map_or("", String::as_str);
        let prev = i
            .checked_sub(1)
            .and_then(|p| w.get(p))
            .map_or("", String::as_str);
        let hit = match word.as_str() {
            "dev" | "test" | "debug" | "demo" if next == "mode" => Some(format!("{word}_{next}")),
            "devmode" | "testmode" | "debugmode" => Some(word.clone()),
            "skip" | "without" | "bypass" | "disable" | "disabled" | "no" | "fake" | "mock"
            | "stub"
                if guarded(next) =>
            {
                Some(format!("{word}_{next}"))
            }
            "allow" | "accept" if next.starts_with("insecure") || next == "invalid" => {
                Some(format!("{word}_{next}"))
            }
            w if w.starts_with("insecure")
                || w.starts_with("bypass")
                || w.starts_with("danger")
                || w.starts_with("skipverif")
                || w.starts_with("skipsignature")
                || w.starts_with("noverify")
                || w.starts_with("disableauth") =>
            {
                Some(w.to_owned())
            }
            _ => None,
        };
        let negated = prev == "no" && !guarded(word);
        if hit.is_some() && !negated {
            return hit;
        }
    }
    None
}

fn allowlisted(rel_path: &str, phrase: &str) -> bool {
    ALLOWLIST
        .iter()
        .any(|(p, w, _)| *p == rel_path && *w == phrase)
}

fn message(phrase: &str) -> String {
    format!(
        "`{phrase}`: no development mode and no switch that skips signing, verification, Access, Relay or the key store (T-32 rule 9, T-41 rule 3)"
    )
}

/// Violations in a Rust file's non-test identifiers and string literals.
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut atoms: Vec<(usize, String)> = Vec::new();
    for (i, line) in lexed.code.lines().enumerate() {
        let n = i.saturating_add(1);
        for ident in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if !ident.is_empty() {
                atoms.push((n, ident.to_owned()));
            }
        }
    }
    atoms.extend(lexed.strings.iter().map(|l| (l.line, l.text.clone())));
    atoms
        .into_iter()
        .filter(|(line, _)| !in_regions(&tests, *line))
        .filter_map(|(line, atom)| forbidden_phrase(&atom).map(|p| (line, p)))
        .filter(|(_, p)| !allowlisted(rel_path, p))
        .map(|(line, p)| Violation {
            rule: RULE,
            path: PathBuf::from(format!("{rel_path}:{line}")),
            message: message(&p),
        })
        .collect()
}

/// Violations in a configuration file; `#` comments are skipped.
pub(crate) fn config_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let content = crate::rules::comments::hash_comment(line)
            .map_or(line, |(at, _)| line.get(..at).unwrap_or(line));
        for atom in content.split(|c: char| c.is_whitespace() || "\"'=:,[]{}()".contains(c)) {
            if let Some(p) = forbidden_phrase(atom).filter(|p| !allowlisted(rel_path, p)) {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(format!("{rel_path}:{}", i.saturating_add(1))),
                    message: message(&p),
                });
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if rel_path == SELF_PATH || crate::rules::source::is_rule_definition(&rel_path) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if ext == "rs" {
            if !is_test_file(&rel_path) {
                out.extend(rust_violations(&rel_path, &read(&path)?));
            }
        } else if (CONFIG_EXTENSIONS.contains(&ext) || name.starts_with(".env"))
            && !CONFIG_SKIP_PREFIXES.iter().any(|p| rel_path.starts_with(p))
        {
            out.extend(config_violations(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-32
    #[test]
    fn t_32_identifiers_are_split_into_words() {
        assert_eq!(
            words("allowInsecureHTTPServer"),
            vec!["allow", "insecure", "http", "server"]
        );
        assert_eq!(words("SKIP_SIGNATURE"), vec!["skip", "signature"]);
    }

    // T-32 T-41 MD-14
    #[test]
    fn t_32_dev_mode_and_security_skipping_switches_are_rejected() {
        for atom in [
            "dev_mode",
            "WORK_TEST_MODE",
            "skip_signature",
            "skipVerification",
            "without_access",
            "without_relay",
            "no_verify",
            "noVerify",
            "allow_insecure",
            "insecure",
            "bypass_access",
            "disable_auth",
            "fake_access",
            "mock_relay",
            "danger_accept_invalid_certs",
            "skip_hsm",
        ] {
            assert!(forbidden_phrase(atom).is_some(), "{atom}");
        }
    }

    // T-32
    #[test]
    fn t_32_ordinary_words_are_accepted() {
        for atom in [
            "no-dev-mode",
            "no_dev_mode",
            "access_client",
            "relay_waitpoint",
            "verification_result",
            "mode",
            "developer",
            "test_vectors",
            "authentication",
            "no-new-privileges",
            "signature_bytes",
        ] {
            assert!(forbidden_phrase(atom).is_none(), "{atom}");
        }
    }

    // T-32 T-41
    #[test]
    fn t_32_flags_in_code_are_rejected_but_comments_and_tests_are_not() {
        assert_eq!(
            rust_violations("a.rs", "struct C { skip_signature: bool }").len(),
            1
        );
        assert_eq!(
            rust_violations("a.rs", "fn f() { env(\"WORK_WITHOUT_ACCESS\"); }").len(),
            1
        );
        let src = "// a bypass is rejected\n#[cfg(test)]\nmod tests { fn insecure_url_is_rejected() {} }\n";
        assert!(rust_violations("a.rs", src).is_empty());
    }

    // T-32 T-41
    #[test]
    fn t_32_config_key_naming_a_weakening_switch_is_rejected() {
        let v = config_violations(
            "deploy/a.toml",
            "# insecure is not allowed\nwithout_relay = true\nname = \"work\"\n",
        );
        assert_eq!(v.len(), 1);
        assert!(v[0].path.ends_with("deploy/a.toml:2"));
    }
}
