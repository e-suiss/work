//! Architecture and code rules (T-4, T-22, T-31, T-32, T-33, T-36, T-53, T-75, OP-28, SEC-24); each
//! check lives in a `rules_*` module.

#[path = "rules_async.rs"]
mod asynchrony;
#[path = "rules_clippy.rs"]
mod clippy;
#[path = "rules_comments.rs"]
pub(crate) mod comments;
#[path = "rules_deps.rs"]
pub(crate) mod deps;
#[path = "rules_derived.rs"]
mod derived;
#[path = "rules_files.rs"]
pub(crate) mod files;
#[path = "rules_kernel.rs"]
mod kernel;
#[path = "rules_lex.rs"]
pub(crate) mod lex;
#[path = "rules_migrations.rs"]
mod migrations;
#[path = "rules_profile.rs"]
mod profile;
#[path = "rules_source.rs"]
pub(crate) mod source;
#[path = "rules_switches.rs"]
pub(crate) mod switches;

use crate::Check;

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "dependency-direction",
            run: deps::check,
        },
        Check {
            name: "kernel",
            run: kernel::check,
        },
        Check {
            name: "kernel-purity",
            run: source::check_purity,
        },
        Check {
            name: "sql-only-in-store",
            run: source::check_sql,
        },
        Check {
            name: "no-physical-delete",
            run: source::check_delete,
        },
        Check {
            name: "derived-columns",
            run: derived::check,
        },
        Check {
            name: "credential-columns",
            run: migrations::check_credentials,
        },
        Check {
            name: "migration-step",
            run: migrations::check_step,
        },
        Check {
            name: "no-dev-mode",
            run: switches::check,
        },
        Check {
            name: "unsafe-allowlist",
            run: source::check_unsafe,
        },
        Check {
            name: "todo-has-issue",
            run: source::check_todo,
        },
        Check {
            name: "panic-profile",
            run: profile::check,
        },
        Check {
            name: "comments",
            run: comments::check,
        },
        Check {
            name: "disallowed-suppression",
            run: clippy::check,
        },
        Check {
            name: "no-external-call-in-transaction",
            run: asynchrony::check_transaction,
        },
        Check {
            name: "external-call-timeout",
            run: asynchrony::check_timeout,
        },
    ]
}

#[cfg(test)]
mod tests {
    fn clippy_table() -> toml::Table {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let text = std::fs::read_to_string(root.join("clippy.toml")).unwrap();
        text.parse().unwrap()
    }

    fn disallowed<'a>(table: &'a toml::Table, key: &str) -> Vec<(&'a str, &'a str)> {
        table
            .get(key)
            .and_then(toml::Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|m| {
                Some((
                    m.get("path").and_then(toml::Value::as_str)?,
                    m.get("reason").and_then(toml::Value::as_str)?,
                ))
            })
            .collect()
    }

    // T-32 T-52
    #[test]
    fn t_32_clippy_disallows_direct_clock_and_rng() {
        let table = clippy_table();
        let disallowed: Vec<&str> = disallowed(&table, "disallowed-methods")
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        for path in [
            "std::time::SystemTime::now",
            "std::time::Instant::now",
            "rand::thread_rng",
            "uuid::Uuid::new_v4",
        ] {
            assert!(disallowed.contains(&path), "{path} is not disallowed");
        }
    }

    // T-32
    #[test]
    fn t_32_clippy_disallows_unbounded_channels() {
        let table = clippy_table();
        let methods = disallowed(&table, "disallowed-methods");
        let types = disallowed(&table, "disallowed-types");
        for path in [
            "tokio::sync::mpsc::unbounded_channel",
            "futures_channel::mpsc::unbounded",
            "std::sync::mpsc::channel",
            "flume::unbounded",
        ] {
            let reason = methods.iter().find(|(p, _)| *p == path).map(|(_, r)| *r);
            assert!(
                reason.is_some_and(|r| r.contains("T-32 rule 7")),
                "{path} is not disallowed with a T-32 reason"
            );
        }
        for path in [
            "tokio::sync::mpsc::UnboundedSender",
            "tokio::sync::mpsc::UnboundedReceiver",
            "futures_channel::mpsc::UnboundedSender",
            "std::sync::mpsc::Sender",
        ] {
            let reason = types.iter().find(|(p, _)| *p == path).map(|(_, r)| *r);
            assert!(
                reason.is_some_and(|r| r.contains("T-32 rule 7")),
                "{path} is not disallowed with a T-32 reason"
            );
        }
    }
}
