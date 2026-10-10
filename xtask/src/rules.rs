//! Architecture and code rules (T-4, T-22, T-31, T-32, T-33, T-36, T-53); each
//! check lives in a `rules_*` module.

#[path = "rules_comments.rs"]
pub(crate) mod comments;
#[path = "rules_deps.rs"]
pub(crate) mod deps;
#[path = "rules_files.rs"]
pub(crate) mod files;
#[path = "rules_kernel.rs"]
mod kernel;
#[path = "rules_lex.rs"]
pub(crate) mod lex;
#[path = "rules_profile.rs"]
mod profile;
#[path = "rules_source.rs"]
pub(crate) mod source;
#[path = "rules_switches.rs"]
mod switches;

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
    ]
}

#[cfg(test)]
mod tests {
    // T-32 T-52
    #[test]
    fn t_32_clippy_disallows_direct_clock_and_rng() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let text = std::fs::read_to_string(root.join("clippy.toml")).unwrap();
        let table: toml::Table = text.parse().unwrap();
        let disallowed: Vec<&str> = table
            .get("disallowed-methods")
            .and_then(toml::Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|m| m.get("path").and_then(toml::Value::as_str))
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
}
