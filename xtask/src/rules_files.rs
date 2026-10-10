//! Repository file walking shared by the rule checks.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SKIP_DIRS: &[&str] = &["target", ".git", "docs", "node_modules", "vendor"];

const SCANNED_HIDDEN_DIRS: &[&str] = &[".github", ".cargo", ".githooks", ".semgrep", ".config"];

/// Lists every file under `root` (sorted), skipping build output, VCS data, the
/// local-only `docs/`, third-party code and hidden directories other than
/// repository configuration.
pub(crate) fn walk(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    walk_into(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_into(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if kind.is_dir() {
            let at_root = dir == root;
            let skipped = SKIP_DIRS.contains(&name.as_str())
                || (name.starts_with('.') && !SCANNED_HIDDEN_DIRS.contains(&name.as_str()));
            if skipped && (at_root || !matches!(name.as_str(), "docs" | "vendor")) {
                continue;
            }
            walk_into(root, &path, out)?;
        } else if kind.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Tracked and untracked-but-not-ignored files relative to `root`; local-only
/// files excluded through `.git/info/exclude` never appear.
pub(crate) fn repo_files(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let mut files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|f| root.join(f).is_file())
        .map(str::to_owned)
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}

/// `path` relative to `root`, with `/` separators.
pub(crate) fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// True for Rust files that only build in test or bench configurations.
pub(crate) fn is_test_file(rel_path: &str) -> bool {
    let parts: Vec<&str> = rel_path.split('/').collect();
    parts.iter().any(|p| matches!(*p, "tests" | "benches"))
        || parts
            .last()
            .is_some_and(|f| *f == "tests.rs" || f.ends_with("_tests.rs"))
}

/// Reads a file as UTF-8.
pub(crate) fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Reads a file, returning `None` when it does not exist.
pub(crate) fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The file extension of a relative path, lower-cased.
pub(crate) fn extension(rel_path: &str) -> String {
    Path::new(rel_path)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// The file name of a relative path.
pub(crate) fn file_name(rel_path: &str) -> &str {
    rel_path.rsplit('/').next().unwrap_or(rel_path)
}

/// A scratch directory for tests, removed on drop.
#[cfg(test)]
pub(crate) struct TempDir(pub(crate) PathBuf);

#[cfg(test)]
impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("xtask-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(crate) fn write(&self, rel_path: &str, text: &str) {
        let path = self.0.join(rel_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, text).unwrap();
    }
}

#[cfg(test)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-37
    #[test]
    fn t_37_integration_tests_and_test_modules_count_as_test_files() {
        assert!(is_test_file("crates/http/tests/router.rs"));
        assert!(is_test_file("crates/kernel/src/tests.rs"));
        assert!(!is_test_file("crates/kernel/src/testkit.rs"));
    }

    // T-31
    #[test]
    fn t_31_walk_skips_docs_target_and_hidden_dirs() {
        let dir = TempDir::new("walk");
        dir.write("crates/a/src/lib.rs", "");
        dir.write("docs/spec/x.md", "");
        dir.write("target/debug/x.rs", "");
        dir.write(".idea/x.xml", "");
        dir.write(".github/workflows/ci.yml", "");
        let files: Vec<String> = walk(&dir.0)
            .unwrap()
            .iter()
            .map(|p| rel(&dir.0, p))
            .collect();
        assert_eq!(files, [".github/workflows/ci.yml", "crates/a/src/lib.rs"]);
    }
}
