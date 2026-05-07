//! Glob compilation, path canonicalization, Windows case-fold,
//! and registry hive alias normalization.

use std::path::{Path, PathBuf};

use crate::error::{PansophicalError, Result};

/// Canonicalize a path for policy evaluation.
///
/// - Resolves `..`, `.`, and symlinks via `std::fs::canonicalize`
/// - On Windows: lowercases the result to prevent case-sensitivity bypass
///
/// Returns an error if the path does not exist (use `canonical_path_for_create`
/// for write/create operations on non-existent files).
pub fn canonical_path(path: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        PansophicalError::Authz(format!(
            "cannot canonicalize path '{}': {e}",
            path.display()
        ))
    })?;
    Ok(normalize_for_platform(canonical))
}

/// Canonicalize for create operations where the target file may not exist.
///
/// Canonicalizes the *parent directory* (which must exist) and appends
/// the filename. This prevents `../` inside a new filename from escaping
/// the sandbox.
pub fn canonical_path_for_create(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        PansophicalError::Authz(format!("path has no parent: '{}'", path.display()))
    })?;
    let filename = path.file_name().ok_or_else(|| {
        PansophicalError::Authz(format!("path has no filename: '{}'", path.display()))
    })?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|e| {
        PansophicalError::Authz(format!(
            "cannot canonicalize parent directory '{}': {e}",
            parent.display()
        ))
    })?;
    Ok(normalize_for_platform(canonical_parent.join(filename)))
}

/// Platform-specific normalization.
/// On Windows: lowercase the path for case-insensitive glob matching.
fn normalize_for_platform(path: PathBuf) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(path.to_string_lossy().to_lowercase())
    }
    #[cfg(not(target_os = "windows"))]
    {
        path
    }
}

/// Check if a concrete path matches a glob pattern string.
///
/// The glob pattern is compiled each time. For repeated matching,
/// use a pre-compiled `GlobSet` (see `compile_glob`).
pub fn path_matches_glob(path: &str, pattern: &str) -> bool {
    let glob = match globset::GlobBuilder::new(pattern)
        .case_insensitive(cfg!(target_os = "windows"))
        .literal_separator(true)
        .build()
    {
        Ok(g) => g,
        Err(_) => return false,
    };
    glob.compile_matcher().is_match(path)
}

/// Registry hive alias normalization.
///
/// Two normalizations:
/// 1. Forward slashes → backslashes
/// 2. Short-form hive aliases → canonical long form
///    (case-insensitive: `hkcu`, `HKCU` both → `HKEY_CURRENT_USER`)
pub fn normalize_registry_path(path: &str) -> String {
    // Replace forward slashes with backslashes.
    let path = path.replace('/', "\\");

    // Normalize hive aliases (case-insensitive).
    let upper = path.to_uppercase();
    let aliases: &[(&str, &str)] = &[
        ("HKCU\\", "HKEY_CURRENT_USER\\"),
        ("HKLM\\", "HKEY_LOCAL_MACHINE\\"),
        ("HKCR\\", "HKEY_CLASSES_ROOT\\"),
        ("HKU\\", "HKEY_USERS\\"),
        ("HKCC\\", "HKEY_CURRENT_CONFIG\\"),
    ];

    for &(short, long) in aliases {
        if upper.starts_with(short) {
            // Replace the short prefix with the long form, preserving
            // the original casing of the rest of the path.
            return format!("{}{}", long, &path[short.len()..]);
        }
    }

    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basic_match() {
        assert!(path_matches_glob("/workspace/src/main.rs", "/workspace/**"));
    }

    #[test]
    fn glob_no_match() {
        assert!(!path_matches_glob("/etc/passwd", "/workspace/**"));
    }

    #[test]
    fn glob_single_star() {
        assert!(path_matches_glob("/workspace/foo.rs", "/workspace/*.rs"));
        assert!(!path_matches_glob("/workspace/sub/foo.rs", "/workspace/*.rs"));
    }

    #[test]
    fn registry_short_to_long() {
        assert_eq!(
            normalize_registry_path("HKCU/Software/MyApp"),
            "HKEY_CURRENT_USER\\Software\\MyApp"
        );
    }

    #[test]
    fn registry_case_insensitive() {
        assert_eq!(
            normalize_registry_path("hkcu/Software/MyApp"),
            "HKEY_CURRENT_USER\\Software\\MyApp"
        );
    }

    #[test]
    fn registry_already_long() {
        assert_eq!(
            normalize_registry_path("HKEY_CURRENT_USER/Software/MyApp"),
            "HKEY_CURRENT_USER\\Software\\MyApp"
        );
    }

    #[test]
    fn registry_hklm() {
        assert_eq!(
            normalize_registry_path("HKLM\\SOFTWARE\\Test"),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test"
        );
    }

    #[test]
    fn registry_slashes_normalized() {
        assert_eq!(
            normalize_registry_path("HKCU/Foo/Bar"),
            "HKEY_CURRENT_USER\\Foo\\Bar"
        );
    }
}
