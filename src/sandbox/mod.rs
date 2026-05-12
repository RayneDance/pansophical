//! OS-level child process sandboxing.
//!
//! Platform-specific implementations:
//! - Linux: landlock + seccomp (planned)
//! - Windows: Restricted Token + Low Integrity Level + Job Objects
//!
//! # Architecture
//!
//! The sandbox provides defense-in-depth below the policy engine:
//!
//! 1. **Policy engine** (authz) — software check before spawn
//! 2. **OS sandbox** — hardware enforcement during execution
//!
//! Even if a tool doesn't declare all its resource needs, or attempts
//! to access paths beyond what was authorized, the OS sandbox restricts
//! the child process to only the paths in the `SandboxProfile`.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "windows")]
pub mod pool;

use std::path::PathBuf;

use crate::config::policy_target::{Effect, PolicyTargetType};
use crate::config::perm::Perm;
use crate::config::schema::KeyConfig;

// ── Task-local sandbox profile ────────────────────────────────────────────────
//
// The transport layer sets this before calling tool.execute(). The reaper
// reads it when spawning a sandboxed child. This avoids adding a parameter
// to the McpTool trait.

tokio::task_local! {
    static CURRENT_PROFILE: SandboxProfile;
    static CURRENT_KEY_NAME: String;
}

/// Run a closure with a sandbox profile and key name set for the current task.
pub async fn with_profile_and_key<F, R>(profile: SandboxProfile, key_name: String, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    CURRENT_PROFILE.scope(profile, CURRENT_KEY_NAME.scope(key_name, f)).await
}

/// Run a closure with a sandbox profile set for the current task.
#[allow(dead_code)]
pub async fn with_profile<F, R>(profile: SandboxProfile, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    CURRENT_PROFILE.scope(profile, f).await
}

/// Get the current task's sandbox profile (if set).
pub fn current_profile() -> Option<SandboxProfile> {
    CURRENT_PROFILE.try_with(|p| p.clone()).ok()
}

/// Get the current task's key name (if set).
pub fn current_key_name() -> Option<String> {
    CURRENT_KEY_NAME.try_with(|k| k.clone()).ok()
}

/// Filesystem access profile for a sandboxed child process.
///
/// Constructed from authz grants + tool resource declarations + config defaults.
/// Passed to the platform-specific sandbox implementation.
#[derive(Debug, Clone, Default)]
pub struct SandboxProfile {
    /// Paths the child is allowed to read.
    pub read_paths: Vec<PathBuf>,
    /// Paths the child is allowed to read + write.
    pub write_paths: Vec<PathBuf>,
    /// Paths the child is allowed to execute.
    pub exec_paths: Vec<PathBuf>,
    /// Whether the child is allowed outbound network access.
    /// On Windows, this adds the `internetClient` capability to the AppContainer.
    /// On Linux, this skips the Landlock TCP deny rules.
    pub allow_network: bool,
    /// Whether the sandbox is enabled.
    #[allow(dead_code)]
    pub enabled: bool,
}

impl SandboxProfile {
    /// Create a new empty profile.
    pub fn new() -> Self {
        Self {
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            exec_paths: Vec::new(),
            allow_network: false,
            enabled: true,
        }
    }

    /// Create a disabled profile (no sandbox enforcement).
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Build a SandboxProfile from a key's config and the tool's arguments.
    ///
    /// Collects all filesystem grant rules from the key's policy and adds them
    /// as read or write paths based on the granted permission level.
    pub fn from_key_config(key_config: &KeyConfig) -> Self {
        let mut profile = Self::new();

        for rule in &key_config.rules {
            if rule.effect != Effect::Grant {
                continue;
            }

            match rule.target_type {
                PolicyTargetType::Filesystem => {
                    if let Some(ref path) = rule.path {
                        let perm = rule.perm.unwrap_or(Perm::READ);

                        if perm.contains(Perm::WRITE) {
                            profile.write_paths.push(PathBuf::from(path));
                        } else {
                            profile.read_paths.push(PathBuf::from(path));
                        }
                    }
                }
                PolicyTargetType::Network => {
                    // Any network grant enables the internetClient capability.
                    profile.allow_network = true;
                }
                _ => {}
            }
        }

        // Windows system paths (System32, SysWOW64) are NOT added to
        // read_paths because they already have ACLs granting access to
        // ALL APPLICATION PACKAGES.  Trying to icacls them fails without
        // admin privileges.  They're only needed for Linux Landlock which
        // has no equivalent built-in grant.
        #[cfg(windows)]
        {
            // COMSPEC is tracked for reference but AppContainers can
            // already execute it via the ALL APPLICATION PACKAGES ACE.
            if let Ok(path) = std::env::var("COMSPEC") {
                profile.exec_paths.push(PathBuf::from(path));
            }
        }

        #[cfg(target_os = "linux")]
        {
            profile.read_paths.push(PathBuf::from("/usr/lib"));
            profile.read_paths.push(PathBuf::from("/usr/lib64"));
            profile.read_paths.push(PathBuf::from("/lib"));
            profile.read_paths.push(PathBuf::from("/lib64"));
            profile.exec_paths.push(PathBuf::from("/usr/bin"));
            profile.exec_paths.push(PathBuf::from("/bin"));
        }

        profile
    }

    /// Add the tool's command binary to the exec paths.
    #[allow(dead_code)]
    pub fn add_executable(&mut self, program: &str) {
        self.exec_paths.push(PathBuf::from(program));
    }
}

/// Strip glob suffixes (`/**`, `\**`, `/*`, `\*`) from a path string.
///
/// On Windows, `PathBuf` normalizes forward slashes to backslashes, so
/// a config path like `E:/pansof/**` becomes `E:\pansof\**` after
/// `PathBuf::from().display()`. This function handles both conventions.
pub fn strip_glob_suffix(path: &str) -> String {
    // Try longest suffixes first.
    for suffix in &["/**", "\\**", "/*", "\\*"] {
        if let Some(stripped) = path.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    path.to_string()
}

/// Set the integrity label on a path to Low, allowing Low Integrity processes to write.
///
/// Uses `icacls <path> /setintegritylevel (OI)(CI)L`.
/// This is idempotent — calling it multiple times on the same path is safe.
#[cfg(windows)]
pub fn set_low_integrity_label(path: &std::path::Path) -> Result<(), String> {
    let path_str = path.display().to_string();
    let output = std::process::Command::new("icacls")
        .args([&path_str, "/setintegritylevel", "(OI)(CI)L"])
        .output()
        .map_err(|e| format!("failed to run icacls: {e}"))?;

    if output.status.success() {
        tracing::debug!(path = %path_str, "Set Low integrity label");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("icacls failed for '{}': {}", path_str, stderr.trim()))
    }
}

/// Prepare write paths for a sandboxed Low Integrity process.
///
/// Sets Low integrity labels on all write_paths in the profile so the
/// sandboxed child can write to them. Other paths remain Medium integrity.
#[cfg(windows)]
pub fn prepare_write_paths(profile: &SandboxProfile) {
    for path in &profile.write_paths {
        let clean = strip_glob_suffix(&path.display().to_string());
        let clean_path = std::path::Path::new(&clean);

        if clean_path.exists() {
            if let Err(e) = set_low_integrity_label(clean_path) {
                tracing::warn!(path = %clean, error = %e, "Failed to set Low integrity label");
            }
        } else {
            tracing::debug!(path = %clean, "Write path does not exist yet — skipping integrity label");
        }
    }
}
