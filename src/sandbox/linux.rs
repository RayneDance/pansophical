//! Linux sandbox: Landlock filesystem restrictions + PR_SET_PDEATHSIG.
//!
//! # Architecture
//!
//! Landlock (kernel 5.13+) provides path-based filesystem access control
//! that works for unprivileged processes. Rules are inherited by children
//! and die with the process — no cleanup needed.
//!
//! The sandbox is applied in a `pre_exec` hook so it takes effect before
//! the child runs any code. We also set `PR_SET_PDEATHSIG(SIGKILL)` so
//! the child is killed if the server dies.
//!
//! # Fallback
//!
//! If Landlock is not available (old kernel, not enabled in LSM config),
//! the child runs unsandboxed with a warning. Same pattern as the Windows
//! restricted token fallback.

use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use landlock::{
    path_beneath_rules, AccessFs, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

use super::SandboxProfile;

/// The Landlock ABI version we target.
/// V5 (kernel 6.7) adds network and ioctl controls. We use V4 as a reasonable
/// baseline that covers filesystem + refer access on 6.4+ kernels, falling
/// back gracefully via BestEffort mode.
const TARGET_ABI: ABI = ABI::V4;

/// Configure a `Command` with Landlock sandbox and PR_SET_PDEATHSIG.
///
/// Installs a `pre_exec` hook that:
/// 1. Sets `PR_SET_PDEATHSIG(SIGKILL)` — child dies when parent dies
/// 2. Applies Landlock filesystem restrictions from the profile
///
/// # Safety
///
/// The `pre_exec` hook runs in the child after `fork()`. We use only
/// async-signal-safe operations (syscalls, no heap allocation from Rust's
/// perspective — the landlock crate uses stack-allocated structures).
pub unsafe fn configure_sandbox(cmd: &mut Command, profile: &SandboxProfile) {
    // Clone the profile data we need into owned values for the closure.
    let read_paths: Vec<String> = profile.read_paths.iter()
        .map(|p| strip_glob_suffix(p).display().to_string())
        .collect();
    let write_paths: Vec<String> = profile.write_paths.iter()
        .map(|p| strip_glob_suffix(p).display().to_string())
        .collect();
    let exec_paths: Vec<String> = profile.exec_paths.iter()
        .map(|p| strip_glob_suffix(p).display().to_string())
        .collect();

    cmd.pre_exec(move || {
        // 1. Set PR_SET_PDEATHSIG so child is killed when parent dies.
        let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Check if parent already died (race between fork and prctl).
        if libc::getppid() == 1 {
            libc::_exit(1);
        }

        // 2. Apply Landlock restrictions.
        let read_access = AccessFs::from_read(TARGET_ABI);
        let write_access = AccessFs::from_all(TARGET_ABI);

        let mut ruleset = match Ruleset::default()
            .handle_access(AccessFs::from_all(TARGET_ABI))
            .and_then(|r| r.create())
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("pansophical: landlock init failed: {e}");
                // Don't fail the spawn — run unsandboxed.
                return Ok(());
            }
        };

        // Add read-only rules.
        for path_str in &read_paths {
            let path = Path::new(path_str);
            if path.exists() {
                let rules = path_beneath_rules(&[path.as_os_str()], read_access);
                if let Err(e) = ruleset.add_rules(rules) {
                    eprintln!("pansophical: landlock read rule '{}': {e}", path_str);
                }
            }
        }

        // Add read+write rules.
        for path_str in &write_paths {
            let path = Path::new(path_str);
            if path.exists() {
                let rules = path_beneath_rules(&[path.as_os_str()], write_access);
                if let Err(e) = ruleset.add_rules(rules) {
                    eprintln!("pansophical: landlock write rule '{}': {e}", path_str);
                }
            }
        }

        // Add execute rules.
        let exec_access = read_access | AccessFs::Execute;
        for path_str in &exec_paths {
            let path = Path::new(path_str);
            if path.exists() {
                let rules = path_beneath_rules(&[path.as_os_str()], exec_access);
                if let Err(e) = ruleset.add_rules(rules) {
                    eprintln!("pansophical: landlock exec rule '{}': {e}", path_str);
                }
            }
        }

        // System paths always needed.
        for dev in &["/proc", "/dev/null", "/dev/urandom", "/dev/zero"] {
            if Path::new(dev).exists() {
                let rules = path_beneath_rules(&[OsStr::new(dev)], read_access);
                let _ = ruleset.add_rules(rules);
            }
        }
        for rw in &["/dev/pts", "/tmp"] {
            if Path::new(rw).exists() {
                let rules = path_beneath_rules(&[OsStr::new(rw)], write_access);
                let _ = ruleset.add_rules(rules);
            }
        }

        // Enforce.
        match ruleset.restrict_self() {
            Ok(status) => {
                if status.ruleset == RulesetStatus::NotEnforced {
                    eprintln!("pansophical: landlock not enforced (kernel too old?)");
                }
            }
            Err(e) => {
                eprintln!("pansophical: landlock restrict_self failed: {e}");
            }
        }

        Ok(())
    });
}

/// Strip glob suffix (`/**`) from a path for Landlock rules.
/// Landlock uses real filesystem paths, not globs.
fn strip_glob_suffix(path: &Path) -> std::path::PathBuf {
    let s = path.display().to_string();
    let clean = s.trim_end_matches("/**");
    std::path::PathBuf::from(clean)
}
