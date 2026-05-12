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
    path_beneath_rules, Access, AccessFs, AccessNet, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

use super::SandboxProfile;

/// The Landlock ABI version we target.
/// V5 (kernel 6.7+) adds network (bind/connect) and ioctl controls.
/// BestEffort mode gracefully degrades on older kernels.
const TARGET_ABI: ABI = ABI::V5;

/// Configure a `Command` with Landlock sandbox and PR_SET_PDEATHSIG.
///
/// Installs a `pre_exec` hook that:
/// 1. Sets `PR_SET_PDEATHSIG(SIGKILL)` — child dies when parent dies
/// 2. Applies Landlock filesystem restrictions from the profile
/// 3. Optionally denies all TCP bind + connect (`deny_network`)
///
/// # Safety
///
/// The `pre_exec` hook runs in the child after `fork()`. We use only
/// async-signal-safe operations (syscalls, no heap allocation from Rust's
/// perspective — the landlock crate uses stack-allocated structures).
pub unsafe fn configure_sandbox(cmd: &mut Command, profile: &SandboxProfile, deny_network: bool) {
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

    // SAFETY: pre_exec runs in the child after fork(). All operations here
    // are async-signal-safe (syscalls via libc, landlock ioctls).
    unsafe {
        cmd.pre_exec(move || {
            // 1. Set PR_SET_PDEATHSIG so child is killed when parent dies.
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Check if parent already died (race between fork and prctl).
            if unsafe { libc::getppid() } == 1 {
                unsafe { libc::_exit(1) };
            }

            // 2. Apply Landlock restrictions.
            let read_access = AccessFs::from_read(TARGET_ABI);
            let write_access = AccessFs::from_all(TARGET_ABI);
            let exec_access = read_access | AccessFs::Execute;

            // Declare which access types we handle. Declaring an access type
            // without adding rules for it means ALL such access is denied.
            let rs_builder = match Ruleset::default()
                .handle_access(AccessFs::from_all(TARGET_ABI))
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("pansophical: landlock fs handle_access failed: {e}");
                    return Ok(());
                }
            };

            // 3. Network deny: handle TCP access types without adding any
            //    allow rules → all TCP bind + connect is denied.
            let rs_builder = if deny_network {
                match rs_builder.handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp) {
                    Ok(r) => r,
                    Err(e) => {
                        // Network rules may fail on pre-6.7 kernels — not fatal.
                        eprintln!("pansophical: landlock net deny not available: {e}");
                        return Ok(());
                    }
                }
            } else {
                rs_builder
            };

            let ruleset = match rs_builder.create() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("pansophical: landlock create failed: {e}");
                    return Ok(());
                }
            };

            // Collect all paths into (path, access) pairs, then add them
            // in a single chain. add_rules() takes self by value, so we
            // must thread the ruleset through each call.
            let mut rs = ruleset;

            for path_str in &read_paths {
                let path = Path::new(path_str);
                if path.exists() {
                    let paths = [path.as_os_str()];
                    let rules = path_beneath_rules(&paths, read_access);
                    rs = match rs.add_rules(rules) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("pansophical: landlock read rule '{}': {e}", path_str);
                            return Ok(());
                        }
                    };
                }
            }

            for path_str in &write_paths {
                let path = Path::new(path_str);
                if path.exists() {
                    let paths = [path.as_os_str()];
                    let rules = path_beneath_rules(&paths, write_access);
                    rs = match rs.add_rules(rules) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("pansophical: landlock write rule '{}': {e}", path_str);
                            return Ok(());
                        }
                    };
                }
            }

            for path_str in &exec_paths {
                let path = Path::new(path_str);
                if path.exists() {
                    let paths = [path.as_os_str()];
                    let rules = path_beneath_rules(&paths, exec_access);
                    rs = match rs.add_rules(rules) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("pansophical: landlock exec rule '{}': {e}", path_str);
                            return Ok(());
                        }
                    };
                }
            }

            // System paths always needed.
            for dev in &["/proc", "/dev/null", "/dev/urandom", "/dev/zero"] {
                if Path::new(dev).exists() {
                    let paths = [OsStr::new(dev)];
                    let rules = path_beneath_rules(&paths, read_access);
                    rs = match rs.add_rules(rules) {
                        Ok(r) => r,
                        Err(_) => return Ok(()),
                    };
                }
            }
            for rw in &["/dev/pts", "/tmp"] {
                if Path::new(rw).exists() {
                    let paths = [OsStr::new(rw)];
                    let rules = path_beneath_rules(&paths, write_access);
                    rs = match rs.add_rules(rules) {
                        Ok(r) => r,
                        Err(_) => return Ok(()),
                    };
                }
            }

            // Enforce.
            match rs.restrict_self() {
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
}

/// Strip glob suffix (`/**`) from a path for Landlock rules.
/// Landlock uses real filesystem paths, not globs.
fn strip_glob_suffix(path: &Path) -> std::path::PathBuf {
    let s = path.display().to_string();
    let clean = s.trim_end_matches("/**");
    std::path::PathBuf::from(clean)
}
