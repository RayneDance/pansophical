//! Build script — embeds git commit hash and build timestamp into the binary.

use std::process::Command;

fn main() {
    // Git short hash.
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    // Git dirty flag.
    let git_dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let git_ref = if git_dirty {
        format!("{git_hash}-dirty")
    } else {
        git_hash
    };

    // Build timestamp (UTC, compact).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("cargo::rerun-if-changed=.git/HEAD");
    println!("cargo::rerun-if-changed=.git/refs/");
    println!("cargo::rustc-env=PANSOPHICAL_GIT_REF={git_ref}");
    println!("cargo::rustc-env=PANSOPHICAL_BUILD_TS={now}");
}
