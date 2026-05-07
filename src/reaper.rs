//! Child process lifecycle management and timeout enforcement.
//!
//! Spawns a monitoring task per child; kills after `tool_timeout_secs`.
//! Handles graceful shutdown: SIGTERM/SIGINT → drain → force-kill.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::config::schema::SandboxConfig;

/// Outcome of a reaped child process.
#[derive(Debug)]
pub enum ReapResult {
    /// Child completed normally.
    Completed {
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// Child was killed due to timeout.
    TimedOut {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// Failed to spawn.
    SpawnFailed(String),
}

/// Spawn a child process with environment stripping and timeout enforcement.
///
/// - Starts with an empty environment
/// - Adds only `env_baseline` vars from the host
/// - Adds any explicitly granted vars
/// - Pipes stdout/stderr (never inherits the server's stdio)
/// - Enforces `timeout_secs` with kill-on-expiry
pub async fn spawn_and_reap(
    program: &str,
    args: &[String],
    sandbox_config: &SandboxConfig,
    granted_env: &[(String, String)],
    timeout_secs: u64,
    max_output_bytes: u64,
) -> ReapResult {
    // Build the command with a stripped environment.
    let mut cmd = Command::new(program);
    cmd.args(args);

    // ── Environment stripping ─────────────────────────────────────────
    // Start with a completely empty environment.
    cmd.env_clear();

    // Add only the baseline vars from the host.
    for var_name in &sandbox_config.env_baseline {
        if let Ok(val) = std::env::var(var_name) {
            cmd.env(var_name, val);
        }
    }

    // Add explicitly granted environment variables.
    for (k, v) in granted_env {
        cmd.env(k, v);
    }

    // ── Stdio isolation ───────────────────────────────────────────────
    // CRITICAL: child must NEVER inherit the server's stdout (JSON-RPC channel).
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());

    // ── Spawn ─────────────────────────────────────────────────────────
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ReapResult::SpawnFailed(format!(
                "failed to spawn '{}': {e}",
                program
            ));
        }
    };

    info!(program = program, "Child spawned");

    // ── Job Object assignment (Windows) ───────────────────────────────
    #[cfg(windows)]
    {
        if let Some(pid) = child.id() {
            if let Err(e) = assign_to_server_job(pid) {
                warn!(program = program, pid = pid, "Failed to assign child to Job Object: {e}");
            }
        }
    }

    // Take ownership of stdout/stderr handles for reading.
    let mut child_stdout = child.stdout.take();
    let mut child_stderr = child.stderr.take();

    // ── Timeout enforcement ───────────────────────────────────────────
    let duration = Duration::from_secs(timeout_secs);

    let wait_result = timeout(duration, child.wait()).await;

    match wait_result {
        Ok(Ok(status)) => {
            // Child completed within timeout.
            let stdout = read_pipe(&mut child_stdout, max_output_bytes).await;
            let stderr = read_pipe(&mut child_stderr, max_output_bytes).await;
            ReapResult::Completed {
                exit_code: status.code(),
                stdout,
                stderr,
            }
        }
        Ok(Err(e)) => {
            error!(program = program, "Child wait error: {e}");
            ReapResult::SpawnFailed(format!("child wait error: {e}"))
        }
        Err(_) => {
            // Timeout expired — kill the child.
            warn!(
                program = program,
                timeout_secs = timeout_secs,
                "Child timed out — killing"
            );
            if let Err(e) = child.kill().await {
                error!("Failed to kill child: {e}");
            }
            // Wait for the process to actually exit after kill.
            let _ = child.wait().await;

            let stdout = read_pipe(&mut child_stdout, max_output_bytes).await;
            let stderr = read_pipe(&mut child_stderr, max_output_bytes).await;
            ReapResult::TimedOut { stdout, stderr }
        }
    }
}

/// Read all data from a pipe handle, truncating at max_bytes.
async fn read_pipe(
    pipe: &mut Option<impl AsyncReadExt + Unpin>,
    max_bytes: u64,
) -> Vec<u8> {
    let pipe = match pipe.as_mut() {
        Some(p) => p,
        None => return vec![],
    };

    let mut buf = Vec::new();
    match pipe.read_to_end(&mut buf).await {
        Ok(_) => truncate_output(buf, max_bytes),
        Err(_) => vec![],
    }
}

/// Truncate output to `max_bytes`, adding a marker if truncated.
fn truncate_output(data: Vec<u8>, max_bytes: u64) -> Vec<u8> {
    if data.len() as u64 <= max_bytes {
        return data;
    }
    let mut truncated = data[..max_bytes as usize].to_vec();
    truncated.extend_from_slice(b"\n[output truncated by pansophical]");
    truncated
}

// ── Windows Job Object ────────────────────────────────────────────────────

#[cfg(windows)]
use std::sync::OnceLock;

/// Global server Job Object. Initialized once, lives for the server lifetime.
/// All child processes are assigned to this job so they die when the server exits.
#[cfg(windows)]
static SERVER_JOB: OnceLock<crate::sandbox::windows::JobObject> = OnceLock::new();

/// Initialize the global server Job Object. Called once at startup.
#[cfg(windows)]
pub fn init_server_job() {
    match crate::sandbox::windows::create_server_job() {
        Ok(job) => {
            let _ = SERVER_JOB.set(job);
            info!("Server Job Object initialized — children will be reaped on exit");
        }
        Err(e) => {
            warn!("Failed to create server Job Object: {e} — children may orphan on crash");
        }
    }
}

/// Assign a child process PID to the server Job Object.
#[cfg(windows)]
fn assign_to_server_job(pid: u32) -> std::io::Result<()> {
    if let Some(job) = SERVER_JOB.get() {
        job.assign_pid(pid)
    } else {
        Ok(()) // Job not initialized — skip silently.
    }
}

/// No-op on non-Windows.
#[cfg(not(windows))]
pub fn init_server_job() {}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::SandboxConfig;

    fn test_sandbox() -> SandboxConfig {
        SandboxConfig {
            enabled: true,
            strategy: "auto".into(),
            env_baseline: vec!["PATH".into()],
        }
    }

    #[tokio::test]
    async fn spawn_echo() {
        let args: Vec<String> = if cfg!(windows) {
            vec!["/C".into(), "echo".into(), "hello".into()]
        } else {
            vec!["hello".into()]
        };
        let program = if cfg!(windows) { "cmd" } else { "echo" };

        let result = spawn_and_reap(
            program,
            &args,
            &test_sandbox(),
            &[],
            5,
            1024,
        )
        .await;

        match result {
            ReapResult::Completed { exit_code, stdout, .. } => {
                assert_eq!(exit_code, Some(0));
                let out = String::from_utf8_lossy(&stdout);
                assert!(out.contains("hello"), "stdout should contain 'hello', got: {out}");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn env_stripping() {
        // Set a test env var, then verify it's NOT visible to the child.
        // SAFETY: test-only, single-threaded test runner for this test.
        unsafe { std::env::set_var("PANSOPHICAL_TEST_SECRET", "should_be_stripped") };

        let args: Vec<String> = if cfg!(windows) {
            vec!["/C".into(), "set".into()]
        } else {
            vec![]
        };
        let program = if cfg!(windows) { "cmd" } else { "env" };

        let result = spawn_and_reap(
            program,
            &args,
            &test_sandbox(),
            &[],
            5,
            65536,
        )
        .await;

        match result {
            ReapResult::Completed { stdout, .. } => {
                let out = String::from_utf8_lossy(&stdout);
                assert!(
                    !out.contains("PANSOPHICAL_TEST_SECRET"),
                    "stripped env var should not be visible: {out}"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        unsafe { std::env::remove_var("PANSOPHICAL_TEST_SECRET") };
    }

    #[tokio::test]
    async fn timeout_kills_child() {
        let args: Vec<String> = if cfg!(windows) {
            vec!["/C".into(), "ping".into(), "-n".into(), "60".into(), "127.0.0.1".into()]
        } else {
            vec!["60".into()]
        };
        let program = if cfg!(windows) { "cmd" } else { "sleep" };

        let result = spawn_and_reap(
            program,
            &args,
            &test_sandbox(),
            &[],
            1, // 1 second timeout
            1024,
        )
        .await;

        match result {
            ReapResult::TimedOut { .. } => {} // expected
            other => panic!("expected TimedOut, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn spawn_nonexistent() {
        let result = spawn_and_reap(
            "nonexistent_binary_12345",
            &[],
            &test_sandbox(),
            &[],
            5,
            1024,
        )
        .await;

        match result {
            ReapResult::SpawnFailed(msg) => {
                assert!(msg.contains("nonexistent_binary_12345"));
            }
            other => panic!("expected SpawnFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn granted_env_visible() {
        let args: Vec<String> = if cfg!(windows) {
            vec!["/C".into(), "echo".into(), "%MY_GRANTED_VAR%".into()]
        } else {
            vec![]
        };
        let program = if cfg!(windows) { "cmd" } else { "env" };

        let result = spawn_and_reap(
            program,
            &args,
            &test_sandbox(),
            &[("MY_GRANTED_VAR".into(), "granted_value".into())],
            5,
            65536,
        )
        .await;

        match result {
            ReapResult::Completed { stdout, .. } => {
                let out = String::from_utf8_lossy(&stdout);
                assert!(
                    out.contains("granted_value"),
                    "granted env var should be visible: {out}"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }
}
