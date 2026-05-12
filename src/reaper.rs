//! Child process lifecycle management and timeout enforcement.
//!
//! Spawns a monitoring task per child; kills after `tool_timeout_secs`.
//! Handles graceful shutdown: SIGTERM/SIGINT → drain → force-kill.
//!
//! On Windows with sandbox enabled, spawns children with a Low Integrity
//! restricted token via `CreateProcessWithTokenW`, preventing writes to
//! most filesystem locations.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

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
        #[allow(dead_code)]
        stdout: Vec<u8>,
        #[allow(dead_code)]
        stderr: Vec<u8>,
    },
    /// Failed to spawn.
    SpawnFailed(String),
}

/// Spawn a child process with environment stripping and timeout enforcement.
///
/// On Windows with `sandbox.enabled = true`, attempts to spawn via
/// `CreateProcessAsUserW` with a Low Integrity restricted token.
/// Falls back to normal spawn if restricted spawn fails.
///
/// If `sandbox_profile` is provided, write paths in the profile are
/// If a sandbox profile is set (via `sandbox::with_profile`), write paths
/// are labeled with Low integrity before spawn, allowing the sandboxed
/// child to write to them while blocking all other locations.
pub async fn spawn_and_reap(
    program: &str,
    args: &[String],
    sandbox_config: &SandboxConfig,
    granted_env: &[(String, String)],
    timeout_secs: u64,
    max_output_bytes: u64,
) -> ReapResult {
    // Build the environment variable list.
    let env_vars = build_env_vars(sandbox_config, granted_env);

    // Try sandboxed spawn on Windows.
    #[cfg(windows)]
    if sandbox_config.enabled {
        // Prepare write paths from the task-local sandbox profile.
        if let Some(profile) = crate::sandbox::current_profile() {
            info!(
                program = program,
                read_paths = ?profile.read_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                write_paths = ?profile.write_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                exec_paths = ?profile.exec_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "Sandbox profile for child process"
            );
            crate::sandbox::prepare_write_paths(&profile);
            
            // 1. Try AppContainer (Strongest isolation)
            match spawn_appcontainer_windows(program, args, &env_vars, timeout_secs, max_output_bytes, &profile).await {
                Ok(result) => return result,
                Err(e) => {
                    warn!(
                        program = program,
                        error = %e,
                        "AppContainer spawn failed — falling back to Low Integrity restricted token"
                    );
                }
            }
        } else {
            warn!(program = program, "No sandbox profile in task-local — skipping AppContainer");
        }

        // 2. Try Low Integrity Restricted Token (Fallback isolation)
        match spawn_restricted_windows(program, args, &env_vars, timeout_secs, max_output_bytes).await {
            Ok(result) => return result,
            Err(e) => {
                if !sandbox_config.allow_fallback {
                    error!(
                        program = program,
                        error = %e,
                        "All sandbox methods failed and allow_fallback = false — refusing to execute"
                    );
                    return ReapResult::SpawnFailed(
                        format!("sandbox required but unavailable for '{}': {e}", program)
                    );
                }
                warn!(
                    program = program,
                    error = %e,
                    "Restricted spawn failed — falling back to unsandboxed (allow_fallback = true)"
                );
            }
        }
    }

    // Try sandboxed spawn on Linux (Landlock).
    #[cfg(target_os = "linux")]
    if sandbox_config.enabled {
        if let Some(profile) = crate::sandbox::current_profile() {
            return spawn_landlock_linux(
                program, args, &env_vars, timeout_secs, max_output_bytes,
                &profile, sandbox_config.deny_network,
            ).await;
        } else if !sandbox_config.allow_fallback {
            error!(
                program = program,
                "No sandbox profile available and allow_fallback = false — refusing to execute"
            );
            return ReapResult::SpawnFailed(
                format!("sandbox required but no profile available for '{}'", program)
            );
        }
    }

    // Normal spawn (fallback / sandbox disabled / no profile).
    spawn_normal(program, args, &env_vars, timeout_secs, max_output_bytes).await
}

/// Build the environment variable list for a child process.
fn build_env_vars(
    sandbox_config: &SandboxConfig,
    granted_env: &[(String, String)],
) -> Vec<(String, String)> {
    let mut vars = Vec::new();

    for var_name in &sandbox_config.env_baseline {
        if let Ok(val) = std::env::var(var_name) {
            vars.push((var_name.clone(), val));
        }
    }

    #[cfg(windows)]
    {
        if !sandbox_config.env_baseline.iter().any(|v| v.eq_ignore_ascii_case("SYSTEMROOT")) {
            if let Ok(val) = std::env::var("SYSTEMROOT") {
                vars.push(("SYSTEMROOT".into(), val));
            }
        }
        if !sandbox_config.env_baseline.iter().any(|v| v.eq_ignore_ascii_case("COMSPEC")) {
            if let Ok(val) = std::env::var("COMSPEC") {
                vars.push(("COMSPEC".into(), val));
            }
        }
    }

    for (k, v) in granted_env {
        vars.push((k.clone(), v.clone()));
    }

    vars
}

/// Spawn using normal Tokio Command (unsandboxed fallback).
async fn spawn_normal(
    program: &str,
    args: &[String],
    env_vars: &[(String, String)],
    timeout_secs: u64,
    max_output_bytes: u64,
) -> ReapResult {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ReapResult::SpawnFailed(format!("failed to spawn '{}': {e}", program));
        }
    };

    info!(program = program, sandboxed = false, "Child spawned");

    #[cfg(windows)]
    {
        if let Some(pid) = child.id() {
            if let Err(e) = assign_to_server_job(pid) {
                warn!(program = program, pid = pid, "Failed to assign child to Job Object: {e}");
            }
        }
    }

    let mut child_stdout = child.stdout.take();
    let mut child_stderr = child.stderr.take();

    let duration = Duration::from_secs(timeout_secs);
    let wait_result = timeout(duration, child.wait()).await;

    match wait_result {
        Ok(Ok(status)) => {
            let stdout = read_pipe(&mut child_stdout, max_output_bytes).await;
            let stderr = read_pipe(&mut child_stderr, max_output_bytes).await;
            ReapResult::Completed { exit_code: status.code(), stdout, stderr }
        }
        Ok(Err(e)) => {
            error!(program = program, "Child wait error: {e}");
            ReapResult::SpawnFailed(format!("child wait error: {e}"))
        }
        Err(_) => {
            warn!(program = program, timeout_secs = timeout_secs, "Child timed out — killing");
            if let Err(e) = child.kill().await { error!("Failed to kill child: {e}"); }
            let _ = child.wait().await;
            let stdout = read_pipe(&mut child_stdout, max_output_bytes).await;
            let stderr = read_pipe(&mut child_stderr, max_output_bytes).await;
            ReapResult::TimedOut { stdout, stderr }
        }
    }
}

// ── Linux Landlock Spawn ──────────────────────────────────────────────────────

/// Spawn a child with Landlock filesystem + network restrictions (Linux only).
///
/// Uses `pre_exec` to apply:
/// 1. `PR_SET_PDEATHSIG(SIGKILL)` — child dies when parent dies
/// 2. Landlock ruleset — restricts filesystem access to paths in the profile
/// 3. Optional TCP deny — blocks all bind + connect when `deny_network` is true
#[cfg(target_os = "linux")]
async fn spawn_landlock_linux(
    program: &str,
    args: &[String],
    env_vars: &[(String, String)],
    timeout_secs: u64,
    max_output_bytes: u64,
    profile: &crate::sandbox::SandboxProfile,
    deny_network: bool,
) -> ReapResult {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());

    // Configure the Landlock sandbox via pre_exec hook.
    // Safety: pre_exec runs after fork(), before exec(). The landlock crate
    // only uses syscalls. PR_SET_PDEATHSIG is async-signal-safe.
    unsafe {
        crate::sandbox::linux::configure_sandbox(cmd.as_std_mut(), profile, deny_network);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ReapResult::SpawnFailed(format!("failed to spawn '{}': {e}", program));
        }
    };

    info!(program = program, sandboxed = true, "Child spawned with Landlock sandbox");

    let mut child_stdout = child.stdout.take();
    let mut child_stderr = child.stderr.take();

    let duration = Duration::from_secs(timeout_secs);
    let wait_result = timeout(duration, child.wait()).await;

    match wait_result {
        Ok(Ok(status)) => {
            let stdout = read_pipe(&mut child_stdout, max_output_bytes).await;
            let stderr = read_pipe(&mut child_stderr, max_output_bytes).await;
            ReapResult::Completed { exit_code: status.code(), stdout, stderr }
        }
        Ok(Err(e)) => {
            error!(program = program, "Child wait error: {e}");
            ReapResult::SpawnFailed(format!("child wait error: {e}"))
        }
        Err(_) => {
            warn!(program = program, timeout_secs = timeout_secs, "Sandboxed child timed out — killing");
            if let Err(e) = child.kill().await { error!("Failed to kill child: {e}"); }
            let _ = child.wait().await;
            let stdout = read_pipe(&mut child_stdout, max_output_bytes).await;
            let stderr = read_pipe(&mut child_stderr, max_output_bytes).await;
            ReapResult::TimedOut { stdout, stderr }
        }
    }
}

// ── Windows AppContainer Spawn ────────────────────────────────────────────────

/// Spawn a child within an AppContainer sandbox (Windows only).
#[cfg(windows)]
async fn spawn_appcontainer_windows(
    program: &str,
    args: &[String],
    env_vars: &[(String, String)],
    timeout_secs: u64,
    max_output_bytes: u64,
    profile: &crate::sandbox::SandboxProfile,
) -> Result<ReapResult, std::io::Error> {
    use crate::sandbox::windows::{build_env_block, AppContainer, spawn_in_appcontainer};
    use std::time::Duration;
    use tokio::time::timeout;

    // Create AppContainer profile
    let mut container = AppContainer::create()?;
    info!(sid = %container.sid_string, "AppContainer created");

    // Grant access to write paths
    for path in &profile.write_paths {
        let raw = path.display().to_string();
        let clean = crate::sandbox::strip_glob_suffix(&raw);
        let clean_path = std::path::Path::new(&clean);
        if clean_path.exists() {
            match container.grant_access(clean_path, true) {
                Ok(()) => debug!(path = %clean, "AppContainer: granted write"),
                Err(e) => warn!(path = %clean, error = %e, "AppContainer: failed to grant write"),
            }
        }
    }

    // Grant access to read paths
    for path in &profile.read_paths {
        let raw = path.display().to_string();
        let clean = crate::sandbox::strip_glob_suffix(&raw);
        let clean_path = std::path::Path::new(&clean);
        if clean_path.exists() {
            match container.grant_access(clean_path, false) {
                Ok(()) => debug!(path = %clean, "AppContainer: granted read"),
                Err(e) => warn!(path = %clean, error = %e, "AppContainer: failed to grant read"),
            }
        }
    }

    // Build command line string (Windows format).
    let mut cmd_line = shell_escape_win(program);
    for arg in args {
        cmd_line.push(' ');
        cmd_line.push_str(&shell_escape_win(arg));
    }

    let env_block = build_env_block(env_vars);

    info!(cmd_line = %cmd_line, sid = %container.sid_string, allow_network = profile.allow_network, "AppContainer: spawning child process");
    let (pi, stdout_handle, stderr_handle) = spawn_in_appcontainer(&container, &cmd_line, &env_block, profile.allow_network)?;

    let pid = pi.dwProcessId;
    let process_h = pi.hProcess as usize;
    let thread_h = pi.hThread as usize;
    let stdout_h = stdout_handle as usize;
    let stderr_h = stderr_handle as usize;

    // Close the thread handle — we only need the process handle.
    crate::sandbox::windows::win32::CloseHandle(thread_h as std::os::windows::io::RawHandle);

    info!(program = program, pid = pid, sandboxed = true, container = %container.sid_string,
        "Child spawned in AppContainer");

    if let Err(e) = assign_to_server_job(pid) {
        warn!(pid = pid, "Failed to assign sandboxed child to Job Object: {e}");
    }

    let max_bytes = max_output_bytes;

    // Read stdout/stderr in blocking tasks (raw Win32 handles aren't async).
    let stdout_task = tokio::task::spawn_blocking(move || {
        read_raw_handle(stdout_h as std::os::windows::io::RawHandle, max_bytes)
    });
    let stderr_task = tokio::task::spawn_blocking(move || {
        read_raw_handle(stderr_h as std::os::windows::io::RawHandle, max_bytes)
    });

    // Wait for process with timeout.
    let duration = Duration::from_secs(timeout_secs);
    let wait_h = process_h; // Copy for the wait task
    let kill_h = process_h; // Copy for potential timeout kill
    let wait_result = timeout(duration,
        tokio::task::spawn_blocking(move || {
            wait_for_process(wait_h as std::os::windows::io::RawHandle)
        })
    ).await;

    // AppContainer profile is automatically deleted here when `container` is dropped.

    match wait_result {
        Ok(Ok(Ok(exit_code))) => {
            let stdout = stdout_task.await.unwrap_or_default();
            let stderr = stderr_task.await.unwrap_or_default();
            Ok(ReapResult::Completed { exit_code, stdout, stderr })
        }
        Ok(Ok(Err(e))) => Ok(ReapResult::SpawnFailed(format!("wait error: {e}"))),
        Ok(Err(e)) => Ok(ReapResult::SpawnFailed(format!("join error: {e}"))),
        Err(_) => {
            warn!(program = program, "Sandboxed child timed out — killing");
            kill_process_handle(kill_h as std::os::windows::io::RawHandle);
            let stdout = stdout_task.await.unwrap_or_default();
            let stderr = stderr_task.await.unwrap_or_default();
            Ok(ReapResult::TimedOut { stdout, stderr })
        }
    }
}

// ── Windows Restricted Spawn ──────────────────────────────────────────────────

/// Spawn a child with a Low Integrity restricted token (Windows only).
#[cfg(windows)]
async fn spawn_restricted_windows(
    program: &str,
    args: &[String],
    env_vars: &[(String, String)],
    timeout_secs: u64,
    max_output_bytes: u64,
) -> Result<ReapResult, std::io::Error> {
    use crate::sandbox::windows::{spawn_with_restricted_token, build_env_block};

    // Build command line string (Windows format).
    let mut cmd_line = shell_escape_win(program);
    for arg in args {
        cmd_line.push(' ');
        cmd_line.push_str(&shell_escape_win(arg));
    }

    let env_block = build_env_block(env_vars);
    let (pi, stdout_handle, stderr_handle) = spawn_with_restricted_token(&cmd_line, &env_block)?;

    let pid = pi.dwProcessId;
    let process_h = pi.hProcess as usize;
    let thread_h = pi.hThread as usize;
    let stdout_h = stdout_handle as usize;
    let stderr_h = stderr_handle as usize;

    // All raw handles are now captured as usize. Drop pi to prevent !Send contamination.
    drop(pi);

    info!(program = program, pid = pid, sandboxed = true,
        "Child spawned with Low Integrity token");

    if let Err(e) = assign_to_server_job(pid) {
        warn!(pid = pid, "Failed to assign sandboxed child to Job Object: {e}");
    }

    // Close the thread handle — we only need the process handle.
    crate::sandbox::windows::win32::CloseHandle(thread_h as std::os::windows::io::RawHandle);

    let max_bytes = max_output_bytes;

    // Read stdout/stderr in blocking tasks (raw Win32 handles aren't async).
    let stdout_task = tokio::task::spawn_blocking(move || {
        read_raw_handle(stdout_h as std::os::windows::io::RawHandle, max_bytes)
    });
    let stderr_task = tokio::task::spawn_blocking(move || {
        read_raw_handle(stderr_h as std::os::windows::io::RawHandle, max_bytes)
    });

    // Wait for process with timeout.
    let duration = Duration::from_secs(timeout_secs);
    let wait_h = process_h; // Copy for the wait task
    let kill_h = process_h; // Copy for potential timeout kill
    let wait_result = timeout(duration,
        tokio::task::spawn_blocking(move || {
            wait_for_process(wait_h as std::os::windows::io::RawHandle)
        })
    ).await;

    match wait_result {
        Ok(Ok(Ok(exit_code))) => {
            let stdout = stdout_task.await.unwrap_or_default();
            let stderr = stderr_task.await.unwrap_or_default();
            Ok(ReapResult::Completed { exit_code, stdout, stderr })
        }
        Ok(Ok(Err(e))) => Ok(ReapResult::SpawnFailed(format!("wait error: {e}"))),
        Ok(Err(e)) => Ok(ReapResult::SpawnFailed(format!("join error: {e}"))),
        Err(_) => {
            warn!(program = program, "Sandboxed child timed out — killing");
            kill_process_handle(kill_h as std::os::windows::io::RawHandle);
            let stdout = stdout_task.await.unwrap_or_default();
            let stderr = stderr_task.await.unwrap_or_default();
            Ok(ReapResult::TimedOut { stdout, stderr })
        }
    }
}

#[cfg(windows)]
fn wait_for_process(handle: std::os::windows::io::RawHandle) -> Result<Option<i32>, std::io::Error> {
    unsafe extern "system" {
        fn WaitForSingleObject(h: std::os::windows::io::RawHandle, ms: u32) -> u32;
        fn GetExitCodeProcess(h: std::os::windows::io::RawHandle, code: *mut u32) -> i32;
    }
    unsafe {
        WaitForSingleObject(handle, 0xFFFFFFFF);
        let mut code: u32 = 0;
        if GetExitCodeProcess(handle, &mut code) != 0 {
            crate::sandbox::windows::win32::CloseHandle(handle);
            Ok(Some(code as i32))
        } else {
            let err = std::io::Error::last_os_error();
            crate::sandbox::windows::win32::CloseHandle(handle);
            Err(err)
        }
    }
}

#[cfg(windows)]
fn kill_process_handle(handle: std::os::windows::io::RawHandle) {
    unsafe extern "system" {
        fn TerminateProcess(h: std::os::windows::io::RawHandle, code: u32) -> i32;
    }
    unsafe { TerminateProcess(handle, 1); }
}

#[cfg(windows)]
fn read_raw_handle(handle: std::os::windows::io::RawHandle, max_bytes: u64) -> Vec<u8> {
    unsafe extern "system" {
        fn ReadFile(
            h: std::os::windows::io::RawHandle, buf: *mut u8,
            to_read: u32, read: *mut u32, overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }
    let mut output = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if output.len() as u64 >= max_bytes { break; }
        let mut bytes_read: u32 = 0;
        let ok = unsafe { ReadFile(handle, buf.as_mut_ptr(), buf.len() as u32, &mut bytes_read, std::ptr::null_mut()) };
        if ok == 0 || bytes_read == 0 { break; }
        output.extend_from_slice(&buf[..bytes_read as usize]);
    }
    crate::sandbox::windows::win32::CloseHandle(handle);
    output
}

#[cfg(windows)]
fn shell_escape_win(s: &str) -> String {
    if s.contains(' ') || s.contains('"') {
        let mut escaped = String::from('"');
        for c in s.chars() {
            if c == '"' { escaped.push('\\'); }
            escaped.push(c);
        }
        escaped.push('"');
        escaped
    } else {
        s.to_string()
    }
}

// ── Shared Utilities ──────────────────────────────────────────────────────────

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

fn truncate_output(data: Vec<u8>, max_bytes: u64) -> Vec<u8> {
    if data.len() as u64 <= max_bytes { return data; }
    let mut truncated = data[..max_bytes as usize].to_vec();
    truncated.extend_from_slice(b"\n[output truncated by pansophical]");
    truncated
}

// ── Windows Job Object ────────────────────────────────────────────────────────

#[cfg(windows)]
use std::sync::OnceLock;

#[cfg(windows)]
static SERVER_JOB: OnceLock<crate::sandbox::windows::JobObject> = OnceLock::new();

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

#[cfg(windows)]
fn assign_to_server_job(pid: u32) -> std::io::Result<()> {
    if let Some(job) = SERVER_JOB.get() {
        job.assign_pid(pid)
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn init_server_job() {}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::SandboxConfig;

    fn test_sandbox() -> SandboxConfig {
        SandboxConfig {
            enabled: false, // Use normal spawn for existing tests
            strategy: "auto".into(),
            env_baseline: vec![
                "PATH".into(),
                "SYSTEMROOT".into(),
                "COMSPEC".into(),
                "TEMP".into(),
                "TMP".into(),
            ],
            allow_fallback: true,
            deny_network: true,
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

        let result = spawn_and_reap(program, &args, &test_sandbox(), &[], 5, 1024).await;

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
        unsafe { std::env::set_var("PANSOPHICAL_TEST_SECRET", "should_be_stripped") };

        let args: Vec<String> = if cfg!(windows) {
            vec!["/C".into(), "set".into()]
        } else {
            vec![]
        };
        let program = if cfg!(windows) { "cmd" } else { "env" };

        let result = spawn_and_reap(program, &args, &test_sandbox(), &[], 5, 65536).await;

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

        let result = spawn_and_reap(program, &args, &test_sandbox(), &[], 1, 1024).await;

        match result {
            ReapResult::TimedOut { .. } => {} // expected
            other => panic!("expected TimedOut, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn spawn_nonexistent() {
        let result = spawn_and_reap("nonexistent_binary_12345", &[], &test_sandbox(), &[], 5, 1024).await;
        match result {
            ReapResult::SpawnFailed(msg) => assert!(msg.contains("nonexistent_binary_12345")),
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
            program, &args, &test_sandbox(),
            &[("MY_GRANTED_VAR".into(), "granted_value".into())],
            5, 65536,
        ).await;

        match result {
            ReapResult::Completed { stdout, .. } => {
                let out = String::from_utf8_lossy(&stdout);
                assert!(out.contains("granted_value"), "granted env var should be visible: {out}");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// Test sandboxed spawn with Low Integrity token (Windows only).
    #[tokio::test]
    #[cfg(windows)]
    async fn sandboxed_spawn_echo() {
        let mut sandbox = test_sandbox();
        sandbox.enabled = true;

        let args: Vec<String> = vec!["/C".into(), "echo".into(), "sandboxed_hello".into()];
        let result = spawn_and_reap("cmd", &args, &sandbox, &[], 5, 1024).await;

        match result {
            ReapResult::Completed { exit_code, stdout, .. } => {
                assert_eq!(exit_code, Some(0));
                let out = String::from_utf8_lossy(&stdout);
                assert!(out.contains("sandboxed_hello"), "sandboxed child stdout: {out}");
            }
            other => panic!("expected sandboxed Completed, got {other:?}"),
        }
    }

    /// Verify that a sandboxed process runs at Low Integrity Level.
    ///
    /// Note: On elevated (admin) sessions, Low Integrity alone may not block
    /// writes to user directories. For full enforcement on elevated sessions,
    /// AppContainer or explicit DACLs are needed (Phase 2).
    #[tokio::test]
    #[cfg(windows)]
    async fn sandboxed_runs_at_low_integrity() {
        let mut sandbox = test_sandbox();
        sandbox.enabled = true;

        // `whoami /groups` shows the integrity level of the process.
        let args = vec!["/C".into(), "whoami".into(), "/groups".into()];
        let result = spawn_and_reap("cmd", &args, &sandbox, &[], 5, 65536).await;

        match result {
            ReapResult::Completed { stdout, .. } => {
                let out = String::from_utf8_lossy(&stdout);
                // The output should contain "Low Mandatory Level" for the sandboxed process.
                assert!(
                    out.contains("Low Mandatory Level"),
                    "Sandboxed process should run at Low Mandatory Level.\n\
                     Actual output:\n{out}"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// Full write-control test:
    /// 1. Create a dir with explicit Medium integrity → Low integrity process can't write
    /// 2. Set the dir to Low integrity → Low integrity process CAN write
    #[tokio::test]
    #[cfg(windows)]
    async fn sandboxed_write_control_via_integrity_labels() {
        let test_dir = std::env::temp_dir().join(format!("pansophical_wc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        std::fs::create_dir_all(&test_dir).unwrap();

        let dir_str = test_dir.display().to_string();

        // Set explicit Medium integrity on the dir.
        let icacls_out = std::process::Command::new("icacls")
            .args([&dir_str, "/setintegritylevel", "(OI)(CI)M"])
            .output()
            .expect("icacls failed");
        assert!(icacls_out.status.success(), "icacls set Medium failed");

        let mut sandbox = test_sandbox();
        sandbox.enabled = true;

        // Pass path via env var to avoid cmd.exe quoting issues with long paths.
        let env = vec![("TESTDIR".into(), dir_str.clone())];

        // 1. Try to write to Medium-integrity dir from Low-integrity process.
        let args = vec!["/C".into(), "copy nul %TESTDIR%\\test.txt".into()];
        let _ = spawn_and_reap("cmd", &args, &sandbox, &env, 5, 4096).await;

        let blocked = !test_dir.join("test.txt").exists();

        // 2. Set dir to Low integrity → should allow writes.
        let icacls_out = std::process::Command::new("icacls")
            .args([&dir_str, "/setintegritylevel", "(OI)(CI)L"])
            .output()
            .expect("icacls failed");
        assert!(icacls_out.status.success(), "icacls set Low failed");

        let args2 = vec!["/C".into(), "copy nul %TESTDIR%\\test2.txt".into()];
        let _ = spawn_and_reap("cmd", &args2, &sandbox, &env, 5, 4096).await;

        let allowed = test_dir.join("test2.txt").exists();

        // Clean up.
        let _ = std::fs::remove_dir_all(&test_dir);

        assert!(blocked, "Low integrity process should NOT write to Medium integrity dir");
        assert!(allowed, "Low integrity process SHOULD write to Low integrity dir");
    }

    /// Full AppContainer test:
    /// 1. AppContainer blocks writes to random directories
    /// 2. AppContainer allows writes to directories specifically granted in the SandboxProfile
    #[tokio::test]
    #[cfg(windows)]
    async fn sandboxed_appcontainer_isolation() {
        let test_dir = std::env::temp_dir().join(format!("pansophical_ac_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        std::fs::create_dir_all(&test_dir).unwrap();
        
        let write_dir = test_dir.join("write");
        std::fs::create_dir_all(&write_dir).unwrap();
        
        let no_write_dir = test_dir.join("nowrite");
        std::fs::create_dir_all(&no_write_dir).unwrap();

        let mut sandbox = test_sandbox();
        sandbox.enabled = true;

        let mut profile = crate::sandbox::SandboxProfile::default();
        profile.write_paths.push(write_dir.clone());
        
        let env = vec![
            ("WRITE_DIR".into(), write_dir.display().to_string()),
            ("NOWRITE_DIR".into(), no_write_dir.display().to_string()),
        ];
        
        crate::sandbox::with_profile(profile, async {
            // 1. Try to write to write_dir
            let args_write = vec!["/C".into(), "copy nul %WRITE_DIR%\\test.txt".into()];
            let _ = spawn_and_reap("cmd", &args_write, &sandbox, &env, 5, 4096).await;

            // 2. Try to write to no_write_dir
            let args_nowrite = vec!["/C".into(), "copy nul %NOWRITE_DIR%\\test.txt".into()];
            let _ = spawn_and_reap("cmd", &args_nowrite, &sandbox, &env, 5, 4096).await;
        }).await;
        
        let write_success = write_dir.join("test.txt").exists();
        let no_write_success = no_write_dir.join("test.txt").exists();
        
        // Clean up
        let _ = std::fs::remove_dir_all(&test_dir);
        
        assert!(write_success, "AppContainer should ALLOW writes to explicitly granted write_paths");
        assert!(!no_write_success, "AppContainer should BLOCK writes to ungranted paths");
    }
}
