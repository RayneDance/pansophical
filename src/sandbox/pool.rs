//! Session-scoped AppContainer pool.
//!
//! Instead of creating a new AppContainer (with unique SID) per tool call,
//! this pool creates one container per API key and reuses it across all
//! tool invocations for that key. This eliminates ACE pollution (thousands
//! of orphaned ACEs from dead per-call containers) and amortizes the cost
//! of recursive ACL grants to a single first-use operation.
//!
//! ## Lifecycle
//!
//! 1. **Startup:** Load state file, clean up orphaned containers from prior crashes
//! 2. **First tool call:** Create container, run recursive grants (slow, one-time)
//! 3. **Subsequent calls:** Reuse cached container (instant)
//! 4. **Shutdown:** Revoke all grants, delete container profiles, remove state file

#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
use tokio::sync::{Notify, RwLock};
#[cfg(windows)]
use tracing::{info, warn};

#[cfg(windows)]
use super::windows::AppContainer;

// ── Pool key ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PoolKey {
    pub key_id: String,
    pub path_hash: u64,
}

#[cfg(windows)]
impl PoolKey {
    pub fn new(key_id: &str, paths: &[PathBuf]) -> Self {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut sorted: Vec<String> = paths
            .iter()
            .map(|p| p.display().to_string().to_lowercase().replace('\\', "/"))
            .collect();
        sorted.sort();

        let mut hasher = DefaultHasher::new();
        sorted.hash(&mut hasher);
        Self {
            key_id: key_id.to_string(),
            path_hash: hasher.finish(),
        }
    }

    /// Deterministic container name for this key, discoverable on restart.
    pub fn container_name(&self) -> String {
        format!("pansophical-{}-{:08x}", self.key_id, self.path_hash & 0xFFFFFFFF)
    }
}

// ── Pool entry ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub struct PoolEntry {
    pub container: AppContainer,
    pub ready: Notify,
    pub is_ready: std::sync::atomic::AtomicBool,
    pub active_count: AtomicUsize,
    pub granted_paths: Vec<String>,
}

// ── Container pool ───────────────────────────────────────────────────────────

#[cfg(windows)]
pub struct ContainerPool {
    entries: RwLock<HashMap<PoolKey, Arc<PoolEntry>>>,
    state_dir: PathBuf,
    skip_dirs: Vec<String>,
}

#[cfg(windows)]
impl ContainerPool {
    /// Create a new empty pool. Call `cleanup_orphans()` after creation.
    pub fn new(state_dir: PathBuf, skip_dirs: Vec<String>) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            state_dir,
            skip_dirs,
        }
    }

    /// Clean up any orphaned containers from a prior crash.
    ///
    /// Reads the state file, checks if the recorded PID is still alive,
    /// and if not, deletes all listed container profiles.
    pub async fn cleanup_orphans(&self) {
        let state_path = self.state_dir.join("appcontainer_state.json");
        if !state_path.exists() {
            return;
        }

        let content = match std::fs::read_to_string(&state_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Failed to read AppContainer state file");
                let _ = std::fs::remove_file(&state_path);
                return;
            }
        };

        let state: StateFile = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Failed to parse AppContainer state file");
                let _ = std::fs::remove_file(&state_path);
                return;
            }
        };

        // Check if the old process is still running.
        if is_process_alive(state.pid) {
            info!(pid = state.pid, "Prior pansophical process still running, skipping orphan cleanup");
            return;
        }

        info!(
            old_pid = state.pid,
            containers = state.containers.len(),
            "Cleaning up orphaned AppContainers from prior crash"
        );

        for entry in &state.containers {
            // Delete the container profile.
            let name_wide: Vec<u16> = entry.name.encode_utf16().chain(std::iter::once(0)).collect();
            super::windows::delete_appcontainer_profile(&name_wide);

            // Revoke ACEs from granted paths.
            for path in &entry.granted_paths {
                revoke_path_aces(&entry.sid, path);
            }

            info!(name = %entry.name, "Cleaned up orphaned container");
        }

        let _ = std::fs::remove_file(&state_path);
    }

    /// Get or create a container for the given key.
    ///
    /// On first call for a key, creates the container and runs the recursive
    /// ACL grant in a background task. The caller waits for the grant to
    /// complete before proceeding.
    pub async fn get_or_create(
        &self,
        key_id: &str,
        read_paths: &[PathBuf],
        write_paths: &[PathBuf],
    ) -> Result<Arc<PoolEntry>, String> {
        let all_paths: Vec<PathBuf> = read_paths.iter().chain(write_paths.iter()).cloned().collect();
        let key = PoolKey::new(key_id, &all_paths);

        // Fast path: check if already exists.
        {
            let entries = self.entries.read().await;
            if let Some(entry) = entries.get(&key) {
                entry.active_count.fetch_add(1, Ordering::Relaxed);
                let ready = entry.is_ready.load(Ordering::Acquire);
                info!(
                    key = %key_id,
                    sid = %entry.container.sid_string,
                    active = entry.active_count.load(Ordering::Relaxed),
                    ready,
                    "Pool HIT — reusing existing container"
                );
                if !ready {
                    info!(key = %key_id, "Waiting for initial grants to complete...");
                    entry.ready.notified().await;
                    info!(key = %key_id, "Initial grants complete, proceeding");
                }
                return Ok(Arc::clone(entry));
            }
        }

        // Slow path: create new container.
        info!(key = %key_id, read_count = read_paths.len(), write_count = write_paths.len(), "Pool MISS — creating new container");
        let total_start = std::time::Instant::now();

        let container_name = key.container_name();
        let mut container = AppContainer::create_named(&container_name)
            .map_err(|e| format!("failed to create AppContainer: {e}"))?;

        info!(
            key = %key_id,
            container = %container_name,
            sid = %container.sid_string,
            elapsed_ms = total_start.elapsed().as_millis() as u64,
            "AppContainer profile created"
        );

        // Run recursive grants — time each operation.
        let skip = self.skip_dirs.clone();
        info!(skip_dirs = ?skip, "Skip directories for recursive walk");
        let mut granted: Vec<String> = Vec::new();

        for (i, path) in read_paths.iter().enumerate() {
            let clean = super::strip_glob_suffix(&path.display().to_string());
            let clean_path = Path::new(&clean);
            if clean_path.exists() {
                let t = std::time::Instant::now();
                info!(path = %clean, index = i, "READ grant: starting recursive walk");
                match super::windows::grant_recursive(
                    clean_path, &container.sid_string, false, &skip,
                ) {
                    Ok(count) => {
                        info!(
                            path = %clean,
                            count,
                            elapsed_ms = t.elapsed().as_millis() as u64,
                            "READ grant: recursive walk complete"
                        );
                        granted.push(clean.clone());
                        container.track_granted_path(clean.clone());
                    }
                    Err(e) => warn!(path = %clean, error = %e, elapsed_ms = t.elapsed().as_millis() as u64, "READ grant: FAILED"),
                }
                // Grant traverse on ancestor directories.
                let t2 = std::time::Instant::now();
                info!(path = %clean, "READ grant: granting ancestor traverse");
                if let Err(e) = super::windows::grant_path_and_ancestors(
                    clean_path, &container.sid_string,
                ) {
                    warn!(path = %clean, error = %e, "READ grant: ancestor traverse FAILED");
                } else {
                    info!(path = %clean, elapsed_ms = t2.elapsed().as_millis() as u64, "READ grant: ancestor traverse complete");
                }
            } else {
                warn!(path = %clean, "READ grant: path does not exist — skipping");
            }
        }

        for (i, path) in write_paths.iter().enumerate() {
            let clean = super::strip_glob_suffix(&path.display().to_string());
            let clean_path = Path::new(&clean);
            if clean_path.exists() {
                let t = std::time::Instant::now();
                info!(path = %clean, index = i, "WRITE grant: starting recursive walk");
                match super::windows::grant_recursive(
                    clean_path, &container.sid_string, true, &skip,
                ) {
                    Ok(count) => {
                        info!(
                            path = %clean,
                            count,
                            elapsed_ms = t.elapsed().as_millis() as u64,
                            "WRITE grant: recursive walk complete"
                        );
                        granted.push(clean.clone());
                        container.track_granted_path(clean.clone());
                    }
                    Err(e) => warn!(path = %clean, error = %e, elapsed_ms = t.elapsed().as_millis() as u64, "WRITE grant: FAILED"),
                }
                // Grant traverse on ancestor directories.
                let t2 = std::time::Instant::now();
                info!(path = %clean, "WRITE grant: granting ancestor traverse");
                if let Err(e) = super::windows::grant_path_and_ancestors(
                    clean_path, &container.sid_string,
                ) {
                    warn!(path = %clean, error = %e, "WRITE grant: ancestor traverse FAILED");
                } else {
                    info!(path = %clean, elapsed_ms = t2.elapsed().as_millis() as u64, "WRITE grant: ancestor traverse complete");
                }
            } else {
                warn!(path = %clean, "WRITE grant: path does not exist — skipping");
            }
        }

        info!(
            key = %key_id,
            total_granted = granted.len(),
            total_elapsed_ms = total_start.elapsed().as_millis() as u64,
            "All grants complete — container ready"
        );

        let entry = Arc::new(PoolEntry {
            container,
            ready: Notify::new(),
            is_ready: std::sync::atomic::AtomicBool::new(true),
            active_count: AtomicUsize::new(1),
            granted_paths: granted,
        });
        entry.ready.notify_waiters();

        // Save to pool.
        {
            let mut entries = self.entries.write().await;
            entries.insert(key, Arc::clone(&entry));
        }

        // Update state file.
        self.write_state_file().await;

        Ok(entry)
    }

    /// Release a pool entry (decrement active count).
    pub fn release(entry: &Arc<PoolEntry>) {
        entry.active_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Clean up all containers. Called on graceful shutdown.
    pub async fn cleanup_all(&self) {
        let mut entries = self.entries.write().await;
        let count = entries.len();
        if count == 0 {
            return;
        }

        info!(count, "Cleaning up AppContainer pool");

        // Entries will be cleaned up when dropped (AppContainer::drop calls revoke + delete).
        entries.clear();

        // Remove state file.
        let state_path = self.state_dir.join("appcontainer_state.json");
        let _ = std::fs::remove_file(&state_path);

        info!("AppContainer pool cleanup complete");
    }

    /// Write the current pool state to the state file for crash recovery.
    async fn write_state_file(&self) {
        let entries = self.entries.read().await;
        let containers: Vec<StateEntry> = entries
            .iter()
            .map(|(key, entry)| StateEntry {
                name: key.container_name(),
                sid: entry.container.sid_string.clone(),
                granted_paths: entry.granted_paths.clone(),
            })
            .collect();

        let state = StateFile {
            pid: std::process::id(),
            containers,
        };

        let state_path = self.state_dir.join("appcontainer_state.json");
        match serde_json::to_string_pretty(&state) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&state_path, json) {
                    warn!(error = %e, "Failed to write AppContainer state file");
                }
            }
            Err(e) => warn!(error = %e, "Failed to serialize AppContainer state"),
        }
    }
}

// ── State file ───────────────────────────────────────────────────────────────

#[cfg(windows)]
#[derive(serde::Serialize, serde::Deserialize)]
struct StateFile {
    pid: u32,
    containers: Vec<StateEntry>,
}

#[cfg(windows)]
#[derive(serde::Serialize, serde::Deserialize)]
struct StateEntry {
    name: String,
    sid: String,
    granted_paths: Vec<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
fn is_process_alive(pid: u32) -> bool {
    use std::os::windows::io::RawHandle;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;

    // Use GetExitCodeProcess only — avoid redeclaring OpenProcess
    #[allow(clashing_extern_declarations)]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> RawHandle;
        fn GetExitCodeProcess(handle: RawHandle, code: *mut u32) -> i32;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(handle, &mut code);
        super::windows::win32::CloseHandle(handle);
        ok != 0 && code == STILL_ACTIVE
    }
}

#[cfg(windows)]
fn revoke_path_aces(sid_string: &str, path: &str) {
    use super::windows::appcontainer::revoke_recursive;
    if let Err(e) = revoke_recursive(std::path::Path::new(path), sid_string) {
        warn!(path = %path, error = %e, "Failed to revoke orphaned ACEs");
    }
}

// ── Key ID resolution ────────────────────────────────────────────────────────

/// Get the current key ID from the task-local context.
/// Falls back to "default" if no key is set (e.g. during tests).
#[cfg(windows)]
pub fn current_key_id() -> String {
    super::current_key_name().unwrap_or_else(|| "default".into())
}
