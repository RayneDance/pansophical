//! Config hot-reload via file watcher.
//!
//! Watches `config.toml` for changes, re-parses, validates, and
//! atomically swaps the `Arc<RwLock<Config>>`. Clears all session
//! approvals on reload (policy change = no cached gates).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use notify::{EventKind, RecursiveMode, Watcher};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::audit::AuditLog;
use crate::config::schema::Config;
use crate::confirm::session::ApprovalCache;

/// Shared config handle for hot-reload.
pub type SharedConfig = Arc<RwLock<Config>>;

/// Start watching `config_path` for changes. Runs forever as a background task.
pub async fn watch_config(
    config_path: PathBuf,
    shared_config: SharedConfig,
    approval_cache: Arc<ApprovalCache>,
    audit: Arc<AuditLog>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    // Debounce: track the last reload time.
    let debounce = Duration::from_secs(2);

    // Start the filesystem watcher in a blocking thread.
    let watched_path = config_path.clone();
    let config_file_name = config_path.file_name()
        .unwrap_or_default()
        .to_os_string();
    std::thread::spawn(move || {
        let rt_tx = tx;
        let filter_name = config_file_name;
        let mut watcher = match notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            if let Ok(event) = event {
                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {
                        // Only fire if the changed file is our config file.
                        // The `notify` crate watches the parent directory, so
                        // writes to audit.log, state.json, etc. also trigger
                        // events. Filter them out to avoid reload spam.
                        let is_config = event.paths.iter().any(|p| {
                            p.file_name().is_some_and(|n| n == filter_name)
                        });
                        if is_config {
                            let _ = rt_tx.blocking_send(());
                        }
                    }
                    _ => {}
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to create file watcher: {e}");
                return;
            }
        };

        if let Err(e) = watcher.watch(&watched_path, RecursiveMode::NonRecursive) {
            error!("Failed to watch config file '{}': {e}", watched_path.display());
            return;
        }

        info!("Watching config file: {}", watched_path.display());

        // Keep the watcher alive forever.
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    });

    // Process reload events (debounced).
    let mut last_reload = std::time::Instant::now();

    while rx.recv().await.is_some() {
        // Debounce: ignore events within 500ms of the last reload.
        if last_reload.elapsed() < debounce {
            continue;
        }

        info!("Config change detected — reloading");

        match Config::load(&config_path) {
            Ok(new_config) => {
                // Atomically swap the config.
                {
                    let mut config = shared_config.write().await;
                    *config = new_config;
                }

                // Clear all session approvals (policy change invalidates gates).
                approval_cache.clear_all();

                // Audit the reload.
                audit.log_event("config_reload", "config reloaded successfully");

                info!("Config reloaded successfully");
                last_reload = std::time::Instant::now();
            }
            Err(e) => {
                // Keep the old config.
                warn!("Config reload failed (keeping old config): {e}");
                audit.log_event(
                    "config_reload_failed",
                    &format!("config reload failed: {e}"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reload_updates_config() {
        // Create a temp config file.
        let dir = std::env::temp_dir().join("pansophical_test_reload");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("test_reload.toml");

        let initial = r#"
[server]
server_secret = "test"
dev_mode = false
"#;
        std::fs::write(&config_path, initial).unwrap();

        let config = Config::load(&config_path).unwrap();
        assert!(!config.server.dev_mode);

        let shared = Arc::new(RwLock::new(config));
        let cache = Arc::new(ApprovalCache::new());
        let audit = Arc::new(AuditLog::new(&crate::config::schema::AuditConfig {
            enabled: false,
            output: "disabled".into(),
            path: String::new(),
        }));

        // Start the watcher.
        let shared_clone = Arc::clone(&shared);
        let cache_clone = Arc::clone(&cache);
        let audit_clone = Arc::clone(&audit);
        let path_clone = config_path.clone();

        tokio::spawn(async move {
            watch_config(path_clone, shared_clone, cache_clone, audit_clone).await;
        });

        // Give the watcher time to start.
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Modify the config.
        let updated = r#"
[server]
server_secret = "test"
dev_mode = true
"#;
        std::fs::write(&config_path, updated).unwrap();

        // Wait for the reload.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let config = shared.read().await;
        assert!(config.server.dev_mode, "config should have been reloaded with dev_mode=true");

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
