mod config;
mod authz;
mod audit;
mod sandbox;
mod reaper;
mod limits;
mod confirm;
mod transport;
mod tools;
mod protocol;
mod session;
mod error;

use clap::Parser;
use std::path::PathBuf;
use tracing::{info, error};

use crate::error::{PansophicalError, Result};

/// Pansophical — Security-first MCP server with intersection-based authorization.
#[derive(Parser, Debug)]
#[command(name = "pansophical", version, about)]
struct Cli {
    /// Path to config file.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    /// Generate a new config.toml with a random server_secret, then exit.
    #[arg(long)]
    init: bool,

    /// Validate the config file and exit with 0 (valid) or 1 (invalid).
    #[arg(long)]
    check: bool,
}

fn main() {
    // Initialize tracing (structured logging).
    // IMPORTANT: Write to stderr, NOT stdout — stdout is the JSON-RPC channel.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let result = if cli.init {
        run_init(&cli.config)
    } else if cli.check {
        run_check(&cli.config)
    } else {
        run_server(&cli.config)
    };

    if let Err(e) = result {
        error!("{e}");
        std::process::exit(1);
    }
}

/// `--init`: Generate a well-commented config.toml with a random server_secret.
fn run_init(path: &PathBuf) -> Result<()> {
    use base64::Engine;
    use rand::RngCore;

    if path.exists() {
        return Err(PansophicalError::Config(format!(
            "config file already exists: {}. Remove it first or use a different path with --config.",
            path.display()
        )));
    }

    // Generate a 32-byte random secret, base64-encoded.
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let server_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);

    // Generate a random demo API token.
    let mut token_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let demo_token = format!("sk_demo_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes));

    let config_content = generate_default_config(&server_secret, &demo_token);

    std::fs::write(path, config_content)?;
    info!("Config written to: {}", path.display());
    info!("Server secret generated (base64). Keep this value safe.");

    // Create the tools/ directory and populate with examples.
    let tools_dir = path.parent().unwrap_or(std::path::Path::new(".")).join("tools");
    if !tools_dir.exists() {
        std::fs::create_dir_all(&tools_dir)?;
        info!("Created tools directory: {}", tools_dir.display());
    }

    write_example_tools(&tools_dir)?;

    info!("Initialization complete. Run `pansophical` to start the server.");
    Ok(())
}

/// Write example script tool definitions into the tools directory.
fn write_example_tools(tools_dir: &std::path::Path) -> Result<()> {
    let examples: &[(&str, &str)] = &[
        ("hello_world.toml", r#"# ══════════════════════════════════════════════════════════════
# Example: Hello World
# ══════════════════════════════════════════════════════════════
# A minimal script tool that echoes a greeting.
# Demonstrates basic parameter passing and shell usage.

name        = "hello_world"
description = "Say hello to someone"
command     = "echo"
args        = ["Hello,"]
allow_shell = false

# Parameters are appended to args when the agent calls the tool.
[[parameters]]
name        = "name"
description = "Name to greet"
required    = true
"#),
        ("git_status.toml", r#"# ══════════════════════════════════════════════════════════════
# Example: Git Status
# ══════════════════════════════════════════════════════════════
# Reports the git status of the current directory.
# No agent-supplied arguments — fully locked down.

name            = "git_status"
description     = "Show git status in short format"
command         = "git"
args            = ["status", "--short"]
allow_shell     = false
arg_passthrough = false
"#),
        ("disk_usage.toml", r#"# ══════════════════════════════════════════════════════════════
# Example: Disk Usage
# ══════════════════════════════════════════════════════════════
# Reports disk usage for the current directory.
# Demonstrates a tool with no parameters (fixed command).

name            = "disk_usage"
description     = "Show disk usage summary for the working directory"
command         = "du"
args            = ["-sh", "."]
allow_shell     = false
arg_passthrough = false
"#),
        ("list_processes.toml", r#"# ══════════════════════════════════════════════════════════════
# Example: List Processes (Windows)
# ══════════════════════════════════════════════════════════════
# Lists running processes. Uses cmd.exe, so allow_shell = true.
# This is an example of explicitly opting into shell access.

name        = "list_processes"
description = "List running processes (Windows)"
command     = "cmd"
args        = ["/C", "tasklist", "/FO", "TABLE"]
allow_shell = true
"#),
    ];

    for (filename, content) in examples {
        let file_path = tools_dir.join(filename);
        if !file_path.exists() {
            std::fs::write(&file_path, content)?;
            info!("  Created example: tools/{}", filename);
        }
    }

    Ok(())
}


/// `--check`: Parse and validate the config file with full schema validation.
fn run_check(path: &PathBuf) -> Result<()> {
    if !path.exists() {
        return Err(PansophicalError::ConfigNotFound {
            path: path.display().to_string(),
        });
    }

    let config = config::schema::Config::load(path)?;
    info!(
        "Config OK: {} ({} keys configured)",
        path.display(),
        config.keys.len()
    );
    Ok(())
}

/// Default server mode: load config and run the transport loop.
fn run_server(path: &PathBuf) -> Result<()> {
    use std::sync::Arc;

    if !path.exists() {
        return Err(PansophicalError::ConfigNotFound {
            path: path.display().to_string(),
        });
    }

    let config = config::schema::Config::load(path)?;

    info!("Pansophical v{}", env!("CARGO_PKG_VERSION"));
    info!("Config: {}", path.display());
    info!("Transport: {}", config.server.transport);

    // Initialize the Windows Job Object for child process containment.
    reaper::init_server_job();

    // Create the audit log.
    let audit = Arc::new(audit::AuditLog::new(&config.audit));
    audit.log_event("startup", &format!(
        "Pansophical v{} starting, transport={}",
        env!("CARGO_PKG_VERSION"),
        config.server.transport,
    ));

    // Create the approval cache and confirm state.
    let approval_cache = Arc::new(confirm::session::ApprovalCache::new());
    let mut cs = confirm::server::ConfirmState::new(
        Arc::clone(&approval_cache),
        Arc::clone(&audit),
        config.server.server_secret.clone(),
    );
    cs.admin_pin = config.ui.auth.pin.clone();
    let confirm_state = Arc::new(cs);

    // Pre-populate dashboard data (tools + keys) for the admin UI.
    {
        let registry = tools::ToolRegistry::load_from_config(&config);
        let tools_list = registry.list();
        let tools_json = serde_json::to_string(&tools_list).unwrap_or_else(|_| "[]".into());

        // Serialize keys config (name → rules only, no tokens).
        let keys_json = {
            let mut keys_obj = serde_json::Map::new();
            for (name, key_config) in &config.keys {
                keys_obj.insert(
                    name.clone(),
                    serde_json::to_value(&key_config.rules).unwrap_or(serde_json::json!([])),
                );
            }
            serde_json::to_string(&keys_obj).unwrap_or_else(|_| "{}".into())
        };

        // Set dashboard data synchronously (no need for a runtime — just lock the mutex).
        let rt_tmp = tokio::runtime::Runtime::new()
            .map_err(|e| PansophicalError::Other(format!("failed to create runtime: {e}")))?;
        let cs = Arc::clone(&confirm_state);
        rt_tmp.block_on(cs.set_dashboard_data(tools_json, keys_json));
    }

    match config.server.transport.as_str() {
        "stdio" => {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PansophicalError::Other(format!("failed to create runtime: {e}")))?;
            rt.block_on(async {
                // Start the confirm server as a background task.
                let confirm_port = config.ui.port;
                let confirm_state_bg = Arc::clone(&confirm_state);
                tokio::spawn(async move {
                    confirm::server::start(confirm_state_bg, confirm_port).await;
                });

                // Start the approval cache sweeper (every 30s).
                let cache_sweep = Arc::clone(&approval_cache);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                        let swept = cache_sweep.sweep_expired();
                        if swept > 0 {
                            tracing::debug!(swept, "Swept expired approvals");
                        }
                    }
                });

                // Start config hot-reload watcher.
                let watcher_path = path.clone();
                let watcher_cache = Arc::clone(&approval_cache);
                let watcher_audit = Arc::clone(&audit);
                let shared_config = Arc::new(tokio::sync::RwLock::new(config.clone()));
                let shared_config_watcher = Arc::clone(&shared_config);
                tokio::spawn(async move {
                    config::watcher::watch_config(
                        watcher_path,
                        shared_config_watcher,
                        watcher_cache,
                        watcher_audit,
                    )
                    .await;
                });

                // Run the stdio transport.
                transport::stdio::run(config, audit, confirm_state).await;
            });
        }
        "http" => {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PansophicalError::Other(format!("failed to create runtime: {e}")))?;
            rt.block_on(async {
                // Start the confirm server.
                let confirm_port = config.ui.port;
                let confirm_state_bg = Arc::clone(&confirm_state);
                tokio::spawn(async move {
                    confirm::server::start(confirm_state_bg, confirm_port).await;
                });

                // Start the approval cache sweeper.
                let cache_sweep = Arc::clone(&approval_cache);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                        let swept = cache_sweep.sweep_expired();
                        if swept > 0 {
                            tracing::debug!(swept, "Swept expired approvals");
                        }
                    }
                });

                // Start config hot-reload watcher.
                let watcher_path = path.clone();
                let watcher_cache = Arc::clone(&approval_cache);
                let watcher_audit = Arc::clone(&audit);
                let shared_config = Arc::new(tokio::sync::RwLock::new(config.clone()));
                let shared_config_watcher = Arc::clone(&shared_config);
                tokio::spawn(async move {
                    config::watcher::watch_config(
                        watcher_path,
                        shared_config_watcher,
                        watcher_cache,
                        watcher_audit,
                    )
                    .await;
                });

                // Run the HTTP transport (blocks).
                transport::http::run(config, audit, confirm_state).await;
            });
        }
        "both" => {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PansophicalError::Other(format!("failed to create runtime: {e}")))?;
            rt.block_on(async {
                // Start the confirm server.
                let confirm_port = config.ui.port;
                let confirm_state_bg = Arc::clone(&confirm_state);
                tokio::spawn(async move {
                    confirm::server::start(confirm_state_bg, confirm_port).await;
                });

                // Start the approval cache sweeper.
                let cache_sweep = Arc::clone(&approval_cache);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                        let swept = cache_sweep.sweep_expired();
                        if swept > 0 {
                            tracing::debug!(swept, "Swept expired approvals");
                        }
                    }
                });

                // Start config hot-reload watcher.
                let watcher_path = path.clone();
                let watcher_cache = Arc::clone(&approval_cache);
                let watcher_audit = Arc::clone(&audit);
                let shared_config = Arc::new(tokio::sync::RwLock::new(config.clone()));
                let shared_config_watcher = Arc::clone(&shared_config);
                tokio::spawn(async move {
                    config::watcher::watch_config(
                        watcher_path,
                        shared_config_watcher,
                        watcher_cache,
                        watcher_audit,
                    )
                    .await;
                });

                // Run HTTP transport in background.
                let http_config = config.clone();
                let http_audit = Arc::clone(&audit);
                let http_confirm = Arc::clone(&confirm_state);
                tokio::spawn(async move {
                    transport::http::run(http_config, http_audit, http_confirm).await;
                });

                // Run stdio transport in foreground.
                transport::stdio::run(config, audit, confirm_state).await;
            });
        }
        _ => {
            // Validated at config load time, but just in case.
            return Err(PansophicalError::ConfigValidation(
                "unknown transport".into(),
            ));
        }
    }

    Ok(())
}

/// Generate the default config.toml content with the given server secret.
fn generate_default_config(server_secret: &str, demo_token: &str) -> String {
    format!(
        r##"# ══════════════════════════════════════════════════════════════════════════════
# Pansophical — MCP Server Configuration
# ══════════════════════════════════════════════════════════════════════════════
#
# This file controls authorization policy, transport settings, safety rails,
# and UI theming for the Pansophical MCP server.
#
# Hot reload: the server watches this file for changes. On modification, it
# re-parses and validates; if valid, the new policy takes effect immediately.
# If invalid, the old policy remains active and a warning is logged.

# ── Server ─────────────────────────────────────────────────────────────────────

[server]
host          = "127.0.0.1"
port          = 3000
transport     = "stdio"       # "stdio" | "http" | "both"
# HMAC signing secret for confirm tokens. Auto-generated on --init.
# Set explicitly to keep tokens valid across restarts.
server_secret = "{server_secret}"
# Expose policy diffs in denial responses. NEVER enable in production.
dev_mode      = false

[server.http]
cors_origins        = ["http://localhost:*"]
on_disconnect       = "kill"   # "kill" | "detach"
reattach_grace_secs = 30

# ── Tools ──────────────────────────────────────────────────────────────────────

[tools]
dir = "./tools"   # path to script tool definition directory

# ── Sandbox ────────────────────────────────────────────────────────────────────

[sandbox]
enabled      = true     # disable only if platform support is unavailable
strategy     = "auto"   # "auto" | "landlock" (Linux) | "app_container" (Windows)
env_baseline = ["PATH", "SYSTEMROOT", "COMSPEC", "TERM", "LANG", "HOME"]  # vars always passed to child

# ── Audit ──────────────────────────────────────────────────────────────────────

[audit]
enabled = true
output  = "file"   # "stdout" | "file" | "syslog"
                   # NOTE: "stdout" is forbidden when transport = "stdio"
path    = "audit.log"

# ── Safety Rails ───────────────────────────────────────────────────────────────

[limits]
max_invocations_per_minute = 60
max_concurrent_tools        = 4
tool_timeout_secs           = 30
max_output_bytes            = 1048576   # 1 MiB

# ── UI / Admin Dashboard ──────────────────────────────────────────────────────

[ui]
port      = 9765
auto_open = "confirm"   # "startup" | "confirm" | "never"

[ui.auth]
pin = ""   # set a PIN to protect admin routes; leave empty for localhost-only

[ui.confirm]
timeout_secs                     = 30
session_approval_options         = [5, 30, 0]   # minutes; 0 = session
session_approval_inactivity_secs = 300

# ── Theming ────────────────────────────────────────────────────────────────────

[ui.theme]
preset = "dark"   # "dark" | "light" | "system"

# ── Keys ───────────────────────────────────────────────────────────────────────
#
# Each key has a bearer token and a set of policy rules.
# The intersection model means: only explicitly granted access is allowed.

# Demo key — auto-generated by --init. Replace with real keys for production.
[keys.demo]
token = "{demo_token}"

# Grant access to all registered tools.
[[keys.demo.rules]]
effect = "grant"
type   = "tool"
name   = "*"

# Grant read/write to the current working directory.
# ⚠ Tighten this path for production use!
[[keys.demo.rules]]
effect = "grant"
type   = "filesystem"
path   = "**"
perm   = "rw"

# Allow tools to see common environment variables.
[[keys.demo.rules]]
effect      = "grant"
type        = "environment"
var_pattern = "USER"

[[keys.demo.rules]]
effect      = "grant"
type        = "environment"
var_pattern = "HOSTNAME"

# ── Additional Keys ───────────────────────────────────────────────────────────
#
# Add more keys for different agents or environments:
#
# [keys.production_agent]
# token = "sk_live_replace_me"
#
# # Only allow specific tools.
# [[keys.production_agent.rules]]
# effect = "grant"
# type   = "tool"
# name   = "read_file"
#
# [[keys.production_agent.rules]]
# effect = "grant"
# type   = "tool"
# name   = "list_dir"
#
# # Restrict filesystem to a specific workspace.
# [[keys.production_agent.rules]]
# effect = "grant"
# type   = "filesystem"
# path   = "C:/Projects/my_workspace/**"
# perm   = "r"
#
# # Inject env vars into tool processes (e.g., API keys, config).
# [[keys.production_agent.rules]]
# effect      = "grant"
# type        = "environment"
# var_pattern = "DATABASE_URL"
#
# [[keys.production_agent.rules]]
# effect      = "grant"
# type        = "environment"
# var_pattern = "API_*"    # wildcard: all vars starting with API_
#
# # Allow running git but require human confirmation.
# [[keys.production_agent.rules]]
# effect     = "grant"
# type       = "program"
# executable = "git"
# confirm    = true
"##
    )
}
