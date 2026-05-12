mod config;
mod authz;
mod audit;
mod sandbox;
mod reaper;
#[allow(dead_code)]
mod limits;
mod confirm;
mod transport;
mod tools;
mod protocol;
mod session;
mod error;

use clap::Parser;
use std::path::{Path, PathBuf};
use tracing::{info, error};

use crate::error::{PansophicalError, Result};

/// Pansophical — Security-first MCP server with intersection-based authorization.
#[derive(Parser, Debug)]
#[command(name = "pansophical", version, about)]
struct Cli {
    /// Path to config file.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    /// Generate a minimal config.toml with a random server_secret, then exit.
    #[arg(long)]
    init: bool,

    /// Set up a full demo environment with AST tools, scoped key, and system prompt.
    #[cfg(feature = "demo")]
    #[arg(long)]
    demo: bool,

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
    } else if {
        #[cfg(feature = "demo")]
        { cli.demo }
        #[cfg(not(feature = "demo"))]
        { false }
    } {
        #[cfg(feature = "demo")]
        { run_demo(&cli.config) }
        #[cfg(not(feature = "demo"))]
        { unreachable!() }
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

/// `--init`: Generate a minimal config.toml with a random server_secret.
///
/// Creates only the config file and an empty tools/ directory.
/// For a full demo setup with AST tools, use `--demo` instead.
fn run_init(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(PansophicalError::Config(format!(
            "config file already exists: {}. Remove it first or use a different path with --config.",
            path.display()
        )));
    }

    let (server_secret, demo_token) = generate_secrets();
    let config_content = generate_default_config(&server_secret, &demo_token);

    std::fs::write(path, config_content)?;
    info!("Config written to: {}", path.display());
    info!("Demo token: {demo_token}");

    // Create the tools/ directory (empty — user adds tools as needed).
    let tools_dir = path.parent().unwrap_or(Path::new(".")).join("tools");
    if !tools_dir.exists() {
        std::fs::create_dir_all(&tools_dir)?;
        info!("Created tools directory: {}", tools_dir.display());
    }

    info!("");
    info!("Initialization complete.");
    info!("  Start server:   pansophical");
    info!("  Full demo:      pansophical --demo");
    info!("  Validate:       pansophical --check");
    Ok(())
}

#[cfg(feature = "demo")]
/// `--demo`: Set up a full demo environment showcasing best practices.
///
/// Creates:
/// - config.toml with a scoped coding_agent key
/// - tools/ directory populated with AST tools + web search
/// - system_prompt.md for Vertex AI integration
fn run_demo(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(PansophicalError::Config(format!(
            "config file already exists: {}. Remove it first or use a different path with --config.",
            path.display()
        )));
    }

    let (server_secret, agent_token) = generate_secrets();

    // Detect the current working directory for scoped filesystem grants.
    let workspace = std::env::current_dir()
        .map(|p| p.display().to_string().replace('\\', "/"))
        .unwrap_or_else(|_| ".".to_string());

    let config_content = generate_demo_config(&server_secret, &agent_token, &workspace);
    std::fs::write(path, &config_content)?;
    info!("Config written to: {}", path.display());

    // Create and populate tools/.
    let tools_dir = path.parent().unwrap_or(Path::new(".")).join("tools");
    if !tools_dir.exists() {
        std::fs::create_dir_all(&tools_dir)?;
    }
    write_demo_tools(&tools_dir)?;

    // Write the system prompt.
    let prompt_path = path.parent().unwrap_or(Path::new(".")).join("system_prompt.md");
    if !prompt_path.exists() {
        std::fs::write(&prompt_path, DEMO_SYSTEM_PROMPT)?;
        info!("  Created system_prompt.md");
    }

    info!("");
    info!("Demo setup complete!");
    info!("  Workspace:     {workspace}");
    info!("  Agent token:   {agent_token}");
    info!("  AST tools:     8 tools in the 'ast' group");
    info!("  Web search:    ext_web_search (DuckDuckGo)");
    info!("");
    info!("  Start server:  pansophical");
    info!("  Validate:      pansophical --check");
    Ok(())
}

/// Generate cryptographically random server secret and API token.
fn generate_secrets() -> (String, String) {
    use base64::Engine;
    use rand::RngCore;

    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let server_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);

    let mut token_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let token = format!("sk_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes));

    (server_secret, token)
}

#[cfg(feature = "demo")]
/// Write demo tool definitions — AST tools + web search.
fn write_demo_tools(tools_dir: &Path) -> Result<()> {
    let tools: &[(&str, &str)] = &[
        ("ast_map.toml", include_str!("../tools/ast_map.toml")),
        ("ast_show.toml", include_str!("../tools/ast_show.toml")),
        ("ast_digest.toml", include_str!("../tools/ast_digest.toml")),
        ("ast_search.toml", include_str!("../tools/ast_search.toml")),
        ("ast_callees.toml", include_str!("../tools/ast_callees.toml")),
        ("ast_callers.toml", include_str!("../tools/ast_callers.toml")),
        ("ast_implements.toml", include_str!("../tools/ast_implements.toml")),
        ("ast_reverse_deps.toml", include_str!("../tools/ast_reverse_deps.toml")),
        ("web_search.toml", include_str!("../tools/web_search.toml")),
    ];

    for (filename, content) in tools {
        let file_path = tools_dir.join(filename);
        if !file_path.exists() {
            std::fs::write(&file_path, content)?;
            info!("  Created tools/{filename}");
        }
    }

    Ok(())
}


/// `--check`: Parse and validate the config file with full schema validation.
fn run_check(path: &Path) -> Result<()> {
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
fn run_server(path: &Path) -> Result<()> {
    use std::sync::Arc;

    if !path.exists() {
        return Err(PansophicalError::ConfigNotFound {
            path: path.display().to_string(),
        });
    }

    let config = config::schema::Config::load(path)?;

    let version = build_version();
    info!("{version}");
    info!("Config: {}", path.display());
    info!("Transport: {}", config.server.transport);

    // Initialize the Windows Job Object for child process containment.
    reaper::init_server_job();

    // Create the audit log.
    let audit = Arc::new(audit::AuditLog::new(&config.audit));
    audit.log_event("startup", &format!(
        "{version}, transport={}",
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
                // Initialize AppContainer pool (Windows only).
                #[cfg(windows)]
                {
                    let config_dir = path.parent()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| std::path::PathBuf::from("."));
                    reaper::init_container_pool(&config.sandbox, config_dir).await;
                }

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
                let watcher_path = path.to_path_buf();
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

                // Cleanup AppContainer pool on shutdown.
                #[cfg(windows)]
                reaper::cleanup_container_pool().await;
            });
        }
        "http" => {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PansophicalError::Other(format!("failed to create runtime: {e}")))?;
            rt.block_on(async {
                // Initialize AppContainer pool (Windows only).
                #[cfg(windows)]
                {
                    let config_dir = path.parent()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| std::path::PathBuf::from("."));
                    reaper::init_container_pool(&config.sandbox, config_dir).await;
                }

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
                let watcher_path = path.to_path_buf();
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

                // Cleanup AppContainer pool on shutdown.
                #[cfg(windows)]
                reaper::cleanup_container_pool().await;
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
                let watcher_path = path.to_path_buf();
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
# token    = "sk_live_replace_me"
# env_file = ".env"  # load env vars from a .env file (KEY=VALUE format)
#
# # Only allow specific tools.
# [[keys.production_agent.rules]]
# effect = "grant"
# type   = "tool"
# name   = "builtin_read_file"
#
# [[keys.production_agent.rules]]
# effect = "grant"
# type   = "tool"
# name   = "builtin_list_dir"
#
# # Restrict filesystem to a specific workspace.
# [[keys.production_agent.rules]]
# effect = "grant"
# type   = "filesystem"
# path   = "C:/Projects/my_workspace/**"
# perm   = "r"
#
# # Inject env vars into tool processes (e.g., API keys, config).
# # With value: injects the literal value into the child process.
# [[keys.production_agent.rules]]
# effect      = "grant"
# type        = "environment"
# var_pattern = "DATABASE_URL"
# value       = "postgres://localhost:5432/mydb"
#
# # Without value: passes through from the server's parent env.
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
\"##
    )
}

#[cfg(feature = "demo")]
/// Generate a demo config.toml with scoped grants and AST tool showcase.
fn generate_demo_config(server_secret: &str, agent_token: &str, workspace: &str) -> String {
    format!(
        r##"# ══════════════════════════════════════════════════════════════════════════════
# Pansophical — Demo Configuration (generated by --demo)
# ══════════════════════════════════════════════════════════════════════════════
#
# This config demonstrates best practices for a coding agent setup:
# - Scoped filesystem grants (read/write to your workspace only)
# - Grouped AST tools for code analysis
# - Network access for web search
# - Human-in-the-loop confirm gates on dangerous operations
#
# Hot reload: edit this file while the server is running — changes take
# effect immediately if the config is valid.

# ── Server ─────────────────────────────────────────────────────────────────────

[server]
host          = "127.0.0.1"
port          = 3000
transport     = "stdio"
server_secret = "{server_secret}"
dev_mode      = false

[server.http]
cors_origins        = ["http://localhost:*"]
on_disconnect       = "kill"
reattach_grace_secs = 30

# ── Tools ──────────────────────────────────────────────────────────────────────

[tools]
dir = "./tools"

# ── Sandbox ────────────────────────────────────────────────────────────────────

[sandbox]
enabled      = true
strategy     = "auto"
env_baseline = ["PATH", "SYSTEMROOT", "COMSPEC", "TERM", "LANG", "HOME"]

# ── Audit ──────────────────────────────────────────────────────────────────────

[audit]
enabled = true
output  = "file"
path    = "audit.log"

# ── Safety Rails ───────────────────────────────────────────────────────────────

[limits]
max_invocations_per_minute = 120
max_concurrent_tools       = 8
tool_timeout_secs          = 30
max_output_bytes           = 2097152   # 2 MiB — generous for AST output

# ── UI ─────────────────────────────────────────────────────────────────────────

[ui]
port      = 9765
auto_open = "confirm"

[ui.auth]
pin = ""

[ui.confirm]
timeout_secs                     = 60
session_approval_options         = [5, 30, 0]
session_approval_inactivity_secs = 300

[ui.theme]
preset = "dark"

# ── Key: coding_agent ──────────────────────────────────────────────────────────
#
# A production-style key with scoped grants. Demonstrates:
# - Tool access via wildcard (grant all tools)
# - Filesystem scoped to a specific workspace
# - Network access for web search
# - Deny rules to protect sensitive paths
# - Commented confirm gate examples

[keys.coding_agent]
token = "{agent_token}"

# Grant access to all registered tools.
[[keys.coding_agent.rules]]
effect = "grant"
type   = "tool"
name   = "*"

# Read/write access scoped to the workspace directory.
[[keys.coding_agent.rules]]
effect = "grant"
type   = "filesystem"
path   = "{workspace}/**"
perm   = "rw"

# Network access for web_search tool.
[[keys.coding_agent.rules]]
effect = "grant"
type   = "network"
host   = "*"
perm   = "r"

# ── Deny rules (defense in depth) ─────────────────────────────────────────────
# Deny always wins over grant. Use these to carve out sensitive paths.

# Protect .git internals from writes (agent can still read).
[[keys.coding_agent.rules]]
effect = "deny"
type   = "filesystem"
path   = "{workspace}/.git/**"
perm   = "w"

# ── Commented examples ────────────────────────────────────────────────────────
#
# Require human confirmation for destructive operations:
# [[keys.coding_agent.rules]]
# effect  = "grant"
# type    = "filesystem"
# path    = "{workspace}/config/**"
# perm    = "w"
# confirm = true
#
# Environment variable injection (e.g., for API keys):
# [[keys.coding_agent.rules]]
# effect      = "grant"
# type        = "environment"
# var_pattern = "OPENAI_API_KEY"
# value       = "sk-..."
"##
    )
}

#[cfg(feature = "demo")]
/// System prompt for the demo setup.
const DEMO_SYSTEM_PROMPT: &str = r#"# Pansophical Coding Agent

You are a coding assistant with access to powerful AST analysis tools and web search.

## Available Tools

### AST Analysis (group: ast)
- **ast_map** — Outline file/directory structure with signatures and line numbers
- **ast_show** — Extract the full source code of a specific symbol
- **ast_digest** — Compact one-page overview of a module
- **ast_search** — Semantic + BM25 search across the codebase
- **ast_callees** — Forward call graph: what does a function call?
- **ast_callers** — Reverse call graph: who calls this function?
- **ast_implements** — Find all implementations of a trait/interface
- **ast_reverse_deps** — Which files import this file?

### Web Search
- **ext_web_search** — Search the web via DuckDuckGo

### Built-in File Operations
- **builtin_read_file** — Read file contents
- **builtin_write_file** — Write/create files
- **builtin_list_dir** — List directory contents
- **builtin_search_files** — Grep/regex search
- **builtin_file_info** — File metadata
- **builtin_move_file** — Move/rename files
- **builtin_delete_file** — Delete files
- **builtin_create_directory** — Create directories
- **builtin_request_access** — Request elevated access from admin

## Workflow

1. Start with `ast_digest` or `ast_map` to understand the codebase structure
2. Use `ast_search` to find relevant code by concept
3. Drill into specific symbols with `ast_show`
4. Trace dependencies with `ast_callers` / `ast_callees`
5. Use `builtin_read_file` / `builtin_write_file` for edits
6. Use `ext_web_search` when you need external information

Be precise with file paths — always use absolute paths.
"#;


/// Build a canonical version string for logs and protocol responses.
///
/// Format: `Pansophical v0.1.0 (abc1234d, 2026-05-12T01:23:45Z)`
/// If the tree is dirty: `Pansophical v0.1.0 (abc1234d-dirty, ...)`
pub fn build_version() -> String {
    let ver = env!("CARGO_PKG_VERSION");
    let git = env!("PANSOPHICAL_GIT_REF");
    let ts = env!("PANSOPHICAL_BUILD_TS");

    // Convert Unix timestamp to human-readable UTC.
    let secs: i64 = ts.parse().unwrap_or(0);
    let dt = chrono::DateTime::from_timestamp(secs, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| ts.to_string());

    format!("Pansophical v{ver} ({git}, {dt})")
}
