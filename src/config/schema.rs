//! TOML-mapped configuration structs.
//!
//! Every struct in this module derives `Deserialize` and maps 1:1
//! to a section of `config.toml`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::policy_target::PolicyRule;

/// Top-level config structure. Maps to the entire `config.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,

    #[serde(default)]
    pub tools: ToolsConfig,

    #[serde(default)]
    pub sandbox: SandboxConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub limits: LimitsConfig,

    #[serde(default)]
    pub ui: UiConfig,

    /// Named keys. Each key has a bearer token and policy rules.
    #[serde(default)]
    pub keys: HashMap<String, KeyConfig>,
}

// ── Server ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_server_port")]
    pub port: u16,

    #[serde(default = "default_transport")]
    pub transport: String,

    #[serde(default)]
    pub server_secret: String,

    #[serde(default)]
    pub dev_mode: bool,

    #[serde(default)]
    pub http: HttpConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpConfig {
    #[serde(default)]
    pub cors_origins: Vec<String>,

    #[serde(default = "default_on_disconnect")]
    pub on_disconnect: String,

    #[serde(default = "default_reattach_grace")]
    pub reattach_grace_secs: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            cors_origins: vec!["http://localhost:*".into()],
            on_disconnect: "kill".into(),
            reattach_grace_secs: 30,
        }
    }
}

// ── Tools ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolsConfig {
    #[serde(default = "default_tools_dir")]
    pub dir: String,
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            dir: "./tools".into(),
        }
    }
}

// ── Sandbox ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SandboxConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_strategy")]
    pub strategy: String,

    #[serde(default = "default_env_baseline")]
    pub env_baseline: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strategy: "auto".into(),
            env_baseline: vec![
                "PATH".into(),
                "TERM".into(),
                "LANG".into(),
                "HOME".into(),
            ],
        }
    }
}

// ── Audit ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_audit_output")]
    pub output: String,

    #[serde(default = "default_audit_path")]
    pub path: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            output: "file".into(),
            path: "audit.log".into(),
        }
    }
}

// ── Limits ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_rate")]
    pub max_invocations_per_minute: u32,

    #[serde(default = "default_concurrent")]
    pub max_concurrent_tools: u32,

    #[serde(default = "default_timeout")]
    pub tool_timeout_secs: u64,

    #[serde(default = "default_output_bytes")]
    pub max_output_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_invocations_per_minute: 60,
            max_concurrent_tools: 4,
            tool_timeout_secs: 30,
            max_output_bytes: 1_048_576,
        }
    }
}

// ── UI ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UiConfig {
    #[serde(default = "default_ui_port")]
    pub port: u16,

    #[serde(default = "default_auto_open")]
    pub auto_open: String,

    #[serde(default)]
    pub auth: UiAuthConfig,

    #[serde(default)]
    pub confirm: ConfirmConfig,

    #[serde(default)]
    pub theme: ThemeConfig,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            port: 9765,
            auto_open: "confirm".into(),
            auth: UiAuthConfig::default(),
            confirm: ConfirmConfig::default(),
            theme: ThemeConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UiAuthConfig {
    #[serde(default)]
    pub pin: String,
}

impl Default for UiAuthConfig {
    fn default() -> Self {
        Self { pin: String::new() }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfirmConfig {
    #[serde(default = "default_confirm_timeout")]
    pub timeout_secs: u64,

    #[serde(default = "default_session_options")]
    pub session_approval_options: Vec<u64>,

    #[serde(default = "default_inactivity")]
    pub session_approval_inactivity_secs: u64,
}

impl Default for ConfirmConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            session_approval_options: vec![5, 30, 0],
            session_approval_inactivity_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThemeConfig {
    #[serde(default = "default_preset")]
    pub preset: String,
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            preset: "dark".into(),
        }
    }
}

// ── Keys ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyConfig {
    /// Bearer token for this key.
    pub token: String,

    /// Policy rules.
    #[serde(default)]
    pub rules: Vec<PolicyRule>,

    /// Per-key limit overrides.
    #[serde(default)]
    pub limits: Option<LimitsConfig>,
}

// ── Default value functions ───────────────────────────────────────────────

fn default_host() -> String { "127.0.0.1".into() }
fn default_server_port() -> u16 { 3000 }
fn default_transport() -> String { "stdio".into() }
fn default_on_disconnect() -> String { "kill".into() }
fn default_reattach_grace() -> u64 { 30 }
fn default_tools_dir() -> String { "./tools".into() }
fn default_true() -> bool { true }
fn default_strategy() -> String { "auto".into() }
fn default_env_baseline() -> Vec<String> {
    vec![
        "PATH".into(), "SYSTEMROOT".into(), "COMSPEC".into(),
        "TERM".into(), "LANG".into(), "HOME".into(),
    ]
}
fn default_audit_output() -> String { "file".into() }
fn default_audit_path() -> String { "audit.log".into() }
fn default_rate() -> u32 { 60 }
fn default_concurrent() -> u32 { 4 }
fn default_timeout() -> u64 { 30 }
fn default_output_bytes() -> u64 { 1_048_576 }
fn default_ui_port() -> u16 { 9765 }
fn default_auto_open() -> String { "confirm".into() }
fn default_confirm_timeout() -> u64 { 30 }
fn default_session_options() -> Vec<u64> { vec![5, 30, 0] }
fn default_inactivity() -> u64 { 300 }
fn default_preset() -> String { "dark".into() }
