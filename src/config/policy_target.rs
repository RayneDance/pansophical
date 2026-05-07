//! PolicyTarget enum and per-target field definitions.
//!
//! Each variant corresponds to a `type = "..."` value in a policy rule.
//! We call this concept PolicyTarget (not "resource type") to avoid
//! collision with the MCP protocol's "Resources" primitive.

use serde::{Deserialize, Serialize};

use crate::config::perm::Perm;

/// A single policy rule from `[[keys.<name>.rules]]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyRule {
    /// "grant" or "deny".
    pub effect: Effect,

    /// The PolicyTarget type: filesystem, program, network, etc.
    #[serde(rename = "type")]
    pub target_type: PolicyTargetType,

    // ── Target-specific fields (all optional; validated per-type) ──

    /// filesystem: glob path
    #[serde(default)]
    pub path: Option<String>,

    /// program: executable name
    #[serde(default)]
    pub executable: Option<String>,

    /// network: hostname
    #[serde(default)]
    pub host: Option<String>,

    /// network: port list
    #[serde(default)]
    pub ports: Option<Vec<u16>>,

    /// network: protocol
    #[serde(default)]
    pub protocol: Option<String>,

    /// http: URL pattern
    #[serde(default)]
    pub url_pattern: Option<String>,

    /// environment: variable name pattern
    #[serde(default)]
    pub var_pattern: Option<String>,

    /// environment: explicit value to inject (if absent, passes through from parent env)
    #[serde(default)]
    pub value: Option<String>,

    /// process: name pattern
    #[serde(default)]
    pub name_pattern: Option<String>,

    /// tool: tool name (meta-authorization)
    #[serde(default)]
    pub name: Option<String>,

    /// secret: secret name
    // (reuses `name` field — disambiguated by target_type)

    /// device: device name pattern
    // (reuses `name` field — disambiguated by target_type)

    /// Permission bits. Not applicable for `tool` target type.
    #[serde(default)]
    pub perm: Option<Perm>,

    /// If true, require HITL confirmation before granting.
    #[serde(default)]
    pub confirm: bool,
}

/// Grant or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Grant,
    Deny,
}

/// The category of system resource being controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyTargetType {
    Filesystem,
    Program,
    Network,
    Http,
    Environment,
    Process,
    Tool,
    Secret,
    Registry,
    Device,
}

impl PolicyRule {
    /// Validate that the required fields are present for this rule's target type.
    pub fn validate(&self) -> Result<(), String> {
        match self.target_type {
            PolicyTargetType::Filesystem => {
                if self.path.is_none() {
                    return Err("filesystem rule requires 'path' field".into());
                }
                if self.perm.is_none() {
                    return Err("filesystem rule requires 'perm' field".into());
                }
            }
            PolicyTargetType::Program => {
                if self.executable.is_none() {
                    return Err("program rule requires 'executable' field".into());
                }
                if self.perm.is_none() {
                    return Err("program rule requires 'perm' field".into());
                }
            }
            PolicyTargetType::Network => {
                if self.host.is_none() {
                    return Err("network rule requires 'host' field".into());
                }
                if self.perm.is_none() {
                    return Err("network rule requires 'perm' field".into());
                }
            }
            PolicyTargetType::Http => {
                if self.url_pattern.is_none() {
                    return Err("http rule requires 'url_pattern' field".into());
                }
                if self.perm.is_none() {
                    return Err("http rule requires 'perm' field".into());
                }
            }
            PolicyTargetType::Environment => {
                if self.var_pattern.is_none() {
                    return Err("environment rule requires 'var_pattern' field".into());
                }
                if self.perm.is_none() {
                    return Err("environment rule requires 'perm' field".into());
                }
            }
            PolicyTargetType::Process => {
                if self.name_pattern.is_none() {
                    return Err("process rule requires 'name_pattern' field".into());
                }
                if self.perm.is_none() {
                    return Err("process rule requires 'perm' field".into());
                }
            }
            PolicyTargetType::Tool => {
                if self.name.is_none() {
                    return Err("tool rule requires 'name' field".into());
                }
                // Tool rules have no permission bits — grant/deny only.
                if self.perm.is_some() {
                    return Err("tool rule must not have 'perm' field".into());
                }
            }
            PolicyTargetType::Secret => {
                if self.name.is_none() {
                    return Err("secret rule requires 'name' field".into());
                }
                if self.perm.is_none() {
                    return Err("secret rule requires 'perm' field".into());
                }
            }
            PolicyTargetType::Registry => {
                if self.path.is_none() {
                    return Err("registry rule requires 'path' field".into());
                }
                if self.perm.is_none() {
                    return Err("registry rule requires 'perm' field".into());
                }
            }
            PolicyTargetType::Device => {
                if self.name.is_none() {
                    return Err("device rule requires 'name' field".into());
                }
                if self.perm.is_none() {
                    return Err("device rule requires 'perm' field".into());
                }
            }
        }
        Ok(())
    }
}
