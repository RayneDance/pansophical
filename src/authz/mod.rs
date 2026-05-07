//! Authorization engine: key resolution, rule evaluation,
//! intersection computation, and explain mode.

pub mod intersection;
pub mod glob;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

use crate::config::perm::Perm;
use crate::config::policy_target::{Effect, PolicyRule, PolicyTargetType};
use crate::config::schema::KeyConfig;

/// A single access request declared by a tool via `access_requests()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub target_type: PolicyTargetType,
    /// The specific resource identifier (path, host, name, etc.)
    pub resource: String,
    /// The permissions the tool needs on this resource.
    pub perm: Perm,
    /// Optional group memberships (e.g., `["builtin"]`).
    /// A tool grant rule matching any group name will grant access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl AccessRequest {
    /// Convenience: create a filesystem access request.
    pub fn filesystem(path: impl Into<String>, perm: Perm) -> Self {
        Self {
            target_type: PolicyTargetType::Filesystem,
            resource: path.into(),
            perm,
            groups: Vec::new(),
        }
    }

    /// Convenience: create a program access request.
    pub fn program(executable: impl Into<String>, perm: Perm) -> Self {
        Self {
            target_type: PolicyTargetType::Program,
            resource: executable.into(),
            perm,
            groups: Vec::new(),
        }
    }

    /// Convenience: create a tool meta-authorization request (no groups).
    #[allow(dead_code)]
    pub fn tool(name: impl Into<String>) -> Self {
        Self {
            target_type: PolicyTargetType::Tool,
            resource: name.into(),
            perm: Perm::empty(),
            groups: Vec::new(),
        }
    }

    /// Create a tool request with group memberships.
    ///
    /// A config rule like `name = "builtin"` will match any tool whose
    /// groups include `"builtin"`.
    pub fn tool_with_groups(name: impl Into<String>, groups: Vec<String>) -> Self {
        Self {
            target_type: PolicyTargetType::Tool,
            resource: name.into(),
            perm: Perm::empty(),
            groups,
        }
    }
}

/// The result of authorization evaluation for a single request.
#[derive(Debug, Clone)]
pub struct GrantResult {
    /// The actual permissions granted (intersection of needs and grants).
    #[allow(dead_code)]
    pub actual_perm: Perm,
    /// Whether any matching rule has `confirm = true`.
    #[allow(dead_code)]
    pub requires_confirm: bool,
}

/// A single denied request with the reason.
#[derive(Debug, Clone, Serialize)]
pub struct DeniedRequest {
    pub target_type: PolicyTargetType,
    pub resource: String,
    pub perm: String,
    pub reason: String,
}

/// Policy diff returned in explain mode (`dev_mode = true`).
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDiff {
    pub requested: Vec<AccessRequest>,
    pub granted: Vec<AccessRequest>,
    pub denied: Vec<DeniedRequest>,
}

/// The outcome of evaluating all access requests for a tool call.
#[derive(Debug)]
pub enum AuthzDecision {
    /// All requests granted. Contains the actual grants and confirm flag.
    Granted {
        #[allow(dead_code)]
        grants: Vec<GrantResult>,
        requires_confirm: bool,
    },
    /// One or more requests denied.
    Denied {
        /// Only populated when `dev_mode = true`.
        explain: Option<PolicyDiff>,
    },
}

/// Evaluate all access requests against a key's policy rules.
///
/// Evaluation order (per the planning doc):
/// 1. For each AccessRequest:
///    a. Deny rule scan — any deny match → reject (deny always wins)
///    b. Grant rule scan — find matching grant with perm superset
///    c. Compute actual_grant = requested perm (not the grant's broader perm)
/// 2. If any request is denied → return Denied
/// 3. If any matching rule has confirm=true → set requires_confirm
pub fn evaluate(
    requests: &[AccessRequest],
    key_config: &KeyConfig,
    dev_mode: bool,
) -> AuthzDecision {
    let mut grants = Vec::with_capacity(requests.len());
    let mut any_confirm = false;
    let mut denied_list = Vec::new();
    let mut granted_list = Vec::new();

    for request in requests {
        match evaluate_single(request, &key_config.rules) {
            SingleResult::Denied(reason) => {
                denied_list.push(DeniedRequest {
                    target_type: request.target_type,
                    resource: request.resource.clone(),
                    perm: request.perm.to_string(),
                    reason,
                });
            }
            SingleResult::Granted { actual_perm, confirm } => {
                grants.push(GrantResult {
                    actual_perm,
                    requires_confirm: confirm,
                });
                if confirm {
                    any_confirm = true;
                }
                granted_list.push(request.clone());
            }
        }
    }

    if !denied_list.is_empty() {
        let explain = if dev_mode {
            Some(PolicyDiff {
                requested: requests.to_vec(),
                granted: granted_list,
                denied: denied_list,
            })
        } else {
            None
        };
        return AuthzDecision::Denied { explain };
    }

    AuthzDecision::Granted {
        grants,
        requires_confirm: any_confirm,
    }
}

/// Collect environment variable grants from a key's policy rules and env_file.
///
/// Sources (in order, later entries override earlier):
/// 1. `env_file` — bulk loading from a `.env` file
/// 2. Policy rules — `type = "environment"` grant rules (passthrough or explicit value)
///
/// Returns `Vec<(var_name, var_value)>` ready for the reaper.
pub fn collect_env_grants(key_config: &KeyConfig) -> Vec<(String, String)> {
    let mut env_vars = Vec::new();

    // 1. Load from env_file if configured.
    if let Some(ref env_file_path) = key_config.env_file {
        match parse_env_file(env_file_path) {
            Ok(vars) => env_vars.extend(vars),
            Err(e) => {
                tracing::warn!(path = %env_file_path, error = %e, "Failed to load env_file");
            }
        }
    }

    // 2. Collect from policy rules.
    for rule in &key_config.rules {
        if rule.effect != Effect::Grant {
            continue;
        }
        if rule.target_type != PolicyTargetType::Environment {
            continue;
        }

        let pattern = match rule.var_pattern.as_deref() {
            Some(p) => p,
            None => continue,
        };

        if let Some(ref value) = rule.value {
            // Explicit value — inject directly.
            // Don't expand wildcards for explicit values.
            if !pattern.contains('*') {
                env_vars.push((pattern.to_string(), value.clone()));
            }
        } else {
            // Passthrough — read from parent env.
            if pattern.ends_with('*') {
                // Wildcard: match all env vars starting with the prefix.
                let prefix = &pattern[..pattern.len() - 1];
                for (key, val) in std::env::vars() {
                    if key.starts_with(prefix) {
                        env_vars.push((key, val));
                    }
                }
            } else {
                // Exact match.
                if let Ok(val) = std::env::var(pattern) {
                    env_vars.push((pattern.to_string(), val));
                }
            }
        }
    }

    env_vars
}

/// Parse a `.env` file into a list of (key, value) pairs.
///
/// Supported format:
/// ```text
/// # Comment lines
/// KEY=value
/// QUOTED_KEY="value with spaces"
/// SINGLE_QUOTED='literal $value'
///
/// # Empty lines are ignored
/// EXPORT_KEY=value   # inline comments NOT supported (value includes everything after =)
/// ```
fn parse_env_file(path: &str) -> Result<Vec<(String, String)>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let mut vars = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Skip `export ` prefix (common in shell-compatible .env files).
        let line = line.strip_prefix("export ").unwrap_or(line);

        // Split on first `=`.
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let mut value = value.trim().to_string();

            // Strip surrounding quotes (double or single).
            if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value = value[1..value.len() - 1].to_string();
            }

            if !key.is_empty() {
                vars.push((key, value));
            }
        }
    }

    Ok(vars)
}

enum SingleResult {
    Granted { actual_perm: Perm, confirm: bool },
    Denied(String),
}

fn evaluate_single(request: &AccessRequest, rules: &[PolicyRule]) -> SingleResult {
    // Step 1: Deny scan — any matching deny rule rejects immediately.
    for rule in rules {
        if rule.effect != Effect::Deny {
            continue;
        }
        if rule.target_type != request.target_type {
            continue;
        }
        if rule_matches_resource(rule, &request.resource) {
            // For deny rules with explicit perm, check if the denied bits overlap.
            if let Some(deny_perm) = rule.perm {
                if request.perm.intersects(deny_perm) {
                    return SingleResult::Denied(format!(
                        "denied by deny rule on '{}'",
                        request.resource
                    ));
                }
            } else {
                // Tool deny with no perm — full deny.
                return SingleResult::Denied(format!(
                    "denied by deny rule on '{}'",
                    request.resource
                ));
            }
        }
    }

    // Step 2: Grant scan — find a matching grant whose perm is a superset.
    let mut best_confirm = false;

    // Tool requests have no perm bits — just need a matching grant.
    if request.target_type == PolicyTargetType::Tool {
        for rule in rules {
            if rule.effect != Effect::Grant {
                continue;
            }
            if rule.target_type != PolicyTargetType::Tool {
                continue;
            }
            // Match by tool name OR by group membership.
            // e.g. `name = "builtin"` matches any tool in the "builtin" group.
            let matches = rule_matches_resource(rule, &request.resource)
                || request.groups.iter().any(|g| {
                    rule.name.as_deref().is_some_and(|n| n == g)
                });
            if matches {
                return SingleResult::Granted {
                    actual_perm: Perm::empty(),
                    confirm: rule.confirm,
                };
            }
        }
        return SingleResult::Denied("no matching tool grant".into());
    }

    // Permission-bearing requests.
    for rule in rules {
        if rule.effect != Effect::Grant {
            continue;
        }
        if rule.target_type != request.target_type {
            continue;
        }
        if !rule_matches_resource(rule, &request.resource) {
            continue;
        }
        if let Some(grant_perm) = rule.perm {
            // The grant's perm must be a superset of (or equal to) the request.
            if grant_perm.contains(request.perm) {
                // Actual grant = the *requested* bits, not the broader grant bits.
                if rule.confirm {
                    best_confirm = true;
                }
                return SingleResult::Granted {
                    actual_perm: request.perm,
                    confirm: best_confirm,
                };
            }
        }
    }

    SingleResult::Denied(format!(
        "no matching grant for {} '{}' with perm {}",
        format!("{:?}", request.target_type).to_lowercase(),
        request.resource,
        request.perm,
    ))
}

/// Check if a rule's resource pattern matches the requested resource.
fn rule_matches_resource(rule: &PolicyRule, resource: &str) -> bool {
    match rule.target_type {
        PolicyTargetType::Filesystem | PolicyTargetType::Registry => {
            if let Some(ref pattern) = rule.path {
                let pattern = if rule.target_type == PolicyTargetType::Registry {
                    glob::normalize_registry_path(pattern)
                } else {
                    pattern.clone()
                };
                glob::path_matches_glob(resource, &pattern)
            } else {
                false
            }
        }
        PolicyTargetType::Program => {
            rule.executable.as_deref().is_some_and(|e| {
                e == resource || e == "*"
            })
        }
        PolicyTargetType::Network => {
            rule.host.as_deref().is_some_and(|h| {
                h == resource || h == "*"
            })
        }
        PolicyTargetType::Http => {
            if let Some(ref pattern) = rule.url_pattern {
                glob::path_matches_glob(resource, pattern)
            } else {
                false
            }
        }
        PolicyTargetType::Environment => {
            if let Some(ref pattern) = rule.var_pattern {
                glob::path_matches_glob(resource, pattern)
            } else {
                false
            }
        }
        PolicyTargetType::Process => {
            if let Some(ref pattern) = rule.name_pattern {
                glob::path_matches_glob(resource, pattern)
            } else {
                false
            }
        }
        PolicyTargetType::Tool | PolicyTargetType::Secret | PolicyTargetType::Device => {
            rule.name.as_deref().is_some_and(|n| {
                n == resource || n == "*"
            })
        }
    }
}
