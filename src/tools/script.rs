//! Script-based tools loaded from TOML definitions.
//!
//! Users define tools in `tools/*.toml`. Each definition specifies a command
//! to execute, arguments, resource access declarations, and safety controls
//! (shell rejection, flag injection prevention, arg validation).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

/// Shell executables that are rejected unless `allow_shell = true`.
const SHELL_BINARIES: &[&str] = &[
    "sh", "bash", "zsh", "fish", "dash", "csh", "tcsh", "ksh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
];

/// Shell metacharacters rejected in argument values (unless `arg_passthrough = true`).
const SHELL_METACHARACTERS: &[char] = &[';', '&', '|', '>', '<', '`', '$', '(', ')'];

/// A tool definition loaded from `tools/*.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScriptToolDefinition {
    pub name: String,
    pub description: String,

    /// Optional group for namespacing and authorization.
    ///
    /// If set, the tool is exposed as `{group}_{name}` (e.g., `devops_git_status`).
    /// If not set, defaults to `ext` → `ext_{name}` (e.g., `ext_hello_world`).
    /// The group is also used for group-based tool grants (e.g., `name = "devops"`).
    #[serde(default)]
    pub group: Option<String>,

    /// The command to invoke.
    pub command: String,

    /// Static arguments prepended before dynamic ones.
    #[serde(default)]
    pub args: Vec<String>,

    /// Whether to allow shell executables.
    #[serde(default)]
    pub allow_shell: bool,

    /// Disable all arg validation (flag injection, metachar checks).
    #[serde(default)]
    pub arg_passthrough: bool,

    /// Whether this tool streams progress notifications.
    #[serde(default)]
    pub streaming: bool,

    /// Tool parameters (agent-supplied arguments).
    #[serde(default)]
    pub parameters: Vec<ScriptParam>,

    /// Resource access declarations.
    #[serde(default)]
    pub resources: Vec<ScriptResource>,
}

/// A parameter the agent can supply.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScriptParam {
    pub name: String,
    pub description: String,
    #[serde(default = "default_string_type")]
    pub param_type: String,
    #[serde(default)]
    pub required: bool,
    /// Allow this param to have values starting with `-`.
    #[serde(default)]
    pub allow_flags: bool,
}

fn default_string_type() -> String {
    "string".into()
}

/// A resource this tool needs access to.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScriptResource {
    /// "filesystem", "program", "network", etc.
    #[serde(rename = "type")]
    pub resource_type: String,

    /// Static path or pattern.
    #[serde(default)]
    pub path: Option<String>,

    /// Take the path from an argument value at runtime.
    #[serde(default)]
    pub path_from_arg: Option<String>,

    /// Permissions needed.
    #[serde(default = "default_read_perm")]
    pub perm: String,
}

fn default_read_perm() -> String {
    "r".into()
}

/// The runtime script tool.
#[derive(Debug)]
pub struct ScriptTool {
    pub def: ScriptToolDefinition,
    /// The namespaced name: `{group}_{name}` or `ext_{name}`.
    namespaced_name: String,
    /// The group name (from def.group or "ext").
    group_name: String,
}

impl ScriptTool {
    /// Load a script tool definition from a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read tool definition '{}': {e}", path.display()))?;

        let def: ScriptToolDefinition = toml::from_str(&content)
            .map_err(|e| format!("invalid tool definition '{}': {e}", path.display()))?;

        // Validate: reject shell commands unless explicitly allowed.
        if !def.allow_shell {
            let cmd_lower = def.command.to_lowercase();
            let cmd_base = Path::new(&cmd_lower)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&cmd_lower);

            for &shell in SHELL_BINARIES {
                if cmd_base == shell {
                    return Err(format!(
                        "tool '{}' uses shell command '{}' but allow_shell is not set. \
                         Set allow_shell = true to explicitly permit this (security warning).",
                        def.name, def.command,
                    ));
                }
            }
        }

        // Compute namespaced name.
        let group_name = def.group.clone().unwrap_or_else(|| "ext".to_string());
        let namespaced_name = format!("{}_{}", group_name, def.name);

        Ok(Self { def, namespaced_name, group_name })
    }

    /// Validate an argument value for safety.
    fn validate_arg(&self, name: &str, value: &str) -> Result<(), String> {
        if self.def.arg_passthrough {
            return Ok(());
        }

        // Flag injection: reject values starting with `-`.
        let param = self.def.parameters.iter().find(|p| p.name == name);
        let allow_flags = param.is_some_and(|p| p.allow_flags);

        if !allow_flags && value.starts_with('-') {
            return Err(format!(
                "argument '{name}' value starts with '-' (possible flag injection). \
                 Set allow_flags = true on this parameter to permit."
            ));
        }

        // Shell metacharacter check.
        if !self.def.allow_shell {
            for &ch in SHELL_METACHARACTERS {
                if value.contains(ch) {
                    return Err(format!(
                        "argument '{name}' contains shell metacharacter '{ch}'. \
                         Set arg_passthrough = true to disable this check."
                    ));
                }
            }
        }

        Ok(())
    }

    /// Build the final argument list with `{param}` interpolation.
    ///
    /// Placeholders like `{path}` in `self.def.args` are replaced with agent-supplied
    /// values. Parameters not referenced by any placeholder are appended at the end.
    fn build_args(&self, params: &Value) -> Result<Vec<String>, String> {
        let mut interpolated_params = std::collections::HashSet::new();
        let mut cmd_args = Vec::with_capacity(self.def.args.len() + self.def.parameters.len());

        for arg_template in &self.def.args {
            let mut result = arg_template.clone();
            let mut had_placeholder = false;

            for param in &self.def.parameters {
                let placeholder = format!("{{{}}}", param.name);
                if result.contains(&placeholder) {
                    had_placeholder = true;
                    if let Some(value) = params.get(&param.name).and_then(|v| v.as_str()) {
                        result = result.replace(&placeholder, value);
                        interpolated_params.insert(param.name.clone());
                    } else if param.required {
                        return Err(format!("missing required argument: {}", param.name));
                    } else {
                        result = String::new();
                        break;
                    }
                }
            }

            if had_placeholder && result.is_empty() {
                continue;
            }

            cmd_args.push(result);
        }

        // Append parameters that were NOT interpolated (backward compat).
        for param in &self.def.parameters {
            if interpolated_params.contains(&param.name) {
                continue;
            }
            if let Some(value) = params.get(&param.name).and_then(|v| v.as_str()) {
                cmd_args.push(value.to_string());
            } else if param.required {
                return Err(format!("missing required argument: {}", param.name));
            }
        }

        Ok(cmd_args)
    }
}

#[async_trait]
impl McpTool for ScriptTool {
    fn name(&self) -> &str {
        &self.namespaced_name
    }

    fn description(&self) -> &str {
        &self.def.description
    }

    fn groups(&self) -> Vec<String> {
        vec![self.group_name.clone()]
    }

    fn input_schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for param in &self.def.parameters {
            properties.insert(
                param.name.clone(),
                json!({
                    "type": param.param_type,
                    "description": param.description,
                }),
            );
            if param.required {
                required.push(Value::String(param.name.clone()));
            }
        }

        json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    }

    fn access_requests(&self, params: &Value) -> Vec<AccessRequest> {
        let mut requests = Vec::new();

        for res in &self.def.resources {
            let path = if let Some(ref arg_name) = res.path_from_arg {
                // Get path from argument value.
                params
                    .get("arguments")
                    .or(Some(params))
                    .and_then(|p| p.get(arg_name))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            } else {
                res.path.clone()
            };

            match res.resource_type.as_str() {
                "network" => {
                    // Network access: host from path field, or "*" for any.
                    let host = path.unwrap_or_else(|| "*".to_string());
                    requests.push(AccessRequest::network(host));
                }
                _ if path.is_some() => {
                    let path = path.unwrap();
                    // Parse perm string.
                    let perm = Perm::from_short(&res.perm).unwrap_or(Perm::READ);

                    match res.resource_type.as_str() {
                        "filesystem" => {
                            // Canonicalize the path.
                            match crate::authz::glob::canonical_path(std::path::Path::new(&path)) {
                                Ok(canonical) => {
                                    requests.push(AccessRequest::filesystem(
                                        canonical.to_string_lossy().to_string(),
                                        perm,
                                    ));
                                }
                                Err(_) => {
                                    // For create operations, try canonical_path_for_create.
                                    if perm.contains(Perm::WRITE)
                                        && let Ok(canonical) = crate::authz::glob::canonical_path_for_create(
                                            std::path::Path::new(&path),
                                        ) {
                                            requests.push(AccessRequest::filesystem(
                                                canonical.to_string_lossy().to_string(),
                                                perm,
                                            ));
                                        }
                                }
                            }
                        }
                        "program" => {
                            requests.push(AccessRequest::program(&path, perm));
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        requests
    }

    async fn execute(
        &self,
        params: &Value,
        config: &Config,
        granted_env: &[(String, String)],
    ) -> Result<Value, String> {
        // Validate all arguments.
        if let Some(args) = params.as_object() {
            for (name, value) in args {
                if let Some(s) = value.as_str() {
                    self.validate_arg(name, s)?;
                }
            }
        }

        // Build the argument list with {param} interpolation.
        let cmd_args = self.build_args(params)?;

        // Spawn via the reaper.
        let result = crate::reaper::spawn_and_reap(
            &self.def.command,
            &cmd_args,
            &config.sandbox,
            granted_env,
            config.limits.tool_timeout_secs,
            config.limits.max_output_bytes,
        )
        .await;

        match result {
            crate::reaper::ReapResult::Completed { stdout, stderr, exit_code } => {
                let output = String::from_utf8_lossy(&stdout).to_string();
                let err_output = String::from_utf8_lossy(&stderr).to_string();

                // Always log stderr if non-empty, even on success.
                if !err_output.is_empty() {
                    tracing::warn!(
                        tool = %self.def.name,
                        exit_code = ?exit_code,
                        stderr = %err_output,
                        "Tool produced stderr output"
                    );
                }

                if exit_code == Some(0) {
                    // Include stderr in the response if present, so the LLM
                    // (and user) can see diagnostics even on successful exit.
                    let text = if err_output.is_empty() {
                        output
                    } else {
                        format!("{output}\n\n--- stderr ---\n{err_output}")
                    };
                    Ok(json!({
                        "content": [{"type": "text", "text": text}],
                        "isError": false,
                    }))
                } else {
                    let code = exit_code.map_or("unknown".to_string(), |c| c.to_string());
                    // Show both stdout and stderr on failure.
                    let combined = format!(
                        "exit code {code}\n--- stdout ---\n{output}\n--- stderr ---\n{err_output}"
                    );
                    tracing::warn!(
                        tool = %self.def.name,
                        exit_code = code,
                        "Tool exited with non-zero code"
                    );
                    Ok(json!({
                        "content": [{"type": "text", "text": combined}],
                        "isError": true,
                    }))
                }
            }
            crate::reaper::ReapResult::TimedOut { .. } => {
                tracing::error!(tool = %self.def.name, "Tool execution timed out");
                Err("tool execution timed out".into())
            }
            crate::reaper::ReapResult::SpawnFailed(e) => {
                tracing::error!(tool = %self.def.name, error = %e, "Tool spawn failed");
                Err(format!("failed to spawn '{}': {e}", self.def.command))
            }
        }
    }
}

/// Load all script tools from a directory.
pub fn load_tools_dir(dir: &Path) -> Vec<ScriptTool> {
    let mut tools = Vec::new();

    if !dir.exists() {
        tracing::debug!("Tools directory does not exist: {}", dir.display());
        return tools;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Cannot read tools directory '{}': {e}", dir.display());
            return tools;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            match ScriptTool::load(&path) {
                Ok(tool) => {
                    tracing::info!("Loaded script tool: {} from {}", tool.def.name, path.display());
                    tools.push(tool);
                }
                Err(e) => {
                    tracing::warn!("Failed to load tool '{}': {e}", path.display());
                }
            }
        }
    }

    tools
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_def() -> ScriptToolDefinition {
        ScriptToolDefinition {
            name: "test_tool".into(),
            description: "A test tool".into(),
            group: None,
            command: "echo".into(),
            args: vec!["hello".into()],
            allow_shell: false,
            arg_passthrough: false,
            streaming: false,
            parameters: vec![ScriptParam {
                name: "input".into(),
                description: "Some input".into(),
                param_type: "string".into(),
                required: true,
                allow_flags: false,
            }],
            resources: vec![],
        }
    }

    fn make_tool(def: ScriptToolDefinition) -> ScriptTool {
        let group_name = def.group.clone().unwrap_or_else(|| "ext".to_string());
        let namespaced_name = format!("{}_{}", group_name, def.name);
        ScriptTool { def, namespaced_name, group_name }
    }

    #[test]
    fn reject_shell_command() {
        let dir = std::env::temp_dir().join("pansophical_script_test");
        std::fs::create_dir_all(&dir).unwrap();
        let tool_path = dir.join("shell_tool.toml");

        let content = r#"
name = "shell_tool"
description = "bad tool"
command = "bash"
"#;
        std::fs::write(&tool_path, content).unwrap();
        let result = ScriptTool::load(&tool_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("allow_shell"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allow_shell_explicit() {
        let dir = std::env::temp_dir().join("pansophical_script_test2");
        std::fs::create_dir_all(&dir).unwrap();
        let tool_path = dir.join("allowed_shell.toml");

        let content = r#"
name = "shell_tool"
description = "explicitly allowed"
command = "bash"
allow_shell = true
"#;
        std::fs::write(&tool_path, content).unwrap();
        let result = ScriptTool::load(&tool_path);
        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flag_injection_rejected() {
        let tool = make_tool(make_def());
        let result = tool.validate_arg("input", "--config=/etc/shadow");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("flag injection"));
    }

    #[test]
    fn flag_injection_allowed_with_flag() {
        let mut def = make_def();
        def.parameters[0].allow_flags = true;
        let tool = make_tool(def);
        let result = tool.validate_arg("input", "--verbose");
        assert!(result.is_ok());
    }

    #[test]
    fn metachar_rejected() {
        let tool = make_tool(make_def());
        let result = tool.validate_arg("input", "hello; rm -rf /");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("metacharacter"));
    }

    #[test]
    fn passthrough_allows_everything() {
        let mut def = make_def();
        def.arg_passthrough = true;
        let tool = make_tool(def);
        assert!(tool.validate_arg("input", "--evil; rm -rf /").is_ok());
    }

    #[test]
    fn input_schema_generated() {
        let tool = make_tool(make_def());
        let schema = tool.input_schema();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["input"].is_object());
        assert_eq!(schema["required"][0], "input");
    }

    #[test]
    fn load_nonexistent_dir() {
        let tools = load_tools_dir(Path::new("/nonexistent_dir_12345"));
        assert!(tools.is_empty());
    }

    #[test]
    fn default_namespace_is_ext() {
        let tool = make_tool(make_def());
        assert_eq!(tool.name(), "ext_test_tool");
        assert_eq!(tool.groups(), vec!["ext".to_string()]);
    }

    #[test]
    fn custom_group_namespace() {
        let mut def = make_def();
        def.group = Some("devops".into());
        let tool = make_tool(def);
        assert_eq!(tool.name(), "devops_test_tool");
        assert_eq!(tool.groups(), vec!["devops".to_string()]);
    }

    // ── Argument interpolation tests ─────────────────────────────────────

    fn make_interpolation_def() -> ScriptToolDefinition {
        ScriptToolDefinition {
            name: "git_status".into(),
            description: "Git status for a dir".into(),
            group: Some("devops".into()),
            command: "git".into(),
            args: vec!["-C".into(), "{path}".into(), "status".into(), "--short".into()],
            allow_shell: false,
            arg_passthrough: false,
            streaming: false,
            parameters: vec![ScriptParam {
                name: "path".into(),
                description: "Dir to check".into(),
                param_type: "string".into(),
                required: true,
                allow_flags: false,
            }],
            resources: vec![],
        }
    }

    #[test]
    fn interpolation_replaces_placeholder() {
        let tool = make_tool(make_interpolation_def());
        let params = json!({"path": "/workspace"});
        let args = tool.build_args(&params).unwrap();
        assert_eq!(args, vec!["-C", "/workspace", "status", "--short"]);
    }

    #[test]
    fn interpolation_missing_required_errors() {
        let tool = make_tool(make_interpolation_def());
        let params = json!({});
        let result = tool.build_args(&params);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing required argument"));
    }

    #[test]
    fn no_placeholder_appends_at_end() {
        // Old-style: no {param} in args → appended at the end.
        let tool = make_tool(make_def());
        let params = json!({"input": "world"});
        let args = tool.build_args(&params).unwrap();
        assert_eq!(args, vec!["hello", "world"]);
    }

    #[test]
    fn mixed_interpolation_and_append() {
        let mut def = make_interpolation_def();
        // Add a second param that is NOT referenced in args.
        def.parameters.push(ScriptParam {
            name: "extra".into(),
            description: "Extra arg".into(),
            param_type: "string".into(),
            required: false,
            allow_flags: false,
        });
        let tool = make_tool(def);
        let params = json!({"path": "/ws", "extra": "verbose"});
        let args = tool.build_args(&params).unwrap();
        // "path" is interpolated into position, "extra" appended at end.
        assert_eq!(args, vec!["-C", "/ws", "status", "--short", "verbose"]);
    }

    #[test]
    fn optional_placeholder_skips_arg() {
        let mut def = make_interpolation_def();
        def.parameters[0].required = false;
        let tool = make_tool(def);
        let params = json!({});
        let args = tool.build_args(&params).unwrap();
        // {path} not supplied → that arg is skipped entirely.
        assert_eq!(args, vec!["-C", "status", "--short"]);
    }
}
