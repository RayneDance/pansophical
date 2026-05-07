//! Built-in `read_file` tool.
//!
//! Reads a file and returns its contents as TextContent.
//! Always out-of-process (via reaper) — never inline.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::reaper;
use crate::tools::McpTool;

pub struct ReadFileTool;

#[async_trait]
impl McpTool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }

    fn description(&self) -> &str {
        "Read the contents of a file at the specified path."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to read."
                }
            },
            "required": ["path"]
        })
    }

    fn access_requests(&self, params: &Value) -> Vec<AccessRequest> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Canonicalize the path for policy evaluation.
        match crate::authz::glob::canonical_path(std::path::Path::new(path)) {
            Ok(canonical) => {
                vec![AccessRequest::filesystem(
                    canonical.to_string_lossy().to_string(),
                    Perm::READ,
                )]
            }
            Err(_) => {
                // Path doesn't exist or can't be canonicalized.
                // Return the raw path — authz will deny it.
                vec![AccessRequest::filesystem(path, Perm::READ)]
            }
        }
    }

    async fn execute(
        &self,
        params: &Value,
        config: &Config,
        _granted_env: &[(String, String)],
    ) -> Result<Value, String> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("missing 'path' parameter")?;

        // Out-of-process execution via reaper.
        // On Windows: use cmd /C type <path>
        // On Linux: use cat <path>
        let (program, args) = if cfg!(windows) {
            ("cmd".to_string(), vec!["/C".into(), "type".into(), path.to_string()])
        } else {
            ("cat".to_string(), vec![path.to_string()])
        };

        let result = reaper::spawn_and_reap(
            &program,
            &args,
            &config.sandbox,
            &[],
            config.limits.tool_timeout_secs,
            config.limits.max_output_bytes,
            None,
        )
        .await;

        match result {
            reaper::ReapResult::Completed { exit_code, stdout, stderr } => {
                if exit_code == Some(0) {
                    let text = String::from_utf8_lossy(&stdout).to_string();
                    Ok(json!({
                        "content": [{"type": "text", "text": text}],
                        "isError": false
                    }))
                } else {
                    let err = String::from_utf8_lossy(&stderr).to_string();
                    Err(format!("read_file failed (exit {}): {err}", exit_code.unwrap_or(-1)))
                }
            }
            reaper::ReapResult::TimedOut { .. } => {
                Err("read_file timed out".into())
            }
            reaper::ReapResult::SpawnFailed(msg) => {
                Err(format!("read_file spawn failed: {msg}"))
            }
        }
    }
}
