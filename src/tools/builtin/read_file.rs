//! Built-in `read_file` tool.
//!
//! Reads a file and returns its contents as TextContent.
//! Reads directly in-process — the authz layer validates access before execution.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

pub struct ReadFileTool;

#[async_trait]
impl McpTool for ReadFileTool {
    fn name(&self) -> &str {
        "builtin_read_file"
    }

    fn description(&self) -> &str {
        "Read the contents of a file at the specified path."
    }

    fn groups(&self) -> Vec<String> {
        vec!["builtin".into()]
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
        _config: &Config,
        _granted_env: &[(String, String)],
    ) -> Result<Value, String> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("missing 'path' parameter")?;

        // Resolve relative paths against CWD.
        let file_path = std::path::Path::new(path);
        let abs_path = if file_path.is_absolute() {
            file_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| format!("failed to get CWD: {e}"))?
                .join(file_path)
        };

        // Read directly in-process. The authz layer already validated access.
        // Builtin tools bypass the sandbox — it's designed for untrusted script tools.
        match tokio::fs::read_to_string(&abs_path).await {
            Ok(text) => Ok(json!({
                "content": [{"type": "text", "text": text}],
                "isError": false
            })),
            Err(e) => Err(format!("read_file failed: {e}")),
        }
    }
}
