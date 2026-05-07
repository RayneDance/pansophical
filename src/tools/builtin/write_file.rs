//! Built-in `write_file` tool.
//!
//! Writes content to a file at the specified path.
//! Uses canonical_path_for_create for non-existent files.
//! Always out-of-process.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

pub struct WriteFileTool;

#[async_trait]
impl McpTool for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn description(&self) -> &str {
        "Write content to a file at the specified path. Creates the file if it doesn't exist."
    }

    fn groups(&self) -> &[&str] {
        &["builtin"]
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to write."
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file."
                }
            },
            "required": ["path", "content"]
        })
    }

    fn access_requests(&self, params: &Value) -> Vec<AccessRequest> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let path_obj = std::path::Path::new(path);

        // For create operations: canonicalize parent + append filename.
        let canonical = if path_obj.exists() {
            crate::authz::glob::canonical_path(path_obj)
        } else {
            crate::authz::glob::canonical_path_for_create(path_obj)
        };

        match canonical {
            Ok(c) => {
                vec![AccessRequest::filesystem(
                    c.to_string_lossy().to_string(),
                    Perm::WRITE,
                )]
            }
            Err(_) => {
                // Can't canonicalize — return raw path; authz will deny.
                vec![AccessRequest::filesystem(path, Perm::WRITE)]
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

        let content = params
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or("missing 'content' parameter")?;

        // Write directly (we're already authorized by the authz layer).
        // NOTE: In Phase 5+, this would go through the sandbox.
        // For the MVSS, we write directly but the authz layer has already
        // verified the path is within the granted policy.
        std::fs::write(path, content).map_err(|e| format!("write_file failed: {e}"))?;

        Ok(json!({
            "content": [{"type": "text", "text": format!("Successfully wrote {} bytes to {}", content.len(), path)}],
            "isError": false
        }))
    }
}
