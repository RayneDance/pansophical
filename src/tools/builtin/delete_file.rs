//! Built-in `delete_file` tool.
//!
//! Deletes a file or empty directory.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

pub struct DeleteFileTool;

#[async_trait]
impl McpTool for DeleteFileTool {
    fn name(&self) -> &str {
        "builtin_delete_file"
    }

    fn description(&self) -> &str {
        "Delete a file or empty directory."
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
                    "description": "Absolute path of the file or empty directory to delete."
                }
            },
            "required": ["path"]
        })
    }

    fn access_requests(&self, params: &Value) -> Vec<AccessRequest> {
        let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
        match crate::authz::glob::canonical_path(std::path::Path::new(path)) {
            Ok(c) => vec![AccessRequest::filesystem(c.to_string_lossy().to_string(), Perm::WRITE)],
            Err(_) => vec![AccessRequest::filesystem(path, Perm::WRITE)],
        }
    }

    async fn execute(
        &self,
        params: &Value,
        _config: &Config,
        _granted_env: &[(String, String)],
    ) -> Result<Value, String> {
        let path_str = params.get("path").and_then(|v| v.as_str())
            .ok_or("missing 'path' parameter")?;

        let path = std::path::Path::new(path_str);

        if path.is_dir() {
            std::fs::remove_dir(path)
                .map_err(|e| format!("delete_file failed (directory must be empty): {e}"))?;
        } else {
            std::fs::remove_file(path)
                .map_err(|e| format!("delete_file failed: {e}"))?;
        }

        Ok(json!({
            "content": [{"type": "text", "text": format!("Deleted: {}", path_str)}],
            "isError": false
        }))
    }
}
