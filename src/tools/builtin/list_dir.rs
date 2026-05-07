//! Built-in `list_dir` tool.
//!
//! Lists directory contents. Returns names and types.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

pub struct ListDirTool;

#[async_trait]
impl McpTool for ListDirTool {
    fn name(&self) -> &str {
        "list_dir"
    }

    fn description(&self) -> &str {
        "List the contents of a directory."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the directory to list."
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

        match crate::authz::glob::canonical_path(std::path::Path::new(path)) {
            Ok(canonical) => {
                vec![AccessRequest::filesystem(
                    canonical.to_string_lossy().to_string(),
                    Perm::READ,
                )]
            }
            Err(_) => {
                vec![AccessRequest::filesystem(path, Perm::READ)]
            }
        }
    }

    async fn execute(
        &self,
        params: &Value,
        _config: &Config,
    ) -> Result<Value, String> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("missing 'path' parameter")?;

        let entries = std::fs::read_dir(path)
            .map_err(|e| format!("list_dir failed: {e}"))?;

        let mut lines = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("entry error: {e}"))?;
            let file_type = entry.file_type().map_err(|e| format!("type error: {e}"))?;
            let kind = if file_type.is_dir() {
                "dir"
            } else if file_type.is_symlink() {
                "link"
            } else {
                "file"
            };
            lines.push(format!(
                "{}\t{}",
                kind,
                entry.file_name().to_string_lossy()
            ));
        }

        Ok(json!([{
            "type": "text",
            "text": lines.join("\n")
        }]))
    }
}
