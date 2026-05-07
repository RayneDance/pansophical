//! Built-in `create_directory` tool.
//!
//! Creates a directory (and parents if needed).

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

pub struct CreateDirectoryTool;

#[async_trait]
impl McpTool for CreateDirectoryTool {
    fn name(&self) -> &str {
        "builtin_create_directory"
    }

    fn description(&self) -> &str {
        "Create a directory (and any missing parent directories)."
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
                    "description": "Absolute path of the directory to create."
                }
            },
            "required": ["path"]
        })
    }

    fn access_requests(&self, params: &Value) -> Vec<AccessRequest> {
        let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
        match crate::authz::glob::canonical_path(std::path::Path::new(path)) {
            Ok(c) => vec![AccessRequest::filesystem(c.to_string_lossy().to_string(), Perm::WRITE)],
            // For new dirs that don't exist yet, canonicalize the parent.
            Err(_) => {
                let p = std::path::Path::new(path);
                if let Some(parent) = p.parent() {
                    match crate::authz::glob::canonical_path(parent) {
                        Ok(c) => vec![AccessRequest::filesystem(c.to_string_lossy().to_string(), Perm::WRITE)],
                        Err(_) => vec![AccessRequest::filesystem(path, Perm::WRITE)],
                    }
                } else {
                    vec![AccessRequest::filesystem(path, Perm::WRITE)]
                }
            }
        }
    }

    async fn execute(
        &self,
        params: &Value,
        _config: &Config,
        _granted_env: &[(String, String)],
    ) -> Result<Value, String> {
        let path = params.get("path").and_then(|v| v.as_str())
            .ok_or("missing 'path' parameter")?;

        std::fs::create_dir_all(path)
            .map_err(|e| format!("create_directory failed: {e}"))?;

        Ok(json!({
            "content": [{"type": "text", "text": format!("Created directory: {}", path)}],
            "isError": false
        }))
    }
}
