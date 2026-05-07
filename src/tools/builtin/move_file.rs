//! Built-in `move_file` tool.
//!
//! Moves or renames a file or directory.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

pub struct MoveFileTool;

#[async_trait]
impl McpTool for MoveFileTool {
    fn name(&self) -> &str {
        "builtin_move_file"
    }

    fn description(&self) -> &str {
        "Move or rename a file or directory."
    }

    fn groups(&self) -> Vec<String> {
        vec!["builtin".into()]
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "Absolute path of the source file or directory."
                },
                "destination": {
                    "type": "string",
                    "description": "Absolute path of the destination."
                }
            },
            "required": ["source", "destination"]
        })
    }

    fn access_requests(&self, params: &Value) -> Vec<AccessRequest> {
        let source = params.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let dest = params.get("destination").and_then(|v| v.as_str()).unwrap_or("");

        let mut reqs = Vec::new();

        // Need write on source (to remove it) and write on destination (to create it).
        match crate::authz::glob::canonical_path(std::path::Path::new(source)) {
            Ok(c) => reqs.push(AccessRequest::filesystem(c.to_string_lossy().to_string(), Perm::WRITE)),
            Err(_) => reqs.push(AccessRequest::filesystem(source, Perm::WRITE)),
        }

        // Destination may not exist yet — canonicalize parent.
        let dest_path = std::path::Path::new(dest);
        let dest_dir = dest_path.parent().unwrap_or(dest_path);
        match crate::authz::glob::canonical_path(dest_dir) {
            Ok(c) => reqs.push(AccessRequest::filesystem(c.to_string_lossy().to_string(), Perm::WRITE)),
            Err(_) => reqs.push(AccessRequest::filesystem(dest, Perm::WRITE)),
        }

        reqs
    }

    async fn execute(
        &self,
        params: &Value,
        _config: &Config,
        _granted_env: &[(String, String)],
    ) -> Result<Value, String> {
        let source = params.get("source").and_then(|v| v.as_str())
            .ok_or("missing 'source' parameter")?;
        let dest = params.get("destination").and_then(|v| v.as_str())
            .ok_or("missing 'destination' parameter")?;

        std::fs::rename(source, dest)
            .map_err(|e| format!("move_file failed: {e}"))?;

        Ok(json!({
            "content": [{"type": "text", "text": format!("Moved {} → {}", source, dest)}],
            "isError": false
        }))
    }
}
