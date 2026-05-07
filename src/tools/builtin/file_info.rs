//! Built-in `file_info` tool.
//!
//! Returns metadata about a file or directory (size, modified time, type).

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

pub struct FileInfoTool;

#[async_trait]
impl McpTool for FileInfoTool {
    fn name(&self) -> &str {
        "builtin_file_info"
    }

    fn description(&self) -> &str {
        "Get metadata about a file or directory (size, type, modified time)."
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
                    "description": "Absolute path to the file or directory."
                }
            },
            "required": ["path"]
        })
    }

    fn access_requests(&self, params: &Value) -> Vec<AccessRequest> {
        let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
        match crate::authz::glob::canonical_path(std::path::Path::new(path)) {
            Ok(c) => vec![AccessRequest::filesystem(c.to_string_lossy().to_string(), Perm::READ)],
            Err(_) => vec![AccessRequest::filesystem(path, Perm::READ)],
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

        let meta = std::fs::metadata(path)
            .map_err(|e| format!("file_info failed: {e}"))?;

        let file_type = if meta.is_dir() {
            "directory"
        } else if meta.is_symlink() {
            "symlink"
        } else {
            "file"
        };

        let size = meta.len();
        let modified = meta.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let readonly = meta.permissions().readonly();

        let text = format!(
            "type: {}\nsize: {} bytes\nmodified: {} (unix epoch)\nreadonly: {}",
            file_type, size, modified, readonly
        );

        Ok(json!({
            "content": [{"type": "text", "text": text}],
            "isError": false
        }))
    }
}
