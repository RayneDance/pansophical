//! Built-in `search_files` tool.
//!
//! Recursively searches for a text pattern in files under a directory.
//! Returns matching file paths and line contents.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::perm::Perm;
use crate::config::schema::Config;
use crate::tools::McpTool;

pub struct SearchFilesTool;

const MAX_RESULTS: usize = 100;
const MAX_DEPTH: usize = 20;
const MAX_LINE_LEN: usize = 500;

#[async_trait]
impl McpTool for SearchFilesTool {
    fn name(&self) -> &str {
        "builtin_search_files"
    }

    fn description(&self) -> &str {
        "Search for a text pattern in files under a directory. Returns matching lines."
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
                    "description": "Absolute path to the directory to search."
                },
                "pattern": {
                    "type": "string",
                    "description": "Text pattern to search for (case-insensitive substring match)."
                },
                "file_pattern": {
                    "type": "string",
                    "description": "Optional glob pattern for filenames to include (e.g. '*.rs'). Defaults to all files."
                }
            },
            "required": ["path", "pattern"]
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
        let pattern = params.get("pattern").and_then(|v| v.as_str())
            .ok_or("missing 'pattern' parameter")?;
        let file_pattern = params.get("file_pattern").and_then(|v| v.as_str());

        let pattern_lower = pattern.to_lowercase();
        let mut results = Vec::new();

        search_dir(
            std::path::Path::new(path),
            &pattern_lower,
            file_pattern,
            &mut results,
            0,
        );

        let total = results.len();
        let truncated = total > MAX_RESULTS;
        let display: Vec<_> = results.into_iter().take(MAX_RESULTS).collect();

        let mut text = display.join("\n");
        if truncated {
            text.push_str(&format!("\n\n[{} total matches, showing first {}]", total, MAX_RESULTS));
        } else if total == 0 {
            text = format!("No matches found for '{}' in {}", pattern, path);
        }

        Ok(json!({
            "content": [{"type": "text", "text": text}],
            "isError": false
        }))
    }
}

fn search_dir(
    dir: &std::path::Path,
    pattern: &str,
    file_pattern: Option<&str>,
    results: &mut Vec<String>,
    depth: usize,
) {
    if depth > MAX_DEPTH || results.len() > MAX_RESULTS * 2 {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            search_dir(&path, pattern, file_pattern, results, depth + 1);
        } else if path.is_file() {
            // Check file pattern filter.
            if let Some(fp) = file_pattern {
                let name = path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !simple_glob_match(fp, &name) {
                    continue;
                }
            }

            // Search file contents.
            if let Ok(contents) = std::fs::read_to_string(&path) {
                for (i, line) in contents.lines().enumerate() {
                    if line.to_lowercase().contains(pattern) {
                        let display_line = if line.len() > MAX_LINE_LEN {
                            format!("{}...", &line[..MAX_LINE_LEN])
                        } else {
                            line.to_string()
                        };
                        results.push(format!(
                            "{}:{}:{}",
                            path.display(),
                            i + 1,
                            display_line,
                        ));
                        if results.len() > MAX_RESULTS * 2 {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Simple glob match supporting only '*' (match any sequence).
fn simple_glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pat = pattern.to_lowercase();
    let name = name.to_lowercase();

    if pat.starts_with("*.") {
        // Extension match: *.rs, *.txt, etc.
        let ext = &pat[1..]; // includes the dot
        name.ends_with(&ext)
    } else if pat.ends_with("*") {
        let prefix = &pat[..pat.len() - 1];
        name.starts_with(&prefix)
    } else {
        name == pat
    }
}
