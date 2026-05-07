//! McpTool trait, tool registry, and built-in tool registration.

pub mod builtin;

use async_trait::async_trait;
use serde_json::Value;

use crate::authz::AccessRequest;
use crate::config::schema::Config;

/// The core trait that every MCP tool implements.
#[async_trait]
pub trait McpTool: Send + Sync {
    /// Tool name as exposed to the agent.
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// JSON Schema for the tool's input parameters.
    fn input_schema(&self) -> Value;

    /// Declare what resources this tool needs for a given call.
    ///
    /// The server evaluates these against the key's policy rules
    /// using the intersection model.
    fn access_requests(&self, params: &Value) -> Vec<AccessRequest>;

    /// Execute the tool. Only called if authorization succeeded.
    ///
    /// Returns MCP-compliant content (TextContent, ImageContent, etc.).
    async fn execute(
        &self,
        params: &Value,
        config: &Config,
    ) -> Result<Value, String>;
}

/// Registry of all available tools.
pub struct ToolRegistry {
    tools: Vec<Box<dyn McpTool>>,
}

impl ToolRegistry {
    /// Create a new registry with built-in tools.
    pub fn new() -> Self {
        let mut registry = Self { tools: vec![] };

        // Register built-in tools.
        registry.register(Box::new(builtin::read_file::ReadFileTool));
        registry.register(Box::new(builtin::write_file::WriteFileTool));
        registry.register(Box::new(builtin::list_dir::ListDirTool));

        registry
    }

    /// Register a new tool.
    pub fn register(&mut self, tool: Box<dyn McpTool>) {
        self.tools.push(tool);
    }

    /// Get all tool definitions for `tools/list`.
    pub fn list(&self) -> Vec<crate::protocol::messages::ToolDefinition> {
        self.tools
            .iter()
            .map(|t| crate::protocol::messages::ToolDefinition {
                name: t.name().to_string(),
                description: t.description().to_string(),
                input_schema: t.input_schema(),
            })
            .collect()
    }

    /// Find a tool by name.
    pub fn get(&self, name: &str) -> Option<&dyn McpTool> {
        self.tools.iter().find(|t| t.name() == name).map(|t| t.as_ref())
    }
}
