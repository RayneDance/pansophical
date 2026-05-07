//! MCP JSON-RPC request, response, and notification types.
//!
//! Implements the JSON-RPC 2.0 envelope as used by the MCP protocol.
//! All MCP messages are JSON-RPC 2.0 with specific method names.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── JSON-RPC 2.0 base types ──────────────────────────────────────────────

/// An incoming JSON-RPC message (request or notification).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcMessage {
    pub jsonrpc: String,
    /// Present for requests; absent for notifications.
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// An outgoing JSON-RPC success response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    pub result: Value,
}

/// An outgoing JSON-RPC error response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub jsonrpc: String,
    pub id: Value,
    pub error: JsonRpcErrorBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcErrorBody {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn new(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result,
        }
    }
}

impl JsonRpcError {
    pub fn new(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            error: JsonRpcErrorBody {
                code,
                message: message.into(),
                data: None,
            },
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.error.data = Some(data);
        self
    }
}

// ── Standard JSON-RPC error codes ─────────────────────────────────────────

/// Standard JSON-RPC 2.0 error codes.
pub mod error_codes {
    /// Parse error: invalid JSON.
    pub const PARSE_ERROR: i32 = -32700;
    /// Invalid request: not a valid JSON-RPC request.
    pub const INVALID_REQUEST: i32 = -32600;
    /// Method not found.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid params.
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal error.
    pub const INTERNAL_ERROR: i32 = -32603;

    // ── Pansophical custom codes ──────────────────────────────────────

    /// Authentication error: unknown token.
    pub const AUTH_ERROR: i32 = -32000;
    /// Authorization error: insufficient permissions.
    pub const UNAUTHORIZED: i32 = -32001;
    /// Rate limited.
    pub const RATE_LIMITED: i32 = -32002;
    /// Concurrency limit exceeded.
    pub const CONCURRENCY_EXCEEDED: i32 = -32003;
    /// Confirmation denied or timed out.
    pub const CONFIRM_DENIED: i32 = -32004;
}

// ── MCP-specific types ───────────────────────────────────────────────────

/// Server capabilities returned in the `initialize` response.
#[derive(Debug, Clone, Serialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    pub list_changed: bool,
}

/// The `initialize` response result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// A tool definition returned in `tools/list`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// The `tools/list` response result.
#[derive(Debug, Clone, Serialize)]
pub struct ToolsListResult {
    pub tools: Vec<ToolDefinition>,
}

/// MCP protocol version we support.
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
