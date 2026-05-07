//! MCP initialize / initialized / shutdown handshake.

use serde_json::Value;
use tracing::{info, warn};

use crate::config::schema::Config;
use crate::protocol::messages::*;

/// Session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    /// Waiting for `initialize` request.
    AwaitingInit,
    /// `initialize` received, waiting for `initialized` notification.
    Initialized,
    /// `initialized` notification received. Fully operational.
    Ready,
    /// Shutdown requested.
    ShuttingDown,
}

/// Handle the `initialize` request.
///
/// Extracts the auth token from `params._meta.token`, resolves the key,
/// and returns the capabilities response or an error.
pub fn handle_initialize(
    id: Value,
    params: Option<Value>,
    config: &Config,
) -> (Result<(String, String), JsonRpcError>, Option<Value>) {
    // Extract protocol version from params.
    let params = match params {
        Some(p) => p,
        None => {
            return (
                Err(JsonRpcError::new(
                    id,
                    error_codes::INVALID_PARAMS,
                    "initialize requires params",
                )),
                None,
            );
        }
    };

    // Check protocol version.
    let client_version = params
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if client_version != MCP_PROTOCOL_VERSION {
        warn!(
            "Client requested protocol version '{}', we support '{}'",
            client_version, MCP_PROTOCOL_VERSION
        );
        // We still proceed — many clients send different versions.
        // We respond with our supported version per the spec.
    }

    // Extract auth token from params._meta.token.
    let token = params
        .get("_meta")
        .and_then(|m| m.get("token"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    // Resolve key.
    let key_name: String = match config.resolve_key(token) {
        Some((name, _)) => name.to_string(),
        None => {
            if token.is_empty() {
                let msg = if config.keys.is_empty() {
                    "no keys configured — run `pansophical --init` to generate a config with a demo key"
                } else {
                    "authentication required: provide token in params._meta.token"
                };
                return (
                    Err(JsonRpcError::new(id, error_codes::AUTH_ERROR, msg)),
                    None,
                );
            } else {
                return (
                    Err(JsonRpcError::new(
                        id,
                        error_codes::AUTH_ERROR,
                        "authentication failed: unknown token",
                    )),
                    None,
                );
            }
        }
    };

    let result = InitializeResult {
        protocol_version: MCP_PROTOCOL_VERSION.to_string(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
            resources: Some(ResourcesCapability { list_changed: true }),
            logging: Some(serde_json::json!({})),
        },
        server_info: ServerInfo {
            name: "pansophical".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };

    let response_value = serde_json::to_value(&result).unwrap();
    info!(key = %key_name, "Session initialized");

    (Ok((key_name, token.to_string())), Some(response_value))
}

/// Handle `tools/list` request.
pub fn handle_tools_list(id: Value, registry: &crate::tools::ToolRegistry) -> Value {
    let result = ToolsListResult {
        tools: registry.list(),
    };
    serde_json::to_value(JsonRpcResponse::new(id, serde_json::to_value(result).unwrap())).unwrap()
}
