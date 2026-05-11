//! Stdio transport: async line-delimited JSON-RPC reader/writer.
//!
//! The server's stdout is the JSON-RPC channel. Child processes
//! must NEVER inherit this fd.
//!
//! Reads one JSON-RPC message per line from stdin, dispatches it,
//! and writes the response to stdout.

use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info, warn};

use crate::audit::{AuditEntry, AuditLog};
use crate::authz::{self, AccessRequest, AuthzDecision};
use crate::config::schema::Config;
use crate::confirm::server::{ApprovalResult, ConfirmState};
use crate::protocol::lifecycle::{self, LifecycleState};
use crate::protocol::messages::*;
use crate::session::Session;
use crate::tools::ToolRegistry;

// ── Task-local session context ────────────────────────────────────────────────
//
// Set before calling tool.execute() so tools like `request_access` can read
// the current session's connection_id and key_name without modifying the
// McpTool trait signature.

/// Session context passed via task-local to tool execution.
#[derive(Clone, Debug)]
pub struct SessionContext {
    pub connection_id: String,
    pub key_name: String,
}

tokio::task_local! {
    static CURRENT_SESSION: SessionContext;
}

/// Get the current task's session context (if set).
pub fn current_session() -> Option<SessionContext> {
    CURRENT_SESSION.try_with(|s| s.clone()).ok()
}

/// Run the stdio transport loop. Blocks until stdin is closed.
pub async fn run(config: Config, audit: Arc<AuditLog>, confirm_state: Arc<ConfirmState>) {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut session = Session::new();
    let registry = ToolRegistry::load_with_confirm(&config, Arc::clone(&confirm_state));

    info!(
        connection_id = %session.connection_id,
        "Stdio transport started"
    );
    audit.log_event("transport_start", &format!(
        "stdio transport started, connection_id={}",
        session.connection_id
    ));

    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF — stdin closed.
                info!(
                    connection_id = %session.connection_id,
                    "Stdin closed — shutting down"
                );
                audit.log_event("transport_close", &format!(
                    "stdin closed, connection_id={}",
                    session.connection_id
                ));
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                debug!(raw = trimmed, "Received message");

                // Parse JSON-RPC message.
                let msg: JsonRpcMessage = match serde_json::from_str(trimmed) {
                    Ok(m) => m,
                    Err(e) => {
                        let err = JsonRpcError::new(
                            Value::Null,
                            error_codes::PARSE_ERROR,
                            format!("JSON parse error: {e}"),
                        );
                        write_response(&mut stdout, &err).await;
                        continue;
                    }
                };

                // Dispatch.
                let response = dispatch(&msg, &mut session, &config, &audit, &registry, &confirm_state).await;
                if let Some(response) = response {
                    write_response(&mut stdout, &response).await;
                }
                // Notifications (id == None) don't get responses.
            }
            Err(e) => {
                error!("Stdin read error: {e}");
                break;
            }
        }
    }
}

/// Dispatch a JSON-RPC message and return an optional response.
async fn dispatch(
    msg: &JsonRpcMessage,
    session: &mut Session,
    config: &Config,
    audit: &AuditLog,
    registry: &ToolRegistry,
    confirm_state: &Arc<ConfirmState>,
) -> Option<Value> {
    let is_notification = msg.id.is_none();
    let id = msg.id.clone().unwrap_or(Value::Null);

    match msg.method.as_str() {
        // ── Lifecycle ─────────────────────────────────────────────────
        "initialize" => {
            if session.state != LifecycleState::AwaitingInit {
                return Some(
                    serde_json::to_value(JsonRpcError::new(
                        id,
                        error_codes::INVALID_REQUEST,
                        "already initialized",
                    ))
                    .unwrap(),
                );
            }

            let (result, response_value) =
                lifecycle::handle_initialize(id.clone(), msg.params.clone(), config);

            match result {
                Ok((key_name, token)) => {
                    session.bind(key_name, token);

                    // Audit: successful auth.
                    audit.log(
                        &AuditEntry::new(&session.connection_id, &session.key_name)
                            .with_decision("granted")
                            .with_event("initialize")
                            .with_detail("session initialized"),
                    );

                    Some(
                        serde_json::to_value(JsonRpcResponse::new(
                            id,
                            response_value.unwrap(),
                        ))
                        .unwrap(),
                    )
                }
                Err(err) => {
                    // Audit: failed auth.
                    audit.log(
                        &AuditEntry::new(&session.connection_id, "unknown")
                            .with_decision("denied")
                            .with_event("initialize")
                            .with_detail(&err.error.message),
                    );

                    Some(serde_json::to_value(err).unwrap())
                }
            }
        }

        "notifications/initialized" => {
            if session.state == LifecycleState::Initialized {
                session.mark_ready();
                info!(
                    connection_id = %session.connection_id,
                    key = %session.key_name,
                    "Session ready"
                );
            } else {
                warn!("Received initialized notification in unexpected state: {:?}", session.state);
            }
            None // Notifications don't get responses.
        }

        // ── Tools ─────────────────────────────────────────────────────
        "tools/list" => {
            if !is_initialized(session, &id) {
                return Some(not_initialized_error(id));
            }
            Some(lifecycle::handle_tools_list(id, registry))
        }

        "tools/call" => {
            if !is_initialized(session, &id) {
                return Some(not_initialized_error(id));
            }
            Some(handle_tools_call(id, msg.params.clone(), session, config, audit, registry, confirm_state).await)
        }

        // ── Shutdown ──────────────────────────────────────────────────
        "shutdown" => {
            session.state = LifecycleState::ShuttingDown;
            info!(connection_id = %session.connection_id, "Shutdown requested");
            audit.log(
                &AuditEntry::new(&session.connection_id, &session.key_name)
                    .with_event("shutdown")
                    .with_decision("n/a")
                    .with_detail("client requested shutdown"),
            );
            Some(
                serde_json::to_value(JsonRpcResponse::new(id, Value::Null))
                    .unwrap(),
            )
        }

        // ── Unknown ───────────────────────────────────────────────────
        _ => {
            if is_notification {
                // Unknown notifications are silently ignored per JSON-RPC spec.
                debug!(method = %msg.method, "Ignoring unknown notification");
                None
            } else {
                Some(
                    serde_json::to_value(JsonRpcError::new(
                        id,
                        error_codes::METHOD_NOT_FOUND,
                        format!("method not found: {}", msg.method),
                    ))
                    .unwrap(),
                )
            }
        }
    }
}

/// Handle `tools/call` — the core authz + execution pipeline.
async fn handle_tools_call(
    id: Value,
    params: Option<Value>,
    session: &Session,
    config: &Config,
    audit: &AuditLog,
    registry: &ToolRegistry,
    confirm_state: &Arc<ConfirmState>,
) -> Value {
    let params = match params {
        Some(p) => p,
        None => {
            return serde_json::to_value(JsonRpcError::new(
                id,
                error_codes::INVALID_PARAMS,
                "tools/call requires params",
            ))
            .unwrap();
        }
    };

    // Extract tool name.
    let tool_name = match params.get("name").and_then(|v| v.as_str()) {
        Some(name) => name,
        None => {
            return serde_json::to_value(JsonRpcError::new(
                id,
                error_codes::INVALID_PARAMS,
                "tools/call requires 'name' in params",
            ))
            .unwrap();
        }
    };

    // Find the tool.
    let tool = match registry.get(tool_name) {
        Some(t) => t,
        None => {
            return serde_json::to_value(JsonRpcError::new(
                id,
                error_codes::METHOD_NOT_FOUND,
                format!("unknown tool: {tool_name}"),
            ))
            .unwrap();
        }
    };

    // Extract arguments.
    let arguments = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));

    // ── Step 1: Build access requests ─────────────────────────────────
    let mut access_requests = tool.access_requests(&arguments);

    // Always require tool meta-authorization.
    access_requests.push(AccessRequest::tool_with_groups(tool_name, tool.groups()));

    // ── Step 2: Evaluate against key's policy ─────────────────────────
    let key_config = match config.resolve_key(&session.token) {
        Some((_, kc)) => kc,
        None => {
            // Anonymous session — check if keys exist at all.
            if config.keys.is_empty() {
                // No keys configured — skip authz for development.
                // Execute directly.
                return execute_tool(id, tool, &arguments, config, audit, session, tool_name, &[]).await;
            }
            return serde_json::to_value(JsonRpcError::new(
                id,
                error_codes::AUTH_ERROR,
                "session key not found",
            ))
            .unwrap();
        }
    };

    let decision = authz::evaluate(&access_requests, key_config, config.server.dev_mode);

    match decision {
        AuthzDecision::Granted { requires_confirm, .. } => {
            if requires_confirm {
                // HITL: request human confirmation before executing.
                let resource_desc = access_requests
                    .iter()
                    .filter(|r| r.target_type != crate::config::policy_target::PolicyTargetType::Tool)
                    .map(|r| r.resource.clone())
                    .next()
                    .unwrap_or_else(|| tool_name.to_string());
                let perm_desc = access_requests
                    .iter()
                    .filter(|r| r.target_type != crate::config::policy_target::PolicyTargetType::Tool)
                    .map(|r| r.perm.to_string())
                    .next()
                    .unwrap_or_default();

                let result = crate::confirm::server::request_confirmation(
                    confirm_state,
                    tool_name,
                    &resource_desc,
                    &perm_desc,
                    &session.key_name,
                    &session.connection_id,
                    config.limits.tool_timeout_secs,
                    config.ui.port,
                )
                .await;

                match result {
                    ApprovalResult::Denied => {
                        audit.log(
                            &AuditEntry::new(&session.connection_id, &session.key_name)
                                .with_tool(tool_name)
                                .with_decision("denied")
                                .with_detail("confirm denied by user"),
                        );
                        return serde_json::to_value(JsonRpcError::new(
                            id,
                            error_codes::CONFIRM_DENIED,
                            "confirmation denied by user",
                        ))
                        .unwrap();
                    }
                    ApprovalResult::Approved(_) => {
                        // Fall through to execution.
                    }
                }
            }

            // Audit: granted.
            audit.log(
                &AuditEntry::new(&session.connection_id, &session.key_name)
                    .with_tool(tool_name)
                    .with_decision("granted")
                    .with_access_requests(serde_json::to_value(&access_requests).unwrap()),
            );

            // Collect environment variable grants from the key's rules.
            let env_grants = authz::collect_env_grants(key_config);

            // Build sandbox profile from the key's filesystem grants.
            let sandbox_profile = crate::sandbox::SandboxProfile::from_key_config(key_config);

            // Execute with the sandbox profile set in the task-local.
            crate::sandbox::with_profile(
                sandbox_profile,
                execute_tool(id, tool, &arguments, config, audit, session, tool_name, &env_grants),
            ).await
        }
        AuthzDecision::Denied { explain } => {
            // ── Check ephemeral grants (from request_access approvals) ────
            // The approval cache may contain grants from admin-approved
            // request_access calls. Check if all NON-TOOL access requests
            // have matching cached approvals. Tool-type requests are skipped
            // because the tool is registered and callable — the denial is
            // about resource access, not tool existence.
            let resource_requests: Vec<_> = access_requests
                .iter()
                .filter(|r| r.target_type != crate::config::policy_target::PolicyTargetType::Tool)
                .collect();
            let mut all_covered = !resource_requests.is_empty();
            for req in &resource_requests {
                // Normalize path separators and case for matching (Windows is case-insensitive).
                let resource = req.resource.replace('\\', "/").to_lowercase();
                let generic_key = crate::confirm::session::ApprovalKey {
                    connection_id: session.connection_id.clone(),
                    key_name: session.key_name.clone(),
                    tool_name: "*".to_string(),
                    resource_pattern: resource.clone(),
                    perm: req.perm.to_string(),
                };
                if confirm_state.approval_cache.check(&generic_key) {
                    debug!(resource = %resource, "Ephemeral grant found");
                    continue;
                }
                // Also try tool-specific key.
                let specific_key = crate::confirm::session::ApprovalKey {
                    connection_id: session.connection_id.clone(),
                    key_name: session.key_name.clone(),
                    tool_name: tool_name.to_string(),
                    resource_pattern: resource.clone(),
                    perm: req.perm.to_string(),
                };
                if confirm_state.approval_cache.check(&specific_key) {
                    debug!(resource = %resource, tool = tool_name, "Ephemeral grant found (tool-specific)");
                    continue;
                }
                all_covered = false;
                break;
            }

            if all_covered {
                // Ephemeral grants cover all denied requests — allow execution.
                info!(
                    tool = tool_name,
                    "Authz denied by policy, but ephemeral grant covers all requests"
                );
                audit.log(
                    &AuditEntry::new(&session.connection_id, &session.key_name)
                        .with_tool(tool_name)
                        .with_decision("granted")
                        .with_detail("ephemeral grant override"),
                );

                let env_grants = authz::collect_env_grants(key_config);
                let mut sandbox_profile = crate::sandbox::SandboxProfile::from_key_config(key_config);

                // Augment the sandbox profile with ephemeral grant paths.
                // Without this, the AppContainer denies access at the OS level
                // even though the authz cache approved the resource.
                for req in &resource_requests {
                    let path = std::path::PathBuf::from(&req.resource);
                    if req.perm.contains(crate::config::perm::Perm::WRITE) {
                        sandbox_profile.write_paths.push(path);
                    } else {
                        sandbox_profile.read_paths.push(path);
                    }
                }

                return crate::sandbox::with_profile(
                    sandbox_profile,
                    execute_tool(id, tool, &arguments, config, audit, session, tool_name, &env_grants),
                ).await;
            }

            // No ephemeral grants — deny as normal.
            let detail = if let Some(ref diff) = explain {
                serde_json::to_string(diff).unwrap_or_default()
            } else {
                "denied".to_string()
            };

            audit.log(
                &AuditEntry::new(&session.connection_id, &session.key_name)
                    .with_tool(tool_name)
                    .with_decision("denied")
                    .with_detail(&detail),
            );

            if let Some(diff) = explain {
                serde_json::to_value(
                    JsonRpcError::new(id, error_codes::UNAUTHORIZED, "authorization denied")
                        .with_data(serde_json::to_value(diff).unwrap()),
                )
                .unwrap()
            } else {
                serde_json::to_value(JsonRpcError::new(
                    id,
                    error_codes::UNAUTHORIZED,
                    "authorization denied",
                ))
                .unwrap()
            }
        }
    }
}

/// Execute a tool after authorization has been granted.
async fn execute_tool(
    id: Value,
    tool: &dyn crate::tools::McpTool,
    arguments: &Value,
    config: &Config,
    audit: &AuditLog,
    session: &Session,
    tool_name: &str,
    granted_env: &[(String, String)],
) -> Value {
    let ctx = SessionContext {
        connection_id: session.connection_id.clone(),
        key_name: session.key_name.clone(),
    };

    let result = CURRENT_SESSION
        .scope(ctx, tool.execute(arguments, config, granted_env))
        .await;

    match result {
        Ok(result) => {
            audit.log(
                &AuditEntry::new(&session.connection_id, &session.key_name)
                    .with_tool(tool_name)
                    .with_decision("granted")
                    .with_outcome("success"),
            );

            serde_json::to_value(JsonRpcResponse::new(id, result)).unwrap()
        }
        Err(err) => {
            audit.log(
                &AuditEntry::new(&session.connection_id, &session.key_name)
                    .with_tool(tool_name)
                    .with_decision("granted")
                    .with_outcome("error")
                    .with_detail(&err),
            );

            serde_json::to_value(JsonRpcResponse::new(
                id,
                serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": err
                    }],
                    "isError": true
                }),
            ))
            .unwrap()
        }
    }
}

/// Check if the session has completed initialization.
fn is_initialized(session: &Session, _id: &Value) -> bool {
    matches!(
        session.state,
        LifecycleState::Initialized | LifecycleState::Ready
    )
}

/// Return a "not initialized" error.
fn not_initialized_error(id: Value) -> Value {
    serde_json::to_value(JsonRpcError::new(
        id,
        error_codes::INVALID_REQUEST,
        "server not initialized — send 'initialize' first",
    ))
    .unwrap()
}

/// Write a JSON response to stdout, followed by a newline.
async fn write_response<W: AsyncWriteExt + Unpin>(writer: &mut W, response: &impl serde::Serialize) {
    let json = serde_json::to_string(response).unwrap();
    debug!(raw = %json, "Sending response");
    if let Err(e) = writer.write_all(json.as_bytes()).await {
        error!("Failed to write response: {e}");
        return;
    }
    if let Err(e) = writer.write_all(b"\n").await {
        error!("Failed to write newline: {e}");
        return;
    }
    if let Err(e) = writer.flush().await {
        error!("Failed to flush stdout: {e}");
    }
}
