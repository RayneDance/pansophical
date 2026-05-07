//! HTTP/SSE transport with bearer token auth, CORS enforcement,
//! and configurable disconnect policy (kill / detach).
//!
//! Routes:
//!   GET  /sse           — SSE connection (bearer token in Authorization header)
//!   POST /message       — JSON-RPC messages (bound to SSE session)
//!   GET  /health        — health check
//!   POST /tools/call    — direct tool call (convenience, same authz pipeline)

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info};

use crate::audit::{AuditEntry, AuditLog};
use crate::authz::{self, AccessRequest, AuthzDecision};
use crate::config::schema::Config;
use crate::confirm::server::{ApprovalResult, ConfirmState};
use crate::protocol::lifecycle;
use crate::protocol::messages::*;
use crate::session::Session;
use crate::tools::ToolRegistry;

/// Shared application state for the HTTP transport.
pub struct HttpState {
    pub config: Config,
    pub audit: Arc<AuditLog>,
    pub confirm_state: Arc<ConfirmState>,
    pub registry: ToolRegistry,
    /// Active SSE sessions: session_id → sender for SSE events.
    pub sessions: DashMap<String, HttpSession>,
}

/// An active SSE session.
pub struct HttpSession {
    pub session: Session,
    pub tx: mpsc::Sender<Result<Event, std::convert::Infallible>>,
}

/// Query params for POST /message.
#[derive(Deserialize)]
pub struct SessionQuery {
    #[serde(rename = "sessionId")]
    session_id: String,
}

/// Run the HTTP transport server. Blocks until shutdown.
pub async fn run(config: Config, audit: Arc<AuditLog>, confirm_state: Arc<ConfirmState>) {
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    let registry = ToolRegistry::load_from_config(&config);

    // Build CORS layer from config.
    let cors = build_cors_layer(&config.server.http.cors_origins);

    let state = Arc::new(HttpState {
        config,
        audit,
        confirm_state,
        registry,
        sessions: DashMap::new(),
    });

    let app = Router::new()
        .route("/sse", get(handle_sse))
        .route("/message", post(handle_message))
        .route("/health", get(|| async { "ok" }))
        .layer(cors)
        .with_state(Arc::clone(&state));

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind HTTP transport to {bind_addr}: {e}");
            return;
        }
    };

    info!("HTTP transport listening on {bind_addr}");

    if let Err(e) = axum::serve(listener, app).await {
        error!("HTTP transport error: {e}");
    }
}

/// Build the CORS layer from the configured origins list.
fn build_cors_layer(origins: &[String]) -> CorsLayer {
    if origins.is_empty() || origins.iter().any(|o| o == "*") {
        CorsLayer::very_permissive()
    } else {
        // Parse origins. Note: wildcard patterns like "http://localhost:*"
        // are not standard CORS; we'll be permissive for localhost.
        let parsed: Vec<_> = origins
            .iter()
            .filter_map(|o| {
                if o.contains('*') {
                    None // Skip wildcard patterns — use permissive for those
                } else {
                    o.parse().ok()
                }
            })
            .collect();

        if parsed.is_empty() {
            // All origins were wildcards — be permissive.
            CorsLayer::very_permissive()
        } else {
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(parsed))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(tower_http::cors::Any)
        }
    }
}

/// Extract bearer token from Authorization header.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

// ── SSE Connection ──────────────────────────────────────────────────────────

/// Handle SSE connection: `GET /sse`.
///
/// The MCP Streamable HTTP spec: client connects with GET /sse,
/// server returns an SSE stream. The server sends an `endpoint` event
/// with a session ID that the client uses for POST /message.
async fn handle_sse(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> Result<Sse<ReceiverStream<Result<Event, std::convert::Infallible>>>, StatusCode> {
    // Extract and validate bearer token.
    let token = extract_bearer(&headers).unwrap_or_default();

    // Validate key exists (if keys are configured).
    if !state.config.keys.is_empty() {
        if state.config.resolve_key(&token).is_none() {
            state.audit.log_event("http_auth_failed", "invalid bearer token");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Create a new session.
    let mut session = Session::new();
    session.token = token;
    let session_id = session.connection_id.clone();

    // Create the SSE channel.
    let (tx, rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(64);

    // Send the endpoint event with session ID.
    let endpoint_url = format!("/message?sessionId={session_id}");
    let _ = tx
        .send(Ok(Event::default()
            .event("endpoint")
            .data(endpoint_url)))
        .await;

    info!(session_id = %session_id, "SSE client connected");

    state.audit.log(
        &AuditEntry::new(&session_id, &session.key_name)
            .with_decision("connected")
            .with_detail("SSE session established"),
    );

    // Store the session.
    state.sessions.insert(
        session_id.clone(),
        HttpSession {
            session,
            tx: tx.clone(),
        },
    );

    // Set up cleanup on disconnect.
    let state_cleanup = Arc::clone(&state);
    let session_id_cleanup = session_id.clone();
    tokio::spawn(async move {
        // When the receiver is dropped (client disconnects), clean up.
        // We use a simple polling approach — check if the sender can still send.
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if tx.is_closed() {
                info!(session_id = %session_id_cleanup, "SSE client disconnected");
                state_cleanup.sessions.remove(&session_id_cleanup);
                state_cleanup.audit.log_event(
                    "http_disconnect",
                    &format!("SSE session {} disconnected", session_id_cleanup),
                );
                break;
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ── Message Handler ─────────────────────────────────────────────────────────

/// Handle JSON-RPC messages: `POST /message?sessionId=...`.
async fn handle_message(
    State(state): State<Arc<HttpState>>,
    _headers: HeaderMap,
    Query(query): Query<SessionQuery>,
    Json(msg): Json<JsonRpcMessage>,
) -> Response {
    let session_id = query.session_id;

    // Find the session.
    let session_entry = match state.sessions.get(&session_id) {
        Some(entry) => entry,
        None => {
            let err = JsonRpcError::new(
                msg.id.clone().unwrap_or(Value::Null),
                error_codes::INVALID_REQUEST,
                "unknown session — connect via GET /sse first",
            );
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::to_value(err).unwrap()),
            )
                .into_response();
        }
    };

    let tx = session_entry.tx.clone();
    let session = &session_entry.session;
    let _id = msg.id.clone().unwrap_or(Value::Null);

    // Dispatch the message.
    let response = dispatch_http(
        &msg,
        session,
        &state.config,
        &state.audit,
        &state.registry,
        &state.confirm_state,
    )
    .await;

    match response {
        Some(value) => {
            // Send via SSE as well.
            let _ = tx
                .send(Ok(Event::default()
                    .event("message")
                    .data(serde_json::to_string(&value).unwrap_or_default())))
                .await;

            // Also return directly as HTTP response.
            (StatusCode::OK, Json(value)).into_response()
        }
        None => {
            // Notification — no response needed.
            StatusCode::ACCEPTED.into_response()
        }
    }
}

/// Dispatch a JSON-RPC message (HTTP variant — reuses the same authz pipeline).
async fn dispatch_http(
    msg: &JsonRpcMessage,
    session: &Session,
    config: &Config,
    audit: &AuditLog,
    registry: &ToolRegistry,
    confirm_state: &Arc<ConfirmState>,
) -> Option<Value> {
    let is_notification = msg.id.is_none();
    let id = msg.id.clone().unwrap_or(Value::Null);

    match msg.method.as_str() {
        "initialize" => {
            let (result, _) =
                lifecycle::handle_initialize(id.clone(), msg.params.clone(), config);
            Some(
                serde_json::to_value(JsonRpcResponse::new(id, serde_json::to_value(result).unwrap()))
                    .unwrap(),
            )
        }

        "notifications/initialized" => {
            // Acknowledge but no response for notifications.
            None
        }

        "tools/list" => {
            let tools = registry.list();
            Some(
                serde_json::to_value(JsonRpcResponse::new(
                    id,
                    serde_json::to_value(ToolsListResult { tools }).unwrap(),
                ))
                .unwrap(),
            )
        }

        "tools/call" => {
            Some(
                handle_tools_call_http(id, msg.params.clone(), session, config, audit, registry, confirm_state)
                    .await,
            )
        }

        "ping" => Some(
            serde_json::to_value(JsonRpcResponse::new(id, json!({}))).unwrap(),
        ),

        _ => {
            if is_notification {
                None
            } else {
                Some(
                    serde_json::to_value(JsonRpcError::new(
                        id,
                        error_codes::METHOD_NOT_FOUND,
                        format!("unknown method: {}", msg.method),
                    ))
                    .unwrap(),
                )
            }
        }
    }
}

/// Handle `tools/call` for HTTP transport — same authz pipeline as stdio.
async fn handle_tools_call_http(
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

    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    // Build access requests.
    let mut access_requests = tool.access_requests(&arguments);
    access_requests.push(AccessRequest::tool_with_groups(tool_name, tool.groups()));

    // Evaluate against key's policy.
    let key_config = match config.resolve_key(&session.token) {
        Some((_, kc)) => kc,
        None => {
            if config.keys.is_empty() {
                return execute_tool_http(id, tool, &arguments, config, audit, session, tool_name, &[]).await;
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

            audit.log(
                &AuditEntry::new(&session.connection_id, &session.key_name)
                    .with_tool(tool_name)
                    .with_decision("granted")
                    .with_access_requests(serde_json::to_value(&access_requests).unwrap()),
            );

            let env_grants = authz::collect_env_grants(key_config);

            let sandbox_profile = crate::sandbox::SandboxProfile::from_key_config(key_config);

            crate::sandbox::with_profile(
                sandbox_profile,
                execute_tool_http(id, tool, &arguments, config, audit, session, tool_name, &env_grants),
            ).await
        }
        AuthzDecision::Denied { explain } => {
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

/// Execute a tool after authorization (HTTP variant).
async fn execute_tool_http(
    id: Value,
    tool: &dyn crate::tools::McpTool,
    arguments: &Value,
    config: &Config,
    audit: &AuditLog,
    session: &Session,
    tool_name: &str,
    granted_env: &[(String, String)],
) -> Value {
    match tool.execute(arguments, config, granted_env).await {
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
            serde_json::to_value(JsonRpcError::new(
                id,
                error_codes::INTERNAL_ERROR,
                err,
            ))
            .unwrap()
        }
    }
}
