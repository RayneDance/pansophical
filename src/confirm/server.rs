//! Confirm HTTP server (axum).
//!
//! Runs on `127.0.0.1:{ui.port}`, serves the approval page
//! and processes approve/deny POST requests.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex};
use tracing::{error, info, warn};

use crate::audit::AuditLog;
use crate::confirm::session::{ApprovalCache, ApprovalKey, ApprovalScope};
use crate::confirm::token::ConfirmToken;
use crate::confirm::ui;

/// The result sent back through the oneshot channel.
#[derive(Debug, Clone)]
pub enum ApprovalResult {
    Approved(ApprovalScope),
    Denied,
}

/// A pending confirmation request.
struct PendingConfirm {
    sender: oneshot::Sender<ApprovalResult>,
    tool_name: String,
    resource: String,
    perm: String,
    key_name: String,
    connection_id: String,
    token_str: String,
    ttl_secs: u64,
}

/// Shared state for the confirm server.
pub struct ConfirmState {
    pub pending: Mutex<HashMap<String, PendingConfirm>>,
    pub used_tokens: Mutex<Vec<String>>,
    pub approval_cache: Arc<ApprovalCache>,
    pub audit: Arc<AuditLog>,
    pub server_secret: String,
    /// JSON-serialized tools list for the dashboard.
    pub tools_json: Mutex<String>,
    /// JSON-serialized keys config for the dashboard.
    pub keys_json: Mutex<String>,
    /// Server start time.
    pub start_time: std::time::Instant,
}

impl ConfirmState {
    pub fn new(
        approval_cache: Arc<ApprovalCache>,
        audit: Arc<AuditLog>,
        server_secret: String,
    ) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            used_tokens: Mutex::new(Vec::new()),
            approval_cache,
            audit,
            server_secret,
            tools_json: Mutex::new("[]".to_string()),
            keys_json: Mutex::new("{}".to_string()),
            start_time: std::time::Instant::now(),
        }
    }

    /// Update the tools/keys JSON for dashboard rendering.
    pub async fn set_dashboard_data(&self, tools_json: String, keys_json: String) {
        *self.tools_json.lock().await = tools_json;
        *self.keys_json.lock().await = keys_json;
    }
}

/// Submit a confirmation request and wait for the user's decision.
///
/// Returns `Some(ApprovalResult)` if the user responds, `None` if the
/// token expires (auto-deny).
pub async fn request_confirmation(
    state: &Arc<ConfirmState>,
    tool_name: &str,
    resource: &str,
    perm: &str,
    key_name: &str,
    connection_id: &str,
    ttl_secs: u64,
    port: u16,
) -> ApprovalResult {
    // Check the approval cache first.
    let cache_key = ApprovalKey {
        connection_id: connection_id.to_string(),
        key_name: key_name.to_string(),
        tool_name: tool_name.to_string(),
        resource_pattern: resource.to_string(),
        perm: perm.to_string(),
    };

    if state.approval_cache.check(&cache_key) {
        info!(
            tool = tool_name,
            resource = resource,
            "Confirm skipped — cached approval"
        );
        return ApprovalResult::Approved(ApprovalScope::Once);
    }

    // Generate a token.
    let token = ConfirmToken::generate(&state.server_secret, ttl_secs);
    let token_str = token.to_string_token();

    // Create the oneshot channel.
    let (tx, rx) = oneshot::channel();

    // Register the pending request.
    {
        let mut pending = state.pending.lock().await;
        pending.insert(
            token_str.clone(),
            PendingConfirm {
                sender: tx,
                tool_name: tool_name.to_string(),
                resource: resource.to_string(),
                perm: perm.to_string(),
                key_name: key_name.to_string(),
                connection_id: connection_id.to_string(),
                token_str: token_str.clone(),
                ttl_secs,
            },
        );
    }

    // Build the URL.
    let url = format!("http://127.0.0.1:{port}/confirm/{token_str}");
    info!(url = %url, tool = tool_name, "Confirmation required — opening browser");

    // Audit.
    state.audit.log(
        &crate::audit::AuditEntry::new(connection_id, key_name)
            .with_tool(tool_name)
            .with_decision("pending")
            .with_detail(&format!("confirm required, url={url}")),
    );

    // Try to open the browser.
    if let Err(e) = open::that(&url) {
        warn!("Failed to open browser: {e}");
        warn!("Manual confirm URL: {url}");
    }

    // Wait for the response or timeout.
    let timeout = tokio::time::Duration::from_secs(ttl_secs);
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            // Channel closed — sender dropped (shouldn't happen).
            ApprovalResult::Denied
        }
        Err(_) => {
            // Timeout — auto-deny.
            warn!(tool = tool_name, "Confirmation timed out — auto-deny");
            state.audit.log(
                &crate::audit::AuditEntry::new(connection_id, key_name)
                    .with_tool(tool_name)
                    .with_decision("denied")
                    .with_detail("confirm timed out"),
            );

            // Clean up the pending entry.
            let mut pending = state.pending.lock().await;
            pending.remove(&token_str);

            ApprovalResult::Denied
        }
    }
}

/// Build the axum router for the confirm server.
pub fn router(state: Arc<ConfirmState>) -> Router {
    Router::new()
        .route("/", get(show_dashboard))
        .route("/confirm/{token}", get(show_confirm_page))
        .route("/confirm/{token}/approve", post(handle_approve))
        .route("/confirm/{token}/deny", post(handle_deny))
        .route("/api/audit", get(api_audit))
        .route("/health", get(health))
        .with_state(state)
}

/// Health check endpoint.
async fn health() -> &'static str {
    "ok"
}

/// Show the confirmation page.
async fn show_confirm_page(
    State(state): State<Arc<ConfirmState>>,
    Path(token_str): Path<String>,
) -> impl IntoResponse {
    // Verify the token.
    if let Err(e) = ConfirmToken::verify(&state.server_secret, &token_str) {
        return (StatusCode::FORBIDDEN, Html(format!("Invalid token: {e}"))).into_response();
    }

    // Find the pending request.
    let pending = state.pending.lock().await;
    match pending.get(&token_str) {
        Some(req) => {
            let html = ui::approval_page(
                &req.tool_name,
                &req.resource,
                &req.perm,
                &req.key_name,
                &token_str,
                req.ttl_secs,
            );
            (StatusCode::OK, Html(html)).into_response()
        }
        None => {
            (StatusCode::NOT_FOUND, Html("Token not found or already used.".to_string()))
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct DecisionBody {
    scope: Option<String>,
}

#[derive(Serialize)]
struct DecisionResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Handle approval.
async fn handle_approve(
    State(state): State<Arc<ConfirmState>>,
    Path(token_str): Path<String>,
    Json(body): Json<DecisionBody>,
) -> impl IntoResponse {
    handle_decision(state, token_str, true, body.scope).await
}

/// Handle denial.
async fn handle_deny(
    State(state): State<Arc<ConfirmState>>,
    Path(token_str): Path<String>,
    Json(body): Json<DecisionBody>,
) -> impl IntoResponse {
    handle_decision(state, token_str, false, body.scope).await
}

async fn handle_decision(
    state: Arc<ConfirmState>,
    token_str: String,
    approved: bool,
    scope_str: Option<String>,
) -> impl IntoResponse {
    // Verify the token.
    if let Err(e) = ConfirmToken::verify(&state.server_secret, &token_str) {
        return (
            StatusCode::FORBIDDEN,
            Json(DecisionResponse {
                ok: false,
                error: Some(format!("Invalid token: {e}")),
            }),
        );
    }

    // Check for replay.
    {
        let used = state.used_tokens.lock().await;
        if used.contains(&token_str) {
            return (
                StatusCode::CONFLICT,
                Json(DecisionResponse {
                    ok: false,
                    error: Some("Token already used".into()),
                }),
            );
        }
    }

    // Find and remove the pending request.
    let pending = {
        let mut pending_map = state.pending.lock().await;
        pending_map.remove(&token_str)
    };

    match pending {
        Some(req) => {
            // Mark token as used.
            {
                let mut used = state.used_tokens.lock().await;
                used.push(token_str.clone());
                // Keep the list bounded (last 10000).
                if used.len() > 10000 {
                    used.drain(..5000);
                }
            }

            let decision = if approved { "approved" } else { "denied" };

            // Parse scope.
            let scope = if approved {
                let scope_val = scope_str.as_deref().unwrap_or("once");
                match ApprovalScope::parse(scope_val) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Invalid scope '{scope_val}': {e}");
                        ApprovalScope::Once
                    }
                }
            } else {
                ApprovalScope::Once
            };

            // Cache the approval if applicable.
            if approved {
                let cache_key = ApprovalKey {
                    connection_id: req.connection_id.clone(),
                    key_name: req.key_name.clone(),
                    tool_name: req.tool_name.clone(),
                    resource_pattern: req.resource.clone(),
                    perm: req.perm.clone(),
                };
                state.approval_cache.approve(cache_key, &scope);
            }

            // Audit.
            state.audit.log(
                &crate::audit::AuditEntry::new(&req.connection_id, &req.key_name)
                    .with_tool(&req.tool_name)
                    .with_decision(decision)
                    .with_detail(&format!(
                        "user {} via confirm UI, scope={:?}",
                        decision, scope
                    )),
            );

            // Send the result through the channel.
            let result = if approved {
                ApprovalResult::Approved(scope)
            } else {
                ApprovalResult::Denied
            };
            let _ = req.sender.send(result);

            (
                StatusCode::OK,
                Json(DecisionResponse {
                    ok: true,
                    error: None,
                }),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(DecisionResponse {
                ok: false,
                error: Some("Token not found or already used".into()),
            }),
        ),
    }
}

/// Start the confirm server as a background tokio task.
pub async fn start(state: Arc<ConfirmState>, port: u16) {
    let app = router(state);

    let listener = match tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind confirm server on port {port}: {e}");
            return;
        }
    };

    info!("Confirm server listening on 127.0.0.1:{port}");

    if let Err(e) = axum::serve(listener, app).await {
        error!("Confirm server error: {e}");
    }
}

/// Show the admin dashboard.
async fn show_dashboard(
    State(state): State<Arc<ConfirmState>>,
) -> impl IntoResponse {
    let pending_count = state.pending.lock().await.len();
    let tools_json = state.tools_json.lock().await.clone();
    let keys_json = state.keys_json.lock().await.clone();

    let elapsed = state.start_time.elapsed();
    let hours = elapsed.as_secs() / 3600;
    let minutes = (elapsed.as_secs() % 3600) / 60;
    let uptime = if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    };

    let html = ui::dashboard_page(
        env!("CARGO_PKG_VERSION"),
        &tools_json,
        &keys_json,
        pending_count,
        &uptime,
    );

    (StatusCode::OK, Html(html))
}

/// API: return the last 200 audit log entries as JSON.
async fn api_audit(
    State(state): State<Arc<ConfirmState>>,
) -> impl IntoResponse {
    // Read the audit log file and return the last entries.
    let entries = state.audit.read_recent(200);
    Json(entries)
}
