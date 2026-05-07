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
use crate::config::schema::Config;
use crate::protocol::lifecycle::{self, LifecycleState};
use crate::protocol::messages::*;
use crate::session::Session;

/// Run the stdio transport loop. Blocks until stdin is closed.
pub async fn run(config: Config, audit: Arc<AuditLog>) {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut session = Session::new();

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
                if let Some(response) = dispatch(&msg, &mut session, &config, &audit) {
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
fn dispatch(
    msg: &JsonRpcMessage,
    session: &mut Session,
    config: &Config,
    audit: &AuditLog,
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
            Some(lifecycle::handle_tools_list(id))
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
