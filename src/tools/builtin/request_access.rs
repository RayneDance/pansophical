//! Built-in `request_access` tool.
//!
//! Lets an LLM request elevated access from the human operator.
//! The call blocks until the admin approves or denies via the dashboard.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::authz::AccessRequest;
use crate::config::schema::Config;
use crate::confirm::server::{ApprovalResult, ConfirmState};
use crate::confirm::session::{ApprovalKey, ApprovalScope};
use crate::tools::McpTool;

pub struct RequestAccessTool {
    confirm_state: Arc<ConfirmState>,
}

impl RequestAccessTool {
    pub fn new(confirm_state: Arc<ConfirmState>) -> Self {
        Self { confirm_state }
    }
}

#[async_trait]
impl McpTool for RequestAccessTool {
    fn name(&self) -> &str {
        "builtin_request_access"
    }

    fn description(&self) -> &str {
        "Request access to a resource that was denied. Sends a request to the admin for approval. \
         Use this when a previous tool call was denied due to missing permissions."
    }

    fn groups(&self) -> Vec<String> {
        vec!["builtin".into()]
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "enum": ["filesystem", "tool", "program"],
                    "description": "Type of resource to request access to"
                },
                "resource": {
                    "type": "string",
                    "description": "The resource identifier (file path, tool name, or executable)"
                },
                "permission": {
                    "type": "string",
                    "enum": ["r", "w", "rw", "x"],
                    "description": "Permission level needed (for filesystem/program resources)"
                },
                "reason": {
                    "type": "string",
                    "description": "Explain why you need this access"
                }
            },
            "required": ["resource_type", "resource", "reason"]
        })
    }

    fn access_requests(&self, _params: &Value) -> Vec<AccessRequest> {
        // This tool only needs tool-level authorization — no filesystem/program access.
        vec![]
    }

    async fn execute(
        &self,
        params: &Value,
        config: &Config,
        _granted_env: &[(String, String)],
    ) -> Result<Value, String> {
        let resource_type = params
            .get("resource_type")
            .and_then(|v| v.as_str())
            .ok_or("missing 'resource_type' parameter")?;

        let resource = params
            .get("resource")
            .and_then(|v| v.as_str())
            .ok_or("missing 'resource' parameter")?;

        let reason = params
            .get("reason")
            .and_then(|v| v.as_str())
            .ok_or("missing 'reason' parameter")?;

        let permission = params
            .get("permission")
            .and_then(|v| v.as_str())
            .unwrap_or("r");

        let perm_display = format!("{resource_type}:{permission}");

        let ttl = config.ui.confirm.timeout_secs;
        let port = config.ui.port;

        // Get the real session context from the task-local.
        let session_ctx = crate::transport::stdio::current_session()
            .ok_or("no session context available")?;

        tracing::info!(
            resource_type = resource_type,
            resource = resource,
            permission = permission,
            reason = reason,
            key = %session_ctx.key_name,
            conn = %session_ctx.connection_id,
            "LLM requesting elevated access"
        );

        // Submit the request through the confirm system.
        let result = crate::confirm::server::request_confirmation(
            &self.confirm_state,
            &format!("request_access ({reason})"),
            resource,
            &perm_display,
            &session_ctx.key_name,
            &session_ctx.connection_id,
            ttl,
            port,
        )
        .await;

        match result {
            ApprovalResult::Approved(scope) => {
                tracing::info!(
                    resource = resource,
                    scope = ?scope,
                    "Access request approved by admin"
                );

                // Store an ephemeral grant in the approval cache with the
                // correct session keys, so subsequent tool calls will find it.
                // Use tool_name = "*" so ANY tool can use this resource grant.
                let cache_key = ApprovalKey {
                    connection_id: session_ctx.connection_id.clone(),
                    key_name: session_ctx.key_name.clone(),
                    tool_name: "*".to_string(),
                    resource_pattern: resource.replace('\\', "/"),
                    perm: permission.to_string(),
                };

                // Force at least 5 minutes for "Once" scope so the LLM
                // has time to retry the operation.
                let effective_scope = match &scope {
                    ApprovalScope::Once => ApprovalScope::Minutes(5),
                    other => other.clone(),
                };
                self.confirm_state
                    .approval_cache
                    .approve(cache_key, &effective_scope);

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "\u{2713} Access APPROVED by admin.\n\
                             Resource: {resource}\n\
                             Type: {resource_type}\n\
                             Permission: {permission}\n\
                             Scope: {scope:?}\n\
                             You may now retry the operation."
                        )
                    }],
                    "isError": false
                }))
            }
            ApprovalResult::Denied => {
                tracing::info!(
                    resource = resource,
                    "Access request denied by admin"
                );
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "\u{2717} Access DENIED by admin.\n\
                             Resource: {resource}\n\
                             Type: {resource_type}\n\
                             Permission: {permission}\n\
                             The admin did not grant this access. \
                             Do not retry this request."
                        )
                    }],
                    "isError": false
                }))
            }
        }
    }
}
