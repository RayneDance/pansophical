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
        "request_access"
    }

    fn description(&self) -> &str {
        "Request access to a resource that was denied. Sends a request to the admin for approval. \
         Use this when a previous tool call was denied due to missing permissions."
    }

    fn groups(&self) -> &[&str] {
        &["builtin"]
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

        // Use a task-local or derive connection/key info.
        // For now, use generic identifiers — the confirm system will
        // display the resource details to the admin.
        let key_name = "agent";
        let connection_id = "request_access";

        tracing::info!(
            resource_type = resource_type,
            resource = resource,
            permission = permission,
            reason = reason,
            "LLM requesting elevated access"
        );

        // Submit the request through the confirm system.
        let result = crate::confirm::server::request_confirmation(
            &self.confirm_state,
            &format!("request_access ({reason})"),
            resource,
            &perm_display,
            key_name,
            connection_id,
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
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "✓ Access APPROVED by admin.\n\
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
                            "✗ Access DENIED by admin.\n\
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
