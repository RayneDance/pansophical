//! Session state: connection ID, resolved key, session approvals cache.

use uuid::Uuid;

/// A single MCP session bound to a connection (stdio pipe or SSE stream).
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique connection identifier. Auto-generated per connection.
    pub connection_id: String,
    /// Resolved key name (from config). Empty string for anonymous.
    pub key_name: String,
    /// The raw token used to authenticate.
    pub token: String,
    /// Lifecycle state.
    pub state: crate::protocol::lifecycle::LifecycleState,
}

impl Session {
    /// Create a new session in the AwaitingInit state.
    pub fn new() -> Self {
        Self {
            connection_id: Uuid::new_v4().to_string(),
            key_name: String::new(),
            token: String::new(),
            state: crate::protocol::lifecycle::LifecycleState::AwaitingInit,
        }
    }

    /// Bind the session to a resolved key after successful initialization.
    pub fn bind(&mut self, key_name: String, token: String) {
        self.key_name = key_name;
        self.token = token;
        self.state = crate::protocol::lifecycle::LifecycleState::Initialized;
    }

    /// Transition to Ready state after `initialized` notification.
    pub fn mark_ready(&mut self) {
        self.state = crate::protocol::lifecycle::LifecycleState::Ready;
    }
}
