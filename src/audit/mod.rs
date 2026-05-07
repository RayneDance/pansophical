//! Audit log writer. Supports file (O_APPEND), stdout, and syslog outputs.
//! Writes one JSON line per authorization decision.

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use tracing::{error, warn};

use crate::config::schema::AuditConfig;

/// The audit log writer. Thread-safe via internal Mutex.
pub struct AuditLog {
    inner: Mutex<AuditInner>,
    /// Path to the audit log file (if file backend).
    path: Option<String>,
}

enum AuditInner {
    File(File),
    Stdout,
    Disabled,
}

/// A single audit log entry. One per authz decision.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// ISO 8601 timestamp.
    pub ts: String,
    /// Connection identifier.
    pub connection_id: String,
    /// Resolved key name.
    pub key: String,
    /// Tool name (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// What the tool requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_requests: Option<Value>,
    /// What was actually granted (intersection result).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_grant: Option<Value>,
    /// The authz decision: "granted", "denied", "confirmed", "confirm_denied", "error".
    pub decision: String,
    /// The final outcome: "success", "error", "timeout", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Extra context (e.g., error message, tool output summary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Event type for non-authz events (e.g., "reload", "reattach", "shutdown").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry with the current timestamp.
    pub fn new(connection_id: &str, key: &str) -> Self {
        Self {
            ts: Utc::now().to_rfc3339(),
            connection_id: connection_id.to_string(),
            key: key.to_string(),
            tool: None,
            access_requests: None,
            actual_grant: None,
            decision: String::new(),
            outcome: None,
            detail: None,
            event: None,
        }
    }

    /// Set the tool name.
    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    /// Set the decision.
    pub fn with_decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = decision.into();
        self
    }

    /// Set the outcome.
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    /// Set the detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Set access requests (serialized from AccessRequest vec).
    pub fn with_access_requests(mut self, requests: Value) -> Self {
        self.access_requests = Some(requests);
        self
    }

    /// Set actual grant (serialized from GrantResult vec).
    pub fn with_actual_grant(mut self, grant: Value) -> Self {
        self.actual_grant = Some(grant);
        self
    }

    /// Set event type for non-authz events.
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }
}

impl AuditLog {
    /// Open or create the audit log based on config.
    pub fn new(config: &AuditConfig) -> Self {
        if !config.enabled {
            return Self {
                inner: Mutex::new(AuditInner::Disabled),
                path: None,
            };
        }

        let (inner, path) = match config.output.as_str() {
            "stdout" => (AuditInner::Stdout, None),
            "file" => {
                match OpenOptions::new()
                    .create(true)
                    .append(true) // O_APPEND: integrity — can't truncate
                    .open(&config.path)
                {
                    Ok(f) => (AuditInner::File(f), Some(config.path.clone())),
                    Err(e) => {
                        error!("Failed to open audit log '{}': {e}", config.path);
                        error!("Falling back to disabled audit log");
                        (AuditInner::Disabled, None)
                    }
                }
            }
            "syslog" => {
                warn!("Syslog output not yet implemented; falling back to disabled");
                (AuditInner::Disabled, None)
            }
            other => {
                error!("Unknown audit output: '{other}'; falling back to disabled");
                (AuditInner::Disabled, None)
            }
        };

        Self {
            inner: Mutex::new(inner),
            path,
        }
    }

    /// Write an audit entry.
    pub fn log(&self, entry: &AuditEntry) {
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                error!("Failed to serialize audit entry: {e}");
                return;
            }
        };

        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Audit log mutex poisoned: {e}");
                return;
            }
        };

        match &mut *inner {
            AuditInner::File(f) => {
                if let Err(e) = writeln!(f, "{json}") {
                    error!("Failed to write audit entry: {e}");
                }
            }
            AuditInner::Stdout => {
                // Write to stderr when transport is stdio (stdout is JSON-RPC).
                // The config validator rejects output="stdout" with transport="stdio",
                // but as defense-in-depth, we use eprintln here.
                eprintln!("{json}");
            }
            AuditInner::Disabled => {
                // No-op.
            }
        }
    }

    /// Log a server lifecycle event (not an authz decision).
    pub fn log_event(&self, event: &str, detail: &str) {
        let entry = AuditEntry::new("server", "system")
            .with_event(event)
            .with_decision("n/a")
            .with_detail(detail);
        self.log(&entry);
    }

    /// Read the last `n` entries from the audit log file.
    /// Returns parsed JSON values for the dashboard API.
    pub fn read_recent(&self, n: usize) -> Vec<Value> {
        let path = match &self.path {
            Some(p) => p,
            None => return vec![],
        };

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        content
            .lines()
            .rev()
            .take(n)
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect::<Vec<Value>>()
            .into_iter()
            .rev()
            .collect()
    }
}
