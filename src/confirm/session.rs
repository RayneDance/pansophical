//! Session approval cache.
//!
//! When a user approves with scope "session" or "minutes:N",
//! that approval is cached here to skip re-confirmation on identical requests.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Key for the approval cache.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ApprovalKey {
    pub connection_id: String,
    pub key_name: String,
    pub tool_name: String,
    pub resource_pattern: String,
    pub perm: String,
}

/// A cached approval with its expiry.
#[derive(Debug, Clone)]
struct CachedApproval {
    approved_at: Instant,
    ttl: Duration,
}

/// The approval cache. Thread-safe via Mutex.
pub struct ApprovalCache {
    entries: Mutex<HashMap<ApprovalKey, CachedApproval>>,
}

/// Approval scope parsed from the user's response.
#[derive(Debug, Clone)]
pub enum ApprovalScope {
    /// Single use — not cached.
    Once,
    /// Cached for N minutes.
    Minutes(u64),
    /// Cached for the session (24 hours max).
    Session,
}

impl ApprovalScope {
    /// Parse from string: "once", "minutes:N", "session".
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "once" => Ok(Self::Once),
            "session" => Ok(Self::Session),
            s if s.starts_with("minutes:") => {
                let n: u64 = s[8..]
                    .parse()
                    .map_err(|_| format!("invalid minutes value: '{}'", &s[8..]))?;
                if n == 0 || n > 1440 {
                    return Err("minutes must be 1-1440".into());
                }
                Ok(Self::Minutes(n))
            }
            _ => Err(format!("unknown approval scope: '{s}'")),
        }
    }

    /// Convert to a TTL duration.
    pub fn ttl(&self) -> Option<Duration> {
        match self {
            Self::Once => None,
            Self::Minutes(n) => Some(Duration::from_secs(n * 60)),
            Self::Session => Some(Duration::from_secs(24 * 60 * 60)),
        }
    }
}

impl ApprovalCache {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Check if there's a valid cached approval for this key.
    pub fn check(&self, key: &ApprovalKey) -> bool {
        let entries = self.entries.lock().unwrap();
        if let Some(approval) = entries.get(key) {
            approval.approved_at.elapsed() < approval.ttl
        } else {
            false
        }
    }

    /// Cache an approval.
    pub fn approve(&self, key: ApprovalKey, scope: &ApprovalScope) {
        if let Some(ttl) = scope.ttl() {
            let mut entries = self.entries.lock().unwrap();
            entries.insert(
                key,
                CachedApproval {
                    approved_at: Instant::now(),
                    ttl,
                },
            );
        }
        // "once" scope: don't cache.
    }

    /// Clear all approvals for a connection (e.g., on disconnect).
    pub fn clear_connection(&self, connection_id: &str) {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|k, _| k.connection_id != connection_id);
    }

    /// Clear all approvals (e.g., on config reload).
    pub fn clear_all(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }

    /// Sweep expired entries. Called periodically by a background task.
    pub fn sweep_expired(&self) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|_, v| v.approved_at.elapsed() < v.ttl);
        before - entries.len()
    }

    /// List all active (non-expired) grants.
    pub fn list_active(&self) -> Vec<(ApprovalKey, u64)> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|(_, v)| v.approved_at.elapsed() < v.ttl)
            .map(|(k, v)| {
                let remaining = v.ttl.saturating_sub(v.approved_at.elapsed()).as_secs();
                (k.clone(), remaining)
            })
            .collect()
    }

    /// Remove a specific grant by key fields.
    pub fn remove(&self, tool: &str, resource: &str, perm: &str) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|k, _| {
            !(k.tool_name == tool && k.resource_pattern == resource && k.perm == perm)
        });
        entries.len() < before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> ApprovalKey {
        ApprovalKey {
            connection_id: "conn-1".into(),
            key_name: "ci".into(),
            tool_name: "write_file".into(),
            resource_pattern: "/workspace/**".into(),
            perm: "w".into(),
        }
    }

    #[test]
    fn once_not_cached() {
        let cache = ApprovalCache::new();
        let key = test_key();
        cache.approve(key.clone(), &ApprovalScope::Once);
        assert!(!cache.check(&key));
    }

    #[test]
    fn minutes_cached() {
        let cache = ApprovalCache::new();
        let key = test_key();
        cache.approve(key.clone(), &ApprovalScope::Minutes(5));
        assert!(cache.check(&key));
    }

    #[test]
    fn session_cached() {
        let cache = ApprovalCache::new();
        let key = test_key();
        cache.approve(key.clone(), &ApprovalScope::Session);
        assert!(cache.check(&key));
    }

    #[test]
    fn clear_connection() {
        let cache = ApprovalCache::new();
        let key = test_key();
        cache.approve(key.clone(), &ApprovalScope::Session);
        assert!(cache.check(&key));

        cache.clear_connection("conn-1");
        assert!(!cache.check(&key));
    }

    #[test]
    fn clear_all() {
        let cache = ApprovalCache::new();
        let key = test_key();
        cache.approve(key.clone(), &ApprovalScope::Session);
        cache.clear_all();
        assert!(!cache.check(&key));
    }

    #[test]
    fn scope_parse() {
        assert!(matches!(ApprovalScope::parse("once"), Ok(ApprovalScope::Once)));
        assert!(matches!(ApprovalScope::parse("session"), Ok(ApprovalScope::Session)));
        assert!(matches!(ApprovalScope::parse("minutes:5"), Ok(ApprovalScope::Minutes(5))));
        assert!(ApprovalScope::parse("minutes:0").is_err());
        assert!(ApprovalScope::parse("minutes:9999").is_err());
        assert!(ApprovalScope::parse("garbage").is_err());
    }
}
