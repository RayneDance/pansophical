//! Rate limiter (token bucket per key) and concurrency gate.
//!
//! Enforces `max_invocations_per_minute`, `max_concurrent_tools`,
//! and `max_output_bytes` (pipe monitoring).
//!
//! TODO: Wire into transport layer (stdio.rs / http.rs) — the limiter is
//! fully implemented and tested but not yet called from the tool execution
//! path. Integration point: between AuthzDecision::Granted and execute_tool().

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::config::schema::LimitsConfig;

/// Shared rate limiter / concurrency gate state.
pub struct Limiter {
    /// Per-key rate limit state. Protected by Mutex for HashMap access;
    /// internals use atomics for hot-path contention reduction.
    per_key: Mutex<HashMap<String, Arc<KeyLimits>>>,
    /// Default limits from config.
    defaults: LimitsConfig,
}

/// Per-key limits state.
pub struct KeyLimits {
    /// Token bucket: tokens remaining in the current window.
    tokens: AtomicU32,
    /// Start of the current rate limit window.
    window_start: Mutex<Instant>,
    /// Max tokens per window (from config).
    max_rate: u32,
    /// Current concurrent tool count. Shared with ConcurrencyGuards.
    concurrent: Arc<AtomicU32>,
    /// Max concurrent tools allowed.
    max_concurrent: u32,
    /// Max output bytes per invocation.
    max_output_bytes: u64,
}

/// Result of a rate/concurrency check.
#[derive(Debug)]
pub enum LimitCheck {
    /// Allowed. Returns a guard that decrements the concurrent count on drop.
    Allowed(ConcurrencyGuard),
    /// Rate limited.
    RateLimited {
        #[allow(dead_code)]
        retry_after_secs: u64,
    },
    /// Concurrency limit exceeded.
    ConcurrencyExceeded {
        #[allow(dead_code)]
        current: u32,
        max: u32,
    },
}

/// RAII guard that decrements the concurrent tool count when dropped.
pub struct ConcurrencyGuard {
    concurrent: Arc<AtomicU32>,
    max_output_bytes: u64,
    /// Running output byte counter for pipe monitoring.
    pub output_bytes: AtomicU64,
}

impl std::fmt::Debug for ConcurrencyGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrencyGuard")
            .field("max_output_bytes", &self.max_output_bytes)
            .field("output_bytes", &self.output_bytes.load(Ordering::Relaxed))
            .finish()
    }
}

impl ConcurrencyGuard {
    /// Check if the output byte limit has been exceeded.
    pub fn output_exceeded(&self) -> bool {
        self.output_bytes.load(Ordering::Relaxed) > self.max_output_bytes
    }

    /// Add bytes to the output counter. Returns true if limit exceeded.
    pub fn add_output_bytes(&self, n: u64) -> bool {
        let new = self.output_bytes.fetch_add(n, Ordering::Relaxed) + n;
        new > self.max_output_bytes
    }

    /// Get the max output bytes limit.
    #[allow(dead_code)]
    pub fn max_output_bytes(&self) -> u64 {
        self.max_output_bytes
    }
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        self.concurrent.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Limiter {
    /// Create a new limiter with the given default limits.
    pub fn new(defaults: &LimitsConfig) -> Self {
        Self {
            per_key: Mutex::new(HashMap::new()),
            defaults: defaults.clone(),
        }
    }

    /// Check rate and concurrency limits for a key.
    ///
    /// If allowed, returns `LimitCheck::Allowed` with a concurrency guard.
    /// The caller MUST hold the guard for the duration of the tool invocation.
    pub fn check(&self, key_name: &str, overrides: Option<&LimitsConfig>) -> LimitCheck {
        let limits = self.get_or_create(key_name, overrides);

        // Check rate limit (token bucket).
        {
            let mut window_start = limits.window_start.lock().unwrap();
            let elapsed = window_start.elapsed();
            if elapsed.as_secs() >= 60 {
                // Reset window.
                *window_start = Instant::now();
                limits.tokens.store(limits.max_rate, Ordering::Relaxed);
            }

            let current = limits.tokens.load(Ordering::Relaxed);
            if current == 0 {
                let remaining = 60 - elapsed.as_secs();
                return LimitCheck::RateLimited {
                    retry_after_secs: remaining,
                };
            }
            limits.tokens.fetch_sub(1, Ordering::Relaxed);
        }

        // Check concurrency limit.
        let current = limits.concurrent.load(Ordering::Relaxed);
        if current >= limits.max_concurrent {
            return LimitCheck::ConcurrencyExceeded {
                current,
                max: limits.max_concurrent,
            };
        }
        limits.concurrent.fetch_add(1, Ordering::Relaxed);

        LimitCheck::Allowed(ConcurrencyGuard {
            concurrent: Arc::clone(&limits.concurrent),
            max_output_bytes: limits.max_output_bytes,
            output_bytes: AtomicU64::new(0),
        })
    }

    /// Get or create per-key limits.
    fn get_or_create(&self, key_name: &str, overrides: Option<&LimitsConfig>) -> Arc<KeyLimits> {
        let mut map = self.per_key.lock().unwrap();

        if let Some(existing) = map.get(key_name) {
            return Arc::clone(existing);
        }

        let config = overrides.unwrap_or(&self.defaults);
        let limits = Arc::new(KeyLimits {
            tokens: AtomicU32::new(config.max_invocations_per_minute),
            window_start: Mutex::new(Instant::now()),
            max_rate: config.max_invocations_per_minute,
            concurrent: Arc::new(AtomicU32::new(0)),
            max_concurrent: config.max_concurrent_tools,
            max_output_bytes: config.max_output_bytes,
        });

        map.insert(key_name.to_string(), Arc::clone(&limits));
        limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limits() -> LimitsConfig {
        LimitsConfig {
            max_invocations_per_minute: 3,
            max_concurrent_tools: 2,
            tool_timeout_secs: 30,
            max_output_bytes: 1024,
        }
    }

    #[test]
    fn allows_within_rate() {
        let limiter = Limiter::new(&test_limits());
        for _ in 0..3 {
            match limiter.check("test_key", None) {
                LimitCheck::Allowed(_) => {}
                other => panic!("expected Allowed, got {other:?}"),
            }
        }
    }

    #[test]
    fn rate_limit_exceeded() {
        let limiter = Limiter::new(&test_limits());
        for _ in 0..3 {
            let _guard = limiter.check("test_key", None);
        }
        match limiter.check("test_key", None) {
            LimitCheck::RateLimited { .. } => {}
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn concurrency_limit_exceeded() {
        let limiter = Limiter::new(&test_limits());
        // Hold two guards to hit the limit.
        let _g1 = limiter.check("test_key", None);
        let _g2 = limiter.check("test_key", None);
        match limiter.check("test_key", None) {
            LimitCheck::ConcurrencyExceeded { max, .. } => {
                assert_eq!(max, 2);
            }
            other => panic!("expected ConcurrencyExceeded, got {other:?}"),
        }
    }

    #[test]
    fn output_byte_tracking() {
        let limiter = Limiter::new(&test_limits());
        match limiter.check("test_key", None) {
            LimitCheck::Allowed(guard) => {
                assert!(!guard.output_exceeded());
                assert!(!guard.add_output_bytes(512));
                assert!(!guard.output_exceeded());
                assert!(guard.add_output_bytes(600));
                assert!(guard.output_exceeded());
            }
            _ => panic!("expected Allowed"),
        }
    }

    #[test]
    fn different_keys_independent() {
        let limiter = Limiter::new(&test_limits());
        for _ in 0..3 {
            let _guard = limiter.check("key_a", None);
        }
        // key_a is rate-limited, but key_b should be fine.
        match limiter.check("key_a", None) {
            LimitCheck::RateLimited { .. } => {}
            _ => panic!("key_a should be rate limited"),
        }
        match limiter.check("key_b", None) {
            LimitCheck::Allowed(_) => {}
            _ => panic!("key_b should be allowed"),
        }
    }
}
