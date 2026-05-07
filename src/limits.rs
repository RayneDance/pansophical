//! Rate limiter (token bucket per key) and concurrency gate.
//!
//! Enforces `max_invocations_per_minute`, `max_concurrent_tools`,
//! and `max_output_bytes` (pipe monitoring).
