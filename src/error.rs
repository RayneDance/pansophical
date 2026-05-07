use thiserror::Error;

/// Top-level error type for the Pansophical server.
///
/// Each module defines its own error variants; this enum aggregates them
/// at the binary boundary for CLI exit codes and structured logging.
#[derive(Debug, Error)]
#[allow(dead_code)]   // Variants are used progressively across implementation phases.
pub enum PansophicalError {
    // ── Config ────────────────────────────────────────────────────────
    #[error("configuration error: {0}")]
    Config(String),

    #[error("config file not found: {path}")]
    ConfigNotFound { path: String },

    #[error("config validation failed: {0}")]
    ConfigValidation(String),

    // ── IO ────────────────────────────────────────────────────────────
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    // ── Authz ─────────────────────────────────────────────────────────
    #[error("authorization error: {0}")]
    Authz(String),

    // ── Transport ─────────────────────────────────────────────────────
    #[error("transport error: {0}")]
    Transport(String),

    // ── Tool ──────────────────────────────────────────────────────────
    #[error("tool error: {0}")]
    Tool(String),

    // ── Generic ───────────────────────────────────────────────────────
    #[error("{0}")]
    Other(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, PansophicalError>;
