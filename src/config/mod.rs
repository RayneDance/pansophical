//! Configuration loading, parsing, validation, and hot reload.

pub mod schema;
pub mod perm;
pub mod policy_target;

use std::path::Path;

use crate::error::{PansophicalError, Result};
use schema::Config;

impl Config {
    /// Load and validate config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the loaded config. Returns a descriptive error on failure.
    pub fn validate(&self) -> Result<()> {
        // Transport validation.
        match self.server.transport.as_str() {
            "stdio" | "http" | "both" => {}
            other => {
                return Err(PansophicalError::ConfigValidation(format!(
                    "unknown transport: \"{other}\". Expected \"stdio\", \"http\", or \"both\"."
                )));
            }
        }

        // Audit/stdio conflict: stdout audit is forbidden with stdio transport.
        if self.server.transport == "stdio" && self.audit.output == "stdout" {
            return Err(PansophicalError::ConfigValidation(
                "audit.output = \"stdout\" is forbidden when transport = \"stdio\" \
                 (would corrupt JSON-RPC channel). Use \"file\" or \"syslog\"."
                    .into(),
            ));
        }

        // On-disconnect validation.
        match self.server.http.on_disconnect.as_str() {
            "kill" | "detach" => {}
            other => {
                return Err(PansophicalError::ConfigValidation(format!(
                    "unknown on_disconnect: \"{other}\". Expected \"kill\" or \"detach\"."
                )));
            }
        }

        // Validate all key rules.
        for (key_name, key_config) in &self.keys {
            for (i, rule) in key_config.rules.iter().enumerate() {
                rule.validate().map_err(|e| {
                    PansophicalError::ConfigValidation(format!(
                        "key \"{key_name}\", rule {}: {e}",
                        i + 1
                    ))
                })?;
            }
        }

        // Auto-open validation.
        match self.ui.auto_open.as_str() {
            "startup" | "confirm" | "never" => {}
            other => {
                return Err(PansophicalError::ConfigValidation(format!(
                    "unknown auto_open: \"{other}\". Expected \"startup\", \"confirm\", or \"never\"."
                )));
            }
        }

        // Sandbox strategy validation.
        match self.sandbox.strategy.as_str() {
            "auto" | "landlock" | "app_container" => {}
            other => {
                return Err(PansophicalError::ConfigValidation(format!(
                    "unknown sandbox strategy: \"{other}\". Expected \"auto\", \"landlock\", or \"app_container\"."
                )));
            }
        }

        Ok(())
    }

    /// Resolve a bearer token to a key name and its config.
    pub fn resolve_key(&self, token: &str) -> Option<(&str, &schema::KeyConfig)> {
        for (name, key_config) in &self.keys {
            if key_config.token == token {
                return Some((name, key_config));
            }
        }
        None
    }
}
