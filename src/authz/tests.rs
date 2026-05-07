//! Authorization integration tests.
//!
//! Tests the full evaluate() pipeline: deny-before-grant, intersection math,
//! path traversal, case sensitivity, registry normalization, explain mode.

use crate::authz::{evaluate, AccessRequest, AuthzDecision};
use crate::config::perm::Perm;
use crate::config::policy_target::{Effect, PolicyRule, PolicyTargetType};
use crate::config::schema::KeyConfig;

/// Helper: build a key config with the given rules.
fn key_with_rules(rules: Vec<PolicyRule>) -> KeyConfig {
    KeyConfig {
        token: "test_token".into(),
        rules,
        limits: None,
    }
}

/// Helper: build a filesystem grant rule.
fn fs_grant(path: &str, perm: Perm) -> PolicyRule {
    PolicyRule {
        effect: Effect::Grant,
        target_type: PolicyTargetType::Filesystem,
        path: Some(path.into()),
        perm: Some(perm),
        confirm: false,
        executable: None,
        host: None,
        ports: None,
        protocol: None,
        url_pattern: None,
        var_pattern: None,
        name_pattern: None,
        name: None,
    }
}

/// Helper: build a filesystem deny rule.
fn fs_deny(path: &str, perm: Perm) -> PolicyRule {
    PolicyRule {
        effect: Effect::Deny,
        target_type: PolicyTargetType::Filesystem,
        path: Some(path.into()),
        perm: Some(perm),
        confirm: false,
        executable: None,
        host: None,
        ports: None,
        protocol: None,
        url_pattern: None,
        var_pattern: None,
        name_pattern: None,
        name: None,
    }
}

/// Helper: build a tool grant rule.
fn tool_grant(name: &str) -> PolicyRule {
    PolicyRule {
        effect: Effect::Grant,
        target_type: PolicyTargetType::Tool,
        name: Some(name.into()),
        perm: None,
        confirm: false,
        path: None,
        executable: None,
        host: None,
        ports: None,
        protocol: None,
        url_pattern: None,
        var_pattern: None,
        name_pattern: None,
    }
}

/// Helper: build a confirm-requiring filesystem grant.
fn fs_grant_confirm(path: &str, perm: Perm) -> PolicyRule {
    let mut rule = fs_grant(path, perm);
    rule.confirm = true;
    rule
}

// ── Intersection math ─────────────────────────────────────────────────────

#[test]
fn intersection_tool_asks_rw_key_grants_r_actual_is_r() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/workspace/main.rs", Perm::READ | Perm::WRITE),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Denied { .. } => {} // expected: rw not covered by r
        AuthzDecision::Granted { .. } => panic!("should be denied: key only grants r"),
    }
}

#[test]
fn intersection_tool_asks_r_key_grants_rw_actual_is_r() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ | Perm::WRITE),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/workspace/main.rs", Perm::READ),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Granted { grants, .. } => {
            assert_eq!(grants[0].actual_perm, Perm::READ);
        }
        AuthzDecision::Denied { .. } => panic!("should be granted"),
    }
}

// ── Subset check ──────────────────────────────────────────────────────────

#[test]
fn subset_check_specific_path_in_wildcard_grant() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ | Perm::WRITE),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/workspace/src/main.rs", Perm::READ),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Granted { grants, .. } => {
            // Actual should be r (the request), not rw (the grant).
            assert_eq!(grants[0].actual_perm, Perm::READ);
        }
        AuthzDecision::Denied { .. } => panic!("should be granted"),
    }
}

// ── Deny always wins ─────────────────────────────────────────────────────

#[test]
fn deny_wins_over_grant_on_same_path() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ | Perm::WRITE),
        fs_deny("/workspace/.git/**", Perm::WRITE),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/workspace/.git/config", Perm::WRITE),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Denied { .. } => {} // expected
        AuthzDecision::Granted { .. } => panic!("deny should win over grant"),
    }
}

#[test]
fn deny_does_not_block_read_when_only_write_denied() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ | Perm::WRITE),
        fs_deny("/workspace/.git/**", Perm::WRITE),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/workspace/.git/config", Perm::READ),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Granted { grants, .. } => {
            assert_eq!(grants[0].actual_perm, Perm::READ);
        }
        AuthzDecision::Denied { .. } => panic!("read should be allowed"),
    }
}

// ── Path outside grants ──────────────────────────────────────────────────

#[test]
fn path_outside_grants_denied() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/etc/passwd", Perm::READ),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Denied { .. } => {} // expected
        AuthzDecision::Granted { .. } => panic!("path outside workspace should be denied"),
    }
}

// ── No matching tool grant ───────────────────────────────────────────────

#[test]
fn no_tool_grant_denied() {
    let key = key_with_rules(vec![
        // No tool grant at all
        fs_grant("/workspace/**", Perm::READ),
    ]);
    let requests = vec![
        AccessRequest::tool("read_file"),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Denied { .. } => {} // expected
        AuthzDecision::Granted { .. } => panic!("should be denied: no tool grant"),
    }
}

#[test]
fn wildcard_tool_grant() {
    let key = key_with_rules(vec![
        tool_grant("*"),
    ]);
    let requests = vec![
        AccessRequest::tool("any_tool"),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Granted { .. } => {} // expected
        AuthzDecision::Denied { .. } => panic!("wildcard tool grant should match"),
    }
}

// ── Unknown key (tested at config level) ─────────────────────────────────

#[test]
fn key_resolution() {
    use crate::config::schema::Config;

    let toml_str = r#"
[server]
server_secret = "test"

[keys.my_agent]
token = "sk_test_123"

[[keys.my_agent.rules]]
effect = "grant"
type   = "tool"
name   = "*"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(config.resolve_key("sk_test_123").is_some());
    assert!(config.resolve_key("unknown_token").is_none());
}

// ── Explain mode (dev_mode) ──────────────────────────────────────────────

#[test]
fn explain_mode_returns_diff_on_denial() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/etc/hosts", Perm::WRITE),
    ];

    match evaluate(&requests, &key, true) {
        AuthzDecision::Denied { explain } => {
            let diff = explain.expect("explain should be Some in dev_mode");
            assert_eq!(diff.denied.len(), 1);
            assert_eq!(diff.denied[0].resource, "/etc/hosts");
            assert!(diff.denied[0].reason.contains("no matching grant"));
        }
        AuthzDecision::Granted { .. } => panic!("should be denied"),
    }
}

#[test]
fn no_explain_in_production_mode() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/etc/hosts", Perm::WRITE),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Denied { explain } => {
            assert!(explain.is_none(), "explain should be None when dev_mode=false");
        }
        AuthzDecision::Granted { .. } => panic!("should be denied"),
    }
}

// ── Confirm flag ─────────────────────────────────────────────────────────

#[test]
fn confirm_flag_propagated() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant_confirm("/workspace/**", Perm::WRITE),
    ]);
    let requests = vec![
        AccessRequest::filesystem("/workspace/main.rs", Perm::WRITE),
    ];

    match evaluate(&requests, &key, false) {
        AuthzDecision::Granted { requires_confirm, .. } => {
            assert!(requires_confirm, "confirm flag should be propagated");
        }
        AuthzDecision::Denied { .. } => panic!("should be granted"),
    }
}

// ── Multiple requests: partial denial ────────────────────────────────────

#[test]
fn partial_denial_denies_all() {
    let key = key_with_rules(vec![
        tool_grant("*"),
        fs_grant("/workspace/**", Perm::READ | Perm::WRITE),
    ]);
    // First request: ok. Second request: denied (outside workspace).
    let requests = vec![
        AccessRequest::filesystem("/workspace/main.rs", Perm::READ),
        AccessRequest::filesystem("/etc/shadow", Perm::READ),
    ];

    match evaluate(&requests, &key, true) {
        AuthzDecision::Denied { explain } => {
            let diff = explain.unwrap();
            assert_eq!(diff.denied.len(), 1);
            assert_eq!(diff.granted.len(), 1);
        }
        AuthzDecision::Granted { .. } => panic!("should be denied: /etc/shadow is outside grants"),
    }
}
