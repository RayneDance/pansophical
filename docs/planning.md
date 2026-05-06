# Pansophical — MCP Server Planning Doc

## What It Is

A **local MCP (Model Context Protocol) server** written in Rust that:
- Exposes modular **utilities** (tools) to AI agents
- Guards every tool invocation with a **key-based authorization check**
- Stores authorization policy in a **TOML config file**

---

## Key & Signing Model

Each agent caller is identified by a **named key**. When a request comes in:

1. The agent presents its key (e.g., a static token, or an HMAC-signed request)
2. The server resolves the key to a policy
3. The policy is checked against the **resource type + resource value** the tool would access
4. If authorized → execute; if not → return a structured denial

**Key design questions:**
- Static bearer token vs. request-level HMAC signing (signing is stronger — prevents replay of intercepted requests)
- Ed25519 keypair per agent would be the gold standard (agent signs, server verifies with stored pubkey)
- Start with: static token for simplicity, graduate to HMAC or Ed25519 later

---

## Authorization Resource Types

Each key has a list of grants, each grant is a **resource type + resource pattern + allowed operations**.

### 1. `filesystem`
Path glob(s) + allowed operations.
```toml
[[keys.my_agent.grants]]
type = "filesystem"
path = "/home/user/project/**"
ops = ["read", "write", "list"]
# NOT "delete" — agent can't rm things
```
Operations: `read`, `write`, `delete`, `list`, `create`

---

### 2. `program`
Which executables the key can invoke. Can optionally restrict argument patterns.
```toml
[[keys.my_agent.grants]]
type = "program"
executable = "git"
args_pattern = "*"   # glob or regex on the full arg string
```
Operations: `execute`

Possible refinements: `allow_shell = false` to block shell expansion, `env_passthrough = ["GIT_*"]`

---

### 3. `network`
Host/IP + port + protocol access for tools that make outbound connections.
```toml
[[keys.my_agent.grants]]
type = "network"
host = "api.github.com"
ports = [443]
protocol = "https"
```
Operations: `connect`, `send`, `receive`

---

### 4. `http`
More granular than network — specifies URL patterns and HTTP methods.
```toml
[[keys.my_agent.grants]]
type = "http"
url_pattern = "https://api.github.com/repos/**"
methods = ["GET", "POST"]
```

---

### 5. `environment`
Which environment variables can be read or injected into spawned processes.
```toml
[[keys.my_agent.grants]]
type = "environment"
var_pattern = "MY_APP_*"
ops = ["read"]
```
Operations: `read`, `write` (write = can set in child process env)

---

### 6. `process`
Signal/kill permissions for processes by name or PID range.
```toml
[[keys.my_agent.grants]]
type = "process"
name_pattern = "my_service*"
ops = ["signal", "kill"]
```

---

### 7. `tool`
Meta-authorization — which MCP tools the key is even allowed to call, before resource checks happen. Acts as a coarse filter.
```toml
[[keys.my_agent.grants]]
type = "tool"
name = "shell_exec"   # or "*" for all tools
```
This is the first gate. If a key lacks a `tool` grant for `shell_exec`, the server rejects before inspecting the args at all.

---

### 8. `secret`
Named credentials or secrets that tools can retrieve (e.g., API keys stored server-side).
```toml
[[keys.my_agent.grants]]
type = "secret"
name = "github_pat"
ops = ["read"]
```

---

### 9. `registry` *(Windows-specific)*
Registry key path patterns for tools that read/write the Windows registry.
```toml
[[keys.my_agent.grants]]
type = "registry"
path = "HKCU\\Software\\MyApp\\**"
ops = ["read"]
```

---

## TOML Config Structure

```toml
[server]
host = "127.0.0.1"
port = 3000

# -- Keys --

[keys.ci_agent]
description = "Runs in GitHub Actions"
# Static token (phase 1). Later: pubkey for signing.
token = "sk_live_abc123..."

  [[keys.ci_agent.grants]]
  type = "tool"
  name = "*"

  [[keys.ci_agent.grants]]
  type = "filesystem"
  path = "/workspace/**"
  ops = ["read", "write", "create"]

  [[keys.ci_agent.grants]]
  type = "program"
  executable = "cargo"
  args_pattern = "build*"

[keys.read_only_agent]
description = "Read-only observer"
token = "sk_live_xyz789..."

  [[keys.read_only_agent.grants]]
  type = "tool"
  name = "read_file"

  [[keys.read_only_agent.grants]]
  type = "filesystem"
  path = "/workspace/**"
  ops = ["read", "list"]
```

---

## Utility Plugin Architecture

Each utility (tool) is a Rust module implementing a common trait:

```rust
pub trait McpTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn schema(&self) -> serde_json::Value;  // JSON Schema for args
    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &RequestContext,   // contains resolved key + policy
    ) -> Result<serde_json::Value, ToolError>;
}
```

The server registry holds a `Vec<Box<dyn McpTool>>`. Adding a new utility = implement the trait, register in `main.rs`. No macros or codegen needed to start.

---

## Request Lifecycle

```
Agent request (tool_name + args + key_token)
        |
        v
1. Resolve key -> policy          [auth layer]
2. Check tool grant               [coarse gate]
3. Tool::execute() called
4.   |- Tool inspects args
5.   |- Tool calls authz::check(resource_type, resource_value, op, &policy)
6.   `- If denied -> ToolError::Unauthorized
        |
        v
Response (result or structured error)
```

---

## Open Questions

- [ ] **Signing scheme**: static token (simple) vs. HMAC-per-request vs. Ed25519?
- [ ] **Pattern matching**: glob (globset crate) vs. regex for paths/args?
- [ ] **Deny lists**: should we support explicit `deny` rules that override grants?
- [ ] **Audit log**: every authorization decision logged to file/stdout?
- [ ] **Hot reload**: should the TOML config reload on change without restart?
- [ ] **MCP transport**: stdio (standard for local MCP) or HTTP/SSE?
- [ ] **First batch of utilities**: shell_exec, read_file, write_file, http_fetch, search_files?
