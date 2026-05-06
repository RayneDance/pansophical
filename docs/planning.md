# Pansophical — MCP Server Planning Doc

## What It Is

A **local MCP (Model Context Protocol) server** written in Rust that:
- Exposes modular **utilities** (tools) to AI agents
- Guards every tool invocation with a **key-based authorization check**
- Stores authorization policy in a **TOML config file**

---

## Decided: Design Questions

| Question | Decision |
|---|---|
| Signing scheme | Static bearer token to start |
| Deny lists | Yes — explicit deny rules, evaluated before grants |
| Audit log | On by default; configurable and optional |
| Hot reload | Yes — validate on change, enforce only if valid |
| MCP transport | stdio (default/local) + HTTP/SSE (remote, opt-in) |
| First utilities | After framework is reviewed and stable |

---

## Key & Signing Model

Each agent caller is identified by a **named key**. When a request comes in:

1. The agent presents its key as a bearer token in the request
2. The server resolves the key to a named policy
3. The policy is evaluated against the tool and resource being requested
4. If authorized → execute; if not → return a structured denial

**Phase 1**: Static bearer token (`Authorization: Bearer <token>` over HTTP, or a header field in the stdio envelope).

**Future**: HMAC-per-request or Ed25519 keypair. The key resolution interface is designed to swap this in without changing the authorization layer.

---

## Authorization Model

### Evaluation Order

```
Request arrives
    |
    v
1. Key resolution          — unknown key → immediate reject
2. Tool grant check        — coarse gate, checked first
3. Deny rule evaluation    — any matching deny → reject (overrides grants)
4. Grant rule evaluation   — any matching grant → allow
5. Default deny            — no matching grant → reject
```

Deny rules are **evaluated before grants** and always win. This lets you do things like:
- Grant `filesystem /** read` (broad)
- Deny  `filesystem /etc/** read` (specific carve-out)

### Rule Structure

Each rule is either a `grant` or `deny`, with a resource type and associated constraints.

```toml
[[keys.my_agent.rules]]
effect = "deny"
type = "filesystem"
path = "/etc/**"
ops = ["read", "write", "delete"]

[[keys.my_agent.rules]]
effect = "grant"
type = "filesystem"
path = "/workspace/**"
ops = ["read", "write", "create"]
```

---

## Authorization Resource Types

### 1. `filesystem`
Path glob(s) + allowed operations.

Operations: `read`, `write`, `delete`, `list`, `create`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "filesystem"
path = "/home/user/project/**"
ops = ["read", "write", "list"]
```

---

### 2. `program`
Which executables the key can invoke.

Operations: `execute`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "program"
executable = "git"
```

> **See Tool Isolation section** — program authorization is only meaningful when combined with enforcement.

---

### 3. `network`
Host/IP + port + protocol for outbound connections.

Operations: `connect`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "network"
host = "api.github.com"
ports = [443]
protocol = "https"
```

---

### 4. `http`
URL patterns + HTTP methods. More granular than `network`.

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "http"
url_pattern = "https://api.github.com/repos/**"
methods = ["GET", "POST"]
```

---

### 5. `environment`
Which env vars can be read or injected into child processes.

Operations: `read`, `write`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "environment"
var_pattern = "MY_APP_*"
ops = ["read"]
```

---

### 6. `process`
Signal/kill permissions by process name pattern.

Operations: `signal`, `kill`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "process"
name_pattern = "my_service*"
ops = ["signal"]
```

---

### 7. `tool`
Meta-authorization — which MCP tools the key may call at all.
This is the **first gate**, checked before any resource rules.

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "tool"
name = "read_file"  # or "*" for all tools
```

---

### 8. `secret`
Named server-side credentials a tool may retrieve.

Operations: `read`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "secret"
name = "github_pat"
ops = ["read"]
```

---

### 9. `registry` *(Windows-specific)*
Registry key path patterns.

Operations: `read`, `write`, `delete`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type = "registry"
path = "HKCU\\Software\\MyApp\\**"
ops = ["read"]
```

---

## ⚠ The Tool Isolation Problem

This is the deepest design challenge in the project.

### The Core Tension

Authorization checks are only meaningful if the server can actually **enforce** them — not just validate arguments before execution. A tool that receives granted arguments and then does something unexpected (e.g., traverses symlinks, spawns sub-processes, makes network calls) defeats the policy.

Pattern matching on arguments is **soft enforcement**. The argument might look valid but the underlying system call might not be.

### Principle: Tools Must Be Simple and Atomic

Each tool should:
- Touch **exactly one resource type**
- Have a **fully declared resource contract** (what it will access, in what mode)
- Do **no implicit side effects** beyond its declaration

A tool like `shell_exec(cmd: String)` is fundamentally unsafe because:
- It can access any resource type
- Its resource contract is unbounded
- Arguments cannot be reliably validated before execution

Preferred model: `run_git(args: Vec<String>)` — fixed executable, declared resource types, auditable argument space.

### Tool Resource Contract (Trait Extension)

Each tool statically declares its resource footprint as part of the trait:

```rust
pub trait McpTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn schema(&self) -> serde_json::Value;

    /// Statically declare what resource types this tool may access.
    /// Used for coarse pre-registration validation and documentation.
    fn resource_types(&self) -> &[ResourceType];

    /// Given concrete args, return the exact resources this invocation
    /// will access. Called before execute(); authz checks this list.
    fn resolve_resources(
        &self,
        args: &serde_json::Value,
    ) -> Result<Vec<ResourceRequest>, ToolError>;

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<serde_json::Value, ToolError>;
}
```

`resolve_resources()` is called **before** `execute()`. The authz layer checks every `ResourceRequest` against the key's policy. If any request is denied, execution never happens.

### Enforcement Layers

**Layer 1 — Argument validation (soft, always on)**
- `resolve_resources()` extracts the concrete resources from args
- Authz evaluates each against deny/grant rules
- Insufficient for tools that can do unbounded things

**Layer 2 — OS-level sandboxing (hard, future)**
- Wrap tool execution in a restricted process environment
- Linux: `seccomp` + `namespaces` (restrict syscalls, filesystem view, network)
- Windows: Job Objects + restricted token
- This is the "virtual environment" concept — the tool process literally cannot access what it hasn't been granted, regardless of what it tries

**Current approach**: Layer 1 only. Tools are trusted Rust code in-process. The policy is enforced by the server before invoking execute(), but the tool itself is not sandboxed.

**Future**: When tools can spawn external processes (e.g., `run_git`), those processes should be spawned inside a constrained environment derived from the key's policy.

### Open Sub-Questions on Isolation

- [ ] Should tools that spawn processes always do so out-of-process with a restricted env, even in the MVP?
- [ ] How do we handle tools that need transitive resource access (e.g., `git` reading `.git/config` which references a remote)?
- [ ] Is per-tool sandboxing config (`[tools.run_git] sandbox = true`) the right knob?

---

## TOML Config Structure

```toml
[server]
host = "127.0.0.1"
port = 3000          # used when transport = "http"
transport = "stdio"  # "stdio" | "http" | "both"

[audit]
enabled = true
output = "stdout"   # "stdout" | "file"
path = "audit.log"  # used when output = "file"

# -- Keys --

[keys.ci_agent]
description = "CI pipeline agent"
token = "sk_live_abc123..."

  # Coarse gate: can call any tool
  [[keys.ci_agent.rules]]
  effect = "grant"
  type = "tool"
  name = "*"

  # Broad filesystem grant for workspace
  [[keys.ci_agent.rules]]
  effect = "grant"
  type = "filesystem"
  path = "/workspace/**"
  ops = ["read", "write", "create"]

  # Carve out: cannot touch .git internals
  [[keys.ci_agent.rules]]
  effect = "deny"
  type = "filesystem"
  path = "/workspace/.git/**"
  ops = ["write", "delete"]

  [[keys.ci_agent.rules]]
  effect = "grant"
  type = "program"
  executable = "cargo"

[keys.read_only_agent]
description = "Read-only observer"
token = "sk_live_xyz789..."

  [[keys.read_only_agent.rules]]
  effect = "grant"
  type = "tool"
  name = "read_file"

  [[keys.read_only_agent.rules]]
  effect = "grant"
  type = "filesystem"
  path = "/workspace/**"
  ops = ["read", "list"]
```

---

## Hot Reload

When the config file changes on disk:
1. Parse and validate the new config
2. If **invalid** — log a warning, keep the current config active, do not reload
3. If **valid** — atomically swap the in-memory config (`Arc<RwLock<Config>>`)
4. Log the reload event to the audit log

In-flight requests complete under the old config. New requests see the new config immediately after the swap.

---

## Transport

### stdio (default)
- JSON-RPC 2.0 messages over stdin/stdout
- Standard MCP local server pattern
- One agent per server process instance

### HTTP/SSE (opt-in)
- HTTP server for tool call requests
- Server-Sent Events for streaming responses
- Supports multiple concurrent agents
- Bearer token passed in `Authorization` header
- Enabled via `transport = "http"` or `transport = "both"` in config

---

## Utility Plugin Architecture

```rust
pub trait McpTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn schema(&self) -> serde_json::Value;
    fn resource_types(&self) -> &[ResourceType];
    fn resolve_resources(&self, args: &serde_json::Value) -> Result<Vec<ResourceRequest>, ToolError>;
    async fn execute(&self, args: serde_json::Value, ctx: &RequestContext) -> Result<serde_json::Value, ToolError>;
}
```

Adding a utility:
1. Create `src/tools/my_tool.rs`
2. Implement `McpTool`
3. Register in `src/tools/mod.rs`

No macros or codegen required.

---

## Request Lifecycle

```
Agent request (tool_name + args + bearer_token)
        |
        v
1. Key resolution                  unknown key → 401
2. tool grant check                no tool grant → 403
3. tool.resolve_resources(args)    → Vec<ResourceRequest>
4. Deny rule scan                  any deny match → 403
5. Grant rule scan                 all resources granted? → continue : 403
6. tool.execute(args, ctx)
        |
        v
Audit log entry (key, tool, resources, decision, timestamp)
        |
        v
Response
```

---

## Crate Structure (Proposed)

```
pansophical/
├── src/
│   ├── main.rs
│   ├── config/          # TOML parsing, hot reload, validation
│   ├── authz/           # Key resolution, rule evaluation (deny/grant)
│   ├── audit/           # Audit log writer
│   ├── transport/
│   │   ├── stdio.rs
│   │   └── http.rs
│   ├── tools/           # McpTool trait + registry
│   │   └── mod.rs
│   └── error.rs
├── docs/
│   └── planning.md
├── Cargo.toml
└── config.example.toml
```

---

## Deferred / Open

- [ ] Tool process sandboxing (Layer 2 enforcement) — design needed before first spawning tool
- [ ] Transitive resource access in sub-processes
- [ ] Per-tool sandbox config knob
- [ ] Signing scheme upgrade path (HMAC / Ed25519)
- [ ] First batch of utilities (post-framework review)
