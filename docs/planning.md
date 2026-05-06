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
| Permission model | Unix-style `r/w/x` bit flags |
| Tool spawning | Always out-of-process |
| Per-tool resource policy | No — "access is access" (key policy only) |
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

## Permission Model: `r/w/x` Bits

Permissions are represented as Unix-style bit flags on every resource rule.
In TOML, they are written as a compact string. Only include the bits you want to grant.

| String | Bits | Meaning |
|---|---|---|
| `"r"` | 100 | read only |
| `"w"` | 010 | write only |
| `"x"` | 001 | execute only |
| `"rw"` | 110 | read + write |
| `"rx"` | 101 | read + execute |
| `"rwx"` | 111 | all permissions |

Internally represented as a `u8` bitfield using the `bitflags!` macro.

### Semantics Per Resource Type

| Resource | `r` | `w` | `x` |
|---|---|---|---|
| `filesystem` | read content, list dir | create / write / modify / delete | traverse dir, execute file |
| `program` | capture stdout/stderr | write to stdin | spawn / execute |
| `network` | receive data | send data | open a connection |
| `http` | GET, HEAD | POST, PUT, PATCH, DELETE | — (not applicable) |
| `environment` | read var value | set var in child process | inherit var into child |
| `secret` | read value | update / rotate | inject into child process env |
| `registry` | read values | write / create / delete values | enumerate / traverse subkeys |
| `process` | read info / status | write to stdin | signal / kill |

> `tool` (meta-authorization) has no permission bits — it is grant/deny only.

---

## Authorization Model

### "Access Is Access"

The policy lives on the **key**, not on individual tools. If a key has `r` on
`/workspace/**`, then any tool may read files under that path on behalf of that
key. There is no second layer of per-tool resource policy.

Tools declare what resources they will touch for a given invocation. The authz
layer checks that list against the key's policy. If it passes, the tool runs —
in a restricted out-of-process environment derived from those same grants.

### Evaluation Order

```
Request arrives
    |
    v
1. Key resolution        — unknown key → immediate reject
2. Tool grant check      — no tool grant → reject (coarse gate)
3. resolve_resources()   — tool maps args → Vec<ResourceRequest>
4. Deny rule scan        — any deny match → reject (overrides grants)
5. Grant rule scan       — all resources covered by grants? → allow : reject
6. Spawn child process   — environment scoped to granted resources only
    |
    v
Audit log (key, tool, resources, decision, outcome, timestamp)
```

Deny rules are **evaluated before grants** and always win. This lets you do
things like:
- Grant `filesystem /workspace/**  rw`  (broad)
- Deny  `filesystem /workspace/.git/**  w`  (specific carve-out)

### Rule Structure

```toml
[[keys.my_agent.rules]]
effect = "deny"
type  = "filesystem"
path  = "/etc/**"
perm  = "rwx"

[[keys.my_agent.rules]]
effect = "grant"
type  = "filesystem"
path  = "/workspace/**"
perm  = "rw"
```

---

## Authorization Resource Types

### 1. `filesystem`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type   = "filesystem"
path   = "/home/user/project/**"
perm   = "rw"
```

Glob patterns on `path`. The `x` bit on a directory means traverse/enter;
on a file it means execute.

---

### 2. `program`

```toml
[[keys.my_agent.rules]]
effect     = "grant"
type       = "program"
executable = "git"
perm       = "x"    # can spawn; add "r" to capture output, "w" to write stdin
```

`executable` is matched against the resolved binary name (not full path).
All process spawning is out-of-process; the child's environment is derived
from the key's full set of grants.

---

### 3. `network`

```toml
[[keys.my_agent.rules]]
effect   = "grant"
type     = "network"
host     = "api.github.com"
ports    = [443]
protocol = "https"
perm     = "rw"   # r = receive, w = send, x = open connection
```

---

### 4. `http`

More granular than `network`. `r` = safe methods (GET, HEAD);
`w` = mutating methods (POST, PUT, PATCH, DELETE). `x` is not used.

```toml
[[keys.my_agent.rules]]
effect      = "grant"
type        = "http"
url_pattern = "https://api.github.com/repos/**"
perm        = "r"   # GET/HEAD only
```

---

### 5. `environment`

```toml
[[keys.my_agent.rules]]
effect      = "grant"
type        = "environment"
var_pattern = "MY_APP_*"
perm        = "rx"  # read value + inherit into child process
```

---

### 6. `process`

```toml
[[keys.my_agent.rules]]
effect       = "grant"
type         = "process"
name_pattern = "my_service*"
perm         = "rx"  # read info + signal/kill
```

---

### 7. `tool`

Meta-authorization. No permission bits — grant/deny only. This is the
**first gate**, checked before anything else.

```toml
[[keys.my_agent.rules]]
effect = "grant"
type   = "tool"
name   = "read_file"   # or "*" for all tools
```

---

### 8. `secret`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type   = "secret"
name   = "github_pat"
perm   = "r"
```

---

### 9. `registry` *(Windows-specific)*

```toml
[[keys.my_agent.rules]]
effect = "grant"
type   = "registry"
path   = "HKCU\\Software\\MyApp\\**"
perm   = "rx"  # read values + enumerate subkeys
```

---

## Tool Isolation

### Always Out-of-Process

Every tool that interacts with system resources spawns a child process.
The server never executes privileged operations in-process. This gives us:
- A clear boundary for what the authz layer needs to control
- A place to insert OS-level restrictions (Layer 2, future)
- Clean separation: the server process only runs authz + dispatch logic

### Pre-Spawn Authorization

Before any child is spawned:
1. The tool's `resolve_resources(args)` is called in-proc
2. It returns the exact resources this invocation will touch
3. The authz layer evaluates them against the key's deny/grant rules
4. If all clear, the child is spawned in a restricted environment derived from
   the granted permissions (restricted PATH, explicit env vars, etc.)

### Transitive Resource Access

> **Unresolved.** When a spawned process (e.g., `git`) itself accesses
> resources transitively (e.g., reads `.git/config` which references a remote),
> the server has no portable way to intercept or validate those accesses before
> they happen. Portably prompting the user mid-execution is also not practical.
>
> **Interim stance**: tools that spawn sub-processes must be scoped tightly
> enough that transitive access is predictable. Document the transitive behaviour
> as part of each tool's spec. Revisit with OS-level sandboxing (Layer 2).

### Layer 2: OS-Level Sandboxing (Future)

- Linux: `seccomp` + `namespaces` (restrict syscalls, filesystem view, network)
- Windows: Job Objects + restricted token
- The child process literally cannot access what it hasn't been granted,
  regardless of what it attempts. This supersedes the soft pre-spawn check.

---

## McpTool Trait

```rust
pub trait McpTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;

    /// JSON Schema for the tool's arguments.
    fn schema(&self) -> serde_json::Value;

    /// Given concrete args, return every resource this invocation will touch.
    /// Called before execute(). Authz checks this list against key policy.
    /// Tools must be honest here — this is the pre-spawn authorization gate.
    fn resolve_resources(
        &self,
        args: &serde_json::Value,
    ) -> Result<Vec<ResourceRequest>, ToolError>;

    /// Execute the tool. By the time this is called, authz has already passed.
    /// Implementations should spawn an out-of-process child for any system access.
    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<serde_json::Value, ToolError>;
}
```

Adding a utility:
1. Create `src/tools/my_tool.rs`
2. Implement `McpTool`
3. Register in `src/tools/mod.rs`

No macros or codegen required.

---

## TOML Config Structure

```toml
[server]
host      = "127.0.0.1"
port      = 3000          # used when transport includes "http"
transport = "stdio"       # "stdio" | "http" | "both"

[audit]
enabled = true
output  = "stdout"        # "stdout" | "file"
path    = "audit.log"     # used when output = "file"

# -- Keys --

[keys.ci_agent]
description = "CI pipeline agent"
token       = "sk_live_abc123..."

  [[keys.ci_agent.rules]]
  effect = "grant"
  type   = "tool"
  name   = "*"

  [[keys.ci_agent.rules]]
  effect = "grant"
  type   = "filesystem"
  path   = "/workspace/**"
  perm   = "rw"

  [[keys.ci_agent.rules]]
  effect = "deny"
  type   = "filesystem"
  path   = "/workspace/.git/**"
  perm   = "w"

  [[keys.ci_agent.rules]]
  effect     = "grant"
  type       = "program"
  executable = "cargo"
  perm       = "x"

[keys.read_only_agent]
description = "Read-only observer"
token       = "sk_live_xyz789..."

  [[keys.read_only_agent.rules]]
  effect = "grant"
  type   = "tool"
  name   = "read_file"

  [[keys.read_only_agent.rules]]
  effect = "grant"
  type   = "filesystem"
  path   = "/workspace/**"
  perm   = "r"
```

---

## Hot Reload

When the config file changes on disk:
1. Parse and validate the new config
2. If **invalid** — log a warning, keep current config active, do not reload
3. If **valid** — atomically swap in-memory config (`Arc<RwLock<Config>>`)
4. Log the reload event to the audit log

In-flight requests complete under the old config. New requests see the new
config immediately after the swap.

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
- Bearer token in `Authorization: Bearer <token>` header
- Enabled via `transport = "http"` or `transport = "both"` in config

---

## Request Lifecycle

```
Agent request  (tool_name + args + bearer_token)
        |
        v
1. Key resolution              unknown key  → 401
2. Tool grant check            no tool rule → 403
3. tool.resolve_resources()    → Vec<ResourceRequest>
4. Deny rule scan              any match    → 403
5. Grant rule scan             any uncovered resource → 403
6. Spawn child process         env scoped to granted resources
        |
        v
Audit log  (key, tool, resources, decision, outcome, timestamp)
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
│   ├── authz/           # Key resolution, permission bits, rule evaluation
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

- [ ] Transitive resource access in sub-processes — revisit with Layer 2 sandboxing
- [ ] Layer 2 OS-level sandboxing (seccomp / Job Objects) — design before first spawning tool ships
- [ ] Signing scheme upgrade path (HMAC / Ed25519)
- [ ] First batch of utilities (post-framework review)
