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
| Audit log | On by default; configurable; O_APPEND or syslog |
| Hot reload | Yes — validate on change, enforce only if valid |
| MCP transport | stdio (default/local) + HTTP/SSE (remote, opt-in) |
| Permission model | Unix-style `r/w/x` bit flags (verb aliases in TOML) |
| Authorization naming | `PolicyTarget` (not "resource type") to avoid collision with MCP Resources |
| Tool spawning | Always out-of-process |
| Per-tool resource config | No — policy lives on the key |
| Enforcement model | Key ceiling ∩ Tool needs = actual child grant |
| Layer 2 sandboxing | Phase 1 — Linux: landlock+seccomp; Windows: AppContainer |
| Safety rails | Rate limits, timeouts, resource caps — configurable |
| Human-in-the-loop | `confirm = true`; session approvals to prevent fatigue |
| Child environment | Clean by default; env grants are the whitelist |
| Authz explain mode | Dev-mode only; returns policy diff on denial |
| SSE disconnect | Kill child on disconnect (default); re-attach via request_id |
| MCP lifecycle | Full compliant initialize handshake; stdio auth via `_meta.token` |
| MCP Resources primitive | Phase 1: file + device URIs; same policy evaluation as tools |
| Progress notifications | Supported via `notifications/progress` with `progressToken` |
| First utilities | After framework is reviewed and stable |

---

## Key & Signing Model

Each agent caller is identified by a **named key**. When a request comes in:

1. The agent presents its key as a bearer token in the request
2. The server resolves the key to a named policy
3. The policy is evaluated against the tool and resource being requested
4. If authorized → execute; if not → return a structured denial

**Phase 1**: Static bearer token.
- **HTTP/SSE**: `Authorization: Bearer <token>` header on the initial SSE connection.
- **stdio**: token passed in `params._meta.token` of the `initialize` request.
  The key is resolved once during the handshake and bound to the session.

**Future**: HMAC-per-request or Ed25519 keypair. The key resolution interface
is designed to swap this in without changing the authorization layer.

---

## MCP Protocol Compliance

Pansophical targets MCP spec version **`2024-11-05`** (current stable).

### Session Lifecycle

#### 1. Initialize (client → server)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": { "name": "my_agent", "version": "1.0.0" },
    "_meta": {
      "token": "sk_live_abc123..."   // stdio auth
    }
  }
}
```

Server actions:
1. Validate protocol version (reject with error if unsupported)
2. Extract `_meta.token`, resolve to key + policy, bind to session
3. Return capabilities:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools":     { "listChanged": true },
      "resources": { "listChanged": true, "subscribe": false },
      "logging":   {}
    },
    "serverInfo": { "name": "pansophical", "version": "0.1.0" }
  }
}
```

`tools.listChanged: true` — hot reload can add/remove tools at runtime.  
`resources.listChanged: true` — hot reload affects the resource list too.

#### 2. Initialized (client → server)

```json
{ "jsonrpc": "2.0", "method": "notifications/initialized" }
```

No response. Server is now fully operational for this session.

#### 3. HTTP/SSE Auth

Bearer token in the `Authorization` header on the initial SSE connection:
```
GET /sse HTTP/1.1
Authorization: Bearer sk_live_abc123...
```
Key is resolved once at connection establishment and applies to all tool calls
over that stream.

#### 4. Shutdown

- **stdio**: server exits cleanly when stdin closes
- **HTTP/SSE**: SSE stream closes; in-flight calls complete or are killed per
  the disconnect policy; pending confirms are auto-denied; reaper kills children

### JSON-RPC Error Codes

| Code | Meaning |
|---|---|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| -32000 | Auth error (unknown key) |
| -32001 | Unauthorized (PolicyTarget denied) |
| -32002 | Rate limited |
| -32003 | Tool timeout |
| -32004 | Confirm denied |

---

## Permission Model: `r/w/x` Bits

Permissions are represented as Unix-style bit flags on every resource rule.
Internally a `u8` bitfield (`bitflags!` macro). In TOML they can be written as:

- **Short form** `perm = "rw"` — for filesystem, where Unix semantics are clear
- **Verb form** `perm = ["read", "write"]` — for other resource types, where
  `x`'s meaning is less obvious. Verbs map 1:1 to bits at parse time.

| Bit | Short | Verb aliases |
|---|---|---|
| 4 | `r` | `read` |
| 2 | `w` | `write` |
| 1 | `x` | `execute`, `connect`, `traverse`, `inject`, `signal` |

All verb aliases map to the same underlying bit. The per-type semantics table
makes clear what each bit *means* for that resource type.

### Semantics Per Resource Type

| Resource | `r` / `read` | `w` / `write` | `x` — type-specific alias |
|---|---|---|---|
| `filesystem` | read content, list dir | create / write / modify / delete | `traverse` (dir), `execute` (file) |
| `program` | capture stdout/stderr | write to stdin | `execute` — spawn the process |
| `network` | receive data | send data | `connect` — open a connection |
| `http` | GET, HEAD | POST, PUT, PATCH, DELETE | — (not used) |
| `environment` | read var value | set var in child | `inject` — inherit var into child |
| `secret` | read value | update / rotate | `inject` — inject into child env |
| `registry` | read values | write / create / delete | `traverse` — enumerate subkeys |
| `process` | read info / status | write to stdin | `signal` — signal or kill |

> `tool` (meta-authorization) has no permission bits — it is grant/deny only.

Glob patterns on paths are **compiled once at config parse time**, not
re-evaluated per request.

---

## Authorization Model

### The Enforcement Principle

There are two parties involved in every resource access:

- The **key policy** sets the *ceiling* — the maximum a caller is allowed
- The **tool** declares its *needs* via `resolve_resources()` — what it actually requires

The actual permissions granted to the child process are the **intersection**:

```
actual_grant = tool_needs ∩ key_grants
```

This provides Principle of Least Privilege automatically, without per-tool
configuration. A read-only tool that only asks for `r` gets only `r`, even if
the key holds `rw`. A tool that asks for more than the key allows is rejected.

### Why `resolve_resources()` Is Not a Security Boundary Alone

A tool that lies in `resolve_resources()` (asks for less, does more) can
defeat the pre-spawn check. This is the "Honest Tool Fallacy." The answer is
not to trust the declaration — it is to **enforce the intersection at the OS
level** so the child process physically cannot exceed it.

Layer 2 sandboxing is therefore **Phase 1**, not deferred.

### Evaluation Order

```
Request arrives
    |
    v
1. Key resolution          — unknown key → 401
2. Tool grant check        — no tool rule → 403
3. resolve_resources()     — tool maps args → Vec<ResourceRequest>
4. Deny rule scan          — any deny match → 403  (deny always wins)
5. Grant rule scan         — all tool needs covered by key grants? → continue : 403
6. Compute actual_grant    — tool_needs ∩ key_grants
7. confirm check           — any rule has confirm=true? → await user approval
8. Spawn child process     — environment + OS sandbox scoped to actual_grant
    |
    v
Audit log  (key, tool, resources, actual_grant, decision, outcome, timestamp)
```

Deny rules are **evaluated before grants** and always win:
- Grant `filesystem /workspace/**  rw`
- Deny  `filesystem /workspace/.git/**  w`  ← specific carve-out

### Authz Explain Mode

When `dev_mode = true` in `[server]`, denial responses include a structured
policy diff to aid tool developers:

```json
{
  "error": "Unauthorized",
  "explain": {
    "requested": [{"type": "filesystem", "path": "/etc/hosts", "perm": "w"}],
    "granted":   [{"type": "filesystem", "path": "/workspace/**", "perm": "rw"}],
    "denied":    [{"type": "filesystem", "path": "/etc/hosts", "perm": "w",
                   "reason": "no matching grant for path"}]
  }
}
```

**`dev_mode` must never be enabled in production.** It reveals policy structure
that an attacker could use to probe the authorization surface. Default: `false`.

### Human-in-the-Loop Gate

Individual rules can require explicit user confirmation before execution:

```toml
[[keys.my_agent.rules]]
effect  = "grant"
type    = "filesystem"
path    = "/workspace/**"
perm    = "w"
confirm = true   # server pauses and surfaces an approval request
```

When `confirm = true` is hit, the server emits a confirmation request over
the transport and waits for a manual approval or rejection. Useful for `w` and
`x` operations on sensitive resources.

---

## PolicyTarget Types

Each policy rule targets a **PolicyTarget** — the category of system resource
being controlled. The `type` field in a rule specifies the PolicyTarget.

> **Naming note**: We call this concept `PolicyTarget` (not "resource type")
> to avoid collision with the MCP protocol's "Resources" primitive, which is
> a separate concept (data exposed to agents for reading). See **MCP Resources
> Primitive** for that.

### 1. `filesystem`

```toml
[[keys.my_agent.rules]]
effect = "grant"
type   = "filesystem"
path   = "/home/user/project/**"
perm   = "rw"
```

Glob on `path`. Short `perm` form is natural here (Unix semantics).

---

### 2. `program`

```toml
[[keys.my_agent.rules]]
effect     = "grant"
type       = "program"
executable = "git"
perm       = ["execute"]
```

`executable` matched against the resolved binary name (not full path).
All spawning is out-of-process and sandboxed.

---

### 3. `network`

```toml
[[keys.my_agent.rules]]
effect   = "grant"
type     = "network"
host     = "api.github.com"
ports    = [443]
protocol = "https"
perm     = ["read", "write", "connect"]
```

---

### 4. `http`

```toml
[[keys.my_agent.rules]]
effect      = "grant"
type        = "http"
url_pattern = "https://api.github.com/repos/**"
perm        = ["read"]   # GET, HEAD only
```

---

### 5. `environment`

Child processes start with a **clean environment** by default. Only a minimal
safe baseline is inherited (`PATH`, `TERM`, `LANG`, `HOME`). Every additional
variable requires an explicit `environment` grant — making these grants the
effective whitelist rather than a nice-to-have. This is the primary mitigation
for transitive credential leakage (e.g., `~/.ssh/config`, `~/.aws/credentials`).

```toml
[[keys.my_agent.rules]]
effect      = "grant"
type        = "environment"
var_pattern = "MY_APP_*"
perm        = ["read", "inject"]
```

---

### 6. `process`

```toml
[[keys.my_agent.rules]]
effect       = "grant"
type         = "process"
name_pattern = "my_service*"
perm         = ["read", "signal"]
```

---

### 7. `tool`

Meta-authorization. No permission bits — grant/deny only. First gate.

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
perm   = ["read"]
```

---

### 9. `registry` *(Windows-specific)*

Two normalizations are applied at parse time before any glob match:
1. **Forward slashes** → backslashes (avoids double-backslash TOML pitfall)
2. **Short-form hive aliases** → canonical long form:
   `HKCU` → `HKEY_CURRENT_USER`, `HKLM` → `HKEY_LOCAL_MACHINE`, etc.

This ensures a rule written for `HKCU/...` cannot be bypassed by a tool
requesting `HKEY_CURRENT_USER/...`.

```toml
[[keys.my_agent.rules]]
effect = "grant"
type   = "registry"
path   = "HKCU/Software/MyApp/**"   # forward slashes + short alias both accepted
perm   = ["read", "traverse"]
```

---

### 10. `device`

Physical hardware access — audio capture, video capture, screen, USB, etc.
Exposed as MCP Resources via `device://` URIs as well as gated here.

| `name` pattern | Covers |
|---|---|
| `microphone/*` | Audio capture devices |
| `camera/*` | Video capture devices |
| `display/*` | Screen capture / output |
| `usb/*` | USB device access |

```toml
[[keys.my_agent.rules]]
effect = "grant"
type   = "device"
name   = "microphone/default"
perm   = ["read"]   # capture audio
```

`x` is not applicable for device targets.

---

---

## MCP Resources Primitive

MCP Resources expose data to agents for reading via `resources/list` and
`resources/read`. This is distinct from MCP Tools (which perform actions).

> **Naming note**: MCP "Resources" ≠ Pansophical `PolicyTarget`. Resources are
> data the agent can read. PolicyTargets are the categories of system access
> that policy rules control.

### Phase 1: File Resources

File resources expose filesystem paths the key has `r` permission on.
URI format: `file:///absolute/path`

```json
// resources/list response
{
  "resources": [
    {
      "uri":      "file:///workspace/README.md",
      "name":     "README.md",
      "mimeType": "text/markdown"
    }
  ]
}
```

`resources/read` on a `file://` URI checks the calling key's policy for
`filesystem` PolicyTarget `r` on that path. Same evaluation order as tool
calls: deny → grant → intersection.

### Device Resources

Device streams are MCP Resources with URI scheme `device://`:

| URI | Resource |
|---|---|
| `device://microphone/default` | Default audio capture stream |
| `device://camera/0` | First video capture device |
| `device://display/primary` | Primary screen capture |

Authorization: `device` PolicyTarget with `r` permission. Same flow as files.

### Future Resource Types

Any PolicyTarget with an `r` bit can expose MCP Resources. Future candidates:
databases (`db://`), message queues, sensor streams.

### `resources/subscribe`

Not implemented in Phase 1. Server declares `subscribe: false` in capabilities.

---

## Progress Notifications

Long-running tools (`cargo build`, large file operations) stream progress
to the agent using `notifications/progress`.

### Protocol

Agent includes `_meta.progressToken` in a `tools/call` request:

```json
{
  "method": "tools/call",
  "params": {
    "name": "run_cargo",
    "arguments": { "args": ["build"] },
    "_meta": { "progressToken": "build-42" }
  }
}
```

While the child runs, the server emits:

```json
{
  "method": "notifications/progress",
  "params": {
    "progressToken": "build-42",
    "progress": 45,
    "total":    100,
    "message":  "Compiling pansophical v0.1.0"
  }
}
```

The `tools/call` response is sent normally when the child completes.

### Implementation

`RequestContext` carries `Option<ProgressToken>`. Tools check for it in
`execute()` and, if present, stream stdout lines as progress notifications.

Script tools opt in via `streaming = true` in their definition; `ScriptTool`
handles the notification loop automatically.

```toml
# tools/run_cargo.toml
[tool]
name      = "run_cargo"
streaming = true   # enables progress notification streaming
```

---

## Tool Isolation & Sandboxing (Phase 1)

### Always Out-of-Process

Every tool that touches system resources spawns a child process. The server
process never performs privileged operations in-process.

**Process I/O — deadlock prevention**: Child stdout and stderr must be consumed
concurrently. If the server reads only stdout while the child fills its stderr
buffer, the child hangs indefinitely (classic broken-pipe deadlock). All child
spawning uses `tokio::process` with both stdout and stderr read simultaneously
on separate async tasks, merged or discarded as needed for the tool's result.

### Layer 2: OS-Level Enforcement (Phase 1)

The pre-spawn authz check (`resolve_resources` → policy evaluation) is a
**necessary but not sufficient** security control. A compromised or malicious
tool can lie in `resolve_resources`. OS-level enforcement makes the sandbox
real, regardless of the tool's declared intent.

| Platform | Mechanism | Notes |
|---|---|---|
| Linux | `landlock` (filesystem), `seccomp` (syscall filter), network namespaces | Mature, composable |
| Windows | **AppContainer** isolation | Preferred over restricted tokens + ACL manipulation, which is brittle. AppContainer provides true filesystem and network virtualization without requiring a separate low-privilege user account or on-the-fly ACL injection. |

The child process is spawned with an environment and OS-level restrictions
derived from `actual_grant`. It **physically cannot** access resources outside
that grant, regardless of what it attempts.

### Environment Stripping

Before spawning any child process, the server builds a **clean environment**:

1. Start with an empty environment
2. Add the safe baseline: `PATH`, `TERM`, `LANG`, `HOME` (configurable)
3. Apply the calling key's `environment` grants — only explicitly granted
   vars (matched by `var_pattern` with `inject` permission) are added

This prevents transitive credential leakage. A tool spawning `git` cannot
pick up `~/.ssh/config` or `~/.aws/credentials` unless those vars/paths
are explicitly granted to the key.

### Transitive Resource Access

> **Mitigated (not fully solved).** Environment stripping removes the most
> common transitive leakage vector. Layer 2 OS sandboxing restricts filesystem
> and network access to `actual_grant`. Tools that need genuinely transitive
> access (e.g., `git push` which calls `ssh`) must have the required network
> grants explicitly, ensuring the operator is aware of the full access chain.
> Per-tool documentation must describe transitive behaviour.

### Orphaned Process Reaper

If the Pansophical server crashes or is force-killed, child processes must not
continue running. Mitigation:

- **Linux**: Assign all children to a process group; `prctl(PR_SET_PDEATHSIG, SIGKILL)` ensures children die with the parent.
- **Windows**: Assign children to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- A dedicated **reaper thread** monitors child process lifetimes and kills
  processes that exceed their configured timeout.

---

## Safety Rails

Configurable per-server and per-key to prevent DoS from runaway agents.

```toml
[limits]
# Global defaults (can be overridden per key)
max_invocations_per_minute = 60
max_concurrent_tools        = 4
tool_timeout_secs           = 30
max_output_bytes            = 1_048_576   # 1 MiB

[keys.ci_agent.limits]
max_invocations_per_minute = 120
tool_timeout_secs          = 300
```

- **Rate limit**: token bucket per key; excess requests get 429
- **Timeout**: hard `SIGKILL` / `TerminateProcess` after `tool_timeout_secs`
- **Output cap**: truncate or error if child output exceeds `max_output_bytes`
- **Concurrency**: reject or queue if concurrent tool count is exceeded

---

## McpTool Trait

```rust
pub trait McpTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;

    /// JSON Schema for the tool's arguments.
    fn schema(&self) -> serde_json::Value;

    /// Given concrete args, declare every PolicyTarget access this invocation needs.
    /// Called before execute(). Used to compute actual_grant = needs ∩ policy.
    /// Note: this is a pre-spawn declaration, not a security boundary on its
    /// own — Layer 2 OS sandboxing enforces the actual_grant at runtime.
    fn access_requests(
        &self,
        args: &serde_json::Value,
    ) -> Result<Vec<AccessRequest>, ToolError>;

    /// Execute the tool. Authz and intersection have already been computed.
    /// Spawn an out-of-process child scoped to ctx.actual_grant.
    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &RequestContext,   // carries actual_grant + key identity
    ) -> Result<serde_json::Value, ToolError>;
}
```

### Built-in Tools
Implemented in Rust, compiled into the binary. These are the primitives
(`read_file`, `write_file`, `run_program`, etc.) that script tools are built on.

**`access_requests()` examples:**

```rust
// read_file: single request, read-only
fn access_requests(&self, args: &Value) -> Result<Vec<AccessRequest>, ToolError> {
    let path = canonical_path(args["path"].as_str()?)?;  // canonicalize first
    Ok(vec![
        AccessRequest::filesystem(path, Perm::READ)
    ])
}

// move_directory: two requests — source needs read+delete, dest needs write+create
fn access_requests(&self, args: &Value) -> Result<Vec<AccessRequest>, ToolError> {
    let src = canonical_path(args["src"].as_str()?)?;
    let dst = canonical_path(args["dst"].as_str()?)?;
    Ok(vec![
        AccessRequest::filesystem(src, Perm::READ | Perm::DELETE),
        AccessRequest::filesystem(dst, Perm::WRITE | Perm::CREATE),
    ])
}
```

**Path canonicalization is mandatory** inside `access_requests()`. Every path
must be resolved to its absolute canonical form (resolving `..`, `.`, and
symlinks) before the policy check. On Windows, paths are also lowercased before
glob matching to prevent case-sensitivity bypass (`C:\Users\X` vs `c:\users\x`).

Adding a built-in tool:
1. Create `src/tools/builtin/my_tool.rs`
2. Implement `McpTool`
3. Register in `src/tools/mod.rs`

### Script Tools
External scripts/programs exposed as MCP tools. No Rust required.
A generic `ScriptTool` struct implements `McpTool` and is driven entirely
by a TOML definition file. See the **Script Tool Definitions** section.

**Shell spawning ban**: `ScriptTool` always spawns the interpreter directly
with the script as an argument — never via `sh -c` or `cmd.exe /c`. Shell
spawning bypasses environment stripping (the shell inherits the parent
environment) and makes resource declarations meaningless. Opt-in is available
for advanced cases but requires explicit `allow_shell = true` in the tool
definition and triggers a loud audit log warning.

---

## Script Tool Definitions

Script tools live in a `tools/` directory alongside `config.toml`.
One `.toml` file per tool. The server watches this directory; dropping
or deleting a file hot-reloads the tool registry immediately.

```
pansophical/
├── config.toml
├── tools/
│   ├── file_editor.toml
│   ├── code_reviewer.toml
│   └── ...
```

### Tool Definition Format

```toml
# tools/file_editor.toml

[tool]
name        = "file_editor"
description = "Modifies a file in some specific way"
version     = "1.0.0"
enabled     = true

# How to invoke it
[tool.invoke]
command     = "py"
args        = ["some_file_editor_flow.py"]
working_dir = "/workspace/scripts"   # optional; defaults to server cwd

# JSON Schema for agent-provided arguments.
# Validated before resolve_resources() is called.
[tool.schema]
type     = "object"
required = ["path"]

  [tool.schema.properties.path]
  type        = "string"
  description = "Absolute path to the file to edit"

  [tool.schema.properties.mode]
  type    = "string"
  enum    = ["append", "overwrite"]
  default = "overwrite"

# Resource declarations — what this tool will access given its args.
# The server uses these + actual arg values to run resolve_resources().
# Checked against the calling key's policy (intersection model).

[[tool.resources]]
type          = "filesystem"
path_from_arg = "path"   # resolved at call time from the agent's "path" arg
perm          = "rw"

[[tool.resources]]
type       = "program"
executable = "py"
perm       = ["execute"]

# Suggested grants — what a key typically needs to call this tool.
# Informational only; does not affect enforcement.
# The web UI pre-populates these when granting a key access to this tool.
# Operators can accept, tighten, or broaden the suggestions.

[[tool.suggested_grants]]
type = "tool"
name = "file_editor"

[[tool.suggested_grants]]
type = "filesystem"
path = "/workspace/**"
perm = "rw"

[[tool.suggested_grants]]
type       = "program"
executable = "py"
perm       = ["execute"]
```

### How `resolve_resources()` Works for Script Tools

The `ScriptTool` wrapper implements `resolve_resources()` by iterating
the `[[tool.resources]]` declarations and substituting `path_from_arg`
(and similar) with the actual values from the agent's args at call time:

```
Agent calls file_editor(path="/workspace/src/main.rs", mode="overwrite")
        |
        v
ScriptTool::resolve_resources() reads [[tool.resources]]:
  - filesystem  /workspace/src/main.rs  rw   ← substituted from arg
  - program     py                       x
        |
        v
Authz intersection check against calling key's policy
```

### Web UI — Tool Management

Available at `http://127.0.0.1:9765/tools`

**Adding a tool:**
1. Fill in name, description, command, args
2. Build the argument schema (form-driven JSON Schema builder)
3. Declare resources (dropdowns: type → arg mapping → permission bits)
4. Submit → server writes `tools/<name>.toml` → hot reload fires

**Granting a key access:**
1. Navigate to the key on the Keys page
2. "Grant tool access" → pick tool from list
3. UI pre-populates `suggested_grants` from the tool definition
4. Operator reviews, tightens or broadens, confirms
5. Server writes updated rules to `config.toml` → hot reload fires

---

## TOML Config Structure

```toml
[server]
host          = "127.0.0.1"
port          = 3000
transport     = "stdio"       # "stdio" | "http" | "both"
# Auto-generated and persisted on first run if left empty.
# Used to sign confirm tokens. Set explicitly to keep tokens valid across restarts.
server_secret = ""
# Expose policy diffs in denial responses. NEVER enable in production.
dev_mode      = false

[server.http]
cors_origins        = ["http://localhost:*"]
on_disconnect       = "kill"   # "kill" | "detach"
reattach_grace_secs = 30

[tools]
dir = "./tools"   # path to script tool definition directory

[sandbox]
enabled      = true     # disable only if platform support is unavailable
strategy     = "auto"   # "auto" | "landlock" (Linux) | "app_container" (Windows)
env_baseline = ["PATH", "TERM", "LANG", "HOME"]  # vars always passed to child

[audit]
enabled = true
output  = "stdout"  # "stdout" | "file" | "syslog"
path    = "audit.log"

[limits]
max_invocations_per_minute = 60
max_concurrent_tools        = 4
tool_timeout_secs           = 30
max_output_bytes            = 1_048_576

# ── UI / Admin Dashboard ──────────────────────────────────────────────────────

[ui]
port      = 9765
auto_open = "confirm"   # "startup" | "confirm" | "never"
                        # "startup" = open browser when server starts
                        # "confirm" = only open when a confirm rule fires
                        # "never"   = never auto-open (headless / CI)

[ui.auth]
# Optional PIN to protect the admin UI.
# If empty, localhost-only binding is the sole protection.
# Recommended for shared or multi-user machines.
pin = ""

[ui.confirm]
timeout_secs = 30   # auto-deny unanswered confirm requests after this many seconds

# ── Theming ───────────────────────────────────────────────────────────────────
#
# Theming is layered — each layer overrides the one above it:
#
#   1. Built-in default styles
#   2. [ui.theme] preset and mode
#   3. [ui.theme.colors] token overrides
#   4. [ui.theme.typography] overrides
#   5. [ui.custom.css_path] — loaded last, can override anything

[ui.theme]
mode   = "system"    # "light" | "dark" | "system" (follows OS preference)
preset = "default"   # built-in palettes: "default" | "ocean" | "forest"
                     #                    "rose"    | "slate"  | "mono"

# Fine-grained color token overrides.
# Values are CSS HSL components (hue deg, saturation %, lightness %).
# e.g. accent = "262 83% 58%" renders as hsl(262, 83%, 58%).
# Omit any token to inherit from the active preset.
[ui.theme.colors]
accent      = ""   # primary interactive color (buttons, links, highlights)
background  = ""   # page background
surface     = ""   # cards, panels, modals
surface_alt = ""   # alternate surface (table rows, input backgrounds)
border      = ""   # borders and dividers
text        = ""   # primary text
text_muted  = ""   # secondary / placeholder text
success     = ""   # success states (green family)
warning     = ""   # warning states (amber family)
danger      = ""   # error / destructive states (red family)

[ui.theme.typography]
font_sans = "Inter"           # sans-serif; loaded from Google Fonts if not installed locally
font_mono = "JetBrains Mono" # monospace; used for paths, tokens, code blocks, audit log
font_size = 14                # base font size in px (UI scales from this)

[ui.theme.layout]
density    = "comfortable"   # "compact" | "comfortable" | "spacious"
animations = true            # micro-animations and transitions; set false to reduce motion
radius     = "md"            # border radius scale: "none" | "sm" | "md" | "lg" | "full"

# ── Branding ──────────────────────────────────────────────────────────────────

[ui.branding]
title        = "Pansophical"   # browser tab title and dashboard header
logo_path    = ""              # path to a custom logo image (SVG or PNG)
favicon_path = ""              # path to a custom favicon (.ico, .png, or .svg)
footer_text  = ""              # optional custom text in the dashboard footer
show_version = true            # show server version in the UI footer

# ── Custom CSS ────────────────────────────────────────────────────────────────

[ui.custom]
# Path to a CSS file loaded after all built-in styles.
# Full override capability — target any class or CSS custom property.
# Hot-reloaded alongside the rest of the config.
css_path = ""

# -- Keys --

[keys.ci_agent]
description = "CI pipeline agent"
token       = "sk_live_abc123..."

  [keys.ci_agent.limits]
  max_invocations_per_minute = 120
  tool_timeout_secs          = 300

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
  effect  = "grant"
  type    = "filesystem"
  path    = "/workspace/**"
  perm    = "w"
  confirm = true   # any write requires manual approval

  [[keys.ci_agent.rules]]
  effect     = "grant"
  type       = "program"
  executable = "cargo"
  perm       = ["execute"]

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
1. Parse and validate the new config (including re-compiling all glob patterns)
2. If **invalid** — log a warning, keep current config active
3. If **valid** — atomically swap `Arc<RwLock<Config>>`; lock held only for the
   swap itself, not for the duration of any tool execution
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
- Strict CORS: `cors_origins` allowlist + `Origin` header validation on every
  request (prevents ambient authority attacks from browser-hosted agents)

#### SSE Disconnect Policy

If an agent's SSE connection drops while a tool is running:

- **Default (`on_disconnect = "kill"`)**: child process is killed immediately.
  Prevents zombie resource consumption. Correct for most tools.
- **`on_disconnect = "detach"`**: child continues running. The agent may
  re-attach within `reattach_grace_secs` using the original `request_id`
  to resume the SSE stream. After the grace period, if no re-attach occurs,
  the child is killed and the result is discarded.

```toml
[server.http]
cors_origins         = ["http://localhost:*"]
on_disconnect        = "kill"   # "kill" | "detach"
reattach_grace_secs  = 30       # only used when on_disconnect = "detach"
```

---

## Confirm Server

A minimal HTTP server dedicated to human-in-the-loop approvals. It is
**always running** on startup — no cold-start latency when the first
approval is needed, and no code path that skips initialization.

```toml
[confirm]
port         = 9765
timeout_secs = 30    # auto-deny if no response within this window
auto_open    = true  # open browser automatically; set false for headless/CI
```

### Flow

```
Tool invocation hits a rule with confirm = true
        |
        v
Server generates a one-time token
  - UUID + HMAC-signed with a server secret
  - TTL = confirm.timeout_secs
        |
        v
auto_open = true  →  open http://127.0.0.1:9765/confirm/<token>
  (via `open` crate: xdg-open on Linux, start on Windows)
        |
        v
Browser renders approval page:
  Key:        ci_agent
  Tool:       write_file
  Resource:   filesystem  /workspace/src/main.rs
  Permission: w
  [⏱ 28s remaining]

  [diff preview if tool provided one]
  - old line
  + new line

  [ APPROVE ONCE ]  [ APPROVE 5 min ]  [ APPROVE SESSION ]  [ DENY ]
        |
        v
User clicks → POST /confirm/<token>/approve  (or /deny)
  Body: { "scope": "once" | "minutes:5" | "session" }
        |
        v
Server records session approval if scope != "once"
Server unblocks the pending request
  → approved: continue to spawn
  → denied:   return 403, audit log entry
        |
        v
TTL expires with no response → auto-deny + audit log entry
```

### Session Approvals

To prevent confirm fatigue on repetitive workflows, approvals can be scoped
beyond a single invocation:

| Scope | Behaviour |
|---|---|
| `once` | This invocation only (default) |
| `minutes:N` | All matching invocations for N minutes |
| `session` | Until connection closes, config reloads, or inactivity timeout |

Session approvals are keyed on `(connection_id, key_id, tool_name, resource_pattern, perm)`.

- **Connection-scoped**: the `connection_id` is the SSE stream ID or stdio
  session ID. If the connection drops and restarts, **all session approvals
  for that connection are immediately cleared**. A fresh `initialize` starts
  a new connection with no carried-over approvals.
- **Inactivity expiry**: session approvals auto-expire after
  `session_approval_inactivity_secs` of no matching invocations, even if the
  connection is still open. Prevents long-idle sessions accumulating wide gates.
- **Memory-only**: session approvals never persist to disk or survive restarts.

```toml
[ui.confirm]
timeout_secs                    = 30
session_approval_options        = [5, 30, 0]   # minutes; 0 = session
session_approval_inactivity_secs = 300         # auto-expire idle session approvals
```

### Diff Preview

Tools can optionally provide a `preview` payload in their response to
`resolve_resources()`. If present, the confirm UI renders it as a unified diff
before the approve/deny buttons. Approving "add a comment to line 10" is
much safer UX than approving "write to main.rs".

The `preview` field is informational — it does not affect enforcement.

### Security Properties

- **Localhost-only** — confirm server binds `127.0.0.1` exclusively
- **One-time tokens** — each token is valid for exactly one approve/deny; replayed tokens are rejected
- **HMAC-signed** — tokens cannot be forged without the server secret
- **Auto-deny on expiry** — unanswered requests fail closed, not open
- **Pending queue** — multiple concurrent confirm requests are queued; the UI lists all pending items
- **PIN-gated admin** — config editing and key management require `ui.auth.pin`; confirm flow does not expose admin capabilities
- **Connection-scoped sessions** — session approvals clear immediately on disconnect; no approval survives a session restart
- **Uniform deny responses** — in production, the error returned to the agent is identical whether the tool grant, deny rule, or grant rule caused the rejection. The audit log records the real reason; the wire response does not reveal policy structure.

---

## Request Lifecycle

```
Agent request  (tool_name + args + bearer_token)
        |
        v
1. Key resolution              unknown key       → 401
2. Tool grant check            no tool rule      → 403
3. tool.access_requests()      → Vec<AccessRequest> (tool's declared PolicyTarget needs)
4. Deny rule scan              any deny match    → 403
5. Grant rule scan             needs not covered → 403
6. Compute actual_grant        = tool_needs ∩ key_grants
7. confirm check               surface approval request if needed; await
8. Spawn child (OS-sandboxed)  scoped to actual_grant
        |
        v
Audit log  (key, tool, declared_needs, actual_grant, decision, outcome, timestamp)
        |
        v
Response
```

---

## Crate Structure (Proposed)

```
pansophical/
├── src/
│   ├── main.rs              # CLI entry point
│   │                        #   --init   generate config + server_secret, exit
│   │                        #   --check  validate config, exit
│   │                        #   (default) run server
│   ├── protocol/        # MCP JSON-RPC protocol layer
│   │   ├── lifecycle.rs # initialize/initialized/shutdown handshake
│   │   ├── messages.rs  # MCP request/response/notification types
│   │   ├── resources.rs # MCP Resources primitive (list/read)
│   │   └── progress.rs  # notifications/progress streaming
│   ├── config/          # TOML parsing, hot reload, validation, glob compilation
│   ├── authz/           # Key resolution, PolicyTarget bits, rule evaluation,
│   │                    # intersection computation
│   ├── audit/           # Audit log writer (O_APPEND / syslog)
│   ├── sandbox/         # OS-level child process sandboxing
│   │   ├── linux.rs     # landlock + seccomp
│   │   └── windows.rs   # AppContainer isolation
│   ├── reaper.rs        # Child process lifecycle + timeout enforcement
│   ├── limits.rs        # Rate limiter + concurrency gate
│   ├── confirm/         # Always-on approval server
│   │   ├── server.rs    # HTTP listener on confirm.port
│   │   ├── token.rs     # One-time token generation + HMAC validation
│   │   └── ui.rs        # Embedded approval page HTML/CSS/JS
│   ├── transport/
│   │   ├── stdio.rs
│   │   └── http.rs      # includes CORS enforcement
│   ├── tools/           # McpTool trait + registry
│   │   ├── mod.rs       # trait definition + unified registry
│   │   ├── builtin/     # compiled-in Rust tools
│   │   └── script.rs    # ScriptTool wrapper (loads from tools/*.toml)
│   └── error.rs
├── docs/
│   └── planning.md
├── Cargo.toml
├── config.example.toml
└── tools/               # script tool definitions (one .toml per tool)
    └── example_tool.toml
```

---

## Implementation Priority

Order modules in this sequence to reach a Minimum Viable Secure Server:

| Priority | Module | Why |
|---|---|---|
| 1 | `authz` + `config` | If the intersection math is wrong, nothing else matters |
| 2 | `transport/stdio` | Easiest to test with existing agents; no network needed |
| 3 | `sandbox/linux` (Landlock) | Primary security claim; must be proven early |
| 4 | `confirm/server` | Without it, all `w`/`x` confirm rules are hard-denies |
| 5 | `tools/builtin` (`read_file`, `write_file`) | Validates the full pipeline end-to-end |
| 6 | `sandbox/windows` (AppContainer) | Parity with Linux |
| 7 | `transport/http` + SSE | Multi-agent, remote use cases |
| 8 | `tools/script` + `protocol/resources` | Script tools + MCP Resources primitive |

---

## Deferred / Open

- [ ] Transitive resource access — mitigated by Layer 2 but not fully solved; document per-tool
- [ ] Signing scheme upgrade path (HMAC / Ed25519)
- [ ] First batch of utilities (post-framework review)
- [ ] `resources/subscribe` — not Phase 1; revisit when resource streaming is needed
- [ ] `db://` and message queue PolicyTargets — future resource types
