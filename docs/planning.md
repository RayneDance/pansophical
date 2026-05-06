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
| Tool spawning | Always out-of-process |
| Per-tool resource config | No — policy lives on the key |
| Enforcement model | Key ceiling ∩ Tool needs = actual child grant |
| Layer 2 sandboxing | Phase 1, not future |
| Safety rails | Rate limits, timeouts, resource caps — configurable |
| Human-in-the-loop | `confirm = true` on individual rules; always-on local confirm server |
| First utilities | After framework is reviewed and stable |

---

## Key & Signing Model

Each agent caller is identified by a **named key**. When a request comes in:

1. The agent presents its key as a bearer token in the request
2. The server resolves the key to a named policy
3. The policy is evaluated against the tool and resource being requested
4. If authorized → execute; if not → return a structured denial

**Phase 1**: Static bearer token (`Authorization: Bearer <token>` over HTTP,
or a header field in the stdio envelope).

**Future**: HMAC-per-request or Ed25519 keypair. The key resolution interface
is designed to swap this in without changing the authorization layer.

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

## Authorization Resource Types

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

Forward slashes are normalized to backslashes at parse time to avoid
the common double-backslash TOML pitfall.

```toml
[[keys.my_agent.rules]]
effect = "grant"
type   = "registry"
path   = "HKCU/Software/MyApp/**"   # forward slashes accepted
perm   = ["read", "traverse"]
```

---

## Tool Isolation & Sandboxing (Phase 1)

### Always Out-of-Process

Every tool that touches system resources spawns a child process. The server
process never performs privileged operations in-process.

### Layer 2: OS-Level Enforcement (Phase 1)

The pre-spawn authz check (`resolve_resources` → policy evaluation) is a
**necessary but not sufficient** security control. A compromised or malicious
tool can lie in `resolve_resources`. OS-level enforcement makes the sandbox
real, regardless of the tool's declared intent.

| Platform | Mechanism |
|---|---|
| Linux | `landlock` (filesystem), `seccomp` (syscall filter), network namespaces |
| Windows | Job Objects, restricted token, ACL-based filesystem restrictions |

The child process is spawned with an environment and OS-level restrictions
derived from `actual_grant`. It **physically cannot** access resources outside
that grant, regardless of what it attempts.

### Transitive Resource Access

> **Unresolved.** When a spawned process (e.g., `git`) itself accesses
> resources transitively (e.g., reads `.git/config` → references a remote),
> the server cannot intercept those accesses at the argument level.
>
> **Interim stance**: Layer 2 sandboxing is the primary mitigation. The child
> process's network and filesystem access are restricted to `actual_grant`,
> so transitive accesses that fall outside the grant are blocked at the OS.
> Tools must document their transitive behaviour as part of their spec.

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

    /// Given concrete args, return every resource this invocation will touch.
    /// Called before execute(). Used to compute actual_grant = needs ∩ policy.
    /// Note: this is a pre-spawn declaration, not a security boundary on its
    /// own — Layer 2 OS sandboxing enforces the actual_grant at runtime.
    fn resolve_resources(
        &self,
        args: &serde_json::Value,
    ) -> Result<Vec<ResourceRequest>, ToolError>;

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

Adding a built-in tool:
1. Create `src/tools/builtin/my_tool.rs`
2. Implement `McpTool`
3. Register in `src/tools/mod.rs`

### Script Tools
External scripts/programs exposed as MCP tools. No Rust required.
A generic `ScriptTool` struct implements `McpTool` and is driven entirely
by a TOML definition file. See the **Script Tool Definitions** section.

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

[server.http]
cors_origins = ["http://localhost:*"]   # strict allowlist for browser agents
# origin header validated on every request

[tools]
dir = "./tools"   # path to script tool definition directory

[sandbox]
enabled  = true     # disable only if platform support is unavailable
strategy = "auto"   # "auto" | "landlock" (Linux) | "job_object" (Windows)

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
  [ APPROVE ]   [ DENY ]
        |
        v
User clicks → POST /confirm/<token>/approve  (or /deny)
        |
        v
Server unblocks the pending request
  → approved: continue to spawn
  → denied:   return 403, audit log entry
        |
        v
TTL expires with no response → auto-deny + audit log entry
```

### Security Properties

- **Localhost-only** — confirm server binds `127.0.0.1` exclusively; not reachable from the network
- **One-time tokens** — each token is valid for exactly one approve/deny; replayed tokens are rejected
- **HMAC-signed** — tokens cannot be forged without the server secret
- **Auto-deny on expiry** — unanswered requests fail closed, not open
- **Pending queue** — multiple concurrent confirm requests are queued and each gets its own page; the UI shows all pending items

---

## Request Lifecycle

```
Agent request  (tool_name + args + bearer_token)
        |
        v
1. Key resolution              unknown key       → 401
2. Tool grant check            no tool rule      → 403
3. tool.resolve_resources()    → Vec<ResourceRequest> (tool's declared needs)
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
│   ├── main.rs
│   ├── config/          # TOML parsing, hot reload, validation, glob compilation
│   ├── authz/           # Key resolution, permission bits, rule evaluation,
│   │                    # intersection computation
│   ├── audit/           # Audit log writer (O_APPEND / syslog)
│   ├── sandbox/         # OS-level child process sandboxing
│   │   ├── linux.rs     # landlock + seccomp
│   │   └── windows.rs   # Job Objects + restricted token
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

## Deferred / Open

- [ ] Transitive resource access — mitigated by Layer 2 but not fully solved; document per-tool
- [ ] Signing scheme upgrade path (HMAC / Ed25519)
- [ ] First batch of utilities (post-framework review)
