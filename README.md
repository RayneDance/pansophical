# Pansophical

> **⚠️ Work in progress.** This project is under active development and was largely LLM-generated. I make no guarantees about security or safety. The sandboxing has not been fully audited. Use at your own risk — releases won't happen until significant review and testing is complete.

**Security-first MCP server with intersection-based authorization and OS-level sandboxing.**

Pansophical is a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that sits between AI agents and the tools they call — enforcing fine-grained authorization, human-in-the-loop confirmation, process sandboxing, and full audit logging on every invocation.

## Why

MCP gives agents access to your filesystem, shell, and APIs. Most MCP servers trust the agent implicitly. Pansophical doesn't. Every tool call passes through a deny-before-grant authorization engine that intersects the agent's request against your explicit policy — and anything not granted is denied.

## Features

### Authorization
- **Intersection-based authz** — agents only get the intersection of what they ask for and what you've granted
- **Deny-before-grant** — deny rules always win over grant rules on the same resource
- **Tool namespacing** — builtins are prefixed `builtin_`, script tools use `{group}_` (default `ext_`) to prevent collisions
- **Ephemeral grants** — agents can request filesystem access at runtime via `builtin_request_access`, approved through the admin dashboard

### Human-in-the-Loop
- **Confirmation prompts** — configurable per-rule, opens browser with one-time HMAC-signed tokens
- **Scoped caching** — approvals can be cached per-session, for N minutes, or single-use
- **Auto-deny on timeout** — unconfirmed requests are denied after the configured timeout

### Sandboxing
- **Windows AppContainer** (primary) — strongest Windows isolation; denies all filesystem and network access by default, only explicitly granted paths are accessible via handle-based ACE grants. Session-scoped container pooling amortizes the grant cost across tool calls
- **Windows Low Integrity** (fallback) — restricted token with Low integrity level; used when AppContainer fails to initialize
- **Linux Landlock** (kernel 5.13+) — path-based filesystem restrictions via `pre_exec` hook; read, write, and execute paths enforced from `SandboxProfile`
- **Network deny** — TCP bind + connect blocked via Landlock V5 (kernel 6.7+) on Linux; AppContainer on Windows. **Known gap:** on Linux kernels < 6.7, network deny silently degrades — child processes retain full network access. The server logs a warning when this occurs. A seccomp-bpf fallback could close this gap on older kernels but is not yet implemented
- **PR_SET_PDEATHSIG** — child processes are killed if the server dies (Linux)
- **Job Objects** — `KILL_ON_JOB_CLOSE` prevents orphaned child processes (Windows)
- **Environment stripping** — child processes start with an empty environment; only `env_baseline` vars are passed
- **Configurable fallback** — `allow_fallback = false` refuses execution when the sandbox can't initialize, preventing silent security degradation
- **Builtin tools run in-process** — builtins like `read_file` execute directly via `tokio::fs` after authz validation, bypassing the sandbox (which is reserved for untrusted script tools)

### Operations
- **Script tools** — define custom tools via TOML without writing Rust
- **Hot reload** — edit `config.toml` and policy takes effect immediately (no restart)
- **Dual transport** — stdio (for local agents) and HTTP/SSE (for remote agents) with bearer token auth
- **Admin dashboard** — web UI at `:9765` showing tools, keys, pending confirmations, and audit log
- **Full audit trail** — append-only JSON log of every authorization decision

## Quickstart

### 1. Build

```bash
cargo build --release
```

### 2. Initialize config

```bash
./target/release/pansophical --init
```

This generates `config.toml` with a random server secret and a `tools/` directory with example script tool definitions.

### 3. Add a key

Open `config.toml` and add a key for your agent:

```toml
[keys.my_agent]
token = "sk_replace_with_a_real_token"

# Grant access to all tools
[[keys.my_agent.rules]]
effect = "grant"
type   = "tool"
name   = "*"

# Grant read/write to your workspace
[[keys.my_agent.rules]]
effect = "grant"
type   = "filesystem"
path   = "/home/user/workspace/**"
perm   = "rw"
```

### 4. Run

```bash
# Stdio mode (for local agents like Claude Desktop, Cursor, etc.)
./target/release/pansophical --config config.toml

# HTTP mode (for remote agents)
# Set transport = "http" in config.toml
./target/release/pansophical --config config.toml

# Both simultaneously
# Set transport = "both" in config.toml
```

### 5. Open the dashboard

Navigate to [http://127.0.0.1:9765](http://127.0.0.1:9765) to see registered tools, configured keys, and the live audit log.

### 6. Try the demo (optional)

A zero-dependency Python harness connects Vertex AI (Gemini) to Pansophical for interactive tool-calling:

```bash
python demo.py [--config config.toml] [--binary target/debug/pansophical.exe]
```

Requires `gcloud` auth (`gcloud auth print-access-token`) for Vertex AI. Spawns the MCP server as a subprocess, discovers available tools, and drops you into a chat where Gemini can call your registered tools through the full authz pipeline.

## Configuration

The server is configured entirely via `config.toml`. Key sections:

| Section | Purpose |
|---------|---------|
| `[server]` | Host, port, transport mode (`stdio`/`http`/`both`), server secret, `dev_mode` |
| `[keys.*]` | Named API keys with bearer tokens and policy rules |
| `[tools]` | Path to script tool definitions directory |
| `[sandbox]` | Sandbox toggle, `env_baseline`, `allow_fallback`, `deny_network` |
| `[limits]` | Rate limiting, concurrency, timeout, max output bytes |
| `[audit]` | Log output (`file`/`stdout`), path |
| `[ui]` | Dashboard port, auto-open behavior, confirmation timeout |

### Policy rules

Each key has an array of rules. Rules are evaluated using an **intersection model**:

```toml
[[keys.my_agent.rules]]
effect  = "grant"       # "grant" or "deny"
type    = "tool"        # "tool" or "filesystem"
name    = "read_file"   # tool name (supports "*" glob)
# For filesystem rules:
# path  = "/workspace/**"
# perm  = "r"           # "r", "w", "rw", or "rwx"
```

A tool call is only authorized if **every access request** (tool name + filesystem paths) is covered by at least one `grant` rule, and no `deny` rule overrides it.

### Sandbox configuration

```toml
[sandbox]
enabled        = true    # Enable OS-level sandboxing
allow_fallback = false   # Refuse execution if sandbox fails (security-sensitive)
deny_network   = true    # Block all TCP bind + connect in sandboxed children
strategy       = "auto"  # "auto", "appcontainer", "restricted", "landlock"
env_baseline   = ["PATH", "TERM", "LANG", "HOME"]
```

## Script tools

Define custom tools in `tools/*.toml`. Top-level keys — no `[tool]` section nesting:

```toml
name            = "git_status"
description     = "Show git status in short format"
command         = "git"
args            = ["-C", "{path}", "status", "--short"]
allow_shell     = false
arg_passthrough = false

[[parameters]]
name        = "path"
description = "Repository path"
required    = true

[[resources]]
type = "filesystem"
path_from_arg = "path"
perm = "r"
```

### Argument interpolation

Arguments can reference parameters with `{param_name}` placeholders. Parameters not referenced by any placeholder are appended at the end (backward-compatible with positional style). Optional parameters whose placeholder can't be filled cause the entire arg to be dropped.

### Safety checks

Script tools enforce several safety checks by default:
- **Shell rejection** — commands matching `bash`, `cmd`, `powershell`, etc. are rejected unless `allow_shell = true`
- **Flag injection** — argument values starting with `-` are rejected unless the parameter sets `allow_flags = true`
- **Metacharacter rejection** — values containing `;`, `&`, `|`, `>`, `` ` ``, `$`, `(`, `)` are rejected unless `arg_passthrough = true`

### Windows note

On Windows, commands like `echo` are shell builtins, not standalone executables. Script tools using shell builtins should set `command = "cmd"` with `args = ["/C", "echo", ...]` and `allow_shell = true`. Alternatively, use standalone executables that don't require a shell.

Script tools run through the same reaper pipeline as external commands — with environment stripping, timeout enforcement, and AppContainer/Landlock sandbox assignment.

## Security model

```
Agent request
    │
    ▼
┌─────────────────────┐
│  Access requests    │  Tool declares what it needs
│  (tool + paths)     │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Policy evaluation  │  Intersect request against key's rules
│  (deny-before-grant)│
└────────┬────────────┘
         │
    ┌────┴────┐
    │ Denied  │──▶ JSON-RPC error + audit entry
    └─────────┘
         │
    ┌────┴────┐
    │ Confirm │──▶ Browser opens, HMAC token, auto-deny on timeout
    └─────────┘
         │
    ┌────┴────┐
    │ Granted │──▶ Builtin: in-process execution
    └─────────┘   Script: reaper spawns sandboxed child
         │
         ▼
    Audit entry logged
```

### Sandbox architecture

| Platform | Primary | Fallback | Network |
|----------|---------|----------|---------|
| **Windows** | AppContainer (deny-all + handle-based ACEs) | Low Integrity restricted token | AppContainer denies by default |
| **Linux** | Landlock V5 (filesystem + network) | Unsandboxed (if `allow_fallback = true`) | Landlock `AccessNet` deny (kernel 6.7+) |

> **⚠️ Windows sandbox status:** AppContainer isolation is functional and tested on Windows 10/11. Handle-based ACL grants, session pooling, and container cleanup all work correctly. However, the implementation has not been security-audited and should not be considered hardened.

**Windows AppContainer details:**
- A **session-scoped container pool** creates one AppContainer per API key and reuses it across all tool calls for that session, eliminating per-call ACE pollution and amortizing grant cost
- Filesystem access is granted via **handle-based `SetSecurityInfo`** (TOCTOU-safe) — not `icacls`. Each file/directory receives a non-inheriting ACE with the container's SID
- ACE existence checks skip `SetSecurityInfo` when the SID already has adequate permissions, avoiding the 50+ second penalty on drive roots
- Ancestor directories up to the drive root receive traverse ACEs so the container can resolve paths
- System directories (`System32`, `SysWOW64`) are already accessible via the built-in `ALL APPLICATION PACKAGES` ACE — no explicit grants needed
- Critical Windows system environment variables (`SYSTEMROOT`, `windir`, `TEMP`, `PATHEXT`, etc.) are always included in the child environment block
- The container profile and all ACEs are cleaned up on shutdown via the pool's `Drop` implementation and orphan cleanup on restart

Both platforms: Job Object / `PR_SET_PDEATHSIG` kills children if the server dies. Environment is stripped to `env_baseline` only.

**Ephemeral grant lifecycle:**

Ephemeral grants (via `builtin_request_access`) allow admin-approved access to resources not covered by static policy. Important security considerations:

- **Capabilities are per-process.** When an ephemeral network grant is approved, the spawned child process receives the `internetClient` capability via `CreateProcessW`. This capability persists for the process's entire lifetime — it cannot be revoked mid-execution.
- **Grant expiry does not kill running processes.** If an ephemeral grant expires while a tool process is still running, that process retains its capabilities until exit. However, the next tool call will be denied at the authz layer since the cache entry has expired.
- **Exposure is bounded by `tool_timeout_secs`.** The reaper enforces a hard kill timeout (default: 30 seconds) on all child processes. This limits the window during which a process can operate after its grant expires.
- **Container reuse is safe.** The AppContainer pool reuses container profiles (SIDs) across tool calls, but capabilities are applied per-spawn, not per-container. A container that spawned a network-capable process can later spawn a non-network process — each gets its own `SecurityCapabilities`.

### Builtin vs script tool execution

| | Builtin tools | Script tools |
|---|---|---|
| **Execution** | In-process (`tokio::fs`, etc.) | Out-of-process via reaper |
| **Sandboxing** | Authz layer only | OS-level (AppContainer / Landlock) |
| **Timeout** | N/A | Configurable via `tool_timeout_secs` |
| **Environment** | Server's own | Stripped to `env_baseline` |

Builtin tools bypass the sandbox because they perform simple, well-defined operations (file read, directory list, etc.) that are already gated by the authorization engine. Script tools run arbitrary external commands and require OS-level isolation.

## Built-in tools

| Tool | Perm | Description |
|------|------|-------------|
| `builtin_read_file` | `r` | Read file contents (in-process) |
| `builtin_write_file` | `w` | Write file contents |
| `builtin_list_dir` | `r` | List directory contents |
| `builtin_file_info` | `r` | File/directory metadata (size, type, modified time, readonly) |
| `builtin_search_files` | `r` | Recursive text search with file pattern filter |
| `builtin_create_directory` | `w` | Create directory and parents (`mkdir -p`) |
| `builtin_move_file` | `w`×2 | Move/rename (requires write on source and destination) |
| `builtin_delete_file` | `w` | Delete file or empty directory |
| `builtin_request_access` | — | Request ephemeral filesystem access from the admin |

## CLI flags

```
pansophical [OPTIONS]

Options:
  --config <PATH>   Path to config file [default: config.toml]
  --init            Generate a new config.toml with random server secret
  --check           Validate config and exit
  -h, --help        Print help
  -V, --version     Print version
```

## Architecture

```
src/
├── main.rs              # Entry point, CLI, server startup
├── config/              # TOML schema, hot reload, permission types
├── authz/               # Authorization engine, glob matching, intersection
├── audit/               # Append-only JSON audit log
├── confirm/             # HITL confirmation (HMAC tokens, browser UI, session cache)
├── sandbox/
│   ├── mod.rs           # SandboxProfile, cross-platform interface, glob stripping
│   ├── pool.rs          # Session-scoped AppContainer pool with orphan cleanup
│   ├── windows.rs       # AppContainer + Low IL restricted token + Win32 security FFI
│   └── linux.rs         # Landlock + PR_SET_PDEATHSIG
├── reaper.rs            # Process spawning, timeout, output caps, sandbox diagnostics
├── limits.rs            # Rate limiter + concurrency gate (token bucket)
├── tools/
│   ├── builtin/         # 9 built-in tools (in-process execution)
│   └── script.rs        # TOML-defined script tool loader + safety checks
├── transport/
│   ├── stdio.rs         # JSON-RPC over stdin/stdout
│   └── http.rs          # HTTP/SSE transport with bearer auth
└── protocol/            # MCP protocol types
```

## License

MIT
