# Pansophical

**Security-first MCP server with intersection-based authorization.**

Pansophical is a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that sits between AI agents and the tools they call — enforcing fine-grained authorization, human-in-the-loop confirmation, environment sandboxing, and full audit logging on every invocation.

## Why

MCP gives agents access to your filesystem, shell, and APIs. Most MCP servers trust the agent implicitly. Pansophical doesn't. Every tool call passes through a deny-before-grant authorization engine that intersects the agent's request against your explicit policy — and anything not granted is denied.

## Features

- **Intersection-based authz** — agents only get the intersection of what they ask for and what you've granted
- **Human-in-the-loop** — configurable confirmation prompts with one-time HMAC tokens, auto-deny on timeout
- **Environment stripping** — child processes start with an empty environment; only explicitly whitelisted vars are passed
- **Process sandboxing** — Windows Job Objects (`KILL_ON_JOB_CLOSE`) prevent orphaned child processes
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

This generates `config.toml` with a random server secret and a `tools/` directory for script tool definitions.

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
path   = "C:\\Projects\\my_workspace\\**"
perm   = "rw"
```

### 4. Run

```bash
# Stdio mode (for local agents like Claude Desktop, Cursor, etc.)
./target/release/pansophical

# HTTP mode (for remote agents)
./target/release/pansophical --config config.toml
# Then set transport = "http" in config.toml

# Both simultaneously
# Set transport = "both" in config.toml
```

### 5. Open the dashboard

Navigate to [http://127.0.0.1:9765](http://127.0.0.1:9765) to see registered tools, configured keys, and the live audit log.

### 6. Try the demo (optional)

A zero-dependency Python harness connects Gemini to Pansophical for interactive tool-calling:

```bash
python demo.py
```

It will ask for a Gemini API key (or reads `GEMINI_API_KEY` env var), spawn the MCP server, and drop you into a chat where Gemini can call your registered tools through the full authz pipeline.

## Configuration

The server is configured entirely via `config.toml`. Key sections:

| Section | Purpose |
|---------|---------|
| `[server]` | Host, port, transport mode (`stdio`/`http`/`both`), server secret |
| `[keys.*]` | Named API keys with bearer tokens and policy rules |
| `[tools]` | Path to script tool definitions directory |
| `[sandbox]` | Environment baseline vars, sandbox strategy |
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
# perm  = "r"           # "r", "w", or "rw"
```

A tool call is only authorized if **every access request** (tool name + filesystem paths) is covered by at least one `grant` rule, and no `deny` rule overrides it.

## Script tools

Define custom tools in `tools/*.toml`:

```toml
[tool]
name        = "git_status"
description = "Show git status for a repository"
command     = "git"
args        = ["status", "--porcelain"]

[tool.security]
allow_shell     = false   # reject shell interpreters
arg_passthrough = false   # don't pass agent-supplied args
```

Script tools run through the same reaper pipeline as built-in tools — with environment stripping, timeout enforcement, and Job Object assignment.

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
    │ Granted │──▶ Reaper spawns child (empty env, Job Object, timeout)
    └─────────┘
         │
         ▼
    Audit entry logged
```

## Built-in tools

| Tool | Description |
|------|-------------|
| `read_file` | Read file contents (requires `r` permission on path) |
| `write_file` | Write file contents (requires `w` permission on path) |
| `list_dir` | List directory contents (requires `r` permission on path) |

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

## License

MIT
