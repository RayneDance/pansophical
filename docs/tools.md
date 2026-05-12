# Script Tool Definitions

Pansophical exposes two kinds of tools to MCP clients:

- **Builtin tools** — compiled into the binary (`builtin_read_file`, `builtin_write_file`, etc.)
- **Script tools** — defined in TOML files in the `tools/` directory

This document covers script tools: how to define them, the full schema, safety controls, and best practices.

---

## Quick Start

Drop a `.toml` file into the `tools/` directory. The server detects it via hot-reload and registers it immediately.

```toml
# tools/greet.toml

name        = "greet"
description = "Say hello to someone"
command     = "echo"
args        = ["Hello, {name}!"]

[[parameters]]
name        = "name"
description = "Name to greet"
required    = true
```

The agent sees this as `ext_greet` (default `ext` group prefix) and can call it with `{"name": "world"}`.

---

## Schema Reference

### Top-Level Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **yes** | — | Tool name. Combined with `group` to form the MCP tool name: `{group}_{name}`. |
| `description` | string | **yes** | — | Human-readable description shown to the agent in `tools/list`. Write this for the LLM — be specific about what the tool does, what it returns, and when to use it. |
| `command` | string | **yes** | — | Executable to invoke. Resolved via `PATH`. Shell commands (`sh`, `bash`, `cmd`, `powershell`) are rejected unless `allow_shell = true`. |
| `group` | string | no | `"ext"` | Namespace prefix. The tool is exposed as `{group}_{name}`. Also used for group-based authorization (`type = "tool"`, `name = "{group}"`). |
| `args` | string[] | no | `[]` | Static arguments. Supports `{param_name}` interpolation (see below). |
| `allow_shell` | bool | no | `false` | Allow shell executables as the command. Triggers an audit warning on every invocation. |
| `arg_passthrough` | bool | no | `false` | Disable all argument validation (flag injection, metacharacter checks). Use only for trusted tools. |
| `streaming` | bool | no | `false` | If `true` and the client sends a `progressToken`, stdout lines are streamed as `notifications/progress`. |

### `[[parameters]]` — Agent-Supplied Arguments

Each `[[parameters]]` block defines an argument the agent can provide when calling the tool.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **yes** | — | Parameter name. Used as the JSON key in `tools/call` arguments and for `{name}` interpolation in `args`. |
| `description` | string | **yes** | — | Description shown to the agent in the tool's JSON Schema. |
| `param_type` | string | no | `"string"` | JSON Schema type (`"string"`, `"integer"`, `"boolean"`, `"number"`). |
| `required` | bool | no | `false` | Whether the parameter is required. Missing required params return an error before execution. |
| `allow_flags` | bool | no | `false` | Allow values starting with `-`. By default, flag-like values are rejected to prevent flag injection attacks. |

### `[[resources]]` — Access Declarations

Each `[[resources]]` block declares a system resource the tool needs. These are checked against the calling key's policy rules — the intersection determines what the sandbox allows.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | string | **yes** | — | Resource type: `"filesystem"`, `"network"`, `"program"`, `"environment"`, etc. |
| `path` | string | no | — | Static path or pattern. Use for fixed paths known at definition time. |
| `path_from_arg` | string | no | — | Take the path from a parameter value at call time. Mutually exclusive with `path`. |
| `perm` | string | no | `"r"` | Permission bits: `"r"` (read), `"w"` (write), `"rw"` (both), or verb form `["read", "write"]`. |

> **One of `path` or `path_from_arg` must be set** for `filesystem` resources. For `network` resources, `path` is typically `"*"` (any host).

---

## Naming and Grouping

Tools are namespaced to prevent collisions:

| `group` | `name` | MCP tool name |
|---------|--------|---------------|
| *(none)* | `hello` | `ext_hello` |
| `"ast"` | `map` | `ast_map` |
| `"devops"` | `git_status` | `devops_git_status` |

### Group-Based Authorization

Groups enable batch authorization. A single policy rule can grant or deny an entire group:

```toml
# Grant access to all tools in the "ast" group
[[keys.my_agent.rules]]
effect = "grant"
type   = "tool"
name   = "ast"

# Deny all tools in the "devops" group
[[keys.my_agent.rules]]
effect = "deny"
type   = "tool"
name   = "devops"
```

---

## Argument Interpolation

Parameter values can be injected into `args` using `{param_name}` placeholders:

```toml
command = "git"
args    = ["-C", "{path}", "log", "--oneline", "-n", "{count}"]

[[parameters]]
name     = "path"
required = true

[[parameters]]
name     = "count"
required = false
```

**Rules:**
- `{param_name}` is replaced with the agent-supplied value
- If the parameter is missing and not required, the entire arg containing the placeholder is omitted
- Parameters without a matching `{name}` placeholder in `args` are appended to the end of the command line
- Each `{param_name}` is a single argument — no shell expansion, no word splitting

---

## Safety Controls

### Shell Rejection

By default, shell executables are rejected at load time:

```
sh, bash, zsh, fish, dash, csh, tcsh, ksh,
cmd, cmd.exe, powershell, powershell.exe, pwsh, pwsh.exe
```

To explicitly allow a shell command:
```toml
command     = "cmd"
args        = ["/C", "tasklist"]
allow_shell = true     # required — triggers audit warning
```

### Metacharacter Rejection

Agent-supplied argument values are scanned for shell metacharacters:

```
; & | > < ` $ ( )
```

If any are found, the tool call is rejected. This is defense-in-depth — even though the command is not invoked through a shell, a naive script using `os.system(arg)` internally could still be vulnerable.

To disable: set `arg_passthrough = true` (use only for trusted tools).

### Flag Injection Prevention

By default, argument values starting with `-` are rejected. This prevents an agent from passing `--config=/etc/shadow` to trick a script into reading unintended files.

To allow flags for a specific parameter:
```toml
[[parameters]]
name        = "options"
description = "Additional flags"
allow_flags = true     # permit values like "--verbose"
```

To disable all arg validation: set `arg_passthrough = true` at the top level.

---

## Resource Declarations

Resource declarations serve two purposes:

1. **Authorization** — the server checks them against the calling key's policy rules
2. **Sandboxing** — the sandbox profile is built from the granted resources

### Filesystem Resources

```toml
# Static path — known at definition time
[[resources]]
type = "filesystem"
path = "/var/log/app.log"
perm = "r"

# Dynamic path — resolved from agent argument
[[resources]]
type          = "filesystem"
path_from_arg = "path"      # uses the "path" parameter value
perm          = "rw"
```

### Network Resources

```toml
[[resources]]
type = "network"
path = "*"       # any host
perm = "r"       # read = receive data
```

Network resources require a matching `network` grant in the key's policy. Without one, the sandbox blocks all TCP connections (AppContainer on Windows, Landlock V5 on Linux 6.7+).

### Program Resources

```toml
[[resources]]
type = "program"
path = "git"     # executable name
perm = "x"       # execute permission
```

---

## Execution Model

1. Agent calls `tools/call` with the tool name and arguments
2. Server validates arguments (required params, metacharacters, flag injection)
3. Server resolves `[[resources]]` — substituting `path_from_arg` values
4. Server checks resources against the calling key's policy (deny → grant → intersection)
5. Server builds a `SandboxProfile` from the granted resources
6. Child process is spawned:
   - Clean environment (only `env_baseline` + key's environment grants)
   - OS-level sandbox (AppContainer / Landlock)
   - Job Object / `PR_SET_PDEATHSIG` for process lifecycle
7. stdout is captured and returned as the tool result
8. stderr is logged (not returned to agent unless the tool exits non-zero)
9. Process is killed after `tool_timeout_secs` if still running

---

## Examples

### Minimal Tool (No Resources)

```toml
# tools/hello.toml
name        = "hello"
description = "Echo a greeting"
command     = "echo"
args        = ["Hello, {name}!"]

[[parameters]]
name     = "name"
required = true
```

### Filesystem Tool

```toml
# tools/word_count.toml
name        = "word_count"
description = "Count words in a file"
command     = "wc"
args        = ["-w", "{path}"]

[[parameters]]
name        = "path"
description = "Absolute path to the file"
required    = true

[[resources]]
type          = "filesystem"
path_from_arg = "path"
perm          = "r"
```

### Grouped Tool

```toml
# tools/git_log.toml
group           = "devops"
name            = "git_log"
description     = "Show recent git commits"
command         = "git"
args            = ["-C", "{path}", "log", "--oneline", "-n", "20"]
arg_passthrough = false

[[parameters]]
name        = "path"
description = "Repository directory"
required    = true

[[resources]]
type          = "filesystem"
path_from_arg = "path"
perm          = "r"
```

### Network Tool

```toml
# tools/fetch_url.toml
name        = "fetch_url"
description = "Fetch the content of a URL"
command     = "curl"
args        = ["-s", "-L", "--max-time", "10", "{url}"]

[[parameters]]
name        = "url"
description = "URL to fetch"
required    = true

[[resources]]
type = "network"
path = "*"
perm = "r"
```

### Shell Tool (Explicit Opt-In)

```toml
# tools/system_info.toml
name        = "system_info"
description = "Show system information (Windows)"
command     = "cmd"
args        = ["/C", "systeminfo"]
allow_shell = true     # required for cmd.exe
```

---

## Best Practices

1. **Write descriptions for the LLM.** The `description` field is what the agent sees in `tools/list`. Be specific: what does the tool return? When should the agent use it? What format is the output?

2. **Declare all resources.** If your tool reads files, declare filesystem resources. If it makes HTTP calls, declare network resources. Undeclared access will be blocked by the sandbox.

3. **Use groups for related tools.** Group tools by function (`ast`, `devops`, `data`). This enables batch authorization and makes `tools/list` easier for agents to navigate.

4. **Prefer `path_from_arg` over `path`.** Dynamic paths let the agent choose the target at call time, while the key's policy still controls which paths are allowed.

5. **Avoid `allow_shell` and `arg_passthrough`.** These weaken security. If you must use them, document why and keep the tool's scope minimal.

6. **Set `required = true` on essential params.** The server validates required params before execution, giving the agent a clear error instead of a cryptic tool failure.

7. **Keep commands simple.** Each tool should do one thing. Chain tools at the agent level, not with shell pipes.

8. **Use `--max-time` or equivalent for network tools.** Unbounded network calls can hit `tool_timeout_secs` and be killed without useful output.
