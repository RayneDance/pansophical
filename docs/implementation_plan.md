# Pansophical — Implementation Plan

Each phase ends in a testable state. Phases 1–6 form the Minimum Viable Secure
Server (MVSS). Phases 7–12 build the full feature set on top.

---

## Phase 0 — Project Scaffold

**Goal**: Compilable skeleton. All modules exist as stubs. CLI parses flags.

### Files
- `Cargo.toml` — dependencies declared (see below)
- `src/main.rs` — CLI entry point
- `src/error.rs` — top-level `PansophicalError` enum
- All module `mod.rs` stubs (empty `pub mod` declarations)

### Key Tasks
1. Add dependencies to `Cargo.toml`:
   ```toml
   tokio          = { version = "1", features = ["full"] }
   serde          = { version = "1", features = ["derive"] }
   serde_json     = "1"
   toml           = "1"
   clap           = { version = "4", features = ["derive"] }
   glob           = "0.3"
   bitflags       = "2"
   hmac           = "0.12"
   sha2           = "0.10"
   uuid           = { version = "1", features = ["v4"] }
   tracing        = "0.1"
   tracing-subscriber = "0.3"
   notify         = "6"          # file watching (hot reload)
   axum           = "0.7"        # confirm server + HTTP transport
   tokio-util     = "0.7"
   open           = "5"          # browser open (confirm server)
   ```
2. Implement CLI with `clap`:
   - `(default)` — run server
   - `--init` — generate `config.toml` + random `server_secret`, print path, exit 0
   - `--check` — parse + validate `config.toml`, print result, exit 0/1
3. `--init` writes a well-commented `config.example.toml` to the current directory

### ✅ Testable
- `cargo build` succeeds with zero warnings
- `cargo run -- --help` shows usage
- `cargo run -- --init` creates `config.toml` in cwd
- `cargo run -- --check` exits 0 on the generated file

---

## Phase 1 — Config + PolicyTarget Types

**Goal**: Full TOML config parsed and validated in memory. The intersection
math is correct and unit-tested.

### Files
- `src/config/mod.rs` — top-level `Config` struct, loader, `--check` impl
- `src/config/schema.rs` — all TOML-mapped structs (`ServerConfig`, `KeyConfig`,
  `PolicyRule`, `LimitsConfig`, `UiConfig`, etc.)
- `src/config/perm.rs` — `Perm` bitflag (`r=4, w=2, x=1`), TOML string parsing
- `src/config/policy_target.rs` — `PolicyTarget` enum + per-target fields
- `src/authz/mod.rs` — `AccessRequest`, `ActualGrant`, rule evaluation
- `src/authz/intersection.rs` — intersection computation
- `src/authz/glob.rs` — glob compilation at parse time, path canonicalization,
  Windows case-fold, registry hive alias normalization

### Key Tasks
1. Parse `Perm` from both short form (`"rw"`) and verb list (`["read","write"]`)
2. Compile all glob patterns at parse time; fail `--check` on invalid patterns
3. Implement `canonical_path()`:
   - `std::fs::canonicalize` (resolves `..`, `.`, symlinks)
   - On Windows: lowercase result before glob match
4. Implement deny-before-grant evaluation:
   ```
   for each AccessRequest:
     if any deny rule matches → reject
     if no grant rule covers → reject
   actual_grant = tool_requests ∩ matched_grants
   ```
   **Intersection is a subset check**: an `AccessRequest` is satisfied when
   there exists a matching grant rule whose path glob contains the requested
   path AND whose `Perm` bits are a superset of the requested bits. The
   actual grant for that request is the *requested* bits (not the grant's
   broader bits). Example: tool asks `r` on `/workspace/src/main.rs`, key
   grants `rw` on `/workspace/**` → actual is `r` on `/workspace/src/main.rs`.
5. Registry normalization: `HKCU` → `HKEY_CURRENT_USER`, slashes → backslashes
6. Key resolution: token → `KeyConfig`
7. **Authz Explain Mode** (`dev_mode = true`): on any denial, build a
   `PolicyDiff` struct (`requested`, `matched_grants`, `denied_reasons`) and
   attach it to the error response. Implement this now — it is essential for
   debugging in Phases 5 and 6.

### ✅ Testable (unit tests in `src/authz/tests.rs`)
- Intersection math: tool asks `rw`, key grants `r` → actual is `r`
- Subset check: tool asks `r` on `/workspace/src/main.rs`, key grants `rw`
  on `/workspace/**` → actual is `r` on the specific path (not `rw`)
- Deny always wins over grant on same path
- Path traversal: `../../etc/passwd` in `access_requests()` is canonicalized
  and falls outside `/workspace/**` → denied
- Windows case bypass: `C:\Users\X` and `c:\users\x` match the same rule
- Registry: `HKCU/Foo` and `HKEY_CURRENT_USER\Foo` match the same rule
- Registry case: `hkcu/Foo` and `HKCU/Foo` are treated identically
- Unknown key token → key resolution returns `None`
- `dev_mode = true`: denied request returns `explain` block; `dev_mode = false`:
  all denials return identical -32001 regardless of which rule caused it

---

## Phase 2 — MCP Protocol + Stdio Transport

**Goal**: A real MCP agent can connect over stdio, complete the initialize
handshake, and call `tools/list`. No tools execute yet.

### Files
- `src/protocol/messages.rs` — JSON-RPC types, MCP envelope types
- `src/protocol/lifecycle.rs` — `initialize` handler, capabilities response,
  session state
- `src/transport/stdio.rs` — async line-delimited JSON-RPC reader/writer
- `src/tools/mod.rs` — `McpTool` trait, `ToolRegistry` (empty for now)
- `src/session.rs` — `Session` struct: connection ID, resolved key, session approvals cache

### Key Tasks
1. `initialize` handler:
   - Extract `params._meta.token`, resolve key, bind to `Session`
   - Return capabilities: `tools.listChanged=true`, `resources.listChanged=true`,
     `logging={}`
   - Reject unknown protocol versions with JSON-RPC error -32602
2. Handle `notifications/initialized` (no-op, log it)
3. Handle `tools/list` → return empty array for now
4. Handle unknown methods → return -32601 Method Not Found
5. Graceful shutdown on stdin close
6. **Stdio stdout isolation**: the server's stdout fd is the JSON-RPC channel.
   Child processes spawned later (Phase 5+) must NEVER inherit it. All
   `tokio::process::Command` spawns must explicitly set
   `stdout(Stdio::piped())` and `stderr(Stdio::piped())`. Inheriting the
   parent stdout fd would interleave child output with JSON-RPC responses,
   corrupting the protocol silently.

### ✅ Testable
- Use `echo` / pipe to drive JSON-RPC messages; verify responses
- `initialize` with a valid token → correct capabilities response
- `initialize` with unknown token → -32000 Auth Error
- `tools/list` after init → `{"tools": []}`
- Unknown method → -32601
- stdin close → process exits 0

---

## Phase 3 — Audit Log

**Goal**: Every authz decision is written to the audit log. Operators can see
what happened and why.

### Files
- `src/audit/mod.rs` — `AuditLog` writer
- `src/audit/entry.rs` — `AuditEntry` struct (key, tool, access_requests,
  actual_grant, decision, outcome, timestamp, connection_id)

### Key Tasks
1. Open log file with `O_APPEND | O_CREAT` (integrity: can't truncate)
2. Write one JSON line per decision
3. Support `output = "stdout" | "file" | "syslog"`
4. Structured fields — machine-readable JSON, not prose
5. Wire into authz evaluation: log every grant, deny, and error

### Audit Entry shape
```json
{
  "ts": "2026-05-06T23:00:00Z",
  "connection_id": "abc123",
  "key": "ci_agent",
  "tool": "write_file",
  "access_requests": [{"target": "filesystem", "path": "/workspace/main.rs", "perm": "w"}],
  "actual_grant":    [{"target": "filesystem", "path": "/workspace/main.rs", "perm": "w"}],
  "decision": "granted",
  "outcome": "success"
}
```

### ✅ Testable
- Send a tool call that gets denied; verify log entry appears with `decision: "denied"`
- Verify the `actual_grant` field in approved calls reflects the intersection, not the full key grant
- Verify file is opened append-only (attempt to truncate externally → log continues)

---

## Phase 4 — Safety Rails

**Goal**: Rate limits and concurrency gates are enforced per key. Runaway
agents can't exhaust server resources.

### Files
- `src/limits.rs` — `RateLimiter` (token bucket per key), `ConcurrencyGate`

### Key Tasks
1. Token bucket per key ID; replenish at `max_invocations_per_minute / 60` tokens/sec
2. Concurrency gate: atomic counter; reject (or optionally queue) when
   `max_concurrent_tools` is reached
3. Per-key limit overrides from `[keys.*.limits]`
4. Errors: rate limited → -32002; concurrency exceeded → -32003
5. **Output pipe monitoring**: the server reads child stdout/stderr through
   the pipe. Track cumulative bytes read; kill child and return an error
   if it exceeds `max_output_bytes`. This catches runaway output before
   it exhausts memory.
   > **Disk write quota**: enforcing a `max_disk_write_bytes` limit requires
   > cgroups (Linux) or job object I/O accounting (Windows). This is deferred;
   > document as a known limitation. Operators should use filesystem quotas
   > at the OS level for now.

### ✅ Testable
- Fire 100 requests rapidly with a key limited to 60/min → excess get -32002
- Open 5 concurrent tool calls with `max_concurrent_tools = 4` → 5th is rejected
- Per-key override: key with `max_invocations_per_minute = 120` is not throttled at 61 req/min

---

## Phase 5 — Linux Sandbox (Landlock + seccomp)

**Goal**: A spawned child process physically cannot access filesystem paths
outside `actual_grant`. Environment stripping is enforced.

### Files
- `src/sandbox/mod.rs` — platform dispatch + `SandboxConfig` builder
- `src/sandbox/linux.rs` — landlock, seccomp, process group, PR_SET_PDEATHSIG
- `src/reaper.rs` — timeout enforcement thread

### Key Tasks
1. Build a clean environment from scratch:
   - Start empty
   - Add `env_baseline` vars (`PATH`, `TERM`, `LANG`, `HOME`)
   - Add key's `environment` grants
2. Apply Landlock: derive allowed paths from `actual_grant.filesystem` entries
   > **TOCTOU note**: Landlock binds to inodes, not path strings. Always
   > build Landlock rules from the results of `canonical_path()` (the
   > already-resolved canonical paths), never from raw agent-provided strings.
   > This means a symlink swap after canonicalization cannot redirect the
   > child to an unintended inode — Landlock holds the original inode.
3. Apply seccomp: block syscalls not needed for typical scripting (optional
   allowlist, conservative defaults)
4. Assign child to process group; set `PR_SET_PDEATHSIG = SIGKILL`
5. **Signal handling — graceful shutdown**: install `SIGINT`/`SIGTERM` handlers
   in `main.rs`:
   - Stop accepting new tool calls (return -32603 Internal Error)
   - Send `notifications/cancelled` to all active sessions
   - Give the reaper `shutdown_grace_secs` (config) to wait for in-flight
     children to finish or be killed
   - Force-kill any surviving children; then exit 0
6. Reaper: spawn a task per child; kill after `tool_timeout_secs`
7. Use `tokio::process::Command` with `stdout(Stdio::piped())` AND
   `stderr(Stdio::piped())`; drain both with `tokio::select!` on separate
   async tasks to prevent either pipe from filling and deadlocking the child

### ✅ Testable (Linux only at this phase)
- Spawn a tool with `filesystem /tmp r` actual_grant; verify it cannot write to `/tmp`
- Spawn a tool with no environment grants; verify `$HOME` is absent (only baseline vars present)
- Spawn a tool that sleeps 60s with `tool_timeout_secs = 2`; verify it's killed
- Kill the server process; verify orphaned child is also killed

---

## Phase 6 — Built-in Tools: `read_file` + `write_file`

**Goal**: Full end-to-end pipeline proven with real tools and real files.

### Files
- `src/tools/builtin/mod.rs` — register built-ins
- `src/tools/builtin/read_file.rs`
- `src/tools/builtin/write_file.rs`

### Key Tasks

**`read_file`**:
- `access_requests()`: `canonical_path(args.path)` → `AccessRequest::filesystem(path, READ)`
- `execute()`: spawn child (or inline read — file reading can be in-process
  since the sandbox enforces access anyway); return `TextContent`

**`write_file`**:
- `access_requests()`: `canonical_path(args.path)` → `AccessRequest::filesystem(path, WRITE | CREATE)`
- Optionally return `preview` diff in `access_requests()` if `args.content` is provided and file exists
- `execute()`: atomic write (write to `.tmp`, rename)

**MCP tool result format**:
```json
{
  "content": [{"type": "text", "text": "file contents here"}],
  "isError": false
}
```

### ✅ Testable (full pipeline)
- `tools/list` returns `read_file` and `write_file` with correct JSON Schema
- `read_file` on a path the key has `r` → returns content
- `read_file` on a path outside key grants → -32001 Unauthorized
- `write_file` with a `confirm = true` rule → hangs until confirm resolved
  (confirm server not yet wired — verify it blocks, then times out and denies)
- Path traversal in args (`../../etc/passwd`) → denied after canonicalization

---

## Phase 7 — Confirm Server

**Goal**: `confirm = true` rules surface a browser approval page instead of
blocking forever or hard-denying.

### Files
- `src/confirm/server.rs` — `axum` HTTP listener on `ui.port`
- `src/confirm/token.rs` — UUID + HMAC-SHA256 one-time token, TTL
- `src/confirm/ui.rs` — embedded HTML/CSS/JS approval page (include_str!)
- `src/confirm/session.rs` — session approval cache (connection_id keyed,
  inactivity expiry)

### Key Tasks
1. Server binds `127.0.0.1:9765` on startup (always-on)
2. `POST /confirm/:token/approve` or `/deny` with `{"scope": "once"|"minutes:5"|"session"}`
3. One-time token: UUID + HMAC-SHA256(server_secret, uuid + expiry); reject replays
4. Auto-open browser via `open` crate when `auto_open = "confirm"` and a
   confirm fires; log a clear error to audit log if browser open fails (headless)
5. Session approval cache: `DashMap<(ConnectionId, KeyId, ToolName, Pattern, Perm), Instant>`
   - Cleared on connection drop
   - **Re-attach behaviour**: for HTTP/SSE detached sessions (Phase 10),
     session approvals survive through the `reattach_grace_secs` window.
     If re-attach occurs: approvals are transferred to the new connection ID.
     If the grace period expires without re-attach: approvals are purged
     along with the detached tool handle.
   - Background task sweeps for inactivity expiry every 30s
6. Pending queue: `DashMap<Token, oneshot::Sender<ApprovalResult>>`
7. Admin routes (`/tools`, `/keys`) require `ui.auth.pin` if set

### ✅ Testable
- Trigger a `confirm = true` write → browser page opens (or log entry appears if headless)
- Approve → write completes; check audit log for `decision: "granted"`
- Deny → -32004 returned; check audit log
- TTL expiry → auto-deny; check audit log
- Replay same token → rejected
- Session approval: approve with `minutes:5`; second identical request within 5 min
  proceeds without confirm; connection restart clears approval

---

## Phase 8 — Hot Reload

**Goal**: Editing `config.toml` or dropping a file in `tools/` takes effect
immediately without restarting the server.

### Files
- `src/config/watcher.rs` — `notify` file watcher, config reload task
- `src/tools/watcher.rs` — `tools/` directory watcher, tool registry reload

### Key Tasks
1. On `config.toml` change:
   - Re-parse and validate; keep old config if invalid (log warning)
   - Atomically swap `Arc<RwLock<Config>>`
   - Clear all session approvals (config change = new policy = no cached gates)
   - Audit log the reload event
2. On `tools/*.toml` change: reload `ToolRegistry`; emit `notifications/tools/list_changed`
   to all connected sessions
3. `--check` reuses the same parse + validate path (no duplication)

### ✅ Testable
- Edit a key's `perm` from `rw` to `r` mid-session; next write attempt → denied
- Drop a malformed `config.toml` → warning logged, old policy remains active
- Drop a new `tools/my_tool.toml` → tool appears in `tools/list` within 1s

---

## Phase 9 — Windows Sandbox (AppContainer)

**Goal**: Same security posture on Windows as Phase 5 provides on Linux.

### Files
- `src/sandbox/windows.rs` — AppContainer creation, Job Object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, environment stripping

### Key Tasks
1. Create AppContainer profile from `actual_grant` filesystem paths
   > **Do not implement AppContainer from raw Win32 syscalls.** Managing
   > Capability SIDs and Security Descriptors by hand is error-prone and
   > takes weeks. Evaluate the `windows` crate (Microsoft's official Rust
   > bindings) and the `CreateAppContainerProfile` / `DeleteAppContainerProfile`
   > Win32 functions as the starting point. If a higher-level wrapper exists
   > at implementation time, prefer it.
2. Assign spawned child to AppContainer
3. Assign child to Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
4. Environment stripping: same logic as Linux, using Windows API
5. All sandbox logic is `#[cfg(target_os = "windows")]`; Linux path is
   `#[cfg(target_os = "linux")]`; `strategy = "auto"` selects platform

### ✅ Testable (Windows only)
- Same test cases as Phase 5, run on Windows
- Verify AppContainer profile is created and destroyed per invocation

---

## Phase 10 — HTTP/SSE Transport

**Goal**: Remote agents can connect over HTTP with bearer token auth and
receive streaming responses.

### Files
- `src/transport/http.rs` — `axum` router: `POST /tools/call`, `GET /sse`
- SSE stream per connection

### Key Tasks
1. `GET /sse` — upgrade to SSE; extract `Authorization: Bearer` header; resolve key
2. CORS: validate `Origin` header against `cors_origins` allowlist on every request
3. `POST /tools/call` — same authz pipeline as stdio
4. SSE disconnect policy:
   - `on_disconnect = "kill"`: drop child `JoinHandle` → tokio cancels the task → reaper kills child
   - `on_disconnect = "detach"`: retain handle in `DashMap<RequestId, RunningTool>`
     with a grace-period timeout
5. Re-attach: `GET /tools/stream/:request_id` resumes SSE for a detached tool

### ✅ Testable
- Connect with a valid bearer token → `initialize` equivalent (tools/list works)
- Connect with invalid token → 401
- Invalid `Origin` header → 403 (CORS)
- Run a long tool; kill SSE connection; verify child is dead within 1s
  (kill policy) or survives the grace period (detach policy)

---

## Phase 11 — Script Tools + MCP Resources + Progress Notifications

**Goal**: Users can define tools in TOML without writing Rust. Long-running
tools stream progress. File and device resources are listable and readable.

### Files
- `src/tools/script.rs` — `ScriptTool` implementing `McpTool`
- `src/protocol/resources.rs` — `resources/list`, `resources/read`
- `src/protocol/progress.rs` — `notifications/progress` sender

### Key Tasks

### Key Tasks

**ScriptTool**:
1. Load `[tool.invoke]` from definition; build `tokio::process::Command`
2. Never use shell: spawn `command` with `args` directly; reject at load time
   if `command` resolves to `sh`, `bash`, `cmd`, `powershell`, or similar,
   unless `allow_shell = true` is explicit (triggers audit log warning on every call)
3. **Arg injection validation**: validate all agent-provided argument values
   that will be passed to the child process:
   - Reject values containing shell metacharacters (`; & | > < ` $ ( )`) if
     `allow_shell = false` (defence-in-depth; the shell isn't involved, but
     a naive script using `os.system(arg)` internally would still be dangerous)
   - Log a warning; the tool definition can declare `arg_passthrough = true`
     to opt out of this check for args that legitimately contain special chars
4. `access_requests()`: iterate `[[tool.resources]]`, substitute `path_from_arg`
   from actual call args, call `canonical_path()`
5. If `streaming = true` and `ctx.progress_token.is_some()`: drain stdout as
   `notifications/progress` messages; send final `tools/call` result on exit

**MCP Resources**:
1. `resources/list`: enumerate all `filesystem` grants with `r` permission;
   return `file://` URIs. Enumerate `device` grants with `r`; return
   `device://` URIs.
2. `resources/read`: check calling key for `r` on the requested URI;
   read and return content

**Progress**:
1. `RequestContext` carries `Option<ProgressToken>`
2. `ScriptTool.execute()` spawns stdout reader that sends `notifications/progress`
   on each newline when token is present

### ✅ Testable
- Define a Python echo tool in `tools/echo.toml`; call it via stdio → returns output
- Define a tool without `allow_shell`; attempt to set `command = "sh"` → rejected at load time
- `resources/list` for a key with `/workspace/** r` → lists files under `/workspace`
- `resources/read` on a file outside key grants → -32001
- Call a `streaming = true` tool with `progressToken` → receive `notifications/progress` events

---

## Phase 12 — Admin Web UI

**Goal**: Operators can manage tools and keys through a browser interface
instead of hand-editing TOML.

### Files
- `src/confirm/ui.rs` (extended) — full dashboard SPA (embedded via `include_str!`)
- Static HTML/CSS/JS or a Rust-side template (no external bundler required)

### Pages
| Route | Purpose |
|---|---|
| `/` | Dashboard: server status, active connections, pending confirms |
| `/tools` | List, add, edit, delete script tool definitions |
| `/keys` | List, add, edit key policies; grant tool access (pre-populates `suggested_grants`) |
| `/audit` | Live-tailing audit log viewer |
| `/confirm/:token` | Approval page (existing from Phase 7) |
| `/settings` | Server config editor (theme, branding, limits) |

### Key Tasks
1. PIN check middleware: if `ui.auth.pin != ""`, all routes except `/confirm/:token`
   require PIN session cookie
2. Tool management: form writes `tools/<name>.toml` → hot reload fires
3. Key management: form writes to `config.toml` `[keys.*]` section → hot reload fires
4. All config writes are atomic (write to `.tmp`, rename)
5. Apply theme config: inject CSS custom properties from `[ui.theme.colors]`;
   load `[ui.custom.css_path]` as last stylesheet

### ✅ Testable (manual + browser)
- Add a script tool via UI → appears in `tools/list` response within 1s
- Grant a key access to a tool → key can now call it
- Edit `[ui.theme.colors.accent]` → UI reloads with new color
- Supply `css_path` → custom CSS is loaded after built-in styles
- Without PIN: all routes accessible from localhost
- With PIN: accessing `/keys` without session cookie → redirected to PIN entry

---

## Summary: Minimum Viable Secure Server (MVSS)

Phases 0–6 produce a server that:
- Parses and validates config with the full PolicyTarget + Perm model
- Handles stdio MCP sessions with correct lifecycle
- Logs every authz decision
- Enforces rate limits and concurrency
- Sandboxes children with Landlock (Linux) and environment stripping
- Exposes `read_file` and `write_file` as real tools through the full pipeline

Everything after Phase 6 extends capability without compromising the security
foundation.

---

## Dependency on External Review

After Phase 6, before beginning Phase 7, do a targeted security review of:
1. The intersection computation (unit tests + code review)
2. Path canonicalization edge cases (symlinks, mount points, UNC paths on Windows)
3. Landlock rule generation from `actual_grant`

These are the three places where a subtle bug causes a real security failure.
