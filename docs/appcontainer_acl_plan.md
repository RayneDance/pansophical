# AppContainer ACL Implementation — Completed

> **Status:** ✅ Implemented and hardened — session-scoped pooling, handle-based ACEs, ACE existence checks, env block fixes.

## Architecture Overview

### Problem Statement

The original AppContainer implementation suffered from three critical issues:

1. **ACE Pollution:** Each tool call created a UUID-named container, stamping ACEs on every granted path. After N tool calls, each file had N orphaned ACEs from dead containers.
2. **Performance:** `icacls /T` recursively touched every file on each grant — 80+ seconds for large directories.
3. **Crash Orphans:** UUID-based containers were unrecoverable after a crash. The server could never find or clean up profiles from dead processes.

### Solution: Session-Scoped Container Pool

```
┌─────────────────────────────────────────────┐
│ ContainerPool (global, lifetime of server)  │
│                                             │
│  PoolKey(key_id, path_hash) → PoolEntry     │
│    - coding_agent-a1b2c3d4 → AppContainer   │
│    - data_agent-e5f6g7h8   → AppContainer   │
│                                             │
│  State file: appcontainer_state.json        │
│  Orphan cleanup: on startup                 │
│  Graceful cleanup: on shutdown              │
└─────────────────────────────────────────────┘
```

## What Changed

### Phase 1: Session-Scoped Container Pool (`sandbox/pool.rs`)

- **Deterministic naming:** Containers named `pansophical-{key_id}-{hash}` instead of UUID
- **Session reuse:** One container per API key, reused across all tool calls
- **State file:** `appcontainer_state.json` records active containers + PID for crash recovery
- **Orphan cleanup:** On startup, reads state file, checks if PID is alive, cleans up dead containers
- **Graceful shutdown:** Revokes all ACEs, deletes profiles, removes state file

### Phase 2: Native Handle-Based ACL Walker (`sandbox/windows.rs`)

Replaced `icacls.exe` process spawning with direct Win32 API calls:

- **`CreateFileW` + `SetSecurityInfo`** — handle-based (TOCTOU-safe)
- **`FindFirstFileW` / `FindNextFileW`** — native directory enumeration
- **`FILE_FLAG_OPEN_REPARSE_POINT`** — no symlink/junction following
- **`GetFileInformationByHandle`** — hardlink detection (`nNumberOfLinks > 1`)
- **ACE existence check** — before calling `SetSecurityInfo`, scans existing ACEs for the SID. If an adequate ACE already exists, skips the call entirely. This avoids the 50+ second `SetSecurityInfo` penalty on drive roots.
- **Configurable skip list** — skips `target/`, `node_modules/`, `.git/`, etc.

### Phase 3: Key Context Propagation

- Added `CURRENT_KEY_NAME` task-local alongside `CURRENT_PROFILE`
- Transport layer passes `key_name` via `with_profile_and_key()`
- Pool reads key from task-local to determine container identity

### Phase 4: Server Integration

- `init_container_pool()` called at async runtime startup (both stdio and HTTP)
- `cleanup_container_pool()` called on graceful shutdown
- `SandboxConfig` extended with `skip_dirs` (configurable, sensible defaults)

## Security Properties

| Property | Before | After |
|---|---|---|
| ACE pollution | Unbounded (N per tool call) | Bounded (1 per key) |
| TOCTOU safety | Path-based (`icacls`) | Handle-based (`SetSecurityInfo`) |
| Symlink following | icacls follows | `FILE_FLAG_OPEN_REPARSE_POINT` |
| Hardlink safety | Not checked | Detected + skipped |
| Crash recovery | None (UUID orphans) | State file + PID check |
| Process isolation | Job Object | Job Object (unchanged) |
| Drive root ACL perf | 50+ seconds per call | 0ms (ACE existence check) |
| Child env block | Missing system vars | 14 critical vars always included |
| Denial messages | Opaque "denied" | Resource type + reason included |

## Files Modified

| File | Changes |
|---|---|
| `src/sandbox/pool.rs` | **New** — Container pool, state file, orphan cleanup |
| `src/sandbox/windows.rs` | Native ACL walker, `create_named()`, `grant_recursive()`, `revoke_recursive()` |
| `src/sandbox/mod.rs` | Pool module, `with_profile_and_key()`, `current_key_name()` |
| `src/config/schema.rs` | `skip_dirs` field on `SandboxConfig` |
| `src/reaper.rs` | Pool init/cleanup, pool-based `spawn_appcontainer_windows` |
| `src/main.rs` | Wired pool init/cleanup into both transport blocks |
| `src/transport/stdio.rs` | `with_profile_and_key()` instead of `with_profile()` |
| `src/transport/http.rs` | `with_profile_and_key()` instead of `with_profile()` |

## Configuration

```toml
[sandbox]
enabled = true
strategy = "auto"

# Directories to skip during recursive ACL grants (case-insensitive)
skip_dirs = [
    "target", "node_modules", ".git", "build", "dist", "out",
    "__pycache__", ".venv", "venv", ".cache", ".next", ".nuxt",
    ".turbo", ".parcel-cache", ".gradle", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".eggs"
]
```
