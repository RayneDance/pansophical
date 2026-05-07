# Pansophical Sandbox — Status & Future Work

## Completed

### Phase 0–2: Windows Low Integrity Restricted Token ✅

- Spawns child processes with a **Low Integrity restricted token** via
  `CreateProcessAsUserW` with `DISABLE_MAX_PRIVILEGE`
- Write-path enforcement via integrity labels on granted directories
- Falls back to unsandboxed execution if token creation fails
- Job Object assignment for process lifetime management

### Phase 4: Windows AppContainer (Strongest Isolation) ✅

AppContainer provides the strongest possible sandbox on Windows, even on
elevated/admin sessions. It blocks ALL filesystem access except paths with
an explicit ACE for the container's SID.

**Implementation** (`src/sandbox/windows.rs`):
1. `CreateAppContainerProfile` — creates a unique container per tool invocation
2. Container SID obtained from the profile for ACE grants
3. For each allowed path, adds an ACE granting the container SID access:
   - Write paths → `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
   - Read paths → `FILE_GENERIC_READ`
4. `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute`
   with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`
5. `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`
6. RAII cleanup: removes ACEs and deletes container profile on drop

**Integration** (`src/reaper.rs`):
- AppContainer is the **primary** sandbox strategy
- Falls back to Low Integrity Restricted Token if AppContainer fails
- Falls back to unsandboxed if both fail

### Authorization Glob Matching Fix ✅

Fixed two bugs in `path_matches_glob` (`src/authz/glob.rs`):
1. **Slash normalization**: Windows `canonicalize()` produces backslash paths
   but config patterns use forward slashes. Both are now normalized to `/`
   before matching.
2. **Directory root matching**: A `/**` pattern now also matches the directory
   itself (e.g., `E:/pansof/**` grants access to both `E:/pansof` and its
   contents). Previously, `list_dir` on the root of a grant was always denied.

### Demo Harness: Vertex AI Migration ✅

- Migrated `demo.py` from Google Gemini Developer API to **Vertex AI**
- Authentication via `gcloud` CLI (no API key needed)
- Uses `gcloud.cmd` on Windows to avoid `WinError 2`
- Added animated spinner during API calls for visual feedback
- Timeout increased from 60s → 120s for large tool result payloads


---

## Future Work

### Phase 3: Linux Landlock

For Linux kernel 5.13+ (available on most modern distros):

1. **Create a Landlock ruleset** via `landlock_create_ruleset` syscall
   - Define handled access rights (read, write, execute, etc.)
2. **Add path-beneath rules** for each path in `SandboxProfile`
   - `write_paths` → `LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_*`
   - `read_paths` → `LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR`
   - `exec_paths` → `LANDLOCK_ACCESS_FS_EXECUTE`
3. **Enforce** via `landlock_restrict_self` in a `pre_exec` hook on the child process
4. **Fallback**: If Landlock is not available (old kernel), log a warning and
   run unsandboxed (same pattern as Windows restricted token fallback)

Reference implementation: `src/sandbox/linux.rs` (file exists, currently empty)

#### Key differences from Windows

- Landlock is **path-based** — no need for integrity labels or token manipulation
- Rules are inherited by children automatically
- Works regardless of whether the server runs as root or unprivileged
- No cleanup needed — rules are per-process and die with the child


### Phase 5: Read-path Enforcement

Currently, read paths are collected in the `SandboxProfile` but only enforced
by AppContainer. The Low Integrity fallback does not restrict reads.

- **Linux**: Add Landlock read rules (straightforward)
- **Windows Low IL**: Read access is not restricted by integrity level.
  AppContainer enforces read restrictions via ACEs (already implemented).
- **Windows AppContainer**: ✅ Read paths get read-only ACEs for the container SID.


### Phase 6: Network Isolation

Restrict child processes from making network connections:

- **Linux**: Landlock v4 (kernel 6.7+) adds `LANDLOCK_ACCESS_NET_*` rules
- **Windows AppContainer**: Network access requires explicit capability grants
- **Fallback**: Use Job Object `JOB_OBJECT_NET_RATE_CONTROL_FLAGS` (limited)


### Tool Namespacing

Resolve tool name collisions by prepending group prefix:
- Builtins: `builtin_read_file`, `builtin_write_file`, etc.
- Script tools without a defined group: `ext_<name>` (e.g. `ext_read_file`)
- Allows both a builtin and script tool with the same base name to coexist


## Priority Order

1. **Linux Landlock** — high value, moderate complexity
2. **Tool namespacing** — prevents collisions, improves clarity
3. **Read-path enforcement** — partially done (AppContainer), needs Landlock + Low IL
4. **Network isolation** — defense-in-depth, platform-dependent
