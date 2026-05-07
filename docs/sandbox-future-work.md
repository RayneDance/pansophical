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

### Phase 3: Linux Landlock ✅

Implemented Landlock filesystem sandboxing for Linux (kernel 5.13+):

**Implementation** (`src/sandbox/linux.rs`):
1. `configure_sandbox()` installs a `pre_exec` hook on the child `Command`
2. Sets `PR_SET_PDEATHSIG(SIGKILL)` — child is killed if server dies
3. Builds a Landlock ruleset from the `SandboxProfile`:
   - `read_paths` → `AccessFs::from_read(ABI::V4)` (read files, list dirs)
   - `write_paths` → `AccessFs::from_all(ABI::V4)` (full read+write+create)
   - `exec_paths` → read + `AccessFs::Execute`
4. Always allows: `/proc` (read), `/dev/null|urandom|zero` (read),
   `/dev/pts` (read+write), `/tmp` (read+write)
5. Enforces via `restrict_self()` — rules apply to the child and all its descendants
6. Falls back to unsandboxed if Landlock is unavailable (old kernel, disabled LSM)

**Integration** (`src/reaper.rs`):
- Landlock sandbox spawns via `spawn_landlock_linux()` when `sandbox.enabled = true`
  and a `SandboxProfile` is available from the task-local
- Falls back to normal unsandboxed spawn if no profile exists
- Same timeout + output cap semantics as Windows sandbox paths

**Key advantages over Windows approach:**
- Path-based — no integrity labels, tokens, or ACE manipulation needed
- Rules are per-process and inherited by children — no cleanup
- Works for unprivileged processes (no root required)
- Simple `pre_exec` hook — no platform-specific API surface


### Phase 5: Read-path Enforcement

Currently, read paths are collected in the `SandboxProfile` but only enforced
by AppContainer. The Low Integrity fallback does not restrict reads.

- **Linux**: ✅ Landlock read rules enforce read-only access
- **Windows Low IL**: Read access is not restricted by integrity level.
  AppContainer enforces read restrictions via ACEs (already implemented).
- **Windows AppContainer**: ✅ Read paths get read-only ACEs for the container SID.


### Phase 6: Network Isolation

Restrict child processes from making network connections:

- **Linux**: Landlock v4 (kernel 6.7+) adds `LANDLOCK_ACCESS_NET_*` rules
- **Windows AppContainer**: Network access requires explicit capability grants
- **Fallback**: Use Job Object `JOB_OBJECT_NET_RATE_CONTROL_FLAGS` (limited)


### Tool Namespacing ✅

Tool name collisions prevented by group prefix:
- Builtins: `builtin_read_file`, `builtin_write_file`, `builtin_list_dir`, `builtin_request_access`
- Script tools: `{group}_{name}` (defaults to `ext_{name}` if no group specified)
- Allows both a builtin and script tool with the same base name to coexist
- Tests: `default_namespace_is_ext`, `custom_group_namespace`


## Priority Order

1. ~~**Linux Landlock**~~ — ✅ done
2. ~~**Tool namespacing**~~ — ✅ done
3. ~~**Read-path enforcement**~~ — ✅ done (AppContainer + Landlock)
4. **Network isolation** — defense-in-depth, platform-dependent (only remaining item)

